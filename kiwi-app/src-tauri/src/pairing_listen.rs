//! LAN/USB pair-claim listener (T-304 + USB bring-up) — the network half of
//! the §3.2 pairing channel: the phone POSTs its ticket + device key and
//! the desktop hands the claim to `PairEngine::claim_ticket_and_register`,
//! then pulls challenges / submits approvals over the same dev channel so a
//! USB-connected authenticator works end to end (`adb reverse` friendly).
//!
//! # Transport posture (pending ruling)
//!
//! authenticator.md §3.2 requires a TLS-protected channel (`wss://`,
//! Agent-6 recommendation) — **still unratified by Lead** (open item §10.2
//! #2). This module is therefore a *plaintext* HTTP listener gated behind
//! `KIWI_PAIR_LISTEN=1` — a development seam so the claim + challenge path
//! is real and testable; it is not the shipping transport. The QR
//! `desktop_endpoint` honestly advertises `http://`, and the doc'd TLS
//! upgrade replaces the socket layer without touching the claim semantics
//! below.
//!
//! # Routes (all dev-only, same flag)
//!
//! - `POST /pair` — `kiwi-pairing-hello` → `kiwi-pairing-registered`
//!   (claims the ticket, registers `pending`, auto-issues the
//!   `device-pairing` activation challenge the phone then pulls).
//! - `GET /challenges?device_id=…` — open (unexpired, unconsumed)
//!   challenges for one device, phone `ChallengeData` snake_case JSON.
//! - `GET /device-status?device_id=…` — `pending|active|suspended|revoked|unknown`.
//! - `POST /issue {"device_id","event"}` — mint an `unlock`/`device-pairing`
//!   challenge for the phone to approve (demo operator path; recovery flows
//!   stay `unsupported-event`).
//! - `POST /response` — phone `ChallengeResponseData` → verify/deny through
//!   `PairEngine` with the same audit rows as the IPC path
//!   (`challenge-approved`/`device-paired`/`challenge-denied`/
//!   `challenge-verification-failed`), plus trust unlock on `unlock`.
//!
//! # Bounds
//!
//! - One accept loop per process; connections are served **sequentially**
//!   (claims are rare and fast) with a per-connection read timeout, so a
//!   stalled peer can only hold the channel for `READ_TIMEOUT`.
//! - Whole request ≤ `MAX_REQUEST_BYTES` (headers + body together);
//!   `Content-Length` is required and bounded — no chunked reads.
//! - The reply vocabulary is fixed codes; ticket bytes, key bytes, and
//!   provider detail never appear in responses, logs, or audit detail.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::state::{AppState, new_id, now_unix};

/// Dev flag — plaintext listener exists only while the wss/TLS ruling is
/// pending (authenticator.md §3.2 open item). `1`/`true` enables.
pub const LISTEN_ENV: &str = "KIWI_PAIR_LISTEN";
/// Fixed-port override for USB (`adb reverse tcp:<port> tcp:<port>`) so the
/// phone can always dial `http://127.0.0.1:<port>/pair` without re-scanning
/// a QR on every restart. Absent/invalid → ephemeral port (old behavior).
pub const PAIR_PORT_ENV: &str = "KIWI_PAIR_PORT";
/// Whole-request byte cap (headers + body).
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Per-connection read deadline.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Claim path — the pairing hello route.
const CLAIM_PATH: &str = "/pair";
/// Challenge pull route (`GET ?device_id=…`).
const CHALLENGES_PATH: &str = "/challenges";
/// Device status route (`GET ?device_id=…`).
const DEVICE_STATUS_PATH: &str = "/device-status";
/// Response submit route (`POST` phone response JSON).
const RESPONSE_PATH: &str = "/response";
/// Operator issue route (`POST {"device_id","event"}`).
const ISSUE_PATH: &str = "/issue";

/// `KIWI_PAIR_LISTEN` truthy check (`1`/`true`, case-insensitive).
pub fn listen_enabled() -> bool {
    std::env::var(LISTEN_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Pick the LAN address a phone can reach: UDP `connect` performs only a
/// routing-table lookup (no packets are sent), so `local_addr` is the
/// egress interface toward the destination — the honest source address
/// for same-LAN traffic.
pub fn lan_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// Fixed port for USB stability (`KIWI_PAIR_PORT`), if valid 1..=65535.
pub fn fixed_port() -> Option<u16> {
    let raw = std::env::var(PAIR_PORT_ENV).ok()?;
    let port: u16 = raw.trim().parse().ok()?;
    (port != 0).then_some(port)
}

/// Bind the dev listener (caller holds the returned std socket until the
/// tokio runtime exists — `run()` converts it via [`serve`]).
pub fn bind() -> Option<(std::net::TcpListener, String)> {
    if !listen_enabled() {
        return None;
    }
    let listener = match fixed_port() {
        Some(port) => std::net::TcpListener::bind(("0.0.0.0", port)).ok()?,
        None => std::net::TcpListener::bind("0.0.0.0:0").ok()?,
    };
    let port = listener.local_addr().ok()?.port();
    let ip = lan_ip()?;
    Some((listener, format!("http://{ip}:{port}{CLAIM_PATH}")))
}

/// Accept loop — takes ownership of the pre-bound socket. Sequential by
/// design: one bounded connection at a time.
pub async fn serve(state: Arc<AppState>, listener: std::net::TcpListener) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(_) => return,
    };
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let st = state.clone();
                let _ = tokio::time::timeout(READ_TIMEOUT, handle_conn(st, stream)).await;
            }
            Err(_) => {
                // Transient accept failure (fd pressure) — yield and retry
                // rather than spin.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// One bounded read → parse → claim → single response → close.
async fn handle_conn(state: Arc<AppState>, mut stream: tokio::net::TcpStream) -> Result<(), ()> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > MAX_REQUEST_BYTES {
            return write_reply(&mut stream, 413, "request-too-large").await;
        }
        let n = stream.read(&mut chunk).await.map_err(|_| ())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if request_complete(&buf) {
            break;
        }
    }
    let (status, body) = dispatch(&state, &buf).await;
    let _ = write_json(&mut stream, status, &body).await;
    Ok(())
}

/// Headers end at CRLF-CRLF; the request is complete once the announced
/// Content-Length has also arrived. Chunked/absent length → incomplete
/// until the peer closes (timeout bounds that wait).
fn request_complete(buf: &[u8]) -> bool {
    let Some(head_end) = find_subslice(buf, b"\r\n\r\n") else {
        return false;
    };
    match content_length(&buf[..head_end]) {
        Some(len) if len <= MAX_REQUEST_BYTES => buf.len() - (head_end + 4) >= len,
        // No/oversized length → let dispatch reject it cleanly.
        _ => true,
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let head = std::str::from_utf8(head).ok()?;
    head.lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .or_else(|| l.strip_prefix("Content-Length:"))
        })
        .and_then(|v| v.trim().parse().ok())
}

async fn write_reply(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    code: &str,
) -> Result<(), ()> {
    let body = format!("{{\"type\":\"kiwi-pairing-error\",\"error\":\"{code}\",\"v\":1}}");
    write_json(stream, status, &body).await
}

async fn write_json(stream: &mut tokio::net::TcpStream, status: u16, body: &str) -> Result<(), ()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        _ => "Error",
    };
    let out = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\naccess-control-allow-origin: *\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(out.as_bytes()).await.map_err(|_| ())
}

/// Method/route/shape gates — every failure is a fixed code, never a
/// parsed detail.
async fn dispatch(state: &AppState, buf: &[u8]) -> (u16, String) {
    let Some(head_end) = find_subslice(buf, b"\r\n\r\n") else {
        return (400, err_json("malformed-request"));
    };
    let head = &buf[..head_end];
    let body = &buf[head_end + 4..];
    let Some(line) = std::str::from_utf8(head)
        .ok()
        .and_then(|h| h.lines().next())
    else {
        return (400, err_json("malformed-request"));
    };
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    // Split off the query string — routes match on the path half only.
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };
    // GET routes carry no body — device_id rides the query string.
    if method == "GET" {
        if path == CHALLENGES_PATH {
            return handle_challenges(state, query).await;
        }
        if path == DEVICE_STATUS_PATH {
            return handle_device_status(state, query).await;
        }
        if path == CLAIM_PATH || path == RESPONSE_PATH || path == ISSUE_PATH {
            return (405, err_json("method-not-allowed"));
        }
        return (404, err_json("unknown-path"));
    }
    // POST routes require a bounded Content-Length body.
    if method == "POST" {
        match content_length(head) {
            Some(len) if len <= MAX_REQUEST_BYTES && body.len() >= len => {}
            _ => return (400, err_json("malformed-request")),
        }
        let body = &body[..content_length(head).unwrap_or(body.len()).min(body.len())];
        if path == CLAIM_PATH {
            return claim(state, body).await;
        }
        if path == RESPONSE_PATH {
            return handle_response(state, body).await;
        }
        if path == ISSUE_PATH {
            return handle_issue(state, body).await;
        }
        return (404, err_json("unknown-path"));
    }
    // Anything else (PUT/DELETE/OPTIONS…) is refused, never proxied.
    if path == CLAIM_PATH
        || path == RESPONSE_PATH
        || path == ISSUE_PATH
        || path == CHALLENGES_PATH
        || path == DEVICE_STATUS_PATH
    {
        return (405, err_json("method-not-allowed"));
    }
    (404, err_json("unknown-path"))
}

/// Minimal query param lookup — values are percent-decoded for the small
/// unreserved set the phone emits; anything else stays encoded and fails
/// the downstream bounded check (fail closed, never echoed).
fn query_param<'a>(query: &'a str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => continue,
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn event_name(event: kiwi_pair::ChallengeEvent) -> &'static str {
    match event {
        kiwi_pair::ChallengeEvent::Unlock => "unlock",
        kiwi_pair::ChallengeEvent::DevicePairing => "device-pairing",
        kiwi_pair::ChallengeEvent::Recovery => "recovery",
        kiwi_pair::ChallengeEvent::ElevatedAction => "elevated-action",
    }
}

fn parse_event(s: &str) -> Option<kiwi_pair::ChallengeEvent> {
    match s {
        "unlock" => Some(kiwi_pair::ChallengeEvent::Unlock),
        "device-pairing" => Some(kiwi_pair::ChallengeEvent::DevicePairing),
        "recovery" => Some(kiwi_pair::ChallengeEvent::Recovery),
        "elevated-action" => Some(kiwi_pair::ChallengeEvent::ElevatedAction),
        _ => None,
    }
}

/// Phone wire: contract §4.2 snake_case `ChallengeData` JSON.
fn challenge_to_phone_json(c: &kiwi_pair::Challenge) -> String {
    let nonce_b64 = B64.encode(c.nonce);
    serde_json::json!({
        "schema_version": 1,
        "challenge_id": c.challenge_id,
        "device_id": c.device_id,
        "session_id": c.session_id,
        "event": event_name(c.event),
        "nonce_b64": nonce_b64,
        "issued_unix": c.issued_unix,
        "expires_unix": c.expires_unix,
    })
    .to_string()
}

fn challenge_row_to_phone_json(c: &kiwi_pair::ChallengeRow) -> String {
    let nonce_b64 = B64.encode(&c.nonce);
    serde_json::json!({
        "schema_version": 1,
        "challenge_id": c.challenge_id,
        "device_id": c.device_id,
        "session_id": c.session_id,
        "event": c.event,
        "nonce_b64": nonce_b64,
        "issued_unix": c.issued_unix,
        "expires_unix": c.expires_unix,
    })
    .to_string()
}

/// `GET /challenges?device_id=…` — open challenges only. Unknown device →
/// empty list (never an oracle: the phone learns nothing beyond its own
/// device's open rows, and an unknown id simply has none).
async fn handle_challenges(state: &AppState, query: &str) -> (u16, String) {
    let Some(device_id) = query_param(query, "device_id") else {
        return (400, err_json("malformed-request"));
    };
    if device_id.is_empty() || device_id.len() > 128 {
        return (400, err_json("invalid-request"));
    }
    let rows = match state
        .pair
        .lock()
        .await
        .open_challenges(&device_id, now_unix(), 64)
    {
        Ok(rows) => rows,
        Err(_) => return (400, err_json("invalid-request")),
    };
    let items: Vec<String> = rows.iter().map(challenge_row_to_phone_json).collect();
    (
        200,
        format!(
            "{{\"type\":\"kiwi-challenges\",\"challenges\":[{}],\"v\":1}}",
            items.join(",")
        ),
    )
}

/// `GET /device-status?device_id=…` — contract security-session §7 state.
async fn handle_device_status(state: &AppState, query: &str) -> (u16, String) {
    let Some(device_id) = query_param(query, "device_id") else {
        return (400, err_json("malformed-request"));
    };
    if device_id.is_empty() || device_id.len() > 128 {
        return (400, err_json("invalid-request"));
    }
    let status = match state.pair.lock().await.store().get_device(&device_id) {
        Ok(Some(d)) => d.status,
        Ok(None) => "unknown".to_string(),
        Err(_) => return (400, err_json("invalid-request")),
    };
    let status = match status.as_str() {
        "pending" | "active" | "suspended" | "revoked" => status,
        _ => "revoked".to_string(),
    };
    (
        200,
        format!(
            "{{\"type\":\"kiwi-device-status\",\"device_id\":\"{device_id}\",\"status\":\"{status}\",\"v\":1}}",
        ),
    )
}

/// `POST /issue {"device_id","event"}` — demo operator path: mint an
/// `unlock` (active devices) or `device-pairing` (pending devices) challenge
/// the phone can pull + approve. Recovery/elevated stay `unsupported-event`
/// until their flows land (pair.rs ruling).
async fn handle_issue(state: &AppState, body: &[u8]) -> (u16, String) {
    #[derive(serde::Deserialize)]
    struct Issue {
        device_id: String,
        event: String,
    }
    let Ok(v) = serde_json::from_slice::<Issue>(body) else {
        return (400, err_json("malformed-request"));
    };
    if v.device_id.is_empty() || v.device_id.len() > 128 {
        return (400, err_json("invalid-request"));
    }
    let Some(event) = parse_event(&v.event) else {
        return (400, err_json("invalid-request"));
    };
    if !matches!(
        event,
        kiwi_pair::ChallengeEvent::Unlock | kiwi_pair::ChallengeEvent::DevicePairing
    ) {
        return (400, err_json("unsupported-event"));
    }
    let nonce = match kiwi_pair::os_nonce() {
        Ok(n) => n,
        Err(_) => return (400, err_json("claim-failed")),
    };
    let challenge_id = new_id("chal");
    let session_id = state.boot_session_id.clone();
    let outcome = state.pair.lock().await.issue_challenge(
        kiwi_pair::ChallengeSpec {
            challenge_id,
            device_id: v.device_id,
            session_id,
            event,
            nonce,
        },
        now_unix(),
        kiwi_pair::CHALLENGE_TTL_SECS,
    );
    match outcome {
        Ok(challenge) => (200, challenge_to_phone_json(&challenge)),
        Err(e) => {
            let code = match e {
                kiwi_pair::PairError::DeviceNotFound(_) => "not-found",
                kiwi_pair::PairError::DeviceRevoked(_) => "device-revoked",
                kiwi_pair::PairError::DeviceNotActive(_) => "device-not-active",
                kiwi_pair::PairError::ReplayDetected => "replay-detected",
                _ => "claim-failed",
            };
            let status = if code == "not-found" { 404 } else { 400 };
            (status, err_json(code))
        }
    }
}

/// `POST /response` — phone `ChallengeResponseData` (contract §6.2/§6.3).
/// Mirrors the IPC audit contract: approve → verify + `challenge-approved`
/// (+ `device-paired` on pairing activation, trust unlock on `unlock`);
/// deny → `challenge-denied` without consuming; every failure audits
/// `challenge-verification-failed err=<ChallengeError|code>`.
async fn handle_response(state: &AppState, body: &[u8]) -> (u16, String) {
    #[derive(serde::Deserialize)]
    struct Resp {
        challenge_id: String,
        device_id: String,
        session_id: String,
        event: String,
        #[serde(default)]
        signature_b64: String,
        #[serde(default)]
        decision: Option<String>,
    }
    let Ok(v) = serde_json::from_slice::<Resp>(body) else {
        return (400, err_json("malformed-request"));
    };
    if v.challenge_id.is_empty()
        || v.challenge_id.len() > 128
        || v.device_id.is_empty()
        || v.device_id.len() > 128
        || v.session_id.is_empty()
        || v.session_id.len() > 256
    {
        return (400, err_json("invalid-request"));
    }
    let Some(event) = parse_event(&v.event) else {
        return (400, err_json("invalid-request"));
    };
    if matches!(
        event,
        kiwi_pair::ChallengeEvent::Recovery | kiwi_pair::ChallengeEvent::ElevatedAction
    ) {
        return (400, err_json("unsupported-event"));
    }
    let deny = match v.decision.as_deref() {
        None | Some("approve") => false,
        Some("deny") => true,
        Some(_) => return (400, err_json("invalid-request")),
    };
    let now = now_unix();
    if deny {
        let resp = kiwi_pair::ChallengeResponse {
            challenge_id: v.challenge_id.clone(),
            device_id: v.device_id.clone(),
            session_id: v.session_id.clone(),
            event,
            signature: Vec::new(),
        };
        if let Err(e) = state.pair.lock().await.deny_response(&resp, now) {
            return audit_http_failure(state, e, event).await;
        }
        let _ = state.audit.lock().await.record(
            "challenge-denied",
            &format!("event={} device={}", event_name(event), v.device_id),
            now,
        );
        return (
            200,
            "{\"type\":\"kiwi-challenge-result\",\"ok\":true,\"decision\":\"deny\",\"v\":1}".to_string(),
        );
    }
    let Ok(signature) = B64.decode(v.signature_b64.as_bytes()) else {
        return (400, err_json("invalid-request"));
    };
    if signature.is_empty() || signature.len() > 512 {
        return (400, err_json("invalid-request"));
    }
    let resp = kiwi_pair::ChallengeResponse {
        challenge_id: v.challenge_id.clone(),
        device_id: v.device_id.clone(),
        session_id: v.session_id.clone(),
        event,
        signature,
    };
    if let Err(e) = state.pair.lock().await.verify_response(&resp, now) {
        return audit_http_failure(state, e, event).await;
    }
    let _ = state.audit.lock().await.record(
        "challenge-approved",
        &format!("event={} device={}", event_name(event), v.device_id),
        now,
    );
    if event == kiwi_pair::ChallengeEvent::DevicePairing {
        let _ = state
            .audit
            .lock()
            .await
            .record("device-paired", &v.device_id, now);
    }
    if event == kiwi_pair::ChallengeEvent::Unlock {
        let _ = state.trust.lock().await.attempt_unlock(&state.policy, true);
    }
    (
        200,
        "{\"type\":\"kiwi-challenge-result\",\"ok\":true,\"decision\":\"approve\",\"v\":1}".to_string(),
    )
}

async fn audit_http_failure(
    state: &AppState,
    e: kiwi_pair::PairError,
    event: kiwi_pair::ChallengeEvent,
) -> (u16, String) {
    let reason = if let kiwi_pair::PairError::Challenge(ce) = &e {
        format!("{ce:?}")
    } else {
        String::new()
    };
    let (status, code) = match &e {
        kiwi_pair::PairError::Challenge(ce) => match ce {
            kiwi_core::challenge::ChallengeError::UnknownChallenge => (404, "unknown-challenge"),
            kiwi_core::challenge::ChallengeError::Expired => (400, "challenge-expired"),
            kiwi_core::challenge::ChallengeError::AlreadyConsumed => (400, "already-consumed"),
            kiwi_core::challenge::ChallengeError::BindingMismatch => (400, "binding-mismatch"),
            kiwi_core::challenge::ChallengeError::InvalidSignature => (400, "invalid-signature"),
        },
        kiwi_pair::PairError::DeviceNotFound(_) => (404, "not-found"),
        kiwi_pair::PairError::DeviceRevoked(_) => (400, "device-revoked"),
        kiwi_pair::PairError::DeviceNotActive(_) => (400, "device-not-active"),
        kiwi_pair::PairError::ReplayDetected => (400, "replay-detected"),
        _ => (400, "claim-failed"),
    };
    let reason = if reason.is_empty() {
        code.to_string()
    } else {
        reason
    };
    let _ = state.audit.lock().await.record(
        "challenge-verification-failed",
        &format!("err={reason} event={}", event_name(event)),
        now_unix(),
    );
    (status, err_json(code))
}

fn err_json(code: &str) -> String {
    format!("{{\"type\":\"kiwi-pairing-error\",\"error\":\"{code}\",\"v\":1}}")
}

/// `kiwi-pairing-hello` → `claim_ticket_and_register` →
/// `kiwi-pairing-registered`. The label is ticket-bound; a `device_label`
/// field is accepted for forward-compat but ignored.
async fn claim(state: &AppState, body: &[u8]) -> (u16, String) {
    #[derive(serde::Deserialize)]
    struct Hello {
        #[serde(rename = "type")]
        kind: String,
        pairing_ticket: String,
        device_public_key_b64: String,
        #[serde(default)]
        keystore_ref: Option<String>,
    }
    let Ok(v) = serde_json::from_slice::<Hello>(body) else {
        return (400, err_json("malformed-request"));
    };
    if v.kind != "kiwi-pairing-hello" {
        return (400, err_json("unexpected-type"));
    }
    // Ed25519 public key: canonical padded std Base64 of exactly 32 bytes —
    // same strictness as the desktop key check (§9d.2).
    let Ok(key) = B64.decode(v.device_public_key_b64.as_bytes()) else {
        return (400, err_json("key-invalid"));
    };
    if key.len() != 32 {
        return (400, err_json("key-invalid"));
    }
    let device_id = new_id("dev");
    let now = now_unix();
    let outcome = state.pair.lock().await.claim_ticket_and_register(
        &v.pairing_ticket,
        &device_id,
        kiwi_pair::KeyAlgorithm::Ed25519,
        &key,
        v.keystore_ref.as_deref(),
        now,
    );
    match outcome {
        Ok(_) => {
            // The claim is the pivotal security event — audit the outcome,
            // never the ticket/key bytes.
            let _ = state.audit.lock().await.record(
                "pair-ticket-claimed",
                &format!("device_id={device_id}"),
                now,
            );
            // Contract §3.2 step 3: the fresh `pending` device immediately
            // gets its `device-pairing` activation challenge so the phone's
            // `pullChallenges` finds it without a second operator step.
            // A nonce/issue failure here never fails the claim itself — the
            // operator can re-issue via POST /issue.
            if let Ok(nonce) = kiwi_pair::os_nonce() {
                let _ = state.pair.lock().await.issue_challenge(
                    kiwi_pair::ChallengeSpec {
                        challenge_id: new_id("chal"),
                        device_id: device_id.clone(),
                        session_id: state.boot_session_id.clone(),
                        event: kiwi_pair::ChallengeEvent::DevicePairing,
                        nonce,
                    },
                    now,
                    kiwi_pair::CHALLENGE_TTL_SECS,
                );
            }
            (
                200,
                format!(
                    "{{\"type\":\"kiwi-pairing-registered\",\"device_id\":\"{device_id}\",\"issued_unix\":{now},\"v\":1}}"
                ),
            )
        }
        Err(e) => {
            // Stable codes, no detail — the ticket field is never echoed.
            let (status, code) = match e {
                kiwi_pair::PairError::InvalidTicket
                | kiwi_pair::PairError::TicketConsumed
                | kiwi_pair::PairError::TicketExpired => (400, "ticket-invalid"),
                kiwi_pair::PairError::BadKeyLength(_)
                | kiwi_pair::PairError::UnsupportedAlgorithm(_) => (400, "key-invalid"),
                kiwi_pair::PairError::DeviceExists(_)
                | kiwi_pair::PairError::DeviceLabelConflict(_) => (409, "device-conflict"),
                kiwi_pair::PairError::InvalidField { .. } => (400, "invalid-request"),
                _ => (400, "claim-failed"),
            };
            (status, err_json(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pair::pair_begin_impl;
    use crate::state::AppState;

    fn test_state(tag: &str) -> Arc<AppState> {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-pairlisten-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut s = AppState::open_test(dir).unwrap();
        s.provision_test_pair_channel("http://127.0.0.1:1/pair");
        Arc::new(s)
    }

    fn b64_32(byte: u8) -> String {
        B64.encode([byte; 32])
    }

    /// Post `body` to a bound listener running `serve`; return the reply.
    /// Client side is tokio too — a blocking std socket here would starve
    /// the single-threaded test runtime's spawned accept loop.
    async fn post(state: &Arc<AppState>, body: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(state.clone(), listener));
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(
            format!(
                "POST {CLAIM_PATH} HTTP/1.1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        conn.read_to_end(&mut reply).await.unwrap();
        String::from_utf8_lossy(&reply).into_owned()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn claim_roundtrip_over_real_socket() {
        let state = test_state("rt");
        let view = pair_begin_impl(&state, "Phone").await.unwrap();
        let body = format!(
            "{{\"type\":\"kiwi-pairing-hello\",\"pairing_ticket\":\"{}\",\"device_public_key_b64\":\"{}\"}}",
            view.ticket,
            b64_32(7)
        );
        let reply = post(&state, &body).await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(
            reply.contains("\"type\":\"kiwi-pairing-registered\""),
            "{reply}"
        );
        assert!(reply.contains("\"device_id\":\"dev-"), "{reply}");
        // The device is registered pending via the engine's atomic path.
        let devices = state.pair.lock().await.list_devices(10).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "Phone");
        // And the ticket reports claimed through the renderer-visible path.
        let s = crate::commands::pair::pair_status_impl(&state, &view.ticket)
            .await
            .unwrap();
        assert_eq!(s.state, "claimed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_and_malformed_claims_fail_closed() {
        let state = test_state("bad");
        // Unknown ticket → fixed ticket-invalid, never an echo.
        let reply = post(
            &state,
            &format!(
                "{{\"type\":\"kiwi-pairing-hello\",\"pairing_ticket\":\"{}\",\"device_public_key_b64\":\"{}\"}}",
                "A".repeat(43),
                b64_32(1)
            ),
        )
        .await;
        assert!(reply.contains("\"error\":\"ticket-invalid\""), "{reply}");
        // Malformed JSON → malformed-request.
        let reply = post(&state, "not json").await;
        assert!(reply.contains("\"error\":\"malformed-request\""), "{reply}");
        // Wrong route → unknown-path.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(state.clone(), listener));
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(b"GET /other HTTP/1.1\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        conn.read_to_end(&mut reply).await.unwrap();
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        assert!(reply.contains("\"error\":\"unknown-path\""), "{reply}");
    }

    async fn get(state: &Arc<AppState>, target: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(state.clone(), listener));
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(
            format!("GET {target} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        conn.read_to_end(&mut reply).await.unwrap();
        String::from_utf8_lossy(&reply).into_owned()
    }

    async fn post_path(state: &Arc<AppState>, path: &str, body: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(state.clone(), listener));
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(
            format!(
                "POST {path} HTTP/1.1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        conn.read_to_end(&mut reply).await.unwrap();
        String::from_utf8_lossy(&reply).into_owned()
    }

    fn canonical_for(row: &kiwi_pair::ChallengeRow) -> Vec<u8> {
        fn push_field(v: &mut Vec<u8>, field: &[u8]) {
            v.extend_from_slice(&(field.len() as u32).to_be_bytes());
            v.extend_from_slice(field);
        }
        let mut v = Vec::with_capacity(256);
        push_field(&mut v, b"kiwi-challenge-v1");
        push_field(&mut v, row.challenge_id.as_bytes());
        push_field(&mut v, row.device_id.as_bytes());
        push_field(&mut v, row.session_id.as_bytes());
        let tag: u8 = match row.event.as_str() {
            "unlock" => 0x01,
            "device-pairing" => 0x02,
            "recovery" => 0x03,
            _ => 0x04,
        };
        v.push(tag);
        v.extend_from_slice(&row.nonce);
        v.extend_from_slice(&row.issued_unix.to_be_bytes());
        v.extend_from_slice(&row.expires_unix.to_be_bytes());
        v
    }

    /// USB bring-up roundtrip: claim → auto-issued device-pairing challenge
    /// is pullable → signed approve over the socket activates the device.
    #[tokio::test(flavor = "current_thread")]
    async fn usb_claim_pull_approve_roundtrip() {
        let state = test_state("usb");
        let view = pair_begin_impl(&state, "UsbPhone").await.unwrap();
        let signer = kiwi_pair::DeviceSigner::from_seed(&[11u8; 32]);
        let pub_b64 = B64.encode(signer.public_key());
        let reply = post(
            &state,
            &format!(
                "{{\"type\":\"kiwi-pairing-hello\",\"pairing_ticket\":\"{}\",\"device_public_key_b64\":\"{pub_b64}\"}}",
                view.ticket,
            ),
        )
        .await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let device_id: String = {
            let body = reply.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            v.get("device_id").and_then(|s| s.as_str()).unwrap().to_string()
        };
        // The claim auto-issued the activation challenge — pull finds it.
        let pulled = get(&state, &format!("/challenges?device_id={device_id}")).await;
        assert!(pulled.starts_with("HTTP/1.1 200"), "{pulled}");
        assert!(pulled.contains("\"event\":\"device-pairing\""), "{pulled}");
        assert!(pulled.contains(&device_id), "{pulled}");
        // Status is pending until the signed approve lands.
        let status = get(&state, &format!("/device-status?device_id={device_id}")).await;
        assert!(status.contains("\"status\":\"pending\""), "{status}");
        // Sign the canonical bytes with the real Ed25519 key and approve.
        // (No nested locks: the open-challenge id is read first, the guard
        // is dropped, then the full row is fetched.)
        let challenge_id = state
            .pair
            .lock()
            .await
            .open_challenges(&device_id, crate::state::now_unix(), 10)
            .unwrap()[0]
            .challenge_id
            .clone();
        let row = state
            .pair
            .lock()
            .await
            .store()
            .get_challenge(&challenge_id)
            .unwrap()
            .unwrap();
        let sig = signer.sign(&canonical_for(&row));
        let sig_b64 = B64.encode(sig);
        let approve = post_path(
            &state,
            "/response",
            &format!(
                "{{\"challenge_id\":\"{}\",\"device_id\":\"{device_id}\",\"session_id\":\"{}\",\"event\":\"device-pairing\",\"decision\":\"approve\",\"signature_b64\":\"{sig_b64}\"}}",
                row.challenge_id, row.session_id,
            ),
        )
        .await;
        assert!(approve.starts_with("HTTP/1.1 200"), "{approve}");
        assert!(approve.contains("\"decision\":\"approve\""), "{approve}");
        let status = get(&state, &format!("/device-status?device_id={device_id}")).await;
        assert!(status.contains("\"status\":\"active\""), "{status}");
        // Unknown challenge refuses fail-closed.
        let bad = post_path(
            &state,
            "/response",
            "{\"challenge_id\":\"chal-ghost\",\"device_id\":\"dev-ghost\",\"session_id\":\"boot-x\",\"event\":\"unlock\",\"decision\":\"approve\",\"signature_b64\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}",
        )
        .await;
        assert!(bad.contains("unknown-challenge") || bad.contains("not-found"), "{bad}");
    }
}
