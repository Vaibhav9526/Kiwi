//! LAN pair-claim listener (T-304) — the network half of the §3.2 pairing
//! channel: the phone POSTs its ticket + device key and the desktop hands
//! the claim to `PairEngine::claim_ticket_and_register`.
//!
//! # Transport posture (pending ruling)
//!
//! authenticator.md §3.2 requires a TLS-protected channel (`wss://`,
//! Agent-6 recommendation) — **still unratified by Lead** (open item §10.2
//! #2). This module is therefore a *plaintext* HTTP listener gated behind
//! `KIWI_PAIR_LISTEN=1` — a development seam so the claim path is real and
//! testable; it is not the shipping transport. The QR `desktop_endpoint`
//! honestly advertises `http://`, and the doc'd TLS upgrade replaces the
//! socket layer without touching the claim semantics below.
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
/// Whole-request byte cap (headers + body).
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Per-connection read deadline.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Claim path — the only route this socket serves.
const CLAIM_PATH: &str = "/pair";

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

/// Bind the dev listener (caller holds the returned std socket until the
/// tokio runtime exists — `run()` converts it via [`serve`]).
pub fn bind() -> Option<(std::net::TcpListener, String)> {
    if !listen_enabled() {
        return None;
    }
    let listener = std::net::TcpListener::bind("0.0.0.0:0").ok()?;
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
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
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
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method != "POST" {
        return (405, err_json("method-not-allowed"));
    }
    if path != CLAIM_PATH {
        return (404, err_json("unknown-path"));
    }
    match content_length(head) {
        Some(len) if len <= MAX_REQUEST_BYTES && body.len() >= len => {}
        _ => return (400, err_json("malformed-request")),
    }
    claim(state, body).await
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
        assert!(reply.starts_with("HTTP/1.1 405"), "{reply}");
    }
}
