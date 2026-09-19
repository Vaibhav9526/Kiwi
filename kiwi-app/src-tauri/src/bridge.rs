//! kiwi-admin bridge — the enforcement loop (admin-api §10 evaluate-outbound,
//! §11 mailflow emit).
//!
//! Localhost-only by construction — the URL parser refuses anything that is
//! not `http://{localhost,127.0.0.1,[::1]}:<port>` (SECURITY.md B5). No new
//! dependency: a small HTTP/1.1 POST over tokio TcpStream with a hard
//! timeout and bounded response is easier to audit than pulling an HTTP
//! stack for two loopback endpoints.
//!
//! Semantics (contract):
//! - `overall == "block"` must stop the send; a transport/parse failure means
//!   "policy check unavailable" and the caller holds the send (fail closed) —
//!   `evaluate_outbound` reports `Err`, never a silent allow.
//! - Mailflow events are emitted post-send-attempt (all recipients, verdict
//!   advisory) and post-receive-sync (per message). Emit failures never fail
//!   the operation — events queue in `AppState.mailflow_pending` and retry on
//!   the next emission opportunity (bounded, drop-oldest).
//! - No endpoint configured at all (no org binding, no `KIWI_ADMIN_URL` env)
//!   is the local-first dev case: the caller warn-logs once and proceeds.
//!
//! Dev-auth (admin-api §12): requests carry `x-kiwi-subject`/`x-kiwi-roles`/
//! `x-kiwi-org` headers. Header actors are a scaffold — never secure, never
//! allowed past loopback.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, OrgBinding};

const TIMEOUT: Duration = Duration::from_secs(4);
const MAX_RESPONSE: usize = 64 * 1024;
/// Bound on locally-queued mailflow events awaiting a reachable admin service.
const MAX_PENDING_EVENTS: usize = 512;

#[derive(Debug, Clone, Deserialize)]
pub struct BridgeReason {
    pub code: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BridgeResult {
    pub recipient: String,
    pub verdict: String,
    #[serde(default)]
    pub reasons: Vec<BridgeReason>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BridgeVerdict {
    /// `"allow" | "warn" | "block"`.
    pub overall: String,
    #[serde(default)]
    pub results: Vec<BridgeResult>,
}

/// Resolved admin-service location: org binding (index.json) wins, then the
/// `KIWI_ADMIN_URL`/`KIWI_ADMIN_ORG` env vars (dev convenience). `org_id`
/// may be `None` — outbound policy evaluation requires it, inbound mailflow
/// events accept null.
#[derive(Debug, Clone)]
pub struct AdminEndpoint {
    pub base_url: String,
    pub org_id: Option<String>,
}

fn err(code: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError::new(code, msg)
}

/// Pure resolver — testable without touching process env.
/// `env` is `(KIWI_ADMIN_URL, KIWI_ADMIN_ORG)` as already read by the caller.
/// A non-loopback URL (from either source) is refused — treated as absent
/// and warned about by the caller.
pub fn resolve_endpoint_with(
    binding: Option<&OrgBinding>,
    env: Option<(String, Option<String>)>,
) -> Option<AdminEndpoint> {
    if let Some(b) = binding {
        if check_loopback(&b.base_url).is_ok() {
            return Some(AdminEndpoint {
                base_url: b.base_url.clone(),
                org_id: Some(b.org_id.clone()),
            });
        }
        // Bound org with a non-loopback URL is a config bug — refuse.
        return None;
    }
    let (url, org) = env?;
    let url = url.trim().to_string();
    if url.is_empty() || check_loopback(&url).is_err() {
        return None;
    }
    Some(AdminEndpoint {
        base_url: url,
        org_id: org
            .filter(|o| !o.trim().is_empty())
            .map(|o| o.trim().to_string()),
    })
}

/// Production resolver: index binding first, then process env.
pub async fn resolve_endpoint(state: &AppState) -> Option<AdminEndpoint> {
    let binding = state.index.lock().await.org.clone();
    let env = std::env::var("KIWI_ADMIN_URL")
        .ok()
        .map(|u| (u, std::env::var("KIWI_ADMIN_ORG").ok()));
    resolve_endpoint_with(binding.as_ref(), env)
}

/// Validate a base_url at config time (`kiwi_set_org_binding`).
pub fn check_loopback(base_url: &str) -> CmdResult<()> {
    parse_loopback(base_url).map(|_| ())
}

/// Parse `http://<host>:<port>` enforcing the loopback allowlist.
fn parse_loopback(base_url: &str) -> CmdResult<(String, u16)> {
    let rest = base_url.strip_prefix("http://").ok_or_else(|| {
        err(
            "invalid-input",
            "admin base_url must be http://<loopback>:<port>",
        )
    })?;
    let hostport = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, p) = rest
            .split_once(']')
            .ok_or_else(|| err("invalid-input", "bad IPv6 base_url"))?;
        (
            h.to_string(),
            p.strip_prefix(':').unwrap_or("80").to_string(),
        )
    } else {
        let (h, p) = hostport
            .rsplit_once(':')
            .ok_or_else(|| err("invalid-input", "base_url needs host:port"))?;
        (h.to_string(), p.to_string())
    };
    let port: u16 = port
        .parse()
        .map_err(|_| err("invalid-input", "bad port in base_url"))?;
    let host_lc = host.to_ascii_lowercase();
    if !matches!(host_lc.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return Err(err(
            "policy-unavailable",
            "admin bridge is localhost-only; refusing non-loopback base_url",
        ));
    }
    Ok((host, port))
}

/// One bounded POST against the admin service. Carries the dev-auth headers
/// (§12) — `x-kiwi-org` is sent whenever the org id is known.
async fn post_json(
    base_url: &str,
    org_id: Option<&str>,
    path: &str,
    body: &[u8],
) -> CmdResult<String> {
    let (host, port) = parse_loopback(base_url)?;
    let org_header = match org_id {
        Some(o) => format!("x-kiwi-org: {o}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n\
         x-kiwi-subject: kiwi-client\r\nx-kiwi-roles: org_admin\r\n{org_header}\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let resp_bytes = tokio::time::timeout(TIMEOUT, async {
        let mut s = TcpStream::connect((host.as_str(), port)).await?;
        s.write_all(req.as_bytes()).await?;
        s.write_all(body).await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_RESPONSE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bridge response exceeds bound",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, std::io::Error>(buf)
    })
    .await
    .map_err(|_| err("policy-unavailable", "admin bridge timeout"))?
    .map_err(|e| {
        err(
            "policy-unavailable",
            format!("admin bridge unreachable: {e}"),
        )
    })?;

    let text = String::from_utf8_lossy(&resp_bytes);
    let mut split = text.splitn(2, "\r\n\r\n");
    let head = split.next().unwrap_or("");
    let body = split.next().unwrap_or("");
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err("policy-unavailable", "malformed bridge response"))?;
    if !(200..300).contains(&status) {
        return Err(err(
            "policy-unavailable",
            format!("admin bridge returned {status}"),
        ));
    }
    Ok(body.to_string())
}

/// Evaluate recipients against the org's enabled outbound policies.
/// `tls_version` is the OBSERVED negotiated TLS of the sending connection
/// (`"tls1.3"` spellings, `None` when unobserved — warns, never blocks).
pub async fn evaluate_outbound(
    endpoint: &AdminEndpoint,
    sender: &str,
    recipients: &[String],
    tls_version: Option<&str>,
) -> CmdResult<BridgeVerdict> {
    let org_id = endpoint
        .org_id
        .as_deref()
        .ok_or_else(|| err("policy-unavailable", "admin endpoint has no org id"))?;
    let body = serde_json::json!({
        "sender": sender,
        "recipients": recipients,
        "tlsVersion": tls_version,
    });
    let body_bytes =
        serde_json::to_vec(&body).map_err(|e| err("internal", format!("bridge encode: {e}")))?;
    let path = format!("/api/v1/orgs/{org_id}/policies/evaluate-outbound");
    let text = post_json(&endpoint.base_url, Some(org_id), &path, &body_bytes).await?;
    serde_json::from_str::<BridgeVerdict>(&text)
        .map_err(|e| err("policy-unavailable", format!("bridge payload parse: {e}")))
}

/// Map an observed rustls protocol-version debug name to the contract
/// `tlsVersion` label used by the admin API (admin-api §10 canonical aliases).
pub fn tls_version_label(debug_name: &str) -> &'static str {
    match debug_name {
        "TLSv1_3" => "tls1.3",
        "TLSv1_2" => "tls1.2",
        "TLSv1_1" => "tls1.1",
        "TLSv1" | "TLSv1_0" => "tls1.0",
        "SSLv3" | "SSLv3_0" => "ssl3",
        _ => "unknown",
    }
}

// --- §11 mailflow events ---------------------------------------------------

/// Wire shape per admin-api §6 — snake_case, metadata only (no subject,
/// no body, ever).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailflowEvent {
    pub id: String,
    pub org_id: Option<String>,
    /// "outbound" | "inbound".
    pub direction: String,
    pub sender: String,
    pub recipient: String,
    /// Message time, unix seconds.
    pub ts: i64,
    pub message_id: Option<String>,
    /// Observed transport TLS label or null (unobserved).
    pub tls_version: Option<String>,
    /// "clean | warn | suspicious | tls-mismatch | unknown" — observed facts
    /// only, never inferred from the policy verdict.
    pub security_status: String,
    /// "allow | warn | block | unknown" — advisory only.
    pub policy_verdict: String,
}

/// §11 `buildSendAttemptEvents`: one outbound event per recipient.
/// `per_recipient` verdicts come from the §10 bridge result; anything
/// outside allow|warn|block normalizes to "unknown".
pub fn build_send_attempt_events(
    org_id: &str,
    sender: &str,
    per_recipient: &[(&str, &str)],
    tls_version: Option<&str>,
    security_status: &str,
    message_id: Option<&str>,
    ts: i64,
) -> Vec<MailflowEvent> {
    per_recipient
        .iter()
        .map(|(recipient, verdict)| MailflowEvent {
            id: crate::state::new_id("mf"),
            org_id: Some(org_id.to_string()),
            direction: "outbound".to_string(),
            sender: sender.to_string(),
            recipient: (*recipient).to_string(),
            ts,
            message_id: message_id.map(str::to_string),
            tls_version: tls_version.map(str::to_string),
            security_status: security_status.to_string(),
            policy_verdict: match *verdict {
                "allow" | "warn" | "block" => (*verdict).to_string(),
                _ => "unknown".to_string(),
            },
        })
        .collect()
}

/// §11 `buildReceivedEvent`: one inbound event per received message.
/// `org_id` may be null inbound. `policy_verdict` is always "unknown".
pub fn build_received_event(
    org_id: Option<&str>,
    sender: &str,
    recipient: &str,
    tls_version: Option<&str>,
    security_status: &str,
    message_id: Option<&str>,
    ts: i64,
) -> MailflowEvent {
    MailflowEvent {
        id: crate::state::new_id("mf"),
        org_id: org_id.map(str::to_string),
        direction: "inbound".to_string(),
        sender: sender.to_string(),
        recipient: recipient.to_string(),
        ts,
        message_id: message_id.map(str::to_string),
        tls_version: tls_version.map(str::to_string),
        security_status: security_status.to_string(),
        policy_verdict: "unknown".to_string(),
    }
}

/// Deterministic §6 `security_status` from observed facts: the severities
/// of the findings a session produced. Unknown when nothing was observed —
/// never inferred from the policy verdict.
pub fn security_status_label(
    observed: bool,
    severities: impl IntoIterator<Item = kiwi_forensics::findings::Severity>,
) -> &'static str {
    use kiwi_forensics::findings::Severity;
    if !observed {
        return "unknown";
    }
    let worst = severities
        .into_iter()
        .map(|s| match s {
            Severity::Critical | Severity::High => 2u8,
            Severity::Medium | Severity::Low => 1,
            Severity::Info => 0,
        })
        .max()
        .unwrap_or(0);
    match worst {
        2 => "suspicious",
        1 => "warn",
        _ => "clean",
    }
}

/// POST one event to `/api/v1/mailflow/events` (single-event ingest per §3).
async fn ingest_event(endpoint: &AdminEndpoint, ev: &MailflowEvent) -> CmdResult<()> {
    let body =
        serde_json::to_vec(ev).map_err(|e| err("internal", format!("mailflow encode: {e}")))?;
    post_json(
        &endpoint.base_url,
        endpoint.org_id.as_deref(),
        "/api/v1/mailflow/events",
        &body,
    )
    .await
    .map(|_| ())
}

/// Emit events, retrying previously-queued events first (FIFO). Emit
/// failures NEVER fail the caller — on the first transport failure the
/// failed event and every un-attempted remainder requeue in
/// `mailflow_pending` (bounded, drop-oldest) for the next opportunity.
pub async fn emit_events(state: &AppState, endpoint: &AdminEndpoint, events: Vec<MailflowEvent>) {
    let mut batch: Vec<MailflowEvent> = {
        let mut q = state.mailflow_pending.lock().await;
        q.drain(..).collect()
    };
    if batch.is_empty() && events.is_empty() {
        return;
    }
    batch.extend(events);
    let mut pending = batch.into_iter();
    let mut requeue: Vec<MailflowEvent> = Vec::new();
    let mut failed = false;
    for ev in pending.by_ref() {
        match ingest_event(endpoint, &ev).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[kiwi-app] mailflow emit deferred: {}", e.message);
                requeue.push(ev);
                failed = true;
                break;
            }
        }
    }
    if failed {
        requeue.extend(pending);
    }
    if !requeue.is_empty() {
        let mut q = state.mailflow_pending.lock().await;
        for ev in requeue {
            if q.len() >= MAX_PENDING_EVENTS {
                q.pop_front();
            }
            q.push_back(ev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_enforced() {
        assert!(parse_loopback("http://127.0.0.1:8787").is_ok());
        assert!(parse_loopback("http://localhost:8787").is_ok());
        assert!(parse_loopback("http://[::1]:8787").is_ok());
        assert!(parse_loopback("https://example.com:443").is_err());
        assert!(parse_loopback("http://evil.test:8787").is_err());
        assert!(parse_loopback("http://169.254.169.254:80").is_err());
    }

    #[test]
    fn endpoint_prefers_binding_then_env_then_none() {
        let bound = OrgBinding {
            org_id: "org-1".into(),
            base_url: "http://127.0.0.1:8471".into(),
        };
        // Binding wins over env.
        let ep = resolve_endpoint_with(
            Some(&bound),
            Some(("http://127.0.0.1:9999".into(), Some("org-x".into()))),
        )
        .unwrap();
        assert_eq!(ep.org_id.as_deref(), Some("org-1"));
        assert_eq!(ep.base_url, "http://127.0.0.1:8471");
        // Env fallback.
        let ep =
            resolve_endpoint_with(None, Some((" http://127.0.0.1:8471 ".into(), None))).unwrap();
        assert_eq!(ep.base_url, "http://127.0.0.1:8471");
        assert!(ep.org_id.is_none());
        // Nothing configured.
        assert!(resolve_endpoint_with(None, None).is_none());
        // Non-loopback refused, either source.
        assert!(resolve_endpoint_with(None, Some(("http://10.0.0.9:8471".into(), None))).is_none());
        let bad = OrgBinding {
            org_id: "org-1".into(),
            base_url: "https://evil.example".into(),
        };
        assert!(resolve_endpoint_with(Some(&bad), None).is_none());
    }

    #[test]
    fn send_attempt_events_match_wire_shape() {
        let events = build_send_attempt_events(
            "org-1",
            "alice@acme.test",
            &[
                ("b@x.test", "allow"),
                ("c@y.test", "block"),
                ("d@z.test", "bogus"),
            ],
            Some("tls1.3"),
            "clean",
            Some("<msg-1>"),
            1_758_000_000,
        );
        assert_eq!(events.len(), 3);
        let v: serde_json::Value = serde_json::to_value(&events[1]).unwrap();
        assert_eq!(v["direction"], "outbound");
        assert_eq!(v["org_id"], "org-1");
        assert_eq!(v["sender"], "alice@acme.test");
        assert_eq!(v["recipient"], "c@y.test");
        assert_eq!(v["policy_verdict"], "block");
        assert_eq!(v["tls_version"], "tls1.3");
        assert_eq!(v["security_status"], "clean");
        assert_eq!(v["message_id"], "<msg-1>");
        assert_eq!(v["ts"], 1_758_000_000);
        assert!(v["id"].as_str().unwrap().starts_with("mf-"));
        // Unrecognized verdicts normalize to "unknown" — never pass through.
        assert_eq!(events[2].policy_verdict, "unknown");
        // §6: metadata only — no subject/body field exists.
        assert!(v.get("subject").is_none() && v.get("body").is_none());
    }

    #[test]
    fn received_event_allows_null_org_and_unknown_verdict() {
        let ev = build_received_event(
            None,
            "ext@sender.test",
            "me@acme.test",
            None,
            "warn",
            None,
            42,
        );
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["direction"], "inbound");
        assert!(v["org_id"].is_null());
        assert!(v["tls_version"].is_null());
        assert_eq!(v["policy_verdict"], "unknown");
        assert_eq!(v["security_status"], "warn");
    }

    #[test]
    fn security_status_maps_findings_not_verdicts() {
        use kiwi_forensics::findings::Severity;
        assert_eq!(security_status_label(false, []), "unknown");
        assert_eq!(security_status_label(true, []), "clean");
        assert_eq!(
            security_status_label(true, [Severity::Low, Severity::Medium]),
            "warn"
        );
        assert_eq!(
            security_status_label(true, [Severity::Info, Severity::Critical]),
            "suspicious"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_queues_when_admin_unreachable() {
        let dir = std::env::temp_dir().join(format!("kiwi-bridge-test-{}", std::process::id()));
        let state = AppState::open_test(dir.clone()).unwrap();
        // A definitely-closed port: bind then drop.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let ep = AdminEndpoint {
            base_url: format!("http://127.0.0.1:{port}"),
            org_id: Some("org-1".into()),
        };
        let ev = build_received_event(None, "a@x", "b@y", None, "unknown", None, 1);
        emit_events(&state, &ep, vec![ev]).await; // must not fail — queues
        assert_eq!(state.mailflow_pending.lock().await.len(), 1);
        let ev2 = build_received_event(None, "a@x", "b@y", None, "unknown", None, 2);
        emit_events(&state, &ep, vec![ev2]).await;
        assert_eq!(state.mailflow_pending.lock().await.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
