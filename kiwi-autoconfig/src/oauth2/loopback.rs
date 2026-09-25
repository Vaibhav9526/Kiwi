//! Loopback redirect listener for the authorization-code grant
//! (RFC 8252 §7.3): binds `127.0.0.1` on an ephemeral port — never a
//! routable interface — and captures the provider's `GET /?code=…&state=…`
//! redirect. Implemented on `std::net` so the module carries no async
//! runtime requirement; `wait` is blocking by contract (callers on async
//! runtimes use `spawn_blocking`).
//!
//! Hardening rules (contract §7): loopback bind only, one bounded read per
//! connection (request line + headers up to [`MAX_REQUEST_LINE`]), a fixed
//! response page carrying no grant material, non-redirect requests
//! (favicon, probes, malformed lines) acknowledged and ignored until the
//! deadline.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use super::{OAuthError, RedirectOutcome};

/// Cap on bytes read from one loopback connection (request line +
/// headers). Redirect queries are < 1 KiB in practice.
pub(crate) const MAX_REQUEST_LINE: usize = 8 * 1024;

/// Poll quantum while waiting on the nonblocking listener.
const ACCEPT_POLL_MS: u64 = 25;

/// Per-connection socket timeouts — a stalled peer cannot hold the grant.
const CONN_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A bound `127.0.0.1:port` listener owned by a `PendingGrant::Loopback`.
/// Constructed via [`OAuthFlow::begin`](super::OAuthFlow::begin) —
/// standalone construction is for tests.
#[derive(Debug)]
pub struct LoopbackListener {
    inner: TcpListener,
}

impl LoopbackListener {
    /// Bind `127.0.0.1` on an OS-assigned port.
    pub fn bind() -> Result<Self, OAuthError> {
        let inner = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| OAuthError::Loopback(format!("bind: {e}")))?;
        inner
            .set_nonblocking(true)
            .map_err(|e| OAuthError::Loopback(format!("nonblocking: {e}")))?;
        Ok(Self { inner })
    }

    /// The bound port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.inner.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// `http://127.0.0.1:{port}` — the redirect_uri registered with the
    /// provider for this grant.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}", self.port())
    }

    /// Block until a request carrying `code`/`error`/`state` arrives, or
    /// `timeout` elapses. Non-matching requests (probes, favicon fetches,
    /// garbage) get a minimal response and the wait continues. Returns
    /// `Err(Expired)` on deadline — the grant is dead by then anyway.
    pub fn wait(&self, timeout: Duration) -> Result<RedirectOutcome, OAuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.inner.accept() {
                Ok((mut stream, _)) => {
                    if let Some(outcome) = handle_conn(&mut stream)? {
                        return Ok(outcome);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                }
                Err(e) => return Err(OAuthError::Loopback(format!("accept: {e}"))),
            }
            if Instant::now() >= deadline {
                return Err(OAuthError::Expired);
            }
        }
    }
}

/// Read one request, answer it, return `Some(outcome)` iff the request
/// carried OAuth redirect parameters.
fn handle_conn(stream: &mut TcpStream) -> Result<Option<RedirectOutcome>, OAuthError> {
    stream
        .set_read_timeout(Some(CONN_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CONN_IO_TIMEOUT)))
        .map_err(|e| OAuthError::Loopback(format!("sockopt: {e}")))?;

    // Bounded read: request line is all we need; stop at end-of-headers
    // or cap, whichever first.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > MAX_REQUEST_LINE {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(OAuthError::Loopback(format!("read: {e}"))),
        }
    }

    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let line = String::from_utf8_lossy(&buf[..line_end]);
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next(), parts.next());

    let outcome = match (method, target) {
        (Some("GET"), Some(t)) if t.starts_with('/') => {
            let query = t.split_once('?').map(|(_, q)| q).unwrap_or("");
            match RedirectOutcome::from_query(query) {
                Ok(o) if o.code.is_some() || o.error.is_some() || o.state.is_some() => {
                    respond(stream, 200, "OK", PAGE_DONE);
                    Some(o)
                }
                // Well-formed request without grant params (favicon etc.) —
                // answer politely, keep waiting for the real redirect.
                _ => {
                    respond(stream, 200, "OK", PAGE_WAITING);
                    None
                }
            }
        }
        _ => {
            respond(stream, 400, "Bad Request", PAGE_BAD);
            None
        }
    };
    Ok(outcome)
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    // Best-effort — the outcome was already parsed; a dead socket must not
    // fail the grant.
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

const PAGE_DONE: &str =
    "<!doctype html><title>KIWI</title><p>Sign-in complete — you can close this tab.</p>";
const PAGE_WAITING: &str = "<!doctype html><title>KIWI</title><p>Return to KIWI.</p>";
const PAGE_BAD: &str = "<!doctype html><title>KIWI</title><p>Bad request.</p>";
