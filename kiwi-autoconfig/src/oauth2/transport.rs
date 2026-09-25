//! Narrow HTTPS transport seam for OAuth endpoints.
//!
//! One verb: `POST` an `application/x-www-form-urlencoded` body, get back
//! status + capped body. The trait is blanket-implemented for every
//! `kiwi_integrations::http::HttpClient`, so the security posture of that
//! seam applies verbatim: `https://` only (refused before connect), no
//! redirect following, bounded streaming bodies, and transport errors
//! classified without the request URL.
//!
//! Tests use `ScriptedHttp` — recorded responses that also assert request
//! shape — so fixture doubles verify *what* was sent, not just what was
//! parsed. No test performs a live call.

use async_trait::async_trait;

use kiwi_integrations::http::{HttpClient, HttpRequest, ReqwestClient};

use super::{MAX_TOKEN_FIELD, OAuthError};

/// Response body cap for OAuth endpoints — token/device payloads are small
/// JSON documents; anything larger is hostile or broken.
pub const MAX_TOKEN_BODY: usize = 64 * 1024;

/// One transport reply: status + bounded body. Headers are not needed —
/// OAuth token/device-code contracts are JSON-body + status only.
#[derive(Debug, Clone)]
pub struct TransportReply {
    /// HTTP status code.
    pub status: u16,
    /// Response body (≤ [`MAX_TOKEN_BODY`] on the live transport).
    pub body: Vec<u8>,
}

/// The seam. Every OAuth request in this module is a form POST; callers
/// inject the transport so flows stay pure/deterministic.
#[async_trait]
pub trait OAuthTransport: Send + Sync {
    /// POST `form` as `application/x-www-form-urlencoded` to `url`.
    /// Implementations must refuse non-HTTPS URLs and never follow
    /// redirects.
    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<TransportReply, OAuthError>;
}

/// Blanket adapter: any `HttpClient` is an `OAuthTransport`. Form values
/// are encoded here (strict percent-encoding, RFC 3986 unreserved set) so
/// every transport sees identical wire bytes.
#[async_trait]
impl<T: HttpClient + ?Sized> OAuthTransport for T {
    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<TransportReply, OAuthError> {
        let body = form_encode(form);
        let req = HttpRequest::post(url, Some(body.into_bytes()))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json");
        let resp = self.request(req).await?;
        Ok(TransportReply {
            status: resp.status,
            body: resp.body,
        })
    }
}

/// Production transport: reqwest + rustls via `ReqwestClient`, with the
/// OAuth body cap applied. Requires a Tokio runtime context (call from the
/// Tauri command layer).
pub fn live_transport(timeout_ms: u64) -> Result<ReqwestClient, OAuthError> {
    let mut client = ReqwestClient::new(timeout_ms)?;
    client.body_cap = MAX_TOKEN_BODY;
    Ok(client)
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// `application/x-www-form-urlencoded` encoder — strict percent-encoding:
/// RFC 3986 unreserved bytes (`A-Z a-z 0-9 - _ . ~`) pass through, every
/// other byte becomes `%XX` of its UTF-8 encoding (space → `%20`, which
/// every compliant form decoder accepts). Deterministic, allocation-bounded
/// by input size.
#[must_use]
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_into(&mut out, k);
        out.push('=');
        encode_into(&mut out, v);
    }
    out
}

fn encode_into(out: &mut String, s: &str) {
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(b >> 4) as usize] as char);
                out.push(HEX_UPPER[(b & 0xf) as usize] as char);
            }
        }
    }
}

/// Form decoder for redirect/callback parsing: `%XX` escapes (UTF-8),
/// `+` → space, `&` separators, `=` name/value split (first `=` wins,
/// matching standard form semantics). Bare `%` / truncated escapes are
/// rejected rather than passed through.
pub fn form_decode(query: &str) -> Result<Vec<(String, String)>, OAuthError> {
    let mut out = Vec::new();
    if query.is_empty() {
        return Ok(out);
    }
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((decode_component(k)?, decode_component(v)?));
    }
    Ok(out)
}

fn decode_component(s: &str) -> Result<String, OAuthError> {
    if s.len() > MAX_TOKEN_FIELD * 2 {
        return Err(OAuthError::Malformed("form field too long"));
    }
    let bytes = s.as_bytes();
    let mut buf = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => buf.push(b' '),
            b'%' => {
                let hi = bytes.get(i + 1).and_then(|b| hex_val(*b));
                let lo = bytes.get(i + 2).and_then(|b| hex_val(*b));
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        buf.push(h << 4 | l);
                        i += 2;
                    }
                    _ => return Err(OAuthError::Malformed("bad percent escape")),
                }
            }
            b => buf.push(b),
        }
        i += 1;
    }
    String::from_utf8(buf).map_err(|_| OAuthError::Malformed("form not utf-8"))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
