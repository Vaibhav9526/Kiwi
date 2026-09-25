//! Async HTTP seam: every integration talks to one [`HttpClient`].
//!
//! The production adapter is [`ReqwestClient`] (reqwest + rustls). Tests use
//! [`ScriptedHttp`] — an ordered, recorded-response transport that also
//! asserts what was requested (method, URL, headers), so fixtures double as
//! request-shape tests.
//!
//! Boundary rules (contract `docs/contracts/integrations.md`):
//!
//! - `https://` only — anything else is [`IntegrationError::InsecureUrl`]
//!   before a socket opens.
//! - Redirects are never followed (a 3xx is a response, not a chase target —
//!   following could bounce a secret-bearing URL onto another host).
//! - Response bodies are capped ([`ReqwestClient::body_cap`]); the cap is
//!   enforced while streaming so a hostile server cannot grow memory.
//! - Transport errors are classified into [`TransportKind`]; the underlying
//!   message is dropped because it embeds the request URL, which for the
//!   deliverability API contains a capability secret.

use async_trait::async_trait;

use crate::error::{IntegrationError, TransportKind};

/// Default per-response body cap (1 MiB) — comfortably above any API JSON
/// these providers emit; a synthesized message is capped separately.
pub const DEFAULT_BODY_CAP: usize = 1024 * 1024;

/// Default request timeout for the live adapter.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// HTTP method — only what the integrated APIs need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    /// Wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A fully-formed request. `url` includes scheme + query. Header names are
/// lowercase on the wire; callers may pass either case.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    /// `(name, value)` pairs, order preserved. Names must be printable ASCII
    /// without CTLs; values likewise (the client rejects CTLs).
    pub headers: Vec<(String, String)>,
    /// Request body for POST. `None`/empty sends no body.
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// GET `url` with no extra headers.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// POST `url` with optional body.
    #[must_use]
    pub fn post(url: impl Into<String>, body: Option<Vec<u8>>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body,
        }
    }

    /// Chainable header append.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// First value of `name` (case-insensitive), if present.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A response. `headers` preserves duplicates (Set-Cookie matters).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// `(name, value)` pairs; names lowercased by the adapter.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// All values of `name` (case-insensitive).
    #[must_use]
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Body interpreted as UTF-8 JSON. Truncated-by-cap bodies fail here as
    /// malformed JSON rather than silently parsing a prefix.
    pub fn json(&self) -> Result<serde_json::Value, IntegrationError> {
        serde_json::from_slice(&self.body).map_err(|_| IntegrationError::Malformed("json body"))
    }
}

/// Percent-encode a URL query value or path segment: unreserved
/// `[A-Za-z0-9._~-]` pass through, everything else is `%XX` (uppercase hex
/// over UTF-8 bytes).
pub(crate) fn encode_param(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for &b in v.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Constructor-time check both providers share: base URLs are `https://`.
pub(crate) fn check_https_base(base: &str) -> Result<(), IntegrationError> {
    if base.starts_with("https://") && base.len() <= 1024 {
        Ok(())
    } else {
        Err(IntegrationError::InsecureUrl)
    }
}

/// The seam. Implemented by [`ReqwestClient`] in production and by
/// [`ScriptedHttp`] in tests; callers may also inject their own transport
/// (proxy, Tor — the providers do not care).
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, IntegrationError>;
}

// ---------------------------------------------------------------------------
// Live adapter
// ---------------------------------------------------------------------------

/// reqwest+rustls adapter. Construct once per provider (cheap enough to
/// share). Refuses non-HTTPS URLs and never follows redirects.
pub struct ReqwestClient {
    client: reqwest::Client,
    /// Response body cap in bytes.
    pub body_cap: usize,
}

impl ReqwestClient {
    /// Build with `timeout_ms` and [`DEFAULT_BODY_CAP`].
    pub fn new(timeout_ms: u64) -> Result<Self, IntegrationError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .map_err(|_| IntegrationError::Transport {
                kind: TransportKind::Other,
            })?;
        Ok(Self {
            client,
            body_cap: DEFAULT_BODY_CAP,
        })
    }

    fn check_url(url: &str) -> Result<(), IntegrationError> {
        if url.len() > 4096 {
            return Err(IntegrationError::Malformed("url"));
        }
        if !url.starts_with("https://") {
            return Err(IntegrationError::InsecureUrl);
        }
        Ok(())
    }

    fn check_headers(req: &HttpRequest) -> Result<(), IntegrationError> {
        for (n, v) in &req.headers {
            if n.is_empty()
                || n.len() > 128
                || v.len() > 4096
                || !n.bytes().all(|b| b.is_ascii_graphic() && b != b':')
                || !v.bytes().all(|b| (b == b'\t') || (0x20..0x7f).contains(&b))
            {
                return Err(IntegrationError::Malformed("request header"));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, IntegrationError> {
        Self::check_url(&req.url)?;
        Self::check_headers(&req)?;

        let mut rb = match req.method {
            HttpMethod::Get => self.client.get(&req.url),
            HttpMethod::Post => self.client.post(&req.url),
        };
        for (n, v) in &req.headers {
            rb = rb.header(n.as_str(), v.as_str());
        }
        if let Some(body) = &req.body {
            rb = rb.body(body.clone());
        }

        let resp = rb.send().await.map_err(|e| IntegrationError::Transport {
            kind: classify(&e),
        })?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();

        // Bounded read: stream the body and stop at cap+1 so we never buffer
        // more than the limit before deciding it is too large.
        let mut body = Vec::new();
        let mut stream = resp;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| IntegrationError::Transport {
                kind: classify(&e),
            })?
        {
            if body.len() + chunk.len() > self.body_cap {
                return Err(IntegrationError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Classify a reqwest error without keeping its message (the message embeds
/// the request URL, which can carry a capability secret).
fn classify(e: &reqwest::Error) -> TransportKind {
    if e.is_timeout() {
        TransportKind::Timeout
    } else if e.is_connect() {
        TransportKind::Connect
    } else if e.is_decode() {
        TransportKind::Decode
    } else {
        TransportKind::Other
    }
}

// ---------------------------------------------------------------------------
// Scripted test transport
// ---------------------------------------------------------------------------

/// One recorded exchange: what the request must look like and what to answer.
///
/// `expect_query` / `expect_headers` are *substring/pair* assertions — the
/// request URL must contain every `expect_query` fragment, and each listed
/// header must be present with exactly that value. `None` matchers accept
/// anything. A mismatch fails the step loudly (the request never happened).
#[derive(Debug, Clone)]
pub struct Step {
    /// Optional step label used in assertion messages.
    pub name: &'static str,
    /// Required method (`None` = any).
    pub expect_method: Option<HttpMethod>,
    /// URL substrings that must all appear (e.g. `["f=check_email", "seq=0"]`).
    pub expect_query: &'static [&'static str],
    /// Headers that must be present verbatim, `(name, value)`.
    pub expect_headers: Vec<(String, String)>,
    /// Required request body (exact match). `None` = don't care.
    pub expect_body: Option<&'static [u8]>,
    /// The recorded response.
    pub respond: HttpResponse,
}

impl Step {
    /// GET step answering `status`/`body`, asserting `expect_query` fragments.
    #[must_use]
    pub fn get(
        name: &'static str,
        expect_query: &'static [&'static str],
        status: u16,
        body: &'static str,
    ) -> Self {
        Self {
            name,
            expect_method: Some(HttpMethod::Get),
            expect_query,
            expect_headers: Vec::new(),
            expect_body: None,
            respond: HttpResponse {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
            },
        }
    }

    /// POST step answering `status`/`body`.
    #[must_use]
    pub fn post(
        name: &'static str,
        expect_query: &'static [&'static str],
        status: u16,
        body: &'static str,
    ) -> Self {
        Self {
            name,
            expect_method: Some(HttpMethod::Post),
            expect_query,
            expect_headers: Vec::new(),
            expect_body: None,
            respond: HttpResponse {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
            },
        }
    }

    /// Attach recorded response headers (e.g. `Set-Cookie`).
    #[must_use]
    pub fn respond_headers(mut self, headers: &[(&'static str, &'static str)]) -> Self {
        self.respond.headers = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        self
    }

    /// Require a request header verbatim.
    #[must_use]
    pub fn expect_header(mut self, name: &str, value: &str) -> Self {
        self.expect_headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// Ordered recorded transport. Each `request` consumes the next step and
/// asserts the request matched it. Exhaustion or mismatch panics in tests —
/// that is the point: a fixture run must replay exactly.
#[derive(Debug, Default)]
pub struct ScriptedHttp {
    steps: std::sync::Mutex<std::collections::VecDeque<Step>>,
}

impl ScriptedHttp {
    /// A transport that will serve `steps` in order.
    #[must_use]
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: std::sync::Mutex::new(steps.into()),
        }
    }

    /// All steps consumed?
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.steps.lock().expect("scripted http").is_empty()
    }

    /// Steps still unconsumed (for failure diagnostics).
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.steps.lock().expect("scripted http").len()
    }
}

#[async_trait]
impl HttpClient for ScriptedHttp {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, IntegrationError> {
        let step = {
            let mut q = self.steps.lock().expect("scripted http");
            q.pop_front()
        };
        let Some(step) = step else {
            panic!("ScriptedHttp: unexpected request {} {}", req.method.as_str(), req.url);
        };
        if let Some(m) = step.expect_method {
            assert_eq!(
                m,
                req.method,
                "step {}: method mismatch for {}",
                step.name,
                req.url
            );
        }
        for frag in step.expect_query {
            assert!(
                req.url.contains(frag),
                "step {}: URL {:?} missing fragment {:?}",
                step.name,
                req.url,
                frag
            );
        }
        for (n, v) in step.expect_headers {
            assert_eq!(
                req.header_value(n),
                Some(*v),
                "step {}: header {n} mismatch",
                step.name
            );
        }
        if let Some(want) = step.expect_body {
            assert_eq!(
                req.body.as_deref(),
                Some(want),
                "step {}: body mismatch",
                step.name
            );
        }
        Ok(step.respond)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_plain_http() {
        let c = ReqwestClient::new(1000).unwrap();
        let err = c.request(HttpRequest::get("http://x.test/")).await.unwrap_err();
        assert_eq!(err, IntegrationError::InsecureUrl);
    }

    #[tokio::test]
    async fn rejects_huge_or_nonascii_headers() {
        let c = ReqwestClient::new(1000).unwrap();
        let req = HttpRequest::get("https://x.test/").header("x-bad", "va\r\nlue");
        let err = c.request(req).await.unwrap_err();
        assert_eq!(err, IntegrationError::Malformed("request header"));
    }

    #[tokio::test]
    async fn scripted_replays_in_order_and_asserts() {
        let http = ScriptedHttp::new(vec![Step::get(
            "s1",
            &["f=check_email", "seq=0"],
            200,
            "{}",
        )
        .expect_header("cookie", "PHPSESSID=s1")]);
        let req = HttpRequest::get("https://api.test/ajax.php?f=check_email&seq=0")
            .header("Cookie", "PHPSESSID=s1");
        let resp = http.request(req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(http.is_exhausted());
    }

    #[tokio::test]
    #[should_panic(expected = "missing fragment")]
    async fn scripted_panics_on_url_mismatch() {
        let http = ScriptedHttp::new(vec![Step::get("s", &["f=wrong"], 200, "{}")]);
        let _ = http.request(HttpRequest::get("https://x.test/?f=right")).await;
    }
}
