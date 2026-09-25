//! Async HTTP seam: every integration talks to one [`HttpClient`].
//!
//! The production adapter is [`ReqwestClient`] (reqwest + rustls). Tests use
//! [`ScriptedHttp`] — an ordered, recorded-response transport that also
//! asserts what was requested (method, URL, query, headers, body), so fixtures
//! double as request-shape tests.
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
//! - Requests and responses redact themselves on `Debug` — the URL, a `Cookie`
//!   header, and a body can each carry secret material.
//! - The convenience live constructors are environment-gated (see
//!   [`LIVE_ENV`]); [`ReqwestClient::new`] stays the trusted production entry
//!   point and is not gated.
//!
//! [`ScriptedHttp`] is offline by construction: it answers from a script and
//! panics on an un-scripted request, so a test reaches the network only if it
//! deliberately builds a [`ReqwestClient`] and opts in through [`LIVE_ENV`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::{IntegrationError, TransportKind};

/// Default per-response body cap (1 MiB). Providers whose JSON embeds message
/// bodies raise this explicitly via [`ReqwestClient::with_body_cap`]; a
/// synthesized message is capped separately by `tempmail::MAX_RFC822`.
pub const DEFAULT_BODY_CAP: usize = 1024 * 1024;

/// Default request timeout for the live adapter.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Environment variable that opts into the live constructors. The value must be
/// exactly `1`; unset, `0`, `true`, `yes`, and anything else refuse.
pub const LIVE_ENV: &str = "KIWI_INTEGRATIONS_LIVE";

/// Environment variable CI runners set to a truthy value.
pub const CI_ENV: &str = "CI";

/// Why a live constructor refused to build. Offline test runs land on
/// [`LiveRefused::NotEnabled`]; CI lands on [`LiveRefused::BlockedInCi`].
#[derive(Debug, PartialEq, Eq)]
pub enum LiveRefused {
    /// [`LIVE_ENV`] is not exactly `1`.
    NotEnabled,
    /// [`CI_ENV`] is truthy: live provider calls are refused even when opted
    /// in, so a canary can never run unattended.
    BlockedInCi,
    /// The TLS client (or the hardcoded base URL) could not be built. The inner
    /// error is already sanitized — no URL, no provider text.
    Build(IntegrationError),
}

impl fmt::Display for LiveRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnabled => write!(
                f,
                "live provider construction is not enabled (set {LIVE_ENV}=1)"
            ),
            Self::BlockedInCi => write!(f, "live provider construction is refused in CI"),
            Self::Build(e) => write!(f, "live transport unavailable ({e})"),
        }
    }
}

impl std::error::Error for LiveRefused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(e) => Some(e),
            _ => None,
        }
    }
}

/// Fail-closed live gate, pure over its inputs so it is testable without
/// mutating the process environment.
fn live_gate(enabled: Option<&str>, ci: Option<&str>) -> Result<(), LiveRefused> {
    if ci.is_some_and(truthy) {
        return Err(LiveRefused::BlockedInCi);
    }
    if enabled != Some("1") {
        return Err(LiveRefused::NotEnabled);
    }
    Ok(())
}

/// [`live_gate`] against the real environment, re-read on every call. A
/// non-UTF-8 `CI` value counts as set, so a mangled environment fails closed.
pub(crate) fn live_gate_from_env() -> Result<(), LiveRefused> {
    let enabled = std::env::var(LIVE_ENV).ok();
    let ci = std::env::var_os(CI_ENV)
        .map(|v| v.to_str().map_or_else(|| String::from("1"), str::to_string));
    live_gate(enabled.as_deref(), ci.as_deref())
}

fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

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
///
/// `Debug` is redacted: the URL, the header values (a `Cookie` carries the
/// session id), and the body can all hold secret material.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    /// `(name, value)` pairs, order preserved. Names must be printable ASCII
    /// without CTLs; values likewise (the client rejects CTLs).
    pub headers: Vec<(String, String)>,
    /// Request body for POST. `None`/empty sends no body.
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &"[redacted]")
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.as_ref().map_or(0, Vec::len))
            .finish()
    }
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
///
/// `Debug` is redacted: `Set-Cookie` carries the rotating session id and the
/// body is untrusted provider data.
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// `(name, value)` pairs; names lowercased by the adapter.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    /// All values of `name` (case-insensitive).
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

    /// Override the per-response body cap (e.g. providers whose JSON embeds
    /// message bodies need more than 1 MiB).
    #[must_use]
    pub fn with_body_cap(mut self, cap: usize) -> Self {
        self.body_cap = cap;
        self
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

        let resp = rb
            .send()
            .await
            .map_err(|e| IntegrationError::Transport { kind: classify(&e) })?;
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
            .map_err(|e| IntegrationError::Transport { kind: classify(&e) })?
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
/// Four combinable levels of strictness:
///
/// - **Fragment** (default): every `expect_query` entry must appear somewhere
///   in the request URL, and every `expect_headers` pair must be present
///   verbatim. Cheap, and the right level for a base-URL probe.
/// - **Exact query** ([`Step::query_exact`]): the request's query must be
///   exactly the listed `key=value` pairs — nothing missing, nothing extra, no
///   altered value.
/// - **Exact URL** ([`Step::url`]): byte equality with the whole URL, scheme
///   and path and query.
/// - **Strict** ([`Step::strict`], implied by [`Step::get_exact`] and
///   [`Step::post_exact`]): exact method and URL are mandatory and the header
///   set must match exactly (no unlisted header, no missing one), and a
///   non-empty body is a mismatch unless [`Step::body`] pins it.
///
/// `expect_forbid` fragments must appear nowhere in the URL (pin "the slug is
/// not in the query"). A mismatch panics before the response is returned, so a
/// mis-shaped request can never look like a pass. Mismatch text is a fixed
/// reason plus the step name — never the request URL, headers, or body, which
/// can carry a capability.
#[derive(Clone)]
pub struct Step {
    /// Step label used in assertion messages.
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
    /// Whole-URL equality, set by [`Step::url`].
    pub expect_url: Option<String>,
    /// Complete query-pair set, set by [`Step::query_exact`]. Values compare
    /// exactly as they appear on the wire (percent-encoding included).
    pub expect_query_exact: Option<&'static [(&'static str, &'static str)]>,
    /// Fragments that must appear nowhere in the URL, set by [`Step::forbid`].
    pub expect_forbid: &'static [&'static str],
    /// Whole-request strictness, set by [`Step::strict`].
    pub strict: bool,
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("name", &self.name)
            .field("method", &self.expect_method)
            .field("url", &"[redacted]")
            .field("query_fragment_count", &self.expect_query.len())
            .field("exact_query", &self.expect_query_exact.is_some())
            .field("header_count", &self.expect_headers.len())
            .field("body_configured", &self.expect_body.is_some())
            .field("strict", &self.strict)
            .field("respond", &self.respond)
            .finish()
    }
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
            expect_url: None,
            expect_query_exact: None,
            expect_forbid: &[],
            strict: false,
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
            expect_url: None,
            expect_query_exact: None,
            expect_forbid: &[],
            strict: false,
        }
    }

    /// GET step that must match the whole request exactly (method, URL, header
    /// set, and an empty body unless [`Step::body`] pins one).
    #[must_use]
    pub fn get_exact(name: &'static str, url: &str, status: u16, body: &'static str) -> Self {
        Self::get(name, &[], status, body).url(url).strict()
    }

    /// POST step that must match the whole request exactly.
    #[must_use]
    pub fn post_exact(name: &'static str, url: &str, status: u16, body: &'static str) -> Self {
        Self::post(name, &[], status, body).url(url).strict()
    }

    /// Require an exact method, an exact URL, an exact header set, and no
    /// un-pinned body. Mismatches report why; the reason never carries the
    /// request's own material.
    #[must_use]
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
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
        self.expect_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Require the exact method.
    #[must_use]
    pub fn method(mut self, m: HttpMethod) -> Self {
        self.expect_method = Some(m);
        self
    }

    /// Require this exact whole URL (scheme + path + query).
    #[must_use]
    pub fn url(mut self, url: &str) -> Self {
        self.expect_url = Some(url.to_string());
        self
    }

    /// Require the query to be exactly these `key=value` pairs — nothing
    /// missing, nothing extra, no value drift.
    #[must_use]
    pub fn query_exact(mut self, pairs: &'static [(&'static str, &'static str)]) -> Self {
        self.expect_query_exact = Some(pairs);
        self
    }

    /// Require that no URL fragment matches (e.g. a leaked capability).
    #[must_use]
    pub fn forbid(mut self, fragment: &'static str) -> Self {
        let mut v = self.expect_forbid.to_vec();
        v.push(fragment);
        self.expect_forbid = Box::leak(v.into_boxed_slice());
        self
    }

    /// Require a byte-exact request body.
    #[must_use]
    pub fn body(mut self, body: &'static [u8]) -> Self {
        self.expect_body = Some(body);
        self
    }

    /// Compare the recorded expectation against a request, returning a fixed,
    /// secret-free reason on the first mismatch.
    fn validate(&self, request: &HttpRequest) -> Result<(), &'static str> {
        if self.strict && (self.expect_method.is_none() || self.expect_url.is_none()) {
            return Err("strict mode requires an exact method and URL");
        }
        if self
            .expect_method
            .is_some_and(|expected| expected != request.method)
        {
            return Err("method mismatch");
        }
        if self
            .expect_url
            .as_ref()
            .is_some_and(|expected| expected != &request.url)
        {
            return Err("exact URL mismatch");
        }
        if self
            .expect_query
            .iter()
            .any(|fragment| !request.url.contains(fragment))
        {
            return Err("missing fragment in request URL");
        }
        if self
            .expect_forbid
            .iter()
            .any(|fragment| request.url.contains(fragment))
        {
            return Err("forbidden URL fragment present");
        }
        if let Some(expected) = self.expect_query_exact {
            let mut actual = query_pairs(&request.url);
            let mut expected = expected.to_vec();
            actual.sort_unstable();
            expected.sort_unstable();
            if actual != expected {
                return Err("exact query mismatch");
            }
        }
        if self.strict {
            if header_set(&self.expect_headers) != header_set(&request.headers) {
                return Err("strict header-set mismatch");
            }
        } else if self
            .expect_headers
            .iter()
            .any(|(name, value)| request.header_value(name) != Some(value.as_str()))
        {
            return Err("required header mismatch");
        }
        if let Some(expected) = self.expect_body {
            if request.body.as_deref().unwrap_or_default() != expected {
                return Err("request body mismatch");
            }
        } else if self.strict && request.body.as_ref().is_some_and(|body| !body.is_empty()) {
            return Err("strict request body mismatch");
        }
        Ok(())
    }
}

/// Ordered recorded transport. Each `request` consumes the next step and
/// asserts the request matched it. Exhaustion or mismatch panics in tests —
/// that is the point: a fixture run must replay exactly.
///
/// Diagnostics are redacted by construction: a mismatch prints the step name
/// and a fixed reason, never the request URL, header values, or body, because
/// those carry the session cookie and the deliverability capability. Finish a
/// fixture test with [`ScriptedHttp::assert_exhausted`] so a dropped provider
/// call fails the test.
#[derive(Debug, Default)]
pub struct ScriptedHttp {
    steps: Mutex<std::collections::VecDeque<Step>>,
}

impl ScriptedHttp {
    /// A transport that will serve `steps` in order.
    #[must_use]
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: Mutex::new(steps.into()),
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

    /// Names of the steps that were never consumed.
    #[must_use]
    pub fn unconsumed(&self) -> Vec<&'static str> {
        self.steps
            .lock()
            .expect("scripted http")
            .iter()
            .map(|s| s.name)
            .collect()
    }

    /// Panics unless every scripted step was consumed. Call this at the end of
    /// a fixture test: an operation that silently stopped calling the
    /// transport then fails the test instead of passing on a half-replayed
    /// script.
    #[track_caller]
    pub fn assert_exhausted(&self) {
        let names = self.unconsumed();
        if !names.is_empty() {
            panic!(
                "ScriptedHttp: {} unconsumed step(s): {}",
                names.len(),
                names.join(", ")
            );
        }
    }
}

/// `key=value` pairs of a URL query, in wire order, percent-encoding intact.
fn query_pairs(url: &str) -> Vec<(&str, &str)> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect()
}

fn header_set(headers: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut set: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        set.entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.clone());
    }
    set
}

#[async_trait]
impl HttpClient for ScriptedHttp {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, IntegrationError> {
        let step = {
            let mut steps = self.steps.lock().expect("scripted http");
            steps.pop_front()
        };
        let Some(step) = step else {
            panic!("ScriptedHttp: unexpected request; URL, headers, and body redacted");
        };
        if let Err(reason) = step.validate(&req) {
            panic!("ScriptedHttp: step {}: {reason}", step.name);
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
        let err = c
            .request(HttpRequest::get("http://x.test/"))
            .await
            .unwrap_err();
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
        let http = ScriptedHttp::new(vec![
            Step::get("s1", &["f=check_email", "seq=0"], 200, "{}")
                .expect_header("cookie", "PHPSESSID=s1"),
        ]);
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
        let _ = http
            .request(HttpRequest::get("https://x.test/?f=right"))
            .await;
    }

    #[tokio::test]
    async fn exact_url_and_query_matchers_accept_the_recorded_request() {
        let http = ScriptedHttp::new(vec![
            Step::get("strict", &[], 200, "{}")
                .url("https://api.test/ajax.php?f=check_email&seq=7")
                .query_exact(&[("f", "check_email"), ("seq", "7")])
                .forbid("sid_token")
                .body(b""),
        ]);
        let resp = http
            .request(HttpRequest::get(
                "https://api.test/ajax.php?f=check_email&seq=7",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        http.assert_exhausted();
    }

    #[tokio::test]
    #[should_panic(expected = "exact query mismatch")]
    async fn exact_query_rejects_an_extra_parameter() {
        let http = ScriptedHttp::new(vec![
            Step::get("strict", &[], 200, "{}").query_exact(&[("f", "check_email")]),
        ]);
        let _ = http
            .request(HttpRequest::get("https://api.test/?f=check_email&leak=1"))
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "exact query mismatch")]
    async fn exact_query_rejects_a_missing_parameter() {
        let http = ScriptedHttp::new(vec![
            Step::get("strict", &[], 200, "{}").query_exact(&[("f", "check_email"), ("seq", "0")]),
        ]);
        let _ = http
            .request(HttpRequest::get("https://api.test/?f=check_email"))
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "exact URL mismatch")]
    async fn exact_url_rejects_a_differing_path() {
        let http = ScriptedHttp::new(vec![
            Step::get("strict", &[], 200, "{}").url("https://api.test/a"),
        ]);
        let _ = http.request(HttpRequest::get("https://api.test/b")).await;
    }

    #[tokio::test]
    #[should_panic(expected = "forbidden URL fragment present")]
    async fn forbid_catches_a_leaked_capability() {
        let http = ScriptedHttp::new(vec![Step::get("strict", &[], 200, "{}").forbid("s3cr3t")]);
        let _ = http
            .request(HttpRequest::get("https://api.test/?slug=s3cr3t"))
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "unconsumed step(s): never-called")]
    async fn assert_exhausted_fails_on_an_unreplayed_script() {
        let http = ScriptedHttp::new(vec![Step::get("never-called", &[], 200, "{}")]);
        assert!(!http.is_exhausted());
        assert_eq!(http.unconsumed(), vec!["never-called"]);
        http.assert_exhausted();
    }

    #[tokio::test]
    #[should_panic(expected = "unexpected request")]
    async fn scripted_panics_when_the_script_runs_out() {
        let http = ScriptedHttp::new(vec![]);
        let _ = http.request(HttpRequest::get("https://x.test/")).await;
    }

    #[test]
    fn mismatch_diagnostics_are_redacted_by_default() {
        let step = Step::get_exact(
            "safe",
            "https://api.test/tests/expected-secret/status",
            200,
            "{}",
        );
        let request = HttpRequest::get("https://api.test/tests/actual-secret/status")
            .header("cookie", "PHPSESSID=session-secret");
        let reason = step.validate(&request).unwrap_err();
        let diagnostic = format!("ScriptedHttp: step {}: {reason}", step.name);
        assert_eq!(reason, "exact URL mismatch");
        assert!(!diagnostic.contains("expected-secret"));
        assert!(!diagnostic.contains("actual-secret"));
        assert!(!diagnostic.contains("session-secret"));
        assert!(!format!("{step:?}").contains("expected-secret"));
    }

    #[test]
    fn request_and_response_debug_carry_no_secret() {
        let req = HttpRequest::post("https://api.test/tests/fx-slug-9u2n4k", Some(b"x".to_vec()))
            .header("cookie", "PHPSESSID=sess42");
        let line = format!("{req:?}");
        assert!(!line.contains("fx-slug-9u2n4k"));
        assert!(!line.contains("PHPSESSID"));
        assert!(line.contains("header_count: 1"));
        assert!(line.contains("body_len: 1"));

        let resp = HttpResponse {
            status: 200,
            headers: vec![("set-cookie".into(), "PHPSESSID=sess42".into())],
            body: b"{\"slug\":\"fx-slug-9u2n4k\"}".to_vec(),
        };
        let line = format!("{resp:?}");
        assert!(!line.contains("fx-slug-9u2n4k"));
        assert!(!line.contains("PHPSESSID"));
        assert!(line.contains("header_count: 1"));
        assert!(line.contains("body_len:"));
    }

    #[tokio::test]
    async fn strict_step_matches_the_complete_request() {
        let http = ScriptedHttp::new(vec![
            Step::get_exact("strict", "https://api.test/check?a=1&b=two", 200, "{}")
                .expect_header("accept", "application/json"),
        ]);
        let response = http
            .request(
                HttpRequest::get("https://api.test/check?a=1&b=two")
                    .header("Accept", "application/json"),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        http.assert_exhausted();
    }

    #[tokio::test]
    #[should_panic(expected = "strict header-set mismatch")]
    async fn strict_step_rejects_extra_headers() {
        let http = ScriptedHttp::new(vec![Step::get_exact(
            "strict",
            "https://api.test/check",
            200,
            "{}",
        )]);
        let _ = http
            .request(HttpRequest::get("https://api.test/check").header("x-extra", "secret"))
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "strict request body mismatch")]
    async fn strict_step_rejects_an_unexpected_body() {
        let http = ScriptedHttp::new(vec![Step::post_exact(
            "strict",
            "https://api.test/submit",
            200,
            "{}",
        )]);
        let _ = http
            .request(HttpRequest::post(
                "https://api.test/submit",
                Some(b"unexpected".to_vec()),
            ))
            .await;
    }

    #[test]
    fn live_gate_refuses_without_the_exact_opt_in() {
        assert_eq!(live_gate(None, None), Err(LiveRefused::NotEnabled));
        assert_eq!(live_gate(Some("0"), None), Err(LiveRefused::NotEnabled));
        assert_eq!(live_gate(Some("true"), None), Err(LiveRefused::NotEnabled));
        assert_eq!(live_gate(Some(""), None), Err(LiveRefused::NotEnabled));
        assert_eq!(live_gate(Some("1"), None), Ok(()));
    }

    #[test]
    fn live_gate_refuses_ci_even_when_opted_in() {
        for ci in ["1", "true", "TRUE", "yes", "on", " 1 "] {
            assert_eq!(
                live_gate(Some("1"), Some(ci)),
                Err(LiveRefused::BlockedInCi),
                "CI={ci:?} must refuse"
            );
        }
        for ci in ["0", "false", "no", ""] {
            assert_eq!(
                live_gate(Some("1"), Some(ci)),
                Ok(()),
                "CI={ci:?} must allow"
            );
        }
        assert_eq!(live_gate(None, Some("true")), Err(LiveRefused::BlockedInCi));
    }

    #[test]
    fn live_refusal_display_names_the_opt_in() {
        let s = LiveRefused::NotEnabled.to_string();
        assert!(s.contains(LIVE_ENV));
        assert!(s.contains('1'));
        assert_eq!(
            LiveRefused::BlockedInCi.to_string(),
            "live provider construction is refused in CI"
        );
        assert!(
            LiveRefused::Build(IntegrationError::NoSession)
                .to_string()
                .contains("no active session")
        );
    }
}
