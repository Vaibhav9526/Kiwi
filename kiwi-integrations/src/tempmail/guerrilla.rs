//! [`TempMailProvider`] over GuerrillaMail's `ajax.php` JSON API.
//!
//! Wire facts (guerrillamail.com/GuerrillaMailAPI.html — API v1.0):
//!
//! - Every request: `GET|POST {base}?f=<fn>&ip=<ip>&agent=<ua>`; session state
//!   rides on the `PHPSESSID` cookie — **server can rotate it on every
//!   response**, we re-read `Set-Cookie` each time.
//! - `get_email_address` (also returns `sid_token` — echoed back when present),
//!   `set_email_user&email_user=`, `check_email&seq=`, `fetch_email&email_id=`,
//!   `forget_me&email_addr=`, `extend`. Max list page: 20.
//! - `subject`/`excerpt` fields arrive HTML-entity-escaped — we decode.
//! - `fetch_email` body is **filtered by GuerrillaMail** (script/iframe
//!   stripped server-side) and arrives as a JSON field — the API has no
//!   raw-source endpoint. We synthesize RFC822: known headers + verbatim
//!   body, marked `X-Kiwi-Temp-Provider`. It is NOT the original message;
//!   render it only through KIWI's sanitized path.
//! - Addresses die 60 min after creation (one +1h `extend`, max 2h);
//!   sessions idle out ~18 min (any call refreshes; a `get_email_address`
//!   on an expired session mints a *new* address — `set_email_user` brings
//!   the old one back while it lives).
//! - Logical failures arrive as `200` plus a top-level `{"error": …}` envelope,
//!   so every success parse runs `reject_in_band_error` first, and `forget_me`
//!   accepts only its documented `true` token.
//!
//! Privacy posture: the API asks for the end user's `ip` and `agent`. KIWI puts
//! constants (`127.0.0.1`, `KIWI/<ver>`) in those parameters — it never places
//! the user's real IP or user-agent there (the network path still reveals the
//! connection source IP to the provider, as any HTTPS request does). The whole
//! session (cookie, token, address) is in-memory `Mutex` state; nothing is
//! persisted, and the two capability strings are zeroized when it is dropped.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;

use super::{
    ExtendOutcome, InboxPoll, MAX_FIELD, MAX_LOCAL_PART, MAX_MAIL_BODY, MAX_RFC822, TempAddress,
    TempMailProvider, TempMessage, TempMessageSummary,
};
use crate::error::{IntegrationError, reject_in_band_error};
use crate::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, LiveRefused, ReqwestClient};
use crate::secret::SecretString;

/// Production endpoint — HTTPS only, hardcoded. (The historical docs say
/// `http://`; the host serves HTTPS fine and we refuse plaintext.)
pub const GUERRILLA_API: &str = "https://api.guerrillamail.com/ajax.php";

/// Constant `ip` param — see module docs.
const PARAM_IP: &str = "127.0.0.1";

/// Response cap for API JSON (fetch bodies ride inside JSON, so the cap is
/// `MAX_MAIL_BODY` + slack, applied per-request).
const MAX_API_BODY: usize = MAX_MAIL_BODY + 1024 * 1024;

/// The only accepted `forget_me` success body, after ASCII trimming. The API
/// answers the bare token `true`; anything else — an `{"error": …}` envelope,
/// `false`, an HTML error page — is a rejection.
const FORGET_ME_OK: &[u8] = b"true";

/// In-memory session. The two capability strings are [`SecretString`]: redacted
/// on print, zeroized when the session is dropped. `forget_me` clears the
/// address but deliberately keeps the session (the API docs say the session
/// itself persists server-side).
#[derive(Debug, Default)]
struct Session {
    php_sessid: Option<SecretString>,
    sid_token: Option<SecretString>,
    address: Option<String>,
    created_unix: Option<u64>,
    /// Highest numeric `mail_id` seen — the `seq` cursor for `check_email`.
    last_seq: u64,
}

/// GuerrillaMail disposable-inbox provider. One instance = one mailbox.
pub struct GuerrillaMail {
    http: Arc<dyn HttpClient>,
    base: String,
    agent: String,
    state: Mutex<Session>,
}

/// Never prints session internals — `PHPSESSID`/`sid_token` stay out of logs.
impl std::fmt::Debug for GuerrillaMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuerrillaMail")
            .field("base", &self.base)
            .field("agent", &self.agent)
            .field("state", &"[redacted]")
            .finish()
    }
}

impl GuerrillaMail {
    /// Provider over an injected transport (tests: [`crate::http::ScriptedHttp`]).
    /// `base` must be `https://` — enforced here, not at first request.
    pub fn new(
        http: Arc<dyn HttpClient>,
        base: &str,
        agent: &str,
    ) -> Result<Self, IntegrationError> {
        let base = base.trim_end_matches('/');
        crate::http::check_https_base(base)?;
        Ok(Self {
            http,
            base: base.to_string(),
            agent: agent.chars().take(160).collect(),
            state: Mutex::new(Session::default()),
        })
    }

    /// Provider over the live reqwest transport (`GUERRILLA_API`, 30 s).
    ///
    /// Fail-closed opt-in: this refuses unless [`crate::http::LIVE_ENV`] is `1`
    /// and no CI marker is set (see [`LiveRefused`]). Offline tests build over
    /// [`crate::http::ScriptedHttp`] and never reach this path.
    pub fn live() -> Result<Self, LiveRefused> {
        crate::http::live_gate_from_env()?;
        let http = ReqwestClient::new(crate::http::DEFAULT_TIMEOUT_MS)
            .map_err(LiveRefused::Build)?
            .with_body_cap(MAX_API_BODY);
        Self::new(Arc::new(http), GUERRILLA_API, "KIWI/0.1").map_err(LiveRefused::Build)
    }

    /// Shared request path: params → GET/POST → session-cookie maintenance →
    /// status mapping. Returns the raw response for the caller to parse.
    ///
    /// The URL and the `Cookie` header necessarily carry the session
    /// capability; they are built under the state lock so no extra copy of the
    /// secret exists outside the request, and `HttpRequest` redacts itself on
    /// `Debug`.
    async fn call(
        &self,
        method: HttpMethod,
        f: &str,
        extra: &[(&str, String)],
    ) -> Result<HttpResponse, IntegrationError> {
        let req = {
            let s = self.state.lock().expect("gm session");
            let mut url = format!(
                "{}?f={f}&ip={PARAM_IP}&agent={}",
                self.base,
                crate::http::encode_param(&self.agent)
            );
            if let Some(t) = s.sid_token.as_ref() {
                url.push_str("&sid_token=");
                url.push_str(&crate::http::encode_param(t.expose()));
            }
            for (k, v) in extra {
                url.push('&');
                url.push_str(k);
                url.push('=');
                url.push_str(&crate::http::encode_param(v));
            }
            let mut req = HttpRequest {
                method,
                url,
                headers: vec![("accept".into(), "application/json".into())],
                body: None,
            };
            if let Some(id) = s.php_sessid.as_ref() {
                req.headers
                    .push(("cookie".into(), format!("PHPSESSID={}", id.expose())));
            }
            req
        };

        let resp = self.http.request(req).await?;
        self.absorb_cookies(&resp);

        match resp.status {
            200..=299 => Ok(resp),
            404 => Err(IntegrationError::NotFound),
            410 => Err(IntegrationError::Expired),
            429 => Err(IntegrationError::RateLimited {
                retry_after_ms: retry_after(&resp),
            }),
            s => Err(IntegrationError::Http { status: s }),
        }
    }

    /// Re-read `PHPSESSID` from `Set-Cookie` (rotatable on every response).
    /// Cookie values are charset-filtered + capped; a bogus cookie is ignored.
    fn absorb_cookies(&self, resp: &HttpResponse) {
        for raw in resp.header_values("set-cookie").take(16) {
            let pair = raw.split(';').next().unwrap_or(raw);
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("PHPSESSID") {
                continue;
            }
            let v: String = value
                .trim()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(128)
                .collect();
            if !v.is_empty() {
                self.state.lock().expect("gm session").php_sessid = Some(SecretString::new(v));
            }
        }
    }
}

#[async_trait]
impl TempMailProvider for GuerrillaMail {
    fn name(&self) -> &'static str {
        "guerrillamail"
    }

    fn address(&self) -> Option<String> {
        self.state.lock().expect("gm session").address.clone()
    }

    async fn get_email_address(&self) -> Result<TempAddress, IntegrationError> {
        let resp = self
            .call(
                HttpMethod::Get,
                "get_email_address",
                &[("lang", "en".into())],
            )
            .await?;
        let v = resp.json()?;
        let addr = parse_address(&v)?;
        let mut s = self.state.lock().expect("gm session");
        s.address = Some(addr.address.clone());
        s.created_unix = addr.created_unix;
        if let Some(t) = jstr(&v, "sid_token") {
            s.sid_token = Some(SecretString::new(t.chars().take(160).collect()));
        }
        s.last_seq = 0;
        Ok(addr)
    }

    async fn set_email_user(&self, local_part: &str) -> Result<TempAddress, IntegrationError> {
        validate_local_part(local_part)?;
        let resp = self
            .call(
                HttpMethod::Post,
                "set_email_user",
                &[("email_user", local_part.into()), ("lang", "en".into())],
            )
            .await?;
        let v = resp.json()?;
        let addr = parse_address(&v)?;
        let mut s = self.state.lock().expect("gm session");
        s.address = Some(addr.address.clone());
        s.created_unix = addr.created_unix;
        s.last_seq = 0; // address switch: the new mailbox has its own cursor
        Ok(addr)
    }

    async fn check_email(&self) -> Result<InboxPoll, IntegrationError> {
        let seq = {
            let s = self.state.lock().expect("gm session");
            if s.address.is_none() {
                return Err(IntegrationError::NoSession);
            }
            s.last_seq
        };
        let resp = self
            .call(HttpMethod::Get, "check_email", &[("seq", seq.to_string())])
            .await?;
        let v = resp.json()?;
        parse_poll(&v, &self.state)
    }

    async fn fetch_email(&self, mail_id: &str) -> Result<TempMessage, IntegrationError> {
        if mail_id.is_empty() || mail_id.len() > 32 || !mail_id.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(IntegrationError::Malformed("mail_id"));
        }
        let resp = self
            .call(
                HttpMethod::Get,
                "fetch_email",
                &[("email_id", mail_id.into())],
            )
            .await?;
        let v = resp.json()?;
        let to = self.state.lock().expect("gm session").address.clone();
        parse_fetch(&v, to.as_deref())
    }

    async fn forget_me(&self) -> Result<(), IntegrationError> {
        let addr = self.address().ok_or(IntegrationError::NoSession)?;
        let resp = self
            .call(HttpMethod::Post, "forget_me", &[("email_addr", addr)])
            .await?;
        let body = resp.body.trim_ascii();
        if body != FORGET_ME_OK {
            if let Ok(value) = serde_json::from_slice::<Value>(body) {
                reject_in_band_error(&value)?;
            }
            return Err(IntegrationError::ProviderRejected("forget_me"));
        }
        let mut s = self.state.lock().expect("gm session");
        s.address = None;
        s.created_unix = None;
        s.last_seq = 0;
        Ok(())
    }

    async fn extend(&self) -> Result<ExtendOutcome, IntegrationError> {
        if self.address().is_none() {
            return Err(IntegrationError::NoSession);
        }
        let resp = self.call(HttpMethod::Post, "extend", &[]).await?;
        parse_extend(&resp.json()?)
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers (pure; unit-tested against recorded fixtures)
// ---------------------------------------------------------------------------

fn parse_address(v: &Value) -> Result<TempAddress, IntegrationError> {
    reject_in_band_error(v)?;
    let address = jstr(v, "email_addr")
        .map(|s| s.chars().take(320).collect::<String>())
        .filter(|s| !s.is_empty())
        .ok_or(IntegrationError::Malformed("email_addr"))?;
    Ok(TempAddress {
        address,
        created_unix: ju64(v, "email_timestamp"),
        sid_token: jstr(v, "sid_token").map(|s| s.chars().take(160).collect()),
    })
}

/// `extend` success shape: `expired` and `affected` are required, `affected`
/// is `0` or `1`, and `email_timestamp` must be numeric when present. A missing
/// or nonsensical field is `Malformed` rather than a guessed `false`.
fn parse_extend(v: &Value) -> Result<ExtendOutcome, IntegrationError> {
    reject_in_band_error(v)?;
    if !v.is_object() {
        return Err(IntegrationError::Malformed("extend"));
    }
    let expired = jbool(v, "expired").ok_or(IntegrationError::Malformed("expired"))?;
    let affected = ju64(v, "affected").ok_or(IntegrationError::Malformed("affected"))?;
    if affected > 1 {
        return Err(IntegrationError::Malformed("affected"));
    }
    let address_created_unix = match v.get("email_timestamp") {
        None => None,
        Some(_) => {
            Some(ju64(v, "email_timestamp").ok_or(IntegrationError::Malformed("email_timestamp"))?)
        }
    };
    Ok(ExtendOutcome {
        expired,
        extended: affected == 1,
        address_created_unix,
    })
}

fn parse_poll(v: &Value, state: &Mutex<Session>) -> Result<InboxPoll, IntegrationError> {
    reject_in_band_error(v)?;
    let list = v
        .get("list")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::Malformed("list"))?;
    let mut messages = Vec::with_capacity(list.len().min(64));
    let mut max_seq = 0u64;
    for item in list.iter().take(64) {
        let id_raw = jstr(item, "mail_id").unwrap_or_default();
        let id: String = id_raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(32)
            .collect();
        if id.is_empty() {
            continue;
        }
        if let Ok(n) = id.parse::<u64>() {
            max_seq = max_seq.max(n);
        }
        messages.push(TempMessageSummary {
            mail_id: id,
            from: field(item, "mail_from", 320),
            subject: decode_entities(&field(item, "mail_subject", MAX_FIELD)),
            excerpt: decode_entities(&field(item, "mail_excerpt", MAX_FIELD)),
            timestamp_unix: ju64(item, "mail_timestamp"),
            date: field(item, "mail_date", 64),
            read: ju64(item, "mail_read") == Some(1),
        });
    }

    let mut s = state.lock().expect("gm session");
    if max_seq > s.last_seq {
        s.last_seq = max_seq;
    }
    let address = jstr(v, "email")
        .map(|e| e.chars().take(320).collect::<String>())
        .filter(|e| !e.is_empty());
    if let Some(a) = &address {
        s.address = Some(a.clone()); // server echoes the live address — resync
    }
    Ok(InboxPoll {
        messages,
        total_new: ju64(v, "count").unwrap_or(0),
        address,
    })
}

fn parse_fetch(v: &Value, to: Option<&str>) -> Result<TempMessage, IntegrationError> {
    reject_in_band_error(v)?;
    let id = jstr(v, "mail_id")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(32)
        .collect::<String>();
    if id.is_empty() {
        return Err(IntegrationError::Malformed("mail_id"));
    }
    let summary = TempMessageSummary {
        mail_id: id.clone(),
        from: field(v, "mail_from", 320),
        subject: decode_entities(&field(v, "mail_subject", MAX_FIELD)),
        excerpt: decode_entities(&field(v, "mail_excerpt", MAX_FIELD)),
        timestamp_unix: ju64(v, "mail_timestamp"),
        date: field(v, "mail_date", 64),
        read: ju64(v, "mail_read") == Some(1),
    };
    let content_type = jstr(v, "content_type")
        .and_then(sanitize_header)
        .filter(|s| !s.is_empty());
    let body = field(v, "mail_body", MAX_MAIL_BODY);

    let raw = synthesize_rfc822(&summary, content_type.as_deref(), to, &body)?;
    Ok(TempMessage {
        summary,
        content_type,
        raw_rfc822: raw,
    })
}

/// Synthesize an RFC822 message from provider fields. Header values are
/// CTL-stripped before interpolation — provider data is hostile. Returns
/// `Malformed` if the result would exceed `MAX_RFC822`.
fn synthesize_rfc822(
    m: &TempMessageSummary,
    content_type: Option<&str>,
    to: Option<&str>,
    body: &str,
) -> Result<Vec<u8>, IntegrationError> {
    let mut out = String::with_capacity(body.len() + 1024);
    let mut hdr = |name: &str, val: Option<String>| {
        if let Some(v) = val.filter(|s| !s.is_empty()) {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(&v);
            out.push_str("\r\n");
        }
    };
    hdr("From", sanitize_header(&m.from));
    hdr("To", to.and_then(sanitize_header));
    hdr("Subject", sanitize_header(&m.subject));
    hdr("Date", sanitize_header(&m.date));
    hdr("MIME-Version", Some("1.0".into()));
    hdr(
        "Content-Type",
        content_type
            .map(str::to_string)
            .or_else(|| Some("text/plain; charset=utf-8".into())),
    );
    hdr("Content-Transfer-Encoding", Some("8bit".into()));
    hdr("X-Guerrilla-Mail-Id", sanitize_header(&m.mail_id));
    hdr(
        "X-Kiwi-Temp-Provider",
        Some("guerrillamail (provider-filtered body; sanitize before render)".into()),
    );
    out.push_str("\r\n");
    out.push_str(body);
    let bytes = out.into_bytes();
    if bytes.len() > MAX_RFC822 {
        return Err(IntegrationError::BodyTooLarge);
    }
    Ok(bytes)
}

/// Decode the HTML entities GuerrillaMail applies to subject/excerpt:
/// named `amp lt gt quot apos` + decimal/hex numeric refs. Unknown entities
/// pass through verbatim. Single pass, bounded by input length.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let Some(end) = rest.find(';') else {
            out.push_str(rest);
            return out;
        };
        if end > 12 {
            out.push('&');
            rest = &rest[1..];
            continue;
        }
        let ent = &rest[1..end];
        let decoded = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `local_part` charset for `set_email_user` — deliberately tighter than the
/// RFC atom set; these end up inside an address on a public server.
fn validate_local_part(p: &str) -> Result<(), IntegrationError> {
    let ok = !p.is_empty()
        && p.len() <= MAX_LOCAL_PART
        && !p.starts_with('.')
        && !p.ends_with('.')
        && !p.contains("..")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(IntegrationError::Malformed("email_user"))
    }
}

/// JSON string field, truncated to `cap` chars. Accepts numbers-as-strings
/// (GM emits `"mail_id": "123"` but isn't consistent).
fn jstr<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Unsigned int field, accepting JSON numbers or decimal strings.
fn ju64(v: &Value, key: &str) -> Option<u64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Boolean field, accepting `true`/`false`, `1`/`0`, `"true"`/`"false"`.
fn jbool(v: &Value, key: &str) -> Option<bool> {
    match v.get(key) {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::Number(n)) => n.as_u64().map(|n| n != 0),
        Some(Value::String(s)) => match s.as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// String field capped at `cap` chars, entity escapes untouched (callers
/// decode where the provider escapes).
fn field(v: &Value, key: &str, cap: usize) -> String {
    jstr(v, key).unwrap_or_default().chars().take(cap).collect()
}

/// Strip CTLs (incl. CR/LF — header-injection guard) and trim. `None` on
/// input that isn't a string.
fn sanitize_header(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{7f}')
        .collect::<String>()
        .trim()
        .to_string();
    Some(cleaned)
}

/// `Retry-After` header → milliseconds (seconds value, capped at 1h).
fn retry_after(resp: &HttpResponse) -> Option<u64> {
    resp.header_values("retry-after")
        .next()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| (s.min(3600)) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ScriptedHttp, Step};

    fn gm(steps: Vec<Step>) -> GuerrillaMail {
        GuerrillaMail::new(
            Arc::new(ScriptedHttp::new(steps)),
            "https://api.guerrillamail.com/ajax.php",
            "KIWI-test",
        )
        .unwrap()
    }

    const ADDR_JSON: &str = r#"{
        "email_addr": "abc123@guerrillamailblock.com",
        "email_timestamp": "1758300000",
        "sid_token": "tok_deadbeef",
        "s_active": "N", "s_date": "", "s_time": "", "s_time_expires": ""
    }"#;

    const ERR_JSON: &str = r#"{"error":"email_addr not valid","f":"get_email_address"}"#;

    #[tokio::test]
    async fn get_email_address_starts_session_and_echoes_cookie() {
        let g = gm(vec![
            Step::get(
                "init",
                &[
                    "f=get_email_address",
                    "ip=127.0.0.1",
                    "agent=KIWI-test",
                    "lang=en",
                ],
                200,
                ADDR_JSON,
            )
            .respond_headers(&[("set-cookie", "PHPSESSID=sess42; path=/; HttpOnly")]),
        ]);
        let a = g.get_email_address().await.unwrap();
        assert_eq!(a.address, "abc123@guerrillamailblock.com");
        assert_eq!(a.created_unix, Some(1_758_300_000));
        assert_eq!(a.sid_token.as_deref(), Some("tok_deadbeef"));
        assert_eq!(
            g.address().as_deref(),
            Some("abc123@guerrillamailblock.com")
        );
    }

    #[tokio::test]
    async fn check_email_sends_cookie_sid_and_seq() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON)
                .respond_headers(&[("set-cookie", "PHPSESSID=sess42; path=/")]),
            Step::get(
                "poll",
                &["f=check_email", "seq=0", "sid_token=tok_deadbeef"],
                200,
                r#"{"list":[{"mail_id":"7001","mail_from":"s@x.test",
                    "mail_subject":"Hi &lt;there&gt;","mail_excerpt":"snip &amp; go",
                    "mail_timestamp":"1758300100","mail_read":"0","mail_date":"2026-09-19 20:01:40"}],
                   "count":"1","email":"abc123@guerrillamailblock.com","ts":"1758300000"}"#,
            )
            .expect_header("cookie", "PHPSESSID=sess42"),
        ]);
        g.get_email_address().await.unwrap();
        let poll = g.check_email().await.unwrap();
        assert_eq!(poll.total_new, 1);
        assert_eq!(poll.messages[0].mail_id, "7001");
        assert_eq!(poll.messages[0].subject, "Hi <there>");
        assert_eq!(poll.messages[0].excerpt, "snip & go");
        assert!(!poll.messages[0].read);
        assert_eq!(
            poll.address.as_deref(),
            Some("abc123@guerrillamailblock.com")
        );
    }

    #[tokio::test]
    async fn check_email_advances_seq_cursor() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::get(
                "poll1",
                &["seq=0"],
                200,
                r#"{"list":[{"mail_id":"7001","mail_from":"a","mail_subject":"x",
                    "mail_excerpt":"","mail_timestamp":"1","mail_read":"0","mail_date":""}],
                   "count":1}"#,
            ),
            Step::get("poll2", &["seq=7001"], 200, r#"{"list":[],"count":0}"#),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(g.check_email().await.unwrap().messages.len(), 1);
        assert!(g.check_email().await.unwrap().messages.is_empty());
    }

    #[tokio::test]
    async fn fetch_email_synthesizes_rfc822() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::get(
                "fetch",
                &["f=fetch_email", "email_id=7001"],
                200,
                r#"{"mail_id":"7001","mail_from":"sender@x.test",
                    "mail_subject":"Re: invoice","mail_excerpt":"...",
                    "mail_timestamp":"1758300100","mail_read":"1",
                    "mail_date":"2026-09-19 20:01:40","content_type":"text/html",
                    "mail_body":"<p>filtered body</p>"}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let m = g.fetch_email("7001").await.unwrap();
        let raw = String::from_utf8(m.raw_rfc822).unwrap();
        assert!(raw.starts_with("From: sender@x.test\r\n"));
        assert!(raw.contains("To: abc123@guerrillamailblock.com\r\n"));
        assert!(raw.contains("Subject: Re: invoice\r\n"));
        assert!(raw.contains("Content-Type: text/html\r\n"));
        assert!(raw.contains("X-Guerrilla-Mail-Id: 7001\r\n"));
        assert!(raw.ends_with("\r\n<p>filtered body</p>"));
        assert_eq!(m.content_type.as_deref(), Some("text/html"));
    }

    #[tokio::test]
    async fn header_injection_in_fields_is_stripped() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::get(
                "fetch",
                &["email_id=9"],
                200,
                r#"{"mail_id":"9","mail_from":"evil@x\r\nBcc: victim@y.test",
                    "mail_subject":"s","mail_excerpt":"","mail_timestamp":"1",
                    "mail_read":"0","mail_date":"","mail_body":"b"}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let m = g.fetch_email("9").await.unwrap();
        let raw = String::from_utf8(m.raw_rfc822).unwrap();
        // CRLF stripped ⇒ no injected header line; the "Bcc:" text is inert
        // inside the single From value.
        assert!(!raw.contains("\r\nBcc:"));
        assert!(raw.starts_with("From: evil@xBcc: victim@y.test\r\n"));
    }

    #[tokio::test]
    async fn set_email_user_validates_and_switches() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post(
                "set",
                &["f=set_email_user", "email_user=my.name-1"],
                200,
                r#"{"email_addr":"my.name-1@guerrillamailblock.com","email_timestamp":"1758300500"}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let a = g.set_email_user("my.name-1").await.unwrap();
        assert_eq!(a.address, "my.name-1@guerrillamailblock.com");
        assert!(g.set_email_user("bad name!").await.is_err());
        assert!(g.set_email_user(".lead").await.is_err());
        assert!(g.set_email_user(&"x".repeat(65)).await.is_err());
    }

    #[tokio::test]
    async fn forget_me_failure_keeps_address_for_retry() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON)
                .respond_headers(&[("set-cookie", "PHPSESSID=sess42; path=/")]),
            Step::post(
                "forget-fails",
                &["f=forget_me", "email_addr=abc123%40guerrillamailblock.com"],
                200,
                r#"{"error":"busy"}"#,
            )
            .expect_header("cookie", "PHPSESSID=sess42"),
        ]);
        g.get_email_address().await.unwrap();
        let before = g.address().unwrap();
        assert!(g.forget_me().await.is_err());
        assert_eq!(g.address().as_deref(), Some(before.as_str()));
    }

    #[tokio::test]
    async fn forget_me_clears_address_keeps_session() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON)
                .respond_headers(&[("set-cookie", "PHPSESSID=sess42; path=/")]),
            Step::post(
                "forget",
                &["f=forget_me", "email_addr=abc123%40guerrillamailblock.com"],
                200,
                "true",
            )
            .expect_header("cookie", "PHPSESSID=sess42"),
        ]);
        g.get_email_address().await.unwrap();
        g.forget_me().await.unwrap();
        assert_eq!(g.address(), None);
        assert!(matches!(
            g.check_email().await.unwrap_err(),
            IntegrationError::NoSession
        ));
    }

    #[tokio::test]
    async fn extend_maps_outcome() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post(
                "ext",
                &["f=extend"],
                200,
                r#"{"expired":false,"affected":1,"email_timestamp":"1758300000"}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let o = g.extend().await.unwrap();
        assert!(o.extended && !o.expired);
        assert_eq!(o.address_created_unix, Some(1_758_300_000));
    }

    #[tokio::test]
    async fn expired_address_extend_reports_expired() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post(
                "ext",
                &["f=extend"],
                200,
                r#"{"expired":true,"affected":0}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let o = g.extend().await.unwrap();
        assert!(o.expired && !o.extended);
    }

    #[tokio::test]
    async fn check_email_without_session_fails_closed() {
        let g = gm(vec![]);
        assert_eq!(
            g.check_email().await.unwrap_err(),
            IntegrationError::NoSession
        );
    }

    #[tokio::test]
    async fn rate_limit_maps_and_reads_retry_after() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 429, "{}")
                .respond_headers(&[("retry-after", "5")]),
        ]);
        match g.get_email_address().await.unwrap_err() {
            IntegrationError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, Some(5000));
            }
            e => panic!("unexpected {e}"),
        }
    }

    #[tokio::test]
    async fn malformed_json_is_an_error_not_a_panic() {
        let g = gm(vec![Step::get(
            "init",
            &["f=get_email_address"],
            200,
            "not json",
        )]);
        assert!(matches!(
            g.get_email_address().await.unwrap_err(),
            IntegrationError::Malformed(_)
        ));
        let g = gm(vec![Step::get("init", &["f=get_email_address"], 200, "{}")]);
        assert_eq!(
            g.get_email_address().await.unwrap_err(),
            IntegrationError::Malformed("email_addr")
        );
    }

    #[tokio::test]
    async fn fetch_rejects_nonnumeric_id_before_request() {
        let g = gm(vec![]);
        assert_eq!(
            g.fetch_email("1 OR 1=1").await.unwrap_err(),
            IntegrationError::Malformed("mail_id")
        );
    }

    #[test]
    fn entity_decoding() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_entities("&#65;&#x42;"), "AB");
        assert_eq!(decode_entities("&bogus;"), "&bogus;");
        assert_eq!(decode_entities("dangling &"), "dangling &");
        assert_eq!(decode_entities("&quot;q&apos;"), "\"q'");
    }

    #[test]
    fn query_encoding() {
        use crate::http::encode_param as q;
        assert_eq!(q("a b@c"), "a%20b%40c");
        assert_eq!(q("plain.txt"), "plain.txt");
        assert_eq!(q("a&b=c"), "a%26b%3Dc");
    }

    #[tokio::test]
    async fn http_base_is_refused() {
        let http = Arc::new(ScriptedHttp::new(vec![]));
        assert_eq!(
            GuerrillaMail::new(http, "http://api.guerrillamail.com/ajax.php", "k").unwrap_err(),
            IntegrationError::InsecureUrl
        );
    }

    #[tokio::test]
    async fn fetch_email_rejects_error_envelope_even_with_usable_fields() {
        let g = gm(vec![Step::get(
            "fetch",
            &["f=fetch_email"],
            200,
            r#"{"error":"not ownership","mail_id":"7"}"#,
        )]);
        assert_eq!(
            g.fetch_email("7").await.unwrap_err(),
            IntegrationError::ProviderRejected("not_ownership")
        );
    }

    #[tokio::test]
    async fn error_envelope_wins_over_plausible_success_fields() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post(
                "ext",
                &["f=extend"],
                200,
                r#"{"error":"busy","expired":false,"affected":1}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.extend().await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    // -----------------------------------------------------------------------
    // In-band error envelopes (INTG-04)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_email_address_rejects_error_envelope() {
        let g = gm(vec![Step::get(
            "init",
            &["f=get_email_address"],
            200,
            ERR_JSON,
        )]);
        assert_eq!(
            g.get_email_address().await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn set_email_user_rejects_error_envelope() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post("set", &["f=set_email_user"], 200, ERR_JSON),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.set_email_user("newbox").await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn check_email_rejects_error_envelope() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::get("poll", &["f=check_email"], 200, ERR_JSON),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.check_email().await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn fetch_email_rejects_error_envelope() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::get("fetch", &["f=fetch_email"], 200, ERR_JSON),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.fetch_email("7001").await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn extend_rejects_error_envelope() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post("ext", &["f=extend"], 200, ERR_JSON),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.extend().await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn not_ownership_keeps_its_own_code() {
        let v: Value = serde_json::from_str(r#"{"error":"not ownership"}"#).unwrap();
        assert_eq!(
            reject_in_band_error(&v).unwrap_err(),
            IntegrationError::ProviderRejected("not_ownership")
        );
    }

    #[test]
    fn empty_or_absent_error_is_not_an_envelope() {
        for body in [
            r#"{}"#,
            r#"{"error":null}"#,
            r#"{"error":""}"#,
            r#"{"error":"  "}"#,
        ] {
            let v: Value = serde_json::from_str(body).unwrap();
            assert!(reject_in_band_error(&v).is_ok(), "{body} must parse");
        }
    }

    // -----------------------------------------------------------------------
    // forget_me / extend shapes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn forget_me_requires_the_exact_success_token() {
        for body in ["false", "1", r#"{"status":"ok"}"#, "trueish", r#""true""#] {
            let g = gm(vec![
                Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
                Step::post("forget", &["f=forget_me"], 200, body),
            ]);
            g.get_email_address().await.unwrap();
            assert_eq!(
                g.forget_me().await.unwrap_err(),
                IntegrationError::ProviderRejected("forget_me"),
                "body {body:?} must not count as success"
            );
            assert_eq!(
                g.address().as_deref(),
                Some("abc123@guerrillamailblock.com"),
                "a rejected forget must stay retryable"
            );
        }
    }

    #[tokio::test]
    async fn forget_me_rejects_error_envelope_with_envelope_code() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post("forget", &["f=forget_me"], 200, ERR_JSON),
        ]);
        g.get_email_address().await.unwrap();
        assert_eq!(
            g.forget_me().await.unwrap_err(),
            IntegrationError::ProviderRejected("provider_error")
        );
    }

    #[tokio::test]
    async fn forget_me_tolerates_surrounding_whitespace() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post("forget", &["f=forget_me"], 200, "true\n"),
        ]);
        g.get_email_address().await.unwrap();
        g.forget_me().await.unwrap();
    }

    #[tokio::test]
    async fn extend_requires_its_documented_fields() {
        for (body, want) in [
            (r#"{}"#, IntegrationError::Malformed("expired")),
            (
                r#"{"expired":false}"#,
                IntegrationError::Malformed("affected"),
            ),
            (
                r#"{"expired":"maybe","affected":1}"#,
                IntegrationError::Malformed("expired"),
            ),
            (
                r#"{"expired":false,"affected":5}"#,
                IntegrationError::Malformed("affected"),
            ),
            (
                r#"{"expired":false,"affected":1,"email_timestamp":"soon"}"#,
                IntegrationError::Malformed("email_timestamp"),
            ),
        ] {
            let g = gm(vec![
                Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
                Step::post("ext", &["f=extend"], 200, body),
            ]);
            g.get_email_address().await.unwrap();
            assert_eq!(g.extend().await.unwrap_err(), want, "body {body}");
        }
    }

    #[tokio::test]
    async fn extend_accepts_string_encoded_numbers() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON),
            Step::post(
                "ext",
                &["f=extend"],
                200,
                r#"{"expired":"false","affected":"1","email_timestamp":"1758300000"}"#,
            ),
        ]);
        g.get_email_address().await.unwrap();
        let o = g.extend().await.unwrap();
        assert!(o.extended && !o.expired);
    }

    // -----------------------------------------------------------------------
    // Secret hygiene + live gate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn debug_never_exposes_session_capabilities() {
        let g = gm(vec![
            Step::get("init", &["f=get_email_address"], 200, ADDR_JSON)
                .respond_headers(&[("set-cookie", "PHPSESSID=sess42; path=/")]),
        ]);
        g.get_email_address().await.unwrap();
        let line = format!("{g:?}");
        assert!(!line.contains("sess42"));
        assert!(!line.contains("tok_deadbeef"));
        assert!(line.contains("[redacted]"));
    }

    #[test]
    fn temp_address_debug_redacts_and_serde_skips_the_token() {
        let a = TempAddress {
            address: "abc123@guerrillamailblock.com".into(),
            created_unix: Some(1),
            sid_token: Some("tok_deadbeef".into()),
        };
        let line = format!("{a:?}");
        assert!(!line.contains("tok_deadbeef"));
        assert!(line.contains("[redacted]"));
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("tok_deadbeef"));
        assert!(json.contains("abc123@guerrillamailblock.com"));
    }

    #[test]
    fn live_constructor_is_env_gated() {
        if crate::http::live_gate_from_env().is_ok() {
            return;
        }
        assert!(GuerrillaMail::live().is_err());
    }
}
