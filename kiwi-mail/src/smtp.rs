//! SMTP send client (RFC 5321): EHLO → STARTTLS → AUTH → MAIL/RCPT/DATA.
//!
//! Security notes:
//! - `require_starttls` (default on) fails closed when a `StartTls` socket
//!   meets a server that doesn't advertise STARTTLS — no silent downgrade.
//! - Envelope addresses are validated against CRLF/header injection.
//! - Credentials live in zeroizing buffers; replies are never logged with
//!   auth material attached (SECURITY.md rules 6, 9).
//! - AUTH PLAIN/LOGIN credentials are only sent over an encrypted transport
//!   unless the caller explicitly constructs `SocketSecurity::Plaintext`
//!   *and* sets `allow_plaintext_auth` — the default refuses.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::{MailError, Result};
use crate::lines::{read_line, write_line};
use crate::transport::{SocketSecurity, Transport};

const PROTO: &str = "smtp";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// RFC 5321 §4.5.3.2 recommends ≥10 min after the final "." — we use 5 min.
const DATA_TIMEOUT: Duration = Duration::from_secs(300);
/// Bound on reply lines a server may send for one command.
const MAX_REPLY_LINES: usize = 200;

/// A parsed SMTP reply: status code + all text lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    pub code: u16,
    /// Text after the code (enhanced status code stripped into `enhanced`).
    pub lines: Vec<String>,
    /// RFC 3463 enhanced code (e.g. "5.7.8") when present on the first line.
    pub enhanced: Option<String>,
}

impl SmtpReply {
    pub fn is_success(&self) -> bool {
        (200..400).contains(&self.code)
    }
    /// 4xx = transient failure; retry later is legitimate.
    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.code)
    }
    /// 5xx = permanent failure.
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }
    pub fn message(&self) -> String {
        self.lines.join(" ")
    }
}

/// Parsed EHLO extension advertisement.
#[derive(Debug, Clone, Default)]
pub struct EhloInfo {
    /// First EHLO line — the server's greeting/domain text.
    pub greeting: String,
    /// Uppercased extension keyword → parameter string ("" if none).
    pub extensions: BTreeMap<String, String>,
}

impl EhloInfo {
    pub fn supports(&self, ext: &str) -> bool {
        self.extensions.contains_key(&ext.to_ascii_uppercase())
    }
    pub fn has_starttls(&self) -> bool {
        self.supports("STARTTLS")
    }
    /// Advertised AUTH mechanisms, uppercased (from `AUTH`/`AUTH=` lines).
    pub fn auth_mechanisms(&self) -> Vec<String> {
        for key in ["AUTH", "AUTH="] {
            if let Some(v) = self.extensions.get(key) {
                return v
                    .split_whitespace()
                    .map(|s| s.to_ascii_uppercase())
                    .collect();
            }
        }
        Vec::new()
    }
    /// SIZE parameter (max message bytes) when advertised.
    pub fn max_size(&self) -> Option<u64> {
        self.extensions.get("SIZE")?.split_whitespace().next()?.parse().ok()
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Refuse to continue when the server doesn't offer STARTTLS on a
    /// `SocketSecurity::StartTls` connection. Default true (fail closed).
    pub require_starttls: bool,
    /// Explicit opt-in for sending AUTH over plaintext. Default false.
    pub allow_plaintext_auth: bool,
    /// Client name sent in EHLO.
    pub client_name: String,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            require_starttls: true,
            allow_plaintext_auth: false,
            client_name: "kiwi.local".into(),
        }
    }
}

/// Authentication credentials. Secrets are zeroizing and never `Debug`-printed.
pub enum SmtpAuth {
    None,
    Plain { user: String, password: Zeroizing<String> },
    Login { user: String, password: Zeroizing<String> },
    /// OAuth2 bearer token (XOAUTH2 SASL).
    XOAuth2 { user: String, token: Zeroizing<String> },
}

pub struct SmtpClient {
    t: Transport,
    config: SmtpConfig,
    ehlo: Option<EhloInfo>,
    scratch: Vec<u8>,
}

/// One outbound message: envelope + complete MIME bytes (CRLF endings).
pub struct SendRequest {
    pub from: String,
    pub to: Vec<String>,
    /// Full RFC 5322 message produced by `crate::mime`.
    pub message: Vec<u8>,
}

/// Per-recipient outcome of one DATA transaction.
#[derive(Debug)]
pub struct SendOutcome {
    pub accepted: Vec<String>,
    /// (recipient, server reply) pairs the server rejected.
    pub rejected: Vec<(String, SmtpReply)>,
    /// Server's final reply to the DATA body (when reached).
    pub data_reply: Option<SmtpReply>,
}

impl SmtpClient {
    /// Connect: read the 220 greeting, EHLO, perform STARTTLS when required
    /// by `Transport`'s socket security, then EHLO again post-upgrade.
    pub async fn connect(t: Transport, config: SmtpConfig) -> Result<Self> {
        let mut c = Self {
            t,
            config,
            ehlo: None,
            scratch: Vec::new(),
        };
        let greeting = c.read_reply().await?;
        if greeting.code != 220 {
            return Err(MailError::ServerReject {
                command: "connect".into(),
                reply: greeting.message(),
            });
        }
        c.ehlo().await?;
        Ok(c)
    }

    /// The EHLO state after any STARTTLS upgrade — what the *current*
    /// encrypted session actually supports.
    pub fn ehlo_info(&self) -> Option<&EhloInfo> {
        self.ehlo.as_ref()
    }

    pub fn transport(&self) -> &Transport {
        &self.t
    }

    async fn command(&mut self, line: &str) -> Result<SmtpReply> {
        write_line(&mut self.t, line.as_bytes()).await?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> Result<SmtpReply> {
        tokio::time::timeout(CMD_TIMEOUT, self.read_reply_inner())
            .await
            .map_err(|_| MailError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut, "smtp reply timeout")))?
    }

    async fn read_reply_inner(&mut self) -> Result<SmtpReply> {
        let mut code: Option<u16> = None;
        let mut lines = Vec::new();
        loop {
            let raw = read_line(&mut self.t, &mut self.scratch, PROTO).await?;
            if raw.len() < 4 {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: format!("malformed reply line: {}", String::from_utf8_lossy(&raw)),
                });
            }
            let parsed: u16 = raw[..3]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .fold(0u16, |a, b| a * 10 + (b - b'0') as u16);
            if raw[..3].iter().any(|b| !b.is_ascii_digit()) {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: format!("non-numeric reply code: {}", String::from_utf8_lossy(&raw)),
                });
            }
            match code {
                None => code = Some(parsed),
                // Multiline replies must keep one code (RFC 5321 §4.2.1).
                Some(c) if c != parsed => {
                    return Err(MailError::Protocol {
                        protocol: PROTO,
                        detail: "multiline reply with inconsistent codes".into(),
                    });
                }
                _ => {}
            }
            let sep = raw[3];
            let text = String::from_utf8_lossy(&raw[4.min(raw.len())..]).into_owned();
            lines.push(text);
            if sep == b' ' {
                break;
            }
            if sep != b'-' || lines.len() >= MAX_REPLY_LINES {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: "malformed/overflowing multiline reply".into(),
                });
            }
        }
        let enhanced = lines
            .first()
            .and_then(|l| l.split_whitespace().next())
            .filter(|tok| {
                tok.len() >= 5
                    && tok.bytes().next().is_some_and(|b| b.is_ascii_digit())
                    && tok.contains('.')
            })
            .map(str::to_owned);
        Ok(SmtpReply {
            code: code.unwrap_or(0),
            lines,
            enhanced,
        })
    }

    async fn ehlo(&mut self) -> Result<()> {
        let name = self.config.client_name.clone();
        let reply = self.command(&format!("EHLO {name}")).await?;
        if !reply.is_success() {
            // RFC 5321 fallback for ancient servers.
            let r = self.command(&format!("HELO {name}")).await?;
            if !r.is_success() {
                return Err(MailError::ServerReject {
                    command: "EHLO/HELO".into(),
                    reply: r.message(),
                });
            }
            self.ehlo = Some(EhloInfo {
                greeting: r.message(),
                extensions: BTreeMap::new(),
            });
            return Ok(());
        }
        self.ehlo = Some(parse_ehlo_reply(&reply));

        if self.t_socket_security() == SocketSecurity::StartTls {
            if self.ehlo.as_ref().is_some_and(|e| e.has_starttls()) {
                self.command("STARTTLS").await.and_then(|r| {
                    if r.code == 220 {
                        Ok(())
                    } else {
                        Err(MailError::ServerReject {
                            command: "STARTTLS".into(),
                            reply: r.message(),
                        })
                    }
                })?;
                self.t.starttls_upgrade().await?;
                // RFC 3207 §4.2: fresh EHLO over the TLS session —
                // extensions may differ from the plaintext advertisement.
                let name = self.config.client_name.clone();
                let r = self.command(&format!("EHLO {name}")).await?;
                if !r.is_success() {
                    return Err(MailError::ServerReject {
                        command: "EHLO (post-STARTTLS)".into(),
                        reply: r.message(),
                    });
                }
                self.ehlo = Some(parse_ehlo_reply(&r));
            } else if self.config.require_starttls {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: "server does not advertise STARTTLS; connection refused \
                             (require_starttls). Possible downgrade attempt."
                        .into(),
                });
            }
        }
        Ok(())
    }

    fn t_socket_security(&self) -> SocketSecurity {
        // Transport keeps its configured mode; live encryption state is in
        // `observation`. STARTTLS mode upgrades on demand.
        self.t.socket_security()
    }

    /// Authenticate per `auth`. Refuses cleartext credentials unless the
    /// caller explicitly opted in via `allow_plaintext_auth`.
    pub async fn authenticate(&mut self, auth: &SmtpAuth) -> Result<()> {
        let needs_secret = !matches!(auth, SmtpAuth::None);
        if needs_secret && !self.t.is_encrypted() && !self.config.allow_plaintext_auth {
            return Err(MailError::Protocol {
                protocol: PROTO,
                detail: "refusing to send credentials over plaintext \
                         (allow_plaintext_auth is off)"
                    .into(),
            });
        }
        match auth {
            SmtpAuth::None => Ok(()),
            SmtpAuth::Plain { user, password } => {
                let token = base64::engine::general_purpose::STANDARD
                    .encode(Zeroizing::new(format!("\0{user}\0{}", password.as_str())));
                let r = self.command(&format!("AUTH PLAIN {token}")).await?;
                auth_result(r)
            }
            SmtpAuth::Login { user, password } => {
                let r = self.command("AUTH LOGIN").await?;
                if r.code != 334 {
                    return auth_result(r);
                }
                let enc = base64::engine::general_purpose::STANDARD;
                let r = self.command(&enc.encode(user.as_bytes())).await?;
                if r.code != 334 {
                    return auth_result(r);
                }
                let r = self
                    .command(&enc.encode(Zeroizing::new(password.as_str().as_bytes().to_vec()).as_slice()))
                    .await?;
                auth_result(r)
            }
            SmtpAuth::XOAuth2 { user, token } => {
                let sasl = Zeroizing::new(format!("user={user}\x01auth=Bearer {}\x01\x01", token.as_str()));
                let b64 = base64::engine::general_purpose::STANDARD.encode(sasl.as_bytes());
                let r = self.command(&format!("AUTH XOAUTH2 {b64}")).await?;
                auth_result(r)
            }
        }
    }

    /// Send one message. Envelope addresses are validated; body bytes are
    /// dot-stuffed on the wire. Partial recipient rejection is reported in
    /// `SendOutcome.rejected` (not an error) — hard failures return `Err`.
    pub async fn send_mail(&mut self, req: &SendRequest) -> Result<SendOutcome> {
        validate_envelope(&req.from, &req.to)?;

        if let Some(max) = self.ehlo.as_ref().and_then(|e| e.max_size())
            && req.message.len() as u64 > max
        {
            return Err(MailError::ServerReject {
                command: "MAIL".into(),
                reply: format!("message {} bytes exceeds server SIZE {max}", req.message.len()),
            });
        }

        let size = req.message.len();
        // SIZE parameter is only legal when the server advertised it (RFC 1870).
        let mail_from = if self.ehlo.as_ref().is_some_and(|e| e.supports("SIZE")) {
            format!("MAIL FROM:<{}> SIZE={size}", req.from)
        } else {
            format!("MAIL FROM:<{}>", req.from)
        };
        let r = self.command(&mail_from).await?;
        if !r.is_success() {
            return Err(MailError::ServerReject {
                command: "MAIL FROM".into(),
                reply: r.message(),
            });
        }

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for rcpt in &req.to {
            let r = self.command(&format!("RCPT TO:<{rcpt}>")).await?;
            if r.is_success() {
                accepted.push(rcpt.clone());
            } else {
                rejected.push((rcpt.clone(), r));
            }
        }
        if accepted.is_empty() {
            let _ = self.command("RSET").await;
            return Ok(SendOutcome {
                accepted,
                rejected,
                data_reply: None,
            });
        }

        let r = self.command("DATA").await?;
        if r.code != 354 {
            return Err(MailError::ServerReject {
                command: "DATA".into(),
                reply: r.message(),
            });
        }

        self.t.write_all(&dot_stuff(&req.message)).await?;
        // DATA terminator is <CRLF>.<CRLF>; if the message already ends in
        // CRLF, only the dot line remains to send.
        if req.message.ends_with(b"\r\n") {
            self.t.write_all(b".\r\n").await?;
        } else {
            self.t.write_all(b"\r\n.\r\n").await?;
        }
        self.t.flush().await?;

        let reply = tokio::time::timeout(DATA_TIMEOUT, self.read_reply_inner())
            .await
            .map_err(|_| MailError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut, "smtp DATA timeout")))?
            ?;
        if !reply.is_success() {
            return Err(MailError::ServerReject {
                command: "DATA body".into(),
                reply: reply.message(),
            });
        }
        Ok(SendOutcome {
            accepted,
            rejected,
            data_reply: Some(reply),
        })
    }

    pub async fn noop(&mut self) -> Result<()> {
        let r = self.command("NOOP").await?;
        r.is_success().then_some(()).ok_or_else(|| MailError::ServerReject {
            command: "NOOP".into(),
            reply: r.message(),
        })
    }

    /// Reset the current mail transaction (used by undo-send paths).
    pub async fn rset(&mut self) -> Result<()> {
        let r = self.command("RSET").await?;
        r.is_success().then_some(()).ok_or_else(|| MailError::ServerReject {
            command: "RSET".into(),
            reply: r.message(),
        })
    }

    pub async fn quit(&mut self) -> Result<()> {
        let _ = self.command("QUIT").await;
        Ok(())
    }

    // Socket-security getter kept as a method so `ehlo()` stays readable.
    // (field is private to transport; mirrored here at connect time)
}

/// Parse an EHLO reply into `EhloInfo`. Per RFC 5321 §4.1.1.1 the first
/// 250 line is `domain [SP greeting]` — never an extension. Continuation
/// lines are `KEYWORD[ SP params]`.
fn parse_ehlo_reply(reply: &SmtpReply) -> EhloInfo {
    let mut info = EhloInfo::default();
    for (i, line) in reply.lines.iter().enumerate() {
        if i == 0 {
            info.greeting = line.clone();
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("").to_ascii_uppercase();
        let val = parts.next().unwrap_or("").trim().to_string();
        if !key.is_empty() {
            info.extensions.insert(key, val);
        }
    }
    info
}

fn auth_result(r: SmtpReply) -> Result<()> {
    match r.code {
        235 => Ok(()),
        // 503 "already authenticated" — treat as success state.
        503 => Ok(()),
        _ if r.is_permanent() || r.is_transient() => Err(MailError::Auth(format!(
            "code {} {}",
            r.code,
            r.enhanced.clone().unwrap_or_default()
        ))),
        _ => Err(MailError::Auth(format!("unexpected reply {}", r.code))),
    }
}

/// Reject CRLF/control injection and empty envelopes (SECURITY.md rule 9).
fn validate_envelope(from: &str, to: &[String]) -> Result<()> {
    fn bad(addr: &str) -> bool {
        addr.is_empty()
            || addr.bytes().any(|b| b < 0x20 || b == 0x7F)
            || addr.contains('<')
            || addr.contains('>')
    }
    if bad(from) {
        return Err(MailError::Protocol {
            protocol: PROTO,
            detail: "invalid/envelope-injection sender address".into(),
        });
    }
    if to.is_empty() {
        return Err(MailError::Protocol {
            protocol: PROTO,
            detail: "send request with no recipients".into(),
        });
    }
    for rcpt in to {
        if bad(rcpt) {
            return Err(MailError::Protocol {
                protocol: PROTO,
                detail: format!("invalid/envelope-injection recipient: {rcpt:?}"),
            });
        }
    }
    Ok(())
}

/// RFC 5321 §4.5.2 transparency: double any leading-dot line.
/// Input must already use CRLF line endings (our `mime` builder does).
fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 64);
    let mut at_line_start = true;
    for &b in body {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}

// ---------------------------------------------------------------------------
// Send queue — hooks for undo-send and send-later (Mailspring-style).
// In-memory for now; persistence behind the store layer (T-105) later.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct QueuedSend {
    pub queue_id: String,
    pub request: SendRequest,
    /// Earliest dispatch time (send-later). `0` = immediately eligible.
    pub not_before_unix: i64,
    /// Dispatch is frozen until this point (undo-send grace window).
    /// Cancelling before it expires is a true undo.
    pub undo_window_until_unix: i64,
    pub attempts: u32,
}

#[derive(Default)]
pub struct SendQueue {
    pending: Vec<QueuedSend>,
}

impl std::fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendRequest")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl SendQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, item: QueuedSend) {
        self.pending.push(item);
    }

    /// Undo-send: remove a queued item. Only valid while its undo window
    /// is still open and it hasn't been dispatched.
    pub fn cancel(&mut self, queue_id: &str, now: i64) -> bool {
        let before = self.pending.len();
        self.pending
            .retain(|q| !(q.queue_id == queue_id && now < q.undo_window_until_unix));
        self.pending.len() != before
    }

    /// Drain sends whose `not_before` has arrived. Callers run `send_mail`
    /// on each; a transient failure should re-enqueue with backoff.
    pub fn due(&mut self, now: i64) -> Vec<QueuedSend> {
        let (due, pending): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|q| q.not_before_unix <= now);
        self.pending = pending;
        due
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TlsSettings;
    use tokio::io::duplex;

    fn transport_for(server: tokio::io::DuplexStream) -> Transport {
        Transport::from_stream(
            server,
            "mail.example.test",
            25,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        )
    }

    #[tokio::test]
    async fn ehlo_parses_extensions() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end
                .write_all(b"220 mx.example.test ESMTP ready\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"250-mx.example.test greets you\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n",
                )
                .await
                .unwrap();
        });
        let mut c = SmtpClient::connect(transport_for(client_end), SmtpConfig::default())
            .await
            .unwrap();
        let ehlo = c.ehlo_info().unwrap();
        assert!(ehlo.has_starttls());
        assert_eq!(ehlo.auth_mechanisms(), vec!["PLAIN", "LOGIN"]);
        assert_eq!(ehlo.max_size(), Some(10_485_760));
        c.quit().await.unwrap();
    }

    #[tokio::test]
    async fn starttls_required_fails_closed() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end
                .write_all(b"220 mx.example.test ESMTP\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(b"250 mx.example.test\r\n")
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            TlsSettings::default(),
        );
        match SmtpClient::connect(t, SmtpConfig::default()).await {
            Err(e) => assert!(matches!(e, MailError::Protocol { .. })),
            Ok(_) => panic!("connect must fail closed without STARTTLS"),
        }
    }

    #[tokio::test]
    async fn plaintext_auth_refused_by_default() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end
                .write_all(b"220 mx\r\n250 mx\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
        });
        let mut c = SmtpClient::connect(transport_for(client_end), SmtpConfig::default())
            .await
            .unwrap();
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        assert!(matches!(
            c.authenticate(&auth).await,
            Err(MailError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn send_mail_dot_stuffs_and_reports_rejections() {
        let (client_end, mut server_end) = duplex(1 << 20);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            server_end.write_all(b"220 mx\r\n").await.unwrap();
            // EHLO
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 mx\r\n").await.unwrap();
            // MAIL FROM
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 2.1.0 ok\r\n").await.unwrap();
            // RCPT 1 ok, RCPT 2 rejected
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 2.1.5 ok\r\n").await.unwrap();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"550 5.1.1 no such user\r\n").await.unwrap();
            // DATA
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"354 go\r\n").await.unwrap();
            // read dot-terminated body
            loop {
                let l = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
                if l == b"." {
                    break;
                }
            }
            server_end.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
        });

        let mut c = SmtpClient::connect(
            transport_for(client_end),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let req = SendRequest {
            from: "me@example.test".into(),
            to: vec!["ok@x.test".into(), "bad@x.test".into()],
            message: b"Subject: t\r\n\r\nstarts with dot\r\n.danger\r\n".to_vec(),
        };
        let out = c.send_mail(&req).await.unwrap();
        assert_eq!(out.accepted, vec!["ok@x.test"]);
        assert_eq!(out.rejected.len(), 1);
        assert_eq!(out.rejected[0].1.code, 550);
        assert_eq!(out.data_reply.unwrap().code, 250);
    }

    #[test]
    fn envelope_injection_rejected() {
        assert!(validate_envelope("a@b", &["x@y".to_string()]).is_ok());
        assert!(validate_envelope("a@b\r\nRCPT TO:<evil>", &["x@y".into()]).is_err());
        assert!(validate_envelope("a@b", &[]).is_err());
        assert!(validate_envelope("", &["x@y".into()]).is_err());
    }

    #[test]
    fn dot_stuffing() {
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n");
        assert_eq!(dot_stuff(b".lead"), b"..lead");
    }

    #[test]
    fn send_queue_undo_and_due() {
        let mut q = SendQueue::new();
        q.enqueue(QueuedSend {
            queue_id: "q1".into(),
            request: SendRequest { from: "a".into(), to: vec!["b".into()], message: vec![] },
            not_before_unix: 100,
            undo_window_until_unix: 50,
            attempts: 0,
        });
        assert!(q.cancel("q1", 40)); // inside undo window
        q.enqueue(QueuedSend {
            queue_id: "q2".into(),
            request: SendRequest { from: "a".into(), to: vec!["b".into()], message: vec![] },
            not_before_unix: 100,
            undo_window_until_unix: 50,
            attempts: 0,
        });
        assert!(!q.cancel("q2", 60)); // window closed
        assert_eq!(q.due(99).len(), 0);
        assert_eq!(q.due(100).len(), 1);
        assert_eq!(q.pending_count(), 0);
    }

    // ------------------------------------------------------------------
    // Recorded-transcript state-machine tests (in-code fixtures pending
    // Agent 6's T-114 transcript corpus).
    // ------------------------------------------------------------------

    use crate::transport::CertVerdict;
    use tokio::task::JoinHandle;

    /// Spawn a scripted "server". Each step is `(expected_prefix, reply)`:
    /// `None` sends bytes immediately (server-initiated greeting); `Some`
    /// first reads a client line and asserts its prefix before replying.
    fn serve(
        mut end: tokio::io::DuplexStream,
        steps: Vec<(Option<&'static str>, &'static [u8])>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = Vec::new();
            for (expect_prefix, reply) in steps {
                if let Some(p) = expect_prefix {
                    let line = read_line(&mut end, &mut buf, PROTO).await.unwrap();
                    let got = String::from_utf8_lossy(&line);
                    assert!(got.starts_with(p), "expected {p:?}, got {got:?}");
                }
                end.write_all(reply).await.unwrap();
            }
        })
    }

    fn plain_transport(end: tokio::io::DuplexStream) -> Transport {
        Transport::from_stream(
            end,
            "mail.example.test",
            25,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        )
    }

    #[tokio::test]
    async fn greeting_not_220_rejects() {
        let (c, mut s) = duplex(4096);
        let h = tokio::spawn(async move {
            s.write_all(b"554 go away\r\n").await.unwrap();
        });
        let r = SmtpClient::connect(plain_transport(c), SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::ServerReject { .. })));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ehlo_falls_back_to_helo() {
        let (c, s) = duplex(8192);
        let _h = serve(
            s,
            vec![
                (None, b"220 mx\r\n"),
                (Some("EHLO"), b"500 unrecognized\r\n"),
                (Some("HELO"), b"250 mx\r\n"),
                (Some("QUIT"), b"221 bye\r\n"),
            ],
        );
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        assert!(client.ehlo_info().unwrap().extensions.is_empty());
        client.quit().await.unwrap();
    }

    #[tokio::test]
    async fn multiline_reply_code_mismatch_is_protocol_error() {
        let (c, mut s) = duplex(8192);
        let _h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            // inconsistent continuation code — a malformed reply
            s.write_all(b"250-ok so far\r\n451 changed my mind\r\n")
                .await
                .unwrap();
        });
        let r = SmtpClient::connect(plain_transport(c), SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::Protocol { .. })));
    }

    #[tokio::test]
    async fn auth_login_two_step() {
        let (c, mut s) = duplex(8192);
        let enc = base64::engine::general_purpose::STANDARD;
        let h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250-mx\r\n250 AUTH LOGIN PLAIN\r\n").await.unwrap();
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // AUTH LOGIN
            assert_eq!(l, b"AUTH LOGIN");
            s.write_all(b"334 VXNlcm5hbWU6\r\n").await.unwrap();      // "Username:"
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // base64(user)
            assert_eq!(l, enc.encode("alice").as_bytes());
            s.write_all(b"334 UGFzc3dvcmQ6\r\n").await.unwrap();      // "Password:"
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // base64(pass)
            assert_eq!(l, enc.encode("s3cret").as_bytes());
            s.write_all(b"235 2.7.0 authenticated\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(
            plain_transport(c),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        client
            .authenticate(&SmtpAuth::Login {
                user: "alice".into(),
                password: Zeroizing::new("s3cret".into()),
            })
            .await
            .unwrap();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn auth_failure_maps_to_auth_error() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // AUTH PLAIN
            s.write_all(b"535 5.7.8 bad credentials\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(
            plain_transport(c),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("wrong".into()),
        };
        match client.authenticate(&auth).await {
            Err(MailError::Auth(detail)) => assert!(detail.contains("535")),
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn all_recipients_rejected_skips_data_and_rsets() {
        let (c, mut s) = duplex(8192);
        let h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // MAIL
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // RCPT 1
            s.write_all(b"550 nope\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // RCPT 2
            s.write_all(b"551 nope\r\n").await.unwrap();
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // must be RSET
            assert_eq!(l, b"RSET");
            s.write_all(b"250 reset\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into(), "b@y".into()],
            message: b"Subject: x\r\n\r\nhi\r\n".to_vec(),
        };
        let out = client.send_mail(&req).await.unwrap();
        assert!(out.accepted.is_empty());
        assert_eq!(out.rejected.len(), 2);
        assert!(out.data_reply.is_none());
        h.await.unwrap();
    }

    #[tokio::test]
    async fn data_command_rejected() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // DATA
            s.write_all(b"554 transaction failed\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into()],
            message: b"Subject: x\r\n\r\nhi\r\n".to_vec(),
        };
        assert!(matches!(
            client.send_mail(&req).await,
            Err(MailError::ServerReject { .. })
        ));
    }

    #[tokio::test]
    async fn size_over_limit_refused_before_sending() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 SIZE 100\r\n").await.unwrap();
            // server must NOT see MAIL FROM
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into()],
            message: vec![b'x'; 500],
        };
        assert!(matches!(
            client.send_mail(&req).await,
            Err(MailError::ServerReject { .. })
        ));
    }

    /// Real rustls server over duplex: exercises the STARTTLS upgrade path
    /// end-to-end and asserts the recorded TlsObservation.
    #[tokio::test]
    async fn starttls_upgrade_captures_tls_observation() {
        // Self-signed fixture cert; client trusts it via extra_roots.
        let certified =
            rcgen::generate_simple_self_signed(vec!["mail.example.test".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx ESMTP\r\n").await.unwrap();
            let mut buf = Vec::new();
            // EHLO (plaintext)
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            // STARTTLS
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            assert_eq!(l, b"STARTTLS");
            s.write_all(b"220 Go ahead\r\n").await.unwrap();
            // TLS handshake on the same stream
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let mut tls = acceptor.accept(s).await.unwrap();
            // EHLO again (post-TLS)
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"250-mx\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            // AUTH PLAIN (over TLS now)
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"235 2.7.0 ok\r\n")
                .await
                .unwrap();
        });

        let settings = TlsSettings {
            accept_invalid_certs: false,
            extra_roots: vec![cert_der.as_ref().to_vec()],
        };
        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            settings,
        );
        let mut client = SmtpClient::connect(t, SmtpConfig::default()).await.unwrap();

        let obs = client.transport().observation().expect("tls observation");
        assert!(obs.upgraded_via_starttls);
        assert_eq!(obs.cert_verdict, Some(CertVerdict::Valid));
        assert!(!obs.peer_certificates.is_empty());
        assert!(obs.cipher_suite.is_some());
        assert!(client.transport().is_encrypted());

        // Plaintext-auth gate must now pass (transport is encrypted).
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        client.authenticate(&auth).await.unwrap();
    }

    /// Same upgrade but with an untrusted cert: `accept_invalid_certs`
    /// completes the handshake while the real verdict is still recorded.
    #[tokio::test]
    async fn starttls_records_invalid_verdict_when_accepted_for_test() {
        // CA-signed leaf for "other.test"; client trusts the CA, so chain
        // verification succeeds and the failure lands on the hostname check.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["kiwi-test-ca".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["other.test".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let leaf_der = leaf_cert.der().clone();
        let leaf_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            leaf_key.serialize_der().into(),
        );
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], leaf_key_der)
            .unwrap();
        let ca_der = ca_cert.der().to_vec();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let mut tls = acceptor.accept(s).await.unwrap();
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"250 mx\r\n").await.unwrap();
        });

        // Hostname mismatch: cert is for "other.test", we connect as
        // "mail.example.test" — verdict must be HostnameMismatch.
        let settings = TlsSettings {
            accept_invalid_certs: true,
            extra_roots: vec![ca_der],
        };
        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            settings,
        );
        let client = SmtpClient::connect(t, SmtpConfig::default()).await.unwrap();
        let obs = client.transport().observation().unwrap();
        assert!(obs.upgraded_via_starttls);
        assert_eq!(obs.cert_verdict, Some(CertVerdict::HostnameMismatch));
    }

    /// Strict default: invalid cert without the test hatch must fail.
    #[tokio::test]
    async fn starttls_invalid_cert_rejected_by_default() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["other.test".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let _ = acceptor.accept(s).await; // will fail client-side; ignore
        });

        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            TlsSettings::default(), // strict
        );
        let r = SmtpClient::connect(t, SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::Tls(_))));
    }
}
