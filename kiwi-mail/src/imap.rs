//! IMAP4rev1 receive client (RFC 3501, plus UIDPLUS/MOVE where advertised).
//!
//! Structure: `ImapClient` owns a `Transport`; commands are tagged
//! (`A0001 …`), responses are classified untagged (`*`), continuation (`+`),
//! or tagged completion. Protocol data is parsed through a bounded
//! S-expression layer (`sexp`) — server output is untrusted input.
//!
//! Sync primitives (`select`, `uid_fetch`, `uid_search`, `status`) expose the
//! UIDVALIDITY/UIDNEXT facts `sync.rs` needs; IDLE is a bounded wait that
//! collects untagged change notifications.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::{MailError, Result};
use crate::lines::{read_line, write_line};
use crate::transport::{SocketSecurity, Transport};

const PROTO: &str = "imap";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// RFC 3501 allows literals; we bound each response buffer.
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
/// Cap on untagged `* ` lines collected per command — a hostile or broken
/// server could otherwise flood memory between command and tagged reply.
const MAX_UNTAGGED: usize = 8192;
/// Cap on IDLE-collected notifications per idle cycle.
const MAX_IDLE_EVENTS: usize = 4096;

// ---------------------------------------------------------------------------
// S-expression layer (imap parenthesized lists / quoted strings / literals)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SExp {
    Nil,
    Atom(String),
    Str(Vec<u8>),
    Num(u64),
    List(Vec<SExp>),
}

impl SExp {
    pub fn as_str(&self) -> Option<String> {
        match self {
            SExp::Str(b) => Some(String::from_utf8_lossy(b).into_owned()),
            SExp::Atom(s) => Some(s.clone()),
            SExp::Num(n) => Some(n.to_string()),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            SExp::Num(n) => Some(*n),
            SExp::Atom(_) | SExp::Str(_) => self.as_str()?.parse().ok(),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[SExp]> {
        match self {
            SExp::List(v) => Some(v),
            _ => None,
        }
    }
}

struct SParser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> SParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.b.len() && self.b[self.pos] == b' ' {
            self.pos += 1;
        }
    }

    fn parse(&mut self) -> Result<SExp> {
        self.skip_ws();
        if self.pos >= self.b.len() {
            return Err(proto_err("unexpected end of response"));
        }
        match self.b[self.pos] {
            b'(' => self.list(),
            b'"' => self.quoted(),
            b'{' => self.literal(),
            _ => self.atom(),
        }
    }

    fn list(&mut self) -> Result<SExp> {
        self.pos += 1; // '('
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.pos >= self.b.len() {
                return Err(proto_err("unterminated list"));
            }
            if self.b[self.pos] == b')' {
                self.pos += 1;
                return Ok(SExp::List(items));
            }
            items.push(self.parse()?);
            if items.len() > 100_000 {
                return Err(proto_err("list too deep/long"));
            }
        }
    }

    fn quoted(&mut self) -> Result<SExp> {
        self.pos += 1; // '"'
        let mut out = Vec::new();
        while self.pos < self.b.len() {
            let c = self.b[self.pos];
            self.pos += 1;
            match c {
                b'"' => return Ok(SExp::Str(out)),
                b'\\' => {
                    if self.pos >= self.b.len() {
                        return Err(proto_err("truncated escape"));
                    }
                    out.push(self.b[self.pos]);
                    self.pos += 1;
                }
                _ => out.push(c),
            }
            if out.len() > MAX_RESPONSE {
                return Err(proto_err("quoted string too large"));
            }
        }
        Err(proto_err("unterminated quoted string"))
    }

    /// `{n}` literal: the next n raw bytes belong to this value.
    fn literal(&mut self) -> Result<SExp> {
        self.pos += 1; // '{'
        let start = self.pos;
        while self.pos < self.b.len() && self.b[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let digits_end = self.pos;
        // tolerate `{n+}` (non-sync literal marker)
        if self.pos < self.b.len() && self.b[self.pos] == b'+' {
            self.pos += 1;
        }
        if self.pos >= self.b.len() || self.b[self.pos] != b'}' {
            return Err(proto_err("malformed literal marker"));
        }
        if digits_end == start {
            return Err(proto_err("empty literal length"));
        }
        let n: usize = std::str::from_utf8(&self.b[start..digits_end])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| proto_err("bad literal length"))?;
        self.pos += 1; // '}'
        // skip the CRLF that frames the literal
        if self.b.get(self.pos) == Some(&b'\r') {
            self.pos += 1;
        }
        if self.b.get(self.pos) == Some(&b'\n') {
            self.pos += 1;
        }
        if self.pos + n > self.b.len() {
            return Err(proto_err("literal overruns buffer"));
        }
        let data = self.b[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(SExp::Str(data))
    }

    fn atom(&mut self) -> Result<SExp> {
        let start = self.pos;
        while self.pos < self.b.len() {
            match self.b[self.pos] {
                b' ' | b'(' | b')' | b'"' | b'{' | b'%' | b'*' | 0x00..=0x1f | 0x7f => break,
                _ => self.pos += 1,
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.pos])
            .map_err(|_| proto_err("non-utf8 atom"))?;
        if s.eq_ignore_ascii_case("nil") {
            return Ok(SExp::Nil);
        }
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(SExp::Num(s.parse().map_err(|_| proto_err("bad number"))?));
        }
        Ok(SExp::Atom(s.to_string()))
    }
}

fn proto_err(detail: impl Into<String>) -> MailError {
    MailError::Protocol {
        protocol: PROTO,
        detail: detail.into(),
    }
}

/// Parse a complete S-expression buffer (e.g. an untagged FETCH payload).
pub fn parse_sexp(bytes: &[u8]) -> Result<SExp> {
    let mut p = SParser { b: bytes, pos: 0 };
    p.skip_ws();
    let v = p.parse()?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Typed structures produced by the client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaggedCode {
    Ok,
    No,
    Bad,
}

pub struct CommandOutcome {
    pub code: TaggedCode,
    /// Untagged `* ` response payloads (bytes after `* `, CRLF stripped,
    /// literals embedded raw).
    pub untagged: Vec<Vec<u8>>,
    /// Free-text portion of the tagged completion.
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct SelectInfo {
    pub mailbox: String,
    pub exists: u64,
    pub recent: u64,
    pub unseen: Option<u64>,
    pub uid_validity: Option<u64>,
    pub uid_next: Option<u64>,
    pub flags: Vec<String>,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct MailboxInfo {
    pub flags: Vec<String>,
    pub delimiter: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Envelope {
    pub date: Option<String>,
    pub subject: Option<String>,
    pub from: Vec<Mailbox>,
    pub sender: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub in_reply_to: Option<String>,
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub email: String,
}

/// Recursive MIME structure descriptor from BODYSTRUCTURE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStructure {
    Single {
        media_type: String,
        subtype: String,
        params: Vec<(String, String)>,
        encoding: String,
        octets: u64,
    },
    Multi {
        subtype: String,
        parts: Vec<BodyStructure>,
        params: Vec<(String, String)>,
    },
    /// Shape we couldn't classify — kept for evidence, never panics.
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct FetchItem {
    pub seq: u64,
    pub uid: Option<u64>,
    pub flags: Vec<String>,
    pub size: Option<u64>,
    pub internal_date: Option<String>,
    pub envelope: Option<Envelope>,
    pub bodystructure: Option<BodyStructure>,
    /// `BODY[...]` literal payloads (section spec → bytes).
    pub bodies: Vec<(String, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Continuation callback for `command_cont`: given the server's `+` line,
/// produce the next client line (e.g. a base64 SASL blob).
type ContFn<'a> = &'a mut dyn FnMut(&[u8]) -> Vec<u8>;

pub struct ImapClient {
    t: Transport,
    config: ImapConfig,
    tag_counter: u32,
    capabilities: BTreeSet<String>,
    scratch: Vec<u8>,
}

/// Client policy. Plaintext auth is refused unless explicitly opted in —
/// same posture as `SmtpConfig`/`Pop3Config`.
#[derive(Debug, Clone, Default)]
pub struct ImapConfig {
    /// Allow LOGIN/AUTHENTICATE over an unencrypted transport. Default false.
    pub allow_plaintext_auth: bool,
}

/// Login/authenticate credential forms. Secrets are zeroizing.
pub enum ImapAuth {
    Login {
        user: String,
        password: Zeroizing<String>,
    },
    /// AUTHENTICATE XOAUTH2 (works with/without SASL-IR).
    XOAuth2 {
        user: String,
        token: Zeroizing<String>,
    },
    /// AUTHENTICATE PLAIN.
    Plain {
        user: String,
        password: Zeroizing<String>,
    },
}

impl ImapClient {
    /// Connect: consume the greeting (`* OK`/`PREAUTH`/`BYE`), fetch
    /// CAPABILITY, and perform STLS when the socket is `StartTls`.
    pub async fn connect(t: Transport) -> Result<Self> {
        Self::connect_with(t, ImapConfig::default()).await
    }

    /// Connect with explicit policy (e.g. test/local plaintext opt-in).
    pub async fn connect_with(t: Transport, config: ImapConfig) -> Result<Self> {
        let mut c = Self {
            t,
            config,
            tag_counter: 0,
            capabilities: BTreeSet::new(),
            scratch: Vec::new(),
        };
        // Greeting: single untagged line — `* OK`, `* PREAUTH`, or `* BYE`.
        let line = c.read_response_line().await?;
        let text = String::from_utf8_lossy(&line).to_string();
        let status = text
            .strip_prefix('*')
            .map(str::trim)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("")
            .to_ascii_uppercase();
        if status != "OK" && status != "PREAUTH" {
            return Err(MailError::ServerReject {
                command: "connect".into(),
                reply: text,
            });
        }
        c.capability().await?;
        if c.t.socket_security() == SocketSecurity::StartTls {
            if c.has_capability("STARTTLS") {
                let out = c.command("STARTTLS").await?;
                if out.code != TaggedCode::Ok {
                    return Err(MailError::ServerReject {
                        command: "STARTTLS".into(),
                        reply: out.text,
                    });
                }
                c.t.starttls_upgrade().await?;
                // Post-STLS state may differ — refresh capabilities.
                c.capability().await?;
            } else {
                return Err(proto_err(
                    "server does not advertise STARTTLS; connection refused \
                     (possible downgrade attempt)",
                ));
            }
        }
        Ok(c)
    }

    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.contains(&cap.to_ascii_uppercase())
    }

    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    pub fn transport(&self) -> &Transport {
        &self.t
    }

    fn next_tag(&mut self) -> String {
        self.tag_counter += 1;
        format!("A{:04}", self.tag_counter)
    }

    /// Read one logical response line, inlining `{n}` literals so S-expr
    /// parsing sees a single buffer. A line ending in `{n}` or `{n+}` means
    /// the next n raw bytes are literal content continuing the same line.
    async fn read_response_line(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        loop {
            if buf.len() > MAX_RESPONSE {
                return Err(proto_err("response exceeds aggregate bound"));
            }
            let line = read_line(&mut self.t, &mut self.scratch, PROTO).await?;
            buf.extend_from_slice(&line);
            match trailing_literal_len(&line) {
                Some(n) => {
                    // Bound checked BEFORE allocation and applied to the
                    // aggregate buffer — N literals of 64MB each must not
                    // grow `buf` without limit.
                    if n > MAX_RESPONSE || buf.len() + n + 2 > MAX_RESPONSE {
                        return Err(proto_err("literal exceeds bound"));
                    }
                    // keep `{n}` + framing CRLF so the sexp literal parser sees them
                    buf.extend_from_slice(b"\r\n");
                    let mut lit = vec![0u8; n];
                    tokio::io::AsyncReadExt::read_exact(&mut self.t, &mut lit).await?;
                    buf.extend_from_slice(&lit);
                }
                None => break,
            }
        }
        Ok(buf)
    }

    /// Send a tagged command; `on_cont` produces continuation lines when the
    /// server replies `+ ` (used by AUTHENTICATE without SASL-IR).
    async fn command(&mut self, cmd: &str) -> Result<CommandOutcome> {
        self.command_cont(cmd, None).await
    }

    async fn command_cont(
        &mut self,
        cmd: &str,
        mut on_cont: Option<ContFn<'_>>,
    ) -> Result<CommandOutcome> {
        let tag = self.next_tag();
        write_line(&mut self.t, format!("{tag} {cmd}").as_bytes()).await?;

        let mut untagged = Vec::new();
        loop {
            let line = tokio::time::timeout(CMD_TIMEOUT, self.read_response_line())
                .await
                .map_err(|_| {
                    MailError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "imap timeout",
                    ))
                })??;
            if line.starts_with(b"* ") {
                untagged.push(line[2..].to_vec());
                if untagged.len() > MAX_UNTAGGED {
                    return Err(proto_err("unbounded untagged responses"));
                }
            } else if line.starts_with(b"+ ") || line == b"+" {
                match &mut on_cont {
                    Some(cb) => {
                        let resp = cb(&line);
                        write_line(&mut self.t, &resp).await?;
                    }
                    None => return Err(proto_err("unexpected continuation")),
                }
            } else if is_tagged(&line, &tag) {
                let rest = String::from_utf8_lossy(&line[tag.len()..])
                    .trim()
                    .to_string();
                let upper = rest.to_ascii_uppercase();
                let (code, text) = if upper.starts_with("OK") {
                    (TaggedCode::Ok, rest[2..].trim().to_string())
                } else if upper.starts_with("NO") {
                    (TaggedCode::No, rest[2..].trim().to_string())
                } else if upper.starts_with("BAD") {
                    (TaggedCode::Bad, rest[3..].trim().to_string())
                } else {
                    return Err(proto_err(format!("bad tagged reply: {rest}")));
                };
                return Ok(CommandOutcome {
                    code,
                    untagged,
                    text,
                });
            } else {
                return Err(proto_err(format!(
                    "unrecognized response line: {}",
                    String::from_utf8_lossy(&line)
                )));
            }
        }
    }

    fn ok_or_reject(out: CommandOutcome, cmd: &str) -> Result<CommandOutcome> {
        match out.code {
            TaggedCode::Ok => Ok(out),
            TaggedCode::No => Err(MailError::ServerReject {
                command: cmd.into(),
                reply: out.text,
            }),
            TaggedCode::Bad => Err(proto_err(format!("server BAD on {cmd}: {}", out.text))),
        }
    }

    // -- commands ----------------------------------------------------------

    pub async fn capability(&mut self) -> Result<BTreeSet<String>> {
        let out = Self::ok_or_reject(self.command("CAPABILITY").await?, "CAPABILITY")?;
        let mut caps = BTreeSet::new();
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line);
            if let Some(rest) = text.to_ascii_uppercase().strip_prefix("CAPABILITY") {
                for tok in rest.split_whitespace() {
                    caps.insert(tok.to_ascii_uppercase());
                }
            }
        }
        // RFC 5161: the tagged reply may carry `[CAPABILITY a b c]` with no
        // untagged line at all — merge those tokens too.
        if let Some(list) = bracket_list(&out.text, "CAPABILITY") {
            for tok in list.split_whitespace() {
                caps.insert(tok.to_ascii_uppercase());
            }
        }
        self.capabilities = caps.clone();
        Ok(caps)
    }

    pub async fn authenticate(&mut self, auth: &ImapAuth) -> Result<()> {
        if !self.t.is_encrypted() && !self.config.allow_plaintext_auth {
            return Err(proto_err(
                "refusing to send credentials over plaintext transport \
                 (allow_plaintext_auth is off)",
            ));
        }
        let enc = base64::engine::general_purpose::STANDARD;
        match auth {
            ImapAuth::Login { user, password } => {
                check_quoted(user)?;
                check_quoted(password)?;
                let out = self
                    .command(&format!("LOGIN {} {}", quoted(user), quoted(password)))
                    .await?;
                Self::ok_or_reject(out, "LOGIN")?;
            }
            ImapAuth::Plain { user, password } => {
                let payload = Zeroizing::new(format!("\0{user}\0{}", password.as_str()));
                if self.has_capability("SASL-IR") {
                    let b64 = enc.encode(payload.as_bytes());
                    let out = self.command(&format!("AUTHENTICATE PLAIN {b64}")).await?;
                    Self::ok_or_reject(out, "AUTHENTICATE PLAIN")?;
                } else {
                    let payload_b64 = enc.encode(payload.as_bytes()).into_bytes();
                    let out = self
                        .command_cont(
                            "AUTHENTICATE PLAIN",
                            Some(&mut |_challenge| payload_b64.clone()),
                        )
                        .await?;
                    Self::ok_or_reject(out, "AUTHENTICATE PLAIN")?;
                }
            }
            ImapAuth::XOAuth2 { user, token } => {
                let sasl = Zeroizing::new(format!(
                    "user={user}\x01auth=Bearer {}\x01\x01",
                    token.as_str()
                ));
                let b64 = enc.encode(sasl.as_bytes()).into_bytes();
                let out = self
                    .command_cont("AUTHENTICATE XOAUTH2", Some(&mut move |_| b64.clone()))
                    .await?;
                Self::ok_or_reject(out, "AUTHENTICATE XOAUTH2")?;
            }
        }
        Ok(())
    }

    /// SELECT (or EXAMINE when `read_only`) — returns mailbox state the sync
    /// engine needs (UIDVALIDITY, UIDNEXT, EXISTS).
    pub async fn select(&mut self, mailbox: &str, read_only: bool) -> Result<SelectInfo> {
        check_quoted(mailbox)?;
        let cmd = if read_only { "EXAMINE" } else { "SELECT" };
        let out = Self::ok_or_reject(
            self.command(&format!("{cmd} {}", quoted(mailbox))).await?,
            cmd,
        )?;
        let mut info = SelectInfo {
            mailbox: mailbox.into(),
            read_only,
            ..Default::default()
        };
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line).to_string();
            let upper = text.to_ascii_uppercase();
            // `* <n> EXISTS` / `* <n> RECENT` — strict two-token shape so
            // e.g. an OK free-text ending in "EXISTS" can't be misread.
            let mut toks = upper.split_whitespace();
            let word = toks.nth(1).unwrap_or("");
            let count = upper
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            match (count, word) {
                (Some(n), "EXISTS") => info.exists = n,
                (Some(n), "RECENT") => info.recent = n,
                _ => {}
            }
            if word == "EXISTS" || word == "RECENT" {
                continue;
            }
            if upper.starts_with("OK") {
                if let Some(v) = bracket_value(&text, "UIDVALIDITY") {
                    info.uid_validity = v.parse().ok();
                }
                if let Some(v) = bracket_value(&text, "UIDNEXT") {
                    info.uid_next = v.parse().ok();
                }
                if let Some(v) = bracket_value(&text, "UNSEEN") {
                    info.unseen = v.parse().ok();
                }
            } else if upper.starts_with("FLAGS")
                && let Ok(SExp::List(items)) = parse_sexp(text[5..].trim().as_bytes())
            {
                info.flags = items.iter().filter_map(|i| i.as_str()).collect();
            }
        }
        if out.text.to_ascii_uppercase().contains("READ-ONLY") {
            info.read_only = true;
        }
        Ok(info)
    }

    /// LIST reference pattern → mailbox descriptors.
    pub async fn list(&mut self, reference: &str, pattern: &str) -> Result<Vec<MailboxInfo>> {
        check_quoted(reference)?;
        check_quoted(pattern)?;
        let out = Self::ok_or_reject(
            self.command(&format!("LIST {} {}", quoted(reference), quoted(pattern)))
                .await?,
            "LIST",
        )?;
        let mut boxes = Vec::new();
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line);
            if let Some(rest) = text.to_ascii_uppercase().strip_prefix("LIST ") {
                // LIST (flags) "delim" name
                if let Ok(SExp::List(flags)) = parse_sexp(rest.trim_start().as_bytes()) {
                    let flags: Vec<String> = flags.iter().filter_map(|f| f.as_str()).collect();
                    // naive tail parse: after the flags list, ` "delim" name`
                    let tail_start = rest.find(')').map(|i| i + 1).unwrap_or(0);
                    let tail = rest[tail_start..].trim();
                    let mut parts = tail.splitn(2, ' ');
                    let delim = parts
                        .next()
                        .map(|d| d.trim_matches('"'))
                        .filter(|d| *d != "NIL")
                        .map(str::to_string);
                    let name = parts
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"')
                        .to_string();
                    if !name.is_empty() {
                        boxes.push(MailboxInfo {
                            flags,
                            delimiter: delim,
                            name,
                        });
                    }
                }
            }
        }
        Ok(boxes)
    }

    pub async fn create_mailbox(&mut self, name: &str) -> Result<()> {
        check_quoted(name)?;
        Self::ok_or_reject(
            self.command(&format!("CREATE {}", quoted(name))).await?,
            "CREATE",
        )?;
        Ok(())
    }

    pub async fn delete_mailbox(&mut self, name: &str) -> Result<()> {
        check_quoted(name)?;
        Self::ok_or_reject(
            self.command(&format!("DELETE {}", quoted(name))).await?,
            "DELETE",
        )?;
        Ok(())
    }

    pub async fn rename_mailbox(&mut self, from: &str, to: &str) -> Result<()> {
        check_quoted(from)?;
        check_quoted(to)?;
        Self::ok_or_reject(
            self.command(&format!("RENAME {} {}", quoted(from), quoted(to)))
                .await?,
            "RENAME",
        )?;
        Ok(())
    }

    /// STATUS mailbox (items…) → (item, value) pairs. Doesn't SELECT.
    pub async fn status(&mut self, mailbox: &str, items: &[&str]) -> Result<Vec<(String, u64)>> {
        check_quoted(mailbox)?;
        for it in items {
            check_bare(it)?;
        }
        let list = items.join(" ");
        let out = Self::ok_or_reject(
            self.command(&format!("STATUS {} ({list})", quoted(mailbox)))
                .await?,
            "STATUS",
        )?;
        let mut pairs = Vec::new();
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line);
            if let Some(open) = text.find('(')
                && let Ok(SExp::List(items)) = parse_sexp(text[open..].trim_end().as_bytes())
            {
                for kv in items.chunks(2) {
                    if let (Some(k), Some(v)) = (kv[0].as_str(), kv.get(1).and_then(|v| v.as_u64()))
                    {
                        pairs.push((k.to_ascii_uppercase(), v));
                    }
                }
            }
        }
        Ok(pairs)
    }

    /// FETCH over a sequence set (e.g. "1:*" or "1,2,3").
    /// `items`: raw FETCH data-item names, e.g. `["UID","FLAGS","ENVELOPE"]`.
    pub async fn fetch(&mut self, seq_set: &str, items: &[&str]) -> Result<Vec<FetchItem>> {
        self.fetch_impl(seq_set, items, false).await
    }

    /// UID FETCH — sequence numbers are UIDs; stable across expunges.
    pub async fn uid_fetch(&mut self, uid_set: &str, items: &[&str]) -> Result<Vec<FetchItem>> {
        self.fetch_impl(uid_set, items, true).await
    }

    async fn fetch_impl(
        &mut self,
        set: &str,
        items: &[&str],
        uid_mode: bool,
    ) -> Result<Vec<FetchItem>> {
        check_bare(set)?;
        for it in items {
            // BODY[HEADER.FIELDS (…)] items contain spaces+parens — allow
            // them, still rejecting control characters.
            check_tail(it)?;
        }
        let item_list = items.join(" ");
        let cmd = if uid_mode {
            format!("UID FETCH {set} ({item_list})")
        } else {
            format!("FETCH {set} ({item_list})")
        };
        let out = Self::ok_or_reject(self.command(&cmd).await?, "FETCH")?;
        let mut fetched = Vec::new();
        for line in &out.untagged {
            if let Some(item) = parse_fetch_line(line)? {
                fetched.push(item);
            }
        }
        Ok(fetched)
    }

    /// `UID SEARCH <criteria>` → matching UIDs.
    pub async fn uid_search(&mut self, criteria: &str) -> Result<Vec<u64>> {
        check_tail(criteria)?;
        let out = Self::ok_or_reject(
            self.command(&format!("UID SEARCH {criteria}")).await?,
            "UID SEARCH",
        )?;
        let mut uids = Vec::new();
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line);
            if let Some(rest) = text.to_ascii_uppercase().strip_prefix("SEARCH") {
                for tok in rest.split_whitespace() {
                    if let Ok(u) = tok.parse() {
                        uids.push(u);
                    }
                }
            }
        }
        Ok(uids)
    }

    /// `UID STORE set +FLAGS|−FLAGS[.SILENT] (…)` — flag mutations.
    pub async fn uid_store(&mut self, uid_set: &str, op: &str, flags: &[&str]) -> Result<()> {
        check_bare(uid_set)?;
        check_bare(op)?;
        for f in flags {
            check_bare(f)?;
        }
        let flag_list = flags.join(" ");
        let out = Self::ok_or_reject(
            self.command(&format!("UID STORE {uid_set} {op} ({flag_list})"))
                .await?,
            "UID STORE",
        )?;
        let _ = out;
        Ok(())
    }

    /// `UID COPY set mailbox`.
    pub async fn uid_copy(&mut self, uid_set: &str, mailbox: &str) -> Result<()> {
        check_bare(uid_set)?;
        check_quoted(mailbox)?;
        Self::ok_or_reject(
            self.command(&format!("UID COPY {uid_set} {}", quoted(mailbox)))
                .await?,
            "UID COPY",
        )?;
        Ok(())
    }

    /// `UID MOVE` (RFC 6851) when advertised; callers fall back to
    /// COPY+STORE+EXPUNGE otherwise.
    pub async fn uid_move(&mut self, uid_set: &str, mailbox: &str) -> Result<()> {
        check_bare(uid_set)?;
        check_quoted(mailbox)?;
        if !self.has_capability("MOVE") {
            self.uid_copy(uid_set, mailbox).await?;
            self.uid_store(uid_set, "+FLAGS.SILENT", &["\\Deleted"])
                .await?;
            return self.expunge().await;
        }
        Self::ok_or_reject(
            self.command(&format!("UID MOVE {uid_set} {}", quoted(mailbox)))
                .await?,
            "UID MOVE",
        )?;
        Ok(())
    }

    /// APPEND a fully-formed RFC 5322 message to a mailbox (sent-mail save).
    pub async fn append(&mut self, mailbox: &str, flags: &[&str], message: &[u8]) -> Result<()> {
        if message.len() > MAX_RESPONSE {
            return Err(proto_err("append message too large"));
        }
        for f in flags {
            check_bare(f)?;
        }
        check_quoted(mailbox)?;
        // Non-sync literal `{n+}` avoids a round trip when LITERAL+ is
        // supported; otherwise the server replies `+` and we send the
        // literal bytes then CRLF — the literal IS the line tail, so the
        // continuation must be written raw (write_line would append a
        // second CRLF, leaving a phantom empty command on the wire).
        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" ({})", flags.join(" "))
        };
        let literal_plus = self.has_capability("LITERAL+") || self.has_capability("LITERAL-");
        let head = format!(
            "APPEND {}{} {{{}{}}}",
            quoted(mailbox),
            flag_str,
            message.len(),
            if literal_plus { "+" } else { "" },
        );
        let tag = self.send_tagged(&head).await?;
        if !literal_plus {
            // Wait for the `+ ` continuation before sending the literal.
            self.await_continuation(&tag).await?;
        }
        self.t.write_all(message).await?;
        self.t.write_all(b"\r\n").await?;
        let out = self.await_tagged(&tag).await?;
        Self::ok_or_reject(out, "APPEND")?;
        Ok(())
    }

    /// Read until the server sends `+ ` (continuation) for `tag`'s command;
    /// a tagged completion first means the command was rejected outright.
    async fn await_continuation(&mut self, tag: &str) -> Result<()> {
        loop {
            let line = tokio::time::timeout(CMD_TIMEOUT, self.read_response_line())
                .await
                .map_err(|_| {
                    MailError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "imap timeout",
                    ))
                })??;
            if line.starts_with(b"+ ") || line == b"+" {
                return Ok(());
            }
            if line.starts_with(b"* ") {
                continue;
            }
            if is_tagged(&line, tag) {
                return Err(proto_err("APPEND rejected before literal send"));
            }
            return Err(proto_err("unrecognized response awaiting continuation"));
        }
    }

    /// Send `line` prefixed with a fresh tag; returns the tag.
    async fn send_tagged(&mut self, line: &str) -> Result<String> {
        let tag = self.next_tag();
        write_line(&mut self.t, format!("{tag} {line}").as_bytes()).await?;
        Ok(tag)
    }

    /// Read lines until the tagged completion for the in-flight command
    /// (APPEND literal path sends its tag before the message bytes).
    async fn await_tagged(&mut self, tag: &str) -> Result<CommandOutcome> {
        let mut untagged = Vec::new();
        loop {
            let line = tokio::time::timeout(CMD_TIMEOUT, self.read_response_line())
                .await
                .map_err(|_| {
                    MailError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "imap timeout",
                    ))
                })??;
            if line.starts_with(b"* ") {
                untagged.push(line[2..].to_vec());
                if untagged.len() > MAX_UNTAGGED {
                    return Err(proto_err("unbounded untagged responses"));
                }
            } else if line.starts_with(b"+ ") || line == b"+" {
                // server wants the literal — shouldn't happen post-send
                return Err(proto_err("unexpected continuation during APPEND"));
            } else if is_tagged(&line, tag) {
                let rest = String::from_utf8_lossy(&line[tag.len()..])
                    .trim()
                    .to_string();
                let code = if rest.to_ascii_uppercase().starts_with("OK") {
                    TaggedCode::Ok
                } else if rest.to_ascii_uppercase().starts_with("NO") {
                    TaggedCode::No
                } else {
                    TaggedCode::Bad
                };
                return Ok(CommandOutcome {
                    code,
                    untagged,
                    text: rest,
                });
            } else {
                return Err(proto_err(format!(
                    "unrecognized response line: {}",
                    String::from_utf8_lossy(&line)
                )));
            }
        }
    }

    pub async fn expunge(&mut self) -> Result<()> {
        Self::ok_or_reject(self.command("EXPUNGE").await?, "EXPUNGE")?;
        Ok(())
    }

    pub async fn noop(&mut self) -> Result<()> {
        Self::ok_or_reject(self.command("NOOP").await?, "NOOP")?;
        Ok(())
    }

    /// IDLE: enter idle, collect untagged notifications until `duration`
    /// expires, then send DONE (RFC 2177). Returns raw untagged payloads;
    /// callers interpret EXISTS/EXPUNGE/FETCH notifications.
    pub async fn idle_collect(&mut self, duration: Duration) -> Result<Vec<Vec<u8>>> {
        if !self.has_capability("IDLE") {
            return Err(proto_err("IDLE not advertised"));
        }
        let tag = self.next_tag();
        write_line(&mut self.t, format!("{tag} IDLE").as_bytes()).await?;
        let cont = self.read_response_line().await?;
        if !(cont.starts_with(b"+")) {
            return Err(proto_err("IDLE rejected (no continuation)"));
        }
        let mut events = Vec::new();
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline || events.len() >= MAX_IDLE_EVENTS {
                break;
            }
            match tokio::time::timeout_at(deadline, self.read_response_line()).await {
                Ok(Ok(line)) if line.starts_with(b"* ") => events.push(line[2..].to_vec()),
                _ => break,
            }
        }
        write_line(&mut self.t, b"DONE").await?;
        // Read tagged completion of the IDLE command — bounded wait: a
        // server that never answers DONE must not hang the client.
        loop {
            let line = tokio::time::timeout(CMD_TIMEOUT, self.read_response_line())
                .await
                .map_err(|_| {
                    MailError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "imap timeout",
                    ))
                })??;
            if is_tagged(&line, &tag) {
                break;
            }
            if line.starts_with(b"* ") && events.len() < MAX_IDLE_EVENTS {
                events.push(line[2..].to_vec());
            }
        }
        Ok(events)
    }

    pub async fn logout(&mut self) -> Result<()> {
        let _ = self.command("LOGOUT").await;
        Ok(())
    }
}

/// Tagged reply match: line is `<tag> SP <status> …` — the space matters,
/// otherwise "A00010 OK" would satisfy a pending "A0001".
fn is_tagged(line: &[u8], tag: &str) -> bool {
    line.len() > tag.len() && line.starts_with(tag.as_bytes()) && line[tag.len()] == b' '
}

/// Extract `[KEY …]` list contents from a response code (e.g.
/// `[CAPABILITY IMAP4rev2 IDLE]` → `Some("IMAP4rev2 IDLE")`).
fn bracket_list(text: &str, key: &str) -> Option<String> {
    let upper = text.to_ascii_uppercase();
    let k = key.to_ascii_uppercase();
    let start = upper.find(&format!("[{k}"))?;
    let inner_start = start + k.len() + 1;
    if text.as_bytes().get(inner_start) == Some(&b' ') {
        let rest = &text[inner_start + 1..];
        let end = rest.find(']')?;
        return Some(rest[..end].to_string());
    }
    // `[KEY]` with no value
    if text.as_bytes().get(inner_start) == Some(&b']') {
        return Some(String::new());
    }
    None
}

/// If `line` ends with an IMAP literal marker `{n}` or `{n+}`, return `n`.
fn trailing_literal_len(line: &[u8]) -> Option<usize> {
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line.iter().rposition(|&b| b == b'{')?;
    let inner = &line[open + 1..line.len() - 1];
    let inner = inner.strip_suffix(b"+").unwrap_or(inner);
    if inner.is_empty() || !inner.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(inner).ok()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn quoted(s: &str) -> String {
    // IMAP quoted-string: escape '"' and '\'.
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Reject control characters in arguments interpolated into command lines —
/// CR/LF inside a quoted string would splice a second command onto the wire
/// (same injection class as SMTP envelope validation).
fn check_quoted(s: &str) -> Result<()> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(proto_err("control character in quoted argument"));
    }
    Ok(())
}

/// Bare arguments (flags, UID sets, item names, ops) join the command
/// unquoted — they additionally must not be empty or contain whitespace.
fn check_bare(s: &str) -> Result<()> {
    if s.is_empty() || s.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(proto_err("invalid bare argument"));
    }
    Ok(())
}

/// Free-form command tails (SEARCH criteria) may contain spaces but never
/// control characters.
fn check_tail(s: &str) -> Result<()> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(proto_err("control character in command argument"));
    }
    Ok(())
}

/// Extract `[KEY value]` response-code values from a tagged/untagged text.
fn bracket_value(text: &str, key: &str) -> Option<String> {
    let upper = text.to_ascii_uppercase();
    let k = key.to_ascii_uppercase();
    let start = upper.find(&format!("[{k} "))? + k.len() + 2;
    let rest = &text[start..];
    let end = rest.find([']', ' '])?;
    Some(rest[..end].to_string())
}

/// Parse one `* <seq> FETCH (…)` untagged line into a FetchItem.
fn parse_fetch_line(line: &[u8]) -> Result<Option<FetchItem>> {
    // shape: `<seq> FETCH (<pairs>)`
    let text = line;
    let fetch_pos = {
        let upper = String::from_utf8_lossy(text).to_ascii_uppercase();
        match upper.find(" FETCH (") {
            Some(p) => p,
            None => return Ok(None), // e.g. EXISTS/RECENT/etc.
        }
    };
    let seq: u64 = String::from_utf8_lossy(&text[..fetch_pos])
        .trim()
        .parse()
        .map_err(|_| proto_err("FETCH line with non-numeric seq"))?;
    let sexp = parse_sexp(&text[fetch_pos + 6..])?;
    let SExp::List(pairs) = sexp else {
        return Err(proto_err("FETCH payload not a list"));
    };
    let mut item = FetchItem {
        seq,
        ..Default::default()
    };
    let mut i = 0;
    while i + 1 < pairs.len() + 1 && i < pairs.len() {
        let key = pairs[i].as_str().unwrap_or_default().to_ascii_uppercase();
        let val = pairs.get(i + 1);
        match key.as_str() {
            "UID" => item.uid = val.and_then(|v| v.as_u64()),
            "RFC822.SIZE" => item.size = val.and_then(|v| v.as_u64()),
            "INTERNALDATE" => item.internal_date = val.and_then(|v| v.as_str()),
            "FLAGS" => {
                if let Some(SExp::List(fl)) = val {
                    item.flags = fl.iter().filter_map(|f| f.as_str()).collect();
                }
            }
            "ENVELOPE" => {
                if let Some(v) = val {
                    item.envelope = parse_envelope(v);
                }
            }
            "BODYSTRUCTURE" => {
                if let Some(v) = val {
                    item.bodystructure = Some(parse_bodystructure(v));
                }
            }
            k if k.starts_with("BODY") || k == "RFC822" => {
                if let Some(SExp::Str(bytes)) = val {
                    item.bodies.push((key, bytes.clone()));
                }
            }
            _ => {}
        }
        i += 2;
    }
    Ok(Some(item))
}

fn parse_address_list(s: &SExp) -> Vec<Mailbox> {
    let mut out = Vec::new();
    if let SExp::List(addrs) = s {
        for a in addrs {
            if let SExp::List(fields) = a {
                let name = fields
                    .first()
                    .and_then(|f| f.as_str())
                    .filter(|s| !s.is_empty());
                let mailbox = fields.get(2).and_then(|f| f.as_str()).unwrap_or_default();
                let host = fields.get(3).and_then(|f| f.as_str()).unwrap_or_default();
                let email = if host.is_empty() {
                    mailbox
                } else {
                    format!("{mailbox}@{host}")
                };
                if !email.is_empty() {
                    out.push(Mailbox { name, email });
                }
            }
        }
    }
    out
}

fn parse_envelope(s: &SExp) -> Option<Envelope> {
    let SExp::List(f) = s else { return None };
    // RFC 3501 defines 10 slots; tolerate servers that emit fewer — read
    // positionally, absent fields stay None (untrusted input, rule 9).
    let get = |i: usize| f.get(i).and_then(|v| v.as_str());
    let addr = |i: usize| f.get(i).map(parse_address_list).unwrap_or_default();
    Some(Envelope {
        date: get(0),
        subject: get(1),
        from: addr(2),
        sender: addr(3),
        reply_to: addr(4),
        to: addr(5),
        cc: addr(6),
        bcc: addr(7),
        in_reply_to: get(8),
        message_id: get(9),
    })
}

fn parse_params(s: &SExp) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let SExp::List(items) = s {
        for kv in items.chunks(2) {
            if let (Some(k), Some(v)) = (kv[0].as_str(), kv.get(1).and_then(|x| x.as_str())) {
                out.push((k, v));
            }
        }
    }
    out
}

fn parse_bodystructure(s: &SExp) -> BodyStructure {
    let SExp::List(f) = s else {
        return BodyStructure::Unknown;
    };
    if f.is_empty() {
        return BodyStructure::Unknown;
    }
    // Multipart: leading elements are part lists, then subtype string.
    if matches!(f[0], SExp::List(_)) {
        let mut parts = Vec::new();
        let mut idx = 0;
        while idx < f.len() && matches!(f[idx], SExp::List(_)) {
            parts.push(parse_bodystructure(&f[idx]));
            idx += 1;
        }
        let subtype = f.get(idx).and_then(|v| v.as_str()).unwrap_or_default();
        let params = f.get(idx + 1).map(parse_params).unwrap_or_default();
        return BodyStructure::Multi {
            subtype,
            parts,
            params,
        };
    }
    // Single part: type subtype params id desc encoding octets …
    let media_type = f[0].as_str().unwrap_or_default();
    let subtype = f.get(1).and_then(|v| v.as_str()).unwrap_or_default();
    let params = f.get(2).map(parse_params).unwrap_or_default();
    let encoding = f.get(5).and_then(|v| v.as_str()).unwrap_or_default();
    let octets = f.get(6).and_then(|v| v.as_u64()).unwrap_or(0);
    if media_type.is_empty() {
        return BodyStructure::Unknown;
    }
    BodyStructure::Single {
        media_type,
        subtype,
        params,
        encoding,
        octets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TlsSettings;
    use tokio::io::duplex;

    #[test]
    fn sexp_parses_lists_strings_literals() {
        let s = parse_sexp(b"(FLAGS (\\Seen \\Deleted) UID 42 SUBJECT \"hi \\\"x\\\"\")").unwrap();
        let SExp::List(items) = s else {
            panic!("not list")
        };
        assert_eq!(items[0].as_str().unwrap(), "FLAGS");
    }

    #[test]
    fn sexp_handles_literal() {
        let s = parse_sexp(b"(BODY[] {5}\r\nhello UID 9)").unwrap();
        let SExp::List(items) = s else {
            panic!("not list")
        };
        assert_eq!(items[1], SExp::Str(b"hello".to_vec()));
        assert_eq!(items[2].as_str().unwrap(), "UID");
        assert_eq!(items[3].as_u64(), Some(9));
    }

    #[test]
    fn sexp_rejects_malformed() {
        assert!(parse_sexp(b"(unterminated").is_err());
        assert!(parse_sexp(b"\"unterminated").is_err());
    }

    #[test]
    fn envelope_parses() {
        let raw = b"FETCH (ENVELOPE (\"Wed, 17 Sep 2025 10:00:00 +0000\" \"hello subj\" ((\"Alice\" NIL \"alice\" \"x.test\")) NIL NIL ((NIL NIL \"bob\" \"y.test\")) NIL NIL \"<r@x>\" \"<m@x>\"))";
        let s = parse_sexp(&raw[6..]).unwrap();
        let env = parse_envelope(&s.as_list().unwrap()[1]).unwrap();
        assert_eq!(env.subject.as_deref(), Some("hello subj"));
        assert_eq!(env.from[0].email, "alice@x.test");
        assert_eq!(env.from[0].name.as_deref(), Some("Alice"));
        assert_eq!(env.to[0].email, "bob@y.test");
        assert_eq!(env.message_id.as_deref(), Some("<m@x>"));
    }

    #[test]
    fn bodystructure_multipart() {
        let raw = b"((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 100 2)(\"text\" \"html\" NIL NIL NIL \"8bit\" 200 3) \"alternative\" (\"boundary\" \"b1\"))";
        let s = parse_sexp(raw).unwrap();
        match parse_bodystructure(&s) {
            BodyStructure::Multi { subtype, parts, .. } => {
                assert_eq!(subtype, "alternative");
                assert_eq!(parts.len(), 2);
            }
            other => panic!("expected multipart, got {other:?}"),
        }
    }

    #[test]
    fn fetch_line_parses() {
        let line = b"23 FETCH (UID 1001 FLAGS (\\Seen) RFC822.SIZE 1234 INTERNALDATE \"17-Sep-2025 10:00:00 +0000\" ENVELOPE (\"d\" \"s\" ((\"A\" NIL \"a\" \"x.test\")) NIL NIL NIL NIL NIL \"<r>\" \"<m>\"))";
        let item = parse_fetch_line(line).unwrap().unwrap();
        assert_eq!(item.seq, 23);
        assert_eq!(item.uid, Some(1001));
        assert_eq!(item.flags, vec!["\\Seen"]);
        assert_eq!(item.size, Some(1234));
        assert_eq!(item.envelope.unwrap().message_id.as_deref(), Some("<m>"));
    }

    #[tokio::test]
    async fn connect_capability_select_flow() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end.write_all(b"* OK imap ready\r\n").await.unwrap();
            let mut buf = Vec::new();
            // CAPABILITY
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"* CAPABILITY IMAP4rev1 UIDPLUS IDLE MOVE LITERAL+\r\nA0001 OK done\r\n",
                )
                .await
                .unwrap();
            // SELECT
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n* 3 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 777] uids\r\n* OK [UIDNEXT 1004] next\r\nA0002 OK [READ-WRITE] selected\r\n",
                )
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext, // plaintext socket: connect skips STLS
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        assert!(c.has_capability("UIDPLUS"));
        assert!(c.has_capability("IDLE"));
        let sel = c.select("INBOX", false).await.unwrap();
        assert_eq!(sel.exists, 3);
        assert_eq!(sel.uid_validity, Some(777));
        assert_eq!(sel.uid_next, Some(1004));
        assert_eq!(sel.flags, vec!["\\Seen", "\\Deleted"]);
        assert!(!sel.read_only);
    }

    #[test]
    fn tagged_match_requires_space() {
        assert!(is_tagged(b"A0001 OK done", "A0001"));
        assert!(!is_tagged(b"A00010 OK sneaky", "A0001"));
        assert!(!is_tagged(b"A0001", "A0001"));
    }

    #[test]
    fn command_args_reject_ctl() {
        assert!(check_quoted("INBOX\r\nA9 NOOP").is_err());
        assert!(check_quoted("Normal Box").is_ok());
        assert!(check_bare("1,2:*").is_ok());
        assert!(check_bare("1 2").is_err());
        assert!(check_bare("").is_err());
        assert!(check_tail("UNSEEN SINCE 1-Feb-1994").is_ok());
        assert!(check_tail("ALL\r\nLOGOUT").is_err());
    }

    #[tokio::test]
    async fn connect_rejects_bye_greeting() {
        let (client_end, mut server_end) = duplex(1 << 16);
        let h = tokio::spawn(async move {
            let _ = server_end
                .write_all(b"* BYE server is shutting down\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let r = ImapClient::connect(t).await;
        assert!(matches!(r, Err(MailError::ServerReject { .. })));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_preauth() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* PREAUTH logged in\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await;
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let c = ImapClient::connect(t).await.unwrap();
        assert!(c.has_capability("IMAP4rev1"));
    }

    /// Two literals each under the per-literal bound but over the aggregate
    /// response bound — the second must be rejected before allocation.
    #[tokio::test]
    async fn aggregate_literal_bound() {
        const BIG: usize = 60 * 1024 * 1024;
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* OK ready\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await; // CAPABILITY
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
            let _ = read_line(&mut server_end, &mut buf, PROTO).await; // UID FETCH
            let _ = server_end
                .write_all(format!("* 1 FETCH (BODY[] {{{BIG}}}\r\n").as_bytes())
                .await;
            let _ = server_end.write_all(&vec![b'x'; BIG]).await;
            let _ = server_end
                .write_all(b" UID 1 {20000000}\r\nA0002 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        let r = c.uid_fetch("1", &["UID", "BODY[]"]).await;
        assert!(matches!(r, Err(MailError::Protocol { .. })));
    }

    /// CRLF inside a mailbox name must be rejected before anything is sent.
    #[tokio::test]
    async fn select_injection_rejected() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* OK ready\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await;
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        assert!(matches!(
            c.select("INBOX\r\nA9 NOOP", false).await,
            Err(MailError::Protocol { .. })
        ));
        assert!(matches!(
            c.uid_search("ALL\r\nA9 LOGOUT").await,
            Err(MailError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn uid_search_parses_uids() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end.write_all(b"* OK ready\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap(); // CAPABILITY
            server_end
                .write_all(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\nA0001 OK\r\n")
                .await
                .unwrap();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap(); // UID SEARCH
            server_end
                .write_all(b"* SEARCH 1001 1002 1010\r\nA0002 OK search done\r\n")
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        let uids = c.uid_search("ALL").await.unwrap();
        assert_eq!(uids, vec![1001, 1002, 1010]);
    }
}
