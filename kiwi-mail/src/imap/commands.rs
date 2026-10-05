//! IMAP commands — `impl ImapClient` for the RFC 3501 command set
//! (greeting/CAPABILITY/STLS/AUTH, SELECT/LIST/STATUS/CREATE/DELETE/
//! RENAME, FETCH/SEARCH/STORE/COPY/MOVE, APPEND, IDLE, EXPUNGE/NOOP/
//! LOGOUT) plus the tagged/untagged/continuation response driver.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::{MailError, Result};
use crate::lines::{read_line, write_line};
use crate::transport::{SocketSecurity, Transport};

use super::*;

// ---------------------------------------------------------------------------

/// Continuation callback for `command_cont`: given the server's `+` line,
/// produce the next client line (e.g. a base64 SASL blob).
type ContFn<'a> = &'a mut dyn FnMut(&[u8]) -> Vec<u8>;

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
            // Match the LIST verb case-insensitively but parse the rest
            // verbatim — mailbox names are case-sensitive (RFC 3501 §5.1:
            // only INBOX is case-invariant).
            if text.len() >= 5 && text[..5].eq_ignore_ascii_case("LIST ") {
                let rest = &text[5..];
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

    /// RFC 3501 §6.3.8 hierarchy delimiter via `LIST "" ""` — the root
    /// reply's name is the empty string, which `list()` drops, so the
    /// delimiter needs its own probe. `Ok(None)` = flat namespace (NIL).
    pub async fn hierarchy_delimiter(&mut self) -> Result<Option<String>> {
        let out = Self::ok_or_reject(self.command("LIST \"\" \"\"").await?, "LIST")?;
        for line in &out.untagged {
            let text = String::from_utf8_lossy(line);
            if text.len() >= 5 && text[..5].eq_ignore_ascii_case("LIST ") {
                let rest = &text[5..];
                // LIST (flags) "delim" name — the delimiter is the first
                // quoted atom after the flags list.
                if let Some(close) = rest.find(')') {
                    let tail = rest[close + 1..].trim();
                    let delim = tail
                        .split(' ')
                        .next()
                        .map(|d| d.trim_matches('"').to_string())
                        .filter(|d| d != "NIL" && !d.is_empty());
                    if delim.is_some() {
                        return Ok(delim);
                    }
                }
            }
        }
        Ok(None)
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
