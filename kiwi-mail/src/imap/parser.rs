//! IMAP response parsing — S-expression layer + typed reply structures.
//!
//! Server output is untrusted input: bounded parsing only (see the
//! `MAX_*` bounds in the parent module). `commands.rs` consumes the
//! types and helpers defined here.

use crate::error::{MailError, Result};

use super::{MAX_RESPONSE, PROTO};

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

pub(crate) fn proto_err(detail: impl Into<String>) -> MailError {
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
        /// Content-Disposition token verbatim ("attachment", "inline", …).
        /// `None` when the server sent no disposition tuple.
        disposition: Option<String>,
        /// Disposition's own parameter list — `filename=` lives here,
        /// distinct from the Content-Type `params` (where `name=` lives).
        disp_params: Vec<(String, String)>,
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

/// otherwise "A00010 OK" would satisfy a pending "A0001".
pub(crate) fn is_tagged(line: &[u8], tag: &str) -> bool {
    line.len() > tag.len() && line.starts_with(tag.as_bytes()) && line[tag.len()] == b' '
}

/// Extract `[KEY …]` list contents from a response code (e.g.
/// `[CAPABILITY IMAP4rev2 IDLE]` → `Some("IMAP4rev2 IDLE")`).
pub(crate) fn bracket_list(text: &str, key: &str) -> Option<String> {
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
pub(crate) fn trailing_literal_len(line: &[u8]) -> Option<usize> {
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

pub(crate) fn quoted(s: &str) -> String {
    // IMAP quoted-string: escape '"' and '\'.
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Reject control characters in arguments interpolated into command lines —
/// CR/LF inside a quoted string would splice a second command onto the wire
/// (same injection class as SMTP envelope validation).
pub(crate) fn check_quoted(s: &str) -> Result<()> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(proto_err("control character in quoted argument"));
    }
    Ok(())
}

/// Bare arguments (flags, UID sets, item names, ops) join the command
/// unquoted — they additionally must not be empty or contain whitespace.
pub(crate) fn check_bare(s: &str) -> Result<()> {
    if s.is_empty() || s.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(proto_err("invalid bare argument"));
    }
    Ok(())
}

/// Free-form command tails (SEARCH criteria) may contain spaces but never
/// control characters.
pub(crate) fn check_tail(s: &str) -> Result<()> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(proto_err("control character in command argument"));
    }
    Ok(())
}

/// Extract `[KEY value]` response-code values from a tagged/untagged text.
pub(crate) fn bracket_value(text: &str, key: &str) -> Option<String> {
    let upper = text.to_ascii_uppercase();
    let k = key.to_ascii_uppercase();
    let start = upper.find(&format!("[{k} "))? + k.len() + 2;
    let rest = &text[start..];
    let end = rest.find([']', ' '])?;
    Some(rest[..end].to_string())
}

/// Parse one `* <seq> FETCH (…)` untagged line into a FetchItem.
pub(crate) fn parse_fetch_line(line: &[u8]) -> Result<Option<FetchItem>> {
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

pub(crate) fn parse_address_list(s: &SExp) -> Vec<Mailbox> {
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

pub(crate) fn parse_envelope(s: &SExp) -> Option<Envelope> {
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

pub(crate) fn parse_params(s: &SExp) -> Vec<(String, String)> {
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

pub(crate) fn parse_bodystructure(s: &SExp) -> BodyStructure {
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
    // The disposition tuple `("ATTACHMENT" ("FILENAME" "x.pdf"))` sits in
    // the extension tail — position varies (text parts carry a `lines`
    // count first, message/rfc822 carries envelope+structure). Scan for
    // the list whose head is a known disposition keyword; an embedded
    // message's envelope/structure lists can't collide (their heads are
    // a date string and a list, respectively).
    let mut disposition = None;
    let mut disp_params = Vec::new();
    for ext in f.iter().skip(7) {
        let SExp::List(d) = ext else { continue };
        let Some(head) = d.first().and_then(|v| v.as_str()) else {
            continue;
        };
        if head.eq_ignore_ascii_case("attachment") || head.eq_ignore_ascii_case("inline") {
            disposition = Some(head.to_string());
            disp_params = d.get(1).map(parse_params).unwrap_or_default();
            break;
        }
    }
    BodyStructure::Single {
        media_type,
        subtype,
        params,
        encoding,
        octets,
        disposition,
        disp_params,
    }
}
