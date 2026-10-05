//! mbox import (T-309): split a Berkeley mbox file into per-message RFC822
//! payloads and read the Thunderbird status headers.
//!
//! Wire rules implemented (mboxrd, the variant Thunderbird writes):
//!
//! - A line starting with `From ` (exactly five bytes, then a space) at the
//!   start of the file or immediately after a `\n` is a message separator —
//!   the *envelope* line, not part of the message. Everything between it and
//!   the next separator is one stored message.
//! - Inside a message, a body line matching `>+From ` was written escaped;
//!   one leading `>` is stripped on read (`>>From ` → `>From `, and so on).
//!   A line that starts with `From ` inside message bytes is by definition
//!   the next separator, so no ambiguity remains.
//! - `X-Mozilla-Status:` / `X-Mozilla-Status2:` are 4-hex-digit bit fields
//!   Thunderbird stamps on stored messages (nsMsgMessageFlags.idl). Mapped
//!   flags are best-effort and documented below; unknown bits are ignored.
//!
//! The parser never fabricates: bytes a caller hands in are split and
//! unescaped verbatim; header decoding is left to `crate::mime::parse_message`
//! on the unescaped payload.

/// One mbox member: the separator line's envelope fields plus the unescaped
/// message bytes that follow it.
#[derive(Debug, Clone)]
pub struct MboxMessage {
    /// 1-based ordinal in the file (reporting key for per-message issues).
    pub index: usize,
    /// Envelope sender token from the `From ` line, if one was present and
    /// bounded. The timestamp half is not parsed — the message's own `Date:`
    /// header is authoritative and already survives via the MIME pipeline.
    pub envelope_from: Option<String>,
    /// Unescaped RFC822 payload (the `From ` line itself stripped).
    pub raw: Vec<u8>,
}

/// `From ` separator prefix.
const SEP: &[u8] = b"From ";
/// Bound on the envelope-sender token kept from the `From ` line.
const MAX_ENVELOPE_FROM: usize = 256;
/// Header scan bound for the Mozilla status lookup — the headers block of a
/// real message is well under this; beyond it we stop caring.
const STATUS_SCAN_BYTES: usize = 32 * 1024;

/// Split `bytes` into mbox members.
///
/// Returns `None` when the file contains no `From ` separator at all — the
/// caller treats that as "not an mbox file" (a hard input error), distinct
/// from a file whose individual members fail to parse later.
///
/// Bytes before the first separator are expected to be absent or pure
/// whitespace (BOM tolerated); anything else is reported via
/// [`MboxSplit::leading_junk`] so the caller can say so honestly.
pub fn split_mbox(bytes: &[u8]) -> Option<MboxSplit> {
    let mut messages = Vec::new();
    let mut cur: Option<MboxMessage> = None;
    let mut saw_separator = false;
    let mut leading_junk = false;
    let mut pos = 0usize;

    while pos <= bytes.len() {
        let line_end = find_line_end(bytes, pos);
        let line = &bytes[pos..line_end.content_end];

        if line.starts_with(SEP) {
            saw_separator = true;
            if let Some(msg) = cur.take() {
                messages.push(finish(msg));
            }
            cur = Some(MboxMessage {
                index: messages.len() + 1,
                envelope_from: envelope_sender(&line[SEP.len()..]),
                raw: Vec::new(),
            });
        } else if let Some(msg) = cur.as_mut() {
            // Re-append the line including its terminator — the message keeps
            // its original line endings. `next_pos` is len+1 at EOF, so clamp.
            let end = line_end.next_pos.min(bytes.len());
            msg.raw.extend_from_slice(&bytes[pos..end]);
        } else if !line.iter().all(|b| b.is_ascii_whitespace()) {
            leading_junk = true;
        }

        pos = line_end.next_pos;
    }
    if let Some(msg) = cur.take() {
        messages.push(finish(msg));
    }
    if !saw_separator {
        return None;
    }
    Some(MboxSplit {
        messages,
        leading_junk,
    })
}

/// Result of [`split_mbox`].
#[derive(Debug)]
pub struct MboxSplit {
    pub messages: Vec<MboxMessage>,
    /// Non-whitespace bytes appeared before the first `From ` line — the file
    /// may still be an mbox (stray preamble), but the caller reports it.
    pub leading_junk: bool,
}

/// `(content_end, next_pos)` for the line starting at `pos`: content excludes
/// the terminator; `next_pos` skips `\r\n` or `\n`.
fn find_line_end(bytes: &[u8], pos: usize) -> LineEnd {
    let rel = &bytes[pos..];
    let nl = rel.iter().position(|b| *b == b'\n');
    match nl {
        None => LineEnd {
            content_end: bytes.len(),
            next_pos: bytes.len() + 1, // sentinel: terminates the loop
        },
        Some(i) => {
            let mut content_end = pos + i;
            if content_end > pos && bytes[content_end - 1] == b'\r' {
                content_end -= 1;
            }
            LineEnd {
                content_end,
                next_pos: pos + i + 1,
            }
        }
    }
}

struct LineEnd {
    content_end: usize,
    next_pos: usize,
}

/// `From ` remainder → sender token (first whitespace-delimited field).
/// `From -` and empty envelopes yield `None`; the token is bounded.
fn envelope_sender(rest: &[u8]) -> Option<String> {
    let end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let tok = &rest[..end.min(MAX_ENVELOPE_FROM)];
    if tok.is_empty() || tok == b"-" {
        return None;
    }
    Some(String::from_utf8_lossy(tok).into_owned())
}

/// Apply mboxrd unescaping to the accumulated payload.
fn finish(mut msg: MboxMessage) -> MboxMessage {
    msg.raw = unescape(&msg.raw);
    msg
}

/// Strip one `>` from every line matching `^>+From ` (mboxrd). Any other
/// line — including `>`-prefixed lines not followed by `From ` — is verbatim.
fn unescape(raw: &[u8]) -> Vec<u8> {
    // Fast path: no escaped line anywhere.
    if !needs_unescape(raw) {
        return raw.to_vec();
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while pos <= raw.len() {
        let le = find_line_end(raw, pos);
        let line = &raw[pos..le.content_end];
        let n_gt = line.iter().take_while(|b| **b == b'>').count();
        if n_gt > 0 && line[n_gt..].starts_with(SEP) {
            out.extend_from_slice(&line[1..]);
        } else {
            out.extend_from_slice(line);
        }
        // Preserve the terminator bytes (`next_pos` is len+1 at EOF).
        let term_end = le.next_pos.min(raw.len());
        out.extend_from_slice(&raw[le.content_end..term_end]);
        pos = le.next_pos;
    }
    out
}

fn needs_unescape(raw: &[u8]) -> bool {
    // `>>From ` contains `>From `, so one window suffices. A false positive
    // (e.g. `abc>From ` mid-line) is harmless — the line-level check in
    // `unescape` only strips `>`s at line start.
    raw.windows(6).any(|w| w == b">From ")
}

// ---------------------------------------------------------------------------
// Write side (T-316 export) — exact mirrors of the read rules above.
// ---------------------------------------------------------------------------

/// Escape one RFC822 payload for mboxrd output — the mirror of `unescape`:
/// every line matching `^>*From ` gains one leading `>` (`From ` → `>From `,
/// `>From ` → `>>From `, any depth). A bare `From ` line in the output
/// stream is by definition a separator, so it must always be escaped. Line
/// terminators pass through verbatim (the reader accepts both LF and CRLF).
/// Single pass, no fast path — a `>>+From ` check-by-substring is easy to
/// under-match; scanning lines is the same O(n) with no special cases.
pub fn escape_for_mbox(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 16);
    let mut pos = 0usize;
    while pos <= raw.len() {
        let le = find_line_end(raw, pos);
        let line = &raw[pos..le.content_end];
        let n_gt = line.iter().take_while(|b| **b == b'>').count();
        if line[n_gt..].starts_with(SEP) {
            out.push(b'>');
        }
        out.extend_from_slice(line);
        let term_end = le.next_pos.min(raw.len());
        out.extend_from_slice(&raw[le.content_end..term_end]);
        pos = le.next_pos;
    }
    out
}

/// The `From ` separator line — `From <token-or---> <asctime-UTC>` LF. The
/// reader keeps only the sender token and ignores the date, but real mbox
/// consumers expect a timestamp-shaped tail, so emit asctime in UTC
/// (`Sat Jan  4 12:00:00 2025` — space-padded day, deterministic).
/// `date_unix` `None` or unparseable → `From -` alone.
pub fn separator(envelope_from: Option<&str>, date_unix: Option<i64>) -> Vec<u8> {
    let token = envelope_from
        .and_then(|f| {
            // `<a@b>` inside a display-name string wins; else first
            // whitespace-free token.
            let inner = f
                .find('<')
                .and_then(|i| f[i + 1..].find('>').map(|j| &f[i + 1..i + 1 + j]));
            let tok = inner.unwrap_or_else(|| f.split_whitespace().next().unwrap_or(""));
            let tok = &tok[..tok.len().min(MAX_ENVELOPE_FROM)];
            (!tok.is_empty()).then_some(tok)
        })
        .unwrap_or("-");
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(SEP);
    out.extend_from_slice(token.as_bytes());
    if let Some(ts) = date_unix.and_then(asctime_utc) {
        out.push(b' ');
        out.extend_from_slice(ts.as_bytes());
    }
    out.push(b'\n');
    out
}

/// `Jan  4 12:00:00 2025`-style UTC asctime — mbox convention, no timezone
/// suffix (asctime has none). `time` format failures → `None` (emitted bare).
fn asctime_utc(unix: i64) -> Option<String> {
    use time::format_description::{self, FormatItem};
    static FMT: std::sync::OnceLock<Vec<FormatItem<'static>>> = std::sync::OnceLock::new();
    let fmt = FMT.get_or_init(|| {
        format_description::parse_borrowed::<2>(
            "[weekday repr:short] [month repr:short] [day padding:space] \
             [hour]:[minute]:[second] [year]",
        )
        .expect("static asctime format is valid")
    });
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()?
        .format(fmt)
        .ok()
}

/// X-Mozilla-Status header lines for a row's stored flags — the write-side
/// mirror of `mozilla_status`'s read map (same bit table). Returns `None`
/// when no mapped flag is set: absence of the header already means unread,
/// so no stamp is needed.
pub fn mozilla_status_lines(flags: &[String]) -> Option<Vec<u8>> {
    let mut status: u32 = 0;
    let mut status2: u32 = 0;
    for f in flags {
        match f.as_str() {
            "\\Seen" => status |= 0x0001,
            "\\Answered" => status |= 0x0002,
            "\\Flagged" => status |= 0x0004,
            "\\Junk" => status2 |= 0x0008_0000,
            _ => {}
        }
    }
    if status == 0 && status2 == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(format!("X-Mozilla-Status: {status:04x}\r\n").as_bytes());
    if status2 != 0 {
        out.extend_from_slice(format!("X-Mozilla-Status2: {status2:08x}\r\n").as_bytes());
    }
    Some(out)
}

/// True when the payload's header block already carries `X-Mozilla-Status` —
/// a previously-imported message keeps its own stamp; export never doubles it.
pub fn has_mozilla_status(raw: &[u8]) -> bool {
    let scan = &raw[..raw.len().min(STATUS_SCAN_BYTES)];
    let mut pos = 0usize;
    while pos <= scan.len() {
        let le = find_line_end(scan, pos);
        let line = &scan[pos..le.content_end];
        if line.is_empty() {
            break;
        }
        if !line[0].is_ascii_whitespace() && header_value(line, b"x-mozilla-status:").is_some() {
            return true;
        }
        pos = le.next_pos;
    }
    false
}

/// X-Mozilla-Status bit → flag mapping (nsMsgMessageFlags.idl, canonical):
///
/// | bit | flag | wire flag |
/// |-----|------|-----------|
/// | status  `0x0001` Read | → | `\Seen` |
/// | status  `0x0002` Replied | → | `\Answered` |
/// | status  `0x0004` Marked | → | `\Flagged` (starred) |
/// | status  `0x0008` Expunged | → | `skipped_expunged`, not imported |
/// | status2 `0x00080000` (historical Junk) | → | `\Junk` |
///
/// Everything else is display-only or runtime-only state (watched threads,
/// partial bodies, labels, …) and is deliberately not mapped. `status2`'s
/// junk bit predates Thunderbird's junkscore model; when present it is a
/// real stored claim, so it maps — best-effort as specified.
pub struct MozillaStatus {
    /// Wire flags to carry onto the imported row (`\Seen`, `\Answered`,
    /// `\Flagged`, `\Junk` — deduped).
    pub flags: Vec<&'static str>,
    /// `X-Mozilla-Status` bit 0x0008 — the user deleted this message and the
    /// folder was never compacted. Honest behavior is to leave it deleted.
    pub expunged: bool,
}

/// Read the Mozilla status headers from a message's header block. Lines are
/// scanned directly (cheap, no mail-parser dependency, immune to the parsed
/// capture cap); values are hex digits — anything else is absent evidence.
pub fn mozilla_status(raw: &[u8]) -> MozillaStatus {
    let scan = &raw[..raw.len().min(STATUS_SCAN_BYTES)];
    let mut status: Option<u32> = None;
    let mut status2: Option<u32> = None;
    let mut pos = 0usize;
    while pos <= scan.len() {
        let le = find_line_end(scan, pos);
        let line = &scan[pos..le.content_end];
        if line.is_empty() {
            break; // end of header block
        }
        // A continuation line (starts with WSP) never matches a name.
        if !line[0].is_ascii_whitespace() {
            if let Some(rest) = header_value(line, b"x-mozilla-status:") {
                status = hex_flag(rest).or(status);
            } else if let Some(rest) = header_value(line, b"x-mozilla-status2:") {
                status2 = hex_flag(rest).or(status2);
            }
        }
        pos = le.next_pos;
    }
    let st = status.unwrap_or(0);
    let st2 = status2.unwrap_or(0);
    let mut flags = Vec::new();
    if st & 0x0001 != 0 {
        flags.push("\\Seen");
    }
    if st & 0x0002 != 0 {
        flags.push("\\Answered");
    }
    if st & 0x0004 != 0 {
        flags.push("\\Flagged");
    }
    if st2 & 0x0008_0000 != 0 {
        flags.push("\\Junk");
    }
    MozillaStatus {
        flags,
        expunged: st & 0x0008 != 0,
    }
}

/// Trimmed-ASCII hex parse → u32. Garbage → `None` (absent evidence).
fn hex_flag(value: &[u8]) -> Option<u32> {
    let s: Vec<u8> = value
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(|b| b.is_ascii_hexdigit())
        .collect();
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(&s).ok()?, 16).ok()
}

/// `name:` case-insensitive prefix → remainder after the colon.
fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name) {
        Some(&line[name.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_from_lines_and_strips_separator() {
        let mbox = b"From alice@x.test Sat Jan  4 12:00:00 2025\n\
                     From: a@x.test\nSubject: one\n\nbody one\n\
                     From bob@y.test Sat Jan  4 12:01:00 2025\n\
                     Subject: two\n\nbody two\n";
        let split = split_mbox(mbox).unwrap();
        assert_eq!(split.messages.len(), 2);
        assert_eq!(
            split.messages[0].envelope_from.as_deref(),
            Some("alice@x.test")
        );
        assert_eq!(
            split.messages[1].envelope_from.as_deref(),
            Some("bob@y.test")
        );
        assert!(!split.leading_junk);
        // The separator never lands in the payload.
        assert!(!split.messages[0].raw.windows(5).any(|w| w == b"From "));
        assert!(split.messages[0].raw.starts_with(b"From: a@x.test"));
    }

    #[test]
    fn unescapes_from_lines_in_body() {
        // mboxrd escapes ">From" → ">From" and ">>From" → ">From" chains.
        let mbox = b"From - Sat Jan  4 12:00:00 2025\n\
                     Subject: t\n\nplain\n>From notasep\n>>From double\n>end\n";
        let split = split_mbox(mbox).unwrap();
        assert_eq!(split.messages.len(), 1);
        let body = String::from_utf8_lossy(&split.messages[0].raw);
        assert!(body.contains("\nFrom notasep\n"), "{body}");
        assert!(body.contains("\n>From double\n"), "{body}");
        assert!(body.contains(">end"), "{body}"); // > not before From: verbatim
    }

    #[test]
    fn mozilla_status_maps_read_starred_and_expunged() {
        let m2 = b"X-Mozilla-Status: 0005\r\nFrom: b@y.test\r\n\r\nbody two\r\n";
        let read_starred = mozilla_status(m2);
        assert!(read_starred.flags.contains(&"\\Seen"));
        assert!(read_starred.flags.contains(&"\\Flagged"));
        assert!(!read_starred.expunged);

        let deleted = b"X-Mozilla-Status: 0009\r\nFrom: c@x\r\n\r\nx";
        assert!(mozilla_status(deleted).expunged);
        assert!(mozilla_status(deleted).flags.contains(&"\\Seen"));

        let junk = b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00080000\r\n\r\nx";
        assert!(mozilla_status(junk).flags.contains(&"\\Junk"));

        // Garbage value → absent evidence, not a panic or a flag.
        let bad = b"X-Mozilla-Status: zzzz\r\n\r\nx";
        assert!(mozilla_status(bad).flags.is_empty());

        // Header-name match must not hit X-Mozilla-Status2 (prefix check is
        // length-exact including the colon).
        let both = b"X-Mozilla-Status2: 00080000\r\nX-Mozilla-Status: 0001\r\n\r\nx";
        let s = mozilla_status(both);
        assert!(s.flags.contains(&"\\Seen") && s.flags.contains(&"\\Junk"));
    }

    #[test]
    fn crlf_and_lf_both_split() {
        let a = b"From a@x t\nSubject: 1\n\nb1\nFrom b@y t\r\nSubject: 2\r\n\r\nb2\r\n";
        let split = split_mbox(a).unwrap();
        assert_eq!(split.messages.len(), 2);
        // CRLF preserved inside payload — byte-faithful, not normalized.
        assert!(split.messages[1].raw.windows(2).any(|w| w == b"\r\n"));
    }

    #[test]
    fn no_separator_is_none_and_leading_junk_is_flagged() {
        assert!(split_mbox(b"just some text\nno separator\n").is_none());
        let split = split_mbox(b"trailing junk line\nFrom a@x t\nSubject: s\n\nb\n").unwrap();
        assert!(split.leading_junk);
        assert_eq!(split.messages.len(), 1);
        // Whitespace-only preamble is fine (e.g. a stray newline).
        let ok = split_mbox(b"\n\nFrom a@x t\nSubject: s\n\nb\n").unwrap();
        assert!(!ok.leading_junk);
    }

    #[test]
    fn empty_last_member_still_surfaces() {
        // A separator with no content yields an empty raw payload — the
        // import layer counts it as a failed message, not silent loss.
        let split = split_mbox(b"From a@x t\n").unwrap();
        assert_eq!(split.messages.len(), 1);
        assert!(split.messages[0].raw.is_empty());
    }
}
