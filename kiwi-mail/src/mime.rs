//! MIME boundary: parse inbound via mail-parser, build outbound natively.
//!
//! Inbound bytes are untrusted input — mail-parser does the heavy lifting and
//! we only surface a bounded, typed summary. Outbound messages are built
//! here (never by string-concatenating at call sites) so header injection,
//! CRLF normalization, and encoding rules are enforced in one place.

use base64::Engine;
use mail_parser::MimeHeaders;
use serde::{Deserialize, Serialize};

use crate::error::{MailError, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Addr {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, Default)]
pub struct AttachmentMeta {
    pub filename: Option<String>,
    pub content_type: String,
    pub size: usize,
}

/// Bounded summary of a parsed inbound message.
#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub subject: Option<String>,
    pub from: Vec<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub date_unix: Option<i64>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    /// Short plain-text preview for list rows (bounded length).
    pub snippet: String,
    /// Raw top-level headers as `(lowercased-name, value)` pairs, bounded
    /// (see `MAX_CAPTURED_HEADERS`): the deterministic classifier
    /// (`crate::category`) and unsubscribe parser (`crate::unsub`) read
    /// bulk/automation signals from these. Values are raw (unparsed) text
    /// so `<…>`-bracketed forms survive; structured values (dates,
    /// content-types, Received) are already surfaced typed above.
    pub headers: Vec<(String, String)>,
    /// One-click unsubscribe offer (RFC 2369/8058, `crate::unsub`).
    /// `None` when the sender advertised nothing actionable.
    pub unsubscribe: Option<crate::unsub::UnsubscribeInfo>,
    /// Deterministic bounded attachment hint derived while parsing (T-254).
    /// This is evidence for the frontend, never a finding or blocking action.
    pub attach_risk: crate::attachrisk::AttachRiskEvidence,
}

/// Outbound message to serialize. `data` on attachments is already-decoded
/// payload bytes; builder base64-encodes them.
#[derive(Debug)]
pub struct OutboundMessage {
    pub from: Addr,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub subject: String,
    /// Plain-text body (always present).
    pub text: String,
    /// Optional HTML alternative.
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<OutboundAttachment>,
    /// Unix time for the Date header.
    pub date_unix: i64,
    /// Caller-supplied Message-ID (must be unique, angle-bracket free).
    pub message_id: String,
}

#[derive(Debug)]
pub struct OutboundAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// Cap on retained raw headers: Received chains alone can run to dozens
/// of lines and classification needs only a handful of signals.
const MAX_CAPTURED_HEADERS: usize = 128;
/// Header values are truncated past this length (matched signals are short).
const MAX_HEADER_VALUE: usize = 1024;

/// Parse inbound message bytes → bounded summary.
/// Returns Err only on input too malformed to parse at all.
pub fn parse_message(raw: &[u8]) -> Result<ParsedMessage> {
    let msg = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| MailError::Protocol {
            protocol: "mime",
            detail: "unparseable message".into(),
        })?;

    let mut out = ParsedMessage {
        message_id: msg.message_id().map(|s| s.to_string()),
        in_reply_to: msg.in_reply_to().as_text().map(|s| s.to_string()),
        subject: msg.subject().map(|s| s.to_string()),
        ..Default::default()
    };
    if let Some(refs) = msg.references().as_text_list() {
        out.references = refs.iter().map(|s| s.to_string()).collect();
    }
    let map_addrs = |al: Option<&mail_parser::Address>| -> Vec<Addr> {
        al.map(|a| {
            a.iter()
                .map(|addr| Addr {
                    name: addr.name().map(|s| s.to_string()),
                    email: addr.address().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
    };
    out.from = map_addrs(msg.from());
    out.to = map_addrs(msg.to());
    out.cc = map_addrs(msg.cc());
    out.date_unix = msg.date().map(|d| d.to_timestamp());
    out.headers = capture_headers(&msg);
    out.unsubscribe = crate::unsub::parse_unsubscribe(&out.headers);

    // First text/plain part becomes text_body; first text/html → html_body.
    for part in msg.text_bodies() {
        if out.text_body.is_none() {
            out.text_body = Some(String::from_utf8_lossy(part.contents()).into_owned());
        }
    }
    for part in msg.html_bodies() {
        if out.html_body.is_none() {
            out.html_body = Some(String::from_utf8_lossy(part.contents()).into_owned());
        }
    }
    let mut attachment_risk = crate::attachrisk::AttachRiskEvidence::default();
    for att in msg.attachments() {
        let contents = att.contents();
        let filename = att.attachment_name().unwrap_or("");
        let content_type = att
            .content_type()
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("")))
            .unwrap_or_else(|| "application/octet-stream".into());
        attachment_risk.merge(crate::attachrisk::inspect_attachment(
            Some(filename),
            &content_type,
            &contents[..contents.len().min(2 * 1024 * 1024)],
        ));
        out.attachments.push(AttachmentMeta {
            filename: att.attachment_name().map(str::to_string),
            content_type,
            size: contents.len(),
        });
    }
    out.attach_risk = attachment_risk;
    let body_src = out
        .text_body
        .clone()
        .or_else(|| out.html_body.clone())
        .unwrap_or_default();
    out.snippet = body_src
        .split_whitespace()
        .take(24)
        .collect::<Vec<_>>()
        .join(" ");
    Ok(out)
}

// ---------------------------------------------------------------------------
// Raw header capture (classification input)
// ---------------------------------------------------------------------------

/// Copy the root part's headers into bounded `(lowercased-name, value)`
/// pairs. Values are the RAW (unparsed) header text sliced from the message
/// via the parser's offsets — this preserves `<…>`-bracketed forms like
/// `List-Unsubscribe: <mailto:…>, <https://…>`, which the typed accessors
/// normalize into address lists (brackets lost). Unknown `X-` headers
/// surface as `HeaderName::Other`. Never fails — hostile input just yields
/// fewer rows.
fn capture_headers(msg: &mail_parser::Message<'_>) -> Vec<(String, String)> {
    let Some(root) = msg.parts.first() else {
        return Vec::new();
    };
    let raw = &msg.raw_message;
    let mut out = Vec::new();
    for h in &root.headers {
        if out.len() >= MAX_CAPTURED_HEADERS {
            break;
        }
        let name = match &h.name {
            mail_parser::HeaderName::Other(n) => n.to_lowercase(),
            known => known.as_static_str().to_lowercase(),
        };
        if name.is_empty() || name.len() > 128 {
            continue;
        }
        // `received` is pure transport noise (and the highest-volume
        // header — long chains would crowd signal headers out of the
        // bounded list). No consumer reads it; forensics parses its own.
        if name == "received" {
            continue;
        }
        // Raw slice first (brackets intact); typed extraction as fallback
        // if the offsets ever fail to slice (never observed — defensive).
        let value = raw_header_value(raw, h).or_else(|| typed_header_value(h));
        let Some(value) = value else {
            continue;
        };
        let mut value = value;
        if value.len() > MAX_HEADER_VALUE {
            let mut end = MAX_HEADER_VALUE;
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            value.truncate(end);
        }
        out.push((name, value));
    }
    out
}

/// Raw header value via parser offsets, unfolded (CRLF before WSP removed
/// per RFC 5322 section 2.2.3) and right-trimmed. `None` when out of bounds.
fn raw_header_value(raw: &[u8], h: &mail_parser::Header<'_>) -> Option<String> {
    let (s, e) = (h.offset_start as usize, h.offset_end as usize);
    if s > e || e > raw.len() {
        return None;
    }
    let text = String::from_utf8_lossy(&raw[s..e]);
    let unfolded = text.replace("\r\n", "");
    Some(unfolded.trim_end().to_string())
}

/// Typed fallback: text, text-list, and address/URL values flattened.
/// (Addresses lose their `<>` brackets here — the raw path above is what
/// `List-Unsubscribe` parsing relies on.)
fn typed_header_value(h: &mail_parser::Header<'_>) -> Option<String> {
    match &h.value {
        mail_parser::HeaderValue::Text(t) => Some(t.to_string()),
        mail_parser::HeaderValue::TextList(l) => Some(l.join(", ")),
        // RFC 2369 list headers (`List-Unsubscribe: <https://…>`) and
        // address headers parse as addresses — flatten to text.
        mail_parser::HeaderValue::Address(a) => Some(address_text(a)),
        _ => None,
    }
}

/// Flatten an address-list/group value to display text (addresses and URLs;
///
/// names included so group headers stay identifiable).
fn address_text(a: &mail_parser::Address<'_>) -> String {
    match a {
        mail_parser::Address::List(list) => list
            .iter()
            .filter_map(|x| x.address.as_deref())
            .collect::<Vec<_>>()
            .join(", "),
        mail_parser::Address::Group(groups) => groups
            .iter()
            .flat_map(|g| {
                g.name.iter().map(|n| n.to_string()).chain(
                    g.addresses
                        .iter()
                        .filter_map(|x| x.address.as_deref().map(str::to_string)),
                )
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

// ---------------------------------------------------------------------------
// Outbound builder
// ---------------------------------------------------------------------------

/// Serialize an `OutboundMessage` to RFC 5322 bytes with CRLF endings.
/// - non-ASCII header values → RFC 2047 encoded-words (UTF-8/B)
/// - text parts → quoted-printable; attachments → base64
/// - multipart/alternative wraps text+html; multipart/mixed adds attachments
pub fn build_message(msg: &OutboundMessage) -> Result<Vec<u8>> {
    let mut h = Vec::new();

    header(&mut h, "From", &format_addr(&msg.from));
    if !msg.to.is_empty() {
        header(&mut h, "To", &format_addrs(&msg.to));
    }
    if !msg.cc.is_empty() {
        header(&mut h, "Cc", &format_addrs(&msg.cc));
    }
    // Bcc is deliberately never emitted on the wire.
    header(&mut h, "Subject", &encode_words(&msg.subject));
    header(&mut h, "Date", &rfc2822_date(msg.date_unix));
    header(
        &mut h,
        "Message-ID",
        &format!("<{}>", sanitize_id(&msg.message_id)),
    );
    if let Some(irt) = &msg.in_reply_to {
        header(&mut h, "In-Reply-To", &format!("<{}>", sanitize_id(irt)));
    }
    if !msg.references.is_empty() {
        let refs = msg
            .references
            .iter()
            .map(|r| format!("<{}>", sanitize_id(r)))
            .collect::<Vec<_>>()
            .join(" ");
        header(&mut h, "References", &refs);
    }
    header(&mut h, "MIME-Version", "1.0");

    let mut body = Vec::new();
    match (&msg.html, msg.attachments.is_empty()) {
        (None, true) => {
            header(&mut h, "Content-Type", "text/plain; charset=utf-8");
            header(&mut h, "Content-Transfer-Encoding", "quoted-printable");
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(&qp_encode(msg.text.as_bytes()));
        }
        (html, true) => {
            let boundary = boundary_for(msg);
            header(
                &mut h,
                "Content-Type",
                &format!("multipart/alternative; boundary=\"{boundary}\""),
            );
            body.extend_from_slice(b"\r\n");
            push_text_part(
                &mut body,
                &boundary,
                "text/plain; charset=utf-8",
                msg.text.as_bytes(),
            );
            if let Some(html) = html {
                push_text_part(
                    &mut body,
                    &boundary,
                    "text/html; charset=utf-8",
                    html.as_bytes(),
                );
            }
            body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        }
        (_, false) => {
            let boundary = boundary_for(msg);
            header(
                &mut h,
                "Content-Type",
                &format!("multipart/mixed; boundary=\"{boundary}\""),
            );
            body.extend_from_slice(b"\r\n");
            // inner alternative (or plain) part
            if let Some(html) = &msg.html {
                let inner = format!("{boundary}-alt");
                body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                body.extend_from_slice(
                    format!("Content-Type: multipart/alternative; boundary=\"{inner}\"\r\n\r\n")
                        .as_bytes(),
                );
                push_text_part(
                    &mut body,
                    &inner,
                    "text/plain; charset=utf-8",
                    msg.text.as_bytes(),
                );
                push_text_part(
                    &mut body,
                    &inner,
                    "text/html; charset=utf-8",
                    html.as_bytes(),
                );
                body.extend_from_slice(format!("--{inner}--\r\n").as_bytes());
            } else {
                push_text_part(
                    &mut body,
                    &boundary,
                    "text/plain; charset=utf-8",
                    msg.text.as_bytes(),
                );
            }
            for (i, att) in msg.attachments.iter().enumerate() {
                let fname = att.filename.replace(['"', '\\', '\r', '\n'], "_");
                body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                body.extend_from_slice(
                    format!(
                        "Content-Type: {}; name=\"{}\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"{}\"\r\n\r\n",
                        sanitize_header_value(&att.content_type),
                        fname,
                        fname,
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(&b64_wrapped(&att.data));
                let _ = i;
            }
            body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        }
    }

    let mut out = h;
    out.extend_from_slice(&body);
    Ok(out)
}

fn push_text_part(out: &mut Vec<u8>, boundary: &str, ctype: &str, text: &[u8]) {
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Type: {ctype}\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(&qp_encode(text));
}

fn header(out: &mut Vec<u8>, name: &str, value: &str) {
    // One sanitization point: header values can never inject lines.
    let v = sanitize_header_value(value);
    out.extend_from_slice(format!("{name}: {v}\r\n").as_bytes());
}

fn sanitize_header_value(v: &str) -> String {
    v.replace(['\r', '\n'], " ")
}

/// Message-ID/References tokens must be addr-spec-safe.
fn sanitize_id(id: &str) -> String {
    id.trim_matches(|c| c == '<' || c == '>')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_@".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// RFC 2047: ASCII passes through; anything else becomes =?UTF-8?B?…?=
fn encode_words(s: &str) -> String {
    if s.is_ascii() {
        return s.replace(['\r', '\n'], " ");
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    format!("=?UTF-8?B?{b64}?=")
}

fn format_addr(a: &Addr) -> String {
    match &a.name {
        Some(n) if !n.is_empty() => format!("{} <{}>", encode_words(n), a.email),
        _ => a.email.clone(),
    }
}

fn format_addrs(list: &[Addr]) -> String {
    list.iter().map(format_addr).collect::<Vec<_>>().join(", ")
}

/// Quoted-printable per RFC 2045 (76-col soft breaks, `=` escapes).
fn qp_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 8);
    let mut col = 0usize;
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let piece: Vec<u8> = match b {
            b'=' | 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f..=0xff => {
                format!("={b:02X}").into_bytes()
            }
            // trailing space/tab before EOL must be escaped
            b' ' | b'\t'
                if input.get(i + 1) == Some(&b'\r') || input.get(i + 1) == Some(&b'\n') =>
            {
                format!("={b:02X}").into_bytes()
            }
            _ => vec![b],
        };
        // soft line break if we'd exceed 76 cols (leave room for piece + '=')
        if col + piece.len() > 75 {
            out.extend_from_slice(b"=\r\n");
            col = 0;
        }
        out.extend_from_slice(&piece);
        if piece == b"\n" || piece.ends_with(b"\n") {
            col = 0;
        } else {
            col += piece.len();
        }
        i += 1;
    }
    out
}

fn b64_wrapped(data: &[u8]) -> Vec<u8> {
    let enc = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = Vec::with_capacity(enc.len() + enc.len() / 76 * 2 + 4);
    for chunk in enc.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn rfc2822_date(unix: i64) -> String {
    use time::format_description::well_known::Rfc2822;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| {
            t.format(&Rfc2822)
                .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into())
        })
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into())
}

fn boundary_for(msg: &OutboundMessage) -> String {
    // Deterministic boundary derived from content; collision probability is
    // negligible for this use, and we never include secrets.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    msg.message_id.hash(&mut h);
    msg.date_unix.hash(&mut h);
    format!("kiwi-{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_message() {
        let raw = b"From: Alice <a@x.test>\r\nTo: b@y.test\r\nSubject: Hi there\r\nMessage-ID: <m1@x>\r\nDate: Wed, 17 Sep 2025 10:00:00 +0000\r\n\r\nHello body\r\n";
        let p = parse_message(raw).unwrap();
        assert_eq!(p.subject.as_deref(), Some("Hi there"));
        assert_eq!(p.from[0].email, "a@x.test");
        assert_eq!(p.message_id.as_deref(), Some("m1@x")); // mail-parser strips <>
        assert!(p.text_body.unwrap().contains("Hello body"));
    }

    #[test]
    fn parse_mime_with_attachment() {
        let raw = b"From: a@x.test\r\nTo: b@y.test\r\nSubject: att\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\nContent-Type: application/pdf; name=\"doc.pdf\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"doc.pdf\"\r\n\r\nQUJD\r\n--B--\r\n";
        let p = parse_message(raw).unwrap();
        assert_eq!(p.attachments.len(), 1);
        assert_eq!(p.attachments[0].filename.as_deref(), Some("doc.pdf"));
        assert_eq!(p.attachments[0].size, 3); // "ABC"
        assert_eq!(p.attach_risk.risk, crate::attachrisk::AttachRisk::Clean);
        assert!(p.attach_risk.reasons.is_empty());
    }

    #[test]
    fn parse_time_attachment_risk_uses_filename_and_type() {
        let raw = b"From: a@x.test\r\nTo: b@y.test\r\nSubject: att\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--B\r\nContent-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nTVpQ\r\n--B--\r\n";
        let p = parse_message(raw).unwrap();
        assert_eq!(p.attach_risk.risk, crate::attachrisk::AttachRisk::Failed);
        assert!(
            p.attach_risk
                .reasons
                .contains(&crate::attachrisk::AttachRiskReason::DoubleExtension)
        );
    }

    #[test]
    fn build_roundtrips_through_parser() {
        let msg = OutboundMessage {
            from: Addr {
                name: Some("Zoë".into()),
                email: "z@x.test".into(),
            },
            to: vec![Addr {
                name: None,
                email: "b@y.test".into(),
            }],
            cc: vec![],
            bcc: vec![],
            subject: "Résumé ✓".into(),
            text: "body text with ünicode".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![OutboundAttachment {
                filename: "a.bin".into(),
                content_type: "application/octet-stream".into(),
                data: vec![1, 2, 3, 4],
            }],
            date_unix: 1_758_000_000,
            message_id: "kiwi-1@x.test".into(),
        };
        let bytes = build_message(&msg).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("=?UTF-8?B?"));
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("base64"));
        assert!(!text.contains("\n\n")); // CRLF only
        let parsed = parse_message(&bytes).unwrap();
        assert_eq!(parsed.subject.as_deref(), Some("Résumé ✓"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename.as_deref(), Some("a.bin"));
    }

    #[test]
    fn header_injection_blocked() {
        let msg = OutboundMessage {
            from: Addr {
                name: None,
                email: "a@x".into(),
            },
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: "hi\r\nBCC: evil@x".into(),
            text: "t".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![],
            date_unix: 0,
            message_id: "m@x".into(),
        };
        let bytes = build_message(&msg).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        // The injected text stays on the Subject line — never becomes a header.
        assert!(!text.contains("\r\nBCC:"));
        assert!(text.contains("Subject: hi  BCC: evil@x\r\n"));
    }

    #[test]
    fn headers_captured_for_classification() {
        let raw = b"From: deals@shop.example\r\nTo: b@y.test\r\nSubject: sale\r\nList-Unsubscribe: <https://shop.example/u>\r\nPrecedence: bulk\r\nX-Mailer: Mailchimp 1.0\r\nReceived: from a by b\r\n\r\nbody\r\n";
        let p = parse_message(raw).unwrap();
        // Text-valued signal headers are kept, names lowercased.
        // `List-Unsubscribe: <url>` parses as an address value — kept as text.
        assert!(
            p.headers
                .iter()
                .any(|(n, v)| n == "list-unsubscribe" && v.contains("https://shop.example/u"))
        );
        assert!(p.headers.iter().any(|(n, _)| n == "precedence"));
        assert!(p.headers.iter().any(|(n, _)| n == "x-mailer"));
        // Received stays typed-only (structured value, skipped here).
        assert!(!p.headers.iter().any(|(n, _)| n == "received"));
    }

    #[test]
    fn unsubscribe_parsed_on_ingest() {
        let raw = b"From: news@x.example\r\nTo: b@y.test\r\nSubject: digest\r\nList-Unsubscribe: <mailto:leave@x.example?subject=bye>, <https://x.example/u>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\nbody\r\n";
        let p = parse_message(raw).unwrap();
        let u = p.unsubscribe.unwrap();
        assert_eq!(u.http_url.as_deref(), Some("https://x.example/u"));
        assert_eq!(u.mailto.as_deref(), Some("leave@x.example"));
        assert!(u.one_click);

        // No offer headers → None.
        let p = parse_message(b"From: a@x.test\r\nSubject: s\r\n\r\nbody\r\n").unwrap();
        assert_eq!(p.unsubscribe, None);
    }
}
