//! Attachment part planning (T-339): walk a BODYSTRUCTURE into the
//! IMAP section list sync uses to fetch a *skeleton* body — headers plus
//! text leaves only, attachment leaves deferred — and to resolve a
//! specific attachment to its `BODY.PEEK[<section>]` fetch.
//!
//! RFC 3501 §6.4.5 numbering: top-level children of a multipart are
//! "1", "2", …; a nested multipart's children are "2.1", "2.2", …
//! A `message/rfc822` leaf is opaque here — its embedded parts are
//! *not* descended (`BODY[2]` on it yields the whole .eml).
//!
//! Skeleton bodies are real MIME: every leaf keeps its MIME headers
//! (`BODY[ N.MIME ]`), deferred parts carry an empty body — the file
//! parses, attachment rows still enumerate, and readers can tell the
//! payload is missing rather than absent.
//!
//! Honesty rule: a stored skeleton is *never* a complete RFC822 message.
//! The `message_parts` rows are the marker — present rows mean the body
//! on disk is partial; absent rows mean it is whole. Surfaces that
//! promise verbatim source (view-source, mbox export) must force a full
//! `BODY[]` load instead of reading a skeleton.

use std::collections::BTreeMap;

use crate::error::{MailError, Result};
use crate::imap::BodyStructure;

/// A leaf classified as an attachment — deferred from the skeleton fetch
/// and fetchable on demand via `UID FETCH BODY.PEEK[<section>]`.
#[derive(Debug, Clone)]
pub struct AttachmentDesc {
    /// Ordinal among attachment leaves, document order — the
    /// `attachmentIndex` the IPC layer resolves.
    pub index: u32,
    /// IMAP section specifier ("2", "1.3", …).
    pub section: String,
    /// Filename from disposition `filename=` / Content-Type `name=`.
    pub name: Option<String>,
    /// `media/subtype` lowercased.
    pub mime: String,
    /// Wire size in octets (the encoded body, per BODYSTRUCTURE).
    pub size: u64,
    /// Content-Transfer-Encoding verbatim ("base64", "7bit", …) — the
    /// download path needs it to decode the fetched section.
    pub encoding: String,
}

/// Every leaf in fetch order plus the attachment subset. `leaves` is the
/// skeleton-fetch plan; `attachments` is what the store persists.
#[derive(Debug, Default)]
pub struct PartPlan {
    /// `(section, eager)` — eager leaves are fetched into the skeleton
    /// body; deferred leaves get `.MIME` headers only.
    pub leaves: Vec<(String, bool)>,
    /// Non-root multipart sections — each needs a `<sec>.MIME` fetch so
    /// the skeleton can emit the container's own Content-Type header
    /// inside its parent part (that header is where the nested boundary
    /// actually lives).
    pub containers: Vec<String>,
    pub attachments: Vec<AttachmentDesc>,
    /// Root is a single-part message (`BODY[1]`/TEXT is the body, its
    /// MIME headers live in HEADER). No leaf `.MIME` items are legal.
    pub root_single: bool,
    /// True when the plan is unusable for skeleton fetch (caller falls
    /// back to a full `BODY[]` fetch — honest, never guessed).
    pub too_complex: bool,
}

impl PartPlan {
    /// `BODY.PEEK[…]` fetch items for the skeleton — HEADER always, then
    /// every leaf's `.MIME`, leaf content for eager leaves, and `.MIME`
    /// for nested multipart containers. A deferred root single needs no
    /// body fetch at all (its MIME headers live in HEADER).
    pub fn fetch_items(&self) -> Vec<String> {
        let mut items = Vec::with_capacity(1 + self.containers.len() + self.leaves.len() * 2);
        items.push("BODY.PEEK[HEADER]".to_string());
        if self.root_single {
            if self.leaves.first().is_some_and(|(_, eager)| *eager) {
                items.push("BODY.PEEK[TEXT]".to_string());
            }
            return items;
        }
        for sec in &self.containers {
            items.push(format!("BODY.PEEK[{sec}.MIME]"));
        }
        for (sec, eager) in &self.leaves {
            items.push(format!("BODY.PEEK[{sec}.MIME]"));
            if *eager {
                items.push(format!("BODY.PEEK[{sec}]"));
            }
        }
        items
    }
}

/// Pathological structures get the full-body fallback instead of a
/// section storm — 64 leaves bounds the FETCH item list.
pub const MAX_PLAN_LEAVES: usize = 64;

/// Attachment classification for one leaf. A leaf is user-content when
/// its disposition is `attachment`, when it carries a filename
/// (`filename=` / `name=` params), or when it is not `text/*` — including
/// `message/rfc822` (forwarded mail is a downloadable .eml). Unnamed
/// inline `text/*` leaves are the message body and fetch eagerly.
pub fn is_attachment_leaf(bs: &BodyStructure) -> bool {
    let BodyStructure::Single {
        media_type,
        params,
        disposition,
        disp_params,
        ..
    } = bs
    else {
        // Unknown shapes defer — deferral is the safe default (nothing
        // fabricated into the body; the part is still downloadable).
        return true;
    };
    if disposition
        .as_deref()
        .is_some_and(|d| d.eq_ignore_ascii_case("attachment"))
    {
        return true;
    }
    let named = params.iter().any(|(k, _)| k.eq_ignore_ascii_case("name"))
        || disp_params
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("filename"));
    if named {
        return true;
    }
    !media_type.eq_ignore_ascii_case("text")
}

fn leaf_name(params: &[(String, String)], disp_params: &[(String, String)]) -> Option<String> {
    disp_params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("filename"))
        .or_else(|| params.iter().find(|(k, _)| k.eq_ignore_ascii_case("name")))
        .map(|(_, v)| v.clone())
        .filter(|s| !s.is_empty())
}

fn leaf(node: &BodyStructure, section: String, plan: &mut PartPlan) {
    let attachment = is_attachment_leaf(node);
    if attachment {
        let (name, mime, size, encoding) = match node {
            BodyStructure::Single {
                media_type,
                subtype,
                params,
                encoding,
                octets,
                disp_params,
                ..
            } => (
                leaf_name(params, disp_params),
                format!("{}/{}", media_type.to_lowercase(), subtype.to_lowercase()),
                *octets,
                encoding.clone(),
            ),
            _ => (None, "application/octet-stream".into(), 0, String::new()),
        };
        plan.attachments.push(AttachmentDesc {
            index: plan.attachments.len() as u32,
            section: section.clone(),
            name,
            mime,
            size,
            encoding,
        });
    }
    plan.leaves.push((section, !attachment));
}

/// Walk a BODYSTRUCTURE into the fetch plan. `None` on `Unknown` roots —
/// the caller falls back to `BODY[]`.
pub fn plan_parts(bs: &BodyStructure) -> Option<PartPlan> {
    if matches!(bs, BodyStructure::Unknown) {
        return None;
    }
    let mut plan = PartPlan {
        root_single: !matches!(bs, BodyStructure::Multi { .. }),
        ..Default::default()
    };
    walk(bs, "", &mut plan);
    if plan.leaves.len() > MAX_PLAN_LEAVES {
        plan.too_complex = true;
    }
    Some(plan)
}

fn walk(node: &BodyStructure, prefix: &str, plan: &mut PartPlan) {
    match node {
        BodyStructure::Multi { parts, .. } => {
            // A nested multipart is a container: its own part headers
            // (`<prefix>.MIME`) carry the nested boundary and must be
            // fetched for the skeleton to emit them.
            if !prefix.is_empty() {
                plan.containers.push(prefix.to_string());
            }
            for (i, part) in parts.iter().enumerate() {
                let section = if prefix.is_empty() {
                    (i + 1).to_string()
                } else {
                    format!("{prefix}.{}", i + 1)
                };
                match part {
                    BodyStructure::Multi { .. } => walk(part, &section, plan),
                    _ => leaf(part, section, plan),
                }
            }
        }
        // Top-level single part: the body IS the message body; its
        // MIME headers live in the message header block.
        _ => leaf(node, "1".to_string(), plan),
    }
}

/// `BODY[…]` response key → section name. `"BODY[2.MIME]"` → `"2.MIME"`,
/// `"BODY[HEADER]"` → `"HEADER"`, `"BODY[]"`/`"RFC822"` → `""`. Returns
/// `None` for non-BODY keys.
pub fn body_section(key: &str) -> Option<String> {
    if key == "RFC822" {
        return Some(String::new());
    }
    key.strip_prefix("BODY[")?
        .strip_suffix(']')
        .map(str::to_string)
}

/// Reassemble a stored body from fetched sections. `sections` maps
/// `"<n>"` (leaf content) and `"<n>.MIME"` (leaf headers) to raw bytes;
/// `"TEXT"` is the top-level single-part body.
///
/// Strict on structure: a multipart without a `boundary=` param, or a
/// multipart missing a fetched `.MIME`/eager-content section the plan
/// asked for, cannot be stitched → `Err` → caller falls back to a full
/// `BODY[]` fetch. Deferred leaves emit their `.MIME` block plus an
/// empty body — structurally present, honestly empty.
pub fn compose_skeleton(
    header: &[u8],
    bs: &BodyStructure,
    sections: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(header.len() + 512);
    out.extend_from_slice(header.trim_ascii_end());
    out.extend_from_slice(b"\r\n\r\n");
    render_node(bs, "", &mut out, sections)?;
    Ok(out)
}

fn missing(what: &str) -> MailError {
    MailError::Protocol {
        protocol: "imap",
        detail: format!("skeleton section absent from FETCH reply: {what}"),
    }
}

fn section<'m>(sections: &'m BTreeMap<String, Vec<u8>>, key: &str) -> Result<&'m [u8]> {
    sections
        .get(key)
        .map(|v| v.as_slice())
        .ok_or_else(|| missing(key))
}

fn render_node(
    node: &BodyStructure,
    prefix: &str,
    out: &mut Vec<u8>,
    sections: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    match node {
        BodyStructure::Multi { parts, params, .. } => {
            let boundary = params
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("boundary"))
                .map(|(_, v)| v.clone())
                .filter(|b| !b.is_empty())
                .ok_or_else(|| MailError::InvalidInput("multipart lacks a boundary".into()))?;
            for (i, part) in parts.iter().enumerate() {
                let sec = if prefix.is_empty() {
                    (i + 1).to_string()
                } else {
                    format!("{prefix}.{}", i + 1)
                };
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                render_part(part, &sec, out, sections)?;
            }
            out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            Ok(())
        }
        // Top-level single part: content is BODY[TEXT]; the MIME headers
        // are already in the message header block. An attachment-class
        // root leaf is deferred → the skeleton body is simply empty.
        _ => {
            if is_attachment_leaf(node) {
                return Ok(());
            }
            out.extend_from_slice(section(sections, "TEXT")?);
            Ok(())
        }
    }
}

fn render_part(
    node: &BodyStructure,
    sec: &str,
    out: &mut Vec<u8>,
    sections: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    match node {
        BodyStructure::Multi { .. } => {
            // The nested container's own part headers (Content-Type with
            // its boundary=) live at `<sec>.MIME` — without them the
            // children's boundaries would be mis-framed.
            out.extend_from_slice(section(sections, &format!("{sec}.MIME"))?.trim_ascii_end());
            out.extend_from_slice(b"\r\n\r\n");
            render_node(node, sec, out, sections)
        }
        _ => {
            out.extend_from_slice(section(sections, &format!("{sec}.MIME"))?.trim_ascii_end());
            out.extend_from_slice(b"\r\n\r\n");
            if !is_attachment_leaf(node) {
                out.extend_from_slice(section(sections, sec)?);
            }
            out.extend_from_slice(b"\r\n");
            Ok(())
        }
    }
}

/// Decode a `Content-Transfer-Encoding` payload. `base64` is lenient —
/// non-alphabet bytes are ignored per RFC 2045 and missing padding is
/// tolerated — but a body that still cannot decode is an error, never a
/// fabricated byte stream. `quoted-printable` decodes `=XX` escapes and
/// soft breaks. `7bit`/`8bit`/`binary`/empty are identity; unknown
/// encodings pass through verbatim — the stored bytes are exactly what
/// the server sent; we never invent a transform.
pub fn decode_transfer_encoding(encoding: &str, raw: &[u8]) -> Result<Vec<u8>> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "base64" => decode_base64(raw),
        "quoted-printable" | "quopri" => Ok(decode_qp(raw)),
        _ => Ok(raw.to_vec()),
    }
}

fn decode_base64(raw: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    // RFC 2045 §6.8: characters outside the base alphabet (whitespace,
    // stray control bytes) are ignored, and short/truncated padding is
    // re-derived from the length. `=` stays in the stream so a *misplaced*
    // pad — a concatenated second encoding, a corrupt body — fails loudly
    // instead of silently shifting the quantum alignment into garbage.
    let mut cleaned: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
        .collect();
    match cleaned.len() % 4 {
        0 => {}
        1 => {
            return Err(MailError::InvalidInput(
                "base64 body has impossible length".into(),
            ));
        }
        rem => cleaned.extend(std::iter::repeat_n(b'=', 4 - rem)),
    }
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|_| MailError::InvalidInput("base64 body undecodable".into()))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_qp(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'=' {
            match (raw.get(i + 1), raw.get(i + 2)) {
                // Soft line break: `=\r\n` (or bare `=\n`) encodes nothing.
                (Some(b'\r'), Some(b'\n')) => i += 3,
                (Some(b'\n'), _) => i += 2,
                (Some(&a), Some(&b)) if hex_val(a).is_some() && hex_val(b).is_some() => {
                    out.push(hex_val(a).unwrap_or(0) * 16 + hex_val(b).unwrap_or(0));
                    i += 3;
                }
                // Invalid escape — emit the `=` verbatim; never guess.
                _ => {
                    out.push(b'=');
                    i += 1;
                }
            }
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MimeHeaders;

    /// Parse a BODYSTRUCTURE s-expression fixture.
    fn bs(raw: &str) -> BodyStructure {
        let sexp = crate::imap::parse_sexp(raw.as_bytes()).unwrap();
        crate::imap::parse_bodystructure(&sexp)
    }

    #[test]
    fn plain_text_and_html_are_eager() {
        let b = bs(
            "((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 100 2)\
              (\"text\" \"html\" NIL NIL NIL \"8bit\" 200 3) \"alternative\")",
        );
        let plan = plan_parts(&b).unwrap();
        assert_eq!(plan.leaves, [("1".into(), true), ("2".into(), true)]);
        assert!(plan.attachments.is_empty());
        assert!(!plan.too_complex);
        assert_eq!(
            plan.fetch_items(),
            [
                "BODY.PEEK[HEADER]",
                "BODY.PEEK[1.MIME]",
                "BODY.PEEK[1]",
                "BODY.PEEK[2.MIME]",
                "BODY.PEEK[2]"
            ]
        );
    }

    #[test]
    fn pdf_defers_with_metadata() {
        let b = bs("((\"text\" \"plain\" NIL NIL NIL \"7bit\" 12 1)\
              (\"application\" \"pdf\" (\"name\" \"invoice.pdf\") NIL NIL \"base64\" 4096 NIL\
                (\"attachment\" (\"filename\" \"invoice.pdf\")) NIL)\
              \"mixed\" (\"boundary\" \"m1\"))");
        let plan = plan_parts(&b).unwrap();
        assert_eq!(plan.leaves.len(), 2);
        assert_eq!(plan.attachments.len(), 1);
        let a = &plan.attachments[0];
        assert_eq!(a.index, 0);
        assert_eq!(a.section, "2");
        assert_eq!(a.name.as_deref(), Some("invoice.pdf"));
        assert_eq!(a.mime, "application/pdf");
        assert_eq!(a.size, 4096);
        assert_eq!(a.encoding, "base64");
        assert_eq!(
            plan.fetch_items(),
            [
                "BODY.PEEK[HEADER]",
                "BODY.PEEK[1.MIME]",
                "BODY.PEEK[1]",
                "BODY.PEEK[2.MIME]"
            ]
        );
    }

    #[test]
    fn inline_named_image_defers() {
        // disposition inline but carries filename= → still a download.
        let b = bs("((\"text\" \"html\" NIL NIL NIL \"8bit\" 50 1)\
              (\"image\" \"png\" NIL NIL NIL \"base64\" 2048 NIL\
                (\"inline\" (\"filename\" \"sig.png\")) NIL)\
              \"mixed\")");
        let plan = plan_parts(&b).unwrap();
        assert_eq!(plan.attachments.len(), 1);
        assert_eq!(plan.attachments[0].section, "2");
    }

    #[test]
    fn rfc822_leaf_is_one_opaque_attachment() {
        let b = bs("((\"text\" \"plain\" NIL NIL NIL \"7bit\" 10 1)\
              (\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 999 NIL NIL NIL NIL)\
              \"mixed\")");
        let plan = plan_parts(&b).unwrap();
        assert_eq!(plan.attachments.len(), 1);
        assert_eq!(plan.attachments[0].mime, "message/rfc822");
        // Not descended — a forwarded mail's inner parts never appear.
        assert_eq!(plan.leaves.len(), 2);
    }

    #[test]
    fn nested_multipart_numbers_dotted() {
        // mixed( alternative(text,text), attachment ) → the alternative
        // children number 1.1/1.2 and its container MIME is "1.MIME".
        let b = bs("(((\"text\" \"plain\" NIL NIL NIL \"7bit\" 10 1)\
               (\"text\" \"html\" NIL NIL NIL \"8bit\" 20 1) \"alternative\")\
              (\"application\" \"zip\" NIL NIL NIL \"base64\" 4096 NIL\
                (\"attachment\" (\"filename\" \"bundle.zip\")) NIL)\
              \"mixed\" (\"boundary\" \"outer\"))");
        let plan = plan_parts(&b).unwrap();
        assert_eq!(plan.containers, ["1"]);
        assert_eq!(
            plan.leaves,
            [
                ("1.1".into(), true),
                ("1.2".into(), true),
                ("2".into(), false)
            ]
        );
        assert_eq!(plan.attachments[0].section, "2");
        assert!(
            plan.fetch_items()
                .contains(&"BODY.PEEK[1.MIME]".to_string())
        );
        assert!(plan.fetch_items().contains(&"BODY.PEEK[1.1]".to_string()));
        assert!(!plan.fetch_items().contains(&"BODY.PEEK[2]".to_string()));
    }

    #[test]
    fn single_part_attachment_needs_header_only() {
        let b = bs(
            "(\"application\" \"pdf\" (\"name\" \"x.pdf\") NIL NIL \"base64\" 4096 NIL\
                    (\"attachment\" (\"filename\" \"x.pdf\")) NIL)",
        );
        let plan = plan_parts(&b).unwrap();
        assert!(plan.root_single);
        assert_eq!(plan.attachments.len(), 1);
        assert_eq!(plan.fetch_items(), ["BODY.PEEK[HEADER]"]);
    }

    #[test]
    fn too_complex_caps_at_64_leaves() {
        let parts: String = (0..70)
            .map(|_| "(\"text\" \"plain\" NIL NIL NIL \"7bit\" 5 1)")
            .collect::<Vec<_>>()
            .join("");
        let b = bs(&format!("({parts} \"mixed\")"));
        let plan = plan_parts(&b).unwrap();
        assert!(plan.too_complex);
        assert_eq!(plan.leaves.len(), 70);
    }

    #[test]
    fn unknown_root_plans_none() {
        assert!(plan_parts(&BodyStructure::Unknown).is_none());
    }

    // -- skeleton composition ----------------------------------------------

    fn mixed_structure() -> BodyStructure {
        bs("((\"text\" \"plain\" NIL NIL NIL \"7bit\" 12 1)\
            (\"application\" \"pdf\" (\"name\" \"i.pdf\") NIL NIL \"base64\" 4096 NIL\
              (\"attachment\" (\"filename\" \"i.pdf\")) NIL)\
            \"mixed\" (\"boundary\" \"bnd\"))")
    }

    #[test]
    fn skeleton_emits_text_and_empty_attachment() {
        let mut sections = BTreeMap::new();
        sections.insert(
            "1.MIME".to_string(),
            b"Content-Type: text/plain\r\n".to_vec(),
        );
        sections.insert("1".to_string(), b"hello body".to_vec());
        sections.insert(
            "2.MIME".to_string(),
            b"Content-Type: application/pdf; name=\"i.pdf\"\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n".to_vec(),
        );
        let raw = compose_skeleton(
            b"From: a@x.test\r\nContent-Type: multipart/mixed; boundary=\"bnd\"",
            &mixed_structure(),
            &sections,
        )
        .unwrap();
        let msg = mail_parser::MessageParser::default()
            .parse(&raw)
            .expect("skeleton must parse");
        let body = msg.body_text(0).unwrap_or_default();
        assert!(body.contains("hello body"), "eager text lands: {body}");
        let atts: Vec<_> = msg.attachments().collect();
        assert_eq!(atts.len(), 1, "deferred leaf still enumerates");
        assert_eq!(atts[0].attachment_name(), Some("i.pdf"));
        assert!(atts[0].contents().is_empty(), "payload honestly absent");
    }

    #[test]
    fn skeleton_missing_section_fails_not_guesses() {
        let mut sections = BTreeMap::new();
        sections.insert("1.MIME".to_string(), b"Content-Type: text/plain".to_vec());
        // `1` content missing — compose must Err so the caller fetches
        // BODY[] instead of storing a silently-truncated body.
        let err = compose_skeleton(b"From: a@x.test", &mixed_structure(), &sections).unwrap_err();
        assert!(matches!(err, MailError::Protocol { .. }), "{err}");
    }

    #[test]
    fn skeleton_missing_boundary_fails() {
        let b = bs("((\"text\" \"plain\" NIL NIL NIL \"7bit\" 5 1)\
                    (\"application\" \"pdf\" NIL NIL NIL \"base64\" 10 NIL NIL NIL)\
                    \"mixed\")");
        let mut sections = BTreeMap::new();
        sections.insert("1.MIME".to_string(), b"Content-Type: text/plain".to_vec());
        sections.insert("1".to_string(), b"x".to_vec());
        sections.insert(
            "2.MIME".to_string(),
            b"Content-Type: application/pdf".to_vec(),
        );
        assert!(compose_skeleton(b"H: v", &b, &sections).is_err());
    }

    #[test]
    fn nested_skeleton_emits_container_mime() {
        let b = bs("(((\"text\" \"plain\" NIL NIL NIL \"7bit\" 10 1)\
               (\"text\" \"html\" NIL NIL NIL \"8bit\" 20 1) \"alternative\"\
               (\"boundary\" \"inner\"))\
              (\"application\" \"zip\" NIL NIL NIL \"base64\" 4096 NIL\
                (\"attachment\" (\"filename\" \"z.zip\")) NIL)\
              \"mixed\" (\"boundary\" \"outer\"))");
        let mut sections = BTreeMap::new();
        sections.insert(
            "1.MIME".to_string(),
            b"Content-Type: multipart/alternative; boundary=\"inner\"".to_vec(),
        );
        sections.insert("1.1.MIME".to_string(), b"Content-Type: text/plain".to_vec());
        sections.insert("1.1".to_string(), b"plain part".to_vec());
        sections.insert("1.2.MIME".to_string(), b"Content-Type: text/html".to_vec());
        sections.insert("1.2".to_string(), b"<p>hi</p>".to_vec());
        sections.insert(
            "2.MIME".to_string(),
            b"Content-Type: application/zip".to_vec(),
        );
        let raw = compose_skeleton(
            b"Content-Type: multipart/mixed; boundary=\"outer\"",
            &b,
            &sections,
        )
        .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("--outer"), "outer boundary emitted");
        assert!(text.contains("--inner"), "inner boundary emitted");
        let msg = mail_parser::MessageParser::default().parse(&raw).unwrap();
        assert_eq!(msg.attachments().count(), 1);
        assert!(msg.body_text(0).unwrap_or_default().contains("plain part"));
    }

    // -- transfer decoding ---------------------------------------------------

    #[test]
    fn base64_lenient_decode() {
        // One base64 stream ("Hello world" = SGVsbG8gd29ybGQ=) split across
        // lines with stray whitespace — the common real-mail shape.
        let raw = b"SGVsbG8g\r\n  d29ybGQ=\r\n";
        assert_eq!(
            decode_transfer_encoding("base64", raw).unwrap(),
            b"Hello world"
        );
        assert_eq!(decode_transfer_encoding("BASE64", b"QQ==").unwrap(), b"A");
        assert_eq!(decode_transfer_encoding("base64", b"QQ").unwrap(), b"A");
        assert_eq!(decode_transfer_encoding("base64", b"QQ=").unwrap(), b"A");
        assert!(decode_transfer_encoding("base64", b"Q").is_err());
        // A mid-stream `=` means the tail is a second encoding — refusing
        // beats silently decoding shifted garbage bytes.
        assert!(decode_transfer_encoding("base64", b"SGVsbG8=d29ybGQ=").is_err());
    }

    #[test]
    fn quoted_printable_decodes() {
        assert_eq!(
            decode_transfer_encoding("quoted-printable", b"hello=20world=3D=\r\nend").unwrap(),
            b"hello world=end"
        );
        // Invalid escapes pass through verbatim — no guessing.
        assert_eq!(
            decode_transfer_encoding("quoted-printable", b"a=XY").unwrap(),
            b"a=XY"
        );
    }

    #[test]
    fn identity_and_unknown_encodings_passthrough() {
        for enc in ["7bit", "8bit", "binary", "", "x-uuencode"] {
            assert_eq!(
                decode_transfer_encoding(enc, b"raw\x00bytes").unwrap(),
                b"raw\x00bytes"
            );
        }
    }

    #[test]
    fn body_section_key_parsing() {
        assert_eq!(body_section("BODY[]").as_deref(), Some(""));
        assert_eq!(body_section("BODY[HEADER]").as_deref(), Some("HEADER"));
        assert_eq!(body_section("BODY[2.MIME]").as_deref(), Some("2.MIME"));
        assert_eq!(body_section("BODY[1.2]").as_deref(), Some("1.2"));
        assert_eq!(body_section("RFC822").as_deref(), Some(""));
        assert_eq!(body_section("FLAGS"), None);
    }
}
