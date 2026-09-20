//! RFC 6350 (vCard 4.0) import and export, bounded on every axis.
//!
//! vCard files are untrusted input: they arrive from exports, USB sticks and
//! the network. The parser therefore
//!
//! * caps the total input, every logical line, every property value, the
//!   number of cards and the number of properties per card
//!   ([`VCardLimits`]) — a hostile file cannot drive unbounded allocation;
//! * never recurses (vCard 4.0 has no nested cards);
//! * keeps going past properties it does not model (`URL`, `BDAY`, `X-*`, …),
//!   so newer producers stay importable;
//! * reports per-card problems as [`ImportIssue`]s instead of discarding a
//!   whole address book because one card is malformed.
//!
//! Stream-level problems (oversized input, unterminated card, stray text,
//! malformed content line) are hard errors: past that point the bounds the
//! caller asked for can no longer be guaranteed.

use crate::contact::{
    Contact, ContactEmail, ContactPhone, MAX_EMAILS, MAX_LABEL_LEN, MAX_PHONES, MAX_TAGS,
};
use crate::error::ContactsError;

/// Version this crate writes on export.
pub const VCARD_VERSION: &str = "4.0";

/// Properties whose value is bulk binary/encoded data we never store. Their
/// value is exempt from [`VCardLimits::max_value_bytes`] (the logical-line and
/// input caps still bound them) so a card carrying an embedded photo imports
/// as a contact instead of failing outright.
const BULK_PROPERTIES: &[&str] = &["PHOTO", "LOGO", "SOUND", "KEY"];

/// Hard bounds on a vCard stream. Defaults suit an address-book import; callers
/// may tighten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VCardLimits {
    /// Whole-stream ceiling.
    pub max_input_bytes: usize,
    /// Ceiling for one logical (unfolded) line. Defaults to the input cap, so
    /// the input size is the real bound; tighten it to reject blob-carrying
    /// cards outright.
    pub max_line_bytes: usize,
    pub max_cards: usize,
    pub max_properties_per_card: usize,
    /// Ceiling for a single stored property value.
    pub max_value_bytes: usize,
}

impl Default for VCardLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_line_bytes: 1024 * 1024,
            max_cards: 1000,
            max_properties_per_card: 256,
            max_value_bytes: 4096,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VCardError {
    #[error("input is {actual} bytes, over the {limit}-byte limit")]
    InputTooLarge { limit: usize, actual: usize },
    #[error("more than {limit} cards in one stream")]
    TooManyCards { limit: usize },
    #[error("line {line} is longer than {limit} bytes")]
    LineTooLong { line: usize, limit: usize },
    #[error("value of {property} exceeds {limit} bytes")]
    ValueTooLong { property: String, limit: usize },
    #[error("card {index} has more than {limit} properties")]
    TooManyProperties { index: usize, limit: usize },
    #[error("card {index} has more than {limit} {property} values")]
    TooManyValues {
        index: usize,
        property: &'static str,
        limit: usize,
    },
    #[error("card {index} has BEGIN:VCARD but no matching END:VCARD")]
    UnterminatedCard { index: usize },
    #[error("line {line} appears outside any BEGIN:VCARD/END:VCARD block")]
    StrayContent { line: usize },
    #[error("line {line} is not a valid vCard content line: {detail}")]
    MalformedLine { line: usize, detail: String },
    #[error("card {index} has no VERSION property")]
    MissingVersion { index: usize },
    #[error("card {index} declares unsupported vCard version {version:?}")]
    UnsupportedVersion { index: usize, version: String },
    #[error("card {index} is not a usable contact: {detail}")]
    InvalidContact { index: usize, detail: String },
    #[error("contact cannot be exported: {0}")]
    NotExportable(String),
}

impl From<ContactsError> for VCardError {
    fn from(e: ContactsError) -> Self {
        VCardError::NotExportable(e.to_string())
    }
}

/// One content line, exactly as authored (after unfolding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// `item1` in `item1.EMAIL:…`, when present.
    pub group: Option<String>,
    /// Uppercased property name (`EMAIL`, `FN`, …).
    pub name: String,
    /// Uppercased parameter name → values, quotes stripped.
    pub params: Vec<(String, Vec<String>)>,
    /// Raw (still escaped) property value.
    pub value: String,
}

impl Property {
    /// Values of the first parameter named `name`, or an empty slice.
    pub fn param(&self, name: &str) -> &[String] {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    /// True when the property is marked preferred — covering `PREF=1`, bare
    /// `PREF` and `TYPE=pref`, the three forms real exporters emit.
    pub fn is_preferred(&self) -> bool {
        self.params.iter().any(|(k, v)| {
            k == "PREF" || (k == "TYPE" && v.iter().any(|t| t.eq_ignore_ascii_case("pref")))
        })
    }
}

/// A single parsed card, before it is turned into a [`Contact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCard {
    /// 0-based position in the stream; used to report issues back to the user.
    pub index: usize,
    pub version: Option<String>,
    pub properties: Vec<Property>,
}

impl RawCard {
    /// Convert to a [`Contact`]. Properties this crate does not model (`ADR`,
    /// `URL`, `BDAY`, `PHOTO`, `X-*`, …) are ignored, not errors.
    pub fn to_contact(&self, now_unix: i64) -> Result<Contact, VCardError> {
        let version = self
            .version
            .as_deref()
            .ok_or(VCardError::MissingVersion { index: self.index })?;
        if !matches!(version, "4.0" | "3.0" | "2.1") {
            return Err(VCardError::UnsupportedVersion {
                index: self.index,
                version: version.to_string(),
            });
        }

        let mut contact = Contact::new("", now_unix);
        let mut name_parts: Option<[String; 5]> = None;
        let mut emails: Vec<(ContactEmail, bool)> = Vec::new();
        let mut phones: Vec<(ContactPhone, bool)> = Vec::new();

        for prop in &self.properties {
            match prop.name.as_str() {
                "FN" => {
                    if contact.display_name.is_empty() {
                        contact.display_name = unescape_text(&prop.value);
                    }
                }
                "N" => name_parts = Some(read_structured_name(&prop.value)),
                "ORG" => {
                    let parts = split_escaped(&prop.value, ';');
                    if let Some(first) = parts.first() {
                        let org = unescape_text(first);
                        if contact.org.is_none() {
                            contact.org = non_empty(&org);
                        }
                    }
                }
                "TITLE" => {
                    if contact.title.is_none() {
                        let v = unescape_text(&prop.value);
                        contact.title = non_empty(&v);
                    }
                }
                "NOTE" => {
                    if contact.notes.is_none() {
                        contact.notes = non_empty(unescape_text(&prop.value).as_str());
                    }
                }
                "UID" => {
                    if contact.source_uid.is_none() {
                        let v = unescape_text(&prop.value);
                        contact.source_uid = non_empty(&v);
                    }
                }
                "REV" => {
                    if contact.rev_unix.is_none() {
                        contact.rev_unix = parse_timestamp(&prop.value);
                    }
                }
                "EMAIL" => {
                    let address = unescape_text(&prop.value);
                    if !address.is_empty() {
                        if emails.len() >= MAX_EMAILS {
                            return Err(VCardError::TooManyValues {
                                index: self.index,
                                property: "EMAIL",
                                limit: MAX_EMAILS,
                            });
                        }
                        emails.push((
                            ContactEmail {
                                address,
                                label: type_label(prop),
                            },
                            prop.is_preferred(),
                        ));
                    }
                }
                "TEL" => {
                    let number = unescape_text(&prop.value);
                    if !number.is_empty() {
                        if phones.len() >= MAX_PHONES {
                            return Err(VCardError::TooManyValues {
                                index: self.index,
                                property: "TEL",
                                limit: MAX_PHONES,
                            });
                        }
                        phones.push((
                            ContactPhone {
                                number,
                                label: type_label(prop),
                            },
                            prop.is_preferred(),
                        ));
                    }
                }
                "CATEGORIES" => {
                    for raw in split_escaped(&prop.value, ',') {
                        let tag = unescape_text(&raw);
                        if tag.is_empty() {
                            continue;
                        }
                        if contact.tags.len() >= MAX_TAGS {
                            return Err(VCardError::TooManyValues {
                                index: self.index,
                                property: "CATEGORIES",
                                limit: MAX_TAGS,
                            });
                        }
                        contact.tags.push(tag);
                    }
                }
                _ => {}
            }
        }

        if contact.display_name.is_empty() {
            contact.display_name = name_parts
                .as_ref()
                .map(display_from_name_parts)
                .unwrap_or_default();
        }
        if contact.display_name.is_empty() {
            contact.display_name = emails
                .first()
                .map(|(e, _)| e.address.clone())
                .unwrap_or_default();
        }
        if let Some([family, given, additional, prefix, suffix]) = name_parts {
            contact.family_name = non_empty(&family);
            contact.given_name = non_empty(&given);
            contact.middle_name = additional
                .split(',')
                .map(str::trim)
                .find(|s| !s.is_empty())
                .map(str::to_string);
            contact.name_prefix = non_empty(&prefix);
            contact.name_suffix = non_empty(&suffix);
        }

        // Stable sort: preferred entries float to the front, everything else
        // keeps file order.
        emails.sort_by_key(|(_, pref)| !*pref);
        phones.sort_by_key(|(_, pref)| !*pref);
        contact.emails = emails.into_iter().map(|(e, _)| e).collect();
        contact.phones = phones.into_iter().map(|(p, _)| p).collect();

        contact.prepare().map_err(|e| VCardError::InvalidContact {
            index: self.index,
            detail: e.to_string(),
        })
    }
}

/// Result of importing a stream: the contacts that converted, plus a
/// per-card explanation for every card that did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VCardImport {
    pub contacts: Vec<Contact>,
    /// One entry per card that could not be converted. Empty is the happy path.
    pub issues: Vec<ImportIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportIssue {
    pub card_index: usize,
    pub detail: String,
}

impl VCardImport {
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Parse a vCard stream. Hard errors are reserved for stream-level damage; see
/// the module docs.
pub fn parse_vcards(input: &str, limits: &VCardLimits) -> Result<Vec<RawCard>, VCardError> {
    if input.len() > limits.max_input_bytes {
        return Err(VCardError::InputTooLarge {
            limit: limits.max_input_bytes,
            actual: input.len(),
        });
    }

    let lines = unfold(input, limits)?;
    let mut cards: Vec<RawCard> = Vec::new();
    let mut current: Option<RawCard> = None;

    for (line_no, text) in lines {
        // Blank lines (including whitespace-only) carry no content and are
        // tolerated anywhere in the stream.
        if text.trim().is_empty() {
            continue;
        }
        let (left, value) =
            split_once_unquoted(&text, ':').ok_or_else(|| VCardError::MalformedLine {
                line: line_no,
                detail: "no ':' separating property name from value".to_string(),
            })?;
        let property = parse_property(&left, value, line_no, limits)?;
        // Cloned so the default arm below can move the property into the card.
        let name = property.name.clone();

        match name.as_str() {
            "BEGIN" => {
                if !property.value.eq_ignore_ascii_case("VCARD") {
                    return Err(VCardError::MalformedLine {
                        line: line_no,
                        detail: format!("BEGIN:{} is not BEGIN:VCARD", property.value),
                    });
                }
                if current.is_some() {
                    return Err(VCardError::MalformedLine {
                        line: line_no,
                        detail: "BEGIN:VCARD inside an already-open card".to_string(),
                    });
                }
                if cards.len() >= limits.max_cards {
                    return Err(VCardError::TooManyCards {
                        limit: limits.max_cards,
                    });
                }
                current = Some(RawCard {
                    index: cards.len(),
                    version: None,
                    properties: Vec::new(),
                });
            }
            "END" => {
                if !property.value.eq_ignore_ascii_case("VCARD") {
                    return Err(VCardError::MalformedLine {
                        line: line_no,
                        detail: format!("END:{} is not END:VCARD", property.value),
                    });
                }
                let card = current
                    .take()
                    .ok_or(VCardError::StrayContent { line: line_no })?;
                cards.push(card);
            }
            "VERSION" => {
                let card = current
                    .as_mut()
                    .ok_or(VCardError::StrayContent { line: line_no })?;
                if card.version.is_none() {
                    card.version = Some(property.value.trim().to_string());
                }
            }
            _ => {
                let card = current
                    .as_mut()
                    .ok_or(VCardError::StrayContent { line: line_no })?;
                if card.properties.len() >= limits.max_properties_per_card {
                    return Err(VCardError::TooManyProperties {
                        index: card.index,
                        limit: limits.max_properties_per_card,
                    });
                }
                card.properties.push(property);
            }
        }
    }

    if let Some(card) = current {
        return Err(VCardError::UnterminatedCard { index: card.index });
    }
    Ok(cards)
}

/// Parse, then convert every card to a [`Contact`], collecting per-card issues.
pub fn import_vcards(
    input: &str,
    limits: &VCardLimits,
    now_unix: i64,
) -> Result<VCardImport, VCardError> {
    let cards = parse_vcards(input, limits)?;
    let mut out = VCardImport::default();
    for card in &cards {
        match card.to_contact(now_unix) {
            Ok(contact) => out.contacts.push(contact),
            Err(e) => out.issues.push(ImportIssue {
                card_index: card.index,
                detail: e.to_string(),
            }),
        }
    }
    Ok(out)
}

// -- export ------------------------------------------------------------------

/// Render one contact as a vCard 4.0 block, CRLF-terminated and folded at 75
/// octets.
///
/// The contact is validated first: without that, a stored value carrying a raw
/// CRLF would let ordinary contact data inject extra vCard lines on export.
pub fn export_vcard(contact: &Contact) -> Result<String, VCardError> {
    let contact = contact.clone().prepare()?;
    let mut out = String::with_capacity(256);
    fold_into(&mut out, "BEGIN:VCARD");
    fold_into(&mut out, &format!("VERSION:{VCARD_VERSION}"));

    let uid = contact
        .source_uid
        .as_deref()
        .filter(|u| !u.is_empty())
        .unwrap_or(&contact.id);
    if !uid.is_empty() {
        fold_into(&mut out, &format!("UID:{}", escape_text(uid)));
    }
    fold_into(
        &mut out,
        &format!("FN:{}", escape_text(&contact.display_name)),
    );
    let n = format!(
        "{};{};{};{};{}",
        escape_text(contact.family_name.as_deref().unwrap_or("")),
        escape_text(contact.given_name.as_deref().unwrap_or("")),
        escape_text(contact.middle_name.as_deref().unwrap_or("")),
        escape_text(contact.name_prefix.as_deref().unwrap_or("")),
        escape_text(contact.name_suffix.as_deref().unwrap_or("")),
    );
    fold_into(&mut out, &format!("N:{n}"));
    if let Some(org) = &contact.org {
        fold_into(&mut out, &format!("ORG:{}", escape_text(org)));
    }
    if let Some(title) = &contact.title {
        fold_into(&mut out, &format!("TITLE:{}", escape_text(title)));
    }
    for e in &contact.emails {
        fold_into(
            &mut out,
            &with_type("EMAIL", e.label.as_deref(), &e.address),
        );
    }
    for p in &contact.phones {
        fold_into(&mut out, &with_type("TEL", p.label.as_deref(), &p.number));
    }
    if !contact.tags.is_empty() {
        let tags: Vec<String> = contact.tags.iter().map(|t| escape_text(t)).collect();
        fold_into(&mut out, &format!("CATEGORIES:{}", tags.join(",")));
    }
    if let Some(notes) = &contact.notes {
        fold_into(&mut out, &format!("NOTE:{}", escape_text(notes)));
    }
    if let Some(rev) = contact.rev_unix {
        fold_into(&mut out, &format!("REV:{}", format_timestamp(rev)));
    }
    fold_into(&mut out, "END:VCARD");
    Ok(out)
}

/// Render several contacts as one concatenated vCard stream.
pub fn export_vcards(contacts: &[Contact]) -> Result<String, VCardError> {
    let mut out = String::with_capacity(contacts.len() * 256);
    for c in contacts {
        out.push_str(&export_vcard(c)?);
    }
    Ok(out)
}

fn with_type(property: &str, label: Option<&str>, value: &str) -> String {
    match label.and_then(sanitize_param_token) {
        Some(token) => format!("{property};TYPE={token}:{}", escape_text(value)),
        None => format!("{property}:{}", escape_text(value)),
    }
}

/// Parameter values come from stored data, so they are restricted to a
/// conservative token alphabet. RFC 6350 has no escaping mechanism for
/// parameters, so anything outside the alphabet is dropped rather than escaped.
fn sanitize_param_token(label: &str) -> Option<String> {
    let token: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(MAX_LABEL_LEN)
        .collect();
    if token.is_empty() {
        None
    } else {
        Some(token.to_ascii_lowercase())
    }
}

/// Escape a text value per RFC 6350 §3.4.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// Fold one logical line into 75-octet physical lines, never splitting a UTF-8
/// sequence, and terminate it with CRLF.
fn fold_into(out: &mut String, line: &str) {
    let mut rest = line;
    let mut budget = 75usize;
    loop {
        if rest.len() <= budget {
            out.push_str(rest);
            out.push_str("\r\n");
            return;
        }
        let mut cut = budget;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            // Unreachable for UTF-8 (max 4 bytes per char) but keeps the loop
            // total rather than risking a non-terminating fold.
            cut = rest.chars().next().map(char::len_utf8).unwrap_or(0);
            if cut == 0 {
                out.push_str("\r\n");
                return;
            }
        }
        out.push_str(rest.get(..cut).unwrap_or(""));
        out.push_str("\r\n ");
        rest = rest.get(cut..).unwrap_or("");
        budget = 74;
    }
}

// -- parsing internals -------------------------------------------------------

/// Split into physical lines, joining continuations (CRLF + one space or tab).
/// Returns `(1-based line number, text)` so errors can point at the source.
fn unfold(input: &str, limits: &VCardLimits) -> Result<Vec<(usize, String)>, VCardError> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut out: Vec<(usize, String)> = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line_no = i + 1;
        if let Some(rest) = raw.strip_prefix(' ').or_else(|| raw.strip_prefix('\t')) {
            if let Some((_, last)) = out.last_mut() {
                if last.len() + rest.len() > limits.max_line_bytes {
                    return Err(VCardError::LineTooLong {
                        line: line_no,
                        limit: limits.max_line_bytes,
                    });
                }
                last.push_str(rest);
                continue;
            }
            // A continuation with nothing to continue: fall through and treat
            // it as a plain line.
        }
        if raw.len() > limits.max_line_bytes {
            return Err(VCardError::LineTooLong {
                line: line_no,
                limit: limits.max_line_bytes,
            });
        }
        out.push((line_no, raw.trim_end_matches('\r').to_string()));
    }
    Ok(out)
}

fn parse_property(
    left: &str,
    value: &str,
    line: usize,
    limits: &VCardLimits,
) -> Result<Property, VCardError> {
    let segments = split_unquoted(left, ';');
    let head = segments.first().map(String::as_str).unwrap_or("");
    if head.is_empty() {
        return Err(VCardError::MalformedLine {
            line,
            detail: "empty property name".to_string(),
        });
    }
    let (group, name) = match head.find('.') {
        Some(i) => (
            head.get(..i).filter(|g| !g.is_empty()).map(str::to_string),
            head.get(i + 1..).unwrap_or("").to_string(),
        ),
        None => (None, head.to_string()),
    };
    let name = name.trim().to_ascii_uppercase();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(VCardError::MalformedLine {
            line,
            detail: format!("invalid property name {name:?}"),
        });
    }
    if !BULK_PROPERTIES.contains(&name.as_str()) && value.len() > limits.max_value_bytes {
        return Err(VCardError::ValueTooLong {
            property: name,
            limit: limits.max_value_bytes,
        });
    }

    let mut params: Vec<(String, Vec<String>)> = Vec::new();
    for segment in segments.iter().skip(1) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        match split_once_unquoted(segment, '=') {
            Some((key, raw_values)) => {
                let key = key.trim().to_ascii_uppercase();
                if key.is_empty() {
                    continue;
                }
                let values = parse_param_values(&raw_values);
                params.push((key, values));
            }
            // Bare parameter: the vCard 3.0 shorthand. `PREF` is a flag;
            // anything else is a value type.
            None => {
                let token = strip_quotes(segment).to_ascii_uppercase();
                if token == "PREF" {
                    params.push(("PREF".to_string(), vec!["1".to_string()]));
                } else if !token.is_empty() {
                    params.push(("TYPE".to_string(), vec![token]));
                }
            }
        }
    }
    Ok(Property {
        group,
        name,
        params,
        value: value.to_string(),
    })
}

fn read_structured_name(raw: &str) -> [String; 5] {
    let parts = split_escaped(raw, ';');
    let mut out: [String; 5] = Default::default();
    for (slot, part) in out.iter_mut().zip(parts.iter()) {
        *slot = unescape_text(part);
    }
    out
}

fn display_from_name_parts(parts: &[String; 5]) -> String {
    let [family, given, additional, prefix, suffix] = parts;
    let mut pieces: Vec<&str> = Vec::with_capacity(5);
    for piece in [prefix, given, additional, family, suffix] {
        if !piece.is_empty() {
            pieces.push(piece.as_str());
        }
    }
    pieces.join(" ").trim().to_string()
}

/// First `TYPE` token that is a meaningful label (`internet`/`pref` are not).
fn type_label(prop: &Property) -> Option<String> {
    prop.param("TYPE")
        .iter()
        .map(|t| t.trim())
        .find(|t| {
            !t.is_empty() && !t.eq_ignore_ascii_case("internet") && !t.eq_ignore_ascii_case("pref")
        })
        .map(|t| t.to_ascii_lowercase())
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Strip one layer of surrounding double quotes, if present.
fn strip_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"') {
        return value.get(1..value.len() - 1).unwrap_or(value);
    }
    value
}

/// Parse one parameter's values. A quoted value is unwrapped and then still
/// split on commas, because vCard 3.0 producers routinely write
/// `TYPE="work,home"` to mean two types rather than one comma-bearing token.
fn parse_param_values(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for value in split_unquoted(raw, ',') {
        for part in strip_quotes(value.trim()).split(',') {
            let part = part.trim();
            if !part.is_empty() {
                out.push(part.to_string());
            }
        }
    }
    out
}

/// Split on `sep`, ignoring separators inside double-quoted spans.
fn split_unquoted(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if ch == sep && !in_quotes {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    out.push(current);
    out
}

fn split_once_unquoted(s: &str, sep: char) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    for (i, ch) in s.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == sep && !in_quotes {
            return Some((s.get(..i)?, s.get(i + ch.len_utf8()..).unwrap_or("")));
        }
    }
    None
}

/// Split on an unescaped `sep`, keeping escape sequences intact so the caller
/// can unescape each component on its own.
fn split_escaped(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == sep {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    out.push(current);
    out
}

/// Undo RFC 6350 §3.4 escaping. Unknown escapes lose the backslash, which is
/// what real-world producers mean by them.
fn unescape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            None => out.push('\\'),
            Some('n') | Some('N') => out.push('\n'),
            Some(other) => out.push(other),
        }
    }
    out.trim().to_string()
}

// -- timestamps --------------------------------------------------------------

/// Parse the timestamp forms real exporters emit (`19961022T140000Z`,
/// `1996-10-22T14:00:00Z`, `19961022`, with an optional `±HHMM` offset) into
/// unix seconds. Anything else yields `None`: `REV` is metadata, never a hard
/// error.
pub fn parse_timestamp(raw: &str) -> Option<i64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let (body, offset) = split_offset(s);
    let (date, time) = match body.find(|c| c == 'T' || c == 't') {
        Some(i) => (body.get(..i)?, body.get(i + 1..).unwrap_or("")),
        None => (body, ""),
    };
    let (year, month, day) = read_date(date)?;
    let (hour, minute, second) = read_time(time)?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

/// Render unix seconds as a vCard 4.0 basic-format timestamp.
pub fn format_timestamp(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{s:02}Z")
}

/// Split a trailing UTC designator or `±HHMM`/`±HH:MM` offset off `s`,
/// returning the remainder and the offset in seconds. A date like `2024-01-01`
/// has no offset and is returned unchanged.
fn split_offset(s: &str) -> (&str, i64) {
    if matches!(s.chars().last(), Some('Z') | Some('z')) {
        if let Some(body) = s.get(..s.len().saturating_sub(1)) {
            return (body, 0);
        }
    }
    let Some(idx) = s.rfind(['+', '-']) else {
        return (s, 0);
    };
    let Some((body, tail)) = s.split_at_checked(idx) else {
        return (s, 0);
    };
    if body.is_empty() {
        return (s, 0);
    }
    let digits: String = tail.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 4
        || !tail
            .chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == '+' || c == '-')
    {
        return (s, 0);
    }
    let (Some(hh), Some(mm)) = (
        digits.get(0..2).and_then(|v| v.parse::<i64>().ok()),
        digits.get(2..4).and_then(|v| v.parse::<i64>().ok()),
    ) else {
        return (s, 0);
    };
    if hh > 23 || mm > 59 {
        return (s, 0);
    }
    let sign = if tail.starts_with('-') { -1 } else { 1 };
    (body, sign * (hh * 3600 + mm * 60))
}

fn read_date(date: &str) -> Option<(i64, u32, u32)> {
    if !date.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return None;
    }
    let digits: String = date.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 8 {
        return None;
    }
    let year = digits.get(0..4)?.parse::<i64>().ok()?;
    let month = digits.get(4..6)?.parse::<u32>().ok()?;
    let day = digits.get(6..8)?.parse::<u32>().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

fn read_time(time: &str) -> Option<(i64, i64, i64)> {
    if time.is_empty() {
        return Some((0, 0, 0));
    }
    if !time.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return None;
    }
    let digits: String = time.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 6 {
        return None;
    }
    let hour = digits.get(0..2)?.parse::<i64>().ok()?;
    let minute = digits.get(2..4)?.parse::<i64>().ok()?;
    let second = digits.get(4..6)?.parse::<i64>().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`). Integer-only, so it is exact and deterministic.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((month as i64) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "BEGIN:VCARD\r\n\
VERSION:4.0\r\n\
UID:urn:uuid:ada-1\r\n\
FN:Ada Lovelace\r\n\
N:Lovelace;Ada;Byron;Countess;Jr\r\n\
ORG:Analytical Engines;Research\r\n\
TITLE:Mathematician\r\n\
EMAIL;TYPE=home:ada@home.invalid\r\n\
EMAIL;TYPE=work;PREF=1:ada@work.invalid\r\n\
TEL;TYPE=mobile:555-0100\r\n\
CATEGORIES:friend,math\r\n\
NOTE:Met at the\\, er\\; demo\\nline two\r\n\
REV:19961022T140000Z\r\n\
END:VCARD\r\n";

    fn limits() -> VCardLimits {
        VCardLimits::default()
    }

    #[test]
    fn parses_a_full_card() {
        let cards = parse_vcards(FULL, &limits()).unwrap();
        assert_eq!(cards.len(), 1);
        let c = cards[0].to_contact(1_000).unwrap();
        assert_eq!(c.display_name, "Ada Lovelace");
        assert_eq!(c.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(c.given_name.as_deref(), Some("Ada"));
        assert_eq!(c.middle_name.as_deref(), Some("Byron"));
        assert_eq!(c.name_prefix.as_deref(), Some("Countess"));
        assert_eq!(c.name_suffix.as_deref(), Some("Jr"));
        assert_eq!(c.org.as_deref(), Some("Analytical Engines"));
        assert_eq!(c.title.as_deref(), Some("Mathematician"));
        assert_eq!(c.source_uid.as_deref(), Some("urn:uuid:ada-1"));
        assert_eq!(c.tags, vec!["friend", "math"]);
        assert_eq!(c.notes.as_deref(), Some("Met at the, er; demo\nline two"));
        assert_eq!(c.rev_unix, Some(845_992_800));
        assert_eq!(c.phones.len(), 1);
        assert_eq!(c.phones[0].label.as_deref(), Some("mobile"));
    }

    #[test]
    fn preferred_email_sorts_first() {
        let cards = parse_vcards(FULL, &limits()).unwrap();
        let c = cards[0].to_contact(0).unwrap();
        assert_eq!(c.primary_email(), Some("ada@work.invalid"));
        assert_eq!(c.emails.len(), 2);
        assert_eq!(c.emails[0].label.as_deref(), Some("work"));
        assert_eq!(c.emails[1].label.as_deref(), Some("home"));
    }

    #[test]
    fn bare_v3_params_and_internet_type_are_understood() {
        let src = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob\r\n\
                   EMAIL;TYPE=INTERNET;PREF:bob@x.invalid\r\n\
                   EMAIL;INTERNET:bob@y.invalid\r\nEND:VCARD\r\n";
        let cards = parse_vcards(src, &limits()).unwrap();
        let c = cards[0].to_contact(0).unwrap();
        assert_eq!(c.primary_email(), Some("bob@x.invalid"), "PREF wins");
        assert_eq!(c.emails.len(), 2);
        assert!(
            c.emails.iter().all(|e| e.label.is_none()),
            "INTERNET is a transport hint, not a label"
        );
    }

    #[test]
    fn unknown_properties_and_groups_are_ignored_not_fatal() {
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Zoe\r\n\
                   item1.EMAIL:zoe@x.invalid\r\n\
                   X-KIWI-CUSTOM:whatever\r\nURL:https://example.invalid\r\n\
                   BDAY:19700101\r\nEND:VCARD\r\n";
        let cards = parse_vcards(src, &limits()).unwrap();
        assert_eq!(cards[0].properties.len(), 5);
        assert_eq!(cards[0].properties[1].group.as_deref(), Some("item1"));
        assert_eq!(
            cards[0].to_contact(0).unwrap().primary_email(),
            Some("zoe@x.invalid")
        );
    }

    #[test]
    fn folded_lines_are_rejoined() {
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada\r\n\
                   NOTE:first part \r\n continued here\r\n\tand a tab fold\r\n\
                   END:VCARD\r\n";
        let cards = parse_vcards(src, &limits()).unwrap();
        let note = cards[0]
            .properties
            .iter()
            .find(|p| p.name == "NOTE")
            .map(|p| p.value.clone());
        assert_eq!(
            note.as_deref(),
            Some("first part continued hereand a tab fold")
        );
    }

    #[test]
    fn quoted_params_may_contain_separators() {
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Q\r\n\
                   EMAIL;TYPE=\"work,home\";X-NOTE=\"a:b;c\":q@x.invalid\r\nEND:VCARD\r\n";
        let cards = parse_vcards(src, &limits()).unwrap();
        let email = cards[0]
            .properties
            .iter()
            .find(|p| p.name == "EMAIL")
            .unwrap();
        assert_eq!(email.value, "q@x.invalid");
        assert_eq!(
            email.param("TYPE"),
            &["work".to_string(), "home".to_string()]
        );
        assert_eq!(email.param("X-NOTE"), &["a:b;c".to_string()]);
        assert_eq!(
            cards[0].to_contact(0).unwrap().emails[0].label.as_deref(),
            Some("work")
        );
    }

    #[test]
    fn a_photo_does_not_fail_the_card() {
        let photo = "a".repeat(20_000);
        let src = format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Zoe\r\nPHOTO;ENCODING=b;TYPE=JPEG:{photo}\r\n\
             EMAIL:zoe@x.invalid\r\nEND:VCARD\r\n"
        );
        let import = import_vcards(&src, &limits(), 0).unwrap();
        assert!(
            import.is_complete(),
            "bulk properties are skipped, not fatal"
        );
        assert_eq!(import.contacts.len(), 1);
        assert_eq!(import.contacts[0].display_name, "Zoe");
    }

    #[test]
    fn oversized_stored_values_are_rejected() {
        let note = "n".repeat(VCardLimits::default().max_value_bytes + 1);
        let src = format!("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nNOTE:{note}\r\nEND:VCARD\r\n");
        assert!(matches!(
            parse_vcards(&src, &limits()),
            Err(VCardError::ValueTooLong { .. })
        ));
    }

    #[test]
    fn multiple_cards_are_independent() {
        let src = format!("{FULL}BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Grace\r\nEND:VCARD\r\n");
        let cards = parse_vcards(&src, &limits()).unwrap();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[1].index, 1);
        let import = import_vcards(&src, &limits(), 0).unwrap();
        assert_eq!(import.contacts.len(), 2);
        assert!(import.is_complete());
    }

    #[test]
    fn display_name_falls_back_to_n_then_email() {
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Hopper;Grace;;;Admiral\r\nEND:VCARD\r\n";
        let c = parse_vcards(src, &limits()).unwrap()[0]
            .to_contact(0)
            .unwrap();
        assert_eq!(c.display_name, "Grace Hopper Admiral");

        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nEMAIL:anon@x.invalid\r\nEND:VCARD\r\n";
        let c = parse_vcards(src, &limits()).unwrap()[0]
            .to_contact(0)
            .unwrap();
        assert_eq!(c.display_name, "anon@x.invalid");
    }

    #[test]
    fn missing_and_unsupported_versions_are_reported_per_card() {
        let src = "BEGIN:VCARD\r\nFN:NoVersion\r\nEND:VCARD\r\n\
                   BEGIN:VCARD\r\nVERSION:9.9\r\nFN:Future\r\nEND:VCARD\r\n\
                   BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Good\r\nEND:VCARD\r\n";
        let import = import_vcards(src, &limits(), 0).unwrap();
        assert_eq!(import.contacts.len(), 1);
        assert_eq!(import.contacts[0].display_name, "Good");
        assert_eq!(import.issues.len(), 2);
        assert_eq!(import.issues[0].card_index, 0);
        assert!(import.issues[0].detail.contains("VERSION"));
        assert_eq!(import.issues[1].card_index, 1);
        assert!(import.issues[1].detail.contains("9.9"));
    }

    #[test]
    fn structurally_broken_streams_fail_hard() {
        assert!(matches!(
            parse_vcards("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:x\r\n", &limits()),
            Err(VCardError::UnterminatedCard { index: 0 })
        ));
        assert!(matches!(
            parse_vcards("FN:stray\r\n", &limits()),
            Err(VCardError::StrayContent { line: 1 })
        ));
        assert!(matches!(
            parse_vcards(
                "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:x\r\nEND:VCARD\r\nFN:after\r\n",
                &limits()
            ),
            Err(VCardError::StrayContent { line: 5 })
        ));
        assert!(matches!(
            parse_vcards(
                "BEGIN:VCARD\r\nVERSION:4.0\r\nFNNOCOLON\r\nEND:VCARD\r\n",
                &limits()
            ),
            Err(VCardError::MalformedLine { line: 3, .. })
        ));
        assert!(matches!(
            parse_vcards("BEGIN:VCARD\r\nVERSION:4.0\r\nBEGIN:VCARD\r\n", &limits()),
            Err(VCardError::MalformedLine { line: 3, .. })
        ));
        assert!(matches!(
            parse_vcards("BEGIN:NOTVCARD\r\nVERSION:4.0\r\n", &limits()),
            Err(VCardError::MalformedLine { line: 1, .. })
        ));
        assert!(matches!(
            parse_vcards("BEGIN:VCARD\r\nVERSION:4.0\r\nEND:NOTVCARD\r\n", &limits()),
            Err(VCardError::MalformedLine { line: 3, .. })
        ));
        assert!(matches!(
            parse_vcards("END:VCARD\r\n", &limits()),
            Err(VCardError::StrayContent { line: 1 })
        ));
    }

    #[test]
    fn empty_input_is_an_empty_import() {
        assert!(parse_vcards("", &limits()).unwrap().is_empty());
        assert!(parse_vcards("\r\n\r\n", &limits()).unwrap().is_empty());
        assert!(
            import_vcards("   \r\n", &limits(), 0)
                .unwrap()
                .contacts
                .is_empty()
        );
    }

    #[test]
    fn input_size_cap_is_enforced() {
        let tight = VCardLimits {
            max_input_bytes: 64,
            ..VCardLimits::default()
        };
        let big = "x".repeat(65);
        assert!(matches!(
            parse_vcards(&big, &tight),
            Err(VCardError::InputTooLarge {
                limit: 64,
                actual: 65
            })
        ));
    }

    #[test]
    fn line_length_cap_is_enforced() {
        let tight = VCardLimits {
            max_line_bytes: 32,
            ..VCardLimits::default()
        };
        let src = format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:{}\r\nEND:VCARD\r\n",
            "y".repeat(80)
        );
        assert!(matches!(
            parse_vcards(&src, &tight),
            Err(VCardError::LineTooLong { limit: 32, .. })
        ));
        // Folding cannot be used to smuggle past the line cap either.
        let folded = format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:ok\r\nNOTE:{}\r\n {}\r\nEND:VCARD\r\n",
            "y".repeat(30),
            "y".repeat(30)
        );
        assert!(matches!(
            parse_vcards(&folded, &tight),
            Err(VCardError::LineTooLong { .. })
        ));
    }

    #[test]
    fn card_count_and_property_count_caps_are_enforced() {
        let two = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:a\r\nEND:VCARD\r\n\
                   BEGIN:VCARD\r\nVERSION:4.0\r\nFN:b\r\nEND:VCARD\r\n";
        let one_card = VCardLimits {
            max_cards: 1,
            ..VCardLimits::default()
        };
        assert!(matches!(
            parse_vcards(two, &one_card),
            Err(VCardError::TooManyCards { limit: 1 })
        ));

        let two_props = VCardLimits {
            max_properties_per_card: 2,
            ..VCardLimits::default()
        };
        assert!(matches!(
            parse_vcards(
                "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:a\r\nORG:b\r\nNOTE:c\r\nEND:VCARD\r\n",
                &two_props
            ),
            Err(VCardError::TooManyProperties { index: 0, limit: 2 })
        ));
    }

    #[test]
    fn per_card_value_caps_are_reported_as_issues() {
        let emails = (0..=MAX_EMAILS)
            .map(|i| format!("EMAIL:e{i}@x.invalid\r\n"))
            .collect::<String>();
        let src = format!("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Many\r\n{emails}END:VCARD\r\n");
        let import = import_vcards(&src, &limits(), 0).unwrap();
        assert!(import.contacts.is_empty());
        assert_eq!(import.issues.len(), 1);
        assert!(import.issues[0].detail.contains("EMAIL"));

        let tags = (0..=MAX_TAGS)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let src =
            format!("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Many\r\nCATEGORIES:{tags}\r\nEND:VCARD\r\n");
        let import = import_vcards(&src, &limits(), 0).unwrap();
        assert!(import.issues[0].detail.contains("CATEGORIES"));
    }

    #[test]
    fn hostile_values_cannot_break_the_stream_open() {
        // An escaped newline in FN stays data: after unescaping it is a newline
        // *inside* a value, never a second card or a stray line. The card is
        // then refused for what its name contains rather than the stream being
        // reinterpreted as structure.
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Evil\\nEND:VCARD\\nBEGIN:VCARD\\nSneaky\r\n\
                   END:VCARD\r\n";
        let cards = parse_vcards(src, &limits()).unwrap();
        assert_eq!(
            cards.len(),
            1,
            "the escaped newline is data, not a card break"
        );
        assert_eq!(cards[0].properties.len(), 1, "and not a stray property");

        let import = import_vcards(src, &limits(), 0).unwrap();
        assert!(
            import.contacts.is_empty(),
            "a name with a newline is not storable"
        );
        assert_eq!(import.issues.len(), 1);
        assert!(
            import.issues[0].detail.contains("display_name"),
            "the reason must name the field: {}",
            import.issues[0].detail
        );
    }

    #[test]
    fn notes_is_the_only_multi_line_field() {
        let src =
            "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ok\r\nNOTE:line one\\nline two\r\nEND:VCARD\r\n";
        let c = parse_vcards(src, &limits()).unwrap()[0]
            .to_contact(0)
            .unwrap();
        assert_eq!(c.notes.as_deref(), Some("line one\nline two"));
        assert_eq!(c.display_name, "Ok");

        // The same escape in a single-line field is refused, not silently kept.
        let src = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ok\r\nORG:Acme\\nInc\r\nEND:VCARD\r\n";
        let import = import_vcards(src, &limits(), 0).unwrap();
        assert!(import.contacts.is_empty());
        assert!(import.issues[0].detail.contains("org"));
    }

    #[test]
    fn timestamps_round_trip_and_reject_junk() {
        assert_eq!(parse_timestamp("19961022T140000Z"), Some(845_992_800));
        assert_eq!(parse_timestamp("1996-10-22T14:00:00Z"), Some(845_992_800));
        assert_eq!(parse_timestamp("19961022T140000+0200"), Some(845_985_600));
        assert_eq!(parse_timestamp("19700101"), Some(0));
        assert_eq!(parse_timestamp("19700101T000000-0130"), Some(5_400));
        assert_eq!(parse_timestamp("not a date"), None);
        assert_eq!(parse_timestamp("20241301"), None, "month 13");
        assert_eq!(parse_timestamp("19961022T996100Z"), None, "hour 99");
        assert_eq!(parse_timestamp("19961022T1400"), None, "short time");
        assert_eq!(parse_timestamp(""), None);

        for unix in [0_i64, 845_992_800, 1_758_000_000, 4_102_444_800] {
            let text = format_timestamp(unix);
            assert_eq!(parse_timestamp(&text), Some(unix), "{text} must round-trip");
        }
    }

    #[test]
    fn export_round_trips_through_import() {
        let mut c = Contact::new("Ada Lovelace", 0)
            .with_email("ada@work.invalid", Some("work"))
            .with_org("Analytical Engines")
            .with_tags(vec!["friend", "math"]);
        c.given_name = Some("Ada".into());
        c.family_name = Some("Lovelace".into());
        c.title = Some("Mathematician".into());
        c.notes = Some("line one\nline two; with, punctuation\\ and backslash".into());
        c.phones = vec![ContactPhone {
            number: "+44 20 7946 0958".into(),
            label: Some("home".into()),
        }];
        c.source_uid = Some("urn:uuid:ada-1".into());
        c.rev_unix = Some(845_992_800);
        c.id = "local-7".into();

        let text = export_vcard(&c).unwrap();
        assert!(text.starts_with("BEGIN:VCARD\r\nVERSION:4.0\r\n"));
        assert!(text.ends_with("END:VCARD\r\n"));
        assert!(text.contains("UID:urn:uuid:ada-1\r\n"));
        assert!(text.contains("REV:19961022T140000Z\r\n"));

        let back = parse_vcards(&text, &limits()).unwrap()[0]
            .to_contact(0)
            .unwrap();
        assert_eq!(back.display_name, c.display_name);
        assert_eq!(back.given_name, c.given_name);
        assert_eq!(back.family_name, c.family_name);
        assert_eq!(back.org, c.org);
        assert_eq!(back.title, c.title);
        assert_eq!(back.notes, c.notes);
        assert_eq!(back.tags, c.tags);
        assert_eq!(back.emails, c.emails);
        assert_eq!(back.phones, c.phones);
        assert_eq!(back.source_uid, c.source_uid);
        assert_eq!(back.rev_unix, c.rev_unix);
    }

    #[test]
    fn export_folds_at_75_octets_on_char_boundaries() {
        let mut c = Contact::new("Ünïcödé Nàme Wîth Möre Thän Sëventy Fïve Öctets", 0);
        c.notes = Some("é".repeat(120));
        c.tags = vec!["kürbis".into()];
        let text = export_vcard(&c).unwrap();
        for line in text.split("\r\n") {
            assert!(line.len() <= 75, "physical line too long: {line:?}");
        }
        let back = parse_vcards(&text, &limits()).unwrap()[0]
            .to_contact(0)
            .unwrap();
        assert_eq!(back.display_name, c.display_name);
        assert_eq!(back.notes, c.notes);
        assert_eq!(back.tags, c.tags);
    }

    #[test]
    fn export_escapes_separators_and_refuses_control_characters() {
        let mut c = Contact::new("Semi; Comma, Back\\slash", 0);
        c.notes = Some("a;b,c\\d".into());
        let text = export_vcard(&c).unwrap();
        assert!(text.contains("FN:Semi\\; Comma\\, Back\\\\slash\r\n"));
        assert!(text.contains("NOTE:a\\;b\\,c\\\\d\r\n"));

        // A stored value carrying a raw CRLF must not be renderable at all.
        let mut bad = Contact::new("ok", 0);
        bad.notes = Some("x\r\nEND:VCARD\r\nBEGIN:VCARD".into());
        assert!(export_vcard(&bad).is_err());
    }

    #[test]
    fn export_sanitizes_type_params() {
        let mut c = Contact::new("A", 0);
        c.emails = vec![ContactEmail {
            address: "a@b.invalid".into(),
            label: Some("we;ird=type".into()),
        }];
        let text = export_vcard(&c).unwrap();
        assert!(
            text.contains("EMAIL;TYPE=weirdtype:a@b.invalid\r\n"),
            "{text}"
        );
        assert_eq!(text.matches("TYPE=").count(), 1);

        let mut c = Contact::new("A", 0);
        c.emails = vec![ContactEmail {
            address: "a@b.invalid".into(),
            label: Some("!!!".into()),
        }];
        assert!(export_vcard(&c).unwrap().contains("EMAIL:a@b.invalid\r\n"));
    }

    #[test]
    fn exports_multiple_cards_as_one_stream() {
        let a = Contact::new("Ada", 0).with_email("ada@x.invalid", None);
        let b = Contact::new("Grace", 0).with_email("grace@x.invalid", None);
        let text = export_vcards(&[a, b]).unwrap();
        assert_eq!(text.matches("BEGIN:VCARD").count(), 2);
        let import = import_vcards(&text, &limits(), 0).unwrap();
        assert_eq!(import.contacts.len(), 2);
        assert_eq!(import.contacts[0].display_name, "Ada");
        assert_eq!(import.contacts[1].display_name, "Grace");
    }

    #[test]
    fn a_contact_without_an_id_still_exports_without_a_fabricated_uid() {
        let c = Contact::new("No Id", 0).with_email("n@x.invalid", None);
        let text = export_vcard(&c).unwrap();
        assert!(!text.contains("UID:"));
    }
}
