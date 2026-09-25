//! Deterministic attachment risk hints (T-254).
//!
//! Evidence only: this module never creates findings, blocks UI, opens files,
//! extracts archives, executes content, or mutates mail.

use serde::{Deserialize, Serialize};

/// Bounded UI vocabulary shared with the auth-risk hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachRisk {
    /// No configured risk signal was observed.
    #[default]
    Clean,
    /// A macro/opaque/encrypted/archive signal requires caution or limits inspection.
    Noted,
    /// A configured dangerous extension/content type was observed.
    Failed,
}

impl AttachRisk {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Noted => "noted",
            Self::Failed => "failed",
        }
    }

    /// Parse persisted data; unknown/corrupt values fail closed to `noted`.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "clean" => Self::Clean,
            "failed" => Self::Failed,
            _ => Self::Noted,
        }
    }
}

/// Fixed reason vocabulary. No filenames, MIME parameters, or payload bytes are
/// retained in reasons, so the list is bounded even for hostile messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttachRiskReason {
    DangerousExtension,
    DoubleExtension,
    DangerousContentType,
    MacroEnabledOffice,
    VbaProjectContainer,
    ArchiveNotInspectable,
    EncryptedOrOpaqueContainer,
    UnicodeConfusable,
}

/// Per-message evidence derived at MIME parse time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachRiskEvidence {
    pub risk: AttachRisk,
    pub reasons: Vec<AttachRiskReason>,
}

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "ps1", "lnk", "iso", "img",
    "msi", "jar", "hta", "wsf",
];
const MACRO_EXTENSIONS: &[&str] = &["docm", "xlsm", "pptm"];
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "7z", "rar", "tar", "gz", "bz2", "xz", "cab", "tgz"];
const DANGEROUS_CONTENT_TYPES: &[&str] = &[
    "application/x-msdownload",
    "application/x-dosexec",
    "application/javascript",
    "text/javascript",
    "application/x-sh",
    "application/x-powershell",
    "application/x-ms-shortcut",
    "application/x-iso9660-image",
    "application/x-msi",
    "application/java-archive",
    "application/x-hta",
];
const ARCHIVE_CONTENT_TYPES: &[&str] = &[
    "application/zip",
    "application/x-7z-compressed",
    "application/vnd.rar",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-tar",
    "application/vnd.ms-cab-compressed",
];
const MACRO_CONTENT_TYPES: &[&str] = &[
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
];
const MAX_FILENAME_CHARS: usize = 512;
const MAX_BODY_SCAN_BYTES: usize = 2 * 1024 * 1024;

fn push_reason(out: &mut AttachRiskEvidence, reason: AttachRiskReason) {
    if !out.reasons.contains(&reason) {
        out.reasons.push(reason);
    }
}

fn raise_to(out: &mut AttachRiskEvidence, risk: AttachRisk) {
    out.risk = match (out.risk, risk) {
        (AttachRisk::Failed, _) | (_, AttachRisk::Failed) => AttachRisk::Failed,
        (AttachRisk::Noted, _) | (_, AttachRisk::Noted) => AttachRisk::Noted,
        _ => AttachRisk::Clean,
    };
}

/// Map a small, fixed set of common fullwidth/Cyrillic lookalikes to ASCII for
/// extension checks. The original Unicode is still bounded; unmapped non-ASCII
/// extensions receive `unicodeConfusable` and never silently become clean.
fn fold_confusable(c: char) -> char {
    match c {
        '\u{ff21}'..='\u{ff3a}' | '\u{ff41}'..='\u{ff5a}' => {
            let (origin, base) = if c.is_uppercase() {
                (0xff21_u32, 'A' as u32)
            } else {
                (0xff41, 'a' as u32)
            };
            char::from_u32(c as u32 - origin + base).unwrap_or(c)
        }
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        _ => c,
    }
}

impl AttachRiskEvidence {
    /// Merge one attachment's evidence, deduplicating the fixed reason set.
    pub fn merge(&mut self, other: Self) {
        raise_to(self, other.risk);
        for reason in other.reasons {
            push_reason(self, reason);
        }
    }
}

fn extension_parts(filename: &str) -> (Vec<String>, bool) {
    let total = filename.chars().count();
    let bounded: String = filename
        .chars()
        .skip(total.saturating_sub(MAX_FILENAME_CHARS))
        .collect();
    let has_non_ascii = !bounded.is_ascii();
    let folded: String = bounded.chars().map(fold_confusable).collect();
    let cleaned = folded.trim_end_matches(['.', ' ']);
    let parts: Vec<String> = cleaned
        .rsplit('.')
        .take(4)
        .map(|part| part.to_ascii_lowercase())
        .collect();
    (parts, has_non_ascii)
}

fn is_ole_compound(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn contains_ascii_case_insensitive(bytes: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    bytes.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn contains_utf16le_ascii_case_insensitive(bytes: &[u8], needle: &[u8]) -> bool {
    let mut wide = Vec::with_capacity(needle.len() * 2);
    for byte in needle {
        wide.push(byte.to_ascii_lowercase());
        wide.push(0);
    }
    contains_ascii_case_insensitive(bytes, &wide)
}

/// Inspect one decoded attachment. Content is scanned only for fixed magic and
/// the literal `vbaProject` marker; it is never extracted, decompressed, or
/// retained. A scan over the cap is an inspection limitation, not clean proof.
pub fn inspect_attachment(
    filename: Option<&str>,
    content_type: &str,
    bytes: &[u8],
) -> AttachRiskEvidence {
    let mut out = AttachRiskEvidence::default();
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if DANGEROUS_CONTENT_TYPES.contains(&content_type.as_str()) {
        raise_to(&mut out, AttachRisk::Failed);
        push_reason(&mut out, AttachRiskReason::DangerousContentType);
    }
    if MACRO_CONTENT_TYPES.contains(&content_type.as_str()) {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::MacroEnabledOffice);
    }
    if ARCHIVE_CONTENT_TYPES.contains(&content_type.as_str()) {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::ArchiveNotInspectable);
    }

    if let Some(filename) = filename {
        let (parts, has_non_ascii) = extension_parts(filename);
        let dangerous = parts
            .iter()
            .any(|part| DANGEROUS_EXTENSIONS.contains(&part.as_str()));
        let macro_enabled = parts
            .iter()
            .any(|part| MACRO_EXTENSIONS.contains(&part.as_str()));
        let archive = parts
            .iter()
            .any(|part| ARCHIVE_EXTENSIONS.contains(&part.as_str()));
        let extension_count = parts.len().saturating_sub(1);
        if dangerous {
            raise_to(&mut out, AttachRisk::Failed);
            push_reason(&mut out, AttachRiskReason::DangerousExtension);
        }
        if dangerous && extension_count >= 2 {
            raise_to(&mut out, AttachRisk::Failed);
            push_reason(&mut out, AttachRiskReason::DoubleExtension);
        }
        if macro_enabled {
            raise_to(&mut out, AttachRisk::Noted);
            push_reason(&mut out, AttachRiskReason::MacroEnabledOffice);
        }
        if archive {
            raise_to(&mut out, AttachRisk::Noted);
            push_reason(&mut out, AttachRiskReason::ArchiveNotInspectable);
        }
        if has_non_ascii {
            raise_to(&mut out, AttachRisk::Noted);
            push_reason(&mut out, AttachRiskReason::UnicodeConfusable);
        }
    }

    let scan = &bytes[..bytes.len().min(MAX_BODY_SCAN_BYTES)];
    let vba_ascii = contains_ascii_case_insensitive(scan, b"vbaProject");
    let vba_utf16 = contains_utf16le_ascii_case_insensitive(scan, b"vbaProject");
    if vba_ascii || vba_utf16 {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::VbaProjectContainer);
    }
    if is_ole_compound(scan) {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::EncryptedOrOpaqueContainer);
    }
    if content_type == "application/pdf" && contains_ascii_case_insensitive(scan, b"/Encrypt") {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::EncryptedOrOpaqueContainer);
    }
    if is_zip(scan) {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::ArchiveNotInspectable);
    }
    if bytes.len() > MAX_BODY_SCAN_BYTES
        && (is_ole_compound(scan) || is_zip(scan) || content_type.contains("officedocument"))
    {
        raise_to(&mut out, AttachRisk::Noted);
        push_reason(&mut out, AttachRiskReason::ArchiveNotInspectable);
    }
    out
}

/// Aggregate fixed per-attachment evidence into the per-message hint.
#[must_use]
pub fn inspect_attachments<'a>(
    attachments: impl IntoIterator<Item = (&'a str, &'a str, &'a [u8])>,
) -> AttachRiskEvidence {
    let mut out = AttachRiskEvidence::default();
    for (filename, content_type, bytes) in attachments {
        out.merge(inspect_attachment(Some(filename), content_type, bytes));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(name: &str, content_type: &str, bytes: &[u8]) -> AttachRiskEvidence {
        inspect_attachment(Some(name), content_type, bytes)
    }

    #[test]
    fn every_dangerous_extension_fails() {
        for ext in DANGEROUS_EXTENSIONS {
            let got = inspect(
                &format!("payload.{ext}"),
                "application/octet-stream",
                b"data",
            );
            assert_eq!(got.risk, AttachRisk::Failed, "extension {ext}");
            assert!(got.reasons.contains(&AttachRiskReason::DangerousExtension));
        }
    }

    #[test]
    fn double_extensions_and_case_tricks_fail() {
        for name in [
            "invoice.pdf.exe",
            "photo.jpg.Ps1",
            "quarterly.report.iso",
            "archive.tar.gz.exe",
        ] {
            let got = inspect(name, "application/octet-stream", b"data");
            assert_eq!(got.risk, AttachRisk::Failed, "filename {name}");
            assert!(
                got.reasons.contains(&AttachRiskReason::DoubleExtension),
                "{name}"
            );
        }
    }

    #[test]
    fn dangerous_content_type_fails_even_with_benign_name() {
        let got = inspect(
            "report.pdf",
            "application/x-msdownload; charset=binary",
            b"MZ",
        );
        assert_eq!(got.risk, AttachRisk::Failed);
        assert!(
            got.reasons
                .contains(&AttachRiskReason::DangerousContentType)
        );
    }

    #[test]
    fn macro_office_extensions_and_vba_containers_are_noted() {
        for ext in MACRO_EXTENSIONS {
            let got = inspect(&format!("book.{ext}"), "application/octet-stream", b"data");
            assert_eq!(got.risk, AttachRisk::Noted);
            assert!(got.reasons.contains(&AttachRiskReason::MacroEnabledOffice));
        }
        let mut ole = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
        ole.extend_from_slice(b"vbaProject");
        let got = inspect("unknown.bin", "application/octet-stream", &ole);
        assert_eq!(got.risk, AttachRisk::Noted);
        assert!(got.reasons.contains(&AttachRiskReason::VbaProjectContainer));
        assert!(
            got.reasons
                .contains(&AttachRiskReason::EncryptedOrOpaqueContainer)
        );

        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"xl/vbaProject.bin");
        let got = inspect("unknown.bin", "application/zip", &zip);
        assert_eq!(got.risk, AttachRisk::Noted);
        assert!(got.reasons.contains(&AttachRiskReason::VbaProjectContainer));
    }

    #[test]
    fn archives_and_encrypted_containers_are_not_inspectable() {
        for name in ["bundle.zip", "photos.7z", "old.tar.gz"] {
            let got = inspect(name, "application/octet-stream", b"opaque");
            assert_eq!(got.risk, AttachRisk::Noted, "{name}");
            assert!(
                got.reasons
                    .contains(&AttachRiskReason::ArchiveNotInspectable)
            );
        }
        let pdf = inspect("locked.pdf", "application/pdf", b"%PDF-1.7\n/Encrypt 9 0 R");
        assert_eq!(pdf.risk, AttachRisk::Noted);
        assert!(
            pdf.reasons
                .contains(&AttachRiskReason::EncryptedOrOpaqueContainer)
        );
    }

    #[test]
    fn unicode_confusables_are_bounded_and_mapped_defensively() {
        let mapped = inspect(
            "invoice.\u{ff45}\u{ff58}\u{ff45}",
            "application/octet-stream",
            b"x",
        );
        assert_eq!(mapped.risk, AttachRisk::Failed);
        assert!(
            mapped
                .reasons
                .contains(&AttachRiskReason::DangerousExtension)
        );
        assert!(
            mapped
                .reasons
                .contains(&AttachRiskReason::UnicodeConfusable)
        );

        let unmapped = inspect(
            "report.\u{0435}\u{0441}\u{0435}",
            "application/octet-stream",
            b"x",
        );
        assert_eq!(unmapped.risk, AttachRisk::Noted);
        assert_eq!(unmapped.reasons, [AttachRiskReason::UnicodeConfusable]);

        let case = inspect("PDF.EXE", "application/octet-stream", b"x");
        assert_eq!(case.risk, AttachRisk::Failed);
        assert!(!case.reasons.contains(&AttachRiskReason::DoubleExtension));

        let long = "a".repeat(MAX_FILENAME_CHARS * 2) + ".exe";
        let bounded = inspect(&long, "application/octet-stream", b"x");
        assert_eq!(
            bounded.risk,
            AttachRisk::Failed,
            "bounded tail still inspected"
        );
    }

    #[test]
    fn clean_and_wire_vocabulary() {
        let got = inspect("report.pdf", "application/pdf", b"%PDF-1.7 clean");
        assert_eq!(got.risk, AttachRisk::Clean);
        assert!(got.reasons.is_empty());
        assert_eq!(AttachRisk::from_wire("clean"), AttachRisk::Clean);
        assert_eq!(AttachRisk::from_wire("noted"), AttachRisk::Noted);
        assert_eq!(AttachRisk::from_wire("failed"), AttachRisk::Failed);
        assert_eq!(AttachRisk::from_wire("future"), AttachRisk::Noted);
    }
}
