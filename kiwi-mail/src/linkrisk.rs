//! Deterministic per-message link risk hints (T-261).
//!
//! Parses bounded URL evidence from plain text and HTML anchors. This is a UI
//! hint only: it never resolves hosts, opens links, blocks UI, creates findings,
//! or mutates mail.

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkRisk {
    /// No configured signal was observed.
    #[default]
    Clean,
    /// A transport/opaque-shape limitation was observed.
    Noted,
    /// A clear high-confidence contradiction or dangerous URL shape was observed.
    Failed,
}

impl LinkRisk {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Noted => "noted",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "clean" => Self::Clean,
            "failed" => Self::Failed,
            _ => Self::Noted,
        }
    }
}

/// Fixed reason vocabulary. No URLs, domains, display text, or body fragments
/// are persisted in reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkRiskReason {
    IpLiteralHost,
    DisplayDomainMismatch,
    InsecureHttp,
    KnownShortener,
    ExcessiveSubdomains,
    ExcessiveHyphens,
    PunycodeHost,
    UnicodeHost,
    CredentialsInUrl,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRiskEvidence {
    pub risk: LinkRisk,
    pub reasons: Vec<LinkRiskReason>,
}

impl LinkRiskEvidence {
    pub fn merge(&mut self, other: Self) {
        raise_to(self, other.risk);
        for reason in other.reasons {
            push_reason(self, reason);
        }
    }
}

const MAX_BODY_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_LINKS: usize = 256;
const MAX_URL_CHARS: usize = 2048;
const MAX_DISPLAY_CHARS: usize = 512;
const MAX_SUBDOMAINS: usize = 4;
const MAX_HYPHENS: usize = 4;
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
];

fn push_reason(out: &mut LinkRiskEvidence, reason: LinkRiskReason) {
    if !out.reasons.contains(&reason) {
        out.reasons.push(reason);
    }
}

fn raise_to(out: &mut LinkRiskEvidence, risk: LinkRisk) {
    out.risk = match (out.risk, risk) {
        (LinkRisk::Failed, _) | (_, LinkRisk::Failed) => LinkRisk::Failed,
        (LinkRisk::Noted, _) | (_, LinkRisk::Noted) => LinkRisk::Noted,
        _ => LinkRisk::Clean,
    };
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn strip_tags(value: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in value.chars().take(MAX_DISPLAY_CHARS) {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    decode_basic_entities(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn host_shape(url: &Url) -> Option<String> {
    url.host_str().map(str::to_ascii_lowercase)
}

fn is_shortener(host: &str) -> bool {
    SHORTENERS
        .iter()
        .any(|shortener| host == *shortener || host.ends_with(&format!(".{shortener}")))
}

fn domain_related(display: &str, host: &str) -> bool {
    display == host
        || display.ends_with(&format!(".{host}"))
        || host.ends_with(&format!(".{display}"))
}

fn display_domains(display: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in display.split_whitespace() {
        let token =
            token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != ':');
        let Some((domain, _)) = token.rsplit_once(':') else {
            if token.contains('.') && !token.contains('@') {
                out.push(token.trim_matches('.').to_ascii_lowercase());
            }
            continue;
        };
        if domain.contains('.') && !domain.contains('@') {
            out.push(domain.trim_matches('.').to_ascii_lowercase());
        }
    }
    out.into_iter().filter(|d| !d.is_empty()).take(4).collect()
}

fn raw_authority(raw: &str) -> &str {
    let after_scheme = raw.split_once("://").map_or("", |(_, rest)| rest);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
}

fn href_from_open_tag(tag: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let start = lower.find("href")?;
    let tail = tag.get(start + 4..)?.strip_prefix('=')?.trim_start();
    let value = tail;
    let value = if let Some(rest) = value.strip_prefix('"') {
        rest.split_once('"')?.0
    } else if let Some(rest) = value.strip_prefix('\'') {
        rest.split_once('\'')?.0
    } else {
        value.split_once('>').map_or(value, |(v, _)| v).trim_end()
    };
    Some(decode_basic_entities(value))
}

fn anchor_display(html: &str, open_end: usize) -> String {
    let lower = html.to_ascii_lowercase();
    let close = lower[open_end..]
        .find("</a")
        .map(|i| open_end + i)
        .unwrap_or_else(|| {
            open_end.saturating_add(MAX_DISPLAY_CHARS.min(html.len().saturating_sub(open_end)))
        });
    strip_tags(html.get(open_end..close).unwrap_or_default())
}

fn inspect_url(raw: &str, display: Option<&str>) -> LinkRiskEvidence {
    let mut out = LinkRiskEvidence::default();
    let raw = raw.trim().chars().take(MAX_URL_CHARS).collect::<String>();
    let Ok(url) = Url::parse(&raw) else {
        return out;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return out;
    }

    if !url.username().is_empty() || url.password().is_some() {
        raise_to(&mut out, LinkRisk::Failed);
        push_reason(&mut out, LinkRiskReason::CredentialsInUrl);
    }
    if url.scheme().eq_ignore_ascii_case("http") {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::InsecureHttp);
    }

    let authority = raw_authority(&raw);
    let host_part = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if !host_part.is_ascii() {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::UnicodeHost);
    }
    let Some(host) = host_shape(&url) else {
        return out;
    };
    if matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))) {
        raise_to(&mut out, LinkRisk::Failed);
        push_reason(&mut out, LinkRiskReason::IpLiteralHost);
    }
    if is_shortener(&host) {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::KnownShortener);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() > MAX_SUBDOMAINS + 1 {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::ExcessiveSubdomains);
    }
    if host.matches('-').count() >= MAX_HYPHENS {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::ExcessiveHyphens);
    }
    if labels.iter().any(|label| label.starts_with("xn--")) {
        raise_to(&mut out, LinkRisk::Noted);
        push_reason(&mut out, LinkRiskReason::PunycodeHost);
    }
    if let Some(display) = display.map(strip_tags) {
        let shown = display_domains(&display);
        if !shown.is_empty() && shown.iter().all(|domain| !domain_related(domain, &host)) {
            raise_to(&mut out, LinkRisk::Failed);
            push_reason(&mut out, LinkRiskReason::DisplayDomainMismatch);
        }
    }
    out
}

fn inspect_plain_text(text: &str, out: &mut LinkRiskEvidence) {
    let bounded = text.chars().take(MAX_BODY_SCAN_BYTES).collect::<String>();
    let lower = bounded.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut seen = 0usize;
    while seen < MAX_LINKS {
        let Some(scheme) = ["http://", "https://"]
            .into_iter()
            .filter_map(|s| lower[cursor..].find(s).map(|i| (i, s.len())))
            .min_by_key(|(i, _)| *i)
        else {
            break;
        };
        let start = cursor + scheme.0;
        let end = bounded[start..]
            .find(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"')
            .map(|i| start + i)
            .unwrap_or(bounded.len());
        let raw = bounded
            .get(start..end)
            .unwrap_or_default()
            .trim_end_matches(['.', ',', ';', ':', ')', ']']);
        out.merge(inspect_url(raw, None));
        cursor = end.max(start + 1);
        seen += 1;
    }
}

fn inspect_html(html: &str, out: &mut LinkRiskEvidence) {
    let bounded = html.chars().take(MAX_BODY_SCAN_BYTES).collect::<String>();
    let lower = bounded.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut seen = 0usize;
    while seen < MAX_LINKS {
        let Some(relative) = lower[cursor..].find("<a") else {
            break;
        };
        let start = cursor + relative;
        let Some(gt_offset) = bounded[start..].find('>') else {
            break;
        };
        let open_end = start + gt_offset + 1;
        let tag = &bounded[start..open_end];
        if let Some(href) = href_from_open_tag(tag) {
            let display = anchor_display(&bounded, open_end);
            out.merge(inspect_url(&href, Some(&display)));
            seen += 1;
        }
        cursor = open_end;
    }
}

/// Aggregate bounded URL evidence from parsed plain text and HTML bodies.
#[must_use]
pub fn inspect_bodies(text: Option<&str>, html: Option<&str>) -> LinkRiskEvidence {
    let mut out = LinkRiskEvidence::default();
    if let Some(text) = text {
        inspect_plain_text(text, &mut out);
    }
    if let Some(html) = html {
        inspect_html(html, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(url: &str) -> LinkRiskEvidence {
        inspect_bodies(Some(url), None)
    }

    #[test]
    fn ip_literals_and_credentials_fail() {
        for url in [
            "http://1.2.3.4/login",
            "https://[2001:db8::1]/login",
            "https://user@safe.example/",
            "https://user:password@safe.example/",
        ] {
            assert_eq!(one(url).risk, LinkRisk::Failed, "url {url}");
        }
        assert!(
            one("http://1.2.3.4/")
                .reasons
                .contains(&LinkRiskReason::IpLiteralHost)
        );
        assert!(
            one("https://user@safe.example/")
                .reasons
                .contains(&LinkRiskReason::CredentialsInUrl)
        );
    }

    #[test]
    fn display_domain_mismatch_fails_but_related_domain_is_clean() {
        let tag = r#"<a href="https://evil.example/login">"#;
        assert_eq!(
            href_from_open_tag(tag).as_deref(),
            Some("https://evil.example/login")
        );
        assert_eq!(anchor_display(tag, tag.len()), "");
        let mismatch = inspect_bodies(
            None,
            Some(r#"<a href="https://evil.example/login">Verify secure-bank.example</a>"#),
        );
        assert_eq!(mismatch.risk, LinkRisk::Failed);
        assert!(
            mismatch
                .reasons
                .contains(&LinkRiskReason::DisplayDomainMismatch)
        );
        let related = inspect_bodies(
            None,
            Some(r#"<a href="https://login.secure-bank.example/">secure-bank.example</a>"#),
        );
        assert_eq!(related.risk, LinkRisk::Clean);
    }

    #[test]
    fn noted_signals_never_escalate_without_clear_failure() {
        let cases = [
            ("http://safe.example/", LinkRiskReason::InsecureHttp),
            ("https://bit.ly/abc", LinkRiskReason::KnownShortener),
            (
                "https://a.b.c.d.e.example/",
                LinkRiskReason::ExcessiveSubdomains,
            ),
            (
                "https://a-b-c-d-e.example/",
                LinkRiskReason::ExcessiveHyphens,
            ),
            (
                "https://xn--bcher-kva.example/",
                LinkRiskReason::PunycodeHost,
            ),
        ];
        for (url, reason) in cases {
            let got = one(url);
            assert_eq!(got.risk, LinkRisk::Noted, "url {url}");
            assert!(got.reasons.contains(&reason), "url {url}");
        }
    }

    #[test]
    fn unicode_case_html_entity_and_worst_link_aggregation() {
        let unicode = one("https://bücher.example/path");
        assert_eq!(unicode.risk, LinkRisk::Noted);
        assert!(unicode.reasons.contains(&LinkRiskReason::UnicodeHost));
        assert!(unicode.reasons.contains(&LinkRiskReason::PunycodeHost));

        let case = inspect_bodies(
            Some("HTTPS://SAFE.EXAMPLE/"),
            Some(r#"<A HREF="HTTPS://EVIL.EXAMPLE/"> SAFE.EXAMPLE </A>"#),
        );
        assert_eq!(case.risk, LinkRisk::Failed);
        assert!(
            case.reasons
                .contains(&LinkRiskReason::DisplayDomainMismatch)
        );

        let entity = inspect_bodies(
            None,
            Some(r#"<a href="https://evil.example/?a=1&amp;b=2">bank.example</a>"#),
        );
        assert_eq!(entity.risk, LinkRisk::Failed);

        let mixed = inspect_bodies(
            Some("http://safe.example/"),
            Some(r#"<a href="https://1.2.3.4/login">bank.example</a>"#),
        );
        assert_eq!(mixed.risk, LinkRisk::Failed, "worst link wins");
        assert!(mixed.reasons.contains(&LinkRiskReason::InsecureHttp));
        assert!(mixed.reasons.contains(&LinkRiskReason::IpLiteralHost));
    }

    #[test]
    fn clean_malformed_nonweb_and_bounded_inputs() {
        assert_eq!(inspect_bodies(None, None).risk, LinkRisk::Clean);
        assert_eq!(one("https://safe.example/path?q=1").risk, LinkRisk::Clean);
        assert_eq!(one("mailto:user@example.com").risk, LinkRisk::Clean);
        assert_eq!(one("not a url https://").risk, LinkRisk::Clean);
        let many = "https://safe.example/ ".repeat(MAX_LINKS + 50);
        assert_eq!(one(&many).risk, LinkRisk::Clean);
    }

    #[test]
    fn wire_vocabulary_is_bounded() {
        assert_eq!(LinkRisk::Clean.as_str(), "clean");
        assert_eq!(LinkRisk::Noted.as_str(), "noted");
        assert_eq!(LinkRisk::Failed.as_str(), "failed");
        assert_eq!(LinkRisk::from_wire("clean"), LinkRisk::Clean);
        assert_eq!(LinkRisk::from_wire("noted"), LinkRisk::Noted);
        assert_eq!(LinkRisk::from_wire("failed"), LinkRisk::Failed);
        assert_eq!(LinkRisk::from_wire("future"), LinkRisk::Noted);
    }
}
