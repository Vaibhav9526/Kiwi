//! One-click unsubscribe parsing (T-202 / F3): RFC 2369 `List-Unsubscribe`
//! plus RFC 8058 `List-Unsubscribe-Post`.
//!
//! Deterministic and side-effect-free: this module only *parses* what the
//! sender advertised. It never fetches URLs and never sends mail — the
//! `mailto:` path is flagged consent-gated (`has_consent_gated_option`)
//! and the UI must get explicit user approval before composing anything.
//!
//! Security policy (deliberate, documented):
//! - Only `<…>`-bracketed tokens are read (RFC 2369 shape). Bare URLs
//!   outside brackets are ignored — predictable beats lenient.
//! - Only `https:` URLs are accepted. Plain-`http:` entries are dropped:
//!   unsubscribing over cleartext both leaks the action and invites
//!   redirect tampering. Legit senders overwhelmingly offer https.
//! - `mailto:` parameters (`?subject=…&body=…`) are stripped — the stored
//!   value is the bare address. Sender-controlled compose parameters must
//!   not flow into a draft unsolicited.
//! - Entries with whitespace/control characters or absurd lengths are
//!   dropped (header-injection hygiene).
//! - `List-Unsubscribe-Post` counts only when it normalizes (whitespace
//!   stripped, lowercased) to exactly `list-unsubscribe=one-click`.

/// Parsed unsubscribe offer. `None` (from [`parse_unsubscribe`]) means "no
/// actionable offer" — headers missing, or present but unparsable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnsubscribeInfo {
    /// First `https:` URL advertised. Safe default action: open it.
    pub http_url: Option<String>,
    /// First `mailto:` address advertised (parameters stripped).
    /// Composing to it REQUIRES explicit user consent — never auto-send.
    pub mailto: Option<String>,
    /// RFC 8058 one-click marker present: the URL accepts
    /// `POST List-Unsubscribe=One-Click` (no confirmation page needed).
    pub one_click: bool,
}

/// What the UI may offer. Derived from [`UnsubscribeInfo::action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsubscribeAction {
    /// No actionable offer.
    None,
    /// Open the https URL (POST when `one_click`, else GET).
    Http,
    /// Consent-gated compose to the mailto address. Never auto-send.
    Mailto,
    /// Both advertised: Http is primary, mailto is the consent-gated fallback.
    Both,
}

impl UnsubscribeInfo {
    /// Classify the offer into the UI action.
    pub fn action(&self) -> UnsubscribeAction {
        match (&self.http_url, &self.mailto) {
            (Some(_), Some(_)) => UnsubscribeAction::Both,
            (Some(_), None) => UnsubscribeAction::Http,
            (None, Some(_)) => UnsubscribeAction::Mailto,
            (None, None) => UnsubscribeAction::None,
        }
    }

    /// True when a `mailto:` option exists: using it requires explicit user
    /// consent and must never be auto-sent. (The https path needs no such
    /// gate beyond the click itself.)
    pub fn has_consent_gated_option(&self) -> bool {
        self.mailto.is_some()
    }
}

/// Bounds for advertised values (generous RFC-side caps; longer entries are
/// treated as hostile junk and dropped).
const MAX_URL_LEN: usize = 2048;
const MAX_ADDR_LEN: usize = 320;

/// Parse `List-Unsubscribe` / `List-Unsubscribe-Post` from captured headers
/// (`(lowercased-name, value)` pairs, as in `ParsedMessage::headers`).
/// First `https:` URL and first `mailto:` address win; returns `None` when
/// nothing actionable survives validation.
pub fn parse_unsubscribe(headers: &[(String, String)]) -> Option<UnsubscribeInfo> {
    let mut info = UnsubscribeInfo::default();
    for (name, value) in headers {
        if name == "list-unsubscribe" {
            for token in bracket_tokens(value) {
                if info.http_url.is_none()
                    && let Some(url) = accept_https(&token)
                {
                    info.http_url = Some(url);
                }
                if info.mailto.is_none()
                    && let Some(addr) = accept_mailto(&token)
                {
                    info.mailto = Some(addr);
                }
                if info.http_url.is_some() && info.mailto.is_some() {
                    break;
                }
            }
        } else if name == "list-unsubscribe-post" {
            let norm: String = value
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_lowercase();
            if norm == "list-unsubscribe=one-click" {
                info.one_click = true;
            }
        }
    }
    if info.http_url.is_none() && info.mailto.is_none() {
        return None;
    }
    Some(info)
}

/// Yield `<…>`-bracketed tokens in order. Text outside brackets (titles,
/// junk) is ignored.
fn bracket_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else {
            break; // unterminated bracket — stop, don't guess
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end + 1..];
    }
    out
}

/// Accept an `https:` URL token. Scheme match is case-insensitive; the rest
/// is preserved verbatim (paths can be case-sensitive). Rejects whitespace,
/// control characters, and overlong values.
fn accept_https(token: &str) -> Option<String> {
    let (scheme, _) = token.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    if token.len() > MAX_URL_LEN || token.len() < "https://x".len() {
        return None;
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    // Require a non-empty authority: `https://` plus at least one host char.
    let after = token.split_once("://").map(|(_, r)| r)?;
    if after.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Accept a `mailto:` token, returning the bare address (parameters after
/// `?` stripped). Rejects whitespace/control characters, missing `@`, and
/// overlong values. Case is preserved (local-parts may be case-sensitive).
fn accept_mailto(token: &str) -> Option<String> {
    let (scheme, rest) = token.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("mailto") {
        return None;
    }
    let addr = rest.split('?').next().unwrap_or("").trim();
    if addr.is_empty() || addr.len() > MAX_ADDR_LEN {
        return None;
    }
    if !addr.contains('@') {
        return None;
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(headers: &[(&str, &str)]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn missing_headers_yield_none() {
        assert_eq!(parse_unsubscribe(&[]), None);
        assert_eq!(parse_unsubscribe(&h(&[("subject", "hi")])), None);
    }

    #[test]
    fn https_only_offer() {
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<https://shop.example/unsub?id=1>",
        )]))
        .unwrap();
        assert_eq!(
            info.http_url.as_deref(),
            Some("https://shop.example/unsub?id=1")
        );
        assert_eq!(info.mailto, None);
        assert!(!info.one_click);
        assert_eq!(info.action(), UnsubscribeAction::Http);
        assert!(!info.has_consent_gated_option());
    }

    #[test]
    fn mailto_only_offer_is_consent_gated() {
        let info =
            parse_unsubscribe(&h(&[("list-unsubscribe", "<mailto:unsub@shop.example>")])).unwrap();
        assert_eq!(info.mailto.as_deref(), Some("unsub@shop.example"));
        assert_eq!(info.http_url, None);
        assert_eq!(info.action(), UnsubscribeAction::Mailto);
        assert!(info.has_consent_gated_option());
    }

    #[test]
    fn both_offer_prefers_http_with_mailto_fallback() {
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<mailto:u@x.example?subject=bye>, <https://x.example/u>",
        )]))
        .unwrap();
        // mailto params stripped to the bare address.
        assert_eq!(info.mailto.as_deref(), Some("u@x.example"));
        assert_eq!(info.http_url.as_deref(), Some("https://x.example/u"));
        assert_eq!(info.action(), UnsubscribeAction::Both);
        assert!(info.has_consent_gated_option());
    }

    #[test]
    fn first_of_each_kind_wins() {
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<https://a.example/1>, <https://b.example/2>",
        )]))
        .unwrap();
        assert_eq!(info.http_url.as_deref(), Some("https://a.example/1"));
        // Second header line continues the scan for still-missing kinds.
        let info = parse_unsubscribe(&h(&[
            ("list-unsubscribe", "<mailto:first@x.example>"),
            ("list-unsubscribe", "<mailto:second@x.example>"),
        ]))
        .unwrap();
        assert_eq!(info.mailto.as_deref(), Some("first@x.example"));
    }

    #[test]
    fn plain_http_and_unknown_schemes_dropped() {
        // Only an http: URL → no actionable offer.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "<http://x.example/u>")])),
            None
        );
        // http: ignored, https: kept.
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<http://x.example/a>, <https://x.example/b>",
        )]))
        .unwrap();
        assert_eq!(info.http_url.as_deref(), Some("https://x.example/b"));
        // ftp: ignored the same way.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "<ftp://x.example/f>")])),
            None
        );
    }

    #[test]
    fn malformed_values_rejected() {
        // No brackets at all.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "https://x.example/u")])),
            None
        );
        // Unterminated bracket.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "<https://x.example/u")])),
            None
        );
        // Empty brackets.
        assert_eq!(parse_unsubscribe(&h(&[("list-unsubscribe", "<>")])), None);
        // mailto without address.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "<mailto:>")])),
            None
        );
        // mailto without @.
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", "<mailto:not-an-address>")])),
            None
        );
        // CRLF injection inside a token.
        assert_eq!(
            parse_unsubscribe(&h(&[(
                "list-unsubscribe",
                "<https://x.example/a\r\nBcc: evil@x>"
            )])),
            None
        );
        // Absurd lengths dropped.
        let long = format!("<https://x.example/{}>", "y".repeat(3000));
        assert_eq!(
            parse_unsubscribe(&h(&[("list-unsubscribe", long.as_str())])),
            None
        );
    }

    #[test]
    fn rfc8058_one_click_flag() {
        let info = parse_unsubscribe(&h(&[
            ("list-unsubscribe", "<https://x.example/u>"),
            ("list-unsubscribe-post", "List-Unsubscribe=One-Click"),
        ]))
        .unwrap();
        assert!(info.one_click);
        assert_eq!(info.action(), UnsubscribeAction::Http);
        // Case + surrounding whitespace tolerated (normalized compare).
        let info = parse_unsubscribe(&h(&[
            ("list-unsubscribe", "<https://x.example/u>"),
            ("list-unsubscribe-post", "  list-unsubscribe = one-click "),
        ]))
        .unwrap();
        assert!(info.one_click);
        // Wrong value → flag stays false, URL still actionable.
        let info = parse_unsubscribe(&h(&[
            ("list-unsubscribe", "<https://x.example/u>"),
            ("list-unsubscribe-post", "List-Unsubscribe=Two-Clicks"),
        ]))
        .unwrap();
        assert!(!info.one_click);
        // Post header alone, without any offer, is not actionable.
        assert_eq!(
            parse_unsubscribe(&h(&[(
                "list-unsubscribe-post",
                "List-Unsubscribe=One-Click"
            )])),
            None
        );
    }

    #[test]
    fn scheme_case_insensitive_value_preserved() {
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<HTTPS://x.example/Path?X=1>, <MAILTO:User@X.Example>",
        )]))
        .unwrap();
        assert_eq!(info.http_url.as_deref(), Some("HTTPS://x.example/Path?X=1"));
        assert_eq!(info.mailto.as_deref(), Some("User@X.Example"));
    }

    #[test]
    fn titles_after_brackets_ignored() {
        let info = parse_unsubscribe(&h(&[(
            "list-unsubscribe",
            "<https://x.example/u> (click here to leave), <mailto:u@x.example> (by mail)",
        )]))
        .unwrap();
        assert_eq!(info.action(), UnsubscribeAction::Both);
    }

    #[test]
    fn action_none_for_empty_info() {
        assert_eq!(UnsubscribeInfo::default().action(), UnsubscribeAction::None);
        assert!(!UnsubscribeInfo::default().has_consent_gated_option());
    }

    #[test]
    fn deterministic_repeat_parse() {
        let headers = h(&[(
            "list-unsubscribe",
            "<mailto:u@x.example>, <https://x.example/u>",
        )]);
        assert_eq!(parse_unsubscribe(&headers), parse_unsubscribe(&headers));
    }
}
