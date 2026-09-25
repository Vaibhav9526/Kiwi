//! Deterministic email categorization (T-201 / F2): tab assignment for
//! Primary / Newsletters / Social / Notifications / Other.
//!
//! Rules are **headers-only** and evaluated in a fixed precedence order —
//! first match wins, so classification is a pure function of the message:
//! no network, no clock, no AI. Every result carries a `reason` string that
//! cites the exact header (and rule) that fired, so the UI can explain any
//! tab assignment without asking a model.
//!
//! Precedence (documented here and locked by tests):
//! 1. `Auto-Submitted` other than `no` → Notifications (machine-generated).
//! 2. From-domain is a known social network → Social (checked before list
//!    headers: social digests carry `List-Unsubscribe` but belong in Social).
//! 3. `Precedence: bulk|list|junk` → Newsletters.
//! 4. Any `List-*` header (`List-Unsubscribe`, `List-Id`, …) → Newsletters.
//! 5. `X-Mailer`/`User-Agent` matching a known bulk sender → Newsletters.
//! 6. No-reply-style sender or `X-Auto-Response-Suppress` → Notifications.
//! 7. Other ESP/automation fingerprints (`X-SMTPAPI`, `X-Campaign-*`, …)
//!    without list evidence → Other. Deliberately NOT Newsletters: these
//!    headers also appear on transactional mail (receipts, password
//!    resets), and guessing wrong there is worse than abstaining.
//! 8. Fallback → Primary. An `X-Mailer` matching a personal MUA is cited
//!    as supporting evidence; otherwise the reason states the absence of
//!    bulk/automation signals.
//!
//! Only the From address is consulted (never display names, subjects, or
//! bodies). `categorize` degrades gracefully: a message with no headers at
//! all (e.g. IMAP ENVELOPE-only metadata) still gets domain-based rules.

use crate::mime::ParsedMessage;

/// Inbox tab assignment. Stored in SQLite as [`Category::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Category {
    /// Human mail: no bulk/automation signals.
    #[default]
    Primary,
    /// Mailing lists, promos, digests with bulk evidence.
    Newsletters,
    /// Mail from known social networks.
    Social,
    /// Machine-generated notices (auto-submitted, no-reply senders).
    Notifications,
    /// Automated mail matching no other tab.
    Other,
}

impl Category {
    /// Stable SQLite/API slug. Never rename without a migration.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Primary => "primary",
            Category::Newsletters => "newsletters",
            Category::Social => "social",
            Category::Notifications => "notifications",
            Category::Other => "other",
        }
    }

    /// Parse a stored slug. Unknown values → `None` (callers fall back to
    /// `Primary` so a future category never breaks old reads).
    pub fn from_slug(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "primary" => Some(Category::Primary),
            "newsletters" => Some(Category::Newsletters),
            "social" => Some(Category::Social),
            "notifications" => Some(Category::Notifications),
            "other" => Some(Category::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classification result: the tab plus the human-readable evidence string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub category: Category,
    pub reason: String,
}

/// Sender domains treated as social networks (suffix match: subdomains
/// like `mail.linkedin.com` match `linkedin.com`).
const SOCIAL_DOMAINS: &[&str] = &[
    "facebook.com",
    "fb.com",
    "instagram.com",
    "threads.net",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "pinterest.com",
    "tiktok.com",
    "snapchat.com",
    "reddit.com",
    "discord.com",
    "tumblr.com",
    "nextdoor.com",
];

/// Local-parts that mark a sender as notification-only.
const NOREPLY_LOCALS: &[&str] = &[
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "do_not_reply",
    "notify",
    "notification",
    "notifications",
    "alert",
    "alerts",
];

/// Substrings (lowercase) of `X-Mailer`/`User-Agent` values that identify
/// bulk senders. Corporate MTAs (Exchange, Postfix, …) are deliberately
/// absent: they carry personal mail too.
const BULK_MAILERS: &[&str] = &[
    "mailchimp",
    "mandrill",
    "sendgrid",
    "sendinblue",
    "brevo",
    "constantcontact",
    "campaignmonitor",
    "marketo",
    "hubspot",
    "salesforce",
    "exacttarget",
    "pardot",
    "braze",
    "iterable",
    "klaviyo",
    "mailgun",
    "sparkpost",
    "amazonses",
    "mailjet",
    "getresponse",
    "aweber",
    "convertkit",
    "activecampaign",
    "mailerlite",
    "benchmarkemail",
    "verticalresponse",
    "icontact",
    "emma",
    "dotdigital",
    "sendpulse",
    "drip",
];

/// Substrings (lowercase) identifying personal mail clients. Cited as
/// supporting evidence for Primary — never decisive on their own.
const PERSONAL_MUAS: &[&str] = &[
    "thunderbird",
    "apple mail",
    "outlook",
    "em client",
    "postbox",
    "fairmail",
    "k-9",
    "bluemail",
    "blue mail",
    "canary",
    "spark",
    "airmail",
    "polymail",
    "mutt",
    "gnus",
    "evolution",
    "kmail",
    "claws",
    "sylpheed",
    "the bat",
    "nine",
    "mailspring",
];

/// Header-name prefixes (lowercase) that fingerprint ESP/automation
/// transport without proving bulk intent → Other (rule 7).
const AUTOMATION_PREFIXES: &[&str] = &[
    "x-campaign",
    "x-bulk",
    "x-mailing-list",
    "x-newsletter",
    "x-autorespond",
    "x-feedback",
    "x-complaints",
    "x-smtpapi",
    "x-sg-",
    "x-mc-",
    "x-mailgun",
    "x-bravo",
    "x-ses-",
    "x-msys",
    "x-csa-",
];

/// Classify a parsed message. Pure function of `from` + `headers`.
pub fn categorize(msg: &ParsedMessage) -> Classification {
    // Rule 1: explicit machine-generated marker.
    if let Some(v) = header(msg, "auto-submitted") {
        let v = v.trim().to_lowercase();
        if !v.is_empty() && v != "no" {
            return Classification {
                category: Category::Notifications,
                reason: format!(
                    "auto-submitted '{v}' marks machine-generated mail → notifications"
                ),
            };
        }
    }

    let from = msg.from.first().map(|a| a.email.as_str()).unwrap_or("");
    let (local, domain) = split_addr(from);

    // Rule 2: social sender domain (before list headers — social digests
    // carry List-Unsubscribe).
    if let Some(pattern) = SOCIAL_DOMAINS.iter().find(|p| domain_matches(&domain, p)) {
        return Classification {
            category: Category::Social,
            reason: format!("from domain '{domain}' matches social sender '{pattern}' → social"),
        };
    }

    // Rule 3: bulk precedence.
    if let Some(v) = header(msg, "precedence") {
        let first = v.split_whitespace().next().unwrap_or("").to_lowercase();
        if matches!(first.as_str(), "bulk" | "list" | "junk") {
            return Classification {
                category: Category::Newsletters,
                reason: format!("precedence '{first}' marks bulk mail → newsletters"),
            };
        }
    }

    // Rule 4: any mailing-list header.
    if let Some(name) = msg
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .find(|n| n.starts_with("list-"))
    {
        return Classification {
            category: Category::Newsletters,
            reason: format!("{name} present → newsletters"),
        };
    }

    // Rule 5: bulk mailer fingerprint in X-Mailer / User-Agent.
    for name in ["x-mailer", "user-agent"] {
        if let Some(v) = header(msg, name)
            && let Some(hit) = BULK_MAILERS.iter().find(|b| v.to_lowercase().contains(*b))
        {
            return Classification {
                category: Category::Newsletters,
                reason: format!(
                    "{name} '{v}' matches bulk mailer '{hit}' → newsletters",
                    v = truncate(v, 80)
                ),
            };
        }
    }

    // Rule 6: notification senders.
    if NOREPLY_LOCALS.iter().any(|n| local == *n) {
        return Classification {
            category: Category::Notifications,
            reason: format!("from '{from}' is a no-reply sender → notifications"),
        };
    }
    if has_header(msg, "x-auto-response-suppress") {
        return Classification {
            category: Category::Notifications,
            reason: "x-auto-response-suppress present → notifications".into(),
        };
    }

    // Rule 7: other automation fingerprints — automated, but no tab claims it.
    if let Some(name) = msg
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .find(|n| AUTOMATION_PREFIXES.iter().any(|p| n.starts_with(p)))
    {
        return Classification {
            category: Category::Other,
            reason: format!("automation header '{name}' without list evidence → other"),
        };
    }

    // Rule 8: default. Cite a personal MUA when visible.
    for name in ["x-mailer", "user-agent"] {
        if let Some(v) = header(msg, name)
            && PERSONAL_MUAS.iter().any(|m| v.to_lowercase().contains(m))
        {
            return Classification {
                category: Category::Primary,
                reason: format!(
                    "no bulk/automation signals; {name} '{v}' looks like a personal mail client → primary",
                    v = truncate(v, 80)
                ),
            };
        }
    }
    Classification {
        category: Category::Primary,
        reason: "no bulk/automation signals → primary".into(),
    }
}

/// First value for a (lowercased) header name, if present.
fn header<'a>(msg: &'a ParsedMessage, name: &str) -> Option<&'a str> {
    msg.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Presence check for a (lowercased) header name.
fn has_header(msg: &ParsedMessage, name: &str) -> bool {
    header(msg, name).is_some()
}

/// Split `local@domain`; returns lowercase `(local, domain)` (`""` halves
/// when malformed — never panics on hostile input).
fn split_addr(addr: &str) -> (String, String) {
    match addr.rsplit_once('@') {
        Some((l, d)) => (
            l.trim().to_lowercase(),
            d.trim().trim_end_matches('.').to_lowercase(),
        ),
        None => (String::new(), String::new()),
    }
}

/// Suffix match on dot boundaries: `mail.linkedin.com` matches
/// `linkedin.com`; `fakelinkedin.com` does not.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    !domain.is_empty() && (domain == pattern || domain.ends_with(&format!(".{pattern}")))
}

/// Shorten long header values for reason strings (char-boundary safe).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime::{Addr, parse_message};

    /// Build a classifiable message from a raw header block.
    fn parsed(raw_headers: &str) -> ParsedMessage {
        let raw = format!("{raw_headers}\r\n\r\nbody\r\n");
        parse_message(raw.as_bytes()).unwrap()
    }

    fn personal() -> ParsedMessage {
        parsed(
            "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: hi\r\nX-Mailer: Thunderbird 128",
        )
    }

    #[test]
    fn slugs_roundtrip_and_reject_unknown() {
        for c in [
            Category::Primary,
            Category::Newsletters,
            Category::Social,
            Category::Notifications,
            Category::Other,
        ] {
            assert_eq!(Category::from_slug(c.as_str()), Some(c));
        }
        assert_eq!(Category::from_slug("PRIMARY"), Some(Category::Primary));
        assert_eq!(Category::from_slug("  social "), Some(Category::Social));
        assert_eq!(Category::from_slug("spam"), None);
        assert_eq!(Category::from_slug(""), None);
        assert_eq!(Category::default(), Category::Primary);
    }

    #[test]
    fn personal_mail_is_primary_with_mua_evidence() {
        let c = categorize(&personal());
        assert_eq!(c.category, Category::Primary);
        // Reason preserves the header's original case — compare folded.
        let reason = c.reason.to_lowercase();
        assert!(reason.contains("thunderbird"), "reason: {}", c.reason);
        assert!(
            reason.contains("personal mail client"),
            "reason: {}",
            c.reason
        );
    }

    #[test]
    fn bare_mail_without_signals_is_primary() {
        let c = categorize(&parsed("From: a@example.com\r\nSubject: s"));
        assert_eq!(c.category, Category::Primary);
        assert!(
            c.reason.contains("no bulk/automation signals"),
            "{}",
            c.reason
        );
    }

    #[test]
    fn list_unsubscribe_is_newsletters() {
        let c = categorize(&parsed(
            "From: deals@shop.example\r\nSubject: sale\r\nList-Unsubscribe: <https://shop.example/unsub>",
        ));
        assert_eq!(c.category, Category::Newsletters);
        assert!(c.reason.contains("list-unsubscribe"), "{}", c.reason);
    }

    #[test]
    fn precedence_bulk_is_newsletters() {
        let c = categorize(&parsed(
            "From: news@example.com\r\nSubject: digest\r\nPrecedence: bulk",
        ));
        assert_eq!(c.category, Category::Newsletters);
        assert!(c.reason.contains("precedence"), "{}", c.reason);
    }

    #[test]
    fn bulk_mailer_x_mailer_is_newsletters() {
        let c = categorize(&parsed(
            "From: hello@brand.example\r\nSubject: news\r\nX-Mailer: Mailchimp Mailer",
        ));
        assert_eq!(c.category, Category::Newsletters);
        assert!(c.reason.contains("mailchimp"), "{}", c.reason);
    }

    #[test]
    fn social_domain_wins_over_list_headers() {
        // LinkedIn digests carry List-Unsubscribe but belong in Social.
        let c = categorize(&parsed(
            "From: jobs@mail.linkedin.com\r\nSubject: jobs\r\nList-Unsubscribe: <https://linkedin.com/unsub>\r\nPrecedence: bulk",
        ));
        assert_eq!(c.category, Category::Social);
        assert!(c.reason.contains("linkedin.com"), "{}", c.reason);
    }

    #[test]
    fn social_match_is_suffix_bounded_and_case_insensitive() {
        let c = categorize(&parsed("From: n@MAIL.X.COM\r\nSubject: s"));
        assert_eq!(c.category, Category::Social);
        // fakex.com must NOT match x.com.
        let c = categorize(&parsed("From: n@fakex.com\r\nSubject: s"));
        assert_eq!(c.category, Category::Primary);
    }

    #[test]
    fn auto_submitted_wins_over_everything() {
        let c = categorize(&parsed(
            "From: jobs@mail.linkedin.com\r\nSubject: ooo\r\nList-Unsubscribe: <https://x.example/u>\r\nAuto-Submitted: auto-replied",
        ));
        assert_eq!(c.category, Category::Notifications);
        assert!(c.reason.contains("auto-submitted"), "{}", c.reason);
    }

    #[test]
    fn auto_submitted_no_is_not_automation() {
        let c = categorize(&parsed(
            "From: a@example.com\r\nSubject: s\r\nAuto-Submitted: no",
        ));
        assert_eq!(c.category, Category::Primary);
    }

    #[test]
    fn noreply_sender_is_notifications() {
        let c = categorize(&parsed(
            "From: \"Shop\" <noreply@shop.example>\r\nSubject: receipt",
        ));
        assert_eq!(c.category, Category::Notifications);
        assert!(c.reason.contains("no-reply"), "{}", c.reason);
    }

    #[test]
    fn bulk_mailer_evidence_beats_noreply() {
        // A Mailchimp campaign from a no-reply address is still a newsletter.
        let c = categorize(&parsed(
            "From: noreply@brand.example\r\nSubject: sale\r\nX-Mailer: sendgrid",
        ));
        assert_eq!(c.category, Category::Newsletters);
    }

    #[test]
    fn automation_fingerprint_without_list_evidence_is_other() {
        let c = categorize(&parsed(
            "From: orders@shop.example\r\nSubject: receipt\r\nX-SMTPAPI: {\"cat\":\"r\"}",
        ));
        assert_eq!(c.category, Category::Other);
        assert!(c.reason.contains("x-smtpapi"), "{}", c.reason);
    }

    #[test]
    fn x_auto_response_suppress_is_notifications() {
        let c = categorize(&parsed(
            "From: sys@example.com\r\nSubject: notice\r\nX-Auto-Response-Suppress: OOF",
        ));
        assert_eq!(c.category, Category::Notifications);
    }

    #[test]
    fn empty_message_defaults_primary() {
        let c = categorize(&ParsedMessage::default());
        assert_eq!(c.category, Category::Primary);
    }

    #[test]
    fn long_x_mailer_value_truncated_in_reason() {
        let long = format!("Mailchimp {}", "x".repeat(200));
        let c = categorize(&parsed(&format!(
            "From: a@b.example\r\nSubject: s\r\nX-Mailer: {long}"
        )));
        assert_eq!(c.category, Category::Newsletters);
        assert!(c.reason.contains('…'), "{}", c.reason);
    }

    #[test]
    fn classification_is_deterministic() {
        let m = parsed(
            "From: deals@shop.example\r\nSubject: s\r\nList-Unsubscribe: <https://x.example/u>",
        );
        assert_eq!(categorize(&m), categorize(&m));
    }

    #[test]
    fn domain_split_rejects_hostile_input() {
        assert_eq!(split_addr("no-at-sign"), (String::new(), String::new()));
        assert_eq!(split_addr("a@b@c."), ("a@b".to_string(), "c".to_string()));
        assert!(!domain_matches("", "x.com"));
        assert!(!domain_matches("notx.com", "x.com"));
        assert!(domain_matches("a.b.x.com", "x.com"));
    }

    #[test]
    fn envelope_only_still_gets_domain_rules() {
        // IMAP metadata ingest has envelope From but no headers: domain
        // rules (social / no-reply) must still fire; list rules degrade to
        // Primary until the body arrives and refines the category.
        let m = ParsedMessage {
            from: vec![Addr {
                name: None,
                email: "user@reddit.com".into(),
            }],
            ..Default::default()
        };
        assert_eq!(categorize(&m).category, Category::Social);

        let m = ParsedMessage {
            from: vec![Addr {
                name: None,
                email: "billing+noreply@shop.example".into(),
            }],
            ..Default::default()
        };
        // "billing+noreply" is not an exact no-reply local-part → Primary.
        assert_eq!(categorize(&m).category, Category::Primary);
    }
}
