//! Stage 4 — MX-derived heuristics.
//!
//! Two deterministic strategies, in order:
//!
//! 1. **Provider hints** — the domain's MX host is matched (exact or
//!    suffix) against a table of known provider MX suffixes. Custom
//!    domains hosted by Google/Microsoft/etc. are found this way.
//! 2. **Pattern guess** — `imap.<domain>:993` / `smtp.<domain>:587`
//!    (STARTTLS). Always flagged `needs_manual_review` by discovery: it is
//!    a guess, never an assertion (no finding, no silent trust).
//!
//! MX ordering is normalized here (preference asc, then host) so the
//! outcome does not depend on resolver order.

use crate::net::MxRecord;
use crate::suggest::{
    AccountSuggestion, AuthKind, IncomingKind, IncomingSuggestion, OutgoingSuggestion,
    SuggestionSource,
};
use kiwi_mail::transport::SocketSecurity;

/// Known provider MX suffix → published endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxHint {
    /// MX hostname suffix (matched case-insensitively; label-boundary).
    pub mx_suffix: &'static str,
    /// Human-readable provider name.
    pub provider: &'static str,
    /// IMAP endpoint `(host, port, security)`.
    pub imap: (&'static str, u16, SocketSecurity),
    /// SMTP submission endpoint.
    pub smtp: (&'static str, u16, SocketSecurity),
    /// Credential kind.
    pub auth: AuthKind,
}

impl MxHint {
    /// Build an [`AccountSuggestion`] for `email` from this hint.
    #[must_use]
    pub fn to_suggestion(&self, email: &str) -> Option<AccountSuggestion> {
        let (local, domain) = crate::split_email(email).ok()?;
        let username = format!("{local}@{}", domain.as_str());
        AccountSuggestion {
            source: SuggestionSource::MxHeuristic,
            email: username.clone(),
            display_name: self.provider.to_string(),
            incoming: IncomingSuggestion {
                kind: IncomingKind::Imap,
                host: self.imap.0.to_string(),
                port: self.imap.1,
                security: self.imap.2,
                auth: self.auth,
                username: username.clone(),
            },
            outgoing: OutgoingSuggestion {
                host: self.smtp.0.to_string(),
                port: self.smtp.1,
                security: self.smtp.2,
                auth: self.auth,
                username,
            },
        }
        .checked()
    }
}

/// Bundled MX-suffix table (published provider facts; apps may supply
/// their own slice).
pub const MX_HINTS: &[MxHint] = &[
    MxHint {
        mx_suffix: "google.com",
        provider: "Google",
        imap: ("imap.gmail.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.gmail.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
    MxHint {
        mx_suffix: "googlemail.com",
        provider: "Google",
        imap: ("imap.gmail.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.gmail.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
    MxHint {
        mx_suffix: "protection.outlook.com",
        provider: "Microsoft 365",
        imap: ("outlook.office365.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.office365.com", 587, SocketSecurity::StartTls),
        auth: AuthKind::XOAuth2,
    },
    MxHint {
        mx_suffix: "yahoodns.net",
        provider: "Yahoo",
        imap: ("imap.mail.yahoo.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.mail.yahoo.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
    MxHint {
        mx_suffix: "messagingengine.com",
        provider: "Fastmail",
        imap: ("imap.fastmail.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.fastmail.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    MxHint {
        mx_suffix: "zoho.com",
        provider: "Zoho",
        imap: ("imap.zoho.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.zoho.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    MxHint {
        mx_suffix: "gmx.net",
        provider: "GMX",
        imap: ("imap.gmx.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("mail.gmx.com", 587, SocketSecurity::StartTls),
        auth: AuthKind::Password,
    },
    MxHint {
        mx_suffix: "yandex.net",
        provider: "Yandex",
        imap: ("imap.yandex.com", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtp.yandex.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    MxHint {
        mx_suffix: "secureserver.net",
        provider: "GoDaddy",
        imap: ("imap.secureserver.net", 993, SocketSecurity::ImplicitTls),
        smtp: ("smtpout.secureserver.net", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
];

/// MX hosts in deterministic order: preference ascending, then hostname.
#[must_use]
pub fn sorted_mx(mx: &[MxRecord]) -> Vec<MxRecord> {
    let mut v: Vec<MxRecord> = mx.iter().take(crate::MAX_CANDIDATES).cloned().collect();
    v.sort_by(|a, b| {
        a.preference
            .cmp(&b.preference)
            .then_with(|| a.host.cmp(&b.host))
    });
    v
}

/// Match one MX host against `table` (exact or label-boundary suffix).
#[must_use]
pub fn hint_for_host<'a>(table: &'a [MxHint], host: &str) -> Option<&'a MxHint> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    table
        .iter()
        .find(|hint| h == hint.mx_suffix || h.ends_with(&format!(".{}", hint.mx_suffix)))
}

/// Provider-hint guess for the domain's MX records; `None` when no MX
/// matches a known provider suffix.
#[must_use]
pub fn from_mx_with_hints(
    email: &str,
    mx: &[MxRecord],
    table: &[MxHint],
) -> Option<AccountSuggestion> {
    if crate::split_email(email).is_err() {
        return None;
    }
    sorted_mx(mx)
        .iter()
        .find_map(|r| hint_for_host(table, &r.host))
        .and_then(|hint| hint.to_suggestion(email))
}

/// [`from_mx_with_hints`] against the bundled [`MX_HINTS`] table.
#[must_use]
pub fn from_mx(email: &str, mx: &[MxRecord]) -> Option<AccountSuggestion> {
    from_mx_with_hints(email, mx, MX_HINTS)
}

/// Pattern guess: `imap.<domain>:993` (implicit TLS) + `smtp.<domain>:587`
/// (STARTTLS), password auth. A guess — discovery marks it for review.
#[must_use]
pub fn generic_guess(email: &str) -> Option<AccountSuggestion> {
    let (local, domain) = crate::split_email(email).ok()?;
    let username = format!("{local}@{}", domain.as_str());
    AccountSuggestion {
        source: SuggestionSource::MxHeuristic,
        email: username.clone(),
        display_name: local,
        incoming: IncomingSuggestion {
            kind: IncomingKind::Imap,
            host: format!("imap.{}", domain.as_str()),
            port: 993,
            security: SocketSecurity::ImplicitTls,
            auth: AuthKind::Password,
            username: username.clone(),
        },
        outgoing: OutgoingSuggestion {
            host: format!("smtp.{}", domain.as_str()),
            port: 587,
            security: SocketSecurity::StartTls,
            auth: AuthKind::Password,
            username,
        },
    }
    .checked()
}

/// Hint first, then pattern guess. Returns `(suggestion, guessed)` where
/// `guessed == true` means the pattern guess was used (needs review).
#[must_use]
pub fn guess(email: &str, mx: &[MxRecord]) -> Option<(AccountSuggestion, bool)> {
    if let Some(s) = from_mx(email, mx) {
        return Some((s, false));
    }
    generic_guess(email).map(|s| (s, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MxRecord;
    use crate::suggest::{AuthKind, IncomingKind, SuggestionSource};

    fn mx(hosts: &[(&str, u16)]) -> Vec<MxRecord> {
        hosts
            .iter()
            .map(|(h, p)| MxRecord {
                host: h.to_string(),
                preference: *p,
            })
            .collect()
    }

    #[test]
    fn sorted_mx_is_deterministic() {
        let records = mx(&[("b.mx.test", 20), ("a.mx.test", 20), ("z.mx.test", 10)]);
        let sorted = sorted_mx(&records);
        let hosts: Vec<&str> = sorted.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, vec!["z.mx.test", "a.mx.test", "b.mx.test"]);
    }

    #[test]
    fn google_mx_hint_hits() {
        let records = mx(&[("alt2.aspmx.l.google.com", 20), ("aspmx.l.google.com", 10)]);
        let s = from_mx("u@mycorp.test", &records).expect("google hint");
        assert_eq!(s.source, SuggestionSource::MxHeuristic);
        assert_eq!(s.display_name, "Google");
        assert_eq!(s.incoming.host, "imap.gmail.com");
        assert_eq!(s.incoming.auth, AuthKind::XOAuth2);
        assert_eq!(s.outgoing.port, 465);
        assert_eq!(s.incoming.username, "u@mycorp.test");
        // Lowest preference host wins the match (10 < 20, both google).
        assert_eq!(
            from_mx("u@mycorp.test", &sorted_mx(&records))
                .unwrap()
                .display_name,
            "Google"
        );
    }

    #[test]
    fn m365_mx_hint_hits() {
        let records = mx(&[("mycorp.test.mail.protection.outlook.com", 10)]);
        let s = from_mx("u@mycorp.test", &records).expect("m365 hint");
        assert_eq!(s.display_name, "Microsoft 365");
        assert_eq!(s.incoming.host, "outlook.office365.com");
    }

    #[test]
    fn suffix_match_is_label_bound() {
        // "notgoogle.com" must NOT match suffix "google.com".
        let records = mx(&[("notgoogle.com", 10)]);
        assert!(from_mx("u@x.test", &records).is_none());
        // But "sub.google.com" does.
        let records2 = mx(&[("sub.google.com", 10)]);
        assert!(from_mx("u@x.test", &records2).is_some());
    }

    #[test]
    fn generic_guess_when_no_hint() {
        let records = mx(&[("mx1.random-host.test", 10)]);
        let (s, guessed) = guess("u@random-host.test", &records).expect("pattern guess");
        assert!(guessed, "pattern guess must be flagged");
        assert_eq!(s.incoming.kind, IncomingKind::Imap);
        assert_eq!(s.incoming.host, "imap.random-host.test");
        assert_eq!(s.incoming.port, 993);
        assert_eq!(s.incoming.security, SocketSecurity::ImplicitTls);
        assert_eq!(s.incoming.auth, AuthKind::Password);
        assert_eq!(s.outgoing.host, "smtp.random-host.test");
        assert_eq!(s.outgoing.port, 587);
        assert_eq!(s.outgoing.security, SocketSecurity::StartTls);
    }

    #[test]
    fn no_mx_at_all_still_gives_pattern_guess() {
        let (s, guessed) = guess("u@bare.test", &[]).expect("pattern guess");
        assert!(guessed);
        assert_eq!(s.incoming.host, "imap.bare.test");
    }

    #[test]
    fn invalid_email_yields_nothing() {
        assert!(from_mx("not-an-email", &mx(&[("aspmx.l.google.com", 10)])).is_none());
        assert!(generic_guess("bad@@").is_none());
        assert!(guess("bad", &[]).is_none());
    }

    #[test]
    fn custom_hints_table_respected() {
        let table = [MxHint {
            mx_suffix: "owncloud.test",
            provider: "SelfHosted",
            imap: ("imap.self.test", 993, SocketSecurity::ImplicitTls),
            smtp: ("smtp.self.test", 587, SocketSecurity::StartTls),
            auth: AuthKind::Password,
        }];
        let records = mx(&[("mx.owncloud.test", 10)]);
        let s = from_mx_with_hints("u@corp.test", &records, &table).expect("custom hint");
        assert_eq!(s.display_name, "SelfHosted");
        // Bundled table has no such suffix.
        assert!(from_mx("u@corp.test", &records).is_none());
    }
}
