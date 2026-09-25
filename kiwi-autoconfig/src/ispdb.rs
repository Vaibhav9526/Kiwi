//! Stage 1 — ISPDB-style fixture table: known providers, fully offline.
//!
//! Facts about *public* provider endpoints only (hostnames, ports, socket
//! security, credential kind). No secrets, no per-user data. A hit here
//! short-circuits the network: discovery works with zero connectivity for
//! every provider listed in [`ISPDB_FIXTURES`].

use crate::DomainName;
use crate::suggest::{
    AccountSuggestion, AuthKind, IncomingKind, IncomingSuggestion, OutgoingSuggestion,
    SuggestionSource,
};
use kiwi_mail::transport::SocketSecurity;

/// One fixture provider: one IMAP + one SMTP endpoint (POP3 optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IspdbEntry {
    /// Human-readable provider name (also used as display-name seed).
    pub provider: &'static str,
    /// Domains served (lowercase; validated at lookup).
    pub domains: &'static [&'static str],
    /// Primary IMAP endpoint `(host, port, security)`.
    pub imap: (&'static str, u16, SocketSecurity),
    /// Optional POP3 endpoint.
    pub pop3: Option<(&'static str, u16, SocketSecurity)>,
    /// SMTP submission endpoint.
    pub smtp: (&'static str, u16, SocketSecurity),
    /// Credential kind the provider expects by default.
    pub auth: AuthKind,
}

impl IspdbEntry {
    /// Build an [`AccountSuggestion`] for `email` (IMAP preferred; POP3
    /// only when the entry publishes no IMAP — kept for table growth).
    #[must_use]
    pub fn to_suggestion(&self, email: &str) -> Option<AccountSuggestion> {
        let (local, domain) = crate::split_email(email).ok()?;
        let username = format!("{local}@{}", domain.as_str());
        let (kind, host, port, security) = if self.imap.0.is_empty() {
            let (h, p, s) = self.pop3?;
            (IncomingKind::Pop3, h, p, s)
        } else {
            let (h, p, s) = self.imap;
            (IncomingKind::Imap, h, p, s)
        };
        AccountSuggestion {
            source: SuggestionSource::Ispdb,
            email: username.clone(),
            display_name: self.provider.to_string(),
            incoming: IncomingSuggestion {
                kind,
                host: host.to_string(),
                port,
                security,
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

/// Bundled fixture table. Endpoints are published provider facts; the
/// table is data, not policy — apps may pass their own slice to
/// [`crate::discover_with_table`].
pub const ISPDB_FIXTURES: &[IspdbEntry] = &[
    IspdbEntry {
        provider: "Google",
        domains: &["gmail.com", "googlemail.com"],
        imap: ("imap.gmail.com", 993, SocketSecurity::ImplicitTls),
        pop3: Some(("pop.gmail.com", 995, SocketSecurity::ImplicitTls)),
        smtp: ("smtp.gmail.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
    IspdbEntry {
        provider: "Microsoft 365",
        domains: &["outlook.com", "hotmail.com", "live.com", "msn.com"],
        imap: ("outlook.office365.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.office365.com", 587, SocketSecurity::StartTls),
        auth: AuthKind::XOAuth2,
    },
    IspdbEntry {
        provider: "Yahoo",
        domains: &["yahoo.com", "ymail.com"],
        imap: ("imap.mail.yahoo.com", 993, SocketSecurity::ImplicitTls),
        pop3: Some(("pop.mail.yahoo.com", 995, SocketSecurity::ImplicitTls)),
        smtp: ("smtp.mail.yahoo.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
    IspdbEntry {
        provider: "iCloud",
        domains: &["icloud.com", "me.com", "mac.com"],
        imap: ("imap.mail.me.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.mail.me.com", 587, SocketSecurity::StartTls),
        auth: AuthKind::Password,
    },
    IspdbEntry {
        provider: "Fastmail",
        domains: &["fastmail.com", "fastmail.fm"],
        imap: ("imap.fastmail.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.fastmail.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    IspdbEntry {
        provider: "Zoho",
        domains: &["zoho.com", "zohomail.com"],
        imap: ("imap.zoho.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.zoho.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    IspdbEntry {
        provider: "GMX",
        domains: &["gmx.com", "gmx.net", "gmx.de"],
        imap: ("imap.gmx.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("mail.gmx.com", 587, SocketSecurity::StartTls),
        auth: AuthKind::Password,
    },
    IspdbEntry {
        provider: "Yandex",
        domains: &["yandex.com", "ya.ru"],
        imap: ("imap.yandex.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.yandex.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::Password,
    },
    IspdbEntry {
        provider: "AOL",
        domains: &["aol.com"],
        imap: ("imap.aol.com", 993, SocketSecurity::ImplicitTls),
        pop3: None,
        smtp: ("smtp.aol.com", 465, SocketSecurity::ImplicitTls),
        auth: AuthKind::XOAuth2,
    },
];

/// Exact-domain lookup in `table`, then parent-domain (subdomain) lookup.
/// Deterministic: table order; exact matches always win.
#[must_use]
pub fn lookup_in<'a>(table: &'a [IspdbEntry], domain: &DomainName) -> Option<&'a IspdbEntry> {
    let matches = |e: &&IspdbEntry| {
        e.domains
            .iter()
            .any(|d| DomainName::parse(d).is_ok_and(|x| x == *domain))
    };
    let suffix = |e: &&IspdbEntry| {
        e.domains.iter().any(|d| {
            DomainName::parse(d).is_ok_and(|x| {
                domain.as_str() == x.as_str()
                    || domain.as_str().ends_with(&format!(".{}", x.as_str()))
            })
        })
    };
    table
        .iter()
        .find(matches)
        .or_else(|| table.iter().find(suffix))
}

/// Look up the bundled fixture table for an address.
#[must_use]
pub fn lookup_email(email: &str) -> Option<AccountSuggestion> {
    let (_local, domain) = crate::split_email(email).ok()?;
    lookup_in(ISPDB_FIXTURES, &domain)?.to_suggestion(email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::SuggestionSource;

    #[test]
    fn fixture_google_lookup() {
        let s = lookup_email("someone@gmail.com").expect("gmail fixture");
        assert_eq!(s.source, SuggestionSource::Ispdb);
        assert_eq!(s.display_name, "Google");
        assert_eq!(s.incoming.host, "imap.gmail.com");
        assert_eq!(s.incoming.port, 993);
        assert_eq!(s.incoming.security, SocketSecurity::ImplicitTls);
        assert_eq!(s.incoming.auth, AuthKind::XOAuth2);
        assert_eq!(s.incoming.username, "someone@gmail.com");
        assert_eq!(s.outgoing.host, "smtp.gmail.com");
        assert_eq!(s.email, "someone@gmail.com");
    }

    #[test]
    fn fixture_lookup_is_case_and_subdomain_tolerant() {
        assert!(lookup_email("User@GOOGLEMAIL.com").is_some());
        let d = DomainName::parse("mail.mycompany.example.test").unwrap();
        let table = [IspdbEntry {
            provider: "T",
            domains: &["example.test"],
            imap: ("imap.t.test", 993, SocketSecurity::ImplicitTls),
            pop3: None,
            smtp: ("smtp.t.test", 587, SocketSecurity::StartTls),
            auth: AuthKind::Password,
        }];
        assert!(
            lookup_in(&table, &d).is_some(),
            "suffix match on parent domain"
        );
        // Exact match still wins over a later suffix match.
        let exact = DomainName::parse("example.test").unwrap();
        assert_eq!(lookup_in(&table, &exact).unwrap().provider, "T");
    }

    #[test]
    fn lookup_misses_unknown_domain() {
        assert!(lookup_email("nobody@unknown.invalid").is_none());
        let d = DomainName::parse("unknown.invalid").unwrap();
        assert!(lookup_in(ISPDB_FIXTURES, &d).is_none());
    }

    #[test]
    fn every_fixture_entry_is_wellformed() {
        // Static data sanity: hosts parse, ports non-zero, domains valid,
        // at least one incoming endpoint per entry.
        for e in ISPDB_FIXTURES {
            assert!(!e.domains.is_empty(), "{}: no domains", e.provider);
            for d in e.domains {
                assert!(
                    DomainName::parse(d).is_ok(),
                    "{}: bad domain {d}",
                    e.provider
                );
            }
            assert!(
                !e.imap.0.is_empty() || e.pop3.is_some(),
                "{}: no incoming",
                e.provider
            );
            for (host, port, _sec) in [e.imap, e.smtp].into_iter().chain(e.pop3) {
                assert!(
                    DomainName::parse(host).is_ok(),
                    "{}: bad host {host}",
                    e.provider
                );
                assert!(port > 0, "{}: zero port for {host}", e.provider);
            }
        }
    }

    #[test]
    fn custom_table_overrides_bundled() {
        let d = DomainName::parse("example.test").unwrap();
        let table = [IspdbEntry {
            provider: "LocalCorp",
            domains: &["example.test"],
            imap: ("imap.corp.test", 143, SocketSecurity::StartTls),
            pop3: None,
            smtp: ("smtp.corp.test", 25, SocketSecurity::Plaintext),
            auth: AuthKind::Password,
        }];
        let s = lookup_in(&table, &d)
            .unwrap()
            .to_suggestion("u@example.test")
            .unwrap();
        assert_eq!(s.display_name, "LocalCorp");
        assert_eq!(s.incoming.host, "imap.corp.test");
        assert_eq!(s.incoming.port, 143);
        assert_eq!(s.incoming.security, SocketSecurity::StartTls);
        assert_eq!(s.outgoing.port, 25);
        // Bundled table must NOT contain example.test (no overlap).
        assert!(lookup_in(ISPDB_FIXTURES, &d).is_none());
    }

    #[test]
    fn named_provider_fixtures_present_and_deterministic() {
        // T-178: the six named providers must be present with their
        // published facts, and lookups must be stable across runs.
        let expected = [
            ("gmail.com", "Google", "imap.gmail.com", AuthKind::XOAuth2),
            (
                "outlook.com",
                "Microsoft 365",
                "outlook.office365.com",
                AuthKind::XOAuth2,
            ),
            (
                "yahoo.com",
                "Yahoo",
                "imap.mail.yahoo.com",
                AuthKind::XOAuth2,
            ),
            (
                "icloud.com",
                "iCloud",
                "imap.mail.me.com",
                AuthKind::Password,
            ),
            ("zoho.com", "Zoho", "imap.zoho.com", AuthKind::Password),
            (
                "fastmail.com",
                "Fastmail",
                "imap.fastmail.com",
                AuthKind::Password,
            ),
        ];
        for (domain, provider, imap_host, auth) in expected {
            let d = DomainName::parse(domain).unwrap();
            let e = lookup_in(ISPDB_FIXTURES, &d)
                .unwrap_or_else(|| panic!("{provider} fixture missing"));
            assert_eq!(e.provider, provider, "{provider}: wrong entry");
            assert_eq!(e.imap.0, imap_host, "{provider}: wrong imap host");
            assert_eq!(e.imap.1, 993, "{provider}: wrong imap port");
            assert_eq!(
                e.imap.2,
                SocketSecurity::ImplicitTls,
                "{provider}: wrong security"
            );
            assert_eq!(e.auth, auth, "{provider}: wrong auth kind");
            // Deterministic: repeated suggestion builds agree exactly.
            let s1 = lookup_email(&format!("u@{domain}"));
            let s2 = lookup_email(&format!("u@{domain}"));
            assert_eq!(s1, s2, "{provider} lookup not deterministic");
        }
    }
}
