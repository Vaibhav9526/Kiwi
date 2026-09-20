//! Discovery pipeline: ISPDB fixtures → `autoconfig.<domain>` →
//! `<domain>/.well-known/autoconfig` → MX heuristics → manual entry.
//!
//! Deterministic and evidence-shaped: every stage appends a
//! [`StageAttempt`] so callers (and the forensics/UI layers) can see *why*
//! a config was proposed. Invalid input is the only error; network
//! trouble, malformed documents and missing records are stage outcomes and
//! are never fatal (SECURITY.md: fail closed on trust, but a config
//! *suggestion* is never a trust decision).

use crate::autoconfig_xml::ClientConfig;
use crate::ispdb::{self, IspdbEntry};
use crate::manual::ManualEntry;
use crate::net::DiscoveryNet;
use crate::suggest::{AccountSuggestion, SuggestionSource};
use crate::{DomainName, Error, heuristics};

/// Well-known autoconfig path (Thunderbird convention).
pub const WELL_KNOWN_PATH: &str = "/.well-known/autoconfig/mail/config-v1.1.xml";
/// Autoconfig host path (Thunderbird convention).
pub const AUTOCONFIG_HOST_PATH: &str = "/mail/config-v1.1.xml";

/// How one stage ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    /// Stage produced the suggestion used.
    Hit,
    /// Stage had nothing to offer (no fixture / no MX record).
    Miss,
    /// Document could not be fetched (DNS/HTTP/timeout/size).
    Unreachable,
    /// Document was fetched but failed validation.
    Malformed,
    /// Document parsed but published nothing usable for this account.
    Unsupported,
}

impl StageOutcome {
    /// Stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Unreachable => "unreachable",
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Ordered record of one stage's result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageAttempt {
    /// Stage identifier.
    pub source: SuggestionSource,
    /// Result.
    pub outcome: StageOutcome,
    /// Short evidence text (static; ≤120 chars by construction).
    pub detail: String,
}

/// Result of a discovery run. `suggestion` is always present.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryOutcome {
    /// Address the run was performed for (normalized).
    pub email: String,
    /// Domain part (normalized).
    pub domain: String,
    /// Proposed config (source in `suggestion.source`).
    pub suggestion: AccountSuggestion,
    /// Convenience copy of `suggestion.source`.
    pub source: SuggestionSource,
    /// `true` for pattern guesses and the manual fallback — the UI must
    /// ask the user to confirm before saving.
    pub needs_manual_review: bool,
    /// Every stage tried, in order (the "why", not a finding).
    pub attempts: Vec<StageAttempt>,
}

/// Autoconfig-host URL for a domain.
#[must_use]
pub fn autoconfig_host_url(domain: &DomainName) -> String {
    format!(
        "https://autoconfig.{}{}",
        domain.as_str(),
        AUTOCONFIG_HOST_PATH
    )
}

/// Well-known autoconfig URL for a domain.
#[must_use]
pub fn well_known_url(domain: &DomainName) -> String {
    format!("https://{}{}", domain.as_str(), WELL_KNOWN_PATH)
}

/// Static, non-leaking description of an XML parse failure.
fn xml_detail(e: &Error) -> &'static str {
    match e {
        Error::TooLong => "autoconfig document exceeds size limit",
        Error::MalformedXml(why) => why,
        Error::InvalidDomain => "document references invalid domain",
        Error::InvalidEmail => "invalid address",
    }
}

/// Run discovery with the bundled ISPDB fixture table.
pub fn discover(email: &str, net: &dyn DiscoveryNet) -> Result<DiscoveryOutcome, Error> {
    discover_with_table(email, net, ispdb::ISPDB_FIXTURES)
}

/// Run discovery with a caller-supplied ISPDB table (app override / tests).
pub fn discover_with_table(
    email: &str,
    net: &dyn DiscoveryNet,
    table: &[IspdbEntry],
) -> Result<DiscoveryOutcome, Error> {
    let (local, domain) = crate::split_email(email)?;
    let email_norm = format!("{local}@{}", domain.as_str());
    let mut attempts: Vec<StageAttempt> = Vec::new();
    let mut hit: Option<(AccountSuggestion, bool)> = None;

    // 1. ISPDB-style fixtures (offline, no network).
    match ispdb::lookup_in(table, &domain).and_then(|e| e.to_suggestion(&email_norm)) {
        Some(s) => {
            attempts.push(StageAttempt {
                source: SuggestionSource::Ispdb,
                outcome: StageOutcome::Hit,
                detail: "matched bundled ISPDB fixture".into(),
            });
            hit = Some((s, false));
        }
        None => attempts.push(StageAttempt {
            source: SuggestionSource::Ispdb,
            outcome: StageOutcome::Miss,
            detail: "no fixture entry for domain".into(),
        }),
    }

    // 2 + 3. Published autoconfig documents, most specific first.
    for (source, url) in [
        (
            SuggestionSource::AutoconfigHost,
            autoconfig_host_url(&domain),
        ),
        (SuggestionSource::WellKnown, well_known_url(&domain)),
    ] {
        if hit.is_some() {
            break;
        }
        match net.fetch_https(&url) {
            None => attempts.push(StageAttempt {
                source,
                outcome: StageOutcome::Unreachable,
                detail: "autoconfig document not reachable".into(),
            }),
            Some(body) => match ClientConfig::parse(&body, &domain) {
                Err(e) => attempts.push(StageAttempt {
                    source,
                    outcome: StageOutcome::Malformed,
                    detail: xml_detail(&e).to_string(),
                }),
                Ok(cfg) => match cfg.to_suggestion(&email_norm, source) {
                    Some(s) => {
                        attempts.push(StageAttempt {
                            source,
                            outcome: StageOutcome::Hit,
                            detail: "autoconfig document published usable servers".into(),
                        });
                        hit = Some((s, false));
                    }
                    None => attempts.push(StageAttempt {
                        source,
                        outcome: StageOutcome::Unsupported,
                        detail: "document published no usable incoming/outgoing pair".into(),
                    }),
                },
            },
        }
    }

    // 4. MX-derived heuristics: provider hint, then pattern guess.
    if hit.is_none() {
        let mx = net.lookup_mx(&domain);
        if mx.is_empty() {
            attempts.push(StageAttempt {
                source: SuggestionSource::MxHeuristic,
                outcome: StageOutcome::Miss,
                detail: "no MX records for domain".into(),
            });
        }
        match heuristics::from_mx(&email_norm, &mx) {
            Some(s) => {
                attempts.push(StageAttempt {
                    source: SuggestionSource::MxHeuristic,
                    outcome: StageOutcome::Hit,
                    detail: "MX host matched known provider".into(),
                });
                hit = Some((s, false));
            }
            None => match heuristics::generic_guess(&email_norm) {
                Some(s) => {
                    attempts.push(StageAttempt {
                        source: SuggestionSource::MxHeuristic,
                        outcome: StageOutcome::Hit,
                        detail: "pattern guess imap.<domain>/smtp.<domain>".into(),
                    });
                    hit = Some((s, true));
                }
                None => attempts.push(StageAttempt {
                    source: SuggestionSource::MxHeuristic,
                    outcome: StageOutcome::Miss,
                    detail: "no provider hint and no usable pattern guess".into(),
                }),
            },
        }
    }

    // 5. Manual fallback — always produces something.
    let (suggestion, guessed) = match hit {
        Some(v) => v,
        None => {
            let entry = ManualEntry::blank(&email_norm);
            let s = entry
                .to_suggestion(&email_norm)
                .ok_or(Error::InvalidEmail)?;
            attempts.push(StageAttempt {
                source: SuggestionSource::Manual,
                outcome: StageOutcome::Hit,
                detail: "manual entry required".into(),
            });
            (s, true)
        }
    };

    Ok(DiscoveryOutcome {
        email: suggestion.email.clone(),
        domain: domain.as_str().to_string(),
        source: suggestion.source,
        needs_manual_review: guessed || suggestion.source == SuggestionSource::Manual,
        suggestion,
        attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ispdb::IspdbEntry;
    use crate::net::MockNet;
    use crate::suggest::{AuthKind, SuggestionSource};
    use kiwi_mail::transport::SocketSecurity;

    /// Well-formed autoconfig document for `pub.test`.
    const XML_PUB: &str = r#"<clientConfig><emailProvider id="pub.test"><domain>pub.test</domain>
      <displayName>Published Provider</displayName>
      <incomingServer type="imap">
        <hostname>imap.pub.test</hostname><port>993</port>
        <socketType>SSL</socketType><username>%EMAILADDRESS%</username>
        <authentication>password-cleartext</authentication>
      </incomingServer>
      <outgoingServer type="smtp">
        <hostname>smtp.pub.test</hostname><port>587</port>
        <socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username>
        <authentication>password-cleartext</authentication>
      </outgoingServer>
    </emailProvider></clientConfig>"#;

    #[test]
    fn urls_are_https_and_deterministic() {
        let d = DomainName::parse("Example.Test.").unwrap();
        assert_eq!(
            autoconfig_host_url(&d),
            "https://autoconfig.example.test/mail/config-v1.1.xml"
        );
        assert_eq!(
            well_known_url(&d),
            "https://example.test/.well-known/autoconfig/mail/config-v1.1.xml"
        );
    }

    #[test]
    fn ispdb_stage_short_circuits_before_network() {
        // Empty net: if ISPDB didn't hit, we'd land on manual. Gmail hits.
        let net = MockNet::new();
        let out = discover("someone@gmail.com", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::Ispdb);
        assert!(!out.needs_manual_review);
        assert_eq!(out.suggestion.incoming.host, "imap.gmail.com");
        assert_eq!(out.attempts.len(), 1, "no network stages run after hit");
        assert_eq!(out.attempts[0].outcome, StageOutcome::Hit);
        assert_eq!(out.email, "someone@gmail.com");
        assert_eq!(out.domain, "gmail.com");
    }

    #[test]
    fn autoconfig_host_beats_wellknown_and_both_beat_mx() {
        let net = MockNet::new()
            .with_https("https://autoconfig.pub.test/mail/config-v1.1.xml", XML_PUB)
            .with_https(
                "https://pub.test/.well-known/autoconfig/mail/config-v1.1.xml",
                XML_PUB,
            )
            .with_mx("pub.test", &[("alt2.aspmx.l.google.com", 20)]);
        let out = discover("u@pub.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::AutoconfigHost);
        assert!(!out.needs_manual_review);
        assert_eq!(out.suggestion.incoming.host, "imap.pub.test");
        assert_eq!(out.attempts.len(), 2);
        assert_eq!(out.attempts[0].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[1].outcome, StageOutcome::Hit);
    }

    #[test]
    fn wellknown_stage_used_when_autoconfig_host_unreachable() {
        let net = MockNet::new().with_https(
            "https://pub.test/.well-known/autoconfig/mail/config-v1.1.xml",
            XML_PUB,
        );
        let out = discover("u@pub.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::WellKnown);
        assert_eq!(out.attempts[0].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[1].outcome, StageOutcome::Unreachable);
        assert_eq!(out.attempts[2].outcome, StageOutcome::Hit);
    }

    #[test]
    fn mx_hint_stage_when_no_documents() {
        let net = MockNet::new().with_mx("corp.test", &[("aspmx.l.google.com", 10)]);
        let out = discover("u@corp.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::MxHeuristic);
        assert!(
            !out.needs_manual_review,
            "provider hint is not a bare guess"
        );
        assert_eq!(out.suggestion.incoming.host, "imap.gmail.com");
        // ispdb miss + two unreachable + mx hit.
        assert_eq!(out.attempts.len(), 4);
        assert_eq!(out.attempts[3].outcome, StageOutcome::Hit);
    }

    #[test]
    fn pattern_guess_is_flagged_for_review() {
        let net = MockNet::new().with_mx("unknown.test", &[("mx1.unknown.test", 10)]);
        let out = discover("u@unknown.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::MxHeuristic);
        assert!(out.needs_manual_review);
        assert_eq!(out.suggestion.incoming.host, "imap.unknown.test");
        assert!(
            out.attempts
                .iter()
                .any(|a| a.outcome == StageOutcome::Hit && a.detail.contains("pattern guess"))
        );
    }

    #[test]
    fn full_fallthrough_ends_in_flagged_pattern_guess() {
        // No net at all, no fixtures, no MX → every network stage misses,
        // pattern guess is the last usable rung and is flagged for review.
        // (The Manual stage below it is defense-in-depth; `generic_guess`
        // is total over valid addresses, so it is only reached if bounds
        // validation of the guess fails.)
        let net = MockNet::new();
        let out = discover("u@nowhere.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::MxHeuristic);
        assert!(out.needs_manual_review);
        assert_eq!(out.suggestion.incoming.host, "imap.nowhere.test");
        // Evidence trail: ispdb miss, two unreachable, mx miss, guess hit.
        let sources: Vec<SuggestionSource> = out.attempts.iter().map(|a| a.source).collect();
        assert_eq!(
            sources,
            vec![
                SuggestionSource::Ispdb,
                SuggestionSource::AutoconfigHost,
                SuggestionSource::WellKnown,
                SuggestionSource::MxHeuristic,
                SuggestionSource::MxHeuristic,
            ]
        );
        assert_eq!(out.attempts[0].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[1].outcome, StageOutcome::Unreachable);
        assert_eq!(out.attempts[2].outcome, StageOutcome::Unreachable);
        assert_eq!(out.attempts[3].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[4].outcome, StageOutcome::Hit);
        assert!(out.attempts[4].detail.contains("pattern guess"));
    }

    #[test]
    fn malformed_document_is_stage_outcome_not_error() {
        let net = MockNet::new()
            .with_https(
                "https://autoconfig.broken.test/mail/config-v1.1.xml",
                "<!DOCTYPE x><clientConfig/>",
            )
            .with_https(
                "https://broken.test/.well-known/autoconfig/mail/config-v1.1.xml",
                "definitely not xml",
            );
        let out = discover("u@broken.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::MxHeuristic);
        assert!(out.needs_manual_review);
        assert_eq!(out.attempts[0].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[1].outcome, StageOutcome::Malformed);
        assert_eq!(out.attempts[2].outcome, StageOutcome::Malformed);
    }

    #[test]
    fn invalid_email_is_the_only_error() {
        assert_eq!(
            discover("not-an-email", &MockNet::new()),
            Err(Error::InvalidEmail)
        );
        assert_eq!(discover("", &MockNet::new()), Err(Error::InvalidEmail));
    }

    #[test]
    fn custom_table_changes_outcome() {
        // Fixture table wins over published documents.
        let mut custom = vec![IspdbEntry {
            provider: "Custom",
            domains: &["pub.test"],
            imap: ("imap.custom.test", 993, SocketSecurity::ImplicitTls),
            pop3: None,
            smtp: ("smtp.custom.test", 465, SocketSecurity::ImplicitTls),
            auth: AuthKind::Password,
        }];
        let net =
            MockNet::new().with_https("https://autoconfig.pub.test/mail/config-v1.1.xml", XML_PUB);
        let out = discover_with_table("u@pub.test", &net, &custom).unwrap();
        assert_eq!(out.source, SuggestionSource::Ispdb);
        assert_eq!(out.suggestion.display_name, "Custom");
        assert_eq!(out.attempts.len(), 1);
        // Empty table: falls through to the published document.
        custom.clear();
        let out2 = discover_with_table("u@pub.test", &net, &custom).unwrap();
        assert_eq!(out2.source, SuggestionSource::AutoconfigHost);
    }

    #[test]
    fn outcome_maps_to_mail_account() {
        let out = discover("someone@gmail.com", &MockNet::new()).unwrap();
        let acct = out.suggestion.to_mail_account();
        assert_eq!(acct.email, "someone@gmail.com");
        assert_eq!(acct.display_name, "Google");
        // IMAP + implicit TLS on kiwi-mail's real account shape.
        assert_eq!(
            acct.incoming.protocol,
            kiwi_mail::account::IncomingProtocol::Imap
        );
        assert_eq!(acct.incoming.server.host, "imap.gmail.com");
        assert_eq!(acct.incoming.server.port, 993);
        assert!(matches!(
            acct.incoming.server.security,
            SocketSecurity::ImplicitTls
        ));
        assert_eq!(acct.incoming.username, "someone@gmail.com");
        // Credential keys are deterministic and secret-free; kind follows
        // the fixture (Google = XOAUTH2).
        match (&acct.incoming.auth, &acct.outgoing.auth) {
            (
                kiwi_mail::account::AuthRef::XOAuth2 { credential_key: ik },
                kiwi_mail::account::AuthRef::XOAuth2 { credential_key: ok },
            ) => {
                assert_eq!(ik, "autoconfig/someone@gmail.com/incoming");
                assert_eq!(ok, "autoconfig/someone@gmail.com/outgoing");
            }
            _ => panic!("expected XOAuth2 credential refs"),
        }
        assert_eq!(acct.outgoing.server.host, "smtp.gmail.com");
        assert_eq!(acct.outgoing.server.port, 465);
    }

    #[test]
    fn determinism_same_inputs_same_output() {
        let net = MockNet::new()
            .with_https("https://autoconfig.pub.test/mail/config-v1.1.xml", XML_PUB)
            .with_mx(
                "pub.test",
                &[("aspmx.l.google.com", 10), ("mx2.zoho.com", 20)],
            );
        let a = discover("u@pub.test", &net).unwrap();
        let b = discover("u@pub.test", &net).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stage_outcome_wire_names_are_stable() {
        assert_eq!(StageOutcome::Hit.as_str(), "hit");
        assert_eq!(StageOutcome::Miss.as_str(), "miss");
        assert_eq!(StageOutcome::Unreachable.as_str(), "unreachable");
        assert_eq!(StageOutcome::Malformed.as_str(), "malformed");
        assert_eq!(StageOutcome::Unsupported.as_str(), "unsupported");
    }

    #[test]
    fn chain_walks_ispdb_then_mx_per_named_fixture() {
        // T-178 integration: discover() end-to-end per bundled fixture —
        // stage 1 hits, stage 4 never runs, no network, deterministic.
        let net = MockNet::new();
        for (domain, provider, imap_host) in [
            ("gmail.com", "Google", "imap.gmail.com"),
            ("outlook.com", "Microsoft 365", "outlook.office365.com"),
            ("yahoo.com", "Yahoo", "imap.mail.yahoo.com"),
            ("icloud.com", "iCloud", "imap.mail.me.com"),
            ("zoho.com", "Zoho", "imap.zoho.com"),
            ("fastmail.com", "Fastmail", "imap.fastmail.com"),
        ] {
            let out = discover(&format!("u@{domain}"), &net).unwrap_or_else(|| {
                panic!("{provider} chain failed")
            });
            assert_eq!(out.source, SuggestionSource::Ispdb, "{provider} source");
            assert_eq!(out.suggestion.display_name, provider, "{provider} name");
            assert_eq!(out.suggestion.incoming.host, imap_host, "{provider} host");
            assert!(!out.needs_manual_review, "{provider} must not be flagged");
            assert_eq!(out.attempts.len(), 1, "{provider}: later stages must not run");
            assert_eq!(out.attempts[0].source, SuggestionSource::Ispdb);
            assert_eq!(out.attempts[0].outcome, StageOutcome::Hit);
        }
    }

    #[test]
    fn chain_falls_through_to_mx_hint_for_private_domain() {
        // T-178 integration: no fixture, no documents, but MX points at a
        // known provider → discovery walks ispdb → autoconfig → well_known
        // → mx and lands on the provider hint (not a bare guess).
        let net = MockNet::new().with_mx("acme.test", &[("mx.zoho.com", 10)]);
        let out = discover("ops@acme.test", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::MxHeuristic);
        assert!(!out.needs_manual_review);
        assert_eq!(out.suggestion.display_name, "Zoho");
        assert_eq!(out.suggestion.incoming.host, "imap.zoho.com");
        let sources: Vec<SuggestionSource> = out.attempts.iter().map(|a| a.source).collect();
        assert_eq!(
            sources,
            vec![
                SuggestionSource::Ispdb,
                SuggestionSource::AutoconfigHost,
                SuggestionSource::WellKnown,
                SuggestionSource::MxHeuristic,
            ]
        );
        assert_eq!(out.attempts[0].outcome, StageOutcome::Miss);
        assert_eq!(out.attempts[1].outcome, StageOutcome::Unreachable);
        assert_eq!(out.attempts[2].outcome, StageOutcome::Unreachable);
        assert_eq!(out.attempts[3].outcome, StageOutcome::Hit);
        assert_eq!(out.attempts[3].detail, "MX host matched known provider");
        // Deterministic end-to-end.
        assert_eq!(discover("ops@acme.test", &net).unwrap(), out);
    }

    #[test]
    fn chain_fixture_beats_published_document() {
        // T-178 integration: when both a fixture and a published document
        // exist, stage order wins (fixture first, network never touched).
        let net = MockNet::new().with_https(
            "https://autoconfig.gmail.com/mail/config-v1.1.xml",
            XML_PUB,
        );
        let out = discover("u@gmail.com", &net).unwrap();
        assert_eq!(out.source, SuggestionSource::Ispdb);
        assert_eq!(out.suggestion.display_name, "Google");
        assert_eq!(out.attempts.len(), 1, "no fetch after fixture hit");
    }
}
