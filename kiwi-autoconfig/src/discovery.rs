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
use crate::{heuristics, DomainName, Error};

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
    format!("https://autoconfig.{}{}", domain.as_str(), AUTOCONFIG_HOST_PATH)
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
        (SuggestionSource::AutoconfigHost, autoconfig_host_url(&domain)),
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
            let s = entry.to_suggestion(&email_norm).ok_or(Error::InvalidEmail)?;
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
