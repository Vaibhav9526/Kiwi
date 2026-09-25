//! Deterministic per-message authentication risk hint (T-249).
//!
//! This is a bounded UI hint derived only from authentication evidence. It is
//! not a security finding, does not move mail, and has no side effects.

use serde::{Deserialize, Serialize};

/// Stable wire vocabulary consumed by the frontend authentication pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthRisk {
    /// All local checks passed with trusted, agreeing upstream evidence.
    Clean,
    /// Incomplete, inconclusive, untrusted, contradictory, or non-qualifying fail.
    #[default]
    Noted,
    /// One of the two exact failed combinations documented below.
    Failed,
}

impl AuthRisk {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Noted => "noted",
            Self::Failed => "failed",
        }
    }

    /// Parse persisted data. Unknown/corrupt values fail closed to `noted`.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "clean" => Self::Clean,
            "failed" => Self::Failed,
            _ => Self::Noted,
        }
    }
}

/// Derive the per-message hint using a deliberately narrow, ordered table.
///
/// `spf_aligned` means the SPF identifier domain aligns with the RFC 5322 From
/// domain under the discovered DMARC `aspf` mode. It is independent of SPF
/// pass/fail: failed SPF cannot authorize DMARC, but its alignment is evidence
/// for the second failed rule.
///
/// 1. `failed` iff `dkim=fail AND dmarc=fail`, or `dmarc=fail AND spf=fail AND
///    spf_aligned`.
/// 2. Otherwise `noted` for every result other than three local passes,
///    including all `none`/`temperror`/`permerror`, softfail/neutral, untrusted
///    or missing upstream evidence, discrepancies, and non-qualifying failures.
/// 3. Otherwise `clean` iff all local methods pass, upstream evidence is
///    present/trusted, and no discrepancy exists.
///
/// Pure: no clock, network, randomness, mail movement, or finding creation.
#[must_use]
pub fn derive_auth_risk(
    spf: &str,
    dkim: &str,
    dmarc: &str,
    spf_aligned: bool,
    upstream_usable: bool,
    upstream_untrusted: bool,
    discrepancy: bool,
) -> AuthRisk {
    let dkim_dmarc_failed = dkim == "fail" && dmarc == "fail";
    let aligned_spf_dmarc_failed = dmarc == "fail" && spf == "fail" && spf_aligned;
    if dkim_dmarc_failed || aligned_spf_dmarc_failed {
        return AuthRisk::Failed;
    }

    let all_local_pass = spf == "pass" && dkim == "pass" && dmarc == "pass";
    if all_local_pass && upstream_usable && !upstream_untrusted && !discrepancy {
        AuthRisk::Clean
    } else {
        AuthRisk::Noted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(
        spf: &str,
        dkim: &str,
        dmarc: &str,
        aligned: bool,
        present: bool,
        untrusted: bool,
        discrepancy: bool,
    ) -> AuthRisk {
        derive_auth_risk(spf, dkim, dmarc, aligned, present, untrusted, discrepancy)
    }

    #[test]
    fn exact_risk_table_is_total_and_deterministic() {
        let cases = [
            ("none", "fail", "fail", false, AuthRisk::Failed),
            ("pass", "fail", "fail", false, AuthRisk::Failed),
            ("fail", "pass", "fail", true, AuthRisk::Failed),
            ("fail", "pass", "fail", false, AuthRisk::Noted),
            ("fail", "fail", "pass", false, AuthRisk::Noted),
            ("fail", "pass", "pass", true, AuthRisk::Noted),
            ("pass", "pass", "fail", false, AuthRisk::Noted),
            ("pass", "pass", "pass", false, AuthRisk::Clean),
            ("none", "pass", "pass", false, AuthRisk::Noted),
            ("pass", "none", "pass", false, AuthRisk::Noted),
            ("pass", "pass", "none", false, AuthRisk::Noted),
            ("temperror", "pass", "pass", false, AuthRisk::Noted),
            ("pass", "temperror", "pass", false, AuthRisk::Noted),
            ("pass", "pass", "temperror", false, AuthRisk::Noted),
            ("permerror", "pass", "pass", false, AuthRisk::Noted),
            ("pass", "permerror", "pass", false, AuthRisk::Noted),
            ("pass", "pass", "permerror", false, AuthRisk::Noted),
            ("softfail", "pass", "pass", false, AuthRisk::Noted),
            ("pass", "neutral", "pass", false, AuthRisk::Noted),
            ("pass", "pass", "hardfail", false, AuthRisk::Noted),
            ("garbage", "pass", "pass", false, AuthRisk::Noted),
        ];
        for (spf, dkim, dmarc, aligned, expected) in cases {
            assert_eq!(
                risk(spf, dkim, dmarc, aligned, true, false, false),
                expected,
                "spf={spf} dkim={dkim} dmarc={dmarc} aligned={aligned}"
            );
        }
    }

    #[test]
    fn untrusted_discrepancy_and_missing_upstream_are_noted() {
        assert_eq!(
            risk("pass", "pass", "pass", false, false, true, false),
            AuthRisk::Noted
        );
        assert_eq!(
            risk("pass", "pass", "pass", false, true, true, false),
            AuthRisk::Noted
        );
        assert_eq!(
            risk("pass", "pass", "pass", false, true, false, true),
            AuthRisk::Noted
        );
    }

    #[test]
    fn none_temperror_and_permerror_never_reach_failed() {
        for spf in ["none", "temperror", "permerror"] {
            for dkim in ["none", "temperror", "permerror"] {
                for dmarc in ["none", "temperror", "permerror"] {
                    assert_ne!(
                        risk(spf, dkim, dmarc, true, true, false, false),
                        AuthRisk::Failed
                    );
                }
            }
        }
    }

    #[test]
    fn wire_vocabulary_is_bounded_and_corruption_is_noted() {
        assert_eq!(AuthRisk::Clean.as_str(), "clean");
        assert_eq!(AuthRisk::Noted.as_str(), "noted");
        assert_eq!(AuthRisk::Failed.as_str(), "failed");
        assert_eq!(AuthRisk::from_wire("clean"), AuthRisk::Clean);
        assert_eq!(AuthRisk::from_wire("failed"), AuthRisk::Failed);
        assert_eq!(AuthRisk::from_wire("noted"), AuthRisk::Noted);
        assert_eq!(AuthRisk::from_wire("future-value"), AuthRisk::Noted);
    }
}
