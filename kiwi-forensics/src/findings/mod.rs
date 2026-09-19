//! Findings, evidence and re-scan diffs.
//!
//! A [`Finding`] is the only thing this crate reports. It is always backed by
//! typed [`Evidence`] carrying a [`crate::model::SourceRef`] chain of custody,
//! so no conclusion can exist without the bytes that produced it
//! (`prompt.md` §2.5).
//!
//! Severity and confidence are assigned by rules from a fixed table — never by
//! AI, never by a floating-point heuristic (`prompt.md` §12).

pub mod diff;

use serde::{Deserialize, Serialize};

use crate::model::{Protocol, SafeText, SessionId, SourceRef};

/// How serious a finding is.
///
/// Ordering is meaningful (`Info < Low < … < Critical`) so reports sort by
/// severity without a lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context only; contributes no score deduction.
    Info,
    /// Hardening opportunity.
    Low,
    /// Real weakness with limited direct impact.
    Medium,
    /// Weakness that undermines confidentiality, integrity or authentication.
    High,
    /// No confidentiality/integrity/authentication, or credential exposure.
    Critical,
}

impl Severity {
    /// All severities, weakest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Score points deducted at full weight (see [`crate::score`]).
    pub fn weight_points(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 12,
            Severity::High => 25,
            Severity::Critical => 40,
        }
    }

    /// Stable lowercase identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// How certain the *observation* behind a finding is.
///
/// Deliberately about evidence strength, not severity: a `Tentative` finding can
/// still be `Critical`, and the scorer reduces its weight accordingly
/// ([`Confidence::multiplier_bp`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The input could support this, but evidence is incomplete (for example a
    /// truncated capture).
    Tentative,
    /// Strong evidence with a stated caveat (for example a stripping indicator
    /// that depends on the capture point observing both peers).
    Firm,
    /// Directly observed, not open to more than one reading.
    Certain,
}

impl Confidence {
    /// All confidences, weakest first.
    pub const ALL: [Confidence; 3] = [
        Confidence::Tentative,
        Confidence::Firm,
        Confidence::Certain,
    ];

    /// Integer multiplier in basis points (`10000` = 1.0). Integers keep scoring
    /// reproducible across platforms.
    pub fn multiplier_bp(self) -> u32 {
        match self {
            Confidence::Tentative => 5_000,
            Confidence::Firm => 8_500,
            Confidence::Certain => 10_000,
        }
    }

    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }
}

/// Subject area of a finding; drives report grouping and UI placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Transport protection as a whole (plaintext mail, implicit-TLS port misuse).
    Transport,
    /// Cipher-suite selection.
    Cipher,
    /// Key exchange / forward secrecy.
    KeyExchange,
    /// Certificate presentation and trust.
    Certificate,
    /// Authentication mechanism and outcome.
    Authentication,
    /// STARTTLS/STLS negotiation, downgrade and stripping indicators.
    StartTls,
    /// Protocol-level expectations.
    Protocol,
    /// Properties of the capture or observation itself (never a peer fault).
    CaptureIntegrity,
}

impl FindingCategory {
    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingCategory::Transport => "transport",
            FindingCategory::Cipher => "cipher",
            FindingCategory::KeyExchange => "key_exchange",
            FindingCategory::Certificate => "certificate",
            FindingCategory::Authentication => "authentication",
            FindingCategory::StartTls => "starttls",
            FindingCategory::Protocol => "protocol",
            FindingCategory::CaptureIntegrity => "capture_integrity",
        }
    }
}