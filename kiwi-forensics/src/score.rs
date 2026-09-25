//! Deterministic security scoring.
//!
//! # Model (`kiwi-score-1`)
//!
//! 1. Each finding has a **weight** in points derived from its severity
//!    (`Critical` 40, `High` 25, `Medium` 12, `Low` 5, `Info` 0).
//! 2. The weight is scaled by the finding's evidence strength
//!    (`Certain` 1.00, `Firm` 0.85, `Tentative` 0.50).
//! 3. Repeats of the *same rule* on the same subject are dimmed
//!    (1st 1.00, 2nd 0.50, 3rd 0.25, 4th+ 0.125) so that one systematic
//!    misconfiguration repeated across many sessions cannot monopolise the score.
//! 4. Deductions are summed and capped at 100; the score is `100 - deduction`.
//!
//! All arithmetic is integer-only: scaling factors are basis points, intermediate
//! units are `points × 10^8`, and the final division rounds **half up**. No
//! floating point is used anywhere, so two platforms (or two runs) cannot produce
//! different scores from the same findings.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, Severity, SeverityCounts};

/// Internal fixed-point scale: confidence basis points × repeat basis points.
const UNIT_SCALE: u64 = 100_000_000;

/// Points deducted per severity at full weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringWeights {
    /// Points for an informational finding (normally zero).
    pub info: u32,
    /// Points for a low-severity finding.
    pub low: u32,
    /// Points for a medium-severity finding.
    pub medium: u32,
    /// Points for a high-severity finding.
    pub high: u32,
    /// Points for a critical finding.
    pub critical: u32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        ScoringWeights {
            info: 0,
            low: 5,
            medium: 12,
            high: 25,
            critical: 40,
        }
    }
}

impl ScoringWeights {
    /// Points for a severity class.
    pub fn points_for(&self, severity: Severity) -> u32 {
        match severity {
            Severity::Info => self.info,
            Severity::Low => self.low,
            Severity::Medium => self.medium,
            Severity::High => self.high,
            Severity::Critical => self.critical,
        }
    }
}

/// Letter grade for a score. Wire form is lowercase (`"a"`–`"f"`); the
/// uppercase `as_str()` spellings are display/legacy-read only (FSV-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// 90–100.
    #[serde(alias = "A")]
    A,
    /// 80–89.
    #[serde(alias = "B")]
    B,
    /// 70–79.
    #[serde(alias = "C")]
    C,
    /// 55–69.
    #[serde(alias = "D")]
    D,
    /// 0–54.
    #[serde(alias = "F")]
    F,
}

impl Grade {
    /// Grade band for a score (0–100).
    pub fn from_score(score: u32) -> Grade {
        match score {
            90..=100 => Grade::A,
            80..=89 => Grade::B,
            70..=79 => Grade::C,
            55..=69 => Grade::D,
            _ => Grade::F,
        }
    }

    /// Stable single-letter identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

/// Scoring configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringPolicy {
    /// Points per severity at full weight.
    pub weights: ScoringWeights,
    /// Repeat dimming in basis points for the 1st, 2nd, 3rd and 4th+ occurrence
    /// of the same rule in one scope.
    pub repeat_multipliers_bp: [u32; 4],
    /// Maximum total deduction (the score floor is `100 - this`).
    pub max_deduction_points: u32,
}

impl Default for ScoringPolicy {
    fn default() -> Self {
        ScoringPolicy {
            weights: ScoringWeights::default(),
            repeat_multipliers_bp: [10_000, 5_000, 2_500, 1_250],
            max_deduction_points: 100,
        }
    }
}

/// Result of scoring a set of findings.
///
/// Not `Copy`: `model_version` is owned text so a stored score can always be
/// interpreted against the model that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScore {
    /// Score on a 0–100 scale, higher is better.
    pub score: u32,
    /// Letter grade for [`SecurityScore::score`].
    pub grade: Grade,
    /// Points deducted (capped by the policy's `max_deduction_points`).
    pub deduction_points: u32,
    /// Findings per severity that fed the score.
    pub counts: SeverityCounts,
    /// Findings whose weight was reduced because the same rule repeated.
    pub dimmed_repeats: u32,
    /// Scoring model identifier, so a stored score can be interpreted later.
    pub model_version: String,
}

impl SecurityScore {
    /// A perfect score with no findings.
    pub fn perfect() -> Self {
        SecurityScore {
            score: 100,
            grade: Grade::A,
            deduction_points: 0,
            counts: SeverityCounts::default(),
            dimmed_repeats: 0,
            model_version: crate::SCORING_MODEL_VERSION.to_string(),
        }
    }
}

/// Score a set of findings.
///
/// The result depends only on the findings and the policy — never on input order
/// (findings are grouped in a `BTreeMap` and sorted inside each group).
pub fn score_findings(findings: &[Finding], policy: &ScoringPolicy) -> SecurityScore {
    if findings.is_empty() {
        return SecurityScore::perfect();
    }

    // (severity, confidence basis points) grouped by rule id, so repeat dimming
    // is applied per rule and iteration order is deterministic.
    let mut by_rule: BTreeMap<&str, Vec<(Severity, u32)>> = BTreeMap::new();
    for finding in findings {
        by_rule
            .entry(finding.rule_id.as_str())
            .or_default()
            .push((finding.severity, finding.confidence.multiplier_bp()));
    }

    let mut units: u64 = 0;
    let mut dimmed_repeats: u32 = 0;
    let slots = policy.repeat_multipliers_bp.len();
    for occurrences in by_rule.values_mut() {
        // Worst and most certain first: the undimmed slot always goes to the most
        // serious instance of the rule.
        occurrences.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        for (index, (severity, confidence_bp)) in occurrences.iter().enumerate() {
            let slot = if slots == 0 { 0 } else { index.min(slots - 1) };
            let repeat_bp = policy.repeat_multipliers_bp.get(slot).copied().unwrap_or(0);
            if index > 0 {
                dimmed_repeats += 1;
            }
            let points = u64::from(policy.weights.points_for(*severity));
            units = units.saturating_add(
                points
                    .saturating_mul(u64::from(*confidence_bp))
                    .saturating_mul(u64::from(repeat_bp)),
            );
        }
    }

    // Round half up, then cap: the floor is `100 - max_deduction_points`.
    let rounded = units.saturating_add(UNIT_SCALE / 2) / UNIT_SCALE;
    let deduction_points = u64::from(policy.max_deduction_points).min(rounded) as u32;
    let score = 100u32.saturating_sub(deduction_points);

    SecurityScore {
        score,
        grade: Grade::from_score(score),
        deduction_points,
        counts: SeverityCounts::from_findings(findings),
        dimmed_repeats,
        model_version: crate::SCORING_MODEL_VERSION.to_string(),
    }
}

/// Score only the findings belonging to one session.
pub fn score_findings_for_session(
    findings: &[Finding],
    session_id: &crate::model::SessionId,
    policy: &ScoringPolicy,
) -> SecurityScore {
    let scoped: Vec<Finding> = findings
        .iter()
        .filter(|finding| &finding.subject.session_id == session_id)
        .cloned()
        .collect();
    score_findings(&scoped, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Confidence, Evidence, EvidenceKind, EvidenceValue, FindingCategory};
    use crate::model::{ConnectionSecurityEvent, Endpoint, Protocol, SessionId, SourceRef};

    fn session(label: &str) -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label(label),
            Protocol::Smtp,
            Endpoint::new("10.0.0.9", 51000),
            Endpoint::new("mail.example.test", 25),
            1_700_000_000_000,
        )
    }

    fn finding(
        rule_id: &str,
        severity: Severity,
        confidence: Confidence,
        session: &ConnectionSecurityEvent,
    ) -> Finding {
        let source = SourceRef::session_only(session.id.clone());
        Finding::builder(
            rule_id,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            severity,
            confidence,
            session,
        )
        .title("t")
        .evidence(Evidence::new(
            EvidenceKind::TransportState,
            "state",
            EvidenceValue::text("plaintext"),
            source,
        ))
        .build()
    }

    #[test]
    fn no_findings_is_a_perfect_score() {
        let score = score_findings(&[], &ScoringPolicy::default());
        assert_eq!(score.score, 100);
        assert_eq!(score.grade, Grade::A);
        assert_eq!(score.deduction_points, 0);
        assert_eq!(score.model_version, crate::SCORING_MODEL_VERSION);
    }

    #[test]
    fn info_only_findings_do_not_reduce_the_score() {
        let s = session("a");
        let findings = vec![
            finding("KIWI-TLS-001", Severity::Info, Confidence::Certain, &s),
            finding("KIWI-TLS-002", Severity::Info, Confidence::Certain, &s),
        ];
        let score = score_findings(&findings, &ScoringPolicy::default());
        assert_eq!(score.score, 100);
        assert_eq!(score.counts.info, 2);
    }

    #[test]
    fn critical_certain_deducts_exactly_its_weight() {
        let s = session("a");
        let findings = vec![finding(
            "KIWI-TRANSPORT-001",
            Severity::Critical,
            Confidence::Certain,
            &s,
        )];
        let score = score_findings(&findings, &ScoringPolicy::default());
        assert_eq!(score.deduction_points, 40);
        assert_eq!(score.score, 60);
        assert_eq!(score.grade, Grade::D);
    }

    #[test]
    fn repeats_of_one_rule_are_dimmed_but_other_rules_are_not() {
        let s = session("a");
        let same_rule = vec![
            finding(
                "KIWI-CIPHER-001",
                Severity::Critical,
                Confidence::Certain,
                &s,
            ),
            finding(
                "KIWI-CIPHER-001",
                Severity::Critical,
                Confidence::Certain,
                &s,
            ),
        ];
        let score = score_findings(&same_rule, &ScoringPolicy::default());
        assert_eq!(score.deduction_points, 60, "40 + 20 (half weight)");
        assert_eq!(score.dimmed_repeats, 1);

        let different_rules = vec![
            finding(
                "KIWI-CIPHER-001",
                Severity::Critical,
                Confidence::Certain,
                &s,
            ),
            finding(
                "KIWI-CIPHER-002",
                Severity::Critical,
                Confidence::Certain,
                &s,
            ),
        ];
        let score = score_findings(&different_rules, &ScoringPolicy::default());
        assert_eq!(score.deduction_points, 80, "both at full weight");
        assert_eq!(score.dimmed_repeats, 0);
    }

    #[test]
    fn tentative_confidence_halves_the_weight_and_rounds_half_up() {
        let s = session("a");
        let findings = vec![finding(
            "KIWI-CIPHER-004",
            Severity::High,
            Confidence::Tentative,
            &s,
        )];
        let score = score_findings(&findings, &ScoringPolicy::default());
        assert_eq!(
            score.deduction_points, 13,
            "25 x 0.5 = 12.5, rounded half up"
        );
        assert_eq!(score.score, 87);
        assert_eq!(score.grade, Grade::B);
    }

    #[test]
    fn deduction_is_capped_and_never_underflows() {
        let s = session("a");
        let findings: Vec<Finding> = (0..40)
            .map(|i| {
                finding(
                    &format!("KIWI-RULE-{i:03}"),
                    Severity::Critical,
                    Confidence::Certain,
                    &s,
                )
            })
            .collect();
        let score = score_findings(&findings, &ScoringPolicy::default());
        assert_eq!(score.deduction_points, 100);
        assert_eq!(score.score, 0);
        assert_eq!(score.grade, Grade::F);
    }

    #[test]
    fn scoring_is_independent_of_input_order() {
        let s = session("a");
        let mut findings = vec![
            finding("KIWI-TLS-003", Severity::High, Confidence::Certain, &s),
            finding("KIWI-TLS-003", Severity::Medium, Confidence::Certain, &s),
            finding(
                "KIWI-CIPHER-001",
                Severity::Critical,
                Confidence::Tentative,
                &s,
            ),
        ];
        let forward = score_findings(&findings, &ScoringPolicy::default());
        findings.reverse();
        let reversed = score_findings(&findings, &ScoringPolicy::default());
        assert_eq!(forward, reversed);
    }

    #[test]
    fn grade_bands_are_exact() {
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(70), Grade::C);
        assert_eq!(Grade::from_score(55), Grade::D);
        assert_eq!(Grade::from_score(54), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);
    }

    #[test]
    fn session_scoped_scoring_ignores_other_sessions() {
        let a = session("a");
        let mut b = session("b");
        b.server = Endpoint::new("other.example.test", 25);
        let findings = vec![
            finding(
                "KIWI-TRANSPORT-001",
                Severity::Critical,
                Confidence::Certain,
                &a,
            ),
            finding(
                "KIWI-CIPHER-001",
                Severity::Critical,
                Confidence::Certain,
                &b,
            ),
        ];
        let policy = ScoringPolicy::default();
        let scoped = score_findings_for_session(&findings, &a.id, &policy);
        assert_eq!(scoped.deduction_points, 40);
        assert_eq!(scoped.counts.total(), 1);
        assert_eq!(score_findings(&findings, &policy).deduction_points, 80);
    }

    #[test]
    fn evidence_text_is_sanitized() {
        assert_eq!(
            EvidenceValue::text("PLAIN\r\n250-KIWI").display_text(),
            "PLAIN 250-KIWI"
        );
        assert_eq!(
            EvidenceValue::unavailable("not captured").display_text(),
            "unavailable: not captured"
        );
        assert_eq!(
            EvidenceValue::bytes("ab12", 8).display_text(),
            "8 bytes (digest ab12)"
        );
    }
}
