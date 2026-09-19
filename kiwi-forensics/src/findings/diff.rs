//! Re-scan diff: what changed between two analyses of the same subject.
//!
//! Determinism matters here more than anywhere else: the diff is what a UI shows
//! after "re-scan", and it is also audit evidence. Implemented with `BTreeMap` /
//! `BTreeSet` and explicit sorts — never `HashMap` iteration order.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{Confidence, Finding, FindingKey, Severity};

/// Compact, serializable snapshot of a finding for before/after comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSnapshot {
    /// Rule that produced the finding.
    pub rule_id: String,
    /// Rule implementation version.
    pub rule_version: u16,
    /// Severity.
    pub severity: Severity,
    /// Evidence strength.
    pub confidence: Confidence,
    /// Finding title at snapshot time.
    pub title: String,
    /// Stable finding id.
    pub finding_id: String,
    /// Subject identity.
    pub subject_key: String,
}

impl FindingSnapshot {
    /// Snapshot a finding.
    pub fn from_finding(finding: &Finding) -> Self {
        FindingSnapshot {
            rule_id: finding.rule_id.clone(),
            rule_version: finding.rule_version,
            severity: finding.severity,
            confidence: finding.confidence,
            title: finding.title.clone(),
            finding_id: finding.finding_id(),
            subject_key: finding.subject.key_text(),
        }
    }
}

/// How a finding changed between two scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Present after, absent before.
    New,
    /// Present before, absent after.
    Resolved,
    /// Present in both with the same severity.
    Unchanged,
    /// Present in both, severity higher after.
    SeverityIncreased,
    /// Present in both, severity lower after.
    SeverityDecreased,
}

impl ChangeKind {
    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::New => "new",
            ChangeKind::Resolved => "resolved",
            ChangeKind::Unchanged => "unchanged",
            ChangeKind::SeverityIncreased => "severity_increased",
            ChangeKind::SeverityDecreased => "severity_decreased",
        }
    }

    /// `true` when this change is bad news for the operator.
    pub fn is_regression(self) -> bool {
        matches!(self, ChangeKind::New | ChangeKind::SeverityIncreased)
    }
}

/// One entry in a re-scan diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingChange {
    /// What changed.
    pub kind: ChangeKind,
    /// Identity of the finding.
    pub key: FindingKey,
    /// State before the re-scan, if present then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<FindingSnapshot>,
    /// State after the re-scan, if present now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<FindingSnapshot>,
}

impl FindingChange {
    /// Severity to display for this change (worst side wins).
    pub fn display_severity(&self) -> Option<Severity> {
        match (&self.after, &self.before) {
            (Some(after), Some(before)) => Some(after.severity.max(before.severity)),
            (Some(after), None) => Some(after.severity),
            (None, Some(before)) => Some(before.severity),
            (None, None) => None,
        }
    }
}

/// Aggregate counts and score movement for a re-scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Findings present only after.
    pub new: u32,
    /// Findings present only before.
    pub resolved: u32,
    /// Findings present in both, unchanged severity.
    pub unchanged: u32,
    /// Findings whose severity rose.
    pub severity_increased: u32,
    /// Findings whose severity fell.
    pub severity_decreased: u32,
    /// Findings before the re-scan.
    pub findings_before: u32,
    /// Findings after the re-scan.
    pub findings_after: u32,
    /// Security score before the re-scan.
    pub score_before: u32,
    /// Security score after the re-scan.
    pub score_after: u32,
    /// `score_after - score_before`; positive means improvement.
    pub score_delta: i32,
    /// `true` when the subject is worse than before.
    pub regression: bool,
}

/// Full re-scan diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescanDiff {
    /// Changes, ordered worst-first then by identity (deterministic).
    pub changes: Vec<FindingChange>,
    /// Aggregate summary.
    pub summary: DiffSummary,
}

impl RescanDiff {
    /// Changes that are bad news, worst first.
    pub fn regressions(&self) -> Vec<&FindingChange> {
        self.changes
            .iter()
            .filter(|change| change.kind.is_regression())
            .collect()
    }

    /// Changes that improved the posture.
    pub fn improvements(&self) -> Vec<&FindingChange> {
        self.changes
            .iter()
            .filter(|change| {
                matches!(
                    change.kind,
                    ChangeKind::Resolved | ChangeKind::SeverityDecreased
                )
            })
            .collect()
    }

    /// `true` when nothing changed at all.
    pub fn is_identical(&self) -> bool {
        !self.changes.is_empty()
            && self
                .changes
                .iter()
                .all(|change| change.kind == ChangeKind::Unchanged)
    }
}

/// Compare two sets of findings for the same subject(s).
///
/// Identity is `(rule_id, protocol:host:port[#discriminator])` — deliberately
/// **not** the session id, so two captures taken on different days line up and
/// the diff reports improvement or regression rather than "everything is new".
pub fn diff_findings(
    before: &[Finding],
    after: &[Finding],
    score_before: u32,
    score_after: u32,
) -> RescanDiff {
    let mut before_map: BTreeMap<FindingKey, &Finding> = BTreeMap::new();
    for finding in before {
        before_map.insert(finding.key(), finding);
    }
    let mut after_map: BTreeMap<FindingKey, &Finding> = BTreeMap::new();
    for finding in after {
        after_map.insert(finding.key(), finding);
    }

    let mut keys: BTreeSet<&FindingKey> = BTreeSet::new();
    keys.extend(before_map.keys());
    keys.extend(after_map.keys());

    let mut changes: Vec<FindingChange> = Vec::with_capacity(keys.len());
    let mut summary = DiffSummary {
        findings_before: before_map.len() as u32,
        findings_after: after_map.len() as u32,
        score_before,
        score_after,
        score_delta: score_after as i32 - score_before as i32,
        ..DiffSummary::default()
    };

    for key in keys {
        let before_finding = before_map.get(key).copied();
        let after_finding = after_map.get(key).copied();
        let kind = match (before_finding, after_finding) {
            (None, Some(_)) => ChangeKind::New,
            (Some(_), None) => ChangeKind::Resolved,
            (Some(before_finding), Some(after_finding)) => {
                match after_finding.severity.cmp(&before_finding.severity) {
                    std::cmp::Ordering::Greater => ChangeKind::SeverityIncreased,
                    std::cmp::Ordering::Less => ChangeKind::SeverityDecreased,
                    std::cmp::Ordering::Equal => ChangeKind::Unchanged,
                }
            }
            // `keys` is the union of both maps, so at least one side is present.
            (None, None) => continue,
        };

        match kind {
            ChangeKind::New => summary.new += 1,
            ChangeKind::Resolved => summary.resolved += 1,
            ChangeKind::Unchanged => summary.unchanged += 1,
            ChangeKind::SeverityIncreased => summary.severity_increased += 1,
            ChangeKind::SeverityDecreased => summary.severity_decreased += 1,
        }

        changes.push(FindingChange {
            kind,
            key: key.clone(),
            before: before_finding.map(FindingSnapshot::from_finding),
            after: after_finding.map(FindingSnapshot::from_finding),
        });
    }

    // Worst-first, then by stable identity: report order never depends on the
    // order the findings arrived in.
    changes.sort_by(|a, b| {
        b.display_severity()
            .cmp(&a.display_severity())
            .then_with(|| a.key.cmp(&b.key))
    });

    summary.regression =
        summary.score_delta < 0 || summary.severity_increased > 0 || summary.new > 0;
    RescanDiff { changes, summary }
}
