//! Rule wire views — F1 inbox rules (T-228 types, T-233 IPC surface).
//!
//! `when`/`then` carry the `kiwi_mail::rules` serde DSL verbatim —
//! `{"kind": …}` predicates, `{"do": …}` actions. The IPC layer adds no
//! translation inside the spec; it only camelCases the envelope fields.

use kiwi_mail::rules::{ApplyNowReport, Predicate, Rule, RuleAction};
use kiwi_mail::store::RuleHit;
use serde::{Deserialize, Serialize};

/// A rule as the renderer sees it. One shape serves both directions:
/// `kiwi_rules_list` emits it, `kiwi_rules_upsert` consumes it (ids are
/// caller-assigned — upsert is create-or-replace).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    pub id: String,
    /// `null`/absent = applies to every account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub name: String,
    pub enabled: bool,
    /// Evaluation order within each class (ascending; `id` breaks ties).
    pub position: i64,
    /// Block-list class — evaluated before regular rules, terminal on
    /// match, verdict = trash.
    pub is_block: bool,
    /// Predicate tree (`{"kind": "sender"|"recipient"|"subject"|"header"|
    /// "body_contains"|"attachment_name"|"all"|"any"|"not"|"always", …}`).
    pub when: Predicate,
    /// Actions in application order (`{"do": "move"|"archive"|"delete"|
    /// "mark_read"|"star", …}`).
    pub then: Vec<RuleAction>,
}

impl From<Rule> for RuleView {
    fn from(r: Rule) -> Self {
        Self {
            id: r.id,
            account_id: r.account_id,
            name: r.name,
            enabled: r.enabled,
            position: r.position,
            is_block: r.is_block,
            when: r.when,
            then: r.then,
        }
    }
}

impl From<RuleView> for Rule {
    fn from(v: RuleView) -> Self {
        Self {
            id: v.id,
            account_id: v.account_id,
            name: v.name,
            enabled: v.enabled,
            position: v.position,
            is_block: v.is_block,
            when: v.when,
            then: v.then,
        }
    }
}

/// One audit row — which rule fired on which stored message, when.
/// `folderId`/`uid` are the coordinates at eval time (a moved message's
/// trail stays at its ingest coordinates; `messageId` is the stable
/// cross-move identity).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleHitView {
    pub folder_id: i64,
    pub uid: u64,
    pub rule_id: String,
    pub message_id: Option<String>,
    pub applied_unix: i64,
}

impl From<RuleHit> for RuleHitView {
    fn from(h: RuleHit) -> Self {
        Self {
            folder_id: h.folder_id,
            uid: h.uid,
            rule_id: h.rule_id,
            message_id: h.message_id,
            applied_unix: h.applied_unix,
        }
    }
}

/// `kiwi_rules_apply_now` receipt — the re-run's aggregate effect.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesApplyView {
    pub scanned: u64,
    pub matched: u64,
    pub moved: u64,
    /// Block-list verdicts applied (each trashed the message).
    pub blocked: u64,
    pub flags_changed: u64,
    /// Messages skipped — no parseable body stored yet.
    pub skipped_no_body: u64,
}

impl From<ApplyNowReport> for RulesApplyView {
    fn from(r: ApplyNowReport) -> Self {
        Self {
            scanned: r.scanned,
            matched: r.matched,
            moved: r.moved,
            blocked: r.blocked,
            flags_changed: r.flags_changed,
            skipped_no_body: r.skipped_no_body,
        }
    }
}

/// One candidate-rule match in `kiwi_rules_preview` — eval-time
/// coordinates plus the display fields the preview list renders.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewHitView {
    pub folder_id: i64,
    pub uid: u64,
    /// Folder name (not id) — this is a display list.
    pub folder: String,
    pub subject: Option<String>,
    pub message_id: Option<String>,
}

/// `kiwi_rules_preview` receipt — a pure read: nothing was moved,
/// flagged, hit-logged, or watermarked.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePreviewView {
    /// Candidates with a parseable stored body that were evaluated.
    pub scanned: u64,
    /// Candidates skipped — no stored body (absent fact, no guess).
    pub skipped_no_body: u64,
    /// `hits.len()` — explicit for the UI's "N messages would match".
    pub matched: u64,
    pub hits: Vec<PreviewHitView>,
}

impl From<kiwi_mail::rules::RulePreview> for RulePreviewView {
    fn from(p: kiwi_mail::rules::RulePreview) -> Self {
        Self {
            scanned: p.scanned,
            skipped_no_body: p.skipped_no_body,
            matched: p.hits.len() as u64,
            hits: p
                .hits
                .into_iter()
                .map(|h| PreviewHitView {
                    folder_id: h.folder_id,
                    uid: h.uid,
                    folder: h.folder_name,
                    subject: h.subject,
                    message_id: h.message_id,
                })
                .collect(),
        }
    }
}
