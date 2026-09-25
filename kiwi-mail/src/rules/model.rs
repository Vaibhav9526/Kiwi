//! Rule data model — the wire/durable shapes for F1 inbox rules.
//!
//! Everything here is plain data + bounds checking; matching lives in
//! [`super::eval`]. Rules arrive from the renderer (untrusted), so
//! [`Rule::validate`] is enforced at the store boundary as well as by
//! callers — a malformed rule must never reach the evaluator or the table.

use serde::{Deserialize, Serialize};

use crate::error::{MailError, Result};

/// `rule_id` — caller-assigned, printable ASCII, no whitespace.
pub const MAX_RULE_ID_LEN: usize = 64;
/// Display name cap.
pub const MAX_RULE_NAME_LEN: usize = 128;
/// Account-id cap (mirrors the `accounts` row's own use).
pub const MAX_ACCOUNT_ID_LEN: usize = 128;
/// Cap on any single leaf match value.
pub const MAX_MATCH_VALUE_LEN: usize = 512;
/// Header field-name cap (RFC 5322 printable token, no `:`).
pub const MAX_HEADER_NAME_LEN: usize = 64;
/// `Move` destination folder-name cap.
pub const MAX_FOLDER_NAME_LEN: usize = 255;
/// Total nodes a predicate tree may contain (bounds eval work).
pub const MAX_PREDICATE_NODES: usize = 32;
/// Nesting depth a predicate tree may reach.
pub const MAX_PREDICATE_DEPTH: usize = 8;
/// Actions a single rule may emit.
pub const MAX_ACTIONS: usize = 8;

fn invalid(reason: &str) -> MailError {
    MailError::InvalidInput(format!("rule rejected: {reason}"))
}

/// How a leaf predicate compares a message field to `value`. All
/// comparisons are ASCII-case-insensitive — mail text is folded the same
/// way everywhere else in the crate (`category`, `search`, `unsub`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    /// Substring anywhere in the field.
    Contains,
    /// Whole-field equality.
    Is,
    /// Suffix match (e.g. `.exe` attachment names).
    EndsWith,
    /// Dot-boundary suffix on the *domain part* — text after the last `@`,
    /// or the whole value when there is none. `evil.com` matches
    /// `a@evil.com` and `a@x.evil.com`, never `a@notevil.com`. This is the
    /// block-list op; substring `Contains` would let `baddomain.com`
    /// trip on `good-baddomain.com`.
    Domain,
}

/// The predicate AST — a tree of field matchers with boolean combinators.
/// Serde shape is `{"kind": "…", …}` so the UI and any future config
/// import share one stable vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Predicate {
    /// Any `From:` address's email (the display name is never consulted —
    /// it is attacker-controlled paint).
    Sender { op: MatchOp, value: String },
    /// Any `To:` or `Cc:` address's email.
    Recipient { op: MatchOp, value: String },
    /// The `Subject:` value.
    Subject { op: MatchOp, value: String },
    /// Any instance of the named header (names fold case). Use for
    /// `List-Id`, `X-*`, `Return-Path`, …
    Header {
        name: String,
        op: MatchOp,
        value: String,
    },
    /// Substring over the extracted bodies: `text_body`, then `html_body`
    /// (raw markup included — deterministic, not rendered), then the
    /// stored `snippet` as a fallback for envelope-only callers.
    BodyContains { value: String },
    /// Any attachment's filename.
    AttachmentName { op: MatchOp, value: String },
    /// All children match. `All { children: [] }` is unconditionally true.
    All { children: Vec<Predicate> },
    /// Any child matches. `Any { children: [] }` is unconditionally false
    /// (the deterministic reading of "no alternatives").
    Any { children: Vec<Predicate> },
    /// Logical negation of the child.
    Not { child: Box<Predicate> },
    /// Unconditional match — the idiom for a scoped block-list rule
    /// ("every message reaching this account").
    Always,
}

/// What a matching rule does. Folder names are resolved against the
/// account's folder list by the *caller* at apply time — evaluation never
/// touches the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum RuleAction {
    /// Move to the named folder.
    Move { folder: String },
    /// Move to the account's archive folder.
    Archive,
    /// Move to Trash — a rule never hard-expunges.
    Delete,
    /// Set the seen flag.
    MarkRead,
    /// Set the starred/flagged flag.
    Star,
}

impl RuleAction {
    /// Folder-disposition actions — the ones that physically relocate the
    /// message. At most one survives evaluation (first ordered wins); a
    /// message can't be in two folders.
    pub(crate) fn is_disposition(&self) -> bool {
        matches!(self, Self::Move { .. } | Self::Archive | Self::Delete)
    }
}

/// One rule row. `position` orders evaluation (ascending, `id` breaks
/// ties); `is_block` marks the block-list class — evaluated before every
/// regular rule and terminal on match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// Owning account; `None` = applies to every account.
    pub account_id: Option<String>,
    pub name: String,
    pub enabled: bool,
    pub position: i64,
    pub is_block: bool,
    /// The predicate tree.
    pub when: Predicate,
    /// Actions applied on match (application order).
    pub then: Vec<RuleAction>,
}

/// The portion of a [`Rule`] stored in `rules.spec_json` — identity and
/// ordering live in columns, logic lives here.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RuleSpec {
    pub when: Predicate,
    pub then: Vec<RuleAction>,
}

/// What evaluation decided. Deterministic and self-describing: `matched`
/// is the evidence trail (which rules fired, in evaluation order) and
/// `blocked_by` records a block-list verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOutcome {
    /// Actions to apply, in application order. Contains at most one
    /// folder disposition and no duplicate flag actions.
    pub actions: Vec<RuleAction>,
    /// Ids of the rules that matched, in evaluation order.
    pub matched: Vec<String>,
    /// The block-list rule that fired, if any — terminal: nothing after
    /// it was evaluated.
    pub blocked_by: Option<String>,
}

impl Rule {
    /// Bounds-check a rule before it is stored or evaluated. The renderer
    /// is untrusted: an over-deep tree or unbounded string is rejected
    /// here, not discovered mid-eval.
    pub fn validate(&self) -> Result<()> {
        let printable = |s: &str| s.bytes().all(|b| b.is_ascii_graphic());
        if self.id.is_empty() || self.id.len() > MAX_RULE_ID_LEN || !printable(&self.id) {
            return Err(invalid("id must be non-empty printable ASCII"));
        }
        if self.name.trim().is_empty() || self.name.len() > MAX_RULE_NAME_LEN {
            return Err(invalid("name missing or too long"));
        }
        if let Some(a) = &self.account_id
            && (a.is_empty() || a.len() > MAX_ACCOUNT_ID_LEN || !printable(a))
        {
            return Err(invalid("account_id"));
        }
        if self.then.is_empty() || self.then.len() > MAX_ACTIONS {
            return Err(invalid("needs 1..=8 actions"));
        }
        for a in &self.then {
            if let RuleAction::Move { folder } = a
                && (folder.trim().is_empty()
                    || folder.len() > MAX_FOLDER_NAME_LEN
                    || folder.bytes().any(|b| b.is_ascii_control()))
            {
                return Err(invalid("move destination folder"));
            }
        }
        let mut nodes = 0usize;
        check_predicate(&self.when, 1, &mut nodes)
    }
}

fn check_value(v: &str) -> Result<()> {
    if v.len() > MAX_MATCH_VALUE_LEN {
        return Err(invalid("match value too long"));
    }
    Ok(())
}

fn check_predicate(p: &Predicate, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if *nodes > MAX_PREDICATE_NODES {
        return Err(invalid("predicate tree too large"));
    }
    if depth > MAX_PREDICATE_DEPTH {
        return Err(invalid("predicate tree too deep"));
    }
    match p {
        Predicate::Sender { value, .. }
        | Predicate::Recipient { value, .. }
        | Predicate::Subject { value, .. }
        | Predicate::AttachmentName { value, .. } => check_value(value),
        Predicate::BodyContains { value } => check_value(value),
        Predicate::Header { name, value, .. } => {
            check_value(value)?;
            if name.is_empty()
                || name.len() > MAX_HEADER_NAME_LEN
                || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
            {
                return Err(invalid("header name"));
            }
            Ok(())
        }
        Predicate::All { children } | Predicate::Any { children } => {
            for c in children {
                check_predicate(c, depth + 1, nodes)?;
            }
            Ok(())
        }
        Predicate::Not { child } => check_predicate(child, depth + 1, nodes),
        Predicate::Always => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_rule() -> Rule {
        Rule {
            id: "r1".into(),
            account_id: None,
            name: "test".into(),
            enabled: true,
            position: 0,
            is_block: false,
            when: Predicate::Always,
            then: vec![RuleAction::MarkRead],
        }
    }

    #[test]
    fn validate_accepts_wellformed() {
        ok_rule().validate().unwrap();
        let mut deep = ok_rule();
        deep.when = Predicate::Not {
            child: Box::new(Predicate::All {
                children: vec![
                    Predicate::Sender {
                        op: MatchOp::Domain,
                        value: "x.com".into(),
                    },
                    Predicate::Header {
                        name: "list-id".into(),
                        op: MatchOp::Contains,
                        value: "l".into(),
                    },
                ],
            }),
        };
        deep.validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_identity() {
        for bad in ["", "has space", "nul\u{0}x"] {
            let mut r = ok_rule();
            r.id = bad.into();
            assert!(r.validate().is_err(), "id {bad:?}");
        }
        let mut r = ok_rule();
        r.id = "x".repeat(MAX_RULE_ID_LEN + 1);
        assert!(r.validate().is_err());
        let mut r = ok_rule();
        r.name = "  ".into();
        assert!(r.validate().is_err());
        let mut r = ok_rule();
        r.account_id = Some("bad id".into());
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_actions_and_bounds() {
        let mut r = ok_rule();
        r.then = vec![];
        assert!(r.validate().is_err());
        r.then = vec![RuleAction::Star; MAX_ACTIONS + 1];
        assert!(r.validate().is_err());
        r.then = vec![RuleAction::Move {
            folder: "  ".into(),
        }];
        assert!(r.validate().is_err());
        r.then = vec![RuleAction::Move {
            folder: "x\ny".into(),
        }];
        assert!(r.validate().is_err());

        // over-long leaf value
        let mut r = ok_rule();
        r.when = Predicate::Subject {
            op: MatchOp::Contains,
            value: "v".repeat(MAX_MATCH_VALUE_LEN + 1),
        };
        assert!(r.validate().is_err());

        // illegal header name (space and ':' both rejected)
        for bad in ["bad name", "x:y", ""] {
            let mut r = ok_rule();
            r.when = Predicate::Header {
                name: bad.into(),
                op: MatchOp::Is,
                value: "v".into(),
            };
            assert!(r.validate().is_err(), "name {bad:?}");
        }
    }

    #[test]
    fn validate_rejects_oversized_trees() {
        // Depth: nested Not chain one level beyond the cap.
        let mut p = Predicate::Always;
        for _ in 0..MAX_PREDICATE_DEPTH {
            p = Predicate::Not { child: Box::new(p) };
        }
        let mut r = ok_rule();
        r.when = p;
        assert!(r.validate().is_err(), "depth cap");

        // Breadth: more sibling nodes than the node cap.
        let mut r = ok_rule();
        r.when = Predicate::Any {
            children: vec![Predicate::Always; MAX_PREDICATE_NODES],
        };
        assert!(r.validate().is_err(), "node cap");
    }

    #[test]
    fn spec_wire_shape_is_stable() {
        // The spec JSON is durable state — pin its spelling so a future
        // refactor can't silently change the on-disk format.
        let spec = RuleSpec {
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: "evil.com".into(),
            },
            then: vec![RuleAction::Move {
                folder: "Trash".into(),
            }],
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(
            json,
            r#"{"when":{"kind":"sender","op":"domain","value":"evil.com"},"then":[{"do":"move","folder":"Trash"}]}"#
        );
        let back: RuleSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.when,
            Predicate::Sender {
                op: MatchOp::Domain,
                value: "evil.com".into()
            }
        );
    }
}
