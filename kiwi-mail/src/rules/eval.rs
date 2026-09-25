//! The evaluator — `eval(msg) -> actions`, pure and total.
//!
//! No I/O, no clock, no store access: the same `(rules, message)` pair
//! always yields the same [`RuleOutcome`]. That determinism is the F1
//! contract — the app layer re-evaluates at ingest, on refine, and on
//! "run rules now", and every run must agree.
//!
//! Order is fully determined:
//!
//! 1. **Block rules first** (`is_block`), in `position` order — the
//!    block list is evaluated before every regular rule regardless of
//!    where the user dragged it, and the first matching block rule is
//!    *terminal*: its actions apply, nothing else is looked at.
//! 2. **Regular rules** in `position` order (`id` breaks ties — the
//!    ordering is total, so the outcome never depends on slice order).
//!    Every matching rule contributes; flag actions dedupe and at most
//!    one folder disposition (`Move`/`Archive`/`Delete`) is emitted —
//!    the first ordered one wins, since a message can't be in two folders.

use super::model::{MatchOp, Predicate, Rule, RuleAction, RuleOutcome};
use crate::mime::ParsedMessage;

/// Evaluate `rules` against `msg`. Callers pass the rules already in scope
/// for the message's account (`MailStore::list_rules` returns global +
/// account rows); the evaluator applies precedence itself.
/// Evaluate the full ruleset with all parsed-message facts available.
pub fn evaluate(msg: &ParsedMessage, rules: &[Rule]) -> RuleOutcome {
    evaluate_at_stage(msg, rules, true).0
}

/// Stable path/kind evidence for every leaf predicate that evaluates true.
pub(crate) fn condition_hits(
    p: &Predicate,
    msg: &ParsedMessage,
) -> Vec<super::apply::PreviewConditionHit> {
    let mut out = Vec::new();
    collect_condition_hits(p, msg, "$", &mut out);
    out
}

fn collect_condition_hits(
    p: &Predicate,
    msg: &ParsedMessage,
    path: &str,
    out: &mut Vec<super::apply::PreviewConditionHit>,
) {
    let mut leaf = |kind| {
        out.push(super::apply::PreviewConditionHit {
            path: path.to_string(),
            kind,
        })
    };
    match p {
        Predicate::Always => leaf("always"),
        Predicate::Sender { .. } if matches(p, msg) => leaf("sender"),
        Predicate::Recipient { .. } if matches(p, msg) => leaf("recipient"),
        Predicate::Subject { .. } if matches(p, msg) => leaf("subject"),
        Predicate::Header { .. } if matches(p, msg) => leaf("header"),
        Predicate::BodyContains { .. } if matches(p, msg) => leaf("body_contains"),
        Predicate::AttachmentName { .. } if matches(p, msg) => leaf("attachment_name"),
        Predicate::All { children } => {
            for (i, child) in children.iter().enumerate() {
                collect_condition_hits(child, msg, &format!("{path}.children[{i}]"), out);
            }
        }
        Predicate::Any { children } => {
            for (i, child) in children.iter().enumerate() {
                collect_condition_hits(child, msg, &format!("{path}.children[{i}]"), out);
            }
        }
        Predicate::Not { child } => {
            collect_condition_hits(child, msg, &format!("{path}.child"), out)
        }
        _ => {}
    }
}

/// Evaluate rules at an ingest stage. The boolean is a stage-evaluable
/// predicate-tree walk: at envelope stage, header/body/attachment facts are
/// `Deferred` rather than being guessed as false. `deferred` means a full
/// parse is required before a disposition can safely be applied.
pub(crate) fn evaluate_at_stage(
    msg: &ParsedMessage,
    rules: &[Rule],
    full_facts: bool,
) -> (RuleOutcome, bool) {
    let order = |a: &&Rule, b: &&Rule| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id));
    let (mut blocks, mut regulars): (Vec<&Rule>, Vec<&Rule>) =
        rules.iter().filter(|r| r.enabled).partition(|r| r.is_block);
    blocks.sort_by(order);
    regulars.sort_by(order);

    // Block class: first match is terminal. A deferred block may become the
    // first match later, so it also suppresses regular application for now.
    for rule in blocks {
        match truth(&rule.when, msg, full_facts) {
            Truth::True => {
                return (
                    RuleOutcome {
                        actions: dedup(rule.then.iter().cloned()),
                        matched: vec![rule.id.clone()],
                        blocked_by: Some(rule.id.clone()),
                    },
                    false,
                );
            }
            Truth::Deferred => return (RuleOutcome::default(), true),
            Truth::False => {}
        }
    }

    let mut out = RuleOutcome::default();
    let mut disposition_taken = false;
    let mut deferred = false;
    let mut deferred_disposition = false;
    for rule in regulars {
        match truth(&rule.when, msg, full_facts) {
            Truth::True => {
                out.matched.push(rule.id.clone());
                for action in &rule.then {
                    if action.is_disposition() {
                        if disposition_taken {
                            continue; // a later move/archive/delete loses
                        }
                        disposition_taken = true;
                    }
                    if !out.actions.contains(action) {
                        out.actions.push(action.clone());
                    }
                }
            }
            Truth::Deferred => {
                deferred = true;
                deferred_disposition |= rule.then.iter().any(RuleAction::is_disposition);
            }
            Truth::False => {}
        }
    }
    // A later deferred disposition could win first-wins ordering. Leave the
    // whole message for the full sweep instead of applying an unstable result.
    if deferred_disposition {
        (RuleOutcome::default(), true)
    } else {
        (out, deferred)
    }
}

fn dedup(actions: impl Iterator<Item = RuleAction>) -> Vec<RuleAction> {
    let mut out: Vec<RuleAction> = Vec::new();
    for a in actions {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Deferred,
}

/// Three-valued predicate evaluation. At envelope stage, header/body/
/// attachment leaves are unknown rather than false; boolean combinators keep
/// enough information to apply safe facts now and defer only what is needed.
fn truth(p: &Predicate, msg: &ParsedMessage, full_facts: bool) -> Truth {
    match p {
        Predicate::Always => Truth::True,
        Predicate::All { children } => children.iter().fold(Truth::True, |acc, child| {
            combine_all(acc, truth(child, msg, full_facts))
        }),
        Predicate::Any { children } => children.iter().fold(Truth::False, |acc, child| {
            combine_any(acc, truth(child, msg, full_facts))
        }),
        Predicate::Not { child } => match truth(child, msg, full_facts) {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::Deferred => Truth::Deferred,
        },
        Predicate::Header { .. }
        | Predicate::BodyContains { .. }
        | Predicate::AttachmentName { .. }
            if !full_facts =>
        {
            Truth::Deferred
        }
        Predicate::Sender { op, value } => {
            bool_truth(msg.from.iter().any(|a| text_match(*op, &a.email, value)))
        }
        Predicate::Recipient { op, value } => bool_truth(
            msg.to
                .iter()
                .chain(msg.cc.iter())
                .any(|a| text_match(*op, &a.email, value)),
        ),
        Predicate::Subject { op, value } => bool_truth(
            msg.subject
                .as_deref()
                .is_some_and(|s| text_match(*op, s, value)),
        ),
        Predicate::Header { name, op, value } => bool_truth(
            msg.headers
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case(name) && text_match(*op, v, value)),
        ),
        Predicate::BodyContains { value } => {
            let needle = value.to_lowercase();
            bool_truth(
                [&msg.text_body, &msg.html_body].iter().any(|b| {
                    b.as_deref()
                        .is_some_and(|s| s.to_lowercase().contains(&needle))
                }) || msg.snippet.to_lowercase().contains(&needle),
            )
        }
        Predicate::AttachmentName { op, value } => bool_truth(
            msg.attachments
                .iter()
                .filter_map(|a| a.filename.as_deref())
                .any(|f| text_match(*op, f, value)),
        ),
    }
}

fn bool_truth(value: bool) -> Truth {
    if value { Truth::True } else { Truth::False }
}

fn combine_all(a: Truth, b: Truth) -> Truth {
    match (a, b) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Deferred,
    }
}

fn combine_any(a: Truth, b: Truth) -> Truth {
    match (a, b) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Deferred,
    }
}

/// Predicate-tree walk — pure, bounded by `Rule::validate`'s node cap.
fn matches(p: &Predicate, msg: &ParsedMessage) -> bool {
    truth(p, msg, true) == Truth::True
}

/// Leaf comparison. `Contains`/`EndsWith` fold to lowercase (Unicode-aware);
/// `Is` folds ASCII — same convention as `category`'s header checks.
fn text_match(op: MatchOp, haystack: &str, needle: &str) -> bool {
    match op {
        MatchOp::Is => haystack.eq_ignore_ascii_case(needle),
        MatchOp::Contains => haystack.to_lowercase().contains(&needle.to_lowercase()),
        MatchOp::EndsWith => haystack.to_lowercase().ends_with(&needle.to_lowercase()),
        MatchOp::Domain => domain_match(haystack, needle),
    }
}

/// Dot-boundary suffix on the domain part — text after the last `@`, or the
/// whole string when there is none (so `List-Id`-style header values like
/// `list.example.com` get the same semantics). Surrounding `<…>`, quotes,
/// and whitespace are stripped — captured header values arrive raw, so the
/// canonical `<dev.lists.example>` form must still match `lists.example`.
/// `evil.com` matches `a@evil.com` and `a@x.evil.com`, never `a@notevil.com`
/// or `a@evil.com.e`. A leading `@` on the pattern is stripped so
/// "@evil.com" ≡ "evil.com".
fn domain_match(value: &str, pattern: &str) -> bool {
    let delims = |c: char| matches!(c, '<' | '>' | '"' | '\'');
    let dom = value
        .rsplit('@')
        .next()
        .unwrap_or(value)
        .trim()
        .trim_matches(delims)
        .trim()
        .to_lowercase();
    let pat = pattern
        .trim()
        .trim_start_matches('@')
        .trim_matches(delims)
        .trim()
        .to_lowercase();
    !dom.is_empty() && !pat.is_empty() && (dom == pat || dom.ends_with(&format!(".{pat}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime::{Addr, AttachmentMeta};

    fn addr(email: &str) -> Addr {
        Addr {
            name: None,
            email: email.into(),
        }
    }

    /// A baseline message most predicates can see something in.
    fn msg() -> ParsedMessage {
        ParsedMessage {
            subject: Some("Weekly Report".into()),
            from: vec![addr("Alice@Corp.example")],
            to: vec![addr("me@home.example")],
            text_body: Some("hello team".into()),
            ..Default::default()
        }
    }

    #[test]
    fn envelope_deferral_does_not_treat_body_or_attachment_as_false() {
        let envelope = msg();
        let body_rule = rule(
            "body",
            1,
            Predicate::BodyContains {
                value: "report".into(),
            },
            vec![RuleAction::Delete],
        );
        let (outcome, deferred) =
            evaluate_at_stage(&envelope, std::slice::from_ref(&body_rule), false);
        assert_eq!(outcome, RuleOutcome::default());
        assert!(
            deferred,
            "a body disposition cannot be decided from envelope facts"
        );

        let mut full = envelope.clone();
        full.text_body = Some("the report is attached".into());
        let (outcome, deferred) = evaluate_at_stage(&full, &[body_rule], true);
        assert_eq!(outcome.matched, vec!["body"]);
        assert!(!deferred);
    }

    fn rule(id: &str, position: i64, when: Predicate, then: Vec<RuleAction>) -> Rule {
        Rule {
            id: id.into(),
            account_id: None,
            name: id.into(),
            enabled: true,
            position,
            is_block: false,
            when,
            then,
        }
    }

    fn block(id: &str, position: i64, when: Predicate, then: Vec<RuleAction>) -> Rule {
        Rule {
            is_block: true,
            ..rule(id, position, when, then)
        }
    }

    // -- ordering ------------------------------------------------------------

    #[test]
    fn regular_rules_apply_in_position_then_id_order() {
        let rules = vec![
            rule("c", 2, Predicate::Always, vec![RuleAction::Star]),
            rule("b", 1, Predicate::Always, vec![RuleAction::MarkRead]),
            rule("a", 1, Predicate::Always, vec![RuleAction::Archive]),
        ];
        let out = evaluate(&msg(), &rules);
        assert_eq!(out.matched, vec!["a", "b", "c"]);
        assert_eq!(
            out.actions,
            vec![
                RuleAction::Archive, // "a"'s disposition — first ordered wins
                RuleAction::MarkRead,
                RuleAction::Star,
            ]
        );
        assert_eq!(out.blocked_by, None);
    }

    #[test]
    fn input_order_does_not_change_the_outcome() {
        let a = rule("a", 1, Predicate::Always, vec![RuleAction::Star]);
        let b = rule("b", 2, Predicate::Always, vec![RuleAction::MarkRead]);
        let m = msg();
        assert_eq!(
            evaluate(&m, &[a.clone(), b.clone()]),
            evaluate(&m, &[b, a]),
            "slice order must not matter"
        );
    }

    #[test]
    fn non_matching_rules_contribute_nothing() {
        let rules = vec![
            rule(
                "no",
                1,
                Predicate::Subject {
                    op: MatchOp::Contains,
                    value: "absent".into(),
                },
                vec![RuleAction::Delete],
            ),
            rule("yes", 2, Predicate::Always, vec![RuleAction::Star]),
        ];
        let out = evaluate(&msg(), &rules);
        assert_eq!(out.matched, vec!["yes"]);
        assert_eq!(out.actions, vec![RuleAction::Star]);
        assert_eq!(evaluate(&msg(), &[]), RuleOutcome::default());
    }

    #[test]
    fn disabled_rules_never_fire() {
        let mut r = rule("off", 1, Predicate::Always, vec![RuleAction::Delete]);
        r.enabled = false;
        let out = evaluate(&msg(), &[r]);
        assert_eq!(out, RuleOutcome::default());
    }

    #[test]
    fn first_disposition_wins_flag_actions_dedup() {
        let rules = vec![
            rule(
                "r1",
                1,
                Predicate::Always,
                vec![
                    RuleAction::Move {
                        folder: "Work".into(),
                    },
                    RuleAction::MarkRead,
                ],
            ),
            rule(
                "r2",
                2,
                Predicate::Always,
                vec![RuleAction::Delete, RuleAction::Star, RuleAction::MarkRead],
            ),
        ];
        let out = evaluate(&msg(), &rules);
        assert_eq!(
            out.actions,
            vec![
                RuleAction::Move {
                    folder: "Work".into()
                },
                RuleAction::MarkRead, // once, not twice
                RuleAction::Star,
            ]
        );
    }

    // -- block-list precedence -------------------------------------------------

    #[test]
    fn block_rules_win_regardless_of_position_and_terminate() {
        let rules = vec![
            // Sorted lower than the regular rule yet still evaluated first.
            block(
                "blocker",
                99,
                Predicate::Sender {
                    op: MatchOp::Domain,
                    value: "corp.example".into(),
                },
                vec![RuleAction::Delete],
            ),
            rule("regular", 1, Predicate::Always, vec![RuleAction::Star]),
        ];
        let out = evaluate(&msg(), &rules);
        assert_eq!(out.blocked_by.as_deref(), Some("blocker"));
        assert_eq!(out.matched, vec!["blocker"]);
        assert_eq!(out.actions, vec![RuleAction::Delete]);
    }

    #[test]
    fn earliest_block_wins_non_matching_block_falls_through() {
        let rules = vec![
            block("b2", 5, Predicate::Always, vec![RuleAction::Delete]),
            block(
                "b1",
                3,
                Predicate::Subject {
                    op: MatchOp::Contains,
                    value: "report".into(),
                },
                vec![RuleAction::Archive],
            ),
            rule("r", 1, Predicate::Always, vec![RuleAction::Star]),
        ];
        let out = evaluate(&msg(), &rules);
        // b1 (pos 3) fires before b2 (pos 5); regular rules never reached.
        assert_eq!(out.blocked_by.as_deref(), Some("b1"));
        assert_eq!(out.actions, vec![RuleAction::Archive]);

        // When no block matches, regular rules proceed normally.
        let rules = vec![
            block(
                "miss",
                1,
                Predicate::Sender {
                    op: MatchOp::Is,
                    value: "nobody@x.example".into(),
                },
                vec![RuleAction::Delete],
            ),
            rule("r", 2, Predicate::Always, vec![RuleAction::Star]),
        ];
        let out = evaluate(&msg(), &rules);
        assert_eq!(out.blocked_by, None);
        assert_eq!(out.matched, vec!["r"]);
        assert_eq!(out.actions, vec![RuleAction::Star]);
    }

    // -- predicate coverage ----------------------------------------------------

    #[test]
    fn sender_predicates() {
        let m = msg();
        let sender = |op, v: &str| Predicate::Sender {
            op,
            value: v.into(),
        };
        assert!(matches(&sender(MatchOp::Is, "alice@corp.example"), &m));
        assert!(matches(&sender(MatchOp::Contains, "corp"), &m));
        assert!(matches(&sender(MatchOp::Domain, "corp.example"), &m));
        // Dot boundary: subdomain matches, look-alike suffix does not.
        let mut sub = msg();
        sub.from = vec![addr("a@deep.corp.example")];
        assert!(matches(&sender(MatchOp::Domain, "corp.example"), &sub));
        let mut lookalike = msg();
        lookalike.from = vec![addr("a@notcorp.example")];
        assert!(!matches(
            &sender(MatchOp::Domain, "corp.example"),
            &lookalike
        ));
        assert!(!matches(&sender(MatchOp::Is, "alice@other.example"), &m));
        // Display names are never consulted.
        let mut spoof = msg();
        spoof.from = vec![Addr {
            name: Some("Boss <ceo@corp.example>".into()),
            email: "evil@bad.example".into(),
        }];
        assert!(!matches(&sender(MatchOp::Contains, "corp"), &spoof));
    }

    #[test]
    fn recipient_predicates_cover_to_and_cc() {
        let mut m = msg();
        m.to = vec![addr("a@x.example")];
        m.cc = vec![addr("b@y.example")];
        let hit = Predicate::Recipient {
            op: MatchOp::Domain,
            value: "y.example".into(),
        };
        assert!(matches(&hit, &m));
        let miss = Predicate::Recipient {
            op: MatchOp::Contains,
            value: "z.example".into(),
        };
        assert!(!matches(&miss, &m));
    }

    #[test]
    fn subject_and_body_predicates() {
        let m = msg();
        let subj = |op, v: &str| Predicate::Subject {
            op,
            value: v.into(),
        };
        assert!(matches(&subj(MatchOp::Contains, "weekly"), &m));
        assert!(matches(&subj(MatchOp::Is, "Weekly Report"), &m));
        assert!(!matches(&subj(MatchOp::Contains, "daily"), &m));
        let mut bare = msg();
        bare.subject = None;
        assert!(!matches(&subj(MatchOp::Contains, "weekly"), &bare));

        // Body: text hit, html-only hit, miss.
        assert!(matches(
            &Predicate::BodyContains {
                value: "HELLO".into()
            },
            &m
        ));
        let mut html = msg();
        html.text_body = None;
        html.snippet = String::new();
        html.html_body = Some("<p>Invoice attached</p>".into());
        assert!(matches(
            &Predicate::BodyContains {
                value: "invoice".into()
            },
            &html
        ));
        assert!(!matches(
            &Predicate::BodyContains {
                value: "absent".into()
            },
            &m
        ));
    }

    #[test]
    fn header_predicates() {
        let mut m = msg();
        m.headers = vec![
            ("list-id".into(), "<dev.lists.example>".into()),
            ("x-spam".into(), "YES".into()),
        ];
        let h = |n: &str, op, v: &str| Predicate::Header {
            name: n.into(),
            op,
            value: v.into(),
        };
        assert!(matches(&h("LIST-ID", MatchOp::Contains, "lists."), &m));
        assert!(matches(&h("x-spam", MatchOp::Is, "yes"), &m));
        assert!(matches(&h("list-id", MatchOp::Domain, "lists.example"), &m));
        assert!(!matches(&h("absent-header", MatchOp::Contains, "x"), &m));
        assert!(!matches(&h("list-id", MatchOp::Contains, "other"), &m));
    }

    #[test]
    fn attachment_name_predicates() {
        let mut m = msg();
        m.attachments = vec![
            AttachmentMeta {
                filename: Some("report.PDF".into()),
                ..Default::default()
            },
            AttachmentMeta {
                filename: None, // unnamed part — never matches
                ..Default::default()
            },
        ];
        let att = |op, v: &str| Predicate::AttachmentName {
            op,
            value: v.into(),
        };
        assert!(matches(&att(MatchOp::EndsWith, ".pdf"), &m));
        assert!(matches(&att(MatchOp::Contains, "report"), &m));
        assert!(!matches(&att(MatchOp::EndsWith, ".exe"), &m));
        let bare = msg();
        assert!(!matches(&att(MatchOp::Contains, "report"), &bare));
    }

    #[test]
    fn combinator_semantics() {
        let m = msg();
        let weekly = Predicate::Subject {
            op: MatchOp::Contains,
            value: "weekly".into(),
        };
        let absent = Predicate::Subject {
            op: MatchOp::Contains,
            value: "absent".into(),
        };
        assert!(matches(
            &Predicate::All {
                children: vec![weekly.clone(), Predicate::Always],
            },
            &m
        ));
        assert!(!matches(
            &Predicate::All {
                children: vec![weekly.clone(), absent.clone()],
            },
            &m
        ));
        assert!(matches(
            &Predicate::Any {
                children: vec![absent.clone(), weekly.clone()],
            },
            &m
        ));
        // Deterministic empty-combinator semantics.
        assert!(matches(&Predicate::All { children: vec![] }, &m));
        assert!(!matches(&Predicate::Any { children: vec![] }, &m));
        // Negation nests.
        assert!(matches(
            &Predicate::Not {
                child: Box::new(Predicate::Not {
                    child: Box::new(weekly),
                }),
            },
            &m
        ));
        assert!(!matches(
            &Predicate::Not {
                child: Box::new(Predicate::Always),
            },
            &m
        ));
    }

    #[test]
    fn empty_sender_address_never_domain_matches() {
        let mut m = msg();
        m.from = vec![addr("")];
        assert!(!matches(
            &Predicate::Sender {
                op: MatchOp::Domain,
                value: "corp.example".into(),
            },
            &m
        ));
    }
}
