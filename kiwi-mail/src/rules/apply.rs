//! Executing outcomes — the impure half of the rules engine (T-233).
//!
//! [`crate::rules::evaluate`] decides; this file performs. The split is
//! deliberate: evaluation stays pure/deterministic, while applying is
//! store work (moves remap UIDs, flags merge, hits are written).
//!
//! Ordering inside an apply: **flag actions run before the disposition
//! move** — a move remaps the uid, so `\Seen`/`\Flagged` must be set while
//! the message still lives at its evaluated coordinates. `rule_hits` are
//! recorded first of all: the evidence lands before any effect.
//!
//! Disposition folder names resolve to per-account folders created on
//! demand: `Move{folder}` names its target; `Archive`/`Delete` are intents
//! the engine maps to `ARCHIVE_FOLDER`/`TRASH_FOLDER` — rules express
//! intent, folder plumbing is the store's problem.

use crate::error::Result;
use crate::mime::ParsedMessage;
use crate::store::MailStore;

use super::eval::evaluate;
use super::model::{RuleAction, RuleOutcome};

/// `Archive` resolves here (created on demand).
pub const ARCHIVE_FOLDER: &str = "Archive";
/// `Delete` resolves here — a rule never hard-expunges (T-233). A
/// block-list verdict also lands here even when the block rule carried
/// only flag actions: "block match = trash + stop".
pub const TRASH_FOLDER: &str = "Trash";

/// What applying one message's outcome did — the caller's receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedRules {
    /// Rule ids that fired (echo of `RuleOutcome::matched`).
    pub matched: Vec<String>,
    /// The block-list rule that terminated evaluation, if any.
    pub blocked_by: Option<String>,
    /// Destination folder id when a disposition moved the message.
    pub moved_to_folder: Option<i64>,
    /// Stored flag rows actually changed by flag actions.
    pub flags_changed: u64,
}

/// Ingest entry point: evaluate the account's in-scope rules against the
/// just-parsed `msg` stored at `(folder_id, uid)` and execute the outcome.
/// `now` stamps the audit trail.
pub fn apply_on_ingest(
    store: &MailStore,
    account_id: &str,
    folder_id: i64,
    uid: u64,
    msg: &ParsedMessage,
    now: i64,
) -> Result<AppliedRules> {
    let rules = store.list_rules(Some(account_id))?;
    if rules.is_empty() {
        return Ok(AppliedRules::default());
    }
    let outcome = evaluate(msg, &rules);
    execute(store, account_id, folder_id, uid, msg, &outcome, now)
}

/// Execute an already-computed outcome for the message at
/// `(folder_id, uid)`. Shared by ingest and `apply_now`.
fn execute(
    store: &MailStore,
    account_id: &str,
    folder_id: i64,
    uid: u64,
    msg: &ParsedMessage,
    outcome: &RuleOutcome,
    now: i64,
) -> Result<AppliedRules> {
    if outcome.matched.is_empty() {
        return Ok(AppliedRules::default());
    }
    // Evidence before effect — hits record the eval coordinates; a move
    // remaps the uid but the trail stays where the verdict was made.
    store.record_rule_hits(
        folder_id,
        uid,
        &outcome.matched,
        msg.message_id.as_deref(),
        now,
    )?;

    let mut applied = AppliedRules {
        matched: outcome.matched.clone(),
        blocked_by: outcome.blocked_by.clone(),
        ..Default::default()
    };

    // Flag pass first: \Seen/\Flagged merge while the uid still lives here.
    for action in &outcome.actions {
        let flag = match action {
            RuleAction::MarkRead => Some("\\Seen"),
            RuleAction::Star => Some("\\Flagged"),
            _ => None,
        };
        if let Some(flag) = flag {
            applied.flags_changed += store.set_flag(folder_id, &[uid], flag, true)?;
        }
    }

    // Disposition pass — eval guarantees at most one survives.
    for action in &outcome.actions {
        let name = match action {
            RuleAction::Move { folder } => Some(folder.as_str()),
            RuleAction::Archive => Some(ARCHIVE_FOLDER),
            RuleAction::Delete => Some(TRASH_FOLDER),
            _ => None,
        };
        let Some(name) = name else { continue };
        let dst = store.ensure_folder(account_id, name)?;
        if dst != folder_id && !store.move_messages(folder_id, dst, &[uid])?.is_empty() {
            applied.moved_to_folder = Some(dst);
        }
        break;
    }

    // Block verdicts are a trash disposition even when the matched block
    // rule carried only flag actions (dispatch: trash + stop).
    if outcome.blocked_by.is_some() && applied.moved_to_folder.is_none() {
        let trash = store.ensure_folder(account_id, TRASH_FOLDER)?;
        if trash != folder_id && !store.move_messages(folder_id, trash, &[uid])?.is_empty() {
            applied.moved_to_folder = Some(trash);
        }
    }
    Ok(applied)
}

/// Aggregate receipt for [`apply_now`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyNowReport {
    /// Messages that had a parseable body and were evaluated.
    pub scanned: u64,
    /// Messages at least one rule matched.
    pub matched: u64,
    /// Messages a disposition moved.
    pub moved: u64,
    /// Block-list verdicts applied.
    pub blocked: u64,
    /// Stored flag rows changed across all applied messages.
    pub flags_changed: u64,
    /// Messages skipped because no readable/parseable body exists yet.
    pub skipped_no_body: u64,
}

/// "Run rules now" over an account's existing mailbox (T-233).
///
/// Deterministic: the work list is frozen up front (every `(folder_id,
/// uid)` with a stored body, Trash excluded), so a message a rule moves
/// mid-run is not re-evaluated in its new home — each message is
/// evaluated exactly once. Re-running is idempotent: flag merges and
/// same-folder move no-ops converge, and `rule_hits` `INSERT OR REPLACE`s
/// rather than duplicating.
///
/// Trash is never scanned — rules never resurrect deleted mail.
/// Messages without a parseable body are skipped and counted (absent
/// fact, no guess — same policy as the category backfill).
pub fn apply_now(store: &MailStore, account_id: &str, now: i64) -> Result<ApplyNowReport> {
    let rules = store.list_rules(Some(account_id))?;
    let mut report = ApplyNowReport::default();
    if rules.is_empty() {
        return Ok(report);
    }

    let mut work: Vec<(i64, u64)> = Vec::new();
    for folder in store.list_folders(account_id)? {
        if folder.name.eq_ignore_ascii_case(TRASH_FOLDER) {
            continue;
        }
        for uid in store.folder_uids(folder.id)? {
            work.push((folder.id, uid));
        }
    }

    for (folder_id, uid) in work {
        let Some(path) = store.body_file(folder_id, uid)? else {
            report.skipped_no_body += 1;
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            report.skipped_no_body += 1;
            continue;
        };
        let Ok(parsed) = crate::mime::parse_message(&bytes) else {
            report.skipped_no_body += 1;
            continue;
        };
        report.scanned += 1;
        let outcome = evaluate(&parsed, &rules);
        let applied = execute(store, account_id, folder_id, uid, &parsed, &outcome, now)?;
        if !applied.matched.is_empty() {
            report.matched += 1;
        }
        if applied.moved_to_folder.is_some() {
            report.moved += 1;
        }
        if applied.blocked_by.is_some() {
            report.blocked += 1;
        }
        report.flags_changed += applied.flags_changed;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount,
    };
    use crate::rules::{MatchOp, Predicate, Rule, RuleAction};
    use crate::store::NewMessageMeta;
    use crate::transport::SocketSecurity;

    fn seed() -> (MailStore, i64) {
        let store = MailStore::open_memory().unwrap();
        store
            .upsert_account(&MailAccount {
                account_id: "a1".into(),
                display_name: "T".into(),
                email: "t@x.test".into(),
                incoming: IncomingAccount {
                    protocol: IncomingProtocol::Imap,
                    server: crate::account::ServerConfig {
                        host: "h".into(),
                        port: 993,
                        security: SocketSecurity::ImplicitTls,
                    },
                    auth: AuthRef::None,
                    username: "t@x.test".into(),
                },
                outgoing: OutgoingAccount {
                    server: crate::account::ServerConfig {
                        host: "h".into(),
                        port: 587,
                        security: SocketSecurity::StartTls,
                    },
                    auth: AuthRef::None,
                    username: "t@x.test".into(),
                },
            })
            .unwrap();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        (store, fid)
    }

    fn meta(uid: u64) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some("a@x".into()),
            to_addrs: None,
            date_unix: None,
            size: None,
            flags: vec![],
            has_attachments: false,
            snippet: None,
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    fn sender_rule(id: &str, domain: &str, then: Vec<RuleAction>) -> Rule {
        Rule {
            id: id.into(),
            account_id: None,
            name: id.into(),
            enabled: true,
            position: 1,
            is_block: false,
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: domain.into(),
            },
            then,
        }
    }

    fn parsed(from: &str, subject: &str) -> ParsedMessage {
        ParsedMessage {
            message_id: Some("<m@x>".into()),
            from: vec![crate::mime::Addr {
                name: None,
                email: from.into(),
            }],
            subject: Some(subject.into()),
            ..Default::default()
        }
    }

    fn flags_of(store: &MailStore, fid: i64, uid: u64) -> Vec<String> {
        store
            .list_messages(fid, 10)
            .unwrap()
            .into_iter()
            .find(|m| m.uid == uid)
            .map(|m| m.flags)
            .unwrap_or_default()
    }

    #[test]
    fn ingest_applies_flags_and_move_and_records_hits() {
        let (store, fid) = seed();
        store.upsert_message(fid, &meta(5), 100).unwrap();
        store
            .upsert_rule(&Rule {
                then: vec![
                    RuleAction::MarkRead,
                    RuleAction::Move {
                        folder: "Work".into(),
                    },
                ],
                ..sender_rule("r1", "corp.example", vec![])
            })
            .unwrap();

        let m = parsed("a@corp.example", "hi");
        let applied = apply_on_ingest(&store, "a1", fid, 5, &m, 200).unwrap();
        assert_eq!(applied.matched, vec!["r1"]);
        let work = store
            .folder_meta(applied.moved_to_folder.unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(work.name, "Work");
        // Flags applied pre-move: the message in "Work" (new uid) is read.
        let wfid = applied.moved_to_folder.unwrap();
        let wuid = store.folder_uids(wfid).unwrap()[0];
        assert!(flags_of(&store, wfid, wuid).iter().any(|f| f == "\\Seen"));
        assert!(store.folder_uids(fid).unwrap().is_empty());
        // Audit trail on the eval coordinates.
        let hits = store.list_rule_hits("a1", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "r1");
        assert_eq!(hits[0].folder_id, fid);
        assert_eq!(hits[0].uid, 5);
        assert_eq!(hits[0].message_id.as_deref(), Some("<m@x>"));
    }

    #[test]
    fn block_verdict_trashes_even_with_flag_only_actions() {
        let (store, fid) = seed();
        store.upsert_message(fid, &meta(7), 100).unwrap();
        store
            .upsert_rule(&Rule {
                is_block: true,
                then: vec![RuleAction::MarkRead], // no disposition
                ..sender_rule("blk", "evil.example", vec![])
            })
            .unwrap();

        let applied =
            apply_on_ingest(&store, "a1", fid, 7, &parsed("x@evil.example", "s"), 200).unwrap();
        assert_eq!(applied.blocked_by.as_deref(), Some("blk"));
        let trash = applied.moved_to_folder.unwrap();
        assert_eq!(
            store.folder_meta(trash).unwrap().unwrap().name,
            TRASH_FOLDER
        );
    }

    #[test]
    fn no_rules_or_no_match_is_a_noop() {
        let (store, fid) = seed();
        store.upsert_message(fid, &meta(1), 100).unwrap();
        let m = parsed("a@x.test", "s");
        assert_eq!(
            apply_on_ingest(&store, "a1", fid, 1, &m, 1).unwrap(),
            AppliedRules::default()
        );
        store
            .upsert_rule(&sender_rule("r", "nope.example", vec![RuleAction::Delete]))
            .unwrap();
        assert_eq!(
            apply_on_ingest(&store, "a1", fid, 1, &m, 1).unwrap(),
            AppliedRules::default()
        );
        assert!(store.list_rule_hits("a1", 10).unwrap().is_empty());
    }

    #[test]
    fn apply_now_scans_skips_trash_and_is_idempotent() {
        let (store, inbox) = seed();
        let sent = store.ensure_folder("a1", "Sent").unwrap();
        store.upsert_message(inbox, &meta(1), 100).unwrap();
        store.upsert_message(sent, &meta(2), 100).unwrap();
        let trash = store.ensure_folder("a1", "Trash").unwrap();
        store.upsert_message(trash, &meta(3), 100).unwrap();
        // Bodies on disk for all three (the Trash one must never run).
        for (fid, uid) in [(inbox, 1), (sent, 2), (trash, 3)] {
            store
                .store_body(
                    fid,
                    uid,
                    format!("From: a@corp.example\r\nSubject: s{uid}\r\n\r\nb").as_bytes(),
                )
                .unwrap();
        }
        store
            .upsert_rule(&sender_rule("r1", "corp.example", vec![RuleAction::Star]))
            .unwrap();

        let rep = apply_now(&store, "a1", 500).unwrap();
        assert_eq!(rep.scanned, 2, "trash excluded");
        assert_eq!(rep.matched, 2);
        assert_eq!(rep.flags_changed, 2);
        for (fid, uid) in [(inbox, 1), (sent, 2)] {
            assert!(flags_of(&store, fid, uid).iter().any(|f| f == "\\Flagged"));
        }
        assert!(!flags_of(&store, trash, 3).iter().any(|f| f == "\\Flagged"));

        // Re-run: matches again but changes nothing (merge + replace dedupe).
        let rep2 = apply_now(&store, "a1", 600).unwrap();
        assert_eq!(rep2.matched, 2);
        assert_eq!(rep2.flags_changed, 0);
        assert_eq!(store.list_rule_hits("a1", 10).unwrap().len(), 2);
    }
}
