//! Inbox rules IPC (F1 surface, T-233). All commands are gated — rule
//! state is mailbox state, closed while the endpoint is locked.
//!
//! The renderer is untrusted: `RuleView` input is converted to
//! `kiwi_mail::rules::Rule` and stored only through
//! `MailStore::upsert_rule`, which re-runs `Rule::validate` at the
//! boundary — malformed predicate trees and oversized fields fail with
//! `invalid-input` before touching the table.

use std::sync::Arc;

use serde_json::json;
use tauri::State;

use kiwi_mail::rules::{self, Rule};

use super::{bounded, clamp_u32, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{RuleHitView, RulePreviewView, RuleView, RulesApplyView};

/// `kiwi_rules_list { accountId? }` — with `accountId`: the rules in
/// scope for that account (global + its own), evaluation order. Without
/// it: global rules only.
#[tauri::command]
pub async fn kiwi_rules_list(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
) -> CmdResult<Vec<RuleView>> {
    gate(state.inner()).await?;
    rules_list_impl(state.inner(), account_id.as_deref()).await
}

async fn rules_list_impl(state: &AppState, account_id: Option<&str>) -> CmdResult<Vec<RuleView>> {
    if let Some(a) = account_id {
        bounded("accountId", a, 128)?;
    }
    let store = state.store.lock().await;
    Ok(store
        .list_rules(account_id)?
        .into_iter()
        .map(RuleView::from)
        .collect())
}

/// `kiwi_rules_upsert { rule: RuleView }` → the stored rule. Create-or-
/// replace by `id`. Validation failures → `invalid-input`.
#[tauri::command]
pub async fn kiwi_rules_upsert(
    state: State<'_, Arc<AppState>>,
    rule: RuleView,
) -> CmdResult<RuleView> {
    gate(state.inner()).await?;
    rules_upsert_impl(state.inner(), rule).await
}

async fn rules_upsert_impl(state: &AppState, view: RuleView) -> CmdResult<RuleView> {
    let rule = Rule::from(view);
    if let Some(a) = &rule.account_id {
        bounded("accountId", a, 128)?;
        if state.store.lock().await.get_account(a)?.is_none() {
            return Err(IpcError::not_found("unknown account"));
        }
    }
    // `upsert_rule` runs Rule::validate — the store-side gate.
    state.store.lock().await.upsert_rule(&rule)?;
    Ok(RuleView::from(rule))
}

/// `kiwi_rules_delete { ruleId }` → `{ removed }`.
#[tauri::command]
pub async fn kiwi_rules_delete(
    state: State<'_, Arc<AppState>>,
    rule_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    rules_delete_impl(state.inner(), &rule_id).await
}

async fn rules_delete_impl(state: &AppState, rule_id: &str) -> CmdResult<serde_json::Value> {
    bounded("ruleId", rule_id, 64)?;
    let removed = state.store.lock().await.delete_rule(rule_id)?;
    Ok(json!({ "removed": removed }))
}

/// `kiwi_rules_apply_now { accountId }` → `RulesApplyView`. Re-runs the
/// evaluator over the account's stored mailbox (Trash excluded; one eval
/// per message) and executes outcomes. Idempotent — safe to re-run.
#[tauri::command]
pub async fn kiwi_rules_apply_now(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<RulesApplyView> {
    gate(state.inner()).await?;
    rules_apply_now_impl(state.inner(), &account_id).await
}

async fn rules_apply_now_impl(state: &AppState, account_id: &str) -> CmdResult<RulesApplyView> {
    bounded("accountId", account_id, 128)?;
    let store = state.store.lock().await;
    if store.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    let report = rules::apply_now(&store, account_id, now_unix())?;
    Ok(RulesApplyView::from(report))
}

/// `kiwi_rules_hits { accountId, limit? }` — the matched-rule audit
/// trail, newest first (`limit` default 100, clamp 1–1000). `ruleId`
/// survives rule deletion — it is evidence, not a join.
#[tauri::command]
pub async fn kiwi_rules_hits(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    limit: Option<u32>,
) -> CmdResult<Vec<RuleHitView>> {
    gate(state.inner()).await?;
    rules_hits_impl(state.inner(), &account_id, limit).await
}

async fn rules_hits_impl(
    state: &AppState,
    account_id: &str,
    limit: Option<u32>,
) -> CmdResult<Vec<RuleHitView>> {
    bounded("accountId", account_id, 128)?;
    if state.store.lock().await.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    let limit = clamp_u32(limit, 100, 1000);
    Ok(state
        .store
        .lock()
        .await
        .list_rule_hits(account_id, limit)?
        .into_iter()
        .map(RuleHitView::from)
        .collect())
}

/// `kiwi_rules_preview { accountId, rule, limit? }` → `RulePreviewView`.
/// Dry-run a candidate rule against the newest stored messages — powers
/// the editor's "test this rule" button. NEVER executes actions, records
/// hits, or writes eval watermarks. `limit` default 50, clamp 1–200.
#[tauri::command]
pub async fn kiwi_rules_preview(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    rule: RuleView,
    limit: Option<u32>,
) -> CmdResult<RulePreviewView> {
    gate(state.inner()).await?;
    rules_preview_impl(state.inner(), &account_id, rule, limit).await
}

async fn rules_preview_impl(
    state: &AppState,
    account_id: &str,
    view: RuleView,
    limit: Option<u32>,
) -> CmdResult<RulePreviewView> {
    bounded("accountId", account_id, 128)?;
    let rule = Rule::from(view);
    // Candidate is renderer input — same bounds gate as the store write.
    rule.validate().map_err(IpcError::from)?;
    let store = state.store.lock().await;
    if store.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    let limit = clamp_u32(limit, 50, 200);
    Ok(RulePreviewView::from(rules::preview_rule(
        &store, account_id, &rule, limit,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::rules::{MatchOp, Predicate, RuleAction};

    async fn state_with_account(tag: &str) -> (Arc<AppState>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-rules-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let acct = kiwi_mail::account::MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: kiwi_mail::account::IncomingAccount {
                protocol: kiwi_mail::account::IncomingProtocol::Imap,
                server: kiwi_mail::account::ServerConfig {
                    host: "h".into(),
                    port: 993,
                    security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
            outgoing: kiwi_mail::account::OutgoingAccount {
                server: kiwi_mail::account::ServerConfig {
                    host: "h".into(),
                    port: 587,
                    security: kiwi_mail::transport::SocketSecurity::StartTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
        };
        state.store.lock().await.upsert_account(&acct).unwrap();
        (Arc::new(state), dir)
    }

    fn view(id: &str, account: Option<&str>) -> RuleView {
        RuleView {
            id: id.into(),
            account_id: account.map(str::to_string),
            name: id.into(),
            enabled: true,
            position: 1,
            is_block: false,
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: "x.example".into(),
            },
            then: vec![RuleAction::MarkRead],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upsert_list_delete_roundtrip_and_validate_gate() {
        let (state, dir) = state_with_account("crud").await;
        // Invalid input → invalid-input code, nothing stored.
        let mut bad = view("bad", None);
        bad.then = vec![];
        let err = rules_upsert_impl(&state, bad).await.unwrap_err();
        assert_eq!(err.code, "invalid-input");

        rules_upsert_impl(&state, view("g1", None)).await.unwrap();
        rules_upsert_impl(&state, view("a1r", Some("a1")))
            .await
            .unwrap();
        // Unknown account scope rejected.
        let err = rules_upsert_impl(&state, view("ghost", Some("nope")))
            .await
            .unwrap_err();
        assert_eq!(err.code, "not-found");

        let all = rules_list_impl(&state, Some("a1")).await.unwrap();
        assert_eq!(all.len(), 2);
        let globals = rules_list_impl(&state, None).await.unwrap();
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].id, "g1");

        let r = rules_delete_impl(&state, "g1").await.unwrap();
        assert_eq!(r["removed"], true);
        assert_eq!(rules_list_impl(&state, None).await.unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn apply_now_and_hits_surface() {
        let (state, dir) = state_with_account("hits").await;
        let store = state.store.lock().await;
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store
            .upsert_message(
                fid,
                &kiwi_mail::store::NewMessageMeta {
                    uid: 9,
                    message_id: Some("<m9@x>".into()),
                    subject: Some("s".into()),
                    from_addr: Some("a@x.example".into()),
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
                },
                now_unix(),
            )
            .unwrap();
        store
            .store_body(
                fid,
                9,
                b"From: a@x.example\r\nSubject: s\r\nMessage-Id: <m9@x>\r\n\r\nhi",
            )
            .unwrap();
        drop(store);

        rules_upsert_impl(&state, view("r9", Some("a1")))
            .await
            .unwrap();
        let rep = rules_apply_now_impl(&state, "a1").await.unwrap();
        assert_eq!(rep.scanned, 1);
        assert_eq!(rep.matched, 1);
        assert_eq!(rep.flags_changed, 1);

        let hits = rules_hits_impl(&state, "a1", None).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "r9");
        // ParsedMessage normalizes Message-Id (strips <>).
        assert_eq!(hits[0].message_id.as_deref(), Some("m9@x"));

        // Unknown account → not-found, not a zero report.
        let err = rules_apply_now_impl(&state, "ghost").await.unwrap_err();
        assert_eq!(err.code, "not-found");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preview_dry_run_matches_and_writes_nothing() {
        let (state, dir) = state_with_account("prev").await;
        let fid = {
            let store = state.store.lock().await;
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            for uid in [1u64, 2] {
                store
                    .upsert_message(
                        fid,
                        &kiwi_mail::store::NewMessageMeta {
                            uid,
                            message_id: None,
                            subject: Some(format!("m{uid}")),
                            from_addr: Some(format!("u{uid}@x.example")),
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
                        },
                        now_unix(),
                    )
                    .unwrap();
            }
            // Only uid 1's sender matches the candidate; uid 2 has a body
            // too, so both are scanned.
            for uid in [1u64, 2] {
                store
                    .store_body(
                        fid,
                        uid,
                        format!("From: u{uid}@x.example\r\nSubject: m{uid}\r\n\r\nb").as_bytes(),
                    )
                    .unwrap();
            }
            fid
        };

        // Candidate matches domain x.example via uid 1 — and nothing else.
        let mut cand = view("cand", Some("a1"));
        cand.when = Predicate::Sender {
            op: MatchOp::Is,
            value: "u1@x.example".into(),
        };
        cand.then = vec![RuleAction::Delete];
        let p = rules_preview_impl(&state, "a1", cand, None).await.unwrap();
        assert_eq!(p.scanned, 2);
        assert_eq!(p.matched, 1);
        assert_eq!(p.hits[0].uid, 1);
        assert_eq!(p.hits[0].folder, "INBOX");

        // Nothing executed: uid 1 is still in INBOX, unread, no hit rows,
        // and its eval watermark slot is untouched.
        let store = state.store.lock().await;
        assert_eq!(store.folder_uids(fid).unwrap(), vec![1, 2]);
        assert!(store.list_rule_hits("a1", 10).unwrap().is_empty());
        assert_eq!(store.uids_pending_body_eval(fid, 10).unwrap().len(), 2);

        // Invalid candidate → invalid-input before touching the store.
        let mut bad = view("bad", None);
        bad.then = vec![];
        let err = rules_preview_impl(&state, "a1", bad, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid-input");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
