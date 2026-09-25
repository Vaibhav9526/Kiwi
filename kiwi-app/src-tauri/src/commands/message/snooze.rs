//! Snooze (T-255) — reversible local-only parking. Parked messages keep
//! their `messages` row exactly where it is (never moved, never trashed):
//! folder lists hide them via the `snoozed` table, the Snoozed view lists
//! them account-wide, and the sync-pass sweep (`MailStore::unsnooze_due`)
//! releases them when the deadline passes. No IMAP write-through exists —
//! snooze is deliberately NOT a server-side move, so a parked remote uid
//! is never re-downloaded as new mail.
//!
//! No undo-send grace: the state flip is one bounded write, and
//! unsnooze is always available.

use std::collections::BTreeMap;
use std::sync::Arc;

use tauri::State;

use super::super::{bounded, clamp_u32, gate};
use super::is_trash_name;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{MessageRefInput, SnoozeResultView, SnoozedMessageView, UnsnoozeResultView};

/// One call's `refs` ceiling — same bound class as `bounded_uids`.
const MAX_SNOOZE_REFS: usize = 500;

/// Explicit `untilUnix` ceiling: ~2 years out. Anything past it is a
/// renderer bug (e.g. milliseconds) — refuse rather than park forever.
const MAX_SNOOZE_AHEAD_SECS: i64 = 2 * 366 * 24 * 60 * 60;

// Preset offsets (ipc.md §6e — server-resolved so every client agrees).
const LATER_TODAY_SECS: i64 = 3 * 60 * 60;
const TOMORROW_SECS: i64 = 24 * 60 * 60;
const NEXT_WEEK_SECS: i64 = 7 * 24 * 60 * 60;

/// Resolve the deadline: exactly one of `untilUnix` / `preset`, presets
/// are fixed offsets from `now` (documented contract; wall-clock-aware
/// presets need a TZ database — flagged to Lead rather than assumed).
fn resolve_until(preset: Option<&str>, until_unix: Option<i64>, now: i64) -> CmdResult<i64> {
    let preset = match preset {
        None => None,
        Some("later_today") => Some(LATER_TODAY_SECS),
        Some("tomorrow") => Some(TOMORROW_SECS),
        Some("next_week") => Some(NEXT_WEEK_SECS),
        Some(_) => return Err(IpcError::invalid("unknown snooze preset")),
    };
    match (preset, until_unix) {
        (Some(off), None) => Ok(now + off),
        (None, Some(t)) if t > now && t - now <= MAX_SNOOZE_AHEAD_SECS => Ok(t),
        (None, Some(_)) => Err(IpcError::invalid(
            "untilUnix must be a future unix timestamp ≤ ~2y out",
        )),
        (None, None) => Err(IpcError::invalid("pass untilUnix or preset")),
        (Some(_), Some(_)) => Err(IpcError::invalid(
            "pass either untilUnix or preset, not both",
        )),
    }
}

/// Validate `refs` (non-empty, ≤500, non-negative, deduped) and prove
/// every referenced folder belongs to `account_id`. Returns
/// `folder_id → uids` grouped for the store calls. Shared by the junk
/// command (T-263) — `pub(super)` keeps it out of the glob re-export.
pub(super) async fn owned_refs(
    state: &AppState,
    account_id: &str,
    refs: &[MessageRefInput],
) -> CmdResult<BTreeMap<i64, Vec<u64>>> {
    if refs.is_empty() {
        return Err(IpcError::invalid("refs must be non-empty"));
    }
    if refs.len() > MAX_SNOOZE_REFS {
        return Err(IpcError::invalid("refs exceeds 500 bound"));
    }
    let mut by_folder: BTreeMap<i64, Vec<u64>> = BTreeMap::new();
    for r in refs {
        if r.folder_id < 0 || r.uid < 0 {
            return Err(IpcError::invalid("folderId and uid must be >= 0"));
        }
        by_folder.entry(r.folder_id).or_default().push(r.uid as u64);
    }
    // Cross-account guard — same contract as move/delete: every folder in
    // the ref set must belong to this account or the call is refused.
    {
        let store = state.store.lock().await;
        for fid in by_folder.keys() {
            let meta = store
                .folder_meta(*fid)?
                .ok_or_else(|| IpcError::not_found("unknown folder"))?;
            if meta.account_id != account_id {
                return Err(IpcError::not_found("folder not on account"));
            }
        }
    }
    for uids in by_folder.values_mut() {
        uids.sort_unstable();
        uids.dedup();
    }
    Ok(by_folder)
}

/// `kiwi_message_snooze { accountId, refs: [{folderId,uid}], untilUnix? ,
/// preset? }` → `SnoozeResultView`. Exactly one deadline source required;
/// `preset` ∈ `later_today` | `tomorrow` | `next_week` (fixed offsets,
/// resolved server-side). Never moves mail — the rows just leave the
/// folder listings until the sweep releases them.
#[tauri::command]
pub async fn kiwi_message_snooze(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    refs: Vec<MessageRefInput>,
    until_unix: Option<i64>,
    preset: Option<String>,
) -> CmdResult<SnoozeResultView> {
    gate(state.inner()).await?;
    snooze_impl(
        state.inner(),
        &account_id,
        refs,
        until_unix,
        preset.as_deref(),
    )
    .await
}

pub(crate) async fn snooze_impl(
    state: &AppState,
    account_id: &str,
    refs: Vec<MessageRefInput>,
    until_unix: Option<i64>,
    preset: Option<&str>,
) -> CmdResult<SnoozeResultView> {
    bounded("accountId", account_id, 128)?;
    let now = now_unix();
    let until = resolve_until(preset, until_unix, now)?;
    let by_folder = owned_refs(state, account_id, &refs).await?;
    let mut snoozed = 0u64;
    {
        let store = state.store.lock().await;
        for (fid, uids) in &by_folder {
            snoozed += store.set_snooze(*fid, uids, until, now)?;
        }
    }
    state.audit.lock().await.record(
        "messages-snoozed",
        &format!("{account_id}: {snoozed} parked until {until}"),
        now,
    )?;
    Ok(SnoozeResultView {
        snoozed,
        until_unix: until,
    })
}

/// `kiwi_message_unsnooze { accountId, refs }` → `UnsnoozeResultView`.
/// Releases parked messages in place — they reappear in whatever folder
/// they live in (snooze never moved them). Idempotent.
#[tauri::command]
pub async fn kiwi_message_unsnooze(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    refs: Vec<MessageRefInput>,
) -> CmdResult<UnsnoozeResultView> {
    gate(state.inner()).await?;
    unsnooze_impl(state.inner(), &account_id, refs).await
}

pub(crate) async fn unsnooze_impl(
    state: &AppState,
    account_id: &str,
    refs: Vec<MessageRefInput>,
) -> CmdResult<UnsnoozeResultView> {
    bounded("accountId", account_id, 128)?;
    let by_folder = owned_refs(state, account_id, &refs).await?;
    let mut unsnoozed = 0u64;
    {
        let store = state.store.lock().await;
        for (fid, uids) in &by_folder {
            unsnoozed += store.clear_snooze(*fid, uids)?;
        }
    }
    state.audit.lock().await.record(
        "messages-unsnoozed",
        &format!("{account_id}: {unsnoozed} released"),
        now_unix(),
    )?;
    Ok(UnsnoozeResultView { unsnoozed })
}

/// `kiwi_list_snoozed { accountId, limit? }` → `SnoozedMessageView[]`.
/// The account's parked mail, soonest-due first. Rows parked into a
/// Trash-named folder are still released on schedule but hidden from the
/// view — trash is the stronger state. `limit` default 200, clamp 1–1000.
#[tauri::command]
pub async fn kiwi_list_snoozed(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    limit: Option<u32>,
) -> CmdResult<Vec<SnoozedMessageView>> {
    gate(state.inner()).await?;
    list_snoozed_impl(state.inner(), &account_id, limit).await
}

pub(crate) async fn list_snoozed_impl(
    state: &AppState,
    account_id: &str,
    limit: Option<u32>,
) -> CmdResult<Vec<SnoozedMessageView>> {
    bounded("accountId", account_id, 128)?;
    let limit = clamp_u32(limit, 200, 1000);
    let store = state.store.lock().await;
    if store.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    Ok(store
        .list_snoozed(account_id, limit)?
        .into_iter()
        .filter(|m| !is_trash_name(&m.folder_name))
        .map(|m| SnoozedMessageView {
            folder_id: m.folder_id,
            uid: m.uid,
            folder: m.folder_name,
            snoozed_from_folder_id: m.from_folder_id,
            snoozed_until: m.until_unix,
            snoozed_at: m.set_at_unix,
            subject: m.subject,
            from_addr: m.from_addr,
            message_id: m.message_id,
            date_unix: m.date_unix,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use kiwi_mail::transport::SocketSecurity;

    async fn state_with_msg(tag: &str) -> (Arc<AppState>, std::path::PathBuf, i64) {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-snooze-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let acct = MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "h".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "h".into(),
                    port: 587,
                    security: SocketSecurity::StartTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
        };
        let store = state.store.lock().await;
        store.upsert_account(&acct).unwrap();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        for uid in [1u64, 2] {
            store
                .upsert_message(
                    fid,
                    &kiwi_mail::store::NewMessageMeta {
                        uid,
                        message_id: None,
                        subject: Some(format!("s{uid}")),
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
        drop(store);
        (Arc::new(state), dir, fid)
    }

    fn rf(folder_id: i64, uid: i64) -> MessageRefInput {
        MessageRefInput { folder_id, uid }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn snooze_hides_lists_and_unsnooze_restores() {
        let (state, dir, fid) = state_with_msg("rt").await;
        let rep = snooze_impl(
            &state,
            "a1",
            vec![rf(fid, 1)],
            Some(now_unix() + 3600),
            None,
        )
        .await
        .unwrap();
        assert_eq!(rep.snoozed, 1);
        // Hidden from the folder list, present in the Snoozed view.
        {
            let store = state.store.lock().await;
            assert_eq!(store.list_messages(fid, 10).unwrap().len(), 1);
        }
        let parked = list_snoozed_impl(&state, "a1", None).await.unwrap();
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].uid, 1);
        assert_eq!(parked[0].folder, "INBOX");
        assert_eq!(parked[0].snoozed_from_folder_id, fid);

        let rel = unsnooze_impl(&state, "a1", vec![rf(fid, 1)]).await.unwrap();
        assert_eq!(rel.unsnoozed, 1);
        let store = state.store.lock().await;
        assert_eq!(store.list_messages(fid, 10).unwrap().len(), 2);
        assert!(store.list_snoozed("a1", 10).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deadline_resolution_and_bounds() {
        let now = now_unix();
        // preset mapping
        assert_eq!(
            resolve_until(Some("later_today"), None, now).unwrap(),
            now + LATER_TODAY_SECS
        );
        assert_eq!(
            resolve_until(Some("tomorrow"), None, now).unwrap(),
            now + TOMORROW_SECS
        );
        assert_eq!(
            resolve_until(Some("next_week"), None, now).unwrap(),
            now + NEXT_WEEK_SECS
        );
        // explicit future deadline ok
        assert_eq!(resolve_until(None, Some(now + 60), now).unwrap(), now + 60);
        // every violation → invalid-input
        for (p, u) in [
            (Some("bogus"), None),
            (Some("tomorrow"), Some(now + 60)),
            (None, None),
            (None, Some(now)),
            (None, Some(now - 1)),
            (None, Some(now + MAX_SNOOZE_AHEAD_SECS + 1)),
        ] {
            let e = resolve_until(p, u, now).unwrap_err();
            assert_eq!(e.code, "invalid-input", "{p:?}/{u:?}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refs_validated_and_folder_owned() {
        let (state, dir, fid) = state_with_msg("own").await;
        // Empty refs, negative coords, oversize → invalid-input.
        for bad in [
            vec![],
            vec![rf(-1, 1)],
            vec![rf(fid, -2)],
            vec![rf(fid, 1); MAX_SNOOZE_REFS + 1],
        ] {
            let e = snooze_impl(&state, "a1", bad, Some(now_unix() + 60), None)
                .await
                .unwrap_err();
            assert_eq!(e.code, "invalid-input");
        }
        // Unknown folder id → not-found.
        let e = snooze_impl(&state, "a1", vec![rf(9999, 1)], Some(now_unix() + 60), None)
            .await
            .unwrap_err();
        assert_eq!(e.code, "not-found");
        // Unknown account → not-found (folder lookup precedes account proof
        // here: the folder can't belong to a missing account either way).
        let e = snooze_impl(
            &state,
            "ghost",
            vec![rf(fid, 1)],
            Some(now_unix() + 60),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, "not-found");
        // Duplicate refs collapse — two parked, not three.
        let rep = snooze_impl(
            &state,
            "a1",
            vec![rf(fid, 1), rf(fid, 1), rf(fid, 2)],
            Some(now_unix() + 60),
            None,
        )
        .await
        .unwrap();
        assert_eq!(rep.snoozed, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
