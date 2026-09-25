//! Batch delete / move (T-163) — folder-scoped uid sets, Trash semantics.

use std::sync::Arc;

use tauri::State;

use kiwi_core::session::Protocol;
use kiwi_mail::account::IncomingProtocol;

use super::super::{bounded, gate, run_mail_io};
use super::{bounded_uids, is_trash_name, owned_folder, resolve_trash, uid_set_of};
use crate::commands::mail::connect_imap;
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{CopyResultView, DeleteResultView, MoveResultView};

/// `kiwi_delete_messages(accountId, folderId, uids, permanent?)`.
/// Soft delete moves to Trash (IMAP `UID MOVE`, COPY+DELETE+EXPUNGE
/// fallback inside kiwi-mail); `permanent: true` or deleting FROM Trash
/// marks `\Deleted` + EXPUNGEs. POP3 is local-only.
#[tauri::command]
pub async fn kiwi_delete_messages(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uids: Vec<i64>,
    permanent: Option<bool>,
) -> CmdResult<DeleteResultView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        delete_messages_impl(s, account_id, folder_id, uids, permanent)
    })
    .await
}

pub(crate) async fn delete_messages_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uids: Vec<i64>,
    permanent: Option<bool>,
) -> CmdResult<DeleteResultView> {
    bounded("accountId", &account_id, 128)?;
    let uids = bounded_uids(&uids)?;
    let folder_name = owned_folder(&state, &account_id, folder_id).await?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(&account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;

    // Permanent when asked, or when the source IS the trash (empty-trash /
    // delete-from-trash = expunge).
    let hard = permanent.unwrap_or(false) || is_trash_name(&folder_name);
    let is_imap = acct.incoming.protocol == IncomingProtocol::Imap;

    let mut moved_to_trash = 0u64;
    let mut deleted = 0u64;
    let mut uid_map = std::collections::BTreeMap::new();
    let mut trash_folder_id = None;

    let mut client = if is_imap {
        let mut c = connect_imap(&state, &acct).await?;
        c.select(&folder_name, false)
            .await
            .map_err(IpcError::from)?;
        Some(c)
    } else {
        None
    };

    if hard {
        if let Some(c) = client.as_mut() {
            c.uid_store(&uid_set_of(&uids), "+FLAGS.SILENT", &["\\Deleted"])
                .await
                .map_err(IpcError::from)?;
            c.expunge().await.map_err(IpcError::from)?;
        }
        let store = state.store.lock().await;
        deleted = store.delete_messages(folder_id, &uids)?;
    } else {
        let (trash_id, trash_name) = resolve_trash(&state, &account_id, client.as_mut()).await?;
        if trash_id == folder_id {
            // Resolving Trash returned the source folder — it's trash after
            // all (custom name not in TRASH_NAMES). Permanent path.
            if let Some(c) = client.as_mut() {
                c.uid_store(&uid_set_of(&uids), "+FLAGS.SILENT", &["\\Deleted"])
                    .await
                    .map_err(IpcError::from)?;
                c.expunge().await.map_err(IpcError::from)?;
            }
            let store = state.store.lock().await;
            deleted = store.delete_messages(folder_id, &uids)?;
        } else {
            if let Some(c) = client.as_mut() {
                c.uid_move(&uid_set_of(&uids), &trash_name)
                    .await
                    .map_err(IpcError::from)?;
            }
            let store = state.store.lock().await;
            let pairs = store.move_messages(folder_id, trash_id, &uids)?;
            moved_to_trash = pairs.len() as u64;
            uid_map = pairs.into_iter().collect();
            trash_folder_id = Some(trash_id);
        }
    }

    if let Some(c) = client.as_mut() {
        let facts = observe::facts_of(c.transport());
        observe::record_connection(
            &state,
            facts,
            ObservationContext {
                protocol: Protocol::Imap,
                account_id: Some(account_id.clone()),
                starttls_offered: Some(c.has_capability("STARTTLS")),
                auth_mechanism: crate::commands::mail::auth_mech_of(&acct.incoming.auth),
                auth_succeeded: Some(true),
                label: "imap delete",
            },
        )
        .await;
        let _ = c.logout().await;
    }
    state.audit.lock().await.record(
        "messages-deleted",
        &format!("{account_id}/f{folder_id}: {moved_to_trash}→trash {deleted}×expunge"),
        now_unix(),
    )?;
    Ok(DeleteResultView {
        folder_id,
        moved_to_trash,
        deleted,
        trash_folder_id,
        uid_map,
    })
}

/// `kiwi_move_messages(accountId, srcFolderId, dstFolderId, uids)`.
/// Both folders must belong to `accountId` — moving across accounts is a
/// cross-account write and is refused outright (Agent 5's note). IMAP does
/// `UID MOVE`; POP3 is local-only.
#[tauri::command]
pub async fn kiwi_move_messages(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    src_folder_id: i64,
    dst_folder_id: i64,
    uids: Vec<i64>,
) -> CmdResult<MoveResultView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        move_messages_impl(s, account_id, src_folder_id, dst_folder_id, uids)
    })
    .await
}

pub(crate) async fn move_messages_impl(
    state: Arc<AppState>,
    account_id: String,
    src_folder_id: i64,
    dst_folder_id: i64,
    uids: Vec<i64>,
) -> CmdResult<MoveResultView> {
    bounded("accountId", &account_id, 128)?;
    let uids = bounded_uids(&uids)?;
    if src_folder_id == dst_folder_id {
        return Err(IpcError::invalid("src and dst folders must differ"));
    }
    // Cross-account guard: BOTH folders resolve on this account or the
    // call is refused — the renderer never gets a partial cross-write.
    let src_name = owned_folder(&state, &account_id, src_folder_id).await?;
    let dst_name = owned_folder(&state, &account_id, dst_folder_id).await?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(&account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;

    let mut client = if acct.incoming.protocol == IncomingProtocol::Imap {
        let mut c = connect_imap(&state, &acct).await?;
        c.select(&src_name, false).await.map_err(IpcError::from)?;
        Some(c)
    } else {
        None
    };
    if let Some(c) = client.as_mut() {
        c.uid_move(&uid_set_of(&uids), &dst_name)
            .await
            .map_err(IpcError::from)?;
        let facts = observe::facts_of(c.transport());
        observe::record_connection(
            &state,
            facts,
            ObservationContext {
                protocol: Protocol::Imap,
                account_id: Some(account_id.clone()),
                starttls_offered: Some(c.has_capability("STARTTLS")),
                auth_mechanism: crate::commands::mail::auth_mech_of(&acct.incoming.auth),
                auth_succeeded: Some(true),
                label: "imap move",
            },
        )
        .await;
        let _ = c.logout().await;
    }

    let pairs = state
        .store
        .lock()
        .await
        .move_messages(src_folder_id, dst_folder_id, &uids)?;
    let moved = pairs.len() as u64;
    state.audit.lock().await.record(
        "messages-moved",
        &format!("{account_id}: f{src_folder_id}→f{dst_folder_id} ×{moved}"),
        now_unix(),
    )?;
    Ok(MoveResultView {
        src_folder_id,
        dst_folder_id,
        moved,
        uid_map: pairs.into_iter().collect(),
    })
}

/// `kiwi_copy_messages(accountId, srcFolderId, dstFolderId, uids)` — the
/// Copy-to sibling every real client exposes next to Move-to (T-325).
/// **Store-level only**: no IMAP `UID COPY` — a copy of a synced-folder
/// message is a local duplicate with fresh local uids, never a server
/// copy (that gap is the sync layer's; documented in ipc.md §6k).
/// Destination is refuse-by-construction like move: smart views have no
/// folder row (`owned_folder` → not-found), and **system-origin** folders
/// (INBOX/SENT/TRASH/DRAFTS/JUNK/ARCHIVE) are refused outright — a
/// local-only copy inside a sync-owned mailbox fabricates "received"
/// provenance that the next reconcile would expunge anyway; copy into a
/// local folder instead. (Move keeps its Trash destination because that
/// is the delete path.) Source is untouched.
#[tauri::command]
pub async fn kiwi_copy_messages(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    src_folder_id: i64,
    dst_folder_id: i64,
    uids: Vec<i64>,
) -> CmdResult<CopyResultView> {
    gate(state.inner()).await?;
    copy_messages_impl(
        state.inner(),
        account_id,
        src_folder_id,
        dst_folder_id,
        uids,
    )
    .await
}

pub(crate) async fn copy_messages_impl(
    state: &AppState,
    account_id: String,
    src_folder_id: i64,
    dst_folder_id: i64,
    uids: Vec<i64>,
) -> CmdResult<CopyResultView> {
    bounded("accountId", &account_id, 128)?;
    let uids = bounded_uids(&uids)?;
    if src_folder_id == dst_folder_id {
        return Err(IpcError::invalid("src and dst folders must differ"));
    }
    owned_folder(state, &account_id, src_folder_id).await?;
    let dst_meta = state
        .store
        .lock()
        .await
        .folder_meta(dst_folder_id)?
        .filter(|m| m.account_id == account_id)
        .ok_or_else(|| IpcError::not_found("unknown dstFolderId"))?;
    if dst_meta.origin == kiwi_mail::store::FolderOrigin::System {
        return Err(IpcError::invalid(
            "cannot copy into a system folder — use a local folder",
        ));
    }
    let pairs = state
        .store
        .lock()
        .await
        .copy_messages(src_folder_id, dst_folder_id, &uids)?;
    let copied = pairs.len() as u64;
    state.audit.lock().await.record(
        "messages-copied",
        &format!("{account_id}: f{src_folder_id}→f{dst_folder_id} ×{copied}"),
        now_unix(),
    )?;
    Ok(CopyResultView {
        src_folder_id,
        dst_folder_id,
        copied,
        uid_map: pairs.into_iter().collect(),
    })
}
