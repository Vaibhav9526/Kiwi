//! Flag mutation / archive (T-146): `seen` → `\Seen`, `starred` →
//! `\Flagged`, `archived` → move to/from the Archive folder.
//!
//! Local store write-through (`update_flags`) + live `UID STORE` for IMAP
//! accounts; POP3 is local-only (no server-side flags exist). Archive uses
//! IMAP `UID MOVE` (COPY+DELETE+EXPUNGE fallback inside kiwi-mail).

use std::sync::Arc;

use tauri::State;

use kiwi_core::session::Protocol;
use kiwi_mail::account::IncomingProtocol;
use kiwi_mail::store::NewMessageMeta;

use super::super::{bounded, gate, run_mail_io};
use crate::commands::mail::connect_imap;
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{MessagePatchInput, MessageUpdateView};

/// Conventional archive mailbox name (RFC 6154 \Archive special-use).
const ARCHIVE_FOLDER: &str = "Archive";

/// Patch a message: `seen` → `\Seen`, `starred` → `\Flagged`,
/// `archived` → move to/from the Archive folder.
#[tauri::command]
pub async fn kiwi_update_message(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    patch: MessagePatchInput,
) -> CmdResult<MessageUpdateView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        update_message_impl(s, account_id, folder_id, uid, patch)
    })
    .await
}

pub(crate) async fn update_message_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    patch: MessagePatchInput,
) -> CmdResult<MessageUpdateView> {
    bounded("accountId", &account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    let uid = uid as u64;
    if patch.seen.is_none() && patch.starred.is_none() && patch.archived.is_none() {
        return Err(IpcError::invalid("patch must change at least one flag"));
    }

    let (folder_name, proto, acct) = {
        let store = state.store.lock().await;
        let meta = store
            .folder_meta(folder_id)?
            .ok_or_else(|| IpcError::not_found("unknown folder"))?;
        if meta.account_id != account_id {
            return Err(IpcError::not_found("folder not on account"));
        }
        let acct = store
            .get_account(&account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        (meta.name, acct.incoming.protocol, acct)
    };

    // Current flags → desired flag set.
    let mut flags: Vec<String> = {
        let store = state.store.lock().await;
        let msgs = store.list_messages(folder_id, 10_000)?;
        msgs.iter()
            .find(|m| m.uid == uid)
            .ok_or_else(|| IpcError::not_found("message not in folder"))?
            .flags
            .clone()
    };
    let set_flag = |flags: &mut Vec<String>, name: &str, on: Option<bool>| match on {
        Some(true) if !flags.iter().any(|f| f.eq_ignore_ascii_case(name)) => {
            flags.push(name.to_string())
        }
        Some(false) => flags.retain(|f| !f.eq_ignore_ascii_case(name)),
        _ => {}
    };
    set_flag(&mut flags, "\\Seen", patch.seen);
    set_flag(&mut flags, "\\Flagged", patch.starred);

    // IMAP write-through: one live connection does flags + move together.
    let mut moved_to = None;
    let mut client = if proto == IncomingProtocol::Imap
        && (patch.seen.is_some() || patch.starred.is_some() || patch.archived.is_some())
    {
        let mut c = connect_imap(&state, &acct).await?;
        c.select(&folder_name, false)
            .await
            .map_err(IpcError::from)?;
        Some(c)
    } else {
        None
    };

    if let Some(c) = client.as_mut() {
        // Per-flag ops — "+FLAGS" / "-FLAGS" with SILENT (untagged-only).
        if let Some(v) = patch.seen {
            c.uid_store(
                &uid.to_string(),
                if v { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" },
                &["\\Seen"],
            )
            .await
            .map_err(IpcError::from)?;
        }
        if let Some(v) = patch.starred {
            c.uid_store(
                &uid.to_string(),
                if v { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" },
                &["\\Flagged"],
            )
            .await
            .map_err(IpcError::from)?;
        }
    }

    // Local flag write-through (even when offline — the next sync
    // reconciles; store flags are the list-view source of truth).
    {
        let store = state.store.lock().await;
        store.update_flags(folder_id, uid, &flags)?;
    }

    // Archive: move to Archive folder (or back to INBOX on unarchive).
    if let Some(archived) = patch.archived {
        let target = if archived { ARCHIVE_FOLDER } else { "INBOX" };
        let dest_id = {
            let store = state.store.lock().await;
            store.ensure_folder(&account_id, target)?
        };
        {
            let mut index = state.index.lock().await;
            index.remember_folder(&account_id, dest_id, target);
            index.save(&state.data_dir)?;
        }
        if let Some(c) = &mut client {
            // Mailbox may not exist server-side yet — create is idempotent.
            let _ = c.create_mailbox(target).await;
            c.uid_move(&uid.to_string(), target)
                .await
                .map_err(IpcError::from)?;
        }
        move_local(&state, folder_id, dest_id, uid).await?;
        moved_to = Some(dest_id);
    }

    // Record the connection if one was opened.
    if let Some(c) = &mut client {
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
                label: "imap update",
            },
        )
        .await;
        let _ = c.logout().await;
    }

    state.audit.lock().await.record(
        "message-updated",
        &format!(
            "{account_id}/f{folder_id}/u{uid}: {:?}",
            patch_summary(&patch)
        ),
        now_unix(),
    )?;

    // T-345: a flag/mailbox change can move the global unread number.
    crate::tray::refresh_tooltip(&state).await;

    Ok(MessageUpdateView {
        folder_id,
        uid,
        flags,
        moved_to_folder_id: moved_to,
    })
}

fn patch_summary(p: &MessagePatchInput) -> String {
    let mut s = Vec::new();
    if let Some(v) = p.seen {
        s.push(format!("seen={v}"));
    }
    if let Some(v) = p.starred {
        s.push(format!("starred={v}"));
    }
    if let Some(v) = p.archived {
        s.push(format!("archived={v}"));
    }
    s.join(" ")
}

/// Local move: upsert the meta row into the destination folder (same uid —
/// uids are folder-scoped), copy the stored body, delete the source row.
async fn move_local(
    state: &AppState,
    src_folder: i64,
    dest_folder: i64,
    uid: u64,
) -> CmdResult<()> {
    let store = state.store.lock().await;
    let msgs = store.list_messages(src_folder, 10_000)?;
    let m = msgs
        .iter()
        .find(|m| m.uid == uid)
        .ok_or_else(|| IpcError::not_found("message not in folder"))?
        .clone();
    store.upsert_message(
        dest_folder,
        &NewMessageMeta {
            uid,
            message_id: m.message_id.clone(),
            subject: m.subject.clone(),
            from_addr: m.from_addr.clone(),
            to_addrs: m.to_addrs.clone(),
            date_unix: m.date_unix,
            size: m.size,
            flags: m.flags.clone(),
            has_attachments: m.has_attachments,
            snippet: m.snippet.clone(),
            // Row copy (archive move): the tab travels with the message.
            category: m.category,
            // …as does the unsubscribe offer (F3).
            unsub_http: m.unsub_http.clone(),
            unsub_mailto: m.unsub_mailto.clone(),
            unsub_oneclick: m.unsub_oneclick,
        },
        now_unix(),
    )?;
    // Copy the stored body before deleting the source row (delete removes
    // the row; the body file is folder-scoped, so copy bytes first).
    if let Some(p) = store.body_file(src_folder, uid)?
        && let Ok(bytes) = std::fs::read(&p)
    {
        store.store_body(dest_folder, uid, &bytes)?;
    }
    store.delete_messages(src_folder, &[uid])?;
    Ok(())
}
