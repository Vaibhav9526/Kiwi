//! Junk / not-junk (T-263 — completes the orphaned T-212 store hooks).
//! `junk: true` marks `\Junk` and moves the message into the account's
//! Junk folder; `junk: false` clears the mark and returns Junk-folder
//! messages to INBOX (un-junk on a non-Junk folder clears the flag only).
//!
//! Protocol truth (ipc.md §6f): for IMAP the flag and the move are
//! written through IMMEDIATELY — the command opens a connection per call,
//! runs `UID STORE ±FLAGS.SILENT (\Junk)` on the selected source folder,
//! then `UID MOVE`. There is no deferred flag queue; the next sync's
//! flag-diff is the reconciliation safety net. POP3 has no server flags
//! or folders — the local flag + move is the whole effect. Either way the
//! local store is the list view's source of truth.
//!
//! Moves use `move_messages`, so parked mail keeps its snooze row (it
//! releases on schedule in Junk). Audit rows `messages-junked` /
//! `messages-unjunked` record every call.

use std::collections::BTreeMap;
use std::sync::Arc;

use tauri::State;

use kiwi_core::session::Protocol;
use kiwi_mail::account::IncomingProtocol;
use kiwi_mail::imap::ImapClient;

use super::super::{bounded, gate, run_mail_io};
use super::{snooze::owned_refs, uid_set_of};
use crate::commands::mail::connect_imap;
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{MessageRefInput, SetJunkMoveView, SetJunkView};

/// Conventional junk mailbox names (RFC 6154 \Junk special-use + common
/// vendor spellings) — matched case-insensitively.
const JUNK_NAMES: &[&str] = &["junk", "spam", "junk e-mail", "junk email", "bulk mail"];

fn is_junk_name(name: &str) -> bool {
    JUNK_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// Resolve the account's Junk folder — same resolution order as
/// `resolve_trash`: local name match → live LIST for a `\Junk`
/// special-use flag → CREATE "Junk". Registers in the sidecar index.
async fn resolve_junk(
    state: &AppState,
    account_id: &str,
    client: Option<&mut ImapClient>,
) -> CmdResult<(i64, String)> {
    {
        let store = state.store.lock().await;
        if let Some(f) = store
            .list_folders(account_id)?
            .into_iter()
            .find(|f| is_junk_name(&f.name))
        {
            return Ok((f.id, f.name));
        }
    }
    let mut name = "Junk".to_string();
    if let Some(c) = client
        && let Ok(listed) = c.list("", "*").await
    {
        match listed.iter().find(|m| {
            m.flags.iter().any(|fl| fl.eq_ignore_ascii_case("\\Junk")) || is_junk_name(&m.name)
        }) {
            Some(m) => name = m.name.clone(),
            None => {
                let _ = c.create_mailbox("Junk").await;
            }
        }
    }
    let store = state.store.lock().await;
    let id = store.ensure_folder(account_id, &name)?;
    drop(store);
    let mut index = state.index.lock().await;
    index.remember_folder(account_id, id, &name);
    index.save(&state.data_dir)?;
    Ok((id, name))
}

/// `kiwi_message_set_junk { accountId, refs, junk }` → `SetJunkView`.
/// `refs` shares the snooze ref contract — 1..500 entries, deduped,
/// every folderId proven to belong to `accountId`.
#[tauri::command]
pub async fn kiwi_message_set_junk(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    refs: Vec<MessageRefInput>,
    junk: bool,
) -> CmdResult<SetJunkView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| set_junk_impl(s, account_id, refs, junk)).await
}

pub(crate) async fn set_junk_impl(
    state: Arc<AppState>,
    account_id: String,
    refs: Vec<MessageRefInput>,
    junk: bool,
) -> CmdResult<SetJunkView> {
    bounded("accountId", &account_id, 128)?;
    let by_folder = owned_refs(&state, &account_id, &refs).await?;
    let acct = {
        let store = state.store.lock().await;
        store
            .get_account(&account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?
    };
    let is_imap = acct.incoming.protocol == IncomingProtocol::Imap;

    // Source-folder display names (select + junk-folder detection).
    let mut folder_names = BTreeMap::new();
    {
        let store = state.store.lock().await;
        for fid in by_folder.keys() {
            let name = store
                .folder_meta(*fid)?
                .ok_or_else(|| IpcError::not_found("unknown folder"))?
                .name;
            folder_names.insert(*fid, name);
        }
    }

    let mut client = if is_imap {
        Some(connect_imap(&state, &acct).await?)
    } else {
        None
    };
    // Resolve the move target lazily on first need — a pure flag flip
    // (junk on Junk, un-junk off Junk) never materializes a folder row.
    let mut junk_target: Option<(i64, String)> = None;
    let mut inbox_target: Option<(i64, String)> = None;

    let mut flagged = 0u64;
    let mut moves = Vec::new();
    let mut target_folder_id = None;

    for (src_fid, uids) in &by_folder {
        let src_name = &folder_names[src_fid];
        let src_is_junk = is_junk_name(src_name);

        // 1. Server flag first (before the move — the flag applies at
        //    the message's current coordinates).
        if let Some(c) = client.as_mut() {
            c.select(src_name, false).await.map_err(IpcError::from)?;
            c.uid_store(
                &uid_set_of(uids),
                if junk {
                    "+FLAGS.SILENT"
                } else {
                    "-FLAGS.SILENT"
                },
                &["\\Junk"],
            )
            .await
            .map_err(IpcError::from)?;
        }

        // 2. Decide the move: junk → Junk folder (unless already there);
        //    un-junk → INBOX (only when it sits in a Junk folder).
        let target = if junk && !src_is_junk {
            if junk_target.is_none() {
                junk_target = Some(resolve_junk(&state, &account_id, client.as_mut()).await?);
            }
            Some(junk_target.as_ref().unwrap())
        } else if !junk && src_is_junk {
            if inbox_target.is_none() {
                let id = {
                    let store = state.store.lock().await;
                    store.ensure_folder(&account_id, "INBOX")?
                };
                {
                    let mut index = state.index.lock().await;
                    index.remember_folder(&account_id, id, "INBOX");
                    index.save(&state.data_dir)?;
                }
                inbox_target = Some((id, "INBOX".to_string()));
            }
            Some(inbox_target.as_ref().unwrap())
        } else {
            None
        };

        // 3. Local flag write — before the local move so the flag rides
        //    the row copy (same ordering as update.rs).
        {
            let store = state.store.lock().await;
            flagged += if junk {
                store.mark_junk(*src_fid, uids)?
            } else {
                store.unmark_junk(*src_fid, uids)?
            };
        }

        // 4. Move server-side then locally (move_messages re-keys any
        //    parked snooze rows — junking a snoozed message keeps it
        //    parked).
        if let Some((dst_fid, dst_name)) = target {
            if let Some(c) = client.as_mut() {
                let _ = c.create_mailbox(dst_name).await; // idempotent
                c.uid_move(&uid_set_of(uids), dst_name)
                    .await
                    .map_err(IpcError::from)?;
            }
            let pairs = {
                let store = state.store.lock().await;
                store.move_messages(*src_fid, *dst_fid, uids)?
            };
            target_folder_id = Some(*dst_fid);
            for (from_uid, to_uid) in pairs {
                moves.push(SetJunkMoveView {
                    from_folder_id: *src_fid,
                    from_uid,
                    to_uid,
                });
            }
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
                label: "imap junk",
            },
        )
        .await;
        let _ = c.logout().await;
    }

    let moved = moves.len() as u64;
    state.audit.lock().await.record(
        if junk {
            "messages-junked"
        } else {
            "messages-unjunked"
        },
        &format!("{account_id}: {flagged} flagged, {moved} moved"),
        now_unix(),
    )?;
    // T-345: junk flag/mailbox moves change the unread figure.
    crate::tray::refresh_tooltip(&state).await;
    Ok(SetJunkView {
        junk,
        flagged,
        moved,
        target_folder_id,
        moves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use kiwi_mail::store::NewMessageMeta;
    use kiwi_mail::transport::SocketSecurity;

    /// POP3 fixture — no live connection is attempted; the flag+move is
    /// local-only, which is exactly what these tests pin down.
    async fn state_with_msgs(tag: &str) -> (Arc<AppState>, std::path::PathBuf, i64) {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-junk-{tag}-{}-{}",
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
                protocol: IncomingProtocol::Pop3,
                server: ServerConfig {
                    host: "pop.x.test".into(),
                    port: 995,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
        };
        let store = state.store.lock().await;
        store.upsert_account(&acct).unwrap();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        for uid in [1u64, 2, 3] {
            store
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid,
                        message_id: None,
                        subject: Some(format!("s{uid}")),
                        from_addr: None,
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

    async fn flags_of(state: &AppState, folder_id: i64, uid: u64) -> Vec<String> {
        let store = state.store.lock().await;
        store
            .list_messages(folder_id, 10_000)
            .unwrap()
            .into_iter()
            .find(|m| m.uid == uid)
            .map(|m| m.flags)
            .unwrap_or_default()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn junk_flags_and_moves_to_junk_then_unjunk_returns() {
        let (state, dir, fid) = state_with_msgs("rt").await;

        let v = set_junk_impl(
            state.clone(),
            "a1".into(),
            vec![rf(fid, 1), rf(fid, 2)],
            true,
        )
        .await
        .unwrap();
        assert_eq!(v.flagged, 2);
        assert_eq!(v.moved, 2);
        let junk_id = v.target_folder_id.unwrap();

        let store = state.store.lock().await;
        // Source keeps only uid 3; Junk holds two rows under fresh uids.
        assert_eq!(store.folder_uids(fid).unwrap(), vec![3]);
        let junk_uids = store.folder_uids(junk_id).unwrap();
        assert_eq!(junk_uids.len(), 2);
        // The \Junk flag rode the row copy into the destination.
        for u in &junk_uids {
            let m = store
                .list_messages(junk_id, 10)
                .unwrap()
                .into_iter()
                .find(|m| m.uid == *u)
                .unwrap();
            assert!(m.flags.iter().any(|f| f == "\\Junk"));
        }
        drop(store);

        // Un-junk from Junk → flag cleared, back in INBOX.
        let v = set_junk_impl(
            state.clone(),
            "a1".into(),
            junk_uids.iter().map(|u| rf(junk_id, *u as i64)).collect(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(v.flagged, 2);
        assert_eq!(v.moved, 2);
        assert_eq!(v.target_folder_id, Some(fid));
        assert_eq!(state.store.lock().await.folder_uids(fid).unwrap().len(), 3);
        assert!(
            state
                .store
                .lock()
                .await
                .folder_uids(junk_id)
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn junk_direction_edges() {
        let (state, dir, fid) = state_with_msgs("edge").await;
        let junk_id = state
            .store
            .lock()
            .await
            .ensure_folder("a1", "Junk")
            .unwrap();

        // junk=true on a ref already inside Junk → flag only, no move.
        state
            .store
            .lock()
            .await
            .move_messages(fid, junk_id, &[3])
            .unwrap();
        let ju3 = state.store.lock().await.folder_uids(junk_id).unwrap()[0];
        let v = set_junk_impl(
            state.clone(),
            "a1".into(),
            vec![rf(junk_id, ju3 as i64)],
            true,
        )
        .await
        .unwrap();
        assert_eq!((v.flagged, v.moved), (1, 0));
        assert!(v.target_folder_id.is_none());
        assert!(
            flags_of(&state, junk_id, ju3)
                .await
                .iter()
                .any(|f| f == "\\Junk")
        );

        // un-junk a ref NOT in a junk folder → flag cleared, no move.
        let v = set_junk_impl(state.clone(), "a1".into(), vec![rf(fid, 1)], false)
            .await
            .unwrap();
        assert_eq!((v.flagged, v.moved), (0, 0)); // never flagged → 0 changes
        assert!(v.target_folder_id.is_none());
        assert_eq!(state.store.lock().await.folder_uids(fid).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn junk_refs_validated_and_owned() {
        let (state, dir, fid) = state_with_msgs("own").await;
        // Cross-account folder → not-found.
        let other = {
            let store = state.store.lock().await;
            let mut acct = store.get_account("a1").unwrap().unwrap();
            acct.account_id = "a2".into();
            store.upsert_account(&acct).unwrap();
            store.ensure_folder("a2", "Elsewhere").unwrap()
        };
        let e = set_junk_impl(state.clone(), "a1".into(), vec![rf(other, 1)], true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "not-found");
        // Empty refs / unknown folder → invalid / not-found.
        let e = set_junk_impl(state.clone(), "a1".into(), vec![], true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid-input");
        let e = set_junk_impl(state.clone(), "a1".into(), vec![rf(9999, 1)], true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "not-found");
        let _ = fid;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
