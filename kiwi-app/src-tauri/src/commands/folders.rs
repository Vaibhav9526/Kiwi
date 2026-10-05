//! Folder management. T-319 local rows are store-only (POP3 accounts and
//! local folders on any account). T-328: on IMAP accounts the three
//! commands also drive real server-side CREATE/RENAME/DELETE — the wire
//! op runs first, a verifying LIST must show the effect, and only then is
//! the local row mirrored. Server `NO`/`BAD` replies surface verbatim;
//! nothing is faked locally ahead of the server.

use std::sync::Arc;

use tauri::State;

use kiwi_mail::account::{IncomingProtocol, MailAccount};
use kiwi_mail::imap::ImapClient;
use kiwi_mail::store::FolderOrigin;

use super::mail::{auth_mech_of, connect_imap};
use super::run_mail_io;
use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::observe;
use crate::state::{AppState, now_unix};
use crate::types::FolderView;

async fn owned_folder(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
) -> CmdResult<kiwi_mail::store::FolderMeta> {
    let store = state.store.lock().await;
    let folder = store
        .folder_meta(folder_id)?
        .ok_or_else(|| IpcError::not_found("unknown folder"))?;
    if folder.account_id != account_id {
        return Err(IpcError::not_found("folder not on account"));
    }
    Ok(folder)
}

async fn view(state: &AppState, meta: &kiwi_mail::store::FolderMeta) -> CmdResult<FolderView> {
    let store = state.store.lock().await;
    let stats = store.folder_stats(meta.id)?;
    Ok(FolderView::from_meta(meta, stats))
}

async fn remember(state: &AppState, account_id: &str, id: i64, name: &str) -> CmdResult<()> {
    let mut index = state.index.lock().await;
    index.remember_folder(account_id, id, name);
    index.save(&state.data_dir)
}

async fn forget(state: &AppState, account_id: &str, id: i64) -> CmdResult<()> {
    let mut index = state.index.lock().await;
    index.forget_folder(account_id, id);
    index.save(&state.data_dir)
}

/// A leaf name that can safely reach the wire: T-319's caps plus the
/// RFC 3501 LIST wildcards (`%`, `*`) — a wildcard in a created name
/// would make later LIST traffic ambiguous — and the canonical mailbox
/// names (those rows are sync-owned `system`, never user-created).
/// The server's hierarchy delimiter is rejected separately, once known.
fn remote_leaf_name(name: &str) -> CmdResult<String> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        return Err(IpcError::invalid("folder name is empty"));
    }
    if name.len() > 255 {
        return Err(IpcError::invalid("folder name exceeds 255 bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err(IpcError::invalid(
            "folder name contains a control character",
        ));
    }
    if name.contains(['%', '*']) {
        return Err(IpcError::invalid(
            "folder name contains a LIST wildcard (% or *)",
        ));
    }
    if kiwi_mail::store::is_system_folder_name(name) {
        return Err(IpcError::invalid("folder name is reserved"));
    }
    Ok(name.to_string())
}

/// The account's IMAP session for one folder op — connect, run the op,
/// record the observation, log out. `op` returns the verified server
/// mailbox name (and the hierarchy delimiter for rename).
async fn with_imap_session<T: Send + 'static>(
    state: &Arc<AppState>,
    acct: MailAccount,
    label: &'static str,
    op: impl AsyncFnOnce(&mut ImapClient) -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    run_mail_io(state.clone(), move |s| async move {
        let mut client = connect_imap(&s, &acct).await?;
        let out = op(&mut client).await;
        let facts = observe::facts_of(client.transport());
        observe::record_connection(
            &s,
            facts,
            observe::ObservationContext {
                protocol: kiwi_core::session::Protocol::Imap,
                account_id: Some(acct.account_id.clone()),
                starttls_offered: Some(client.has_capability("STARTTLS")),
                auth_mechanism: auth_mech_of(&acct.incoming.auth),
                auth_succeeded: Some(true),
                label,
            },
        )
        .await;
        let _ = client.logout().await;
        out
    })
    .await
}

/// `LIST "" ""` — the RFC 3501 delimiter probe. `None` = flat namespace.
async fn wire_delimiter(client: &mut ImapClient) -> CmdResult<Option<String>> {
    client.hierarchy_delimiter().await.map_err(IpcError::from)
}

/// The mailbox name the server actually reports for `wire` — the mirror
/// follows the server's spelling, never our derived string.
async fn listed_name(client: &mut ImapClient, wire: &str) -> CmdResult<String> {
    let listed = client.list("", wire).await.map_err(IpcError::from)?;
    listed
        .iter()
        .find(|m| m.name == wire || m.name.eq_ignore_ascii_case(wire))
        .map(|m| m.name.clone())
        .ok_or_else(|| {
            IpcError::new(
                "protocol-error",
                "server ACKed the folder op but LIST does not show the mailbox",
            )
        })
}

#[tauri::command]
pub async fn kiwi_folder_create(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    parent_id: Option<i64>,
    name: String,
) -> CmdResult<FolderView> {
    gate(state.inner()).await?;
    folder_create_impl(state.inner(), &account_id, parent_id, &name).await
}

pub(crate) async fn folder_create_impl(
    state: &Arc<AppState>,
    account_id: &str,
    parent_id: Option<i64>,
    name: &str,
) -> CmdResult<FolderView> {
    bounded("accountId", account_id, 128)?;
    bounded("name", name, 255)?;
    if parent_id.is_some_and(|id| id < 0) {
        return Err(IpcError::invalid("parentId must be >= 0"));
    }
    let acct = state
        .store
        .lock()
        .await
        .get_account(account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;

    if acct.incoming.protocol == IncomingProtocol::Imap {
        // ---- server-side path (T-328) ----
        let leaf = remote_leaf_name(name)?;
        let parent_wire = match parent_id {
            Some(id) => {
                let p = owned_folder(state, account_id, id).await?;
                if p.origin == FolderOrigin::Local {
                    return Err(IpcError::invalid(
                        "parent folder is local — the server cannot see it",
                    ));
                }
                Some(p.name)
            }
            None => None,
        };
        state.audit.lock().await.record(
            "folder-create-requested",
            &format!("{account_id} parent={} name={name}", parent_id.unwrap_or(0)),
            now_unix(),
        )?;
        let leaf_for_wire = leaf.clone();
        let wire = with_imap_session(state, acct, "imap folder create", async move |client| {
            let sep = wire_delimiter(client).await?.ok_or_else(|| {
                IpcError::new(
                    "protocol-error",
                    "server reports a flat namespace (NIL hierarchy delimiter)",
                )
            })?;
            if leaf_for_wire.contains(sep.as_str()) {
                return Err(IpcError::invalid(
                    "folder name contains the server's hierarchy separator",
                ));
            }
            let wire = match &parent_wire {
                Some(p) => format!("{p}{sep}{leaf_for_wire}"),
                None => leaf_for_wire.clone(),
            };
            client.create_mailbox(&wire).await.map_err(IpcError::from)?;
            listed_name(client, &wire).await
        })
        .await?;
        let meta = {
            let store = state.store.lock().await;
            let id = store.ensure_folder(account_id, &wire)?;
            store
                .folder_meta(id)?
                .ok_or_else(|| IpcError::new("internal", "folder row missing after mirror"))?
        };
        remember(state, account_id, meta.id, &meta.name).await?;
        state.audit.lock().await.record(
            "folder-created-remote",
            &format!("{account_id} wire={}", meta.name),
            now_unix(),
        )?;
        return view(state, &meta).await;
    }

    // ---- local path (T-319 — POP3 has no server folder namespace) ----
    if let Some(id) = parent_id {
        let parent = owned_folder(state, account_id, id).await?;
        if parent.origin != FolderOrigin::Local {
            return Err(IpcError::invalid("parent folder is not local"));
        }
    }
    state.audit.lock().await.record(
        "folder-create-requested",
        &format!("{account_id} parent={} name={name}", parent_id.unwrap_or(0)),
        now_unix(),
    )?;
    let meta = {
        let store = state.store.lock().await;
        store.create_local_folder(account_id, parent_id, name)?
    };
    remember(state, account_id, meta.id, &meta.name).await?;
    view(state, &meta).await
}

#[tauri::command]
pub async fn kiwi_folder_rename(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    new_name: String,
) -> CmdResult<FolderView> {
    gate(state.inner()).await?;
    folder_rename_impl(state.inner(), &account_id, folder_id, &new_name).await
}

pub(crate) async fn folder_rename_impl(
    state: &Arc<AppState>,
    account_id: &str,
    folder_id: i64,
    new_name: &str,
) -> CmdResult<FolderView> {
    bounded("accountId", account_id, 128)?;
    bounded("newName", new_name, 255)?;
    let old = owned_folder(state, account_id, folder_id).await?;
    if old.origin != FolderOrigin::Local {
        // ---- server-side path (T-328) ----
        if old.name.eq_ignore_ascii_case("INBOX") {
            // RFC 3501 RENAME INBOX is technically defined but means
            // "move every inbox message" — not a rename. Fail closed.
            return Err(IpcError::new("policy-blocked", "INBOX cannot be renamed"));
        }
        let acct = state
            .store
            .lock()
            .await
            .get_account(account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        if acct.incoming.protocol != IncomingProtocol::Imap {
            return Err(IpcError::new(
                "policy-blocked",
                "server folders can be renamed only on IMAP accounts",
            ));
        }
        let leaf = remote_leaf_name(new_name)?;
        state.audit.lock().await.record(
            "folder-rename-requested",
            &format!("{account_id} id={folder_id} {} -> {new_name}", old.name),
            now_unix(),
        )?;
        let old_wire = old.name.clone();
        let (wire, sep) =
            with_imap_session(state, acct, "imap folder rename", async move |client| {
                let sep = wire_delimiter(client).await?.ok_or_else(|| {
                    IpcError::new(
                        "protocol-error",
                        "server reports a flat namespace (NIL hierarchy delimiter)",
                    )
                })?;
                if leaf.contains(sep.as_str()) {
                    return Err(IpcError::invalid(
                        "folder name contains the server's hierarchy separator",
                    ));
                }
                // Renames keep the parent prefix: `A/B` renamed to `C` is
                // `A/C` — the leaf is the rename unit, matching the local UX.
                let new_wire = match old_wire.rfind(sep.as_str()) {
                    Some(i) => format!("{}{sep}{leaf}", &old_wire[..i]),
                    None => leaf.clone(),
                };
                client
                    .rename_mailbox(&old_wire, &new_wire)
                    .await
                    .map_err(IpcError::from)?;
                // RFC 3501 §6.3.5: the server renames inferiors and carries
                // subscription state to the new name — nothing to mirror
                // client-side beyond the rows.
                Ok((listed_name(client, &new_wire).await?, sep))
            })
            .await?;
        let metas = {
            let store = state.store.lock().await;
            store.rename_remote_folder(folder_id, &wire, &sep)?
        };
        {
            let mut index = state.index.lock().await;
            for m in &metas {
                index.remember_folder(account_id, m.id, &m.name);
            }
            index.save(&state.data_dir)?;
        }
        state.audit.lock().await.record(
            "folder-renamed-remote",
            &format!("{account_id} {} -> {}", old.name, wire),
            now_unix(),
        )?;
        return view(state, &metas[0]).await;
    }
    state.audit.lock().await.record(
        "folder-rename-requested",
        &format!("{account_id} id={folder_id} {} -> {new_name}", old.name),
        now_unix(),
    )?;
    let meta = {
        let store = state.store.lock().await;
        store.rename_local_folder(folder_id, new_name)?
    };
    remember(state, account_id, meta.id, &meta.name).await?;
    view(state, &meta).await
}

#[tauri::command]
pub async fn kiwi_folder_delete(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    let deleted = folder_delete_impl(state.inner(), &account_id, folder_id).await?;
    Ok(serde_json::json!({ "folderId": deleted }))
}

pub(crate) async fn folder_delete_impl(
    state: &Arc<AppState>,
    account_id: &str,
    folder_id: i64,
) -> CmdResult<i64> {
    bounded("accountId", account_id, 128)?;
    let folder = owned_folder(state, account_id, folder_id).await?;
    if folder.origin != FolderOrigin::Local {
        // ---- server-side path (T-328) ----
        if folder.name.eq_ignore_ascii_case("INBOX") {
            // RFC 3501 §6.3.4: INBOX is permanent.
            return Err(IpcError::new("policy-blocked", "INBOX cannot be deleted"));
        }
        let acct = state
            .store
            .lock()
            .await
            .get_account(account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        if acct.incoming.protocol != IncomingProtocol::Imap {
            return Err(IpcError::new(
                "policy-blocked",
                "server folders can be deleted only on IMAP accounts",
            ));
        }
        state.audit.lock().await.record(
            "folder-delete-requested",
            &format!("{account_id} id={folder_id} name={}", folder.name),
            now_unix(),
        )?;
        let wire = folder.name.clone();
        with_imap_session(state, acct, "imap folder delete", async move |client| {
            client.delete_mailbox(&wire).await.map_err(IpcError::from)?;
            // DELETE removes the mailbox and its contents — a mailbox the
            // server still lists afterwards means the ACK was nominal.
            let listed = client.list("", &wire).await.map_err(IpcError::from)?;
            if listed.iter().any(|m| m.name.eq_ignore_ascii_case(&wire)) {
                return Err(IpcError::new(
                    "protocol-error",
                    "server ACKed DELETE but still lists the mailbox",
                ));
            }
            Ok(())
        })
        .await?;
        {
            let store = state.store.lock().await;
            if !store.delete_remote_folder(folder_id)? {
                return Err(IpcError::not_found("unknown folder"));
            }
        }
        forget(state, account_id, folder_id).await?;
        state.audit.lock().await.record(
            "folder-deleted-remote",
            &format!("{account_id} wire={}", folder.name),
            now_unix(),
        )?;
        return Ok(folder_id);
    }
    state.audit.lock().await.record(
        "folder-delete-requested",
        &format!("{account_id} id={folder_id} name={}", folder.name),
        now_unix(),
    )?;
    {
        let store = state.store.lock().await;
        if !store.delete_local_folder(folder_id)? {
            return Err(IpcError::not_found("unknown folder"));
        }
    }
    forget(state, account_id, folder_id).await?;
    Ok(folder_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use kiwi_mail::transport::SocketSecurity;

    fn state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-folders-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        AppState::open_test(dir).unwrap()
    }

    /// POP3 fixture — local-only CRUD without a server round-trip (T-328
    /// routes IMAP accounts to the wire; POP3 has no folder namespace).
    fn account(id: &str) -> MailAccount {
        MailAccount {
            account_id: id.into(),
            display_name: id.into(),
            email: format!("{id}@example.test"),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Pop3,
                server: ServerConfig {
                    host: "imap.example.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: id.into(),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.example.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: id.into(),
            },
        }
    }

    fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn local_folder_crud_is_audited_indexed_and_account_scoped() {
        let s = Arc::new(state("crud"));
        block_on(async {
            let store = s.store.lock().await;
            store.upsert_account(&account("a1")).unwrap();
            store.upsert_account(&account("a2")).unwrap();
            let system = store.ensure_folder("a1", "INBOX").unwrap();
            drop(store);

            let created = folder_create_impl(&s, "a1", None, "Archive Local")
                .await
                .unwrap();
            assert_eq!(created.origin, "local");
            assert_eq!(created.parent_id, None);
            let child = folder_create_impl(&s, "a1", Some(created.id), "Nested")
                .await
                .unwrap();
            let renamed = folder_rename_impl(&s, "a1", child.id, "Renamed")
                .await
                .unwrap();
            assert_eq!(renamed.name, "Renamed");
            assert!(folder_delete_impl(&s, "a1", child.id).await.is_ok());
            assert!(
                folder_rename_impl(&s, "a2", created.id, "No")
                    .await
                    .is_err()
            );
            assert!(folder_delete_impl(&s, "a2", created.id).await.is_err());
            assert!(folder_delete_impl(&s, "a1", system).await.is_err());

            let folders = s.index.lock().await.folders.get("a1").cloned().unwrap();
            assert!(!folders.iter().any(|f| f.id == child.id));
            assert!(
                folders
                    .iter()
                    .any(|f| f.id == created.id && f.name == "Archive Local")
            );
            let audit = std::fs::read_to_string(s.data_dir.join("audit.jsonl")).unwrap();
            assert!(audit.contains("folder-create-requested"));
            assert!(audit.contains("folder-rename-requested"));
            assert!(audit.contains("folder-delete-requested"));
        });
    }
}
