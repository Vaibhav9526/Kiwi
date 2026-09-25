//! T-319 local folder management. The SQLite store owns folder rows; these
//! commands never imply IMAP server-folder CREATE/RENAME/DELETE.

use std::sync::Arc;

use tauri::State;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
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
    state: &AppState,
    account_id: &str,
    parent_id: Option<i64>,
    name: &str,
) -> CmdResult<FolderView> {
    bounded("accountId", account_id, 128)?;
    bounded("name", name, 255)?;
    if parent_id.is_some_and(|id| id < 0) {
        return Err(IpcError::invalid("parentId must be >= 0"));
    }
    if let Some(id) = parent_id {
        let parent = owned_folder(state, account_id, id).await?;
        if parent.origin != kiwi_mail::store::FolderOrigin::Local {
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
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    new_name: &str,
) -> CmdResult<FolderView> {
    bounded("accountId", account_id, 128)?;
    bounded("newName", new_name, 255)?;
    let old = owned_folder(state, account_id, folder_id).await?;
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
    state: &AppState,
    account_id: &str,
    folder_id: i64,
) -> CmdResult<i64> {
    bounded("accountId", account_id, 128)?;
    let folder = owned_folder(state, account_id, folder_id).await?;
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

    fn account(id: &str) -> MailAccount {
        MailAccount {
            account_id: id.into(),
            display_name: id.into(),
            email: format!("{id}@example.test"),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
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
        let s = state("crud");
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
