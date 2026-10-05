//! T-330 storage diagnostics: report the real size and health of the local
//! mail store, and let the user compact it.
//!
//! **Lock ordering (this is what makes compaction safe).** `MailStore` owns
//! exactly one write connection to `mail.db` and has no lock of its own. Every
//! writer in the app — the live-sync worker, manual sync, folder CRUD, the
//! outbox, imports — reaches that connection only by taking
//! `state.store: Mutex<MailStore>`. `VACUUM` rewrites the whole file and
//! cannot run inside a transaction, so this module holds `state.store` across
//! the entire rebuild. No other writer can therefore be mid-statement on that
//! connection while the rebuild runs: the mutex *is* the serialization, and
//! there is no second connection to `mail.db` in the process.
//!
//! Two things are deliberately *not* claimed:
//! - The store exposes no "write in flight" flag, so the mutex ordering above
//!   (not a flag) is the safety argument. The additional `sync-in-flight`
//!   refusal below is a UX guard on real app state, not the correctness
//!   mechanism.
//! - Body/attachment payload trees are **not** touched: VACUUM only rewrites
//!   `mail.db`.

use std::collections::BTreeMap;
use std::sync::Arc;

use tauri::State;

use super::gate;
use crate::error::{CmdResult, IpcError};
use crate::state::{AccountSyncStatus, AppState, now_unix};
use crate::types::{StorageCompactView, StorageStatsView};

/// Live-sync states that mean a worker may be writing the mail store right
/// now. The real vocabulary written by `syncer` is `pending | connecting |
/// syncing | idle | polling | backoff | paused-locked | stopped`; of those,
/// only these three can hold a store write in flight. `idle`, `backoff`,
/// `paused-locked`, `stopped` and `pending` are quiescent with respect to the
/// store, so compaction is allowed in those states.
const WRITE_IN_FLIGHT_STATES: [&str; 3] = ["connecting", "syncing", "polling"];

/// Accounts whose live-sync worker is currently in a writing state.
fn writers_in_flight(status: &BTreeMap<String, AccountSyncStatus>) -> Vec<String> {
    let mut busy: Vec<String> = status
        .iter()
        .filter(|(_, s)| WRITE_IN_FLIGHT_STATES.contains(&s.state.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    busy.sort();
    busy
}

/// `kiwi_storage_stats()` -> `StorageStatsView` **[gated]**
///
/// Read-only measurement of local storage. `dbBytes` is the real file length
/// of `mail.db` (never `page_count * page_size`); `attachmentBytes` is a
/// real sum over the persisted `attachments/` tree and is `null` when that
/// tree cannot be measured; `auditCount` is the real row count of the
/// hash-chained `audit.jsonl` (the audit trail is a file, not a SQL table);
/// `integrityCheck` is SQLite's own `PRAGMA integrity_check` result, where any
/// value other than `"ok"` must be rendered as a problem, never a pass.
#[tauri::command]
pub async fn kiwi_storage_stats(state: State<'_, Arc<AppState>>) -> CmdResult<StorageStatsView> {
    gate(state.inner()).await?;
    storage_stats_impl(state.inner()).await
}

pub(crate) async fn storage_stats_impl(state: &AppState) -> CmdResult<StorageStatsView> {
    // Deliberately not nested: the store mutex is released before the audit
    // mutex is taken, so this command adds no lock-ordering constraint to the
    // rest of the app.
    let stats = state.store.lock().await.storage_stats()?;
    let audit_count = state.audit.lock().await.len();
    Ok(StorageStatsView {
        db_bytes: stats.db_bytes,
        message_count: stats.message_count,
        folder_count: stats.folder_count,
        attachment_bytes: stats.attachment_bytes,
        audit_count,
        schema_version: stats.schema_version,
        integrity_check: stats.integrity_check,
    })
}
/// `kiwi_storage_compact()` -> `StorageCompactView` **[gated]**
///
/// Rebuilds `mail.db` with `VACUUM` and returns the real file size measured
/// immediately before and after. Audited as `storage-compact-requested` /
/// `storage-compacted`; the request row is written *before* the effect, so a
/// crash mid-rebuild still leaves the attempt in the log.
///
/// Fails closed with `sync-in-flight` (plus a 2 s retry hint) while a live
/// sync worker is in a writing state. That refusal is a UX guard on real
/// `sync_status`; the correctness guarantee is the store mutex held across
/// the whole rebuild (see the module docs).
#[tauri::command]
pub async fn kiwi_storage_compact(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<StorageCompactView> {
    gate(state.inner()).await?;
    storage_compact_impl(state.inner()).await
}

pub(crate) async fn storage_compact_impl(state: &AppState) -> CmdResult<StorageCompactView> {
    {
        // Scoped so the sync-status mutex is released before the audit and
        // store mutexes are taken: never more than one app lock at a time.
        let status = state.sync_status.lock().await;
        let busy = writers_in_flight(&status);
        if !busy.is_empty() {
            return Err(IpcError::new(
                "sync-in-flight",
                format!(
                    "compaction refused: account(s) {} are syncing",
                    busy.join(", ")
                ),
            )
            .with_retry_after(Some(2_000)));
        }
    }

    // Intent before effect: a crash during VACUUM still leaves the request.
    state
        .audit
        .lock()
        .await
        .record("storage-compact-requested", "vacuum", now_unix())?;

    // The store mutex is held for the WHOLE rebuild. kiwi-mail has one write
    // connection and no lock of its own, so this is what serializes VACUUM
    // against every other writer in the process.
    let report = state.store.lock().await.compact()?;

    let detail = format!(
        "before={} after={}",
        report
            .before_bytes
            .map(|b| b.to_string())
            .unwrap_or_else(|| "none".into()),
        report
            .after_bytes
            .map(|b| b.to_string())
            .unwrap_or_else(|| "none".into()),
    );
    state
        .audit
        .lock()
        .await
        .record("storage-compacted", &detail, now_unix())?;

    Ok(StorageCompactView {
        before_db_bytes: report.before_bytes,
        after_db_bytes: report.after_bytes,
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

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-storage-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn account() -> MailAccount {
        MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: "a@x.test".into(),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: "a@x.test".into(),
            },
        }
    }

    fn meta(uid: u64) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some("a@x".into()),
            to_addrs: Some("b@y".into()),
            date_unix: Some(1_758_000_000),
            size: Some(1234),
            flags: vec![],
            has_attachments: false,
            snippet: Some("hi".into()),
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    async fn seeded(tag: &str) -> (Arc<AppState>, std::path::PathBuf) {
        let dir = test_dir(tag);
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        {
            let store = state.store.lock().await;
            store.upsert_account(&account()).unwrap();
            let inbox = store.ensure_folder("a1", "INBOX").unwrap();
            for uid in 1..=5 {
                store
                    .upsert_message(inbox, &meta(uid), 1_758_000_000)
                    .unwrap();
            }
        }
        (state, dir)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stats_report_real_counts_and_honest_nulls() {
        let (state, dir) = seeded("stats").await;
        // One real audit row, so auditCount is a measured count of the
        // hash-chained log rather than a constant.
        state
            .audit
            .lock()
            .await
            .record("probe", "one row", now_unix())
            .unwrap();

        let view = storage_stats_impl(&state).await.unwrap();
        assert_eq!(view.message_count, 5);
        assert_eq!(view.folder_count, 1);
        assert_eq!(view.audit_count, 1);
        assert_eq!(view.schema_version, 19);
        assert_eq!(view.integrity_check, "ok");
        // File-backed store: a real measured size, not null and not an
        // estimate.
        assert!(view.db_bytes.expect("file-backed") > 0);
        // Nothing persisted under attachments/: measured, so an honest 0 -
        // and the field is still honest-null when the tree is gone.
        assert_eq!(view.attachment_bytes, Some(0));
        let _ = std::fs::remove_dir_all(dir.join("attachments"));
        let view = storage_stats_impl(&state).await.unwrap();
        assert_eq!(view.attachment_bytes, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compact_is_audited_and_returns_real_before_after() {
        let (state, dir) = seeded("compact").await;
        // Free pages so the rebuild has something to reclaim.
        {
            let store = state.store.lock().await;
            let inbox = store.ensure_folder("a1", "INBOX").unwrap();
            for uid in 1..=150 {
                store.upsert_message(inbox, &meta(100 + uid), 1).unwrap();
            }
            let doomed: Vec<u64> = (101..=250).collect();
            store.delete_messages(inbox, &doomed).unwrap();
        }

        let view = storage_compact_impl(&state).await.unwrap();
        let before = view.before_db_bytes.expect("file-backed");
        let after = view.after_db_bytes.expect("file-backed");
        assert!(after < before, "after={after} before={before}");

        // The data survived and the store is still sound + counted the same.
        let stats = storage_stats_impl(&state).await.unwrap();
        assert_eq!(stats.message_count, 5);
        assert_eq!(stats.integrity_check, "ok");

        // Both the intent and the outcome are in the log, intent first.
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let req = log.find("storage-compact-requested").expect("intent row");
        let done = log.find("storage-compacted").expect("outcome row");
        assert!(req < done, "intent must be appended before the effect");
        assert!(log.contains("before=") && log.contains("after="));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compact_refuses_while_a_sync_is_in_flight() {
        let (state, dir) = seeded("busy").await;
        {
            let mut map = state.sync_status.lock().await;
            let entry = map.entry("a1".to_string()).or_default();
            entry.state = "syncing".into();
        }
        let err = storage_compact_impl(&state).await.unwrap_err();
        assert_eq!(err.code, "sync-in-flight");
        assert_eq!(err.retry_after_ms, Some(2_000));

        // Fail-closed: nothing was compacted and nothing was audited, so a
        // refused attempt leaves no false "compacted" evidence behind.
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        assert!(!log.contains("storage-compacted"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compact_is_allowed_when_sync_is_quiescent() {
        let (state, dir) = seeded("quiescent").await;
        {
            let mut map = state.sync_status.lock().await;
            for (id, st) in [
                ("a1", "idle"),
                ("a2", "backoff"),
                ("a3", "paused-locked"),
                ("a4", "pending"),
            ] {
                let entry = map.entry(id.to_string()).or_default();
                entry.state = st.into();
            }
        }
        assert!(storage_compact_impl(&state).await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn storage_commands_are_lock_gated() {
        let (state, dir) = seeded("locked").await;
        state.trust.lock().await.force_lock();
        // Prove the exact check the commands run refuses while locked.
        let err = gate(&state).await.unwrap_err();
        assert_eq!(err.code, "locked");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
