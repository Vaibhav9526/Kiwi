//! Live sync engine (T-157) — the piece that puts real mail in the app.
//!
//! A supervisor task (spawned from `run()`'s setup hook) reconciles
//! `index.account_ids` against a worker map: each configured account gets
//! a dedicated worker that runs connect → full `sync_folder` pass → IDLE
//! (IMAP) or periodic poll (POP3), emitting `kiwi://mail-changed` to the
//! webview whenever a pass changes stored mail.
//!
//! Failure handling: exponential backoff (5 s → 120 s cap) with
//! `sync_status` reflecting `backoff` + `nextRetryUnix`. Lock handling:
//! while the endpoint is `Locked` workers pause — no connects, no
//! credential use, and a worker that notices the lock mid-IDLE logs out
//! rather than holding an authenticated session (same posture as the
//! outbox dispatcher, contract §2/§7).
//!
//! Why dedicated threads, not `tauri::async_runtime::spawn`: kiwi-mail
//! clients are `!Send` inside futures (SASL continuations; `Transport`/
//! `MailStore` are `!Sync`) — the same constraint `run_mail_io` solves
//! per-command. Each worker thread runs its own current-thread runtime;
//! only owned data crosses back (status writes + emitted events).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};

use kiwi_core::trust::TrustState;
use kiwi_mail::account::{IncomingProtocol, MailAccount};
use kiwi_mail::sync::sync_folder;

use crate::commands::mail::{
    ReceivedFact, auth_mech_of, collect_received, connect_imap, emit_received, pop3_sync,
};
use crate::error::CmdResult;
use crate::observe::{self, ObservationContext};
use crate::state::{AccountSyncStatus, AppState, now_unix};
use crate::types::MailChangedEvent;

/// Supervisor reconcile cadence — picks up added/removed accounts.
const SUPERVISOR_TICK: Duration = Duration::from_secs(2);
/// Max IDLE dwell per cycle — bounds lock-pause latency; DONE+IDLE re-entry
/// is one cheap roundtrip.
const IDLE_CYCLE: Duration = Duration::from_secs(30);
/// POP3 poll interval (no push channel exists).
const POP3_POLL_SECS: i64 = 60;
/// Backoff: 5 s doubling to a 120 s cap.
const BACKOFF_BASE_SECS: i64 = 5;
const BACKOFF_MAX_SECS: i64 = 120;
/// Folder cap for the connect-time full pass (same bound as manual sync).
const MAX_SYNC_FOLDERS: usize = 64;
/// IMAP IDLE runs on INBOX — the folder servers actually push for.
const IDLE_FOLDER: &str = "INBOX";

/// How a worker reports a mail-changed event — `app.emit` in production,
/// a capture vec in tests.
pub type Emit = Arc<dyn Fn(&MailChangedEvent) + Send + Sync>;

/// Event name the webview subscribes to.
pub const MAIL_CHANGED_EVENT: &str = "kiwi://mail-changed";

/// Exponential backoff for attempt `n` (1-based): 5, 10, 20, 40, 80, 120…
fn backoff_secs(attempts: u32) -> i64 {
    (BACKOFF_BASE_SECS << attempts.saturating_sub(1).min(5)).min(BACKOFF_MAX_SECS)
}

async fn is_locked(state: &AppState) -> bool {
    state.trust.lock().await.state() == TrustState::Locked
}

/// Update one account's sync-status entry.
async fn set_status(state: &AppState, account_id: &str, f: impl FnOnce(&mut AccountSyncStatus)) {
    f(state
        .sync_status
        .lock()
        .await
        .entry(account_id.to_string())
        .or_default());
}

// ---------------------------------------------------------------------------
// Supervisor — reconcile configured accounts ↔ running workers.
// ---------------------------------------------------------------------------

/// Long-lived supervisor, spawned once from `setup()`. Every tick it
/// spawns workers for new accounts, reaps finished ones, and prunes status
/// entries for removed accounts.
pub async fn sync_supervisor(app: AppHandle) {
    let mut workers: BTreeMap<String, JoinHandle<()>> = BTreeMap::new();
    let mut tick = tokio::time::interval(SUPERVISOR_TICK);
    let state0 = app.state::<Arc<AppState>>().inner().clone();
    loop {
        // Reconcile on the tick OR immediately when a command pokes the
        // wake signal (account add/remove — the wizard shouldn't wait).
        tokio::select! {
            _ = tick.tick() => {}
            _ = state0.sync_wakeup.notified() => {}
        }
        let state = state0.clone();
        let ids = state.index.lock().await.account_ids.clone();

        workers.retain(|_, h| !h.is_finished());
        state
            .sync_status
            .lock()
            .await
            .retain(|id, _| ids.contains(id));

        for id in ids {
            if workers.contains_key(&id) {
                continue;
            }
            let app2 = app.clone();
            let emit: Emit = Arc::new(move |ev| {
                let _ = app2.emit(MAIL_CHANGED_EVENT, ev);
            });
            match spawn_worker(state.clone(), id.clone(), emit) {
                Ok(h) => {
                    workers.insert(id, h);
                }
                Err(e) => {
                    eprintln!("[kiwi-app] sync worker spawn {id}: {e}");
                    set_status(&state, &id, |s| {
                        s.state = "stopped".into();
                        s.last_error = Some(format!("worker spawn failed: {e}"));
                    })
                    .await;
                }
            }
        }
    }
}

/// Spawn one account's sync worker on a dedicated thread + current-thread
/// runtime (kiwi-mail clients are `!Send` — see module doc).
pub(crate) fn spawn_worker(
    state: Arc<AppState>,
    account_id: String,
    emit: Emit,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("kiwi-sync-{account_id}"))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[kiwi-app] sync worker runtime {account_id}: {e}");
                    return;
                }
            };
            rt.block_on(worker_loop(state, account_id, emit));
        })
}

// ---------------------------------------------------------------------------
// Worker — one account's live sync loop.
// ---------------------------------------------------------------------------

async fn worker_loop(state: Arc<AppState>, account_id: String, emit: Emit) {
    let mut failures = 0u32;
    loop {
        // Account existence first — a removed account must stop the worker
        // even while the endpoint is locked.
        let acct = {
            let store = state.store.lock().await;
            match store.get_account(&account_id) {
                Ok(Some(a)) => a,
                _ => {
                    set_status(&state, &account_id, |s| s.state = "stopped".into()).await;
                    return;
                }
            }
        };
        // Lock gate for background work: hold nothing, use no credentials.
        if is_locked(&state).await {
            set_status(&state, &account_id, |s| {
                s.state = "paused-locked".into();
                s.next_retry_unix = None;
            })
            .await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let result = match acct.incoming.protocol {
            IncomingProtocol::Imap => imap_live(&state, &acct, &emit).await,
            IncomingProtocol::Pop3 => match pop3_poll(&state, &acct, &emit).await {
                Ok(()) => {
                    failures = 0;
                    interruptible_sleep(&state, &account_id, POP3_POLL_SECS).await;
                    continue;
                }
                Err(e) => Err(e),
            },
        };
        match result {
            // Clean exit: lock noticed mid-IDLE, or a graceful close —
            // the loop's lock check pauses us properly if so.
            Ok(()) => failures = 0,
            Err(e) => {
                failures += 1;
                let wait = backoff_secs(failures);
                eprintln!(
                    "[kiwi-app] sync {account_id}: {} — retry in {wait}s",
                    e.message
                );
                set_status(&state, &account_id, |s| {
                    s.state = "backoff".into();
                    s.last_error = Some(e.message);
                    s.next_retry_unix = Some(now_unix() + wait);
                    s.attempts = failures;
                })
                .await;
                interruptible_sleep(&state, &account_id, wait).await;
            }
        }
    }
}

/// Sleep in 1 s chunks, waking early if the endpoint locks or the account
/// disappears — keeps the pause honest without making the worker hold
/// connections while locked, and keeps removal snappy.
async fn interruptible_sleep(state: &AppState, account_id: &str, secs: i64) {
    for _ in 0..secs.max(0) {
        if is_locked(state).await {
            return;
        }
        let gone = !matches!(
            state.store.lock().await.get_account(account_id),
            Ok(Some(_))
        );
        if gone {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// POP3 poll pass — `pop3_sync` already does connect → auth → sync →
/// observe → §11 emit. Emit mail-changed when the poll changed anything.
async fn pop3_poll(state: &AppState, acct: &MailAccount, emit: &Emit) -> CmdResult<()> {
    set_status(state, &acct.account_id, |s| s.state = "polling".into()).await;
    let reports = pop3_sync(state, acct).await?;
    let changed: u64 = reports
        .iter()
        .map(|r| r.downloaded + r.deleted_remote)
        .sum();
    set_status(state, &acct.account_id, |s| {
        s.last_sync_unix = Some(now_unix());
        s.new_messages += reports.iter().map(|r| r.downloaded).sum::<u64>();
        s.attempts = 0;
        s.last_error = None;
    })
    .await;
    if changed > 0 {
        emit(&MailChangedEvent {
            account_id: acct.account_id.clone(),
            folder: Some("INBOX".into()),
            folder_id: reports.first().map(|r| r.folder_id),
            reason: "poll".into(),
            new_messages: reports.iter().map(|r| r.downloaded).sum(),
            flag_updates: 0,
            expunged: 0,
            at_unix: now_unix(),
        });
    }
    Ok(())
}

/// IMAP live pass on ONE connection: full folder sync → IDLE loop on
/// INBOX. Returns Err to trigger reconnect+backoff; Ok(()) only when the
/// lock was noticed mid-IDLE (connection logged out first).
async fn imap_live(state: &AppState, acct: &MailAccount, emit: &Emit) -> CmdResult<()> {
    set_status(state, &acct.account_id, |s| s.state = "connecting".into()).await;
    let mut client = connect_imap(state, acct).await?;

    set_status(state, &acct.account_id, |s| s.state = "syncing".into()).await;
    let endpoint = crate::bridge::resolve_endpoint(state).await;
    let mut received: Vec<ReceivedFact> = Vec::new();
    let mut total_new = 0u64;
    let mut total_flags = 0u64;
    let mut total_expunged = 0u64;
    let mut folders_synced = 0u64;

    let folder_names: Vec<String> = match client.list("", "*").await {
        Ok(listed) => listed
            .iter()
            .map(|m| m.name.clone())
            .take(MAX_SYNC_FOLDERS)
            .collect(),
        Err(e) => {
            let _ = client.logout().await;
            return Err(e.into());
        }
    };
    for name in &folder_names {
        let (folder_id, before) = {
            let store = state.store.lock().await;
            let id = store.ensure_folder(&acct.account_id, name)?;
            let uids: std::collections::BTreeSet<u64> =
                store.folder_uids(id)?.into_iter().collect();
            drop(store);
            let mut index = state.index.lock().await;
            index.remember_folder(&acct.account_id, id, name);
            index.save(&state.data_dir)?;
            (id, uids)
        };
        let report = {
            let store = state.store.lock().await;
            match sync_folder(&mut client, &store, &acct.account_id, name, now_unix()).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = client.logout().await;
                    return Err(e.into());
                }
            }
        };
        if endpoint.is_some() {
            collect_received(state, folder_id, &before, &mut received).await?;
        }
        // T-169: harvest threading headers for just-arrived uids.
        {
            let new_uids: Vec<u64> = state
                .store
                .lock()
                .await
                .folder_uids(folder_id)?
                .into_iter()
                .filter(|u| !before.contains(u))
                .take(2000)
                .collect();
            if !new_uids.is_empty() {
                crate::commands::mail::capture_thread_headers(
                    state,
                    &mut client,
                    folder_id,
                    &new_uids,
                )
                .await;
            }
        }
        total_new += report.new_messages;
        total_flags += report.flag_updates;
        total_expunged += report.expunged;
        folders_synced += 1;
    }

    // One session record for the whole live connection — IDLE cycles and
    // event-triggered re-syncs below are the same observed session.
    let facts = observe::facts_of(client.transport());
    let tls_label = facts
        .observation
        .as_ref()
        .and_then(|o| o.protocol_version.as_deref())
        .map(crate::bridge::tls_version_label);
    let (record, _eval) = observe::record_connection(
        state,
        facts,
        ObservationContext {
            protocol: kiwi_core::session::Protocol::Imap,
            account_id: Some(acct.account_id.clone()),
            starttls_offered: Some(client.has_capability("STARTTLS")),
            auth_mechanism: auth_mech_of(&acct.incoming.auth),
            auth_succeeded: Some(true),
            label: "imap live",
        },
    )
    .await;
    let security_status =
        crate::bridge::security_status_label(true, record.findings.iter().map(|f| f.severity));
    if let Some(ep) = &endpoint {
        emit_received(state, ep, acct, received, tls_label, security_status).await;
    }

    set_status(state, &acct.account_id, |s| {
        s.state = "idle".into();
        s.last_sync_unix = Some(now_unix());
        s.last_error = None;
        s.next_retry_unix = None;
        s.attempts = 0;
        s.folders_synced = folders_synced;
        s.new_messages += total_new;
    })
    .await;
    // The full pass always emits — the UI needs the "initial sync done"
    // signal even when nothing new arrived.
    emit(&MailChangedEvent {
        account_id: acct.account_id.clone(),
        folder: None,
        folder_id: None,
        reason: "sync".into(),
        new_messages: total_new,
        flag_updates: total_flags,
        expunged: total_expunged,
        at_unix: now_unix(),
    });

    // IDLE on INBOX: servers push EXISTS/EXPUNGE/FETCH for the selected
    // mailbox. Short cycles bound both lock-pause latency and dead-
    // connection detection.
    client
        .select(IDLE_FOLDER, false)
        .await
        .map_err(crate::error::IpcError::from)?;
    let inbox_id = {
        let store = state.store.lock().await;
        store.ensure_folder(&acct.account_id, IDLE_FOLDER)?
    };
    loop {
        if is_locked(state).await {
            let _ = client.logout().await;
            return Ok(());
        }
        let events = match client.idle_collect(IDLE_CYCLE).await {
            Ok(e) => e,
            Err(e) => {
                let _ = client.logout().await;
                return Err(e.into());
            }
        };
        if events.is_empty() {
            continue; // idle cycle expired — loop re-checks lock, re-enters
        }
        let before: std::collections::BTreeSet<u64> = {
            let store = state.store.lock().await;
            store.folder_uids(inbox_id)?.into_iter().collect()
        };
        let report = {
            let store = state.store.lock().await;
            match sync_folder(
                &mut client,
                &store,
                &acct.account_id,
                IDLE_FOLDER,
                now_unix(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = client.logout().await;
                    return Err(e.into());
                }
            }
        };
        let mut received = Vec::new();
        if endpoint.is_some() {
            collect_received(state, inbox_id, &before, &mut received).await?;
        }
        // T-169: threading headers for the IDLE-arrived uids.
        {
            let new_uids: Vec<u64> = state
                .store
                .lock()
                .await
                .folder_uids(inbox_id)?
                .into_iter()
                .filter(|u| !before.contains(u))
                .take(2000)
                .collect();
            if !new_uids.is_empty() {
                crate::commands::mail::capture_thread_headers(
                    state,
                    &mut client,
                    inbox_id,
                    &new_uids,
                )
                .await;
            }
        }
        if let Some(ep) = &endpoint {
            emit_received(state, ep, acct, received, tls_label, security_status).await;
        }
        set_status(state, &acct.account_id, |s| {
            s.last_sync_unix = Some(now_unix());
            s.new_messages += report.new_messages;
        })
        .await;
        if report.new_messages > 0 || report.flag_updates > 0 || report.expunged > 0 {
            emit(&MailChangedEvent {
                account_id: acct.account_id.clone(),
                folder: Some(IDLE_FOLDER.into()),
                folder_id: Some(inbox_id),
                reason: "idle".into(),
                new_messages: report.new_messages,
                flag_updates: report.flag_updates,
                expunged: report.expunged,
                at_unix: now_unix(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AddAccountInput, AuthInput, ServerInput};

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-syncer-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = std::pin::pin!(f);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn acct_input(host: &str, port: u16) -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming_protocol: "imap".into(),
            incoming: ServerInput {
                host: host.into(),
                port,
                security: "tls".into(),
            },
            outgoing: ServerInput {
                host: "smtp.x.test".into(),
                port: 465,
                security: "tls".into(),
            },
            username: None,
            outgoing_username: None,
            incoming_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
                oauth2_ticket: None,
            }),
            outgoing_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
                oauth2_ticket: None,
            }),
            accept_invalid_certs: false,
        }
    }

    /// Delete the account from store + index so the worker exits, then join.
    fn stop_worker(state: &Arc<AppState>, account_id: &str, h: JoinHandle<()>) {
        block_on(async {
            state.index.lock().await.account_ids.clear();
            let _ = state.store.lock().await.delete_account(account_id);
        });
        h.join().expect("worker should exit once account is gone");
    }

    #[test]
    fn backoff_progression() {
        assert_eq!(backoff_secs(1), 5);
        assert_eq!(backoff_secs(2), 10);
        assert_eq!(backoff_secs(3), 20);
        assert_eq!(backoff_secs(5), 80);
        assert_eq!(backoff_secs(6), 120);
        assert_eq!(backoff_secs(99), 120); // capped
    }

    #[test]
    fn mail_changed_event_shape() {
        let ev = MailChangedEvent {
            account_id: "a1".into(),
            folder: Some("INBOX".into()),
            folder_id: Some(3),
            reason: "idle".into(),
            new_messages: 2,
            flag_updates: 1,
            expunged: 0,
            at_unix: 100,
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["accountId"], "a1");
        assert_eq!(v["folder"], "INBOX");
        assert_eq!(v["reason"], "idle");
        assert_eq!(v["newMessages"], 2);
    }

    #[test]
    fn worker_pauses_when_locked_never_connects() {
        // Locked endpoint: the worker must not attempt a connection at all.
        // We give it a moment, then assert no session was observed and the
        // status shows the pause.
        let state = Arc::new(test_state("locked"));
        block_on(state.trust.lock()).force_lock();
        let account_id = {
            let state = state.clone();
            block_on(async move {
                let acct =
                    crate::commands::accounts::add_account_impl(&state, acct_input("127.0.0.1", 1))
                        .await
                        .unwrap();
                acct.id
            })
        };
        let emit: Emit = Arc::new(|_| {});
        let h = spawn_worker(state.clone(), account_id.clone(), emit).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        let status = block_on(async { state.sync_status.lock().await.get(&account_id).cloned() });
        assert_eq!(status.map(|s| s.state).as_deref(), Some("paused-locked"));
        // No connection was observed — nothing reached the journal.
        assert!(block_on(state.sessions.lock()).is_empty());
        stop_worker(&state, &account_id, h);
    }

    #[test]
    fn worker_marks_backoff_on_refused_connect() {
        // IMAP account pointing at a closed local port — connect fails
        // fast, worker must land in backoff with a retry time.
        let state = Arc::new(test_state("refused"));
        let account_id = {
            let state = state.clone();
            block_on(async move {
                let acct = crate::commands::accounts::add_account_impl(
                    &state,
                    acct_input("127.0.0.1", 1), // nothing listens here
                )
                .await
                .unwrap();
                acct.id
            })
        };
        let emit: Emit = Arc::new(|_| {});
        let h = spawn_worker(state.clone(), account_id.clone(), emit).unwrap();
        // Wait (bounded) for the worker to record its first backoff.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = None;
        while std::time::Instant::now() < deadline {
            let s = block_on(async { state.sync_status.lock().await.get(&account_id).cloned() });
            if let Some(s) = &s
                && s.state == "backoff"
            {
                seen = Some(s.clone());
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let s = seen.expect("worker never reached backoff");
        assert!(s.next_retry_unix.unwrap() >= now_unix());
        assert!(s.last_error.is_some());
        assert_eq!(s.attempts, 1);
        stop_worker(&state, &account_id, h);
    }

    #[test]
    fn worker_exits_when_account_removed() {
        let state = Arc::new(test_state("gone"));
        let emit: Emit = Arc::new(|_| {});
        let account_id = "acct-ghost".to_string();
        // No account in store/index → worker writes "stopped" and exits.
        let h = spawn_worker(state.clone(), account_id.clone(), emit).unwrap();
        h.join().expect("worker should exit promptly");
        let s = block_on(async { state.sync_status.lock().await.get(&account_id).cloned() });
        assert_eq!(s.map(|s| s.state).as_deref(), Some("stopped"));
    }
}
