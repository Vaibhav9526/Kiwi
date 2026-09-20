//! Mail read paths: folder list, message envelopes, body fetch (with
//! on-demand IMAP fetch for bodies not yet stored), and account sync.
//! All gated — mailbox access is closed while the endpoint is locked
//! (contract security-session.md §4).
//!
//! Commands that touch protocol clients run through `run_mail_io` — the
//! client/store types are `!Sync`-unfriendly inside `Send` futures.

use std::sync::Arc;

use tauri::State;

use kiwi_core::session::{AuthMechanism, Protocol};
use kiwi_mail::account::{AuthRef, IncomingProtocol, MailAccount};
use kiwi_mail::imap::{ImapAuth, ImapClient};
use kiwi_mail::mime::parse_message;
use kiwi_mail::pop3::Pop3Auth;
use kiwi_mail::sync::{sync_folder, sync_pop3};
use kiwi_mail::transport::{TlsSettings, Transport};

use super::{bounded, gate, resolve_secret, run_mail_io};
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{AttachmentView, FolderView, MessageBodyView, MessageView, SyncReportView};

/// `kiwi_list_folders { accountId }` → folders known for the account
/// (sync populates them; `INBOX` is auto-registered on first sync).
#[tauri::command]
pub async fn kiwi_list_folders(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<Vec<FolderView>> {
    gate(state.inner()).await?;
    list_folders_impl(state.inner(), &account_id).await
}

async fn list_folders_impl(state: &AppState, account_id: &str) -> CmdResult<Vec<FolderView>> {
    bounded("accountId", account_id, 128)?;
    let entries = state
        .index
        .lock()
        .await
        .folders
        .get(account_id)
        .cloned()
        .unwrap_or_default();
    let store = state.store.lock().await;
    let mut out = Vec::new();
    for e in entries {
        if let Some(meta) = store.folder_meta(e.id)? {
            out.push(FolderView::from(&meta));
        }
    }
    Ok(out)
}

/// `kiwi_list_messages { accountId, folderId, limit? }` → envelopes,
/// newest first (store returns ascending uid).
#[tauri::command]
pub async fn kiwi_list_messages(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    limit: Option<u32>,
) -> CmdResult<Vec<MessageView>> {
    gate(state.inner()).await?;
    list_messages_impl(state.inner(), account_id, folder_id, limit).await
}

pub(crate) async fn list_messages_impl(
    state: &AppState,
    account_id: String,
    folder_id: i64,
    limit: Option<u32>,
) -> CmdResult<Vec<MessageView>> {
    bounded("accountId", &account_id, 128)?;
    let limit = super::clamp_u32(limit, 50, 500);
    let store = state.store.lock().await;
    // Folder must belong to the claimed account (cross-account reads denied).
    let meta = store
        .folder_meta(folder_id)?
        .ok_or_else(|| IpcError::not_found("unknown folder"))?;
    if meta.account_id != account_id {
        return Err(IpcError::not_found("folder not on account"));
    }
    let metas = store.list_messages(folder_id, limit)?;
    // Pre-resolve body paths for lazy threading-header learning — the
    // store lock is dropped before the index lock (no nested locks).
    let mut body_paths: Vec<Option<std::path::PathBuf>> = metas
        .iter()
        .map(|m| {
            if m.body_path.is_some() {
                store.body_file(m.folder_id, m.uid).ok().flatten()
            } else {
                None
            }
        })
        .collect();
    drop(store);
    let mut msgs = metas.iter().map(MessageView::from).collect::<Vec<_>>();
    msgs.reverse();
    body_paths.reverse(); // same permutation as msgs

    // T-169: join the threading-header cache; lazily learn from stored
    // bodies (≤32 parses per call — bounded work).
    let mut index = state.index.lock().await;
    let mut dirty = false;
    let mut budget = 32usize;
    for (i, v) in msgs.iter_mut().enumerate() {
        let key = crate::state::thread_key(v.folder_id, v.uid);
        if let Some(h) = index.thread_headers.get(&key) {
            v.in_reply_to = h.in_reply_to.clone();
            v.references = h.references.clone();
            continue;
        }
        if budget == 0 {
            continue;
        }
        let Some(path) = body_paths.get(i).and_then(|p| p.as_ref()) else {
            continue;
        };
        budget -= 1;
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(p) = parse_message(&bytes) else {
            continue;
        };
        v.in_reply_to = p.in_reply_to.clone();
        v.references = p.references.clone();
        index.remember_thread_headers(
            v.folder_id,
            v.uid,
            crate::state::ThreadHeaders {
                in_reply_to: p.in_reply_to,
                references: p.references,
            },
        );
        dirty = true;
    }
    if dirty {
        let _ = index.save(&state.data_dir);
    }
    Ok(msgs)
}

/// `kiwi_get_message { accountId, folderId, uid }` → parsed body view.
/// If the body isn't stored locally and the account is IMAP, fetches
/// `BODY[]` on demand and stores it first.
#[tauri::command]
pub async fn kiwi_get_message(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<MessageBodyView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| get_message_impl(s, account_id, folder_id, uid)).await
}

pub(crate) async fn get_message_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<MessageBodyView> {
    bounded("accountId", &account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    match load_body_raw(&state, &account_id, folder_id, uid as u64).await? {
        Some(raw) => body_view(folder_id, uid as u64, &raw).await,
        None => Ok(MessageBodyView {
            folder_id,
            uid: uid as u64,
            message_id: None,
            subject: None,
            from: vec![],
            to: vec![],
            cc: vec![],
            date_unix: None,
            text_body: None,
            html_body: None,
            attachments: vec![],
            body_present: false,
            in_reply_to: None,
            references: vec![],
        }),
    }
}

/// Shared body loader for get/render/attachment commands: ownership check →
/// stored body → on-demand IMAP fetch (recorded + stored). `Ok(None)` means
/// "not present locally and not fetchable" — never an IPC error.
pub(crate) async fn load_body_raw(
    state: &Arc<AppState>,
    account_id: &str,
    folder_id: i64,
    uid: u64,
) -> CmdResult<Option<Vec<u8>>> {
    let (folder_name, proto) = {
        let store = state.store.lock().await;
        let meta = store
            .folder_meta(folder_id)?
            .ok_or_else(|| IpcError::not_found("unknown folder"))?;
        if meta.account_id != account_id {
            return Err(IpcError::not_found("folder not on account"));
        }
        let acct = store
            .get_account(account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        (meta.name, acct.incoming.protocol)
    };

    // Body on disk? Read it (and harvest threading headers once — T-169).
    let raw = {
        let store = state.store.lock().await;
        store
            .body_file(folder_id, uid)?
            .and_then(|p| std::fs::read(p).ok())
    };
    if let Some(raw) = raw {
        remember_threading(state, folder_id, uid, &raw).await;
        return Ok(Some(raw));
    }

    // Not stored — fetch on demand for IMAP (recorded observation).
    if proto != IncomingProtocol::Imap {
        return Ok(None);
    }
    let acct = state
        .store
        .lock()
        .await
        .get_account(account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;
    let mut client = connect_imap(state, &acct).await?;
    client
        .select(&folder_name, false)
        .await
        .map_err(IpcError::from)?;
    let items = client
        .uid_fetch(&uid.to_string(), &["UID", "BODY[]"])
        .await
        .map_err(IpcError::from)?;
    let raw = items
        .first()
        .and_then(|f| f.bodies.first().map(|(_, b)| b.clone()));
    let facts = observe::facts_of(client.transport());
    observe::record_connection(
        state,
        facts,
        ObservationContext {
            protocol: Protocol::Imap,
            account_id: Some(account_id.to_string()),
            starttls_offered: Some(client.has_capability("STARTTLS")),
            auth_mechanism: auth_mech_of(&acct.incoming.auth),
            auth_succeeded: Some(true),
            label: "imap fetch",
        },
    )
    .await;
    let _ = client.logout().await;
    let Some(raw) = raw else {
        return Ok(None);
    };
    state.store.lock().await.store_body(folder_id, uid, &raw)?;
    remember_threading(state, folder_id, uid, &raw).await;
    Ok(Some(raw))
}

/// Cache a body-bearing message's threading headers into the sidecar
/// index (T-169). Called from every path that has a body in hand —
/// never fails the caller (headers are best-effort derived data).
pub(crate) async fn remember_threading(state: &AppState, folder_id: i64, uid: u64, raw: &[u8]) {
    // Cheap pre-check: cached already → skip the parse entirely.
    let key = crate::state::thread_key(folder_id, uid);
    if state.index.lock().await.thread_headers.contains_key(&key) {
        return;
    }
    let Ok(parsed) = parse_message(raw) else {
        return;
    };
    let mut index = state.index.lock().await;
    index.remember_thread_headers(
        folder_id,
        uid,
        crate::state::ThreadHeaders {
            in_reply_to: parsed.in_reply_to,
            references: parsed.references,
        },
    );
    let _ = index.save(&state.data_dir);
}

/// Fetch `In-Reply-To`/`References` for freshly-synced uids via
/// `BODY.PEEK[HEADER.FIELDS]` — one fetch per ≤200-uid chunk, only for
/// uids the store just learned. Best-effort: a hiccup leaves the fields
/// null rather than failing the sync. (T-169)
pub(crate) async fn capture_thread_headers(
    state: &AppState,
    client: &mut ImapClient,
    folder_id: i64,
    new_uids: &[u64],
) {
    for chunk in new_uids
        .iter()
        .take(2000)
        .copied()
        .collect::<Vec<_>>()
        .chunks(200)
    {
        let set = chunk
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let Ok(items) = client
            .uid_fetch(
                &set,
                &["UID", "BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]"],
            )
            .await
        else {
            return;
        };
        let mut index = state.index.lock().await;
        for item in &items {
            let Some(uid) = item.uid else { continue };
            for (_, bytes) in &item.bodies {
                let Ok(p) = parse_message(bytes) else {
                    continue;
                };
                index.remember_thread_headers(
                    folder_id,
                    uid,
                    crate::state::ThreadHeaders {
                        in_reply_to: p.in_reply_to,
                        references: p.references,
                    },
                );
            }
        }
        let _ = index.save(&state.data_dir);
    }
}

async fn body_view(folder_id: i64, uid: u64, raw: &[u8]) -> CmdResult<MessageBodyView> {
    let parsed = parse_message(raw).map_err(IpcError::from)?;
    let emails = |addrs: &[kiwi_mail::mime::Addr]| -> Vec<String> {
        addrs.iter().map(|a| a.email.clone()).collect()
    };
    Ok(MessageBodyView {
        folder_id,
        uid,
        message_id: parsed.message_id,
        subject: parsed.subject,
        from: emails(&parsed.from),
        to: emails(&parsed.to),
        cc: emails(&parsed.cc),
        date_unix: parsed.date_unix,
        text_body: parsed.text_body,
        html_body: parsed.html_body,
        attachments: parsed
            .attachments
            .iter()
            .map(|a| AttachmentView {
                filename: a.filename.clone(),
                content_type: a.content_type.clone(),
                size: a.size,
            })
            .collect(),
        body_present: true,
        in_reply_to: parsed.in_reply_to.clone(),
        references: parsed.references.clone(),
    })
}

/// Auth mechanism label for session records, from the account's `AuthRef`.
pub(crate) fn auth_mech_of(auth: &AuthRef) -> AuthMechanism {
    match auth {
        AuthRef::None => AuthMechanism::None,
        AuthRef::Password { .. } | AuthRef::Apop { .. } => AuthMechanism::Login,
        AuthRef::XOAuth2 { .. } => AuthMechanism::XOAuth2,
    }
}

/// Connect + authenticate an IMAP session for the account. Caller must
/// `record_connection` + `logout`.
pub(crate) async fn connect_imap(state: &AppState, acct: &MailAccount) -> CmdResult<ImapClient> {
    let accept_invalid = state
        .index
        .lock()
        .await
        .account_meta
        .get(&acct.account_id)
        .map(|m| m.accept_invalid_certs)
        .unwrap_or(false);
    let t = Transport::connect(
        &acct.incoming.server.host,
        acct.incoming.server.port,
        acct.incoming.server.security,
        TlsSettings {
            accept_invalid_certs: accept_invalid,
            extra_roots: Vec::new(),
        },
    )
    .await
    .map_err(IpcError::from)?;
    let mut client = ImapClient::connect(t).await.map_err(IpcError::from)?;
    let secret = resolve_secret(state, &acct.incoming.auth)?;
    if let Some(secret) = secret {
        let auth = match acct.incoming.auth {
            AuthRef::XOAuth2 { .. } => ImapAuth::XOAuth2 {
                user: acct.incoming.username.clone(),
                token: secret,
            },
            _ => ImapAuth::Login {
                user: acct.incoming.username.clone(),
                password: secret,
            },
        };
        client.authenticate(&auth).await.map_err(IpcError::from)?;
    }
    Ok(client)
}

/// `kiwi_sync_account { accountId, folders? }` → per-folder sync reports.
/// IMAP: LIST → register folders → `sync_folder` each. POP3: `sync_pop3`
/// into INBOX. Every connection is recorded (observation → trust + findings).
#[tauri::command]
pub async fn kiwi_sync_account(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folders: Option<Vec<String>>,
) -> CmdResult<Vec<SyncReportView>> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| sync_account_impl(s, account_id, folders)).await
}

pub(crate) async fn sync_account_impl(
    state: Arc<AppState>,
    account_id: String,
    folders: Option<Vec<String>>,
) -> CmdResult<Vec<SyncReportView>> {
    bounded("accountId", &account_id, 128)?;
    if let Some(fs) = &folders {
        if fs.len() > 64 {
            return Err(IpcError::invalid("folders list exceeds 64"));
        }
        for f in fs {
            bounded("folder", f, 256)?;
        }
    }
    let acct = state
        .store
        .lock()
        .await
        .get_account(&account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;
    match acct.incoming.protocol {
        IncomingProtocol::Imap => imap_sync(&state, &acct, folders).await,
        IncomingProtocol::Pop3 => pop3_sync(&state, &acct).await,
    }
}

/// Per-message facts needed for a §11 received event — collected from the
/// store for messages that are new since the sync's UID snapshot.
/// `pub(crate)` for the live-sync worker (T-157).
pub(crate) struct ReceivedFact {
    sender: Option<String>,
    message_id: Option<String>,
    /// Message time (`date_unix`) per §6 `ts` semantics.
    ts: i64,
}

/// Diff a folder's UID set around a sync and collect §11 facts for the
/// newly-arrived messages (bounded — §11 emit failures never fail sync).
/// `pub(crate)` for the live-sync worker (T-157).
pub(crate) async fn collect_received(
    state: &AppState,
    folder_id: i64,
    before: &std::collections::BTreeSet<u64>,
    out: &mut Vec<ReceivedFact>,
) -> CmdResult<()> {
    if out.len() >= 200 {
        return Ok(());
    }
    let store = state.store.lock().await;
    let new_uids: Vec<u64> = store
        .folder_uids(folder_id)?
        .into_iter()
        .filter(|u| !before.contains(u))
        .take(200 - out.len())
        .collect();
    if new_uids.is_empty() {
        return Ok(());
    }
    // Newest-first listing — fresh arrivals sit at the top; bound the scan.
    let scan = new_uids.len().clamp(64, 500) as u32;
    let metas = store.list_messages(folder_id, scan)?;
    for uid in new_uids {
        if let Some(m) = metas.iter().find(|m| m.uid == uid) {
            out.push(ReceivedFact {
                sender: m.from_addr.clone(),
                message_id: m.message_id.clone(),
                // §6 `ts` is message time; fall back to now when unobserved.
                ts: m.date_unix.unwrap_or_else(now_unix),
            });
        }
    }
    Ok(())
}

/// Emit §11 inbound events for everything `collect_received` gathered.
/// Sender-less messages can't honestly emit (§6 requires a non-empty
/// sender) — they're skipped. Never fails the sync.
/// `pub(crate)` for the live-sync worker (T-157).
pub(crate) async fn emit_received(
    state: &AppState,
    endpoint: &crate::bridge::AdminEndpoint,
    acct: &MailAccount,
    received: Vec<ReceivedFact>,
    tls_label: Option<&'static str>,
    security_status: &str,
) {
    let events: Vec<_> = received
        .iter()
        .filter_map(|m| {
            m.sender.as_deref().map(|s| {
                crate::bridge::build_received_event(
                    endpoint.org_id.as_deref(),
                    s,
                    &acct.email,
                    tls_label,
                    security_status,
                    m.message_id.as_deref(),
                    m.ts,
                )
            })
        })
        .collect();
    crate::bridge::emit_events(state, endpoint, events).await;
}

async fn imap_sync(
    state: &AppState,
    acct: &MailAccount,
    folders: Option<Vec<String>>,
) -> CmdResult<Vec<SyncReportView>> {
    let endpoint = crate::bridge::resolve_endpoint(state).await;
    let mut client = connect_imap(state, acct).await?;
    let folder_names = match folders {
        Some(fs) => fs,
        None => {
            let listed = client.list("", "*").await.map_err(IpcError::from)?;
            listed.iter().map(|m| m.name.clone()).collect::<Vec<_>>()
        }
    };
    let mut reports = Vec::new();
    let mut received: Vec<ReceivedFact> = Vec::new();
    for name in folder_names.iter().take(64) {
        // Register the folder + capture its row id before syncing into it.
        let (folder_id, before_uids) = {
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
            sync_folder(&mut client, &store, &acct.account_id, name, now_unix())
                .await
                .map_err(IpcError::from)?
        };
        if endpoint.is_some() {
            collect_received(state, folder_id, &before_uids, &mut received).await?;
        }
        // T-169: harvest threading headers for just-arrived uids.
        {
            let new_uids: Vec<u64> = state
                .store
                .lock()
                .await
                .folder_uids(folder_id)?
                .into_iter()
                .filter(|u| !before_uids.contains(u))
                .take(2000)
                .collect();
            if !new_uids.is_empty() {
                capture_thread_headers(state, &mut client, folder_id, &new_uids).await;
            }
        }
        reports.push(SyncReportView {
            protocol: "imap".into(),
            folder: name.clone(),
            folder_id,
            new_messages: report.new_messages,
            flag_updates: report.flag_updates,
            expunged: report.expunged,
            remote_exists: report.remote_exists,
            uid_validity_reset: report.uid_validity_reset,
            ..Default::default()
        });
    }
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
            protocol: Protocol::Imap,
            account_id: Some(acct.account_id.clone()),
            starttls_offered: Some(client.has_capability("STARTTLS")),
            auth_mechanism: auth_mech_of(&acct.incoming.auth),
            auth_succeeded: Some(true),
            label: "imap sync",
        },
    )
    .await;
    if let Some(ep) = &endpoint {
        emit_received(
            state,
            ep,
            acct,
            received,
            tls_label,
            crate::bridge::security_status_label(true, record.findings.iter().map(|f| f.severity)),
        )
        .await;
    }
    let _ = client.logout().await;
    Ok(reports)
}

/// `pub(crate)`: the live-sync worker reuses this as its POP3 poll pass
/// (T-157) — it already does connect → auth → sync → observe → §11 emit.
pub(crate) async fn pop3_sync(
    state: &AppState,
    acct: &MailAccount,
) -> CmdResult<Vec<SyncReportView>> {
    let accept_invalid = state
        .index
        .lock()
        .await
        .account_meta
        .get(&acct.account_id)
        .map(|m| m.accept_invalid_certs)
        .unwrap_or(false);
    let t = Transport::connect(
        &acct.incoming.server.host,
        acct.incoming.server.port,
        acct.incoming.server.security,
        TlsSettings {
            accept_invalid_certs: accept_invalid,
            extra_roots: Vec::new(),
        },
    )
    .await
    .map_err(IpcError::from)?;
    let mut client =
        kiwi_mail::pop3::Pop3Client::connect(t, kiwi_mail::pop3::Pop3Config::default())
            .await
            .map_err(IpcError::from)?;
    if let Some(secret) = resolve_secret(state, &acct.incoming.auth)? {
        let auth = match acct.incoming.auth {
            AuthRef::Apop { .. } => Pop3Auth::Apop {
                user: acct.incoming.username.clone(),
                password: secret,
            },
            _ => Pop3Auth::UserPass {
                user: acct.incoming.username.clone(),
                password: secret,
            },
        };
        client.authenticate(&auth).await.map_err(IpcError::from)?;
    }
    let endpoint = crate::bridge::resolve_endpoint(state).await;
    let (report, folder_id, mut received) = {
        let store = state.store.lock().await;
        let folder_id = store.ensure_folder(&acct.account_id, "INBOX")?;
        let before: std::collections::BTreeSet<u64> =
            store.folder_uids(folder_id)?.into_iter().collect();
        let r = sync_pop3(
            &mut client,
            &store,
            &acct.account_id,
            "INBOX",
            false,
            now_unix(),
        )
        .await
        .map_err(IpcError::from)?;
        let mut received = Vec::new();
        if endpoint.is_some() {
            drop(store);
            collect_received(state, folder_id, &before, &mut received).await?;
        }
        (r, folder_id, received)
    };
    {
        let mut index = state.index.lock().await;
        index.remember_folder(&acct.account_id, folder_id, "INBOX");
        index.save(&state.data_dir)?;
    }
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
            protocol: Protocol::Pop3,
            account_id: Some(acct.account_id.clone()),
            starttls_offered: Some(client.has_capa("STLS")),
            auth_mechanism: auth_mech_of(&acct.incoming.auth),
            auth_succeeded: Some(true),
            label: "pop3 sync",
        },
    )
    .await;
    if let Some(ep) = &endpoint {
        emit_received(
            state,
            ep,
            acct,
            std::mem::take(&mut received),
            tls_label,
            crate::bridge::security_status_label(true, record.findings.iter().map(|f| f.severity)),
        )
        .await;
    }
    let _ = client.quit().await;
    Ok(vec![SyncReportView {
        protocol: "pop3".into(),
        folder: "INBOX".into(),
        folder_id,
        downloaded: report.downloaded,
        deleted_remote: report.deleted_remote,
        remote_exists: report.remote_drops,
        ..Default::default()
    }])
}

/// `kiwi_sync_status { accountId? }` → per-account live-sync worker status
/// (T-157). One row per configured account; a worker that hasn't run yet
/// reports `state: "pending"`. Unknown `accountId` → `not-found`.
#[tauri::command]
pub async fn kiwi_sync_status(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
) -> CmdResult<Vec<crate::types::SyncStatusView>> {
    gate(state.inner()).await?;
    let state = state.inner();
    if let Some(id) = &account_id {
        bounded("accountId", id, 128)?;
    }
    let index = state.index.lock().await;
    let known: Vec<String> = match &account_id {
        Some(id) => {
            if !index.account_ids.contains(id) {
                return Err(IpcError::not_found("unknown account"));
            }
            vec![id.clone()]
        }
        None => index.account_ids.clone(),
    };
    let map = state.sync_status.lock().await;
    Ok(known
        .into_iter()
        .map(|id| {
            let s = map.get(&id);
            crate::types::SyncStatusView {
                account_id: id,
                state: s
                    .map(|s| s.state.clone())
                    .unwrap_or_else(|| "pending".into()),
                last_sync_unix: s.and_then(|s| s.last_sync_unix),
                last_error: s.and_then(|s| s.last_error.clone()),
                next_retry_unix: s.and_then(|s| s.next_retry_unix),
                folders_synced: s.map(|s| s.folders_synced).unwrap_or(0),
                new_messages: s.map(|s| s.new_messages).unwrap_or(0),
                attempts: s.map(|s| s.attempts).unwrap_or(0),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::store::NewMessageMeta;

    /// T-169: stored bodies teach the threading cache; list_messages
    /// joins it into MessageView.
    #[tokio::test(flavor = "current_thread")]
    async fn list_messages_fills_threading_from_stored_body() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-thread-{}-{}",
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
            incoming: kiwi_mail::account::IncomingAccount {
                protocol: IncomingProtocol::Pop3,
                server: kiwi_mail::account::ServerConfig {
                    host: "pop.x.test".into(),
                    port: 995,
                    security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
            outgoing: kiwi_mail::account::OutgoingAccount {
                server: kiwi_mail::account::ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
        };
        let fid;
        {
            let store = state.store.lock().await;
            store.upsert_account(&acct).unwrap();
            fid = store.ensure_folder("a1", "INBOX").unwrap();
            store
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid: 7,
                        message_id: Some("<m2@x>".into()),
                        subject: Some("Re: t".into()),
                        from_addr: None,
                        to_addrs: None,
                        date_unix: None,
                        size: None,
                        flags: vec![],
                        has_attachments: false,
                        snippet: None,
                    },
                    now_unix(),
                )
                .unwrap();
            store
                .store_body(
                    fid,
                    7,
                    b"From: a@x\r\nTo: b@y\r\nSubject: Re: t\r\nMessage-ID: <m2@x>\r\nIn-Reply-To: <m1@x>\r\nReferences: <m0@x>\r\n  <m1@x>\r\n\r\nbody\r\n",
                )
                .unwrap();
        }

        let views = list_messages_impl(&state, "a1".into(), fid, None)
            .await
            .unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].in_reply_to.as_deref(), Some("m1@x"));
        assert_eq!(views[0].references, vec!["m0@x", "m1@x"]); // folded hdr
        // Cached in the index for subsequent lists.
        assert!(
            state
                .index
                .lock()
                .await
                .thread_headers
                .contains_key(&crate::state::thread_key(fid, 7))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remember_threading_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-thread2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let raw = b"Subject: x\r\nIn-Reply-To: <p@x>\r\n\r\nb";
        remember_threading(&state, 1, 9, raw).await;
        remember_threading(&state, 1, 9, raw).await; // no dup / no panic
        let index = state.index.lock().await;
        let h = index
            .thread_headers
            .get(&crate::state::thread_key(1, 9))
            .unwrap();
        assert_eq!(h.in_reply_to.as_deref(), Some("p@x"));
        // Empty-headers bodies are not cached (absence = "unknown").
        drop(index);
        remember_threading(&state, 1, 10, b"Subject: y\r\n\r\nb").await;
        assert!(
            !state
                .index
                .lock()
                .await
                .thread_headers
                .contains_key(&crate::state::thread_key(1, 10))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
