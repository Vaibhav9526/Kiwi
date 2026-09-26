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
use kiwi_mail::authstamp::AuthSealer;
use kiwi_mail::imap::{ImapAuth, ImapClient};
use kiwi_mail::mime::parse_message;
use kiwi_mail::pop3::Pop3Auth;
use kiwi_mail::sync::{sync_folder, sync_pop3_with_auth};
use kiwi_mail::transport::{TlsSettings, Transport};
use kiwi_mailauth::dns::HickoryResolver;

use super::{bounded, gate, resolve_secret, run_mail_io};
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{
    AttachmentView, FolderView, MessageBodyView, MessageView, SearchHitView, SyncReportView,
};

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

pub(crate) async fn list_folders_impl(
    state: &AppState,
    account_id: &str,
) -> CmdResult<Vec<FolderView>> {
    bounded("accountId", account_id, 128)?;
    if state.store.lock().await.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    let store = state.store.lock().await;
    let mut out = Vec::new();
    for meta in store.list_folders(account_id)? {
        let stats = store.folder_stats(meta.id)?;
        out.push(FolderView::from_meta(&meta, stats));
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

/// `kiwi_search_messages { query, folderId?, limit? }` → FTS hits,
/// newest first. Grammar lives in `kiwi_mail::search` (terms, `subject:`/
/// `from:`/`to:`/`body:` scopes, `"phrases"`, `-negation`). `folderId`
/// scopes the search to one folder; absent → every folder. The owning
/// `accountId` is resolved server-side per hit from the folder row —
/// the caller never guesses it. `has:`/`folder:` tokens are UI-side
/// post-filters and never reach this command.
#[tauri::command]
pub async fn kiwi_search_messages(
    state: State<'_, Arc<AppState>>,
    query: String,
    folder_id: Option<i64>,
    limit: Option<u32>,
) -> CmdResult<Vec<SearchHitView>> {
    gate(state.inner()).await?;
    search_messages_impl(state.inner(), &query, folder_id, limit).await
}

pub(crate) async fn search_messages_impl(
    state: &AppState,
    query: &str,
    folder_id: Option<i64>,
    limit: Option<u32>,
) -> CmdResult<Vec<SearchHitView>> {
    bounded("query", query, 512)?;
    if let Some(fid) = folder_id
        && fid < 0
    {
        return Err(IpcError::invalid("folderId must be >= 0"));
    }
    let limit = super::clamp_u32(limit, 50, 500);
    let store = state.store.lock().await;
    let metas = store.search(query, folder_id, limit)?;
    // folder → owning-account resolution, once per unique folder.
    let mut owners: std::collections::BTreeMap<i64, String> = std::collections::BTreeMap::new();
    let mut out = Vec::with_capacity(metas.len());
    for m in metas {
        let account_id = match owners.get(&m.folder_id) {
            Some(a) => a.clone(),
            None => {
                let a = store
                    .folder_meta(m.folder_id)?
                    .map(|f| f.account_id)
                    .unwrap_or_default();
                owners.insert(m.folder_id, a.clone());
                a
            }
        };
        out.push(SearchHitView {
            account_id,
            folder_id: m.folder_id,
            uid: m.uid,
            subject: m.subject.unwrap_or_default(),
            from_addr: m.from_addr.unwrap_or_default(),
            snippet: m.snippet.unwrap_or_default(),
            date_unix: m.date_unix,
            has_attachments: m.has_attachments,
        });
    }
    Ok(out)
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
        Some(raw) => body_view(&state, folder_id, uid as u64, &raw).await,
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

/// `kiwi_message_source { accountId, folderId, uid }` → verbatim RFC822
/// source (T-295 — the T-292 "view source" wire). Same fetch semantics as
/// `kiwi_get_message` (stored body, IMAP on-demand fetch recorded). A body
/// that is absent locally AND unfetchable is `not-found` — never an empty
/// string. Source is lossy-decoded and capped at 8 MiB (char-boundary
/// walk-back, same rule as `kiwi_render_body`).
#[tauri::command]
pub async fn kiwi_message_source(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<crate::types::MessageSourceView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        message_source_impl(s, account_id, folder_id, uid)
    })
    .await
}

/// 8 MiB wire cap — same bound `kiwi_render_body` documents (ipc.md §6b).
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) async fn message_source_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<crate::types::MessageSourceView> {
    bounded("accountId", &account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    match load_body_full(&state, &account_id, folder_id, uid as u64).await? {
        Some(raw) => {
            let bytes = raw.len() as u64;
            let text = String::from_utf8_lossy(&raw).into_owned();
            let capped =
                crate::commands::message::render::truncate_to_byte_cap(text, MAX_SOURCE_BYTES);
            Ok(crate::types::MessageSourceView {
                folder_id,
                uid: uid as u64,
                source: capped,
                bytes,
                truncated: bytes > MAX_SOURCE_BYTES as u64,
            })
        }
        None => Err(IpcError::not_found("message source not available")),
    }
}

/// Folder ownership + account lookup shared by the body loaders.
async fn owned_folder_account(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
) -> CmdResult<(String, IncomingProtocol, MailAccount)> {
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
    Ok((meta.name, acct.incoming.protocol, acct))
}

/// Shared body loader for get/render/attachment commands: ownership check →
/// stored body → on-demand IMAP fetch (recorded + stored). `Ok(None)` means
/// "not present locally and not fetchable" — never an IPC error.
///
/// T-339: `message_parts` rows mean the body is meant to be a *skeleton*
/// (headers + text leaves; attachment payloads deferred). The loader
/// composes and stores that skeleton; verbatim surfaces use
/// [`load_body_full`], which never accepts one.
pub(crate) async fn load_body_raw(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: u64,
) -> CmdResult<Option<Vec<u8>>> {
    let (folder_name, proto, acct) = owned_folder_account(state, account_id, folder_id).await?;

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
    let mut client = connect_imap(state, &acct).await?;
    client
        .select(&folder_name, false)
        .await
        .map_err(IpcError::from)?;

    // (bytes, complete) — a skeleton is honest reader data but not a
    // complete RFC822 body, so it skips the auth stamp and keeps its rows.
    let mut raw: Option<(Vec<u8>, bool)> = None;
    {
        let store = state.store.lock().await;
        if store.has_message_parts(folder_id, uid)?
            && kiwi_mail::sync::fetch_skeleton_body(&mut client, &store, folder_id, uid)
                .await
                .map_err(IpcError::from)?
        {
            // Skeleton stored — read it back for the caller. A disk flake
            // leaves `raw` empty → falls through to the BODY[] fetch.
            raw = store
                .body_file(folder_id, uid)?
                .and_then(|p| std::fs::read(p).ok())
                .map(|b| (b, false));
        }
    }
    if raw.is_none() {
        let items = client
            .uid_fetch(&uid.to_string(), &["UID", "BODY[]"])
            .await
            .map_err(IpcError::from)?;
        raw = items
            .first()
            .and_then(|f| f.bodies.first().map(|(_, b)| (b.clone(), true)));
    }
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
    let Some((raw, complete)) = raw else {
        return Ok(None);
    };
    {
        let store = state.store.lock().await;
        store.store_body(folder_id, uid, &raw)?;
        if complete {
            // The complete body ends the skeleton marker — its "payloads
            // are deferred" claim would now be a lie.
            let _ = store.clear_message_parts(folder_id, uid);
            // T-279: Authentication-Results on lazy body ingest — the same
            // evidence path `fetch_missing_bodies_with_auth` uses. IMAP
            // carries no SMTP receipt, so `receipt` is `None` and SPF
            // records `none` rather than a fabricated verdict. Stamp
            // failures degrade to "not evaluated" — they must not fail the
            // read. Skeleton bytes never reach this: stamping a partial
            // body would mint a fabricated DKIM verdict.
            if let Ok(parsed) = parse_message(&raw) {
                let stamp = auth_sealer().evaluate_and_stamp(&parsed, &raw, now_unix(), None);
                let _ = store.set_auth(folder_id, uid, &stamp);
            }
        }
    }
    remember_threading(state, folder_id, uid, &raw).await;
    Ok(Some(raw))
}

/// Complete-body loader for verbatim surfaces (view-source, mbox export —
/// T-339). `message_parts` rows mark the stored bytes as a skeleton: a
/// skeleton is never acceptable output there, so this forces a fresh
/// `BODY[]` regardless of what's on disk. The landed body replaces the
/// skeleton and clears the rows — the message is now whole.
///
/// Messages without part rows delegate to [`load_body_raw`] unchanged.
pub(crate) async fn load_body_full(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: u64,
) -> CmdResult<Option<Vec<u8>>> {
    let has_parts = {
        let store = state.store.lock().await;
        store.has_message_parts(folder_id, uid)?
    };
    if !has_parts {
        return load_body_raw(state, account_id, folder_id, uid).await;
    }
    let (folder_name, proto, acct) = owned_folder_account(state, account_id, folder_id).await?;
    if proto != IncomingProtocol::Imap {
        // Only IMAP sync writes part rows — unreachable in practice. A
        // stored local body is whatever it is; never fabricate.
        return load_body_raw(state, account_id, folder_id, uid).await;
    }
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
    {
        let store = state.store.lock().await;
        store.store_body(folder_id, uid, &raw)?;
        let _ = store.clear_message_parts(folder_id, uid);
        if let Ok(parsed) = parse_message(&raw) {
            let stamp = auth_sealer().evaluate_and_stamp(&parsed, &raw, now_unix(), None);
            let _ = store.set_auth(folder_id, uid, &stamp);
        }
    }
    remember_threading(state, folder_id, uid, &raw).await;
    Ok(Some(raw))
}

/// T-339: resolve a deferred attachment row to its stored payload,
/// fetching `UID FETCH BODY.PEEK[<section>]` on demand when absent.
///
/// The section comes from the persisted server-derived descriptor,
/// re-verified against a *fresh* BODYSTRUCTURE: index + section + mime
/// must all match, else the local uid has drifted from the server's
/// (post-move staleness, folder rebuild) and any bytes fetched would
/// belong to another message — fail closed. Returns the local payload
/// path; bytes never cross this API.
pub(crate) async fn ensure_part_fetched(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: u64,
    part_index: u32,
) -> CmdResult<std::path::PathBuf> {
    let (row, folder_name, acct) = {
        let store = state.store.lock().await;
        let row = store
            .message_part(folder_id, uid, part_index)?
            .ok_or_else(|| IpcError::not_found("no such attachment index"))?;
        let meta = store
            .folder_meta(folder_id)?
            .ok_or_else(|| IpcError::not_found("unknown folder"))?;
        if meta.account_id != account_id {
            return Err(IpcError::not_found("folder not on account"));
        }
        let acct = store
            .get_account(account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        (row, meta.name, acct)
    };
    let payload = {
        let store = state.store.lock().await;
        store.attachment_payload_path(folder_id, uid, part_index)
    };
    if row.fetched && payload.is_file() {
        return Ok(payload);
    }
    if acct.incoming.protocol != IncomingProtocol::Imap {
        return Err(IpcError::not_found("attachment payload not stored"));
    }
    let mut client = connect_imap(state, &acct).await?;
    let fetched: CmdResult<Vec<u8>> = async {
        client
            .select(&folder_name, false)
            .await
            .map_err(IpcError::from)?;
        let items = client
            .uid_fetch(&uid.to_string(), &["UID", "BODYSTRUCTURE"])
            .await
            .map_err(IpcError::from)?;
        let bs = items
            .iter()
            .find_map(|i| i.bodystructure.clone())
            .ok_or_else(|| IpcError::new("protocol-error", "server returned no BODYSTRUCTURE"))?;
        let plan = kiwi_mail::parts::plan_parts(&bs)
            .ok_or_else(|| IpcError::new("protocol-error", "BODYSTRUCTURE is not plannable"))?;
        let desc = plan
            .attachments
            .get(row.part_index as usize)
            .filter(|d| d.section == row.section && d.mime == row.mime)
            .ok_or_else(|| {
                IpcError::new(
                    "protocol-error",
                    "attachment map drifted — resync the folder",
                )
            })?;
        let item = format!("BODY.PEEK[{}]", desc.section);
        let items = client
            .uid_fetch(&uid.to_string(), &["UID", &item])
            .await
            .map_err(IpcError::from)?;
        let wire = items
            .iter()
            .flat_map(|i| i.bodies.iter())
            .find(|(key, _)| {
                kiwi_mail::parts::body_section(key).as_deref() == Some(desc.section.as_str())
            })
            .map(|(_, b)| b.clone())
            .ok_or_else(|| {
                IpcError::new(
                    "protocol-error",
                    "server omitted the requested BODY section",
                )
            })?;
        let decoded = kiwi_mail::parts::decode_transfer_encoding(&row.encoding, &wire)
            .map_err(IpcError::from)?;
        if decoded.len() > crate::commands::message::MAX_ATTACHMENT_BYTES {
            return Err(IpcError::invalid("attachment exceeds 50 MiB bound"));
        }
        Ok(decoded)
    }
    .await;
    // Every live IMAP session is observed, success or failure.
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
            label: "imap part fetch",
        },
    )
    .await;
    let _ = client.logout().await;
    let decoded = fetched?;
    let path = {
        let store = state.store.lock().await;
        let path = store.store_attachment(folder_id, uid, part_index, &decoded)?;
        store.mark_part_fetched(folder_id, uid, part_index)?;
        // Payload bytes arrived — the skeleton parse could only see
        // filename/type, so merge the byte-scan evidence in now. Merge
        // never drops earlier reasons and never downgrades a verdict.
        let mut evidence = store
            .get_attachment_risk(folder_id, uid)?
            .unwrap_or_default();
        evidence.merge(kiwi_mail::attachrisk::inspect_attachment(
            row.name.as_deref(),
            &row.mime,
            &decoded,
        ));
        let _ = store.set_attachment_risk(folder_id, uid, &evidence);
        path
    };
    state.audit.lock().await.record(
        "attachment-fetched",
        &format!(
            "{account_id}/f{folder_id}/u{uid}[{part_index}] → {}",
            row.name.as_deref().unwrap_or("(unnamed)")
        ),
        now_unix(),
    )?;
    Ok(path)
}

/// The production DNS resolver for Authentication-Results stamping
/// (T-279, `mailauth.md` §6). Built lazily on first lookup so startup
/// never blocks on DNS, and shared so hickory's answer cache stays warm
/// across syncs. A host with no working DNS memoizes the failed build —
/// lookups then return `Temp` instead of panicking or retrying forever.
pub(crate) fn auth_sealer() -> &'static HickoryResolver {
    static SEALER: std::sync::OnceLock<HickoryResolver> = std::sync::OnceLock::new();
    SEALER.get_or_init(HickoryResolver::system)
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

async fn body_view(
    state: &AppState,
    folder_id: i64,
    uid: u64,
    raw: &[u8],
) -> CmdResult<MessageBodyView> {
    let parsed = parse_message(raw).map_err(IpcError::from)?;
    let emails = |addrs: &[kiwi_mail::mime::Addr]| -> Vec<String> {
        addrs.iter().map(|a| a.email.clone()).collect()
    };
    // T-339: `message_parts` rows are authoritative for a message that has
    // them — the skeleton body's empty parts must never masquerade as the
    // real payload list. `fetched` tells the UI whether a save would hit
    // the wire first.
    let parts = state.store.lock().await.message_parts(folder_id, uid)?;
    let attachments = if parts.is_empty() {
        parsed
            .attachments
            .iter()
            .enumerate()
            .map(|(i, a)| AttachmentView {
                index: i as u32,
                filename: a.filename.clone(),
                content_type: a.content_type.clone(),
                size: a.size,
                fetched: true,
            })
            .collect()
    } else {
        parts
            .iter()
            .map(|p| AttachmentView {
                index: p.part_index,
                filename: p.name.clone(),
                content_type: p.mime.clone(),
                // Wire size for deferred parts (encoded octets), decoded
                // once fetched — the only honest numbers we have.
                size: p
                    .size_bytes
                    .and_then(|v| usize::try_from(v).ok())
                    .unwrap_or(0),
                fetched: p.fetched,
            })
            .collect()
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
        attachments,
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
    let mut client = ImapClient::connect_with(
        t,
        kiwi_mail::imap::ImapConfig {
            // KIWI_DEV_PLAINTEXT fixture seam — loopback hosts only.
            allow_plaintext_auth: kiwi_core::dev::plaintext_fixture_for(&acct.incoming.server.host),
        },
    )
    .await
    .map_err(IpcError::from)?;
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
            rule_failures: report.rule_failures,
            ..Default::default()
        });
    }
    // T-345: one tooltip refresh per pass — the count is global, not
    // per-folder, so refreshing inside the loop is waste.
    crate::tray::refresh_tooltip(state).await;
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
    let (accept_invalid, delete_after_download) = state
        .index
        .lock()
        .await
        .account_meta
        .get(&acct.account_id)
        .map(|m| (m.accept_invalid_certs, m.pop3_delete_after_download))
        .unwrap_or((false, false));
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
    let mut client = kiwi_mail::pop3::Pop3Client::connect(
        t,
        kiwi_mail::pop3::Pop3Config {
            // KIWI_DEV_PLAINTEXT fixture seam — loopback hosts only.
            allow_plaintext_auth: kiwi_core::dev::plaintext_fixture_for(&acct.incoming.server.host),
            ..Default::default()
        },
    )
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
        // T-279: stamp Authentication-Results at ingest. POP3 carries no
        // SMTP receipt context, so `receipt` stays `None` (SPF records
        // `none` with an explicit comment — never a guessed verdict).
        // T-295: `delete_after_download` is the per-account opt-in flag
        // (AccountMeta, default keep-on-server).
        let r = sync_pop3_with_auth(
            &mut client,
            &store,
            &acct.account_id,
            "INBOX",
            delete_after_download,
            now_unix(),
            auth_sealer(),
            None,
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
    // T-345: the tray tooltip tracks the same arrival.
    crate::tray::refresh_tooltip(state).await;
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
        rule_failures: report.rule_failures,
        ..Default::default()
    }])
}

/// `kiwi_set_pop3_policy { accountId, deleteAfterDownload }` — per-account
/// POP3 server-side deletion (T-295). Default off (keep-on-server); setting
/// `true` makes every later sync issue DELE per ingested drop — the email
/// then exists only locally. POP3-only, recorded + audited; never implied.
#[tauri::command]
pub async fn kiwi_set_pop3_policy(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    delete_after_download: bool,
) -> CmdResult<crate::types::Pop3PolicyView> {
    gate(state.inner()).await?;
    set_pop3_policy_impl(state.inner(), account_id, delete_after_download).await
}

pub(crate) async fn set_pop3_policy_impl(
    state: &AppState,
    account_id: String,
    delete_after_download: bool,
) -> CmdResult<crate::types::Pop3PolicyView> {
    bounded("accountId", &account_id, 128)?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(&account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;
    if acct.incoming.protocol != IncomingProtocol::Pop3 {
        return Err(IpcError::invalid(
            "pop3 policy applies to POP3 accounts only",
        ));
    }
    {
        let mut index = state.index.lock().await;
        index
            .account_meta
            .entry(account_id.clone())
            .or_default()
            .pop3_delete_after_download = delete_after_download;
        index.save(&state.data_dir)?;
    }
    state.audit.lock().await.record(
        "pop3-delete-policy",
        &format!(
            "{account_id}: {}",
            if delete_after_download {
                "delete after download"
            } else {
                "keep on server"
            }
        ),
        now_unix(),
    )?;
    Ok(crate::types::Pop3PolicyView {
        account_id,
        delete_after_download,
    })
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

    /// T-231: `kiwi_search_messages` — FTS hits carry the owning
    /// `accountId` resolved server-side; folderId scopes the search;
    /// bounds are enforced.
    async fn seed_searchable(state: &AppState) -> (i64, i64) {
        let acct = |id: &str| MailAccount {
            account_id: id.into(),
            display_name: "A".into(),
            email: format!("{id}@x.test"),
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
        let store = state.store.lock().await;
        store.upsert_account(&acct("a1")).unwrap();
        store.upsert_account(&acct("a2")).unwrap();
        let f1 = store.ensure_folder("a1", "INBOX").unwrap();
        let f2 = store.ensure_folder("a2", "INBOX").unwrap();
        for (fid, uid, subject) in [
            (f1, 1, "Quarterly invoice draft"),
            (f1, 2, "Lunch plans"),
            (f2, 1, "Invoice for a2"),
        ] {
            store
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid,
                        message_id: Some(format!("<s{uid}-{fid}@x>")),
                        subject: Some(subject.into()),
                        from_addr: Some("b@y.test".into()),
                        to_addrs: None,
                        date_unix: Some(1_700_000_000 + uid as i64),
                        size: None,
                        flags: vec![],
                        has_attachments: uid == 1,
                        snippet: Some(format!("snippet about {subject}")),
                        category: Default::default(),
                        unsub_http: None,
                        unsub_mailto: None,
                        unsub_oneclick: false,
                    },
                    now_unix(),
                )
                .unwrap();
        }
        (f1, f2)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn search_messages_returns_account_and_scopes() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-search-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        let (f1, _f2) = seed_searchable(&state).await;

        // Cross-account search: hits carry the resolved owner.
        let hits = search_messages_impl(&state, "invoice", None, None)
            .await
            .unwrap();
        assert_eq!(hits.len(), 2);
        let mut owners: Vec<&str> = hits.iter().map(|h| h.account_id.as_str()).collect();
        owners.sort_unstable();
        assert_eq!(owners, ["a1", "a2"]);
        assert!(hits.iter().all(|h| !h.subject.is_empty()));

        // Folder scope narrows to one account's folder.
        let scoped = search_messages_impl(&state, "invoice", Some(f1), None)
            .await
            .unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].account_id, "a1");
        assert_eq!(scoped[0].folder_id, f1);
        assert!(scoped[0].has_attachments);

        // Scoped grammar + negation pass through to the FTS layer.
        let from = search_messages_impl(&state, "subject:invoice", Some(f1), None)
            .await
            .unwrap();
        assert_eq!(from.len(), 1);
        let neg = search_messages_impl(&state, "invoice -draft", None, None)
            .await
            .unwrap();
        assert_eq!(neg.len(), 1);
        assert_eq!(neg[0].account_id, "a2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn search_messages_enforces_bounds() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-search2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();

        // Over-long query → invalid-input.
        let long = "x".repeat(600);
        let err = search_messages_impl(&state, &long, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid-input");
        // Negative folder id → invalid-input.
        let err = search_messages_impl(&state, "a", Some(-3), None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid-input");
        // Empty store → empty hits, no error.
        assert!(
            search_messages_impl(&state, "anything", None, None)
                .await
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T-264: `kiwi_list_folders` emits real store counts — `exists` is the
    /// row total and `unseen` counts rows without `\Seen`; both travel with
    /// moves and survive flag ops (never fabricated zeros).
    #[tokio::test(flavor = "current_thread")]
    async fn list_folders_reports_exists_and_unseen() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-foldstats-{}-{}",
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
        let meta = |uid: u64, seen: bool| NewMessageMeta {
            uid,
            message_id: Some(format!("<f{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some("b@y.test".into()),
            to_addrs: None,
            date_unix: Some(1_700_000_000),
            size: None,
            flags: if seen { vec!["\\Seen".into()] } else { vec![] },
            has_attachments: false,
            snippet: None,
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        };
        let fid = {
            let store = state.store.lock().await;
            store.upsert_account(&acct).unwrap();
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            let junk = store.ensure_folder("a1", "Junk").unwrap();
            store
                .upsert_message(fid, &meta(1, true), now_unix())
                .unwrap();
            store
                .upsert_message(fid, &meta(2, false), now_unix())
                .unwrap();
            store
                .upsert_message(fid, &meta(3, false), now_unix())
                .unwrap();
            store.mark_junk(fid, &[3]).unwrap(); // junk ≠ unseen change
            drop(store);
            let mut index = state.index.lock().await;
            index.remember_folder("a1", fid, "INBOX");
            index.remember_folder("a1", junk, "Junk");
            index.save(&state.data_dir).unwrap();
            fid
        };
        let folders = list_folders_impl(&state, "a1").await.unwrap();
        let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
        assert_eq!((inbox.exists, inbox.unseen), (3, 2));
        let junk = folders.iter().find(|f| f.name == "Junk").unwrap();
        assert_eq!((junk.exists, junk.unseen), (0, 0), "no rows yet");

        // Read one → unseen drops; exists unchanged.
        {
            let store = state.store.lock().await;
            store.set_flag(fid, &[2], "\\Seen", true).unwrap();
        }
        let folders = list_folders_impl(&state, "a1").await.unwrap();
        let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
        assert_eq!((inbox.exists, inbox.unseen), (3, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------
    // T-295 — kiwi_message_source + POP3 delete-after-download policy
    // -------------------------------------------------------------------

    fn test_acct(id: &str, pop3: bool) -> MailAccount {
        MailAccount {
            account_id: id.into(),
            display_name: "A".into(),
            email: format!("{id}@x.test"),
            incoming: kiwi_mail::account::IncomingAccount {
                protocol: if pop3 {
                    IncomingProtocol::Pop3
                } else {
                    IncomingProtocol::Imap
                },
                server: kiwi_mail::account::ServerConfig {
                    host: "in.x.test".into(),
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
        }
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kiwi-t295-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn message_source_roundtrips_stored_rfc822() {
        let dir = test_dir("src");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let fid = {
            let store = state.store.lock().await;
            store.upsert_account(&test_acct("a1", true)).unwrap();
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            // store_body sets body_path on the message row — it must exist.
            store
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid: 7,
                        message_id: Some("<src1@x>".into()),
                        subject: Some("raw hello".into()),
                        from_addr: Some("a@x.test".into()),
                        to_addrs: None,
                        date_unix: Some(100),
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
                    7,
                    b"Subject: raw hello\r\nX-Custom: kept\r\n\r\nbody bytes\r\n",
                )
                .unwrap();
            fid
        };
        let v = message_source_impl(state.clone(), "a1".into(), fid, 7)
            .await
            .expect("source");
        assert_eq!(v.folder_id, fid);
        assert_eq!(v.uid, 7);
        assert_eq!(
            v.source, "Subject: raw hello\r\nX-Custom: kept\r\n\r\nbody bytes\r\n",
            "verbatim RFC822 — no parse/normalization"
        );
        assert_eq!(v.bytes, 50);
        assert!(!v.truncated);

        // Absent body (POP3 — nothing fetchable) → honest not-found.
        let err = message_source_impl(state.clone(), "a1".into(), fid, 99)
            .await
            .expect_err("absent body must error");
        assert_eq!(err.code, "not-found");
        // uid bounds + unknown folder/account stay honest too.
        assert_eq!(
            message_source_impl(state.clone(), "a1".into(), fid, -1)
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        assert_eq!(
            message_source_impl(state.clone(), "ghost".into(), fid, 1)
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn message_source_byte_cap_is_honest() {
        let dir = test_dir("cap");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let fid = {
            let store = state.store.lock().await;
            store.upsert_account(&test_acct("a1", true)).unwrap();
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            // Just over the 8 MiB wire cap, multi-byte char at the
            // boundary proves the walk-back never splits a code point.
            let mut raw = vec![b'x'; MAX_SOURCE_BYTES - 1];
            raw.extend_from_slice("€".as_bytes()); // 3 bytes, straddles cap
            raw.extend_from_slice(b"tail");
            store
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid: 1,
                        message_id: Some("<big@x>".into()),
                        subject: None,
                        from_addr: None,
                        to_addrs: None,
                        date_unix: None,
                        size: Some(raw.len() as u64),
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
            store.store_body(fid, 1, &raw).unwrap();
            fid
        };
        let v = message_source_impl(state.clone(), "a1".into(), fid, 1)
            .await
            .expect("capped source");
        assert!(v.truncated);
        assert_eq!(v.bytes, (MAX_SOURCE_BYTES + 3 + 4 - 1) as u64);
        assert_eq!(v.source.len(), MAX_SOURCE_BYTES - 1);
        assert!(
            !v.source.ends_with('\u{fffd}'),
            "boundary walk-back must not fabricate a replacement char"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pop3_policy_toggle_persists_and_is_pop3_only() {
        let dir = test_dir("pol");
        let state = AppState::open_test(dir.clone()).unwrap();
        {
            let store = state.store.lock().await;
            store.upsert_account(&test_acct("p1", true)).unwrap();
            store.upsert_account(&test_acct("i1", false)).unwrap();
        }
        // Default: keep-on-server.
        assert!(
            !state
                .index
                .lock()
                .await
                .account_meta
                .get("p1")
                .map(|m| m.pop3_delete_after_download)
                .unwrap_or(false)
        );
        let v = set_pop3_policy_impl(&state, "p1".into(), true)
            .await
            .expect("toggle on");
        assert_eq!(v.account_id, "p1");
        assert!(v.delete_after_download);
        assert!(
            state
                .index
                .lock()
                .await
                .account_meta
                .get("p1")
                .unwrap()
                .pop3_delete_after_download
        );
        // Toggle back off persists (resume safety = keep).
        set_pop3_policy_impl(&state, "p1".into(), false)
            .await
            .expect("toggle off");
        assert!(
            !state
                .index
                .lock()
                .await
                .account_meta
                .get("p1")
                .unwrap()
                .pop3_delete_after_download
        );
        // IMAP account → invalid-input; unknown → not-found.
        assert_eq!(
            set_pop3_policy_impl(&state, "i1".into(), true)
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        assert_eq!(
            set_pop3_policy_impl(&state, "ghost".into(), true)
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
