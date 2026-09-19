//! Application state shared by all IPC commands.
//!
//! One `AppState` lives behind `tauri::State`. It owns: the mail store
//! handle, the kiwi-core trust machine + registries, the in-memory send
//! queue, the bounded session/finding journals fed by `observe`, the
//! endpoint-signal set fed by `signals` (T-121), the OS credential binding,
//! and a small sidecar index (`index.json`) covering what `MailStore`
//! does not yet expose (account enumeration, account→folder list,
//! per-account client options, org binding). Sidecar writes are
//! write-then-rename so a crash never leaves a torn file.
//!
//! Concurrency: async commands take `tokio::sync::Mutex` guards; guards are
//! never held across network awaits — each command locks, extracts what it
//! needs, drops, then does I/O.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use kiwi_core::challenge::ChallengeBook;
use kiwi_core::device::DeviceRegistry;
use kiwi_core::policy::TrustPolicy;
use kiwi_core::session::SecuritySession;
use kiwi_core::trust::{TrustMachine, TrustSignal};
use kiwi_forensics::findings::Finding;
use kiwi_mail::account::CredentialStore;
use kiwi_mail::smtp::SendQueue;
use kiwi_mail::store::MailStore;

use crate::audit::AuditLog;
use crate::credstore::OsCredentialStore;
use crate::error::{CmdResult, IpcError};

/// Bound on retained session observations (ring buffer).
pub const MAX_SESSIONS: usize = 512;
/// Bound on retained findings (deduped by finding id, latest wins).
pub const MAX_FINDINGS: usize = 4096;

/// One observed mail connection and everything it produced.
#[derive(Clone)]
pub struct SessionRecord {
    pub session: SecuritySession,
    /// Session-derived trust signals (kiwi-core `session_signals`).
    pub signals: Vec<TrustSignal>,
    /// Deterministic findings from the forensics rule engine.
    pub findings: Vec<Finding>,
    /// Auth/usage notes for the event view ("imap login", "smtp send").
    pub label: String,
}

/// Per-account client options the `MailAccount` model does not carry —
/// kept in the sidecar index until kiwi-mail grows the fields (see status
/// log: store/model gaps).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountMeta {
    /// Explicit per-account opt-in for certificate-validation failures —
    /// the setup wizard's "accept once" consent. Recorded + audited, never
    /// implied. Default false (strict).
    #[serde(default)]
    pub accept_invalid_certs: bool,
    /// Explicit per-account opt-in to REMOTE content in rendered HTML
    /// bodies (images/fonts fetched from the network — a tracking surface).
    /// Recorded + audited, never implied. Default false (stripped).
    #[serde(default)]
    pub remote_content_allowed: bool,
    /// Org binding for the send-path policy bridge (admin-api §10).
    #[serde(default)]
    pub org_id: Option<String>,
}

/// Folder the account is known to have (id is the mail-store row id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderEntry {
    pub id: i64,
    pub name: String,
}

/// Per-queued-send metadata kept alongside `SendQueue` (which has no item
/// iterator) for `kiwi_list_outbox` and dispatch context. Serialized —
/// outbox items persist to `data_dir/outbox/<queue_id>.{json,eml}` so
/// pending sends survive a restart (T-142).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxMeta {
    pub account_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    /// MIME Message-ID — used as mailflow `message_id` (§11 correlation).
    pub message_id: String,
    pub not_before_unix: i64,
    pub undo_window_until_unix: i64,
    pub attempts: u32,
}

/// Local admin-service binding (kiwi-admin, localhost only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgBinding {
    pub org_id: String,
    pub base_url: String,
}

/// Sidecar index — app-layer bookkeeping that is NOT mail data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppIndex {
    pub schema_version: u32,
    /// This endpoint's own device id (generated once, persisted).
    pub device_id: String,
    #[serde(default)]
    pub account_ids: Vec<String>,
    #[serde(default)]
    pub account_meta: BTreeMap<String, AccountMeta>,
    /// account_id → known folders (populated by sync / manual creation).
    #[serde(default)]
    pub folders: BTreeMap<String, Vec<FolderEntry>>,
    /// Registered authenticator device ids (DeviceRegistry has no
    /// enumeration API — the index keeps the id list).
    #[serde(default)]
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub org: Option<OrgBinding>,
}

impl Default for AppIndex {
    fn default() -> Self {
        Self {
            schema_version: 1,
            device_id: new_id("dev"),
            account_ids: Vec::new(),
            account_meta: BTreeMap::new(),
            folders: BTreeMap::new(),
            device_ids: Vec::new(),
            org: None,
        }
    }
}

impl AppIndex {
    fn load(dir: &Path) -> CmdResult<Self> {
        let path = dir.join("index.json");
        if !path.exists() {
            let idx = Self::default();
            idx.save(dir)?;
            return Ok(idx);
        }
        let text = std::fs::read_to_string(&path)?;
        serde_json::from_str(&text)
            .map_err(|e| IpcError::new("store-error", format!("index.json corrupt: {e}")))
    }

    /// Persist atomically (write-then-rename).
    pub fn save(&self, dir: &Path) -> CmdResult<()> {
        let path = dir.join("index.json");
        let tmp = dir.join("index.json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| IpcError::new("internal", format!("index serialize: {e}")))?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn remember_folder(&mut self, account_id: &str, id: i64, name: &str) {
        let list = self.folders.entry(account_id.to_string()).or_default();
        if !list.iter().any(|f| f.id == id) {
            list.push(FolderEntry {
                id,
                name: name.to_string(),
            });
        }
    }
}

// --- Outbox persistence (T-142) ----------------------------------------------
// Each queued send is two files: `outbox/<queue_id>.json` (OutboxMeta) and
// `outbox/<queue_id>.eml` (the built MIME message). Writes are
// write-then-rename; loads bound count (256) and size (32 MiB/item,
// 100 MiB total). Body bytes at rest share mail.db's sensitivity — local
// disk only, never IPC.

/// Max persisted outbox items reloaded at boot.
const MAX_OUTBOX_ITEMS: usize = 256;
/// Max size of one persisted message.
const MAX_OUTBOX_ITEM_BYTES: usize = 32 * 1024 * 1024;
/// Max total persisted payload.
const MAX_OUTBOX_TOTAL_BYTES: usize = 100 * 1024 * 1024;

fn outbox_dir(dir: &Path) -> PathBuf {
    dir.join("outbox")
}

fn outbox_meta_path(dir: &Path, queue_id: &str) -> PathBuf {
    outbox_dir(dir).join(format!("{queue_id}.json"))
}

fn outbox_body_path(dir: &Path, queue_id: &str) -> PathBuf {
    outbox_dir(dir).join(format!("{queue_id}.eml"))
}

/// Persist one queued send (meta + MIME bytes), atomically per file.
/// Called by the send path at enqueue time. `queue_id` is generated by us
/// (`send-<hex>`) — the charset check is a backstop for filename safety.
pub fn persist_outbox_item(
    dir: &Path,
    queue_id: &str,
    meta: &OutboxMeta,
    mime: &[u8],
) -> CmdResult<()> {
    if !meta_filesafe(queue_id) {
        return Err(IpcError::invalid("queue_id is not filename-safe"));
    }
    if mime.len() > MAX_OUTBOX_ITEM_BYTES {
        return Err(IpcError::invalid("queued message exceeds 32 MiB"));
    }
    std::fs::create_dir_all(outbox_dir(dir))?;
    let bytes = serde_json::to_vec_pretty(meta)
        .map_err(|e| IpcError::new("internal", format!("outbox meta: {e}")))?;
    write_atomic(&outbox_meta_path(dir, queue_id), &bytes)?;
    write_atomic(&outbox_body_path(dir, queue_id), mime)?;
    Ok(())
}

/// Rewrite just the metadata file (retry/backoff updates — body unchanged).
/// No-op when the item was never persisted (e.g., dropped concurrently).
pub fn update_outbox_meta(dir: &Path, queue_id: &str, meta: &OutboxMeta) -> CmdResult<()> {
    let path = outbox_meta_path(dir, queue_id);
    if !path.exists() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(meta)
        .map_err(|e| IpcError::new("internal", format!("outbox meta: {e}")))?;
    write_atomic(&path, &bytes)
}

/// Drop a queued send's persisted files. Idempotent — called on every
/// terminal outcome (sent, failed, cancelled).
pub fn remove_outbox_item(dir: &Path, queue_id: &str) {
    let _ = std::fs::remove_file(outbox_meta_path(dir, queue_id));
    let _ = std::fs::remove_file(outbox_body_path(dir, queue_id));
}

/// Reload persisted outbox items (meta + MIME) at boot. Bounded and
/// fault-tolerant: malformed or oversized files are skipped (warn-logged),
/// never fatal — a torn write must not brick startup.
pub fn load_outbox(dir: &Path) -> Vec<(String, OutboxMeta, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(outbox_dir(dir)) else {
        return out;
    };
    let mut total = 0usize;
    for entry in entries.flatten() {
        if out.len() >= MAX_OUTBOX_ITEMS || total >= MAX_OUTBOX_TOTAL_BYTES {
            break;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(queue_id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !meta_filesafe(queue_id) {
            continue;
        }
        let meta = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<OutboxMeta>(&b).ok());
        let body = std::fs::read(outbox_body_path(dir, queue_id)).ok();
        match (meta, body) {
            (Some(m), Some(b)) if b.len() <= MAX_OUTBOX_ITEM_BYTES => {
                total += b.len();
                out.push((queue_id.to_string(), m, b));
            }
            _ => {
                eprintln!("[kiwi-app] skipped unreadable outbox item {queue_id}");
            }
        }
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> CmdResult<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// queue_id is `send-<hex>` (new_id) — the charset check is a backstop for
/// path-component safety on the filename.
fn meta_filesafe(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Generate an opaque id (CSPRNG-backed) with a readable prefix.
pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).unwrap_or_else(|_| {
        // Entropy failure should be impossible on supported platforms; if it
        // ever happens, fall back to a time+pid mix rather than panicking.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        b[..8].copy_from_slice(&t.to_be_bytes());
        b[8..].copy_from_slice(&(std::process::id() as u32).to_be_bytes());
    });
    format!("{prefix}-{}", crate::audit::hex(&b))
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The shared application state.
pub struct AppState {
    pub data_dir: PathBuf,
    pub store: Mutex<MailStore>,
    pub credentials: Arc<dyn CredentialStore>,
    pub trust: Mutex<TrustMachine>,
    pub policy: TrustPolicy,
    pub devices: Mutex<DeviceRegistry>,
    pub challenges: Mutex<ChallengeBook>,
    pub send_queue: Mutex<SendQueue>,
    /// queue_id → send metadata (SendQueue exposes no item iterator).
    pub outbox_meta: Mutex<BTreeMap<String, OutboxMeta>>,
    /// Observed sessions, newest last (bounded ring).
    pub sessions: Mutex<VecDeque<SessionRecord>>,
    /// Findings deduped by finding id (latest observation wins).
    pub findings: Mutex<BTreeMap<String, Finding>>,
    /// Latest endpoint-collected signals (T-121).
    pub endpoint_signals: Mutex<Vec<TrustSignal>>,
    /// Mailflow events awaiting a reachable admin service (§11 —
    /// queue-and-retry, bounded, drop-oldest).
    pub mailflow_pending: Mutex<VecDeque<crate::bridge::MailflowEvent>>,
    /// One-shot warn flag: "no admin endpoint configured" (dev degrade).
    pub policy_warned: std::sync::atomic::AtomicBool,
    /// One-shot warn flag: "admin endpoint set but no org id".
    pub no_org_warned: std::sync::atomic::AtomicBool,
    pub index: Mutex<AppIndex>,
    pub audit: Mutex<AuditLog>,
    /// Per-boot session id — challenges bind to it, so issued challenges die
    /// with the process (challenge book is in-memory anyway).
    pub boot_session_id: String,
    session_counter: AtomicU64,
}

impl AppState {
    /// Production open: store + index + audit under `data_dir`, OS keystore,
    /// persisted outbox reloaded (T-142).
    pub fn open(data_dir: PathBuf) -> CmdResult<Self> {
        std::fs::create_dir_all(&data_dir)?;
        let store = MailStore::open(&data_dir)?;
        let index = AppIndex::load(&data_dir)?;
        let audit = AuditLog::open(&data_dir)?;
        let mut s = Self::assemble(
            data_dir,
            store,
            index,
            audit,
            Arc::new(OsCredentialStore::new()),
        );
        s.reload_outbox();
        Ok(s)
    }

    /// Test open: in-memory mail store + in-memory credentials under `dir`
    /// (index + audit + outbox persistence still real files so their
    /// behavior is exercised).
    #[cfg(test)]
    pub fn open_test(data_dir: PathBuf) -> CmdResult<Self> {
        std::fs::create_dir_all(&data_dir)?;
        let store = MailStore::open_memory()?;
        let index = AppIndex::load(&data_dir)?;
        let audit = AuditLog::open(&data_dir)?;
        let mut s = Self::assemble(
            data_dir,
            store,
            index,
            audit,
            Arc::new(kiwi_mail::account::MemoryCredentialStore::new()),
        );
        s.reload_outbox();
        Ok(s)
    }

    /// Rebuild the in-memory queue + meta map from `data_dir/outbox/*`.
    /// Persisted undo windows may already be expired — that's fine: the
    /// item simply isn't cancelable and is due immediately.
    fn reload_outbox(&mut self) {
        for (queue_id, meta, mime) in load_outbox(&self.data_dir) {
            self.send_queue
                .get_mut()
                .enqueue(kiwi_mail::smtp::QueuedSend {
                    queue_id: queue_id.clone(),
                    request: kiwi_mail::smtp::SendRequest {
                        from: meta.from.clone(),
                        to: meta.to.clone(),
                        message: mime,
                    },
                    not_before_unix: meta.not_before_unix,
                    undo_window_until_unix: meta.undo_window_until_unix,
                    attempts: meta.attempts,
                });
            self.outbox_meta.get_mut().insert(queue_id, meta);
        }
    }

    fn assemble(
        data_dir: PathBuf,
        store: MailStore,
        index: AppIndex,
        audit: AuditLog,
        credentials: Arc<dyn CredentialStore>,
    ) -> Self {
        Self {
            data_dir,
            store: Mutex::new(store),
            credentials,
            trust: Mutex::new(TrustMachine::new()),
            policy: TrustPolicy::default(),
            devices: Mutex::new(DeviceRegistry::new()),
            challenges: Mutex::new(ChallengeBook::new()),
            send_queue: Mutex::new(SendQueue::new()),
            outbox_meta: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(VecDeque::new()),
            findings: Mutex::new(BTreeMap::new()),
            endpoint_signals: Mutex::new(Vec::new()),
            mailflow_pending: Mutex::new(VecDeque::new()),
            policy_warned: std::sync::atomic::AtomicBool::new(false),
            no_org_warned: std::sync::atomic::AtomicBool::new(false),
            index: Mutex::new(index),
            audit: Mutex::new(audit),
            boot_session_id: new_id("boot"),
            session_counter: AtomicU64::new(0),
        }
    }

    /// Unique session id for one observed connection.
    pub fn next_session_id(&self, proto: &str) -> String {
        let n = self.session_counter.fetch_add(1, Ordering::Relaxed);
        format!("app:{proto}:{n}")
    }

    /// Recompute the trust decision from every live signal source:
    /// endpoint indicators + device-registry status + all retained session
    /// signals. `Locked` is sticky inside `TrustMachine`.
    ///
    /// Locks are taken sequentially (never nested): index → devices →
    /// endpoint → sessions → trust. Keep that order everywhere.
    pub async fn refresh_trust(&self) -> kiwi_core::trust::TrustEvaluation {
        let device_id = self.index.lock().await.device_id.clone();
        let device_kinds = self.devices.lock().await.device_signals(&device_id);
        let mut signals = self.endpoint_signals.lock().await.clone();
        for kind in device_kinds {
            signals.push(crate::observe::device_signal(&device_id, kind));
        }
        for record in self.sessions.lock().await.iter() {
            signals.extend(record.signals.iter().cloned());
        }
        self.trust.lock().await.evaluate(&self.policy, signals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_roundtrip() {
        let dir = std::env::temp_dir().join(format!("kiwi-idx-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut idx = AppIndex::default();
        idx.account_ids.push("a1".into());
        idx.remember_folder("a1", 7, "INBOX");
        idx.save(&dir).unwrap();
        let loaded = AppIndex::load(&dir).unwrap();
        assert_eq!(loaded.device_id, idx.device_id);
        assert_eq!(loaded.folders["a1"][0].name, "INBOX");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
