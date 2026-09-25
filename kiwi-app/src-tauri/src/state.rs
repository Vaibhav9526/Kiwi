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

use kiwi_autoconfig::net::DiscoveryNet;
use kiwi_autoconfig::oauth2::{OAuthError, PendingGrant, ProviderConfig, TokenSet};
use kiwi_core::challenge::ChallengeBook;
use kiwi_core::device::DeviceRegistry;
use kiwi_core::policy::TrustPolicy;
use kiwi_core::session::SecuritySession;
use kiwi_core::trust::{TrustMachine, TrustSignal};
use kiwi_forensics::findings::Finding;
use kiwi_integrations::deliverability::TestReservation;
use kiwi_integrations::http::HttpClient;
use kiwi_integrations::tempmail::GuerrillaMail;
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
/// iterator) for `kiwi_list_outbox` and dispatch context. Durability lives
/// in mail.db's `outbox` table (T-142) — this map is its in-memory view.
/// `Deserialize` is retained for the legacy file-outbox import.
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

/// Bound on concurrent deliverability reservations (single-use addresses,
/// ~1h TTL server-side — 32 is headroom, not a promise).
pub const MAX_DELIVERABILITY_SESSIONS: usize = 32;

/// Bound on concurrent OAuth2 grants (wizard sessions die with the
/// process). Each loopback grant additionally holds a bound OS socket
/// until its deadline — the bound keeps a flood of abandoned wizard
/// openings from leaking listeners.
pub const MAX_OAUTH2_SESSIONS: usize = 32;

/// Loopback auth-code grant lifetime: the redirect listener stays bound
/// this long waiting for the browser return (Google auth codes live
/// ~10 min). Device grants carry their own server-side `expires_in`.
pub const OAUTH2_LOOPBACK_TIMEOUT_SECS: u64 = 600;

/// One in-flight OAuth2 grant (T-230). Holds transient grant secrets —
/// the PKCE verifier rides inside the loopback grant (moved to the waiter
/// thread), the device code inside the device grant — plus, for deferred
/// binds, a completed `TokenSet`. In-memory only: never serialized, never
/// persisted, never logged, never audited (audit sees provider + email
/// only).
pub struct OAuth2Session {
    /// Provider config the grant was begun with (deployment client_id
    /// included — a public id, not a secret).
    pub provider: ProviderConfig,
    /// Account email the grant is for — `None` when the wizard started
    /// before the address was known; bound at `kiwi_add_account` consume.
    pub email: Option<String>,
    /// Creation time (unix seconds) — drives bounded-map eviction.
    pub created_unix: i64,
    /// Grant-state machine.
    pub state: OAuth2SessionState,
}

/// Grant lifecycle behind a `ticket_id`.
pub enum OAuth2SessionState {
    /// Device-code grant awaiting user approval; `oauth2_poll` drives it.
    /// `grant` is always `PendingGrant::Device`.
    Device {
        /// The pending grant (holds the device code — a poll credential).
        grant: PendingGrant,
        /// Current cadence hint for the UI poll loop; `slow_down` bumps it.
        interval_secs: u64,
        /// Provider-grant deadline (from the device-code response).
        expires_at_unix: Option<i64>,
    },
    /// Loopback grant — the listener + verifier moved to the waiter
    /// thread at `begin`; `result` gains the exchange outcome exactly
    /// once (`Err` becomes `Failed` on the next poll).
    Loopback {
        /// Waiter-thread output slot: `Some` once redirect-wait + code
        /// exchange have settled.
        result: std::sync::Arc<std::sync::Mutex<Option<Result<TokenSet, OAuthError>>>>,
    },
    /// Grant completed and tokens persisted under `credential_key`
    /// (`oauth2/<provider>/<email>`) — the email was known at completion.
    Completed {
        /// Credential-store key the `TokenSet` blob lives under.
        credential_key: String,
    },
    /// Grant completed but not yet persisted — `begin` had no email, so
    /// `kiwi_add_account` supplies it and persists on consume.
    CompletedDeferred {
        /// The acquired token set (held in memory only).
        tokens: TokenSet,
    },
    /// Terminal failure — next `oauth2_poll` reports `status:"error"`.
    /// `code` is the sanitized IPC error code; `message` carries no
    /// secret material (OAuthError is secret-free by construction).
    Failed { code: &'static str, message: String },
}

/// One in-flight deliverability test (T-227). `reservation.slug` is a
/// capability secret; `consent_token` is the single-use capability
/// `kiwi_integrations_deliverability_send` must present — minted by
/// `..._begin`, consumed on first valid send. Never serialized, never
/// persisted, never audited.
pub struct DeliverabilitySession {
    pub reservation: TestReservation,
    /// `Some` until `deliverability_send` consumes it.
    pub consent_token: Option<String>,
    /// Consent consumed and a send enqueued for this test.
    pub sent: bool,
}

impl std::fmt::Debug for DeliverabilitySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliverabilitySession")
            .field("address", &self.reservation.address)
            .field(
                "consent_token",
                &self.consent_token.as_ref().map(|_| "[redacted]"),
            )
            .field("sent", &self.sent)
            .finish()
    }
}

/// Live-sync worker status (T-157) — one entry per account the supervisor
/// has spawned a worker for. Written by `syncer`, read by
/// `kiwi_sync_status`.
#[derive(Debug, Clone, Default)]
pub struct AccountSyncStatus {
    /// "pending" | "connecting" | "syncing" | "idle" | "polling" |
    /// "backoff" | "paused-locked" | "stopped"
    pub state: String,
    pub last_sync_unix: Option<i64>,
    pub last_error: Option<String>,
    pub next_retry_unix: Option<i64>,
    /// Folders synced on the most recent full pass.
    pub folders_synced: u64,
    /// New messages pulled since the worker started (cumulative).
    pub new_messages: u64,
    /// Consecutive connection/sync failures (drives backoff).
    pub attempts: u32,
}

/// Threading headers for one stored message (T-169). Derived cache —
/// recomputed lazily from stored bodies or fetched at sync time; the
/// mail store remains the system of record for the messages themselves.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadHeaders {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Key form for the thread-headers cache.
pub fn thread_key(folder_id: i64, uid: u64) -> String {
    format!("f{folder_id}:u{uid}")
}

/// Bound on cached threading headers — evicts by key order (crude but
/// bounded; the cache is rebuildable from bodies/sync at any time).
pub const MAX_THREAD_HEADERS: usize = 50_000;

/// Bound on stored preference entries (global + per-account combined).
pub const MAX_PREFS: usize = 1_024;

/// Preference key forms — `:` is reserved as the scope separator and
/// never allowed inside a caller-supplied key.
pub fn pref_key(account_id: Option<&str>, key: &str) -> String {
    match account_id {
        Some(id) => format!("acct:{id}:{key}"),
        None => format!("global:{key}"),
    }
}

/// Sidecar index — app-layer bookkeeping that is NOT mail data.
/// (`thread_headers` is a derived cache of header fields, not a copy of
/// mail data — it can be dropped and repopulated losslessly.)
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
    /// Threading header cache (T-169): `"f<folderId>:u<uid>"` →
    /// `In-Reply-To`/`References`. Bounded at [`MAX_THREAD_HEADERS`].
    #[serde(default)]
    pub thread_headers: BTreeMap<String, ThreadHeaders>,
    /// User preferences (T-175): `"global:<key>"` or `"acct:<id>:<key>"`
    /// → JSON value. Bounded at [`MAX_PREFS`].
    #[serde(default)]
    pub prefs: BTreeMap<String, serde_json::Value>,
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
            thread_headers: BTreeMap::new(),
            prefs: BTreeMap::new(),
        }
    }
}

impl AppIndex {
    pub(crate) fn load(dir: &Path) -> CmdResult<Self> {
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

    /// Record threading headers for one message (T-169). Over-cap evicts
    /// the smallest key — a bounded rebuildable cache, not an LRU.
    pub fn remember_thread_headers(&mut self, folder_id: i64, uid: u64, h: ThreadHeaders) {
        if h.in_reply_to.is_none() && h.references.is_empty() {
            return; // nothing to cache — absence means "no threading data"
        }
        if self.thread_headers.len() >= MAX_THREAD_HEADERS {
            self.thread_headers.pop_first();
        }
        self.thread_headers.insert(thread_key(folder_id, uid), h);
    }
}

// --- Outbox persistence (T-142) ----------------------------------------------
// Queued sends live in mail.db's `outbox` table (schema v2) — one row per
// committed send, built MIME in-row, so enqueue is a single atomic write.
// `outbox/<queue_id>.{json,eml}` files from the pre-SQLite format are
// imported once at open, then removed. Body bytes at rest share mail.db's
// sensitivity — local disk only, never IPC.

/// Max persisted outbox items reloaded at boot.
pub const MAX_OUTBOX_ITEMS: u32 = 256;
/// Max size of one persisted message (enforced at enqueue).
pub const MAX_OUTBOX_ITEM_BYTES: usize = 32 * 1024 * 1024;
/// Max total legacy-import payload.
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

/// Build the store row for a queued send (meta sidecar + MIME bytes).
pub fn outbox_row_of(
    queue_id: &str,
    meta: &OutboxMeta,
    mime: Vec<u8>,
    created_unix: i64,
) -> kiwi_mail::store::OutboxRow {
    kiwi_mail::store::OutboxRow {
        queue_id: queue_id.to_string(),
        account_id: meta.account_id.clone(),
        from_addr: meta.from.clone(),
        to_addrs: meta.to.clone(),
        subject: meta.subject.clone(),
        message_id: meta.message_id.clone(),
        mime,
        not_before_unix: meta.not_before_unix,
        undo_window_until_unix: meta.undo_window_until_unix,
        attempts: meta.attempts,
        created_unix,
    }
}

/// Drop a queued send's legacy persisted files. Idempotent.
fn remove_outbox_item(dir: &Path, queue_id: &str) {
    let _ = std::fs::remove_file(outbox_meta_path(dir, queue_id));
    let _ = std::fs::remove_file(outbox_body_path(dir, queue_id));
}

/// Read the pre-SQLite file outbox for one-time import. Bounded and
/// fault-tolerant: malformed or oversized files are skipped (warn-logged),
/// never fatal — a torn write must not brick startup.
fn load_legacy_outbox(dir: &Path) -> Vec<(String, OutboxMeta, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(outbox_dir(dir)) else {
        return out;
    };
    let mut total = 0usize;
    for entry in entries.flatten() {
        if out.len() >= MAX_OUTBOX_ITEMS as usize || total >= MAX_OUTBOX_TOTAL_BYTES {
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

/// queue_id is `send-<hex>` (new_id) — the charset check is a backstop for
/// path-component safety on the legacy filename.
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
    /// Live-sync worker status per account (T-157).
    pub sync_status: Mutex<BTreeMap<String, AccountSyncStatus>>,
    /// Wake signal for the sync supervisor — account add/remove (and any
    /// future "sync now" surface) pokes this so the reconcile doesn't
    /// wait out the 2 s tick (T-157-adjacent).
    pub sync_wakeup: tokio::sync::Notify,
    /// One-shot warn flag: "no admin endpoint configured" (dev degrade).
    pub policy_warned: std::sync::atomic::AtomicBool,
    /// One-shot warn flag: "admin endpoint set but no org id".
    pub no_org_warned: std::sync::atomic::AtomicBool,
    /// Local address book (T-175) — `contacts.db` under `data_dir`,
    /// owned by `kiwi-contacts` (never shares mail.db's tables).
    pub contacts: Mutex<kiwi_contacts::ContactStore>,
    /// Shared transport for every kiwi-integrations provider (T-227) —
    /// `ReqwestClient` in production, `ScriptedHttp` in tests. Providers
    /// are constructed per command against this; the seam is what makes
    /// integration flows testable offline.
    pub integrations_http: Arc<dyn HttpClient>,
    /// The one live disposable-inbox session (GuerrillaMail sessions are
    /// single-mailbox). Session state (PHPSESSID, sid_token, address)
    /// lives inside the provider, in memory only — nothing persists.
    pub tempmail: Mutex<Option<GuerrillaMail>>,
    /// In-flight deliverability tests keyed by opaque `test_id`. Bounded
    /// at [`MAX_DELIVERABILITY_SESSIONS`]; sessions die with the process.
    pub deliverability: Mutex<BTreeMap<String, DeliverabilitySession>>,
    /// In-flight OAuth2 grants keyed by opaque `ticket_id` (T-230).
    /// Bounded at [`MAX_OAUTH2_SESSIONS`]; sessions die with the process.
    pub oauth2_sessions: Mutex<BTreeMap<String, OAuth2Session>>,
    /// Discovery seam for `kiwi_discover_account`: live HTTPS fetch +
    /// MX lookup in production, `MockNet` in tests.
    pub autoconfig_net: Arc<dyn DiscoveryNet>,
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
        let http = integrations_transport()?;
        let mut s = Self::assemble(
            data_dir,
            store,
            index,
            audit,
            Arc::new(OsCredentialStore::new()),
            http.clone(),
            Arc::new(crate::discovery_net::LiveDiscoveryNet::new(http)),
        )?;
        s.reload_outbox();
        Ok(s)
    }

    /// Test open: file-backed mail store under `dir` (restart-resume is
    /// exercised) + in-memory credentials; index + audit real files.
    #[cfg(test)]
    pub fn open_test(data_dir: PathBuf) -> CmdResult<Self> {
        Self::open_test_with_http(data_dir, integrations_transport()?)
    }

    /// Test open with an injected integration transport — `ScriptedHttp`
    /// replays recorded exchanges, so integration commands run offline.
    /// Discovery gets an empty `MockNet` (ISPDB fixtures still resolve).
    #[cfg(test)]
    pub fn open_test_with_http(
        data_dir: PathBuf,
        integrations_http: Arc<dyn HttpClient>,
    ) -> CmdResult<Self> {
        Self::open_test_with_net(
            data_dir,
            integrations_http,
            Arc::new(kiwi_autoconfig::net::MockNet::new()),
        )
    }

    /// Test open with injected integration transport AND discovery net.
    #[cfg(test)]
    pub fn open_test_with_net(
        data_dir: PathBuf,
        integrations_http: Arc<dyn HttpClient>,
        autoconfig_net: Arc<dyn DiscoveryNet>,
    ) -> CmdResult<Self> {
        std::fs::create_dir_all(&data_dir)?;
        let store = MailStore::open(&data_dir)?;
        let index = AppIndex::load(&data_dir)?;
        let audit = AuditLog::open(&data_dir)?;
        let mut s = Self::assemble(
            data_dir,
            store,
            index,
            audit,
            Arc::new(kiwi_mail::account::MemoryCredentialStore::new()),
            integrations_http,
            autoconfig_net,
        )?;
        s.reload_outbox();
        Ok(s)
    }

    /// Rebuild the in-memory queue + meta map from mail.db's `outbox`
    /// table, after folding in any legacy `outbox/*.json|.eml` files.
    /// Persisted undo windows may already be expired — that's fine: the
    /// item simply isn't cancelable and is due immediately.
    fn reload_outbox(&mut self) {
        for (queue_id, meta, mime) in load_legacy_outbox(&self.data_dir) {
            let row = outbox_row_of(&queue_id, &meta, mime, now_unix());
            if let Err(e) = self.store.get_mut().outbox_put(&row) {
                // e.g. orphaned send for a deleted account (FK) — drop it.
                eprintln!("[kiwi-app] legacy outbox import {queue_id} failed: {e}");
            }
            remove_outbox_item(&self.data_dir, &queue_id);
        }
        let rows = match self.store.get_mut().outbox_list(MAX_OUTBOX_ITEMS) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[kiwi-app] outbox reload failed: {e}");
                Vec::new()
            }
        };
        for row in rows {
            self.send_queue
                .get_mut()
                .enqueue(kiwi_mail::smtp::QueuedSend {
                    queue_id: row.queue_id.clone(),
                    request: kiwi_mail::smtp::SendRequest {
                        from: row.from_addr.clone(),
                        to: row.to_addrs.clone(),
                        message: row.mime.clone(),
                    },
                    not_before_unix: row.not_before_unix,
                    undo_window_until_unix: row.undo_window_until_unix,
                    attempts: row.attempts,
                });
            self.outbox_meta.get_mut().insert(
                row.queue_id.clone(),
                OutboxMeta {
                    account_id: row.account_id,
                    from: row.from_addr,
                    to: row.to_addrs,
                    subject: row.subject,
                    message_id: row.message_id,
                    not_before_unix: row.not_before_unix,
                    undo_window_until_unix: row.undo_window_until_unix,
                    attempts: row.attempts,
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        data_dir: PathBuf,
        store: MailStore,
        index: AppIndex,
        audit: AuditLog,
        credentials: Arc<dyn CredentialStore>,
        integrations_http: Arc<dyn HttpClient>,
        autoconfig_net: Arc<dyn DiscoveryNet>,
    ) -> CmdResult<Self> {
        Ok(Self {
            contacts: Mutex::new(
                kiwi_contacts::ContactStore::open(&data_dir, now_unix())
                    .map_err(|e| IpcError::new("contacts", format!("open contacts.db: {e}")))?,
            ),
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
            sync_status: Mutex::new(BTreeMap::new()),
            sync_wakeup: tokio::sync::Notify::new(),
            policy_warned: std::sync::atomic::AtomicBool::new(false),
            no_org_warned: std::sync::atomic::AtomicBool::new(false),
            integrations_http,
            tempmail: Mutex::new(None),
            deliverability: Mutex::new(BTreeMap::new()),
            oauth2_sessions: Mutex::new(BTreeMap::new()),
            autoconfig_net,
            index: Mutex::new(index),
            audit: Mutex::new(audit),
            boot_session_id: new_id("boot"),
            session_counter: AtomicU64::new(0),
        })
    }

    /// Poke the sync supervisor so an added/removed account reconciles
    /// immediately instead of on the next tick.
    pub fn kick_sync(&self) {
        self.sync_wakeup.notify_one();
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

/// Build the production integration transport: reqwest+rustls, HTTPS-only,
/// redirects never followed. Body cap covers a fetched temp-mail body
/// embedded in provider JSON (`MAX_MAIL_BODY` + envelope slack).
fn integrations_transport() -> CmdResult<Arc<dyn HttpClient>> {
    let client =
        kiwi_integrations::http::ReqwestClient::new(kiwi_integrations::http::DEFAULT_TIMEOUT_MS)
            .map_err(IpcError::from)?
            .with_body_cap(kiwi_integrations::tempmail::MAX_MAIL_BODY + 2 * 1024 * 1024);
    Ok(Arc::new(client))
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
