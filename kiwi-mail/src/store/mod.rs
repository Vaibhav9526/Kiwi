//! Local mail storage: SQLite metadata + on-disk bodies/attachments.
//!
//! Layout (`root` = per-profile data dir):
//!   `mail.db`              â€” accounts, folders, message metadata, sync state,
//!                            outbox (persistent send queue, T-142)
//!   `bodies/<folder_id>/<uid>.eml` â€” raw RFC 5322 message bytes
//!   `attachments/<folder_id>/<uid>/<n>` â€” decoded attachment payloads
//!
//! All queries are parameterized (SECURITY.md rule 9). Schema version lives
//! in `PRAGMA user_version`; migrations are explicit and append-only.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

use crate::attachrisk::AttachRiskEvidence;
use crate::authrisk::AuthRisk;
use crate::category::Category;
use crate::error::{MailError, Result};
use crate::linkrisk::LinkRiskEvidence;
use crate::rules::Rule;

use schema::{DDL, SCHEMA_VERSION};

mod diagnostics;
mod outbox;
mod queries;
mod schema;
mod threads;

pub use diagnostics::{CompactReport, StorageStats};
pub use outbox::OutboxRow;
pub use threads::MAX_CONVERSATION_KEY_LEN;

/// Canonical junk flag (F13/T-212): the keyword stored in a message's
/// `flags` column and applied server-side as `+FLAGS (\Junk)`. Comparisons
/// are case-insensitive; legacy spellings (`$Junk`, bare `Junk`) are a
/// normalization question owned by T-212's caller, not this constant.
pub const JUNK_FLAG: &str = "\\Junk";

/// Message metadata row â€” the query shape the UI/mail-flow emitter consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMeta {
    pub id: i64,
    pub folder_id: i64,
    pub uid: u64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub to_addrs: Option<String>,
    pub date_unix: Option<i64>,
    pub size: Option<u64>,
    pub flags: Vec<String>,
    pub has_attachments: bool,
    pub snippet: Option<String>,
    pub body_path: Option<String>,
    /// Deterministic inbox tab (T-201) â€” set at ingest, refined on body fetch.
    pub category: Category,
    /// Unsubscribe offer (T-202): https URL, if advertised.
    pub unsub_http: Option<String>,
    /// Unsubscribe offer: mailto address (params stripped), if advertised.
    /// Consent-gated â€” never auto-send.
    pub unsub_mailto: Option<String>,
    /// RFC 8058 one-click marker present on the offer.
    pub unsub_oneclick: bool,
    /// SPF/DKIM/DMARC verdicts stamped at ingest (T-232). `None` until the
    /// body has been fetched and evaluated â€” an absent stamp is "not yet
    /// evaluated", which is NOT the same as a `none` verdict. Populated by
    /// `list_messages` / `list_messages_by_category` from `message_auth`.
    pub auth: Option<AuthMeta>,
    /// Attachment evidence derived at body parse time (T-254). `None` means
    /// the body has not been parsed yet, not "clean".
    pub attach_risk: Option<AttachRiskEvidence>,
    /// Link evidence derived at body parse time (T-261). `None` means not yet
    /// parsed, not clean. It never resolves, opens, or blocks a link.
    pub link_risk: Option<LinkRiskEvidence>,
}

/// Persisted Authentication-Results verdicts for one message (T-232).
///
/// Verdict strings use the `kiwi.mailauth/1` vocabulary so the UI maps them
/// without a second lookup. `evidence` carries the bounded explanations and
/// the evidence refs (key query, DMARC record) as one JSON blob â€” evidence,
/// never a finding, never a body.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMeta {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
    pub dmarc_policy: String,
    pub dkim_domain: Option<String>,
    pub key_query: Option<String>,
    pub dmarc_record: Option<String>,
    /// The RFC 8601 header value that was stamped.
    pub header_value: Option<String>,
    /// Bounded evidence: explanations + evidence refs, as JSON.
    pub evidence: Option<serde_json::Value>,
    /// Bounded upstream MTA Authentication-Results and local/upstream
    /// comparisons (T-240). This is evidence, never a finding or trust claim.
    pub upstream: UpstreamAuthEvidence,
    /// Deterministic bounded UI hint (T-249), persisted with the stamp.
    /// It is not a finding and never moves or otherwise mutates mail.
    pub auth_risk: AuthRisk,
}

/// One verdict emitted by an upstream authentication service.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamAuthVerdict {
    pub authserv_id: String,
    pub verdict: String,
}

/// One local/upstream comparison. A discrepancy is true only for an exact
/// pass/fail contradiction; inconclusive verdicts never manufacture one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthVerdictComparison {
    pub method: String,
    pub upstream_verdict: String,
    pub local_verdict: String,
    pub discrepancy: bool,
}

/// Authentication-Results observed before KIWI's in-memory stamp (T-240).
///
/// Multiple A-R fields and repeated method results are retained as bounded
/// evidence. `untrusted_relay` is set when the message had no A-R header at
/// all; this is a provenance limitation, not a finding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamAuthEvidence {
    pub present: bool,
    pub untrusted_relay: bool,
    pub malformed_headers: u32,
    pub authserv_ids: Vec<String>,
    pub spf: Vec<UpstreamAuthVerdict>,
    pub dkim: Vec<UpstreamAuthVerdict>,
    pub dmarc: Vec<UpstreamAuthVerdict>,
    pub comparisons: Vec<AuthVerdictComparison>,
}

impl Default for UpstreamAuthEvidence {
    fn default() -> Self {
        Self {
            present: false,
            untrusted_relay: true,
            malformed_headers: 0,
            authserv_ids: Vec::new(),
            spf: Vec::new(),
            dkim: Vec::new(),
            dmarc: Vec::new(),
            comparisons: Vec::new(),
        }
    }
}

impl UpstreamAuthEvidence {
    /// True when at least one extracted verdict directly contradicts KIWI's
    /// local pass/fail result. Absence and inconclusive states are not conflicts.
    pub fn has_discrepancy(&self) -> bool {
        self.comparisons.iter().any(|c| c.discrepancy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderOrigin {
    Remote,
    Local,
    System,
}

impl FolderOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Local => "local",
            Self::System => "system",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "remote" => Ok(Self::Remote),
            "local" => Ok(Self::Local),
            "system" => Ok(Self::System),
            other => {
                let _ = other;
                Err(MailError::Store(rusqlite::Error::InvalidQuery))
            }
        }
    }
}

/// Canonical real mailboxes reserved from local create/rename. These are
/// store rows; UI smart views (Unread, Snoozed, Starred, categories) are not
/// rows at all, so there is no id they could pass to folder deletion.
pub const SYSTEM_FOLDER_NAMES: [&str; 6] = ["INBOX", "SENT", "TRASH", "DRAFTS", "JUNK", "ARCHIVE"];

pub fn is_system_folder_name(name: &str) -> bool {
    SYSTEM_FOLDER_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderMeta {
    pub id: i64,
    pub account_id: String,
    pub parent_id: Option<i64>,
    pub name: String,
    pub origin: FolderOrigin,
    pub uid_validity: Option<u64>,
    pub uid_next: Option<u64>,
    pub highest_uid: u64,
}

/// Per-folder message counts (T-264, IPC-6). `exists` = total stored rows;
/// `unseen` = rows lacking the `\Seen` flag token. Literal store counts —
/// parked (snoozed) rows still count: snooze defers, it does not suppress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderStats {
    pub exists: u64,
    pub unseen: u64,
}
/// Metadata needed to upsert a synced message (bodies handled separately).
#[derive(Debug, Clone)]
pub struct NewMessageMeta {
    pub uid: u64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub to_addrs: Option<String>,
    pub date_unix: Option<i64>,
    pub size: Option<u64>,
    pub flags: Vec<String>,
    pub has_attachments: bool,
    pub snippet: Option<String>,
    /// Tab assignment at ingest. IMAP metadata ingest only has the envelope
    /// (domain rules still apply); the body-fetch path refines it via
    /// `set_category` once headers arrive. Defaults to Primary.
    pub category: Category,
    /// Unsubscribe offer at ingest (`None`/`None`/`false` when the sender
    /// advertised nothing actionable; refined on body fetch like `category`).
    pub unsub_http: Option<String>,
    pub unsub_mailto: Option<String>,
    pub unsub_oneclick: bool,
}

/// One persisted deferred-attachment row (`message_parts`, T-339).
///
/// Presence of any row for a `(folder_id, uid)` marks the stored body as a
/// *skeleton* — MIME headers and text leaves are real, but attachment
/// payloads were never downloaded. Absence means the stored body (if any)
/// is the complete message. `section` is the server-derived IMAP part
/// specifier used for `BODY.PEEK[<section>]` on demand; callers never
/// construct it from UI input. `size_bytes` is the *wire* octet count from
/// BODYSTRUCTURE — the decoded payload is smaller for base64/qp parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePart {
    /// Ordinal among the message's attachment leaves — the
    /// `attachmentIndex` the IPC layer resolves.
    pub part_index: u32,
    /// IMAP section specifier ("2", "1.3", …).
    pub section: String,
    /// Filename from disposition/Content-Type params, if any.
    pub name: Option<String>,
    /// `media/subtype` lowercased.
    pub mime: String,
    /// Wire size in octets (encoded). `None` when BODYSTRUCTURE had none.
    pub size_bytes: Option<u64>,
    /// Content-Transfer-Encoding verbatim — drives decode at fetch time.
    pub encoding: String,
    /// True after the decoded payload durably landed under
    /// `attachments/<folder_id>/<uid>/<part_index>`.
    pub fetched: bool,
}

/// A stored rule plus its cumulative sync-time application health. The
/// health fields are store-owned diagnostics and never enter `spec_json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRecord {
    pub rule: Rule,
    pub failure_count: u64,
    pub last_error: Option<String>,
    pub last_failure_unix: Option<i64>,
}

/// One rule-hit audit row (T-233): which rule fired on which stored
/// message, when. `rule_id` is verbatim (not an FK) so evidence survives
/// rule deletion; `message_id` is the stable RFC822 identity â€” the
/// folder/uid pair records where the verdict was made and goes stale if
/// the message was moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub folder_id: i64,
    pub uid: u64,
    pub rule_id: String,
    pub message_id: Option<String>,
    pub applied_unix: i64,
}

/// A stored message's identity + display fields, folder-qualified — the
/// row shape `recent_for_preview` returns for the rules dry-run (T-244).
/// Carries what the preview list renders; no flags, no body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRef {
    pub folder_id: i64,
    pub uid: u64,
    pub folder_name: String,
    pub subject: Option<String>,
    pub message_id: Option<String>,
}

/// One parked message in the Snoozed view (T-255): coordinates, the
/// parking deadline, and display metadata. `from_folder_id` is where it
/// was parked — the message may have moved since; `folder_id`/`folder_name`
/// are where it lives NOW (it never left a real folder — snooze is a
/// hide-in-place marker, not a move).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnoozedMessage {
    pub folder_id: i64,
    pub uid: u64,
    pub folder_name: String,
    pub from_folder_id: i64,
    pub until_unix: i64,
    pub set_at_unix: i64,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub message_id: Option<String>,
    pub date_unix: Option<i64>,
}

pub struct MailStore {
    conn: Connection,
    root: PathBuf,
}

impl MailStore {
    /// Test-only access to the connection (foreign-key fixtures).
    #[cfg(test)]
    pub fn conn_for_test(&self) -> &Connection {
        &self.conn
    }

    /// Crate-internal access to the connection â€” `search` runs FTS5
    /// queries that don't fit the row-level API. Not public: callers
    /// outside the crate must go through typed methods.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Open (or create) the store under `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("bodies"))?;
        std::fs::create_dir_all(root.join("attachments"))?;
        let conn = Connection::open(root.join("mail.db"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn, root };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory store for tests. The payload dir is unique per call â€”
    /// parallel tests in one process must not share `bodies/` trees.
    pub fn open_memory() -> Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn,
            root: std::env::temp_dir().join(format!(
                "kiwi-mail-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )),
        };
        std::fs::create_dir_all(store.root.join("bodies"))?;
        std::fs::create_dir_all(store.root.join("attachments"))?;
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        migrate_conn(&self.conn, &self.root)
    }
}

/// One-time schema step + backfill, factored for tests (which build
/// pre-vN databases by hand and drive this directly). Migration steps are
/// version-gated and append-only: a v3 database runs the v4 step then the
/// v5 step; a v4 database runs only the v5 step; fresh databases (v0) get
/// everything from `DDL` and skip both.
pub(crate) fn migrate_conn(conn: &Connection, root: &Path) -> Result<()> {
    let v: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if v < SCHEMA_VERSION {
        conn.execute_batch(DDL)?;
        // FTS5 index (T-159): created/backfilled idempotently on every bump.
        crate::search::ensure_schema(conn)?;
        if v > 0 {
            // Pre-v4 database: fresh DDL above is a no-op for existing
            // tables, so add the column explicitly, then classify rows
            // whose bodies are on disk.
            if v < 4 {
                ensure_category_column(conn)?;
                backfill_categories(conn, root)?;
            }
            // Pre-v5 database: same treatment for the unsubscribe columns.
            if v < 5 {
                ensure_unsub_columns(conn)?;
                backfill_unsub(conn, root)?;
            }
            // Pre-v8 database: retain pre-existing MTA A-R evidence in the
            // same auth table without touching the shared `messages` table.
            if v < 8 {
                ensure_upstream_auth_column(conn)?;
            }
            // Pre-v10 database: add the bounded T-249 hint column without
            // backfilling verdicts or fabricating provenance/alignment.
            if v < 10 {
                ensure_auth_risk_column(conn)?;
            }
            // Pre-v14 database: preserve rules and add bounded health counters.
            if v < 14 {
                ensure_rule_failure_columns(conn)?;
            }
            // Pre-v17 database: local folder management is a store-owned
            // concern. Existing rows are preserved; only canonical mailbox
            // names are classified as system, all others remain remote.
            if v < 17 {
                ensure_folder_management_columns(conn)?;
            }
            // Pre-v16 database: existing queued sends have no recorded
            // failure reason — NULL is the honest state (nothing failed
            // yet, or the reason predates the column and is unknowable).
            if v < 16 {
                ensure_outbox_error_column(conn)?;
            }
            // Pre-v18 database: conversation mute (T-341). The column is added
            // NULL-first and then backfilled from each row's own subject, so
            // the grouping is derived from data actually in the database — no
            // message is invented and no row is dropped.
            //
            // The index is created HERE, not in the DDL: on a legacy database
            // the DDL's `CREATE TABLE IF NOT EXISTS messages` is a no-op, so
            // the column does not exist until `ensure_conversation_key_column`
            // adds it. An index in the DDL would run first and fail with
            // "no such column". This block also runs for fresh databases
            // (v0 < 18), where the column is already present from the DDL.
            if v < 18 {
                ensure_conversation_key_column(conn)?;
                conn.execute_batch(
                    "CREATE INDEX IF NOT EXISTS idx_messages_conversation
                        ON messages(conversation_key)",
                )?;
                backfill_conversation_keys(conn)?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(account_id, parent_id)",
        )?;
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_sibling_name
             ON folders(account_id, COALESCE(parent_id, 0), name COLLATE NOCASE)",
        )?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
    }
    Ok(())
}

/// `ALTER TABLE â€¦ ADD COLUMN` guarded by `PRAGMA table_info` so the step is
/// idempotent (a partially-migrated DB never errors here).
fn ensure_category_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "category" {
            return Ok(());
        }
    }
    conn.execute_batch("ALTER TABLE messages ADD COLUMN category TEXT NOT NULL DEFAULT 'primary'")?;
    Ok(())
}

/// Add the T-240 upstream evidence column idempotently. Existing rows remain
/// NULL: no backfill is possible without the original received header context,
/// and inventing one would fabricate provenance evidence.
fn ensure_upstream_auth_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(message_auth)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "upstream_json" {
            return Ok(());
        }
    }
    conn.execute_batch("ALTER TABLE message_auth ADD COLUMN upstream_json TEXT")?;
    Ok(())
}

/// Add the bounded T-249 hint idempotently. Existing rows stay NULL: deriving
/// aligned-SPF-failure evidence would require the original receipt context.
fn ensure_auth_risk_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(message_auth)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "auth_risk" {
            return Ok(());
        }
    }
    conn.execute_batch(
        "ALTER TABLE message_auth ADD COLUMN auth_risk TEXT
         CHECK (auth_risk IN ('clean', 'noted', 'failed'))",
    )?;
    Ok(())
}

/// Add the T-244 per-rule health columns without resetting existing rules.
/// Historical counters cannot be reconstructed, so upgraded rows start at
/// zero with no last error.
fn ensure_rule_failure_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(rules)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "failure_count" {
            return Ok(());
        }
    }
    conn.execute_batch(
        "ALTER TABLE rules ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE rules ADD COLUMN last_error TEXT;
         ALTER TABLE rules ADD COLUMN last_failure_unix INTEGER",
    )?;
    Ok(())
}

fn ensure_folder_management_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(folders)")?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !cols.iter().any(|c| c == "parent_id") {
        conn.execute_batch("ALTER TABLE folders ADD COLUMN parent_id INTEGER REFERENCES folders(id) ON DELETE RESTRICT")?;
    }
    if !cols.iter().any(|c| c == "origin") {
        conn.execute_batch(
            "ALTER TABLE folders ADD COLUMN origin TEXT NOT NULL DEFAULT 'remote'
             CHECK (origin IN ('remote', 'local', 'system'))",
        )?;
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(account_id, parent_id)",
    )?;
    rebuild_folders_for_v17(conn)?;
    Ok(())
}

fn rebuild_folders_for_v17(conn: &Connection) -> Result<()> {
    // The old table's UNIQUE(account_id,name) is account-wide. Rebuild once
    // to the requested per-parent case-insensitive identity while preserving
    // ids (messages and all sibling tables reference them).
    conn.execute_batch("PRAGMA foreign_keys = OFF")?;
    conn.execute_batch(
        "CREATE TABLE folders_v17 (
             id           INTEGER PRIMARY KEY,
             account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
             parent_id    INTEGER REFERENCES folders_v17(id) ON DELETE RESTRICT,
             name         TEXT NOT NULL,
             origin       TEXT NOT NULL CHECK (origin IN ('remote','local','system')),
             uid_validity INTEGER,
             uid_next     INTEGER,
             highest_uid  INTEGER NOT NULL DEFAULT 0
         );
         INSERT INTO folders_v17
             (id, account_id, parent_id, name, origin, uid_validity, uid_next, highest_uid)
         SELECT id, account_id, parent_id, name, origin,
                uid_validity, uid_next, highest_uid
           FROM folders;
         DROP TABLE folders;
         ALTER TABLE folders_v17 RENAME TO folders;
         PRAGMA foreign_keys = ON",
    )?;
    for name in SYSTEM_FOLDER_NAMES {
        conn.execute(
            "UPDATE folders SET origin = 'system' WHERE LOWER(name) = ?1",
            [name.to_ascii_lowercase()],
        )?;
    }
    Ok(())
}

/// T-341: add the `conversation_key` column idempotently. It is nullable on
/// purpose — a subject with no signal has no conversation, and NULL is the
/// honest value that suppresses nothing.
fn ensure_conversation_key_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "conversation_key" {
            return Ok(());
        }
    }
    conn.execute_batch(
        "ALTER TABLE messages ADD COLUMN conversation_key TEXT;
         CREATE INDEX IF NOT EXISTS idx_messages_conversation
             ON messages(conversation_key)",
    )?;
    Ok(())
}

/// Derive `conversation_key` for every stored row that lacks one.
///
/// Batched by rowid so a large mailbox does not load every subject into memory
/// at once. Only rows with a subject can produce a key; a row whose subject is
/// NULL or folds to nothing keeps NULL forever, which is the honest answer
/// (it is in no conversation, so nothing can suppress it).
fn backfill_conversation_keys(conn: &Connection) -> Result<()> {
    const BATCH: i64 = 500;
    // Cursor, not "until empty": a row whose subject folds to nothing keeps
    // NULL forever, so re-selecting "rows still missing a key" would spin on
    // exactly those rows. Advancing past the last id seen terminates instead.
    let mut cursor: i64 = 0;
    loop {
        let mut stmt = conn.prepare(
            "SELECT id, subject FROM messages
              WHERE id > ?1 AND conversation_key IS NULL AND subject IS NOT NULL
              ORDER BY id LIMIT ?2",
        )?;
        let batch = stmt
            .query_map(params![cursor, BATCH], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        let Some(last) = batch.last().map(|(id, _)| *id) else {
            return Ok(());
        };
        for (id, subject) in &batch {
            // A subject that folds to nothing stays NULL (no conversation).
            if let Some(key) = crate::threading::normalize_subject(subject) {
                conn.execute(
                    "UPDATE messages SET conversation_key = ?2 WHERE id = ?1",
                    params![id, key],
                )?;
            }
        }
        cursor = last;
    }
}

/// T-298: `outbox.last_error` — sanitized reason for the most recent
/// failed attempt. Existing rows stay NULL; a reason that predates the
/// column cannot be reconstructed without fabricating.
fn ensure_outbox_error_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(outbox)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "last_error" {
            return Ok(());
        }
    }
    conn.execute_batch("ALTER TABLE outbox ADD COLUMN last_error TEXT")?;
    Ok(())
}

/// Same guard for the T-202 unsubscribe columns (one sentinel check covers
/// all three â€” they are always added together).
fn ensure_unsub_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for col in cols {
        if col? == "unsub_http" {
            return Ok(());
        }
    }
    conn.execute_batch(
        "ALTER TABLE messages ADD COLUMN unsub_http TEXT;
         ALTER TABLE messages ADD COLUMN unsub_mailto TEXT;
         ALTER TABLE messages ADD COLUMN unsub_oneclick INTEGER NOT NULL DEFAULT 0",
    )?;
    Ok(())
}

/// Best-effort classification of pre-v4 rows: parse each stored body and
/// write its tab. Rows without bodies, oversized bodies, or unparseable
/// bodies keep the `'primary'` default â€” absent fact, no guess. Individual
/// failures never abort the migration.
fn backfill_categories(conn: &Connection, root: &Path) -> Result<()> {
    for (folder_id, uid, bytes) in bodies_to_backfill(conn, root)? {
        let Ok(parsed) = crate::mime::parse_message(&bytes) else {
            continue;
        };
        let category = crate::category::categorize(&parsed).category;
        let _ = conn.execute(
            "UPDATE messages SET category = ?3 WHERE folder_id = ?1 AND uid = ?2",
            rusqlite::params![folder_id, uid as i64, category.as_str()],
        );
    }
    Ok(())
}

/// Best-effort unsubscribe backfill for pre-v5 rows: same body walk, fills
/// the T-202 columns. Rows whose bodies lack an actionable offer keep
/// `NULL/NULL/0` â€” absent fact, no guess.
fn backfill_unsub(conn: &Connection, root: &Path) -> Result<()> {
    for (folder_id, uid, bytes) in bodies_to_backfill(conn, root)? {
        let Ok(parsed) = crate::mime::parse_message(&bytes) else {
            continue;
        };
        let Some(info) = parsed.unsubscribe else {
            continue;
        };
        let _ = conn.execute(
            "UPDATE messages SET unsub_http = ?3, unsub_mailto = ?4,
             unsub_oneclick = ?5 WHERE folder_id = ?1 AND uid = ?2",
            rusqlite::params![
                folder_id,
                uid as i64,
                info.http_url,
                info.mailto,
                info.one_click as i64,
            ],
        );
    }
    Ok(())
}

/// Stored bodies eligible for migration backfills: `(folder_id, uid,
/// bytes)`. Missing files, oversized bodies, and read failures are skipped
/// silently â€” the caller's per-row failure policy applies after this.
fn bodies_to_backfill(conn: &Connection, root: &Path) -> Result<Vec<(i64, u64, Vec<u8>)>> {
    /// Bodies above this are skipped (headers live at the top, but
    /// `parse_message` walks the whole body â€” bound the one-time cost).
    const MAX_BACKFILL_BYTES: u64 = 8 << 20;
    let pending: Vec<(i64, u64, String)> = {
        let mut stmt = conn.prepare(
            "SELECT folder_id, uid, body_path FROM messages WHERE body_path IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fid, uid, rel) = r?;
            out.push((fid, uid as u64, rel));
        }
        out
    };
    let mut out = Vec::new();
    for (folder_id, uid, rel) in pending {
        let path = root.join(&rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > MAX_BACKFILL_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        out.push((folder_id, uid, bytes));
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::MailAccount;
    use rusqlite::params;

    fn meta(uid: u64) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some("a@x".into()),
            to_addrs: Some("b@y".into()),
            date_unix: Some(1_758_000_000),
            size: Some(1234),
            flags: vec!["\\Seen".into()],
            has_attachments: false,
            snippet: Some("hi".into()),
            category: Category::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    #[test]
    fn account_folder_message_roundtrip() {
        let store = MailStore::open_memory().unwrap();
        let acct = MailAccount {
            account_id: "a1".into(),
            display_name: "Test".into(),
            email: "t@x.test".into(),
            incoming: crate::account::IncomingAccount {
                protocol: crate::account::IncomingProtocol::Imap,
                server: crate::account::ServerConfig {
                    host: "h".into(),
                    port: 993,
                    security: crate::transport::SocketSecurity::ImplicitTls,
                },
                auth: crate::account::AuthRef::None,
                username: "t@x.test".into(),
            },
            outgoing: crate::account::OutgoingAccount {
                server: crate::account::ServerConfig {
                    host: "h".into(),
                    port: 587,
                    security: crate::transport::SocketSecurity::StartTls,
                },
                auth: crate::account::AuthRef::None,
                username: "t@x.test".into(),
            },
        };
        store.upsert_account(&acct).unwrap();
        let got = store.get_account("a1").unwrap().unwrap();
        assert_eq!(got.email, "t@x.test");

        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        assert_eq!(fid, store.ensure_folder("a1", "INBOX").unwrap());
        store
            .set_folder_sync_state(fid, Some(777), Some(1004), 1003)
            .unwrap();
        let fm = store.folder_meta(fid).unwrap().unwrap();
        assert_eq!(fm.uid_validity, Some(777));

        store.upsert_message(fid, &meta(1001), 100).unwrap();
        store.upsert_message(fid, &meta(1002), 100).unwrap();
        let msgs = store.list_messages(fid, 50).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].uid, 1001);
        assert_eq!(msgs[0].flags, vec!["\\Seen"]);

        assert!(
            store
                .update_flags(fid, 1001, &["\\Flagged".to_string()])
                .unwrap()
        );
        let msgs = store.list_messages(fid, 50).unwrap();
        assert_eq!(msgs[0].flags, vec!["\\Flagged"]);

        // body storage
        let path = store
            .store_body(fid, 1001, b"Subject: x\r\n\r\nbody")
            .unwrap();
        assert!(path.exists());
        assert!(store.body_file(fid, 1001).unwrap().is_some());
        assert_eq!(store.uids_without_body(fid).unwrap(), vec![1002]);

        // expunge
        assert_eq!(store.delete_messages(fid, &[1002]).unwrap(), 1);
        assert_eq!(store.folder_uids(fid).unwrap(), vec![1001]);

        // uidvalidity reset wipes messages
        store.clear_folder_messages(fid).unwrap();
        assert!(store.folder_uids(fid).unwrap().is_empty());
    }

    #[test]
    fn outbox_roundtrip() {
        let store = MailStore::open_memory().unwrap();
        store
            .conn
            .execute(
                "INSERT INTO accounts (account_id, display_name, email, config_json)
                 VALUES ('a1', 'd', 'e', '{}')",
                [],
            )
            .unwrap();
        let row = OutboxRow {
            queue_id: "send-q1".into(),
            account_id: "a1".into(),
            from_addr: "a@x".into(),
            to_addrs: vec!["b@y".into(), "c@y".into()],
            subject: "s".into(),
            message_id: "<m@x>".into(),
            mime: b"Subject: s\r\n\r\nbody".to_vec(),
            not_before_unix: 200,
            undo_window_until_unix: 110,
            attempts: 0,
            last_error: None,
            created_unix: 100,
        };
        store.outbox_put(&row).unwrap();
        let rows = store.outbox_list(10).unwrap();
        assert_eq!(rows, vec![row.clone()]);

        // retry backoff update records the sanitized reason (T-298)
        assert!(
            store
                .outbox_set_timing("send-q1", 230, 1, Some("server-reject: 421 try later"))
                .unwrap()
        );
        let rows = store.outbox_list(10).unwrap();
        assert_eq!(rows[0].not_before_unix, 230);
        assert_eq!(rows[0].attempts, 1);
        assert_eq!(
            rows[0].last_error.as_deref(),
            Some("server-reject: 421 try later")
        );
        // a reschedule clears the stale reason
        assert!(store.outbox_set_timing("send-q1", 240, 1, None).unwrap());
        assert_eq!(store.outbox_list(10).unwrap()[0].last_error, None);
        assert!(!store.outbox_set_timing("send-gone", 1, 1, None).unwrap());

        // limit bounds the read
        assert_eq!(store.outbox_list(0).unwrap().len(), 0);

        // terminal drop is idempotent
        assert!(store.outbox_delete("send-q1").unwrap());
        assert!(!store.outbox_delete("send-q1").unwrap());
        assert!(store.outbox_list(10).unwrap().is_empty());
    }

    /// T-345: the tray tooltip count is `total_unseen` — the same unseen +
    /// muted-conversation predicate as `folder_stats`, summed across every
    /// folder. `outbox_count` feeds the quit guard, so both are pinned here.
    #[test]
    fn total_unseen_and_outbox_count_match_their_consumers() {
        let store = MailStore::open_memory().unwrap();
        store.upsert_account(&acct("a1")).unwrap();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();

        let mut unseen = meta(1);
        unseen.flags = vec![];
        let seen = meta(2); // meta() defaults to \\Seen
        let mut muted = meta(3);
        muted.flags = vec![];
        muted.subject = Some("Deploy".into());
        store.upsert_message(fid, &unseen, 100).unwrap();
        store.upsert_message(fid, &seen, 100).unwrap();
        store.upsert_message(fid, &muted, 100).unwrap();
        assert_eq!(store.total_unseen().unwrap(), 2);

        // Muting "deploy" (normalized) drops that message from the total,
        // matching folder_stats — the badge and the tooltip agree.
        store
            .set_conversation_muted("a1", "deploy", true, 100)
            .unwrap();
        assert_eq!(store.total_unseen().unwrap(), 1);
        store
            .set_conversation_muted("a1", "deploy", false, 100)
            .unwrap();
        assert_eq!(store.total_unseen().unwrap(), 2);

        // The quit guard reads a real row count, not a probe of the file.
        assert_eq!(store.outbox_count().unwrap(), 0);
        store
            .outbox_put(&OutboxRow {
                queue_id: "q1".into(),
                account_id: "a1".into(),
                from_addr: "a@x".into(),
                to_addrs: vec!["b@y".into()],
                subject: "s".into(),
                message_id: "<m@x>".into(),
                mime: b"Subject: s\r\n\r\nbody".to_vec(),
                not_before_unix: 200,
                undo_window_until_unix: 0,
                attempts: 0,
                last_error: None,
                created_unix: 100,
            })
            .unwrap();
        assert_eq!(store.outbox_count().unwrap(), 1);
        store.outbox_delete("q1").unwrap();
        assert_eq!(store.outbox_count().unwrap(), 0);
    }

    fn acct(id: &str) -> MailAccount {
        use crate::account::{AuthRef, IncomingAccount, IncomingProtocol, OutgoingAccount};
        use crate::transport::SocketSecurity;
        MailAccount {
            account_id: id.into(),
            display_name: "Test".into(),
            email: "t@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: crate::account::ServerConfig {
                    host: "h".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: "t@x.test".into(),
            },
            outgoing: OutgoingAccount {
                server: crate::account::ServerConfig {
                    host: "h".into(),
                    port: 587,
                    security: SocketSecurity::StartTls,
                },
                auth: AuthRef::None,
                username: "t@x.test".into(),
            },
        }
    }

    fn seed_account(store: &MailStore, id: &str) {
        store.upsert_account(&acct(id)).unwrap();
    }

    fn outbox_row(id: &str, not_before: i64, undo_until: i64) -> OutboxRow {
        OutboxRow {
            queue_id: id.into(),
            account_id: "a1".into(),
            from_addr: "a@x".into(),
            to_addrs: vec!["b@y".into()],
            subject: "s".into(),
            message_id: format!("<{id}@x>"),
            mime: b"Subject: s\r\n\r\nbody".to_vec(),
            not_before_unix: not_before,
            undo_window_until_unix: undo_until,
            attempts: 0,
            last_error: None,
            created_unix: 100,
        }
    }

    #[test]
    fn outbox_due_and_next_due() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        assert_eq!(store.outbox_next_due_at().unwrap(), None);
        store.outbox_put(&outbox_row("q1", 500, 110)).unwrap();
        store.outbox_put(&outbox_row("q2", 200, 110)).unwrap();
        store.outbox_put(&outbox_row("q3", 900, 110)).unwrap();

        assert_eq!(store.outbox_next_due_at().unwrap(), Some(200));
        let due: Vec<_> = store
            .outbox_due(500, 10)
            .unwrap()
            .iter()
            .map(|r| r.queue_id.clone())
            .collect();
        assert_eq!(due, vec!["q2", "q1"]); // earliest not_before first
        store.outbox_delete("q2").unwrap();
        assert_eq!(store.outbox_next_due_at().unwrap(), Some(500));
    }

    #[test]
    fn delete_account_cascades_and_cleans_payloads() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store.upsert_message(fid, &meta(1001), 100).unwrap();
        let body = store.store_body(fid, 1001, b"Subject: x\r\n\r\nb").unwrap();
        let att = store.store_attachment(fid, 1001, 0, b"payload").unwrap();
        store.outbox_put(&outbox_row("q1", 200, 110)).unwrap();
        assert!(body.exists() && att.exists());
        assert_eq!(store.list_accounts().unwrap().len(), 1);

        assert!(store.delete_account("a1").unwrap());
        assert!(!body.exists(), "body file must be removed");
        assert!(!att.exists(), "attachment must be removed");
        assert!(store.list_accounts().unwrap().is_empty());
        assert!(store.outbox_list(10).unwrap().is_empty());
        assert!(store.folder_meta(fid).unwrap().is_none());
        assert!(!store.delete_account("a1").unwrap()); // idempotent
    }

    #[test]
    fn move_messages_remaps_uids_and_moves_payloads() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let src = store.ensure_folder("a1", "INBOX").unwrap();
        let dst = store.ensure_folder("a1", "Trash").unwrap();
        store.upsert_message(src, &meta(101), 100).unwrap();
        store.upsert_message(src, &meta(102), 100).unwrap();
        store.upsert_message(src, &meta(103), 100).unwrap();
        store.upsert_message(dst, &meta(9), 100).unwrap(); // occupied uid
        let body = store.store_body(src, 102, b"Subject: m\r\n\r\nb").unwrap();
        store.store_attachment(src, 102, 0, b"payload").unwrap();
        assert!(body.exists());

        // Fresh UIDs in dst (max was 9): 101â†’10, 102â†’11. Absent uid skipped.
        let moved = store.move_messages(src, dst, &[101, 102, 999]).unwrap();
        assert_eq!(moved, vec![(101, 10), (102, 11)]);
        assert_eq!(store.folder_uids(src).unwrap(), vec![103]);
        assert_eq!(store.folder_uids(dst).unwrap(), vec![9, 10, 11]);
        // Payload followed the message under its new uid.
        let new_body = store.body_file(dst, 11).unwrap().unwrap();
        assert!(new_body.exists());
        assert!(!body.exists());
        let att = store
            .root
            .join("attachments")
            .join(dst.to_string())
            .join("11")
            .join("0");
        assert!(att.exists());
        // Fields preserved across the move.
        let rows = store.list_messages(dst, 10).unwrap();
        assert_eq!(
            rows.iter()
                .find(|m| m.uid == 11)
                .unwrap()
                .subject
                .as_deref(),
            Some("s")
        );

        // list_folders: both folders, name order.
        let names: Vec<_> = store
            .list_folders("a1")
            .unwrap()
            .iter()
            .map(|f| f.name.clone())
            .collect();
        assert_eq!(names, vec!["INBOX", "Trash"]);
    }

    #[test]
    fn delete_messages_removes_body_file() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store.upsert_message(fid, &meta(1001), 100).unwrap();
        let body = store.store_body(fid, 1001, b"Subject: x\r\n\r\nb").unwrap();
        assert!(body.exists());
        store.delete_messages(fid, &[1001]).unwrap();
        assert!(!body.exists());
    }

    #[test]
    fn pop3_seen_dedup() {
        let store = MailStore::open_memory().unwrap();
        let acct_id = "a1";
        store
            .conn
            .execute(
                "INSERT INTO accounts (account_id, display_name, email, config_json)
                 VALUES (?1, 'd', 'e', '{}')",
                params![acct_id],
            )
            .unwrap();
        assert!(!store.pop3_seen_contains(acct_id, "uidl1").unwrap());
        store.pop3_mark_seen(acct_id, "uidl1", 100).unwrap();
        assert!(store.pop3_seen_contains(acct_id, "uidl1").unwrap());
    }

    #[test]
    fn category_persist_refine_filter() {
        use crate::category::Category;
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();

        // Ingest stores the tabâ€¦
        let mut m1 = meta(1001);
        m1.category = Category::Newsletters;
        store.upsert_message(fid, &m1, 100).unwrap();
        store.upsert_message(fid, &meta(1002), 100).unwrap(); // Primary default
        let rows = store.list_messages(fid, 10).unwrap();
        assert_eq!(rows[0].category, Category::Newsletters);
        assert_eq!(rows[1].category, Category::Primary);

        // â€¦refinement updates itâ€¦
        assert!(store.set_category(fid, 1002, Category::Social).unwrap());
        assert!(!store.set_category(fid, 9999, Category::Other).unwrap());
        assert_eq!(
            store.list_messages(fid, 10).unwrap()[1].category,
            Category::Social
        );

        // â€¦re-upserts never clobber a refined tab with an ingest defaultâ€¦
        store.upsert_message(fid, &meta(1002), 200).unwrap();
        assert_eq!(
            store.list_messages(fid, 10).unwrap()[1].category,
            Category::Social
        );

        // â€¦and the tab filter powers the F2 UI tabs.
        let social = store
            .list_messages_by_category(fid, Category::Social, 10)
            .unwrap();
        assert_eq!(social.len(), 1);
        assert_eq!(social[0].uid, 1002);
        assert!(
            store
                .list_messages_by_category(fid, Category::Notifications, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn move_preserves_category() {
        use crate::category::Category;
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let src = store.ensure_folder("a1", "INBOX").unwrap();
        let dst = store.ensure_folder("a1", "Archive").unwrap();
        let mut m = meta(101);
        m.category = Category::Notifications;
        store.upsert_message(src, &m, 100).unwrap();
        store.move_messages(src, dst, &[101]).unwrap();
        let rows = store.list_messages(dst, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].category, Category::Notifications);
    }

    // -- snooze (T-255) --------------------------------------------------

    #[test]
    fn snooze_hides_lists_then_unsnooze_restores() {
        use crate::category::Category;
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store.upsert_message(fid, &meta(101), 100).unwrap();
        store.upsert_message(fid, &meta(102), 100).unwrap();

        // Park 101 until t=500; absent uid is skipped, not an error.
        assert_eq!(store.set_snooze(fid, &[101, 999], 500, 100).unwrap(), 1);
        assert_eq!(
            store
                .list_messages(fid, 10)
                .unwrap()
                .iter()
                .map(|m| m.uid)
                .collect::<Vec<_>>(),
            vec![102]
        );
        // Category tabs hide it too.
        assert!(
            store
                .list_messages_by_category(fid, Category::Primary, 10)
                .unwrap()
                .iter()
                .all(|m| m.uid != 101)
        );
        // …but it is still stored: folder_uids (sync truth) keeps it.
        assert_eq!(store.folder_uids(fid).unwrap(), vec![101, 102]);

        let parked = store.list_snoozed("a1", 10).unwrap();
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].uid, 101);
        assert_eq!(parked[0].until_unix, 500);
        assert_eq!(parked[0].from_folder_id, fid);
        assert_eq!(parked[0].folder_name, "INBOX");

        // Explicit release → back in the list, out of the view.
        assert_eq!(store.clear_snooze(fid, &[101, 777]).unwrap(), 1);
        assert_eq!(store.list_messages(fid, 10).unwrap().len(), 2);
        assert!(store.list_snoozed("a1", 10).unwrap().is_empty());
    }

    #[test]
    fn unsnooze_due_releases_due_rows_bounded() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        for uid in [1u64, 2, 3] {
            store.upsert_message(fid, &meta(uid), 100).unwrap();
        }
        store.set_snooze(fid, &[1], 100, 50).unwrap(); // due
        store.set_snooze(fid, &[2], 200, 50).unwrap(); // due at t=200
        store.set_snooze(fid, &[3], 9_999, 50).unwrap(); // future — stays

        let out = store.unsnooze_due("a1", 200, 200).unwrap();
        assert_eq!(out, vec![(fid, 1), (fid, 2)]);
        assert_eq!(
            store.list_snoozed("a1", 10).unwrap()[0].uid,
            3,
            "only the future snooze remains parked"
        );
        // uid3 stays hidden until its own deadline passes.
        assert_eq!(store.list_messages(fid, 10).unwrap().len(), 2);

        // Bound: re-park two dues, cap the sweep at one.
        store.set_snooze(fid, &[1, 2], 300, 250).unwrap();
        let out = store.unsnooze_due("a1", 400, 1).unwrap();
        assert_eq!(out, vec![(fid, 1)]);
        assert_eq!(store.list_snoozed("a1", 10).unwrap().len(), 2);
        // Second call releases the other due row — uid3's future deadline
        // is untouched. Pass-to-pass convergence, deterministic order.
        assert_eq!(store.unsnooze_due("a1", 400, 200).unwrap(), vec![(fid, 2)]);
        let left = store.list_snoozed("a1", 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].uid, 3);
    }

    #[test]
    fn snooze_survives_move_and_dies_with_delete() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let src = store.ensure_folder("a1", "INBOX").unwrap();
        let dst = store.ensure_folder("a1", "Work").unwrap();
        store.upsert_message(src, &meta(101), 100).unwrap();
        store.upsert_message(src, &meta(102), 100).unwrap();
        store.set_snooze(src, &[101, 102], 500, 100).unwrap();

        // Move carries the park state to the new coordinates; from_folder
        // still points at INBOX (where it was parked).
        let moved = store.move_messages(src, dst, &[101]).unwrap();
        let dst_uid = moved[0].1;
        let parked = store.list_snoozed("a1", 10).unwrap();
        assert_eq!(parked.len(), 2);
        let m101 = parked.iter().find(|m| m.uid == dst_uid).unwrap();
        assert_eq!(m101.folder_id, dst);
        assert_eq!(m101.from_folder_id, src);
        assert_eq!(m101.folder_name, "Work");

        // Hard delete drops the parking row (FK cascade).
        store.delete_messages(dst, &[dst_uid]).unwrap();
        assert_eq!(store.list_snoozed("a1", 10).unwrap().len(), 1);

        // UIDVALIDITY-style wipe cascades too.
        store.clear_folder_messages(src).unwrap();
        assert!(store.list_snoozed("a1", 10).unwrap().is_empty());

        // Account deletion: folders→messages→snoozed cascade chain.
        store.upsert_message(src, &meta(200), 100).unwrap();
        store.set_snooze(src, &[200], 500, 100).unwrap();
        assert_eq!(store.list_snoozed("a1", 10).unwrap().len(), 1);
        store.delete_account("a1").unwrap();
        assert!(store.list_snoozed("a1", 10).unwrap().is_empty());
    }

    #[test]
    fn resnooze_updates_deadline_keeps_origin() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store.upsert_message(fid, &meta(101), 100).unwrap();
        store.set_snooze(fid, &[101], 500, 100).unwrap();
        // Re-park with a later deadline — from_folder_id stays original.
        store.set_snooze(fid, &[101], 900, 200).unwrap();
        let parked = store.list_snoozed("a1", 10).unwrap();
        assert_eq!(parked.len(), 1, "re-snooze updates in place");
        assert_eq!(parked[0].until_unix, 900);
        assert_eq!(parked[0].set_at_unix, 200);
        assert_eq!(parked[0].from_folder_id, fid);
    }

    /// Pre-v4 database (messages table without `category`, `user_version = 3`)
    /// migrates to current: columns appear, stored bodies are classified and
    /// their unsubscribe offers extracted, rows without bodies keep defaults.
    #[test]
    fn v3_to_v4_migration_backfills_category() {
        use rusqlite::Connection;
        let dir = std::env::temp_dir().join(format!(
            "kiwi-mig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join("bodies").join("1")).unwrap();
        let conn = Connection::open(dir.join("mail.db")).unwrap();
        // v3 shape: messages WITHOUT the category/unsubscribe columns.
        conn.execute_batch(
            "CREATE TABLE messages (
                id              INTEGER PRIMARY KEY,
                folder_id       INTEGER NOT NULL,
                uid             INTEGER NOT NULL,
                message_id      TEXT,
                subject         TEXT,
                from_addr       TEXT,
                to_addrs        TEXT,
                date_unix       INTEGER,
                size            INTEGER,
                flags           TEXT NOT NULL DEFAULT '',
                has_attachments INTEGER NOT NULL DEFAULT 0,
                snippet         TEXT,
                body_path       TEXT,
                fetched_at      INTEGER NOT NULL,
                UNIQUE (folder_id, uid)
            );
            INSERT INTO messages
                (folder_id, uid, subject, from_addr, flags, fetched_at, body_path)
            VALUES
                (1, 42, 'sale', 'deals@shop.example', '', 100, 'bodies/1/42.eml'),
                (1, 43, 'hello', 'alice@example.com', '', 100, NULL);
            PRAGMA user_version = 3;",
        )
        .unwrap();
        std::fs::write(
            dir.join("bodies").join("1").join("42.eml"),
            b"From: deals@shop.example\r\nSubject: sale\r\nList-Unsubscribe: <mailto:leave@shop.example?subject=bye>, <https://shop.example/u>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\nbuy now\r\n",
        )
        .unwrap();

        super::migrate_conn(&conn, &dir).unwrap();

        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, super::schema::SCHEMA_VERSION);
        let cat: String = conn
            .query_row("SELECT category FROM messages WHERE uid = 42", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cat, "newsletters");
        // Unsubscribe offer backfilled from the same body (params stripped).
        let (http, mailto, oneclick): (Option<String>, Option<String>, i64) = conn
            .query_row(
                "SELECT unsub_http, unsub_mailto, unsub_oneclick FROM messages WHERE uid = 42",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(http.as_deref(), Some("https://shop.example/u"));
        assert_eq!(mailto.as_deref(), Some("leave@shop.example"));
        assert_eq!(oneclick, 1);
        // No body â†’ defaults stay.
        let cat: String = conn
            .query_row("SELECT category FROM messages WHERE uid = 43", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cat, "primary");
        let (http, mailto, oneclick): (Option<String>, Option<String>, i64) = conn
            .query_row(
                "SELECT unsub_http, unsub_mailto, unsub_oneclick FROM messages WHERE uid = 43",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(http, None);
        assert_eq!(mailto, None);
        assert_eq!(oneclick, 0);

        // Idempotent: a second run is a no-op.
        super::migrate_conn(&conn, &dir).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pre-v5 database (has `category`, lacks unsubscribe columns,
    /// `user_version = 4`) gains the columns with backfilled offers; the
    /// existing category values are untouched.
    #[test]
    fn v4_to_v5_migration_backfills_unsub() {
        use rusqlite::Connection;
        let dir = std::env::temp_dir().join(format!(
            "kiwi-mig5-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join("bodies").join("1")).unwrap();
        let conn = Connection::open(dir.join("mail.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                id              INTEGER PRIMARY KEY,
                folder_id       INTEGER NOT NULL,
                uid             INTEGER NOT NULL,
                message_id      TEXT,
                subject         TEXT,
                from_addr       TEXT,
                to_addrs        TEXT,
                date_unix       INTEGER,
                size            INTEGER,
                flags           TEXT NOT NULL DEFAULT '',
                has_attachments INTEGER NOT NULL DEFAULT 0,
                snippet         TEXT,
                body_path       TEXT,
                fetched_at      INTEGER NOT NULL,
                category        TEXT NOT NULL DEFAULT 'primary',
                UNIQUE (folder_id, uid)
            );
            INSERT INTO messages
                (folder_id, uid, subject, from_addr, flags, fetched_at,
                 body_path, category)
            VALUES
                (1, 7, 'digest', 'news@x.example', '', 100,
                 'bodies/1/7.eml', 'newsletters');
            PRAGMA user_version = 4;",
        )
        .unwrap();
        std::fs::write(
            dir.join("bodies").join("1").join("7.eml"),
            b"From: news@x.example\r\nSubject: digest\r\nList-Unsubscribe: <https://x.example/leave>\r\n\r\nnews\r\n",
        )
        .unwrap();

        super::migrate_conn(&conn, &dir).unwrap();

        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, super::schema::SCHEMA_VERSION);
        // Category untouched; unsubscribe filled.
        let (cat, http, oneclick): (String, Option<String>, i64) = conn
            .query_row(
                "SELECT category, unsub_http, unsub_oneclick FROM messages WHERE uid = 7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(cat, "newsletters");
        assert_eq!(http.as_deref(), Some("https://x.example/leave"));
        assert_eq!(oneclick, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsubscribe_persist_refine_no_clobber() {
        use crate::unsub::UnsubscribeInfo;
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        let fid = store.ensure_folder("a1", "INBOX").unwrap();

        // Ingest stores the offerâ€¦
        let mut m = meta(1001);
        m.unsub_http = Some("https://x.example/u".into());
        m.unsub_mailto = Some("u@x.example".into());
        m.unsub_oneclick = true;
        store.upsert_message(fid, &m, 100).unwrap();
        let row = store.list_messages(fid, 10).unwrap().remove(0);
        assert_eq!(row.unsub_http.as_deref(), Some("https://x.example/u"));
        assert_eq!(row.unsub_mailto.as_deref(), Some("u@x.example"));
        assert!(row.unsub_oneclick);

        // â€¦refinement replaces itâ€¦
        let info = UnsubscribeInfo {
            http_url: Some("https://y.example/n".into()),
            mailto: None,
            one_click: false,
        };
        assert!(store.set_unsubscribe(fid, 1001, &info).unwrap());
        assert!(!store.set_unsubscribe(fid, 9999, &info).unwrap());
        let row = store.list_messages(fid, 10).unwrap().remove(0);
        assert_eq!(row.unsub_http.as_deref(), Some("https://y.example/n"));
        assert_eq!(row.unsub_mailto, None);
        assert!(!row.unsub_oneclick);

        // â€¦re-upserts never clobber a refined offer with ingest defaultsâ€¦
        store.upsert_message(fid, &meta(1001), 200).unwrap();
        let row = store.list_messages(fid, 10).unwrap().remove(0);
        assert_eq!(row.unsub_http.as_deref(), Some("https://y.example/n"));

        // â€¦and moves carry it.
        let dst = store.ensure_folder("a1", "Archive").unwrap();
        store.move_messages(fid, dst, &[1001]).unwrap();
        let row = store.list_messages(dst, 10).unwrap().remove(0);
        assert_eq!(row.unsub_http.as_deref(), Some("https://y.example/n"));
    }

    // -- rules CRUD (T-228) ---------------------------------------------------

    fn rule(id: &str, account: Option<&str>, position: i64) -> crate::rules::Rule {
        use crate::rules::{MatchOp, Predicate, Rule, RuleAction};
        Rule {
            id: id.into(),
            account_id: account.map(str::to_string),
            name: format!("rule {id}"),
            enabled: true,
            position,
            is_block: false,
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: "x.example".into(),
            },
            then: vec![RuleAction::MarkRead],
        }
    }

    #[test]
    fn rules_scope_order_update_delete() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");

        store.upsert_rule(&rule("z-last", None, 30)).unwrap();
        store.upsert_rule(&rule("a-first", None, 10)).unwrap();
        store.upsert_rule(&rule("b-acct", Some("a1"), 20)).unwrap();

        // Global scope sees only the global rules.
        let globals = store.list_rules(None).unwrap();
        assert_eq!(
            globals.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["a-first", "z-last"]
        );
        // Account scope = global + own, position order.
        let scoped = store.list_rules(Some("a1")).unwrap();
        assert_eq!(
            scoped.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["a-first", "b-acct", "z-last"]
        );
        assert_eq!(
            scoped[1].when,
            rule("b-acct", Some("a1"), 20).when // spec round-trips through JSON
        );

        // Upsert updates in place (reorder + edit).
        let mut moved = rule("b-acct", Some("a1"), 1);
        moved.is_block = true;
        store.upsert_rule(&moved).unwrap();
        let scoped = store.list_rules(Some("a1")).unwrap();
        assert_eq!(scoped[0].id, "b-acct");
        assert!(scoped[0].is_block);
        assert_eq!(store.get_rule("b-acct").unwrap().unwrap().position, 1);

        // Delete is idempotent.
        assert!(store.delete_rule("b-acct").unwrap());
        assert!(!store.delete_rule("b-acct").unwrap());
        assert_eq!(store.list_rules(Some("a1")).unwrap().len(), 2);
        assert!(store.get_rule("b-acct").unwrap().is_none());
    }

    #[test]
    fn rule_health_persists_count_and_bounded_last_error() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        store.upsert_rule(&rule("healthy", Some("a1"), 1)).unwrap();
        let error = "line one\n".to_string() + &"x".repeat(600);
        store
            .record_rule_failures(&["healthy".into(), "healthy".into()], &error, 42)
            .unwrap();
        store
            .record_rule_failures(&["healthy".into()], "second failure", 43)
            .unwrap();
        let record = store.get_rule_record("healthy").unwrap().unwrap();
        assert_eq!(
            record.failure_count, 2,
            "duplicate id counts once per event"
        );
        assert_eq!(record.last_error.as_deref(), Some("second failure"));
        assert_eq!(record.last_failure_unix, Some(43));

        // Editing a rule does not erase historical health.
        let mut edited = rule("healthy", Some("a1"), 2);
        edited.name = "renamed".into();
        store.upsert_rule(&edited).unwrap();
        let record = store.get_rule_record("healthy").unwrap().unwrap();
        assert_eq!(record.failure_count, 2);
        assert_eq!(record.last_error.as_deref(), Some("second failure"));
    }

    #[test]
    fn v13_to_v14_adds_rule_health_without_losing_rules() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        // Model a pre-v14 rules table: current DDL has the new columns, so
        // rebuild just that table with the old shape and an existing row.
        conn.execute_batch(
            "ALTER TABLE rules RENAME TO rules_new;
             CREATE TABLE rules (
                rule_id TEXT PRIMARY KEY, account_id TEXT, name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, position INTEGER NOT NULL,
                is_block INTEGER NOT NULL DEFAULT 0, spec_json TEXT NOT NULL);
             INSERT INTO rules
                SELECT rule_id, account_id, name, enabled, position, is_block, spec_json
                FROM rules_new;
             INSERT INTO rules
                (rule_id, account_id, name, enabled, position, is_block, spec_json)
                VALUES ('kept', 'a1', 'Keep me', 1, 0, 0, '{}');
             DROP TABLE rules_new;
             PRAGMA user_version = 13",
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-rules-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(rules)")
            .unwrap()
            .query_map([], |r| r.get(1))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|c| c == "failure_count"));
        assert!(columns.iter().any(|c| c == "last_error"));
        assert!(columns.iter().any(|c| c == "last_failure_unix"));
        let (count, last): (i64, Option<String>) = conn
            .query_row("SELECT failure_count, last_error FROM rules", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((count, last), (0, None), "health history is not fabricated");
    }

    #[test]
    fn v14_to_v15_creates_templates_and_preserves_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        // Model a pre-v15 database: drop the new table, pin v14, and put
        // a row in a neighboring table to prove migration is additive.
        conn.execute_batch(
            "DROP TABLE templates;
             INSERT INTO accounts (account_id, display_name, email, config_json)
                VALUES ('a1', 'A', 'a@x.test', '{}');
             PRAGMA user_version = 14",
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-tpl-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'templates'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let kept: String = conn
            .query_row(
                "SELECT email FROM accounts WHERE account_id = 'a1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, "a@x.test");
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn v15_to_v16_adds_outbox_last_error_preserving_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        // Model a pre-v16 database: drop the column (fresh DDL already
        // has it), pin v15, and seed a queued send to prove the column
        // add is additive, not a rebuild.
        conn.execute_batch(
            "ALTER TABLE outbox DROP COLUMN last_error;
             INSERT INTO accounts (account_id, display_name, email, config_json)
                VALUES ('a1', 'A', 'a@x.test', '{}');
             INSERT INTO outbox (queue_id, account_id, from_addr, to_addrs,
                                 subject, message_id, mime, not_before_unix,
                                 undo_until_unix, attempts, created_unix)
                VALUES ('send-old', 'a1', 'a@x', '[\"b@y\"]', 's', '<m@x>',
                        X'00', 100, 0, 0, 90);
             PRAGMA user_version = 15",
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-obx-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        let (attempts, last_error): (i64, Option<String>) = conn
            .query_row(
                "SELECT attempts, last_error FROM outbox WHERE queue_id = 'send-old'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(attempts, 0, "row preserved");
        assert_eq!(
            last_error, None,
            "pre-column sends have no reason — NULL, never fabricated"
        );
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn templates_crud_roundtrip_and_id_sequence() {
        let store = MailStore::open_memory().unwrap();
        let t = crate::templates::Template {
            id: String::new(),
            name: "Intro".into(),
            subject: "Hi {{name}}".into(),
            body_text: "Hello {{name}},\n\n— us".into(),
            body_html: None,
            created_unix: 0,
            updated_unix: 0,
        };
        let first = store.insert_template(&t, 10).unwrap();
        assert_eq!(first.id, "tpl-1");
        assert_eq!((first.created_unix, first.updated_unix), (10, 10));
        let second = store.insert_template(&t, 11).unwrap();
        assert_eq!(second.id, "tpl-2");

        // Reserved prefix cannot be caller-supplied.
        let mut forged = t.clone();
        forged.id = "tpl-99".into();
        assert!(store.insert_template(&forged, 12).is_err());
        // Explicit caller id is fine when it avoids the prefix.
        forged.id = "imported-1".into();
        assert!(store.insert_template(&forged, 12).is_ok());

        // Update is full-replace: created preserved, updated bumped.
        let mut edited = second.clone();
        edited.name = "Renamed".into();
        edited.body_html = Some("<p>hi</p>".into());
        assert!(store.update_template(&edited, 20).unwrap());
        let got = store.get_template("tpl-2").unwrap().unwrap();
        assert_eq!(got.name, "Renamed");
        assert_eq!((got.created_unix, got.updated_unix), (11, 20));
        let mut absent = edited.clone();
        absent.id = "tpl-404".into();
        assert!(!store.update_template(&absent, 21).unwrap());
        assert!(store.get_template("tpl-404").unwrap().is_none());

        // Order is name-then-id; delete is idempotent.
        let names: Vec<_> = store
            .list_templates()
            .unwrap()
            .iter()
            .map(|t| t.name.clone())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(store.delete_template("tpl-1").unwrap());
        assert!(!store.delete_template("tpl-1").unwrap());
    }

    #[test]
    fn rules_validate_gate_and_corrupt_row_handling() {
        let store = MailStore::open_memory().unwrap();
        // Invalid rules never reach the table.
        let mut bad = rule("bad", None, 1);
        bad.then = vec![];
        assert!(store.upsert_rule(&bad).is_err());
        assert!(store.get_rule("bad").unwrap().is_none());

        // A corrupt spec row is skipped by list_rules but reported by get.
        store
            .conn
            .execute(
                "INSERT INTO rules
                   (rule_id, account_id, name, enabled, position, is_block, spec_json)
                 VALUES ('corrupt', NULL, 'c', 1, 5, 0, '{not json')",
                [],
            )
            .unwrap();
        store.upsert_rule(&rule("ok", None, 1)).unwrap();
        let ids: Vec<_> = store
            .list_rules(None)
            .unwrap()
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(ids, vec!["ok"]);
        assert!(store.get_rule("corrupt").is_err());
    }

    #[test]
    fn rules_cascade_on_account_delete() {
        let store = MailStore::open_memory().unwrap();
        seed_account(&store, "a1");
        store.upsert_rule(&rule("g", None, 1)).unwrap();
        store.upsert_rule(&rule("mine", Some("a1"), 1)).unwrap();
        assert!(store.delete_account("a1").unwrap());
        let rest = store.list_rules(None).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].id, "g");
    }

    // -- T-261 link risk evidence --------------------------------------------

    #[test]
    fn link_risk_roundtrips_attaches_and_moves() {
        let s = MailStore::open_memory().unwrap();
        seed_account(&s, "a1");
        let src = s.ensure_folder("a1", "INBOX").unwrap();
        let dst = s.ensure_folder("a1", "Archive").unwrap();
        s.upsert_message(src, &meta(19), 0).unwrap();
        let evidence = crate::linkrisk::LinkRiskEvidence {
            risk: crate::linkrisk::LinkRisk::Failed,
            reasons: vec![
                crate::linkrisk::LinkRiskReason::IpLiteralHost,
                crate::linkrisk::LinkRiskReason::DisplayDomainMismatch,
            ],
        };
        assert!(s.set_link_risk(src, 19, &evidence).unwrap());
        assert_eq!(s.get_link_risk(src, 19).unwrap(), Some(evidence.clone()));
        assert_eq!(
            s.list_messages(src, 10).unwrap()[0].link_risk,
            Some(evidence.clone())
        );
        assert_eq!(
            s.list_messages_by_category(src, Category::Primary, 10)
                .unwrap()[0]
                .link_risk,
            Some(evidence.clone())
        );
        let moved = s.move_messages(src, dst, &[19]).unwrap();
        assert_eq!(moved, vec![(19, 1)]);
        assert!(s.get_link_risk(src, 19).unwrap().is_none());
        assert_eq!(s.get_link_risk(dst, 1).unwrap(), Some(evidence));
    }

    #[test]
    fn v12_to_v13_creates_link_sibling_without_backfill() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        conn.execute_batch("DROP TABLE message_link_risk; PRAGMA user_version = 12")
            .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-link-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_link_risk", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "historical URL evidence is not fabricated");
    }

    // -- T-254 attachment risk evidence ---------------------------------------

    #[test]
    fn attachment_risk_roundtrips_attaches_and_moves() {
        let s = MailStore::open_memory().unwrap();
        seed_account(&s, "a1");
        let src = s.ensure_folder("a1", "INBOX").unwrap();
        let dst = s.ensure_folder("a1", "Archive").unwrap();
        s.upsert_message(src, &meta(9), 0).unwrap();
        let evidence = crate::attachrisk::AttachRiskEvidence {
            risk: crate::attachrisk::AttachRisk::Failed,
            reasons: vec![
                crate::attachrisk::AttachRiskReason::DangerousExtension,
                crate::attachrisk::AttachRiskReason::DoubleExtension,
            ],
        };
        assert!(s.set_attachment_risk(src, 9, &evidence).unwrap());
        assert_eq!(
            s.get_attachment_risk(src, 9).unwrap(),
            Some(evidence.clone())
        );
        assert_eq!(
            s.list_messages(src, 10).unwrap()[0].attach_risk,
            Some(evidence.clone())
        );
        assert_eq!(
            s.list_messages_by_category(src, Category::Primary, 10)
                .unwrap()[0]
                .attach_risk,
            Some(evidence.clone())
        );
        let moved = s.move_messages(src, dst, &[9]).unwrap();
        assert_eq!(moved, vec![(9, 1)]);
        assert!(s.get_attachment_risk(src, 9).unwrap().is_none());
        assert_eq!(s.get_attachment_risk(dst, 1).unwrap(), Some(evidence));
    }

    #[test]
    fn v10_to_v11_creates_attachment_sibling_without_backfill() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        conn.execute_batch("DROP TABLE message_attachment_risk; PRAGMA user_version = 10")
            .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-attach-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_attachment_risk", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "no historical risk is fabricated");
    }

    #[test]
    fn v11_to_v12_creates_snoozed_for_existing_databases() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        // A pre-v12 database: no `snoozed` table, older user_version.
        conn.execute_batch("DROP TABLE snoozed; PRAGMA user_version = 11")
            .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-snooze-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        // Table exists with the full column set, empty — nothing was parked.
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM snoozed", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    // -- T-264 folder counts ------------------------------------------------

    #[test]
    fn folder_stats_counts_seen_unseen_and_moves() {
        let s = MailStore::open_memory().unwrap();
        seed_account(&s, "a1");
        let src = s.ensure_folder("a1", "INBOX").unwrap();
        let dst = s.ensure_folder("a1", "Junk").unwrap();
        let empty = s.ensure_folder("a1", "Empty").unwrap();

        // meta() defaults \Seen: 2 seen + 1 unseen at source.
        s.upsert_message(src, &meta(1), 0).unwrap();
        s.upsert_message(src, &meta(2), 0).unwrap();
        let mut unseen_meta = meta(3);
        unseen_meta.flags = vec![];
        s.upsert_message(src, &unseen_meta, 0).unwrap();

        let st = s.folder_stats(src).unwrap();
        assert_eq!((st.exists, st.unseen), (3, 1));
        let st = s.folder_stats(empty).unwrap();
        assert_eq!((st.exists, st.unseen), (0, 0), "empty folder");

        // Mark seen: unseen drops; un-marking restores (case-insensitive).
        s.set_flag(src, &[3], "\\Seen", true).unwrap();
        let st = s.folder_stats(src).unwrap();
        assert_eq!((st.exists, st.unseen), (3, 0));
        s.set_flag(src, &[1], "\\seen", false).unwrap();
        let st = s.folder_stats(src).unwrap();
        assert_eq!((st.exists, st.unseen), (3, 1));

        // Junk is orthogonal to \Seen: flagging junk moves neither count.
        s.set_flag(src, &[2], JUNK_FLAG, true).unwrap();
        let st = s.folder_stats(src).unwrap();
        assert_eq!((st.exists, st.unseen), (3, 1));

        // Move unseen uid 1 + seen uid 2: counts travel with the rows.
        let moved = s.move_messages(src, dst, &[1, 2]).unwrap();
        assert_eq!(moved.len(), 2);
        assert_eq!(
            (
                s.folder_stats(src).unwrap().exists,
                s.folder_stats(src).unwrap().unseen
            ),
            (1, 0)
        );
        let st = s.folder_stats(dst).unwrap();
        assert_eq!((st.exists, st.unseen), (2, 1), "flags ride the move");

        // Delete + snooze: delete drops exists; parked rows still count
        // (literal store truth — defer, not suppress).
        s.delete_messages(dst, &[moved[0].1]).unwrap();
        let st = s.folder_stats(dst).unwrap();
        assert_eq!((st.exists, st.unseen), (1, 0));
        s.set_snooze(src, &[3], 1_758_000_000 + 9999, src).unwrap();
        let st = s.folder_stats(src).unwrap();
        assert_eq!((st.exists, st.unseen), (1, 0), "parked still counts");
    }

    /// T-232: Authentication-Results stamping.
    ///
    /// Fully offline â€” persistence only; the verdict evaluation itself is
    /// covered by `authstamp`'s own `MockResolver` suite. These tests prove
    /// the stamp is written at ingest, survives a re-fetch, and reaches list
    /// rows so the UI pill has real values.
    mod auth {
        use super::*;
        use crate::authstamp::AuthStamp;

        fn meta(uid: u64) -> NewMessageMeta {
            NewMessageMeta {
                uid,
                message_id: None,
                subject: None,
                from_addr: None,
                to_addrs: None,
                date_unix: None,
                size: None,
                flags: vec![],
                has_attachments: false,
                snippet: None,
                category: Category::Primary,
                unsub_http: None,
                unsub_mailto: None,
                unsub_oneclick: false,
            }
        }

        fn stamp(dkim: &str, dmarc: &str) -> AuthStamp {
            AuthStamp {
                spf: "none".into(),
                dkim: dkim.into(),
                dmarc: dmarc.into(),
                dmarc_policy: "reject".into(),
                dkim_domain: Some("example.com".into()),
                dkim_key_query: Some("sel._domainkey.example.com".into()),
                dmarc_record: Some("v=DMARC1; p=reject".into()),
                spf_explanation: "no SMTP receipt context".into(),
                dkim_explanation: "body hash mismatch".into(),
                dmarc_explanation: "no aligned identifier".into(),
                header_value: "kiwi; spf=none; dkim=pass; dmarc=pass".into(),
                upstream: Default::default(),
                auth_risk: crate::authrisk::AuthRisk::Noted,
            }
        }

        fn store_with_message(uid: u64) -> (MailStore, i64) {
            let s = MailStore::open_memory().unwrap();
            // Minimal account row: these tests are about the auth stamp, not
            // the account model, so insert the FK parent directly.
            s.conn()
                .execute(
                    "INSERT INTO accounts (account_id, display_name, email, config_json)
                     VALUES ('a1', 'T', 'me@example.com', '{}')",
                    [],
                )
                .unwrap();
            let folder = s.ensure_folder("a1", "INBOX").unwrap();
            s.upsert_message(folder, &meta(uid), 0).unwrap();
            (s, folder)
        }

        #[test]
        fn set_and_get_auth_roundtrip() {
            let (s, folder) = store_with_message(7);
            assert!(s.set_auth(folder, 7, &stamp("pass", "pass")).unwrap());
            let got = s.get_auth(folder, 7).unwrap().expect("stamp persisted");
            assert_eq!(got.spf, "none");
            assert_eq!(got.dkim, "pass");
            assert_eq!(got.dmarc, "pass");
            assert_eq!(got.dmarc_policy, "reject");
            assert_eq!(got.key_query.as_deref(), Some("sel._domainkey.example.com"));
            assert_eq!(
                got.header_value.as_deref(),
                Some("kiwi; spf=none; dkim=pass; dmarc=pass")
            );
            let ev = got.evidence.expect("evidence json");
            assert_eq!(ev["dkim"], "body hash mismatch");
            assert!(got.upstream.untrusted_relay);
        }

        #[test]
        fn upstream_evidence_and_discrepancy_roundtrip() {
            let (s, folder) = store_with_message(8);
            let mut auth = stamp("pass", "fail");
            auth.upstream = crate::authstamp::parse_upstream_auth_results(&[(
                "Authentication-Results".into(),
                "mx.example; spf=pass; dkim=fail; dmarc=pass".into(),
            )]);
            crate::authstamp::compare_upstream_verdicts(&mut auth.upstream, "none", "pass", "fail");
            s.set_auth(folder, 8, &auth).unwrap();
            let got = s.get_auth(folder, 8).unwrap().unwrap();
            assert_eq!(got.upstream.authserv_ids, ["mx.example"]);
            assert_eq!(got.upstream.comparisons.len(), 3);
            assert!(got.upstream.has_discrepancy());
            assert_eq!(got.auth_risk, AuthRisk::Noted);
            let listed = s.list_messages(folder, 10).unwrap().remove(0);
            assert!(listed.auth.unwrap().upstream.has_discrepancy());
        }

        #[test]
        fn re_ingest_refreshes_instead_of_duplicating() {
            let (s, folder) = store_with_message(7);
            s.set_auth(folder, 7, &stamp("fail", "fail")).unwrap();
            s.set_auth(folder, 7, &stamp("pass", "pass")).unwrap();
            let got = s.get_auth(folder, 7).unwrap().unwrap();
            assert_eq!(got.dkim, "pass", "second write wins");
            let rows: i64 = s
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM message_auth WHERE folder_id = ?1 AND uid = 7",
                    rusqlite::params![folder],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(rows, 1, "exactly one row per (folder, uid)");
        }

        #[test]
        fn list_attaches_auth_and_leaves_unstamped_none() {
            let (s, folder) = store_with_message(1);
            s.upsert_message(folder, &meta(2), 0).unwrap();
            s.set_auth(folder, 1, &stamp("pass", "pass")).unwrap();
            let msgs = s.list_messages(folder, 50).unwrap();
            let m1 = msgs.iter().find(|m| m.uid == 1).unwrap();
            let m2 = msgs.iter().find(|m| m.uid == 2).unwrap();
            assert_eq!(m1.auth.as_ref().unwrap().dkim, "pass");
            assert!(
                m2.auth.is_none(),
                "no stamp means not evaluated â€” distinct from a `none` verdict"
            );
        }

        #[test]
        fn category_list_also_carries_auth() {
            let (s, folder) = store_with_message(3);
            s.set_auth(folder, 3, &stamp("fail", "pass")).unwrap();
            let msgs = s
                .list_messages_by_category(folder, Category::Primary, 10)
                .unwrap();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].auth.as_ref().unwrap().dkim, "fail");
        }

        #[test]
        fn uids_without_auth_lists_only_unstamped_bodies() {
            let (s, folder) = store_with_message(1);
            s.upsert_message(folder, &meta(2), 0).unwrap();
            s.set_auth(folder, 1, &stamp("pass", "pass")).unwrap();
            let pending = s.uids_without_auth(folder).unwrap();
            assert!(!pending.contains(&1), "stamped rows drop out");
        }

        #[test]
        fn v7_to_v10_migration_preserves_auth_without_fabricated_backfill() {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(DDL).unwrap();
            conn.execute_batch(
                "CREATE TABLE message_auth_v7 (
                    folder_id INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    spf TEXT NOT NULL DEFAULT 'none',
                    dkim TEXT NOT NULL DEFAULT 'none',
                    dmarc TEXT NOT NULL DEFAULT 'none',
                    dmarc_policy TEXT NOT NULL DEFAULT 'none',
                    dkim_domain TEXT,
                    key_query TEXT,
                    dmarc_record TEXT,
                    header_value TEXT,
                    evidence_json TEXT,
                    PRIMARY KEY (folder_id, uid)
                 );
                 INSERT INTO message_auth_v7 VALUES
                    (1, 7, 'none', 'pass', 'pass', 'none', NULL, NULL, NULL, 'kiwi; dkim=pass', NULL);
                 DROP TABLE message_auth;
                 ALTER TABLE message_auth_v7 RENAME TO message_auth;
                 PRAGMA user_version = 7;",
            )
            .unwrap();
            let root =
                std::env::temp_dir().join(format!("kiwi-mig-auth-v8-{}", std::process::id()));
            migrate_conn(&conn, &root).unwrap();
            let v: u32 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, SCHEMA_VERSION);
            let upstream: Option<String> = conn
                .query_row(
                    "SELECT upstream_json FROM message_auth WHERE folder_id = 1 AND uid = 7",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(upstream.is_none(), "old rows are not backfilled");
            let auth_risk: Option<String> = conn
                .query_row(
                    "SELECT auth_risk FROM message_auth WHERE folder_id = 1 AND uid = 7",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(auth_risk.is_none(), "missing alignment is not fabricated");
        }
    }

    #[test]
    fn migrate_v5_to_v6_adds_rules_table() {
        // Simulate a v5 database: current schema minus the rules table.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(DDL).unwrap();
        conn.execute_batch("DROP TABLE rules; PRAGMA user_version = 5")
            .unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-mig-rules-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'rules'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn local_folder_crud_validates_ownership_and_fails_closed() {
        let s = MailStore::open_memory().unwrap();
        seed_account(&s, "a1");
        seed_account(&s, "a2");
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        let remote = s.ensure_folder("a1", "Projects/Remote").unwrap();
        assert_eq!(
            s.folder_meta(inbox).unwrap().unwrap().origin,
            FolderOrigin::System
        );
        assert_eq!(
            s.folder_meta(remote).unwrap().unwrap().origin,
            FolderOrigin::Remote
        );

        let parent = s.create_local_folder("a1", None, "Local").unwrap();
        assert_eq!(parent.origin, FolderOrigin::Local);
        let child = s
            .create_local_folder("a1", Some(parent.id), "Child")
            .unwrap();
        assert_eq!(child.parent_id, Some(parent.id));
        for bad in ["", "  ", ".", "..", "a/b", "a\\b", "Trash"] {
            assert!(s.create_local_folder("a1", None, bad).is_err(), "{bad:?}");
        }
        assert!(
            s.create_local_folder("a1", Some(parent.id), "cHiLd")
                .is_err()
        );
        assert!(
            s.create_local_folder("a2", Some(parent.id), "Other")
                .is_err()
        );
        assert!(
            s.create_local_folder("a1", Some(inbox), "System child")
                .is_err()
        );
        assert_eq!(
            s.rename_local_folder(child.id, "Renamed").unwrap().name,
            "Renamed"
        );
        assert!(s.rename_local_folder(child.id, "Trash").is_err());
        assert!(s.rename_local_folder(remote, "Nope").is_err());
        assert!(s.rename_local_folder(inbox, "Nope").is_err());
        assert!(s.delete_local_folder(parent.id).is_err());
        s.upsert_message(child.id, &meta(1), 0).unwrap();
        assert!(s.delete_local_folder(child.id).is_err());
        assert!(s.delete_local_folder(inbox).is_err());
        assert!(s.delete_local_folder(remote).is_err());
        s.delete_messages(child.id, &[1]).unwrap();
        assert!(s.delete_local_folder(child.id).unwrap());
        assert!(s.delete_local_folder(parent.id).unwrap());
    }

    #[test]
    fn v16_to_v17_preserves_folders_and_classifies_origins() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE accounts (account_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                                    email TEXT NOT NULL, config_json TEXT NOT NULL);
             CREATE TABLE folders (id INTEGER PRIMARY KEY,
                                   account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                                   name TEXT NOT NULL, uid_validity INTEGER, uid_next INTEGER,
                                   highest_uid INTEGER NOT NULL DEFAULT 0, UNIQUE(account_id, name));
             CREATE TABLE messages (id INTEGER PRIMARY KEY,
                                    folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                                    uid INTEGER NOT NULL, message_id TEXT, subject TEXT, from_addr TEXT,
                                    to_addrs TEXT, date_unix INTEGER, size INTEGER, flags TEXT NOT NULL DEFAULT '',
                                    has_attachments INTEGER NOT NULL DEFAULT 0, snippet TEXT, body_path TEXT,
                                    fetched_at INTEGER NOT NULL, UNIQUE(folder_id, uid));
             INSERT INTO accounts VALUES ('a1', 'A', 'a@x.test', '{}');
             INSERT INTO folders (account_id, name) VALUES ('a1','INBOX'),('a1','Archive'),('a1','Project');
             PRAGMA user_version = 16;",
        ).unwrap();
        let root = std::env::temp_dir().join(format!("kiwi-folder-v17-{}", std::process::id()));
        migrate_conn(&conn, &root).unwrap();
        let rows: Vec<(String, String)> = conn
            .prepare("SELECT name, origin FROM folders ORDER BY name")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![
                ("Archive".into(), "system".into()),
                ("INBOX".into(), "system".into()),
                ("Project".into(), "remote".into()),
            ]
        );
    }
}
