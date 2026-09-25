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

use rusqlite::Connection;

use crate::category::Category;
use crate::error::Result;

use schema::{DDL, SCHEMA_VERSION};

mod outbox;
mod queries;
mod schema;

pub use outbox::OutboxRow;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderMeta {
    pub id: i64,
    pub account_id: String,
    pub name: String,
    pub uid_validity: Option<u64>,
    pub uid_next: Option<u64>,
    pub highest_uid: u64,
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
        }
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
            created_unix: 100,
        };
        store.outbox_put(&row).unwrap();
        let rows = store.outbox_list(10).unwrap();
        assert_eq!(rows, vec![row.clone()]);

        // retry backoff update
        assert!(store.outbox_set_timing("send-q1", 230, 1).unwrap());
        let rows = store.outbox_list(10).unwrap();
        assert_eq!(rows[0].not_before_unix, 230);
        assert_eq!(rows[0].attempts, 1);
        assert!(!store.outbox_set_timing("send-gone", 1, 1).unwrap());

        // limit bounds the read
        assert_eq!(store.outbox_list(0).unwrap().len(), 0);

        // terminal drop is idempotent
        assert!(store.outbox_delete("send-q1").unwrap());
        assert!(!store.outbox_delete("send-q1").unwrap());
        assert!(store.outbox_list(10).unwrap().is_empty());
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
        fn v7_to_v8_migration_preserves_local_auth_without_backfill() {
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
}
