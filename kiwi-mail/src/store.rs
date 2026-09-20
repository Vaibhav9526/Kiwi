//! Local mail storage: SQLite metadata + on-disk bodies/attachments.
//!
//! Layout (`root` = per-profile data dir):
//!   `mail.db`              — accounts, folders, message metadata, sync state,
//!                            outbox (persistent send queue, T-142)
//!   `bodies/<folder_id>/<uid>.eml` — raw RFC 5322 message bytes
//!   `attachments/<folder_id>/<uid>/<n>` — decoded attachment payloads
//!
//! All queries are parameterized (SECURITY.md rule 9). Schema version lives
//! in `PRAGMA user_version`; migrations are explicit and append-only.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::account::MailAccount;
use crate::error::{MailError, Result};

const SCHEMA_VERSION: u32 = 3;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email        TEXT NOT NULL,
    config_json  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS folders (
    id           INTEGER PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    uid_validity INTEGER,
    uid_next     INTEGER,
    highest_uid  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, name)
);
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY,
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder_id, uid);
CREATE TABLE IF NOT EXISTS pop3_seen (
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    uidl       TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, uidl)
);
-- Queued outbound sends (undo-send + send-later, T-142). The built MIME
-- lives in-row: one row is one committed send, so enqueue is a single
-- atomic write — no torn meta/body pair possible.
CREATE TABLE IF NOT EXISTS outbox (
    queue_id        TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    from_addr       TEXT NOT NULL,
    to_addrs        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    mime            BLOB NOT NULL,
    not_before_unix INTEGER NOT NULL,
    undo_until_unix INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_unix    INTEGER NOT NULL
);
"#;

/// Message metadata row — the query shape the UI/mail-flow emitter consumes.
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

/// One persisted queued send (T-142). `mime` is the fully built RFC 5322
/// message — kept in-row so a queued send is one atomic write. Callers
/// bound `mime` before insert (kiwi-app caps at 32 MiB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub queue_id: String,
    pub account_id: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub subject: String,
    /// MIME Message-ID — correlates mailflow events (admin-api §11).
    pub message_id: String,
    pub mime: Vec<u8>,
    /// Earliest dispatch time (send-later schedule / retry backoff).
    pub not_before_unix: i64,
    /// Undo-send cancel deadline. `0` = already committed.
    pub undo_window_until_unix: i64,
    pub attempts: u32,
    pub created_unix: i64,
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

    /// Crate-internal access to the connection — `search` runs FTS5
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

    /// In-memory store for tests. The payload dir is unique per call —
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
        let v: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v < SCHEMA_VERSION {
            self.conn.execute_batch(DDL)?;
            // FTS5 search index (T-159): created/backfilled idempotently on
            // every schema bump — an old DB reaches here with rows in
            // `messages` and no `messages_fts`, the backfill fills it once.
            crate::search::ensure_schema(&self.conn)?;
            self.conn
                .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }
        Ok(())
    }

    // -- accounts -----------------------------------------------------------

    pub fn upsert_account(&self, acct: &MailAccount) -> Result<()> {
        let config_json = serde_json::to_string(acct)
            .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        self.conn.execute(
            "INSERT INTO accounts (account_id, display_name, email, config_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
               display_name = excluded.display_name,
               email = excluded.email,
               config_json = excluded.config_json",
            params![acct.account_id, acct.display_name, acct.email, config_json],
        )?;
        Ok(())
    }

    pub fn get_account(&self, account_id: &str) -> Result<Option<MailAccount>> {
        let mut stmt = self
            .conn
            .prepare("SELECT config_json FROM accounts WHERE account_id = ?1")?;
        let mut rows = stmt.query(params![account_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let json: String = row.get(0)?;
                let acct = serde_json::from_str(&json)
                    .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
                Ok(Some(acct))
            }
        }
    }

    /// All stored accounts (enumeration for the app layer's account list).
    pub fn list_accounts(&self) -> Result<Vec<MailAccount>> {
        let mut stmt = self
            .conn
            .prepare("SELECT config_json FROM accounts ORDER BY account_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            let json = r?;
            out.push(
                serde_json::from_str(&json)
                    .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?,
            );
        }
        Ok(out)
    }

    /// Remove an account; folders/messages/pop3_seen/outbox rows cascade.
    /// On-disk bodies and attachments for its folders are removed too.
    pub fn delete_account(&self, account_id: &str) -> Result<bool> {
        let folder_ids = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM folders WHERE account_id = ?1")?;
            let rows = stmt.query_map(params![account_id], |r| r.get::<_, i64>(0))?;
            let mut ids = Vec::new();
            for r in rows {
                ids.push(r?);
            }
            ids
        };
        let n = self.conn.execute(
            "DELETE FROM accounts WHERE account_id = ?1",
            params![account_id],
        )?;
        for fid in folder_ids {
            self.remove_payload_dirs(fid);
        }
        // Outbox rows cascade at the row level; their MIME is in-row, so no
        // orphaned files remain to sweep.
        Ok(n > 0)
    }

    // -- folders ------------------------------------------------------------

    /// Insert-or-get a folder row; returns its id.
    pub fn ensure_folder(&self, account_id: &str, name: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO folders (account_id, name) VALUES (?1, ?2)",
            params![account_id, name],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM folders WHERE account_id = ?1 AND name = ?2",
            params![account_id, name],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// All folders for an account, name order (trash discovery, folder
    /// pickers).
    pub fn list_folders(&self, account_id: &str) -> Result<Vec<FolderMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, name, uid_validity, uid_next, highest_uid
             FROM folders WHERE account_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![account_id], |r| {
            Ok(FolderMeta {
                id: r.get(0)?,
                account_id: r.get(1)?,
                name: r.get(2)?,
                uid_validity: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                uid_next: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                highest_uid: r.get::<_, i64>(5)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn folder_meta(&self, folder_id: i64) -> Result<Option<FolderMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, name, uid_validity, uid_next, highest_uid
             FROM folders WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![folder_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(FolderMeta {
                id: r.get(0)?,
                account_id: r.get(1)?,
                name: r.get(2)?,
                uid_validity: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                uid_next: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                highest_uid: r.get::<_, i64>(5)? as u64,
            })),
        }
    }

    /// Record the server's folder state after a SELECT/STATUS.
    pub fn set_folder_sync_state(
        &self,
        folder_id: i64,
        uid_validity: Option<u64>,
        uid_next: Option<u64>,
        highest_uid: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE folders SET uid_validity = ?2, uid_next = ?3,
             highest_uid = MAX(highest_uid, ?4) WHERE id = ?1",
            params![
                folder_id,
                uid_validity.map(|v| v as i64),
                uid_next.map(|v| v as i64),
                highest_uid as i64
            ],
        )?;
        Ok(())
    }

    /// UIDVALIDITY changed → all local UIDs are meaningless. Also drops the
    /// folder's on-disk payloads — wiped UIDs must not leave orphan files.
    pub fn clear_folder_messages(&self, folder_id: i64) -> Result<u64> {
        let n = self.conn.execute(
            "DELETE FROM messages WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.remove_payload_dirs(folder_id);
        Ok(n as u64)
    }

    /// Best-effort removal of a folder's on-disk payloads (bodies +
    /// attachments). Missing dirs are fine; errors are ignored — the DB row
    /// is already gone and leftover files get swept on next open.
    fn remove_payload_dirs(&self, folder_id: i64) {
        let _ = std::fs::remove_dir_all(self.root.join("bodies").join(folder_id.to_string()));
        let _ = std::fs::remove_dir_all(self.root.join("attachments").join(folder_id.to_string()));
    }

    // -- messages -----------------------------------------------------------

    pub fn upsert_message(&self, folder_id: i64, meta: &NewMessageMeta, now: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO messages
               (folder_id, uid, message_id, subject, from_addr, to_addrs,
                date_unix, size, flags, has_attachments, snippet, fetched_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(folder_id, uid) DO UPDATE SET
               flags = excluded.flags,
               has_attachments = excluded.has_attachments",
            params![
                folder_id,
                meta.uid as i64,
                meta.message_id,
                meta.subject,
                meta.from_addr,
                meta.to_addrs,
                meta.date_unix,
                meta.size.map(|v| v as i64),
                meta.flags.join(" "),
                meta.has_attachments as i64,
                meta.snippet,
                now,
            ],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, meta.uid as i64],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// Update only flags (used by incremental UID FETCH (FLAGS) sync).
    pub fn update_flags(&self, folder_id: i64, uid: u64, flags: &[String]) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET flags = ?3 WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64, flags.join(" ")],
        )?;
        Ok(n > 0)
    }

    /// All locally-known UIDs for a folder (expunge detection).
    pub fn folder_uids(&self, folder_id: i64) -> Result<Vec<u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uid FROM messages WHERE folder_id = ?1")?;
        let rows = stmt.query_map(params![folder_id], |r| r.get::<_, i64>(0))?;
        let mut uids = Vec::new();
        for r in rows {
            uids.push(r? as u64);
        }
        Ok(uids)
    }

    /// UIDs still missing a fetched body.
    pub fn uids_without_body(&self, folder_id: i64) -> Result<Vec<u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uid FROM messages WHERE folder_id = ?1 AND body_path IS NULL")?;
        let rows = stmt.query_map(params![folder_id], |r| r.get::<_, i64>(0))?;
        let mut uids = Vec::new();
        for r in rows {
            uids.push(r? as u64);
        }
        Ok(uids)
    }

    /// Delete message rows + their on-disk payloads (expunges).
    pub fn delete_messages(&self, folder_id: i64, uids: &[u64]) -> Result<u64> {
        let mut n = 0u64;
        for uid in uids {
            n += self.conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64],
            )? as u64;
            let _ = std::fs::remove_file(self.body_path(folder_id, *uid));
            let _ = std::fs::remove_dir_all(
                self.root
                    .join("attachments")
                    .join(folder_id.to_string())
                    .join(uid.to_string()),
            );
        }
        Ok(n)
    }

    /// Move messages between folders of the SAME account. Each row is
    /// re-inserted under a fresh destination UID (mirroring UID COPY
    /// semantics — new UIDs, never reused), the body file + attachment dir
    /// move on disk, then the source row is deleted. Order is crash-safe:
    /// the destination copy lands before the source is removed, so a
    /// mid-move crash leaves a duplicate (the next sync reconciles), never
    /// a loss. Returns `(src_uid → dst_uid)` pairs.
    pub fn move_messages(
        &self,
        src_folder_id: i64,
        dst_folder_id: i64,
        uids: &[u64],
    ) -> Result<Vec<(u64, u64)>> {
        let mut next: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(uid), 0) FROM messages WHERE folder_id = ?1",
            params![dst_folder_id],
            |r| r.get(0),
        )?;
        let mut moved = Vec::new();
        for uid in uids {
            let row = self
                .conn
                .query_row(
                    "SELECT message_id, subject, from_addr, to_addrs, date_unix,
                            size, flags, has_attachments, snippet, body_path,
                            fetched_at
                     FROM messages WHERE folder_id = ?1 AND uid = ?2",
                    params![src_folder_id, *uid as i64],
                    |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<i64>>(4)?,
                            r.get::<_, Option<i64>>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, i64>(7)?,
                            r.get::<_, Option<String>>(8)?,
                            r.get::<_, Option<String>>(9)?,
                            r.get::<_, i64>(10)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                message_id,
                subject,
                from_addr,
                to_addrs,
                date_unix,
                size,
                flags,
                has_attachments,
                snippet,
                body_path,
                fetched_at,
            )) = row
            else {
                continue; // uid absent in src — skip, not an error
            };
            next += 1;
            let dst_uid = next;
            self.conn.execute(
                "INSERT INTO messages
                   (folder_id, uid, message_id, subject, from_addr, to_addrs,
                    date_unix, size, flags, has_attachments, snippet,
                    body_path, fetched_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12)",
                params![
                    dst_folder_id,
                    dst_uid,
                    message_id,
                    subject,
                    from_addr,
                    to_addrs,
                    date_unix,
                    size,
                    flags,
                    has_attachments,
                    snippet,
                    fetched_at,
                ],
            )?;
            // Relocate the body payload, then repoint body_path at it.
            if body_path.is_some() {
                let src_abs = self.body_path(src_folder_id, *uid);
                let dst_abs = self.body_path(dst_folder_id, dst_uid as u64);
                if let Some(parent) = dst_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if src_abs.exists() {
                    std::fs::rename(&src_abs, &dst_abs)?;
                }
                if dst_abs.exists() {
                    let rel = dst_abs
                        .strip_prefix(&self.root)
                        .unwrap_or(&dst_abs)
                        .to_string_lossy()
                        .into_owned();
                    self.conn.execute(
                        "UPDATE messages SET body_path = ?3
                         WHERE folder_id = ?1 AND uid = ?2",
                        params![dst_folder_id, dst_uid, rel],
                    )?;
                }
            }
            // Relocate the attachment payload dir.
            let src_att = self
                .root
                .join("attachments")
                .join(src_folder_id.to_string())
                .join(uid.to_string());
            if src_att.exists() {
                let dst_att = self
                    .root
                    .join("attachments")
                    .join(dst_folder_id.to_string())
                    .join(dst_uid.to_string());
                if let Some(parent) = dst_att.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(&src_att, &dst_att)?;
            }
            self.conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![src_folder_id, *uid as i64],
            )?;
            moved.push((*uid, dst_uid as u64));
        }
        Ok(moved)
    }

    pub fn list_messages(&self, folder_id: i64, limit: u32) -> Result<Vec<MessageMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, folder_id, uid, message_id, subject, from_addr,
                    to_addrs, date_unix, size, flags, has_attachments,
                    snippet, body_path
             FROM messages WHERE folder_id = ?1 ORDER BY uid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![folder_id, limit as i64], |r| {
            Ok(MessageMeta {
                id: r.get(0)?,
                folder_id: r.get::<_, i64>(1)?,
                uid: r.get::<_, i64>(2)? as u64,
                message_id: r.get(3)?,
                subject: r.get(4)?,
                from_addr: r.get(5)?,
                to_addrs: r.get(6)?,
                date_unix: r.get(7)?,
                size: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                flags: r
                    .get::<_, String>(9)?
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
                has_attachments: r.get::<_, i64>(10)? != 0,
                snippet: r.get(11)?,
                body_path: r.get(12)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Bounded full-text search over the FTS5 index (`search` module).
    /// Public typed wrapper — the IPC layer calls this, never raw SQL.
    pub fn search(
        &self,
        query: &str,
        folder_id: Option<i64>,
        limit: u32,
    ) -> Result<Vec<MessageMeta>> {
        crate::search::search_messages(self, query, folder_id, limit)
    }

    // -- bodies & attachments (on disk, bounded by callers) -----------------

    fn body_path(&self, folder_id: i64, uid: u64) -> PathBuf {
        self.root
            .join("bodies")
            .join(folder_id.to_string())
            .join(format!("{uid}.eml"))
    }

    /// Store raw message bytes; records `body_path` on the row.
    pub fn store_body(&self, folder_id: i64, uid: u64, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.body_path(folder_id, uid);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename so readers never see a partial file.
        let tmp = path.with_extension("eml.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        let rel = path
            .strip_prefix(&self.root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        self.conn.execute(
            "UPDATE messages SET body_path = ?3 WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64, rel],
        )?;
        Ok(path)
    }

    /// Absolute path of a stored body, if present.
    pub fn body_file(&self, folder_id: i64, uid: u64) -> Result<Option<PathBuf>> {
        let rel: Option<String> = self
            .conn
            .query_row(
                "SELECT body_path FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, uid as i64],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        Ok(rel.map(|r| self.root.join(r)))
    }

    /// Store a decoded attachment payload.
    pub fn store_attachment(
        &self,
        folder_id: i64,
        uid: u64,
        index: u32,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        let dir = self
            .root
            .join("attachments")
            .join(folder_id.to_string())
            .join(uid.to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(index.to_string());
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    // -- outbox (queued sends — undo-send + send-later, T-142) ---------------

    /// Persist a queued send. `INSERT OR REPLACE` keeps enqueue idempotent
    /// across the legacy-file import path. Caller bounds `mime`.
    pub fn outbox_put(&self, row: &OutboxRow) -> Result<()> {
        let to_json = serde_json::to_string(&row.to_addrs)
            .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO outbox
               (queue_id, account_id, from_addr, to_addrs, subject,
                message_id, mime, not_before_unix, undo_until_unix,
                attempts, created_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                row.queue_id,
                row.account_id,
                row.from_addr,
                to_json,
                row.subject,
                row.message_id,
                row.mime,
                row.not_before_unix,
                row.undo_window_until_unix,
                row.attempts as i64,
                row.created_unix,
            ],
        )?;
        Ok(())
    }

    /// All persisted queued sends, oldest first, bounded by `limit`.
    /// Rows with undecodable recipient lists are skipped — a corrupt row
    /// must not brick outbox reload.
    pub fn outbox_list(&self, limit: u32) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT queue_id, account_id, from_addr, to_addrs, subject,
                    message_id, mime, not_before_unix, undo_until_unix,
                    attempts, created_unix
             FROM outbox ORDER BY created_unix, queue_id LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)? as u32,
                r.get::<_, i64>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                queue_id,
                account_id,
                from_addr,
                to_json,
                subject,
                message_id,
                mime,
                not_before_unix,
                undo_window_until_unix,
                attempts,
                created_unix,
            ) = row?;
            let Ok(to_addrs) = serde_json::from_str::<Vec<String>>(&to_json) else {
                continue;
            };
            out.push(OutboxRow {
                queue_id,
                account_id,
                from_addr,
                to_addrs,
                subject,
                message_id,
                mime,
                not_before_unix,
                undo_window_until_unix,
                attempts,
                created_unix,
            });
        }
        Ok(out)
    }

    /// Update dispatch timing + attempt count (retry backoff, send-later
    /// reschedule). Returns false when the row is gone.
    pub fn outbox_set_timing(
        &self,
        queue_id: &str,
        not_before_unix: i64,
        attempts: u32,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE outbox SET not_before_unix = ?2, attempts = ?3
             WHERE queue_id = ?1",
            params![queue_id, not_before_unix, attempts as i64],
        )?;
        Ok(n > 0)
    }

    /// Queued sends eligible for dispatch at `now` (`not_before` reached),
    /// earliest-scheduled first. Used by the send-later scheduler after a
    /// reload: rows only exist while queued, so `now` is the whole filter.
    pub fn outbox_due(&self, now: i64, limit: u32) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT queue_id, account_id, from_addr, to_addrs, subject,
                    message_id, mime, not_before_unix, undo_until_unix,
                    attempts, created_unix
             FROM outbox WHERE not_before_unix <= ?1
             ORDER BY not_before_unix, queue_id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)? as u32,
                r.get::<_, i64>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                queue_id,
                account_id,
                from_addr,
                to_json,
                subject,
                message_id,
                mime,
                not_before_unix,
                undo_window_until_unix,
                attempts,
                created_unix,
            ) = row?;
            let Ok(to_addrs) = serde_json::from_str::<Vec<String>>(&to_json) else {
                continue;
            };
            out.push(OutboxRow {
                queue_id,
                account_id,
                from_addr,
                to_addrs,
                subject,
                message_id,
                mime,
                not_before_unix,
                undo_window_until_unix,
                attempts,
                created_unix,
            });
        }
        Ok(out)
    }

    /// Earliest `not_before` among queued sends — the scheduler's wake-up
    /// time. `None` when the outbox is empty.
    pub fn outbox_next_due_at(&self) -> Result<Option<i64>> {
        self.conn
            .query_row("SELECT MIN(not_before_unix) FROM outbox", [], |r| r.get(0))
            .map_err(Into::into)
    }

    /// Drop a queued send — every terminal outcome (sent, failed,
    /// cancelled, blocked). Idempotent.
    pub fn outbox_delete(&self, queue_id: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM outbox WHERE queue_id = ?1", params![queue_id])?;
        Ok(n > 0)
    }

    // -- POP3 dedup ----------------------------------------------------------

    pub fn pop3_seen_contains(&self, account_id: &str, uidl: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pop3_seen WHERE account_id = ?1 AND uidl = ?2",
            params![account_id, uidl],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn pop3_mark_seen(&self, account_id: &str, uidl: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pop3_seen (account_id, uidl, seen_at) VALUES (?1, ?2, ?3)",
            params![account_id, uidl, now],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Fresh UIDs in dst (max was 9): 101→10, 102→11. Absent uid skipped.
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
}
