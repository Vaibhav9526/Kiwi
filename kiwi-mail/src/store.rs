//! Local mail storage: SQLite metadata + on-disk bodies/attachments.
//!
//! Layout (`root` = per-profile data dir):
//!   `mail.db`              — accounts, folders, message metadata, sync state
//!   `bodies/<folder_id>/<uid>.eml` — raw RFC 5322 message bytes
//!   `attachments/<folder_id>/<uid>/<n>` — decoded attachment payloads
//!
//! All queries are parameterized (SECURITY.md rule 9). Schema version lives
//! in `PRAGMA user_version`; migrations are explicit and append-only.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::account::MailAccount;
use crate::error::{MailError, Result};

const SCHEMA_VERSION: u32 = 1;

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

    /// In-memory store for tests.
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn,
            root: std::env::temp_dir().join(format!("kiwi-mail-test-{}", std::process::id())),
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

    /// UIDVALIDITY changed → all local UIDs are meaningless.
    pub fn clear_folder_messages(&self, folder_id: i64) -> Result<u64> {
        let n = self.conn.execute(
            "DELETE FROM messages WHERE folder_id = ?1",
            params![folder_id],
        )?;
        Ok(n as u64)
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
        let mut stmt = self.conn.prepare(
            "SELECT uid FROM messages WHERE folder_id = ?1 AND body_path IS NULL",
        )?;
        let rows = stmt.query_map(params![folder_id], |r| r.get::<_, i64>(0))?;
        let mut uids = Vec::new();
        for r in rows {
            uids.push(r? as u64);
        }
        Ok(uids)
    }

    pub fn delete_messages(&self, folder_id: i64, uids: &[u64]) -> Result<u64> {
        let mut n = 0u64;
        for uid in uids {
            n += self.conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64],
            )? as u64;
        }
        Ok(n)
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
        store.set_folder_sync_state(fid, Some(777), Some(1004), 1003).unwrap();
        let fm = store.folder_meta(fid).unwrap().unwrap();
        assert_eq!(fm.uid_validity, Some(777));

        store.upsert_message(fid, &meta(1001), 100).unwrap();
        store.upsert_message(fid, &meta(1002), 100).unwrap();
        let msgs = store.list_messages(fid, 50).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].uid, 1001);
        assert_eq!(msgs[0].flags, vec!["\\Seen"]);

        assert!(store.update_flags(fid, 1001, &["\\Flagged".to_string()]).unwrap());
        let msgs = store.list_messages(fid, 50).unwrap();
        assert_eq!(msgs[0].flags, vec!["\\Flagged"]);

        // body storage
        let path = store.store_body(fid, 1001, b"Subject: x\r\n\r\nbody").unwrap();
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
