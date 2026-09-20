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

use rusqlite::Connection;

use crate::error::Result;

use schema::{DDL, SCHEMA_VERSION};

mod outbox;
mod queries;
mod schema;

pub use outbox::OutboxRow;

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
