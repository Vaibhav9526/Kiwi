//! Storage diagnostics (T-330) Ã¢â‚¬â€ measured facts about the local mail store.
//!
//! Everything in [`StorageStats`] is read from the live store or from real
//! file metadata. Nothing is estimated, rounded up to a plausible number, or
//! remembered from an earlier call:
//!
//! - `db_bytes` is the length of the `mail.db` **file** (`fs::metadata`). It
//!   is deliberately *not* `page_count * page_size`: that product describes a
//!   fully allocated database, so it over-reports a mostly-free one and would
//!   be an estimate wearing a number's clothes. `None` when there is no file
//!   to measure (the in-memory test store) Ã¢â‚¬â€ absence, never a fake `0`.
//! - `message_count` / `folder_count` are `SELECT COUNT(*)`.
//! - `schema_version` is `PRAGMA user_version` Ã¢â‚¬â€ the migration source of
//!   truth Ã¢â‚¬â€ not the compiled-in constant.
//! - `integrity_check` is the first `PRAGMA integrity_check` row verbatim:
//!   `"ok"`, or SQLite's own error text. A pragma that cannot be run is
//!   reported as such, never laundered into `"ok"`.
//! - `attachment_bytes` sums the real file lengths under `attachments/`, and
//!   is `None` when that tree is absent or unreadable. It counts *persisted
//!   decoded payloads only*: body bytes still inside a stored `.eml` are not
//!   included, because no per-part size is persisted and counting them would
//!   mean re-parsing every body - a measurement this module does not perform.
//!
//! The audit trail is intentionally **absent** here: `audit.jsonl` is a
//! hash-chained JSONL file owned by kiwi-app, not a SQL table, so the store
//! cannot count it. The IPC layer adds `audit_count` from the real audit
//! store (see `commands::storage`).

use std::path::Path;

use rusqlite::Connection;

use super::MailStore;
use crate::error::Result;

/// Cap on the reported `integrity_check` text. SQLite can return a long
/// multi-error report; a diagnostics row must stay a single bounded line, so
/// the tail is dropped and the truncation is stated rather than hidden.
const MAX_INTEGRITY_TEXT: usize = 200;

/// One measured snapshot of local mail storage (T-330).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageStats {
    /// Real on-disk length of `mail.db`, or `None` when there is no file.
    pub db_bytes: Option<u64>,
    pub message_count: u64,
    pub folder_count: u64,
    /// Real sum of persisted decoded-attachment payload bytes, or `None` when
    /// the `attachments/` tree could not be measured.
    pub attachment_bytes: Option<u64>,
    /// `PRAGMA user_version` of the open database.
    pub schema_version: u32,
    /// `"ok"`, or SQLite's own `integrity_check` error text.
    pub integrity_check: String,
}

/// What one `VACUUM` actually did (T-330). Both sizes are real file
/// measurements taken immediately before and after the rebuild, so `None` on
/// either side means "not measurable" (no file), never "did not change".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactReport {
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
}

impl MailStore {
    /// Real length of the `mail.db` file, or `None` when it cannot be read
    /// (in-memory store, or the file vanished).
    pub fn db_bytes(&self) -> Option<u64> {
        file_len(&self.root.join("mail.db"))
    }

    /// Measure the store: counts, file size, schema version, integrity.
    ///
    /// Read-only Ã¢â‚¬â€ it opens no write transaction and mutates no row.
    pub fn storage_stats(&self) -> Result<StorageStats> {
        Ok(StorageStats {
            db_bytes: self.db_bytes(),
            message_count: self.count("SELECT COUNT(*) FROM messages")?,
            folder_count: self.count("SELECT COUNT(*) FROM folders")?,
            attachment_bytes: tree_bytes(&self.root.join("attachments")),
            schema_version: self
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))?,
            integrity_check: integrity_of(&self.conn),
        })
    }

    /// Rebuild the database file with `VACUUM`, returning the real file size
    /// measured before and after.
    ///
    /// **Caller contract (T-330):** hold the store mutex across this whole
    /// call. `MailStore` owns a single write connection and has no lock of its
    /// own, so the caller is what serializes VACUUM against every other
    /// writer. `VACUUM` rewrites the entire file and cannot run inside a
    /// transaction, so a concurrent statement on that connection would fail
    /// or corrupt the rebuild Ã¢â‚¬â€ the app layer takes `state.store` for the
    /// entire duration.
    pub fn compact(&self) -> Result<CompactReport> {
        let before_bytes = self.db_bytes();
        self.conn.execute_batch("VACUUM;")?;
        Ok(CompactReport {
            before_bytes,
            after_bytes: self.db_bytes(),
        })
    }

    fn count(&self, sql: &str) -> Result<u64> {
        let n: i64 = self.conn.query_row(sql, [], |r| r.get(0))?;
        // COUNT(*) is never negative; the clamp only keeps a hostile cast
        // from wrapping into a 4-billion-row claim.
        Ok(n.max(0) as u64)
    }
}

/// Real file length, or `None` when the file is missing/unreadable.
fn file_len(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// Sum the real lengths of every regular file under `dir`.
///
/// `None` when the tree is absent or any entry cannot be read: an incomplete
/// walk must not be reported as a smaller total. Symlinks and other non-file
/// entries are skipped rather than followed Ã¢â‚¬â€ a link could leave the store
/// root or loop.
fn tree_bytes(dir: &Path) -> Option<u64> {
    if !dir.is_dir() {
        return None;
    }
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = std::fs::read_dir(&current).ok()?;
        for entry in entries {
            let entry = entry.ok()?;
            // `file_type` does not follow symlinks.
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                total = total.saturating_add(entry.metadata().ok()?.len());
            }
        }
    }
    Some(total)
}

/// `PRAGMA integrity_check` as one honest line.
///
/// Healthy Ã¢â€ â€™ `"ok"`. Corrupt Ã¢â€ â€™ SQLite's own text. Pragma unusable (the file
/// is not a database, the statement is refused) Ã¢â€ â€™ that error, prefixed. This
/// function never returns `"ok"` for anything it did not actually read.
pub(crate) fn integrity_of(conn: &Connection) -> String {
    let mut stmt = match conn.prepare("PRAGMA integrity_check") {
        Ok(stmt) => stmt,
        Err(e) => return bounded(&format!("unavailable: {e}")),
    };
    let mut rows = match stmt.query_map([], |r| r.get::<_, String>(0)) {
        Ok(rows) => rows,
        Err(e) => return bounded(&format!("unavailable: {e}")),
    };
    match rows.next() {
        Some(Ok(text)) => bounded(&text),
        Some(Err(e)) => bounded(&format!("unavailable: {e}")),
        // The pragma ran and produced nothing: a real, uninterpretable fact.
        None => "unavailable: integrity_check returned no row".to_string(),
    }
}

/// Keep the integrity line bounded, and say so when it is cut.
fn bounded(text: &str) -> String {
    if text.chars().count() <= MAX_INTEGRITY_TEXT {
        return text.to_string();
    }
    let head: String = text.chars().take(MAX_INTEGRITY_TEXT).collect();
    format!("{head}... (truncated)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use crate::category::Category;
    use crate::store::NewMessageMeta;
    use crate::transport::SocketSecurity;

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-diag-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn account() -> MailAccount {
        MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: "a@x.test".into(),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: "a@x.test".into(),
            },
        }
    }

    fn meta(uid: u64) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some("a@x".into()),
            to_addrs: Some("b@y".into()),
            date_unix: Some(1_758_000_000),
            size: Some(1234),
            flags: vec![],
            has_attachments: false,
            snippet: Some("hi".into()),
            category: Category::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    #[test]
    fn stats_are_measured_not_estimated() {
        let root = temp_root("stats");
        let store = MailStore::open(&root).unwrap();
        store.upsert_account(&account()).unwrap();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        store.ensure_folder("a1", "Archive").unwrap();
        for uid in 1..=3 {
            store.upsert_message(inbox, &meta(uid), 1).unwrap();
        }

        let stats = store.storage_stats().unwrap();
        assert_eq!(stats.message_count, 3);
        assert_eq!(stats.folder_count, 2);
        assert_eq!(stats.schema_version, super::super::schema::SCHEMA_VERSION);
        assert_eq!(stats.integrity_check, "ok");
        // A real file size for a file-backed store: the actual file length,
        // not a page_count * page_size estimate.
        let bytes = stats.db_bytes.expect("file-backed store has a file");
        assert!(bytes > 0);
        assert_eq!(
            stats.db_bytes,
            std::fs::metadata(root.join("mail.db"))
                .ok()
                .map(|m| m.len())
        );
        // Nothing persisted to attachments/ yet: measured, so an honest 0.
        assert_eq!(stats.attachment_bytes, Some(0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn in_memory_store_reports_no_file_size() {
        let store = MailStore::open_memory().unwrap();
        let stats = store.storage_stats().unwrap();
        // No mail.db behind an in-memory store: say so rather than
        // inventing 0 bytes.
        assert_eq!(stats.db_bytes, None);
        assert_eq!(stats.message_count, 0);
        assert_eq!(stats.folder_count, 0);
        assert_eq!(stats.integrity_check, "ok");
    }

    #[test]
    fn attachment_bytes_sum_real_persisted_payloads() {
        let root = temp_root("attach");
        let store = MailStore::open(&root).unwrap();
        store.upsert_account(&account()).unwrap();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        store.upsert_message(inbox, &meta(1), 1).unwrap();

        store.store_attachment(inbox, 1, 0, &[7u8; 100]).unwrap();
        store.store_attachment(inbox, 1, 1, &[9u8; 250]).unwrap();
        assert_eq!(store.storage_stats().unwrap().attachment_bytes, Some(350));

        // A tree that cannot be walked is an honest null, not a small number.
        std::fs::remove_dir_all(root.join("attachments")).unwrap();
        assert_eq!(store.storage_stats().unwrap().attachment_bytes, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compact_reports_real_before_and_after_and_keeps_rows() {
        let root = temp_root("compact");
        let store = MailStore::open(&root).unwrap();
        store.upsert_account(&account()).unwrap();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        for uid in 1..=200 {
            store.upsert_message(inbox, &meta(uid), 1).unwrap();
        }
        // Free a lot of pages so VACUUM has something to reclaim.
        let doomed: Vec<u64> = (1..=180).collect();
        store.delete_messages(inbox, &doomed).unwrap();
        let before = store.db_bytes().unwrap();

        let report = store.compact().unwrap();
        assert_eq!(report.before_bytes, Some(before));
        let after = report
            .after_bytes
            .expect("file-backed store measures after");
        // VACUUM rewrites the file into a compact form: with 180 rows freed
        // it must have given pages back.
        assert!(after < before, "after={after} before={before}");

        // Data survived the rebuild and the file is still sound.
        let stats = store.storage_stats().unwrap();
        assert_eq!(stats.message_count, 20);
        assert_eq!(stats.integrity_check, "ok");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn integrity_of_never_claims_ok_for_a_damaged_file() {
        let root = temp_root("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("broken.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t(x);").unwrap();
        }
        // Overwrite the header so the file is no longer a database at all.
        std::fs::write(&path, b"not a sqlite database at all").unwrap();
        let conn = Connection::open(&path).unwrap();
        let report = integrity_of(&conn);
        assert_ne!(report, "ok");
        assert!(!report.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn integrity_text_is_bounded_and_says_it_was_cut() {
        let long = "x".repeat(MAX_INTEGRITY_TEXT + 50);
        let out = bounded(&long);
        assert!(out.ends_with("(truncated)"));
        // A short report is passed through untouched.
        assert_eq!(bounded("ok"), "ok");
    }
}
