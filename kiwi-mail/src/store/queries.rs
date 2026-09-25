//! Typed queries — accounts, folders, message metadata, sync state,
//! bodies/attachments on disk, POP3 dedup. All SQL is parameterized
//! (SECURITY.md rule 9); row-level schema lives in `schema.rs`.

use std::path::PathBuf;

use rusqlite::{OptionalExtension, params};

use crate::account::MailAccount;
use crate::category::Category;
use crate::error::{MailError, Result};
use crate::rules::{Rule, RuleSpec};

use super::*;

/// Shared `messages` row → [`MessageMeta`] mapping (list + category filter).
/// Unknown `category` slugs fall back to Primary so a future tab never
/// breaks old reads.
fn map_message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageMeta> {
    let slug: String = r.get(13)?;
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
        category: Category::from_slug(&slug).unwrap_or_default(),
        unsub_http: r.get(14)?,
        unsub_mailto: r.get(15)?,
        unsub_oneclick: r.get::<_, i64>(16)? != 0,
    })
}

impl MailStore {
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
                date_unix, size, flags, has_attachments, snippet, fetched_at,
                category, unsub_http, unsub_mailto, unsub_oneclick)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
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
                meta.category.as_str(),
                meta.unsub_http,
                meta.unsub_mailto,
                meta.unsub_oneclick as i64,
            ],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, meta.uid as i64],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// Refine a row's tab once full headers arrive (IMAP body fetch) or a
    /// re-classification runs. Deliberately separate from `upsert_message`:
    /// re-upserts must not clobber a refined category with an envelope-only
    /// default, so the conflict clause above leaves `category` (and the
    /// unsubscribe columns below) untouched.
    pub fn set_category(&self, folder_id: i64, uid: u64, category: Category) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET category = ?3 WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64, category.as_str()],
        )?;
        Ok(n > 0)
    }

    /// Refine a row's unsubscribe offer once full headers arrive. Same
    /// split reason as `set_category`: the offer is unknown at metadata
    /// time and must survive later re-upserts.
    pub fn set_unsubscribe(
        &self,
        folder_id: i64,
        uid: u64,
        info: &crate::unsub::UnsubscribeInfo,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET unsub_http = ?3, unsub_mailto = ?4,
             unsub_oneclick = ?5 WHERE folder_id = ?1 AND uid = ?2",
            params![
                folder_id,
                uid as i64,
                info.http_url,
                info.mailto,
                info.one_click as i64,
            ],
        )?;
        Ok(n > 0)
    }

    /// Messages of one tab in a folder, uid order, bounded (powers the F2 UI tabs).
    pub fn list_messages_by_category(
        &self,
        folder_id: i64,
        category: Category,
        limit: u32,
    ) -> Result<Vec<MessageMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, folder_id, uid, message_id, subject, from_addr,
                    to_addrs, date_unix, size, flags, has_attachments,
                    snippet, body_path, category,
                    unsub_http, unsub_mailto, unsub_oneclick
             FROM messages WHERE folder_id = ?1 AND category = ?2
             ORDER BY uid LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![folder_id, category.as_str(), limit as i64],
            map_message_row,
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Update only flags (used by incremental UID FETCH (FLAGS) sync).
    pub fn update_flags(&self, folder_id: i64, uid: u64, flags: &[String]) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET flags = ?3 WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64, flags.join(" ")],
        )?;
        Ok(n > 0)
    }

    /// Mark messages as junk: adds the canonical [`JUNK_FLAG`] to each row's
    /// flag set (F13). Bulk-ready: pass any number of UIDs; absent UIDs are
    /// skipped and already-junk rows are left untouched. Returns the number
    /// of rows actually changed. Local-only — the caller performs the live
    /// `UID STORE +FLAGS (\Junk)` for IMAP (same split as `update_flags`).
    pub fn mark_junk(&self, folder_id: i64, uids: &[u64]) -> Result<u64> {
        self.set_junk(folder_id, uids, true)
    }

    /// Clear the junk mark: removes [`JUNK_FLAG`] (any case) from each row.
    /// Same bulk/absent/idempotent semantics as [`mark_junk`]; the caller
    /// performs the live `UID STORE -FLAGS (\Junk)` for IMAP.
    pub fn unmark_junk(&self, folder_id: i64, uids: &[u64]) -> Result<u64> {
        self.set_junk(folder_id, uids, false)
    }

    fn set_junk(&self, folder_id: i64, uids: &[u64], junk: bool) -> Result<u64> {
        let mut changed = 0u64;
        for uid in uids {
            let current: Option<String> = self
                .conn
                .query_row(
                    "SELECT flags FROM messages WHERE folder_id = ?1 AND uid = ?2",
                    params![folder_id, *uid as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(current) = current else {
                continue; // uid absent — skip, not an error
            };
            let mut flags: Vec<String> = current.split_whitespace().map(str::to_string).collect();
            let has = flags.iter().any(|f| f.eq_ignore_ascii_case(JUNK_FLAG));
            if junk && !has {
                flags.push(JUNK_FLAG.to_string());
            } else if !junk && has {
                flags.retain(|f| !f.eq_ignore_ascii_case(JUNK_FLAG));
            } else {
                continue; // already in the desired state — not counted
            }
            let n = self.conn.execute(
                "UPDATE messages SET flags = ?3 WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64, flags.join(" ")],
            )?;
            changed += u64::from(n > 0);
        }
        Ok(changed)
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
                            fetched_at, category,
                            unsub_http, unsub_mailto, unsub_oneclick
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
                            r.get::<_, String>(11)?,
                            r.get::<_, Option<String>>(12)?,
                            r.get::<_, Option<String>>(13)?,
                            r.get::<_, i64>(14)?,
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
                category,
                unsub_http,
                unsub_mailto,
                unsub_oneclick,
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
                    body_path, fetched_at, category,
                    unsub_http, unsub_mailto, unsub_oneclick)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13,?14,?15,?16)",
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
                    category,
                    unsub_http,
                    unsub_mailto,
                    unsub_oneclick,
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
                    snippet, body_path, category,
                    unsub_http, unsub_mailto, unsub_oneclick
             FROM messages WHERE folder_id = ?1 ORDER BY uid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![folder_id, limit as i64], map_message_row)?;
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

    // -- inbox rules (F1 deterministic engine, T-228) -------------------------

    /// Insert or replace a rule. `Rule::validate` gates the write —
    /// the renderer is untrusted, so bounds are enforced at the store
    /// boundary too, not only by well-behaved callers.
    pub fn upsert_rule(&self, rule: &Rule) -> Result<()> {
        rule.validate()?;
        let spec = serde_json::to_string(&RuleSpec {
            when: rule.when.clone(),
            then: rule.then.clone(),
        })
        .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        self.conn.execute(
            "INSERT INTO rules
               (rule_id, account_id, name, enabled, position, is_block, spec_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(rule_id) DO UPDATE SET
               account_id = excluded.account_id,
               name       = excluded.name,
               enabled    = excluded.enabled,
               position   = excluded.position,
               is_block   = excluded.is_block,
               spec_json  = excluded.spec_json",
            params![
                rule.id,
                rule.account_id,
                rule.name,
                rule.enabled as i64,
                rule.position,
                rule.is_block as i64,
                spec
            ],
        )?;
        Ok(())
    }

    /// Rules in scope for `account_id`: global rows (NULL account_id) plus
    /// the account's own, in deterministic storage order (`position`, then
    /// `rule_id` — the evaluator applies block precedence on top).
    /// `None` lists global rules only — binding NULL makes
    /// `account_id = ?1` never true, so one statement serves both shapes.
    /// Rows with undecodable specs are skipped: one corrupt row must not
    /// disable the whole rule set.
    pub fn list_rules(&self, account_id: Option<&str>) -> Result<Vec<Rule>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, account_id, name, enabled, position, is_block, spec_json
             FROM rules
             WHERE account_id IS NULL OR account_id = ?1
             ORDER BY position, rule_id",
        )?;
        let rows = stmt.query_map(params![account_id], map_rule_row)?;
        let mut out = Vec::new();
        for r in rows {
            if let Some(rule) = r? {
                out.push(rule);
            }
        }
        Ok(out)
    }

    /// One rule by id. A corrupt spec surfaces as an error here — an
    /// explicit fetch should never silently drop the row.
    pub fn get_rule(&self, rule_id: &str) -> Result<Option<Rule>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, account_id, name, enabled, position, is_block, spec_json
             FROM rules WHERE rule_id = ?1",
        )?;
        let mut rows = stmt.query(params![rule_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(
                map_rule_row(r)?.ok_or(MailError::Store(rusqlite::Error::InvalidQuery))?,
            )),
        }
    }

    /// Remove a rule; returns whether a row existed (idempotent for the
    /// UI's delete-and-forget flow).
    pub fn delete_rule(&self, rule_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM rules WHERE rule_id = ?1", params![rule_id])?
            > 0)
    }
}

/// `rules` row → [`Rule`]. `Ok(None)` = the spec JSON is undecodable;
/// `list_rules` skips such rows, `get_rule` turns them into an error.
fn map_rule_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Rule>> {
    let spec_json: String = r.get(6)?;
    let Some(spec) = serde_json::from_str::<RuleSpec>(&spec_json).ok() else {
        return Ok(None);
    };
    Ok(Some(Rule {
        id: r.get(0)?,
        account_id: r.get(1)?,
        name: r.get(2)?,
        enabled: r.get::<_, i64>(3)? != 0,
        position: r.get(4)?,
        is_block: r.get::<_, i64>(5)? != 0,
        when: spec.when,
        then: spec.then,
    }))
}
