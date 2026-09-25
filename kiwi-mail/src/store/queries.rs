//! Typed queries — accounts, folders, message metadata, sync state,
//! bodies/attachments on disk, POP3 dedup. All SQL is parameterized
//! (SECURITY.md rule 9); row-level schema lives in `schema.rs`.

use std::path::PathBuf;

use mail_parser::{MessageParser, MimeHeaders};
use rusqlite::{OptionalExtension, params};

use crate::account::MailAccount;
use crate::category::Category;
use crate::error::{MailError, Result};
use crate::rules::{Rule, RuleSpec};
use crate::templates::{TEMPLATE_ID_PREFIX, Template};

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
        // Filled by the list callers from evidence sibling tables.
        auth: None,
        attach_risk: None,
        link_risk: None,
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
    /// folder's on-disk payloads — wiped UIDs must not leave orphan files —
    /// and its rule-eval watermarks: the uid epoch restarted, so a stale
    /// `stage` row would either skip evals the new message deserves or pin
    /// an old message's state onto its uid's successor.
    pub fn clear_folder_messages(&self, folder_id: i64) -> Result<u64> {
        let n = self.conn.execute(
            "DELETE FROM messages WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM rule_evals WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM message_attachment_risk WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM message_link_risk WHERE folder_id = ?1",
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

    /// The stored unsubscribe offer for one message, or `None` when the
    /// `(folder_id, uid)` row does not exist. A row with no advertised
    /// endpoints returns `UnsubscribeInfo` with all fields empty — the
    /// caller distinguishes "no message" from "no offer" on `Option`.
    pub fn unsubscribe_offer(
        &self,
        folder_id: i64,
        uid: u64,
    ) -> Result<Option<crate::unsub::UnsubscribeInfo>> {
        let row = self
            .conn
            .query_row(
                "SELECT unsub_http, unsub_mailto, unsub_oneclick
                 FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, uid as i64],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(
            row.map(|(http_url, mailto, oc)| crate::unsub::UnsubscribeInfo {
                http_url,
                mailto,
                one_click: oc != 0,
            }),
        )
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
               AND NOT EXISTS (SELECT 1 FROM snoozed s
                               WHERE s.folder_id = messages.folder_id
                                 AND s.uid = messages.uid)
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
        self.attach_auth(folder_id, &mut out)?;
        self.attach_attachment_risks(folder_id, &mut out)?;
        self.attach_link_risks(folder_id, &mut out)?;
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
        self.set_flag(folder_id, uids, JUNK_FLAG, junk)
    }

    /// Merge-set one flag on stored messages — unlike `update_flags`
    /// (which replaces the flag set from server state), this adds or
    /// removes a single flag and reports how many rows actually changed.
    /// Bulk-ready: absent UIDs are skipped, already-correct rows are not
    /// counted. Local-only — the caller performs the live `UID STORE
    /// ±FLAGS` for IMAP. Used by the rules engine (`\Seen`/`\Flagged`,
    /// T-233) and the junk toggle (T-212 delegates above).
    pub fn set_flag(&self, folder_id: i64, uids: &[u64], flag: &str, on: bool) -> Result<u64> {
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
            let has = flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
            if on && !has {
                flags.push(flag.to_string());
            } else if !on && has {
                flags.retain(|f| !f.eq_ignore_ascii_case(flag));
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

    /// Per-folder message counts (T-264): `exists` = total rows, `unseen` =
    /// rows without a `\Seen` token. One indexed `COUNT` per call; the flags
    /// column is space-separated, so the padded-token `LIKE` is exact
    /// (SQLite LIKE is ASCII case-insensitive — matching IMAP flag
    /// semantics — and `\Seen` contains no wildcards). Snoozed rows count:
    /// parking hides from the list view, not from the store's truth.
    pub fn folder_stats(&self, folder_id: i64) -> Result<FolderStats> {
        self.conn
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN ' ' || flags || ' ' NOT LIKE '% \\Seen %'
                                          THEN 1 ELSE 0 END), 0)
                 FROM messages WHERE folder_id = ?1",
                params![folder_id],
                |r| {
                    Ok(FolderStats {
                        exists: r.get::<_, i64>(0)? as u64,
                        unseen: r.get::<_, i64>(1)? as u64,
                    })
                },
            )
            .map_err(Into::into)
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
            self.conn.execute(
                "DELETE FROM message_attachment_risk WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64],
            )?;
            self.conn.execute(
                "DELETE FROM message_link_risk WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64],
            )?;
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
                "INSERT OR REPLACE INTO message_attachment_risk
                    (folder_id, uid, risk, reasons_json)
                 SELECT ?1, ?2, risk, reasons_json
                 FROM message_attachment_risk WHERE folder_id = ?3 AND uid = ?4",
                params![dst_folder_id, dst_uid, src_folder_id, *uid as i64],
            )?;
            self.conn.execute(
                "INSERT OR REPLACE INTO message_link_risk
                    (folder_id, uid, risk, reasons_json)
                 SELECT ?1, ?2, risk, reasons_json
                 FROM message_link_risk WHERE folder_id = ?3 AND uid = ?4",
                params![dst_folder_id, dst_uid, src_folder_id, *uid as i64],
            )?;
            // Carry the snooze state across the move (T-255) — parked mail
            // stays parked at its new coordinates. Must run BEFORE the
            // source-row DELETE below: the composite FK would otherwise
            // cascade-drop the parking record.
            self.conn.execute(
                "UPDATE snoozed SET folder_id = ?1, uid = ?2
                 WHERE folder_id = ?3 AND uid = ?4",
                params![dst_folder_id, dst_uid, src_folder_id, *uid as i64],
            )?;
            self.conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![src_folder_id, *uid as i64],
            )?;
            self.conn.execute(
                "DELETE FROM message_attachment_risk WHERE folder_id = ?1 AND uid = ?2",
                params![src_folder_id, *uid as i64],
            )?;
            self.conn.execute(
                "DELETE FROM message_link_risk WHERE folder_id = ?1 AND uid = ?2",
                params![src_folder_id, *uid as i64],
            )?;
            moved.push((*uid, dst_uid as u64));
        }
        Ok(moved)
    }

    /// Persist (or refresh) a message's Authentication-Results verdicts
    /// (T-232). Called from the ingest paths once the raw body — and thus the
    /// DKIM body hash and full header set — is available. Idempotent via
    /// `INSERT OR REPLACE`, so a re-fetch refreshes rather than duplicates.
    pub fn set_auth(
        &self,
        folder_id: i64,
        uid: u64,
        stamp: &crate::authstamp::AuthStamp,
    ) -> Result<bool> {
        let evidence = serde_json::json!({
            "spf": stamp.spf_explanation,
            "dkim": stamp.dkim_explanation,
            "dmarc": stamp.dmarc_explanation,
        });
        let upstream_json = serde_json::to_string(&stamp.upstream)
            .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        let n = self.conn.execute(
            "INSERT OR REPLACE INTO message_auth
                (folder_id, uid, spf, dkim, dmarc, dmarc_policy, dkim_domain,
                 key_query, dmarc_record, header_value, evidence_json, upstream_json,
                 auth_risk)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                folder_id,
                uid as i64,
                stamp.spf,
                stamp.dkim,
                stamp.dmarc,
                stamp.dmarc_policy,
                stamp.dkim_domain,
                stamp.dkim_key_query,
                stamp.dmarc_record,
                stamp.header_value,
                evidence.to_string(),
                upstream_json,
                stamp.auth_risk.as_str(),
            ],
        )?;
        Ok(n > 0)
    }

    /// Read one message's persisted verdicts, if any.
    pub fn get_auth(&self, folder_id: i64, uid: u64) -> Result<Option<AuthMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT spf, dkim, dmarc, dmarc_policy, dkim_domain, key_query,
                    dmarc_record, header_value, evidence_json, upstream_json, auth_risk
             FROM message_auth WHERE folder_id = ?1 AND uid = ?2",
        )?;
        let mut rows = stmt.query(params![folder_id, uid as i64])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let evidence: Option<String> = row.get(8)?;
        let spf: String = row.get(0)?;
        let dkim: String = row.get(1)?;
        let dmarc: String = row.get(2)?;
        let upstream: UpstreamAuthEvidence = row
            .get::<_, Option<String>>(9)?
            .and_then(|e| serde_json::from_str(&e).ok())
            .unwrap_or_default();
        // Legacy v9 rows have no stored hint. Derive conservatively without
        // inventing SPF alignment; missing alignment can only avoid `failed`.
        let auth_risk = row
            .get::<_, Option<String>>(10)?
            .map(|v| AuthRisk::from_wire(&v))
            .unwrap_or_else(|| {
                crate::authrisk::derive_auth_risk(
                    &spf,
                    &dkim,
                    &dmarc,
                    false,
                    upstream.present && !upstream.authserv_ids.is_empty(),
                    upstream.untrusted_relay,
                    upstream.has_discrepancy(),
                )
            });
        Ok(Some(AuthMeta {
            spf,
            dkim,
            dmarc,
            dmarc_policy: row.get(3)?,
            dkim_domain: row.get(4)?,
            key_query: row.get(5)?,
            dmarc_record: row.get(6)?,
            header_value: row.get(7)?,
            evidence: evidence.and_then(|e| serde_json::from_str(&e).ok()),
            upstream,
            auth_risk,
        }))
    }

    /// Bulk-read verdicts for a folder and attach them to the message rows.
    ///
    /// Kept out of the `messages` SELECTs on purpose: that query text is
    /// shared with the unsub/junk and rules owners, and a single extra
    /// `SELECT … FROM message_auth` per list keeps their columns untouched.
    /// A message with no row keeps `auth: None` ("not evaluated yet").
    fn attach_auth(&self, folder_id: i64, msgs: &mut [MessageMeta]) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare(
            "SELECT uid, spf, dkim, dmarc, dmarc_policy, dkim_domain, key_query,
                    dmarc_record, header_value, evidence_json, upstream_json, auth_risk
             FROM message_auth WHERE folder_id = ?1",
        )?;
        let rows = stmt.query_map(params![folder_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                AuthMeta {
                    spf: r.get(1)?,
                    dkim: r.get(2)?,
                    dmarc: r.get(3)?,
                    dmarc_policy: r.get(4)?,
                    dkim_domain: r.get(5)?,
                    key_query: r.get(6)?,
                    dmarc_record: r.get(7)?,
                    header_value: r.get(8)?,
                    evidence: r
                        .get::<_, Option<String>>(9)?
                        .and_then(|e| serde_json::from_str(&e).ok()),
                    upstream: r
                        .get::<_, Option<String>>(10)?
                        .and_then(|e| serde_json::from_str(&e).ok())
                        .unwrap_or_default(),
                    auth_risk: r
                        .get::<_, Option<String>>(11)?
                        .map(|v| AuthRisk::from_wire(&v))
                        .unwrap_or(AuthRisk::Noted),
                },
            ))
        })?;
        for r in rows {
            let (uid, meta) = r?;
            let uid = uid as u64;
            if let Some(m) = msgs.iter_mut().find(|m| m.uid == uid) {
                m.auth = Some(meta);
            }
        }
        Ok(())
    }

    /// Persist bounded attachment-risk evidence parsed from the received MIME
    /// body. This is independent of optional DNS auth sealing and has no
    /// blocking or mail-movement side effects.
    pub fn set_attachment_risk(
        &self,
        folder_id: i64,
        uid: u64,
        evidence: &crate::attachrisk::AttachRiskEvidence,
    ) -> Result<bool> {
        let reasons = serde_json::to_string(&evidence.reasons)
            .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        let n = self.conn.execute(
            "INSERT OR REPLACE INTO message_attachment_risk
                (folder_id, uid, risk, reasons_json) VALUES (?1, ?2, ?3, ?4)",
            params![folder_id, uid as i64, evidence.risk.as_str(), reasons],
        )?;
        Ok(n > 0)
    }

    /// True when the exact folder-scoped message row exists.
    pub fn message_exists(&self, folder_id: i64, uid: u64) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE folder_id = ?1 AND uid = ?2)",
                params![folder_id, uid as i64],
                |row| row.get::<_, i64>(0),
            )
            .map(|exists| exists != 0)?)
    }

    /// Read persisted attachment evidence for one message.
    pub fn get_attachment_risk(
        &self,
        folder_id: i64,
        uid: u64,
    ) -> Result<Option<crate::attachrisk::AttachRiskEvidence>> {
        let mut stmt = self.conn.prepare(
            "SELECT risk, reasons_json FROM message_attachment_risk
             WHERE folder_id = ?1 AND uid = ?2",
        )?;
        let mut rows = stmt.query(params![folder_id, uid as i64])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let risk: String = row.get(0)?;
        let reasons_json: String = row.get(1)?;
        let reasons = serde_json::from_str(&reasons_json).unwrap_or_default();
        Ok(Some(crate::attachrisk::AttachRiskEvidence {
            risk: crate::attachrisk::AttachRisk::from_wire(&risk),
            reasons,
        }))
    }

    fn attach_attachment_risks(&self, folder_id: i64, msgs: &mut [MessageMeta]) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare(
            "SELECT uid, risk, reasons_json FROM message_attachment_risk
             WHERE folder_id = ?1",
        )?;
        let rows = stmt.query_map(params![folder_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (uid, risk, reasons_json) = row?;
            let Some(message) = msgs.iter_mut().find(|m| m.uid == uid as u64) else {
                continue;
            };
            message.attach_risk = Some(crate::attachrisk::AttachRiskEvidence {
                risk: crate::attachrisk::AttachRisk::from_wire(&risk),
                reasons: serde_json::from_str(&reasons_json).unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Persist bounded link-risk evidence parsed from received MIME bodies.
    /// Independent of auth sealing; no resolve/open/block behavior exists here.
    pub fn set_link_risk(
        &self,
        folder_id: i64,
        uid: u64,
        evidence: &crate::linkrisk::LinkRiskEvidence,
    ) -> Result<bool> {
        let reasons = serde_json::to_string(&evidence.reasons)
            .map_err(|_| MailError::Store(rusqlite::Error::InvalidQuery))?;
        let n = self.conn.execute(
            "INSERT OR REPLACE INTO message_link_risk
                (folder_id, uid, risk, reasons_json) VALUES (?1, ?2, ?3, ?4)",
            params![folder_id, uid as i64, evidence.risk.as_str(), reasons],
        )?;
        Ok(n > 0)
    }

    pub fn get_link_risk(
        &self,
        folder_id: i64,
        uid: u64,
    ) -> Result<Option<crate::linkrisk::LinkRiskEvidence>> {
        let mut stmt = self.conn.prepare(
            "SELECT risk, reasons_json FROM message_link_risk
             WHERE folder_id = ?1 AND uid = ?2",
        )?;
        let mut rows = stmt.query(params![folder_id, uid as i64])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let risk: String = row.get(0)?;
        let reasons_json: String = row.get(1)?;
        Ok(Some(crate::linkrisk::LinkRiskEvidence {
            risk: crate::linkrisk::LinkRisk::from_wire(&risk),
            reasons: serde_json::from_str(&reasons_json).unwrap_or_default(),
        }))
    }

    fn attach_link_risks(&self, folder_id: i64, msgs: &mut [MessageMeta]) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare(
            "SELECT uid, risk, reasons_json FROM message_link_risk WHERE folder_id = ?1",
        )?;
        let rows = stmt.query_map(params![folder_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (uid, risk, reasons_json) = row?;
            let Some(message) = msgs.iter_mut().find(|m| m.uid == uid as u64) else {
                continue;
            };
            message.link_risk = Some(crate::linkrisk::LinkRiskEvidence {
                risk: crate::linkrisk::LinkRisk::from_wire(&risk),
                reasons: serde_json::from_str(&reasons_json).unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Messages eligible for Authentication-Results evaluation: those with a
    /// stored body but no stamp yet. Kept so a later re-evaluation pass can
    /// backfill without a full re-sync.
    pub fn uids_without_auth(&self, folder_id: i64) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.uid FROM messages m
             WHERE m.folder_id = ?1 AND m.body_path IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM message_auth a
                               WHERE a.folder_id = m.folder_id AND a.uid = m.uid)
             ORDER BY m.uid",
        )?;
        let rows = stmt.query_map(params![folder_id], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r? as u64);
        }
        Ok(out)
    }

    /// List messages with their Authentication-Results verdicts attached.
    pub fn list_messages(&self, folder_id: i64, limit: u32) -> Result<Vec<MessageMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, folder_id, uid, message_id, subject, from_addr,
                    to_addrs, date_unix, size, flags, has_attachments,
                    snippet, body_path, category,
                    unsub_http, unsub_mailto, unsub_oneclick
             FROM messages WHERE folder_id = ?1
               AND NOT EXISTS (SELECT 1 FROM snoozed s
                               WHERE s.folder_id = messages.folder_id
                                 AND s.uid = messages.uid)
             ORDER BY uid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![folder_id, limit as i64], map_message_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        self.attach_auth(folder_id, &mut out)?;
        self.attach_attachment_risks(folder_id, &mut out)?;
        self.attach_link_risks(folder_id, &mut out)?;
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

    /// Resolve one stored attachment by its MIME filename into a private
    /// sandbox-staging path. The caller supplies a reference only; raw bytes
    /// never cross IPC.
    pub fn stage_attachment(
        &self,
        folder_id: i64,
        uid: u64,
        filename: &str,
        max_bytes: usize,
    ) -> Result<(PathBuf, String)> {
        let body_path = self
            .body_file(folder_id, uid)?
            .ok_or_else(|| MailError::InvalidInput("message body not stored".into()))?;
        let raw = std::fs::read(body_path)?;
        let message = MessageParser::default().parse(&raw).ok_or_else(|| {
            crate::error::MailError::Protocol {
                protocol: "mime",
                detail: "stored body failed MIME parse".into(),
            }
        })?;
        let mut matches = message
            .attachments()
            .filter(|a| a.attachment_name().is_some_and(|stored| stored == filename));
        let attachment = matches.next().ok_or_else(|| {
            crate::error::MailError::InvalidInput("stored attachment not found".into())
        })?;
        if matches.next().is_some() {
            return Err(crate::error::MailError::InvalidInput(
                "attachment filename is ambiguous".into(),
            ));
        }
        if attachment.contents().len() > max_bytes {
            return Err(crate::error::MailError::InvalidInput(
                "attachment exceeds sandbox size bound".into(),
            ));
        }
        let content_type = attachment
            .content_type()
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("")))
            .unwrap_or_else(|| "application/octet-stream".into());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = self
            .root
            .join("sandbox-staging")
            .join(format!("{}-{nonce}-{uid}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("artifact.bin");
        std::fs::write(&path, attachment.contents())?;
        Ok((path, content_type))
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
    /// the account's own, with persisted health diagnostics. Rows with
    /// undecodable specs are skipped so one corrupt row cannot disable the
    /// whole ruleset.
    pub fn list_rule_records(&self, account_id: Option<&str>) -> Result<Vec<RuleRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, account_id, name, enabled, position, is_block, spec_json,
                    failure_count, last_error, last_failure_unix
             FROM rules
             WHERE account_id IS NULL OR account_id = ?1
             ORDER BY position, rule_id",
        )?;
        let rows = stmt.query_map(params![account_id], map_rule_record_row)?;
        let mut out = Vec::new();
        for r in rows {
            if let Some(record) = r? {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Rules in scope for `account_id`: global rows (NULL account_id) plus
    /// the account's own, in deterministic storage order (`position`, then
    /// `rule_id` — the evaluator applies block precedence on top).
    /// `None` lists global rules only — binding NULL makes
    /// `account_id = ?1` never true, so one statement serves both shapes.
    pub fn list_rules(&self, account_id: Option<&str>) -> Result<Vec<Rule>> {
        Ok(self
            .list_rule_records(account_id)?
            .into_iter()
            .map(|record| record.rule)
            .collect())
    }

    /// One rule by id. A corrupt spec surfaces as an error here — an
    /// explicit fetch should never silently drop the row.
    pub fn get_rule(&self, rule_id: &str) -> Result<Option<Rule>> {
        Ok(self.get_rule_record(rule_id)?.map(|record| record.rule))
    }

    /// One rule plus its store-owned application health.
    pub fn get_rule_record(&self, rule_id: &str) -> Result<Option<RuleRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, account_id, name, enabled, position, is_block, spec_json,
                    failure_count, last_error, last_failure_unix
             FROM rules WHERE rule_id = ?1",
        )?;
        let mut rows = stmt.query(params![rule_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(
                map_rule_record_row(r)?.ok_or(MailError::Store(rusqlite::Error::InvalidQuery))?,
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

    /// Increment each matching rule's cumulative failure count and replace
    /// its bounded last-error diagnostic. This is deliberately not cleared on
    /// success: the count is historical health, while `last_error` identifies
    /// the most recent incident. Duplicate ids in one call count once.
    pub fn record_rule_failures(&self, rule_ids: &[String], error: &str, now: i64) -> Result<()> {
        let mut bounded = error.trim().replace(['\r', '\n'], " ");
        if bounded.len() > 512 {
            bounded.truncate(512);
            while !bounded.is_char_boundary(bounded.len()) {
                bounded.pop();
            }
        }
        let mut stmt = self.conn.prepare(
            "UPDATE rules SET failure_count = failure_count + 1,
                    last_error = ?2, last_failure_unix = ?3
             WHERE rule_id = ?1",
        )?;
        let mut seen = std::collections::BTreeSet::new();
        for id in rule_ids {
            if seen.insert(id) {
                stmt.execute(params![id, bounded, now])?;
            }
        }
        Ok(())
    }

    /// Record which rules fired on a stored message — the F1 audit trail
    /// (T-233). `INSERT OR REPLACE`: re-evaluating the same rule on the
    /// same row refreshes `applied_unix` instead of duplicating. Caller
    /// passes the eval coordinates (pre-move) and the RFC822 message-id.
    pub fn record_rule_hits(
        &self,
        folder_id: i64,
        uid: u64,
        rule_ids: &[String],
        message_id: Option<&str>,
        now: i64,
    ) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO rule_hits
               (folder_id, uid, rule_id, message_id, applied_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for rule_id in rule_ids {
            stmt.execute(params![folder_id, uid as i64, rule_id, message_id, now])?;
        }
        Ok(())
    }

    /// Newest-first rule-hit audit for an account (joined through
    /// folders), bounded. Powers the transparency surface — the user can
    /// always ask "which rules touched this mailbox".
    pub fn list_rule_hits(&self, account_id: &str, limit: u32) -> Result<Vec<RuleHit>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.folder_id, h.uid, h.rule_id, h.message_id, h.applied_unix
             FROM rule_hits h
             JOIN folders f ON f.id = h.folder_id
             WHERE f.account_id = ?1
             ORDER BY h.applied_unix DESC, h.rule_id, h.folder_id, h.uid
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![account_id, limit as i64], |r| {
            Ok(RuleHit {
                folder_id: r.get(0)?,
                uid: r.get::<_, i64>(1)? as u64,
                rule_id: r.get(2)?,
                message_id: r.get(3)?,
                applied_unix: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Mark that the rules engine evaluated the message at `(folder_id,
    /// uid)` to `stage` (0 = envelope facts, 1 = full parse — the
    /// `rule_evals.stage` contract). Callers write this only after a
    /// successful apply: a failed apply keeps the earlier stage, so the
    /// deferred pass retries it at the next sync instead of skipping.
    pub fn mark_rule_eval(&self, folder_id: i64, uid: u64, stage: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO rule_evals (folder_id, uid, stage, at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![folder_id, uid as i64, stage, now],
        )?;
        Ok(())
    }

    /// Messages in `folder_id` eligible for deferred full-parse eval: a
    /// body is stored but the deepest eval watermark is envelope-stage (or
    /// no row exists — e.g. mail moved into INBOX by the user, or rows
    /// predating the table). Bounded, uid order (oldest first).
    pub fn uids_pending_body_eval(&self, folder_id: i64, limit: u32) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.uid FROM messages m
             LEFT JOIN rule_evals re
               ON re.folder_id = m.folder_id AND re.uid = m.uid
             WHERE m.folder_id = ?1 AND m.body_path IS NOT NULL
               AND (re.stage IS NULL OR re.stage < 1)
             ORDER BY m.uid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![folder_id, limit as i64], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r? as u64);
        }
        Ok(out)
    }

    /// The account's newest stored messages (insertion order — "last N
    /// stored" per the preview contract), excluding the folder named
    /// `exclude` case-insensitively (callers pass the Trash name so the
    /// dry-run scope matches `rules::apply_now`).
    pub fn recent_for_preview(
        &self,
        account_id: &str,
        exclude: &str,
        limit: u32,
    ) -> Result<Vec<MessageRef>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.folder_id, m.uid, f.name, m.subject, m.message_id
             FROM messages m
             JOIN folders f ON f.id = m.folder_id
             WHERE f.account_id = ?1 AND LOWER(f.name) != LOWER(?2)
             ORDER BY m.id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![account_id, exclude, limit as i64], |r| {
            Ok(MessageRef {
                folder_id: r.get(0)?,
                uid: r.get::<_, i64>(1)? as u64,
                folder_name: r.get(2)?,
                subject: r.get(3)?,
                message_id: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -- snooze (T-255) -----------------------------------------------------

    /// Park `uids` in `folder_id` until `until_unix`. Purely reversible
    /// local state: the `messages` row never moves — folder listings hide
    /// parked rows — so snooze can't desync the server and never touches
    /// Trash. Absent uids are skipped (same convention as `set_flag`);
    /// re-snoozing an already-parked message updates the deadline but
    /// keeps the original `from_folder_id`. Returns rows parked.
    pub fn set_snooze(
        &self,
        folder_id: i64,
        uids: &[u64],
        until_unix: i64,
        now: i64,
    ) -> Result<u64> {
        let mut n = 0u64;
        for uid in uids {
            n += u64::from(
                self.conn.execute(
                    "INSERT INTO snoozed (folder_id, uid, until_unix, from_folder_id, set_at_unix)
                     SELECT ?1, ?2, ?3, ?1, ?4
                     WHERE EXISTS (SELECT 1 FROM messages
                                   WHERE folder_id = ?1 AND uid = ?2)
                     ON CONFLICT(folder_id, uid) DO UPDATE SET
                         until_unix = excluded.until_unix,
                         set_at_unix = excluded.set_at_unix",
                    params![folder_id, *uid as i64, until_unix, now],
                )? > 0,
            );
        }
        Ok(n)
    }

    /// Release parked messages explicitly (`kiwi_message_unsnooze` and
    /// the due-sweep share this shape). Idempotent — unparked uids are
    /// no-ops. Returns rows that were actually parked.
    pub fn clear_snooze(&self, folder_id: i64, uids: &[u64]) -> Result<u64> {
        let mut n = 0u64;
        for uid in uids {
            n += u64::from(
                self.conn.execute(
                    "DELETE FROM snoozed WHERE folder_id = ?1 AND uid = ?2",
                    params![folder_id, *uid as i64],
                )? > 0,
            );
        }
        Ok(n)
    }

    /// Due-snooze sweep: release up to `limit` parked rows whose deadline
    /// passed, soonest-due first, uid order for ties. Returns the
    /// released `(folder_id, uid)` coordinates so callers can log/count.
    /// Bounded per call — leftovers stay parked until the next pass.
    pub fn unsnooze_due(&self, account_id: &str, now: i64, limit: u32) -> Result<Vec<(i64, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.folder_id, s.uid FROM snoozed s
             JOIN folders f ON f.id = s.folder_id
             WHERE f.account_id = ?1 AND s.until_unix <= ?2
             ORDER BY s.until_unix, s.folder_id, s.uid
             LIMIT ?3",
        )?;
        let due: Vec<(i64, u64)> = stmt
            .query_map(params![account_id, now, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (fid, uid) in &due {
            self.conn.execute(
                "DELETE FROM snoozed WHERE folder_id = ?1 AND uid = ?2",
                params![fid, *uid as i64],
            )?;
        }
        Ok(due)
    }

    /// The account's parked mail for the Snoozed view — soonest-due
    /// first, then folder/uid for a total order. Every parked row is
    /// returned (including trash-parked ones); the IPC layer filters
    /// what the view should render.
    pub fn list_snoozed(&self, account_id: &str, limit: u32) -> Result<Vec<SnoozedMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.folder_id, s.uid, f.name, s.from_folder_id,
                    s.until_unix, s.set_at_unix,
                    m.subject, m.from_addr, m.message_id, m.date_unix
             FROM snoozed s
             JOIN folders f ON f.id = s.folder_id
             JOIN messages m
               ON m.folder_id = s.folder_id AND m.uid = s.uid
             WHERE f.account_id = ?1
             ORDER BY s.until_unix, s.folder_id, s.uid
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![account_id, limit as i64], |r| {
            Ok(SnoozedMessage {
                folder_id: r.get(0)?,
                uid: r.get::<_, i64>(1)? as u64,
                folder_name: r.get(2)?,
                from_folder_id: r.get(3)?,
                until_unix: r.get(4)?,
                set_at_unix: r.get(5)?,
                subject: r.get(6)?,
                from_addr: r.get(7)?,
                message_id: r.get(8)?,
                date_unix: r.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -- message templates (T-288) --------------------------------------------

    /// Insert a template, assigning `tpl-N` when `id` is empty. The
    /// `tpl-` prefix is reserved for store-assigned ids — a caller-
    /// supplied one is rejected so the sequence cannot be collided with.
    /// `validate()` runs at the boundary; timestamps are caller-passed.
    pub fn insert_template(&self, template: &Template, now: i64) -> Result<Template> {
        let mut t = template.clone();
        if t.id.is_empty() {
            t.id = self.next_template_id()?;
        } else if t.id.starts_with(TEMPLATE_ID_PREFIX) {
            return Err(MailError::InvalidInput(format!(
                "template rejected: id `{}` uses the reserved `{TEMPLATE_ID_PREFIX}` prefix",
                t.id
            )));
        }
        t.created_unix = now;
        t.updated_unix = now;
        t.validate()?;
        self.conn.execute(
            "INSERT INTO templates
               (template_id, name, subject, body_text, body_html, created_unix, updated_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                t.id,
                t.name,
                t.subject,
                t.body_text,
                t.body_html,
                t.created_unix,
                t.updated_unix
            ],
        )?;
        Ok(t)
    }

    /// Full replace by id — not a merge. `created_unix` is preserved from
    /// the stored row; `updated_unix` becomes `now`. `Err` when absent.
    pub fn update_template(&self, template: &Template, now: i64) -> Result<bool> {
        let mut t = template.clone();
        t.validate()?;
        let Some(existing) = self.get_template(&t.id)? else {
            return Ok(false);
        };
        t.created_unix = existing.created_unix;
        t.updated_unix = now;
        Ok(self.conn.execute(
            "UPDATE templates SET name = ?2, subject = ?3, body_text = ?4,
                    body_html = ?5, updated_unix = ?6
             WHERE template_id = ?1",
            params![
                t.id,
                t.name,
                t.subject,
                t.body_text,
                t.body_html,
                t.updated_unix
            ],
        )? > 0)
    }

    /// One template by id.
    pub fn get_template(&self, template_id: &str) -> Result<Option<Template>> {
        let mut stmt = self.conn.prepare(
            "SELECT template_id, name, subject, body_text, body_html, created_unix, updated_unix
             FROM templates WHERE template_id = ?1",
        )?;
        let mut rows = stmt.query(params![template_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(map_template_row(r)?)),
        }
    }

    /// All templates in deterministic order (name, then id).
    pub fn list_templates(&self) -> Result<Vec<Template>> {
        let mut stmt = self.conn.prepare(
            "SELECT template_id, name, subject, body_text, body_html, created_unix, updated_unix
             FROM templates ORDER BY name, template_id",
        )?;
        let rows = stmt.query_map([], map_template_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Remove a template; returns whether a row existed.
    pub fn delete_template(&self, template_id: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM templates WHERE template_id = ?1",
            params![template_id],
        )? > 0)
    }

    /// `tpl-N`, one past the current maximum — single-connection SQLite
    /// serializes writers, so MAX+1 cannot race.
    fn next_template_id(&self) -> Result<String> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(CAST(SUBSTR(template_id, ?1) AS INTEGER)), 0) + 1
             FROM templates WHERE template_id GLOB 'tpl-*'",
            params![TEMPLATE_ID_PREFIX.len() as i64 + 1],
            |r| r.get(0),
        )?;
        Ok(format!("{TEMPLATE_ID_PREFIX}{n}"))
    }
}

/// `templates` row → [`Template`]. Columns are plain text — no decode
/// failure mode, so unlike rules there is no skip path.
fn map_template_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Template> {
    Ok(Template {
        id: r.get(0)?,
        name: r.get(1)?,
        subject: r.get(2)?,
        body_text: r.get(3)?,
        body_html: r.get(4)?,
        created_unix: r.get(5)?,
        updated_unix: r.get(6)?,
    })
}

/// `rules` row → [`RuleRecord`]. `Ok(None)` = the spec JSON is undecodable;
/// list calls skip such rows, explicit get turns them into an error.
fn map_rule_record_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<RuleRecord>> {
    let spec_json: String = r.get(6)?;
    let Some(spec) = serde_json::from_str::<RuleSpec>(&spec_json).ok() else {
        return Ok(None);
    };
    Ok(Some(RuleRecord {
        rule: Rule {
            id: r.get(0)?,
            account_id: r.get(1)?,
            name: r.get(2)?,
            enabled: r.get::<_, i64>(3)? != 0,
            position: r.get(4)?,
            is_block: r.get::<_, i64>(5)? != 0,
            when: spec.when,
            then: spec.then,
        },
        failure_count: r.get::<_, i64>(7)?.max(0) as u64,
        last_error: r.get(8)?,
        last_failure_unix: r.get(9)?,
    }))
}
