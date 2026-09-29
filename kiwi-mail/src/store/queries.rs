//! Typed queries — accounts, folders, message metadata, sync state,
//! bodies/attachments on disk, POP3 dedup. All SQL is parameterized
//! (SECURITY.md rule 9); row-level schema lives in `schema.rs`.

use std::path::{Path, PathBuf};

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

/// Shared `folders` row → [`FolderMeta`] mapping.
fn map_folder_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<FolderMeta> {
    let origin: String = r.get(4)?;
    let parent_id: Option<i64> = r.get(2)?;
    Ok(FolderMeta {
        id: r.get(0)?,
        account_id: r.get(1)?,
        parent_id,
        name: r.get(3)?,
        origin: FolderOrigin::from_str(&origin).map_err(|_| rusqlite::Error::InvalidQuery)?,
        uid_validity: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        uid_next: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
        highest_uid: r.get::<_, i64>(7)? as u64,
    })
}

/// Recursive directory copy — `std::fs` has no dir copy. Attachment payload
/// dirs are shallow trees of extracted parts; every entry is copied
/// verbatim and the destination is created on demand.
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn validate_local_folder_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(MailError::InvalidInput("folder name is empty".into()));
    }
    if trimmed.len() > 255 {
        return Err(MailError::InvalidInput(
            "folder name exceeds 255 bytes".into(),
        ));
    }
    if trimmed.contains(['/', '\\']) || trimmed.chars().any(char::is_control) {
        return Err(MailError::InvalidInput(
            "folder name contains a path separator or control character".into(),
        ));
    }
    if is_system_folder_name(trimmed) {
        return Err(MailError::InvalidInput("folder name is reserved".into()));
    }
    Ok(trimmed.to_string())
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

    /// Insert-or-get a server/sync-owned folder row; returns its id.
    pub fn ensure_folder(&self, account_id: &str, name: &str) -> Result<i64> {
        let origin = if is_system_folder_name(name) {
            FolderOrigin::System
        } else {
            FolderOrigin::Remote
        };
        self.conn.execute(
            "INSERT OR IGNORE INTO folders (account_id, name, origin)
             VALUES (?1, ?2, ?3)",
            params![account_id, name, origin.as_str()],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM folders
             WHERE account_id = ?1 AND name = ?2 AND parent_id IS NULL
               AND origin <> 'local'",
            params![account_id, name],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// Insert-or-get a local folder used by imports or explicit user CRUD.
    pub fn ensure_local_folder(&self, account_id: &str, name: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO folders (account_id, name, origin)
             VALUES (?1, ?2, 'local')",
            params![account_id, name],
        )?;
        Ok(self.conn.query_row(
            "SELECT id FROM folders
             WHERE account_id = ?1 AND name = ?2 AND parent_id IS NULL
               AND origin = 'local'",
            params![account_id, name],
            |r| r.get(0),
        )?)
    }

    /// Resolve an import target (T-326): reuse the **local** folder of this
    /// name, create one when absent, refuse a remote/system row. Imported
    /// messages carry locally-minted uids with no server identity — in a
    /// synced folder the next reconcile treats the server as authoritative
    /// and would expunge them. The lookup is `COLLATE NOCASE` to mirror
    /// `idx_folders_sibling_name`: a case-variant of a synced name is the
    /// same folder and must refuse, not die on the unique index.
    pub fn ensure_target_folder(&self, account_id: &str, name: &str) -> Result<i64> {
        let row = self
            .conn
            .query_row(
                "SELECT id, origin FROM folders
                 WHERE account_id = ?1 AND name = ?2 COLLATE NOCASE
                   AND parent_id IS NULL",
                params![account_id, name],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        match row {
            // Fail closed: an unrecognized origin is not a proven-local row.
            Some((id, origin)) => match FolderOrigin::from_str(&origin) {
                Ok(FolderOrigin::Local) => Ok(id),
                _ => Err(MailError::PolicyRejected(format!(
                    "import target '{name}' is a synced folder — imports land in local folders only"
                ))),
            },
            None => self.ensure_local_folder(account_id, name),
        }
    }

    /// All folders for an account, name order (trash discovery, folder
    /// pickers).
    pub fn list_folders(&self, account_id: &str) -> Result<Vec<FolderMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, parent_id, name, origin, uid_validity,
                    uid_next, highest_uid
             FROM folders WHERE account_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![account_id], map_folder_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn folder_meta(&self, folder_id: i64) -> Result<Option<FolderMeta>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, account_id, parent_id, name, origin, uid_validity,
                        uid_next, highest_uid
                 FROM folders WHERE id = ?1",
                params![folder_id],
                map_folder_row,
            )
            .optional()?)
    }

    /// Create one empty local folder. The store owns the row; sync never
    /// receives or mirrors it. `parent_id = None` means a root local folder.
    pub fn create_local_folder(
        &self,
        account_id: &str,
        parent_id: Option<i64>,
        name: &str,
    ) -> Result<FolderMeta> {
        let name = validate_local_folder_name(name)?;
        if self.get_account(account_id)?.is_none() {
            return Err(MailError::InvalidInput("unknown account".into()));
        }
        if let Some(parent_id) = parent_id {
            let parent = self
                .folder_meta(parent_id)?
                .ok_or_else(|| MailError::InvalidInput("unknown parent folder".into()))?;
            if parent.account_id != account_id {
                return Err(MailError::InvalidInput(
                    "parent folder is on another account".into(),
                ));
            }
            if parent.origin != FolderOrigin::Local {
                return Err(MailError::InvalidInput("parent folder is not local".into()));
            }
        }
        let duplicate: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folders
             WHERE account_id = ?1 AND parent_id IS ?2 AND name = ?3 COLLATE NOCASE",
            params![account_id, parent_id, name],
            |r| r.get(0),
        )?;
        if duplicate > 0 {
            return Err(MailError::InvalidInput(
                "folder name already exists under this parent".into(),
            ));
        }
        self.conn.execute(
            "INSERT INTO folders (account_id, parent_id, name, origin)
             VALUES (?1, ?2, ?3, 'local')",
            params![account_id, parent_id, name],
        )?;
        let id = self.conn.last_insert_rowid();
        self.folder_meta(id)?
            .ok_or_else(|| MailError::Store(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Rename one local folder. Remote and system rows are immutable here.
    pub fn rename_local_folder(&self, folder_id: i64, new_name: &str) -> Result<FolderMeta> {
        let folder = self
            .folder_meta(folder_id)?
            .ok_or_else(|| MailError::InvalidInput("unknown folder".into()))?;
        if folder.origin != FolderOrigin::Local {
            return Err(MailError::PolicyRejected(
                "only local folders can be renamed".into(),
            ));
        }
        let new_name = validate_local_folder_name(new_name)?;
        let duplicate: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folders
             WHERE account_id = ?1 AND parent_id IS ?2 AND name = ?3 COLLATE NOCASE
               AND id <> ?4",
            params![folder.account_id, folder.parent_id, new_name, folder_id],
            |r| r.get(0),
        )?;
        if duplicate > 0 {
            return Err(MailError::InvalidInput(
                "folder name already exists under this parent".into(),
            ));
        }
        self.conn.execute(
            "UPDATE folders SET name = ?2 WHERE id = ?1",
            params![folder_id, new_name],
        )?;
        self.folder_meta(folder_id)?
            .ok_or_else(|| MailError::Store(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Delete an empty local leaf. Messages, child folders, system folders and
    /// remote folders all fail closed. UI smart views have no row/id at all.
    pub fn delete_local_folder(&self, folder_id: i64) -> Result<bool> {
        let folder = self
            .folder_meta(folder_id)?
            .ok_or_else(|| MailError::InvalidInput("unknown folder".into()))?;
        if folder.origin != FolderOrigin::Local {
            return Err(MailError::PolicyRejected(
                "only local folders can be deleted".into(),
            ));
        }
        let messages: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder_id = ?1",
            params![folder_id],
            |r| r.get(0),
        )?;
        let children: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folders WHERE parent_id = ?1",
            params![folder_id],
            |r| r.get(0),
        )?;
        if messages > 0 || children > 0 {
            return Err(MailError::PolicyRejected("folder is not empty".into()));
        }
        Ok(self
            .conn
            .execute("DELETE FROM folders WHERE id = ?1", params![folder_id])?
            > 0)
    }

    /// Rename a remote/system folder row after the server ACKed `RENAME`
    /// (T-328). Local rows refuse — they have their own validated path.
    /// Inferiors follow the server (RFC 3501 §6.3.5 renames them): every
    /// flat row named `old<sep>…` moves under `new<sep>…`. Returns every
    /// renamed meta (target first) so name caches can be refreshed.
    pub fn rename_remote_folder(
        &self,
        folder_id: i64,
        new_name: &str,
        sep: &str,
    ) -> Result<Vec<FolderMeta>> {
        let folder = self
            .folder_meta(folder_id)?
            .ok_or_else(|| MailError::InvalidInput("unknown folder".into()))?;
        if folder.origin == FolderOrigin::Local {
            return Err(MailError::PolicyRejected(
                "local folders are renamed through the local path".into(),
            ));
        }
        let duplicate: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folders
             WHERE account_id = ?1 AND parent_id IS NULL
               AND name = ?2 COLLATE NOCASE AND id <> ?3",
            params![folder.account_id, new_name, folder_id],
            |r| r.get(0),
        )?;
        if duplicate > 0 {
            return Err(MailError::InvalidInput("folder name already exists".into()));
        }
        let prefix = format!("{}{sep}", folder.name);
        let children: Vec<(i64, String)> = self
            .list_folders(&folder.account_id)?
            .into_iter()
            .filter(|f| f.name.starts_with(&prefix))
            .map(|f| (f.id, format!("{new_name}{sep}{}", &f.name[prefix.len()..])))
            .collect();
        // One transaction: a crash between the target UPDATE and the
        // inferior rewrites must not leave a half-renamed mirror.
        let tx = self.conn.unchecked_transaction()?;
        let mut renamed = Vec::with_capacity(children.len() + 1);
        for (id, name) in std::iter::once((folder_id, new_name.to_string())).chain(children) {
            tx.execute(
                "UPDATE folders SET name = ?2 WHERE id = ?1",
                params![id, name],
            )?;
            renamed.push(tx.query_row(
                "SELECT id, account_id, parent_id, name, origin, uid_validity,
                        uid_next, highest_uid
                 FROM folders WHERE id = ?1",
                params![id],
                map_folder_row,
            )?);
        }
        tx.commit()?;
        Ok(renamed)
    }

    /// Delete a remote/system folder row after the server ACKed `DELETE`
    /// (T-328). `clear_folder_messages` drops its messages, evidence rows,
    /// rule watermarks and payload dirs; inferiors survive — they are flat
    /// rows and the server keeps them (RFC 3501 §6.3.4). Local rows
    /// refuse: they have their own empty-leaf path.
    pub fn delete_remote_folder(&self, folder_id: i64) -> Result<bool> {
        let folder = self
            .folder_meta(folder_id)?
            .ok_or_else(|| MailError::InvalidInput("unknown folder".into()))?;
        if folder.origin == FolderOrigin::Local {
            return Err(MailError::PolicyRejected(
                "local folders are deleted through the local path".into(),
            ));
        }
        self.clear_folder_messages(folder_id)?;
        Ok(self
            .conn
            .execute("DELETE FROM folders WHERE id = ?1", params![folder_id])?
            > 0)
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
        // T-341: materialize the conversation key at ingest so a later mute can
        // suppress counts in SQL. Set on INSERT only - the conflict clause
        // below deliberately leaves it (and `subject`) alone, so a re-upsert
        // can never re-point a stored message at a different conversation.
        let conversation_key = meta
            .subject
            .as_deref()
            .and_then(crate::threading::normalize_subject);
        self.conn.execute(
            "INSERT INTO messages
               (folder_id, uid, message_id, subject, from_addr, to_addrs,
                date_unix, size, flags, has_attachments, snippet, fetched_at,
                category, unsub_http, unsub_mailto, unsub_oneclick,
                conversation_key)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
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
                conversation_key,
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
    ///
    /// T-341: `unseen` additionally excludes messages in a **muted
    /// conversation**, so a mute is a real count suppression and not a
    /// client-side filter. Two deliberate boundaries:
    /// - `exists` is untouched. It is the honest total of stored rows; the
    ///   task scopes suppression to *unseen* counts, and inventing a smaller
    ///   "exists" would misreport what the store holds.
    /// - A message with a `NULL` conversation_key (subject with no signal) is
    ///   never suppressed: `NULL = key` is never true, so it drops out of the
    ///   EXISTS naturally rather than needing a special case.
    ///
    /// The frontend's smart-folder badges are sums of this `unseen`, so they
    /// drop in the same query — no second aggregate to keep in sync.
    pub fn folder_stats(&self, folder_id: i64) -> Result<FolderStats> {
        self.conn
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN ' ' || m.flags || ' ' NOT LIKE '% \\Seen %'
                                          AND NOT EXISTS (
                                                SELECT 1 FROM folders f
                                                JOIN muted_conversations mc
                                                  ON mc.account_id = f.account_id
                                                 AND mc.conversation_key = m.conversation_key
                                               WHERE f.id = m.folder_id)
                                          THEN 1 ELSE 0 END), 0)
                 FROM messages m WHERE m.folder_id = ?1",
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

    /// Global unseen count across every account/folder (T-345 tray
    /// tooltip). Same predicate as `folder_stats`' `unseen` — no `\Seen`
    /// token and not in a muted conversation — so the tray number matches
    /// the sum of the badges rather than inventing its own definition.
    pub fn total_unseen(&self) -> Result<u64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM messages m
                 WHERE ' ' || m.flags || ' ' NOT LIKE '% \\Seen %'
                   AND NOT EXISTS (
                         SELECT 1 FROM folders f
                         JOIN muted_conversations mc
                           ON mc.account_id = f.account_id
                          AND mc.conversation_key = m.conversation_key
                         WHERE f.id = m.folder_id)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)
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
                            unsub_http, unsub_mailto, unsub_oneclick,
                            conversation_key
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
                            r.get::<_, Option<String>>(15)?,
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
                // T-341: carried verbatim — the stored key is the fold of
                // this row's subject, so move/copy keep the conversation
                // (and any mute on it) attached instead of re-deriving.
                conversation_key,
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
                    unsub_http, unsub_mailto, unsub_oneclick, conversation_key)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13,?14,?15,?16,?17)",
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
                    conversation_key,
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
            // T-339: deferred-part descriptors re-key too (payload dir
            // relocated above). Same pre-DELETE ordering — the composite
            // FK would cascade the rows away.
            self.conn.execute(
                "UPDATE message_parts SET folder_id = ?1, uid = ?2
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

    /// Copy messages between folders of the SAME account (T-325). Fresh
    /// destination uids exactly like a move, but the source row and payload
    /// are untouched — the destination row is a **local-only copy** carrying
    /// no server identity (a real IMAP COPY into a synced folder is the sync
    /// layer's job — tracked gap). Body files and attachment dirs are
    /// byte-copied, never renamed; risk + auth evidence rows are copied so
    /// the duplicate keeps its evaluation. The snooze row deliberately does
    /// NOT carry — parking binds to the source coordinate, and a copy of a
    /// parked message must not vanish at wake. Crash-safe trivially: a
    /// mid-copy abort leaves a subset of duplicates, never a loss.
    /// Returns `(src_uid → dst_uid)` pairs.
    pub fn copy_messages(
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
        let mut copied = Vec::new();
        for uid in uids {
            let row = self
                .conn
                .query_row(
                    "SELECT message_id, subject, from_addr, to_addrs, date_unix,
                            size, flags, has_attachments, snippet, body_path,
                            fetched_at, category,
                            unsub_http, unsub_mailto, unsub_oneclick,
                            conversation_key
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
                            r.get::<_, Option<String>>(15)?,
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
                // T-341: carried verbatim — the stored key is the fold of
                // this row's subject, so move/copy keep the conversation
                // (and any mute on it) attached instead of re-deriving.
                conversation_key,
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
                    unsub_http, unsub_mailto, unsub_oneclick, conversation_key)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13,?14,?15,?16,?17)",
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
                    conversation_key,
                ],
            )?;
            // Copy the body payload, then repoint the new row at the copy.
            if body_path.is_some() {
                let src_abs = self.body_path(src_folder_id, *uid);
                let dst_abs = self.body_path(dst_folder_id, dst_uid as u64);
                if let Some(parent) = dst_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if src_abs.exists() {
                    std::fs::copy(&src_abs, &dst_abs)?;
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
            // Copy the attachment payload dir (recursive — dirs hold the
            // extracted parts; the source dir stays).
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
                copy_dir_all(&src_att, &dst_att)?;
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
            // T-339: deferred-part descriptors carry (payload dir copied
            // above). The minted dst uid has no server identity, so a lazy
            // fetch on the copy fails the drift check rather than pulling
            // another message's bytes — honest refusal, no fabrication.
            self.conn.execute(
                "INSERT OR REPLACE INTO message_parts
                    (folder_id, uid, part_index, section, name, mime,
                     size_bytes, encoding, fetched)
                 SELECT ?1, ?2, part_index, section, name, mime,
                        size_bytes, encoding, fetched
                 FROM message_parts WHERE folder_id = ?3 AND uid = ?4",
                params![dst_folder_id, dst_uid, src_folder_id, *uid as i64],
            )?;
            // Auth evidence carries too — the copy keeps the verdict its
            // bytes earned. (Move lacks this carry — tracked pre-existing
            // gap; copying both is strictly honest.)
            self.conn.execute(
                "INSERT OR REPLACE INTO message_auth
                    (folder_id, uid, spf, dkim, dmarc, dmarc_policy,
                     dkim_domain, key_query, dmarc_record, header_value,
                     evidence_json, upstream_json, auth_risk)
                 SELECT ?1, ?2, spf, dkim, dmarc, dmarc_policy,
                        dkim_domain, key_query, dmarc_record, header_value,
                        evidence_json, upstream_json, auth_risk
                 FROM message_auth WHERE folder_id = ?3 AND uid = ?4",
                params![dst_folder_id, dst_uid, src_folder_id, *uid as i64],
            )?;
            copied.push((*uid, dst_uid as u64));
        }
        Ok(copied)
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

    /// Highest uid in a folder (0 when empty) — the local minting base for
    /// import/move rows that carry no server identity.
    pub fn max_uid(&self, folder_id: i64) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(uid), 0) FROM messages WHERE folder_id = ?1",
            params![folder_id],
            |r| r.get(0),
        )?)
    }

    /// True when the account already stores this RFC822 `Message-ID` in any
    /// folder (T-309 mbox-import dedup). `message_id` is nullable on the row —
    /// callers only ask about present values.
    pub fn account_has_message_id(&self, account_id: &str, message_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM messages m
                    JOIN folders f ON f.id = m.folder_id
                    WHERE f.account_id = ?1 AND m.message_id = ?2
                )",
                params![account_id, message_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|exists| exists != 0)?)
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

    /// Stage an already-stored attachment payload file into the same
    /// private sandbox-staging layout as [`stage_attachment`] (T-339:
    /// deferred parts resolve to `attachments/<folder>/<uid>/<idx>` files,
    /// not a MIME body). Copies bytes — the persisted payload is never
    /// moved or truncated out from under the fetch marker.
    pub fn stage_payload_file(&self, src: &Path, uid: u64, max_bytes: usize) -> Result<PathBuf> {
        let size = std::fs::metadata(src)?.len();
        if size > max_bytes as u64 {
            return Err(MailError::InvalidInput(
                "attachment exceeds sandbox size bound".into(),
            ));
        }
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
        std::fs::copy(src, &path)?;
        Ok(path)
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

    // -- deferred attachment parts (T-339) ------------------------------------
    //
    // `message_parts` rows are the skeleton marker: present rows mean the
    // stored body is partial (attachment payloads deferred); absent rows mean
    // it is whole. Rows carry the server-derived IMAP `section` — the only
    // lawful input to `BODY.PEEK[<section>]` — so a deferred payload fetch
    // never builds a part specifier from UI input.

    fn map_part_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessagePart> {
        Ok(MessagePart {
            part_index: r.get::<_, i64>(0)? as u32,
            section: r.get(1)?,
            name: r.get(2)?,
            mime: r.get(3)?,
            size_bytes: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            encoding: r.get(5)?,
            fetched: r.get::<_, i64>(6)? != 0,
        })
    }

    /// Record/replace the deferred-attachment descriptor set for a message.
    /// Re-syncs keep `fetched` on parts that already landed; rows beyond the
    /// new plan are dropped (structure changed server-side).
    pub fn set_message_parts(
        &self,
        folder_id: i64,
        uid: u64,
        parts: &[crate::parts::AttachmentDesc],
    ) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO message_parts
               (folder_id, uid, part_index, section, name, mime, size_bytes, encoding)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(folder_id, uid, part_index) DO UPDATE SET
               section = excluded.section,
               name = excluded.name,
               mime = excluded.mime,
               size_bytes = excluded.size_bytes,
               encoding = excluded.encoding",
        )?;
        for part in parts {
            stmt.execute(params![
                folder_id,
                uid as i64,
                part.index as i64,
                part.section,
                part.name,
                part.mime,
                part.size as i64,
                part.encoding,
            ])?;
        }
        drop(stmt);
        self.conn.execute(
            "DELETE FROM message_parts
             WHERE folder_id = ?1 AND uid = ?2 AND part_index >= ?3",
            params![folder_id, uid as i64, parts.len() as i64],
        )?;
        Ok(())
    }

    /// All deferred-attachment descriptors for a message, ordered by index.
    pub fn message_parts(&self, folder_id: i64, uid: u64) -> Result<Vec<MessagePart>> {
        let mut stmt = self.conn.prepare(
            "SELECT part_index, section, name, mime, size_bytes, encoding, fetched
             FROM message_parts
             WHERE folder_id = ?1 AND uid = ?2
             ORDER BY part_index",
        )?;
        let rows = stmt.query_map(params![folder_id, uid as i64], Self::map_part_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// One descriptor by its ordinal — `attachmentIndex` resolution point.
    pub fn message_part(
        &self,
        folder_id: i64,
        uid: u64,
        part_index: u32,
    ) -> Result<Option<MessagePart>> {
        self.conn
            .query_row(
                "SELECT part_index, section, name, mime, size_bytes, encoding, fetched
                 FROM message_parts
                 WHERE folder_id = ?1 AND uid = ?2 AND part_index = ?3",
                params![folder_id, uid as i64, part_index as i64],
                Self::map_part_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Any `message_parts` rows at all → the stored body is a skeleton.
    pub fn has_message_parts(&self, folder_id: i64, uid: u64) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM message_parts WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Mark a part's payload as durably stored. Call only after the
    /// decoded bytes are on disk — the flag is the "can skip the wire"
    /// bit, so it must never lead the write.
    pub fn mark_part_fetched(&self, folder_id: i64, uid: u64, part_index: u32) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE message_parts SET fetched = 1
             WHERE folder_id = ?1 AND uid = ?2 AND part_index = ?3",
            params![folder_id, uid as i64, part_index as i64],
        )?;
        Ok(n > 0)
    }

    /// Absolute path of a fetched payload, present or not.
    pub fn attachment_payload_path(&self, folder_id: i64, uid: u64, part_index: u32) -> PathBuf {
        self.root
            .join("attachments")
            .join(folder_id.to_string())
            .join(uid.to_string())
            .join(part_index.to_string())
    }

    /// Drop all part rows + fetched payloads for a message — used when a
    /// complete `BODY[]` replaces a skeleton (the rows' "deferred" claim
    /// would become a lie) and on any local purge path that bypasses
    /// `delete_messages`.
    pub fn clear_message_parts(&self, folder_id: i64, uid: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM message_parts WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64],
        )?;
        let _ = std::fs::remove_dir_all(
            self.root
                .join("attachments")
                .join(folder_id.to_string())
                .join(uid.to_string()),
        );
        Ok(())
    }

    /// Copy `message_parts` rows + fetched payload dir across a local
    /// move/copy (the copy-by-reference variant used by `update.rs`'s
    /// archive path; `move_messages`/`copy_messages` carry rows inline
    /// inside their own ordering). Payload files are byte-copied — the
    /// caller removes the source row/dir afterwards for a move.
    ///
    /// Honesty note: the descriptors describe the *message*, so they
    /// carry to a copy faithfully — but the dst uid is locally minted and
    /// has no server identity. An on-demand fetch against it fails the
    /// drift check in `ensure_part_fetched` rather than silently pulling
    /// a different server's-coordinated payload.
    pub fn copy_parts_state(
        &self,
        src_folder_id: i64,
        src_uid: u64,
        dst_folder_id: i64,
        dst_uid: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO message_parts
                (folder_id, uid, part_index, section, name, mime, size_bytes,
                 encoding, fetched)
             SELECT ?1, ?2, part_index, section, name, mime, size_bytes,
                    encoding, fetched
             FROM message_parts WHERE folder_id = ?3 AND uid = ?4",
            params![dst_folder_id, dst_uid as i64, src_folder_id, src_uid as i64],
        )?;
        let src = self
            .root
            .join("attachments")
            .join(src_folder_id.to_string())
            .join(src_uid.to_string());
        if src.exists() {
            let dst = self
                .root
                .join("attachments")
                .join(dst_folder_id.to_string())
                .join(dst_uid.to_string());
            copy_dir_all(&src, &dst)?;
        }
        Ok(())
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
