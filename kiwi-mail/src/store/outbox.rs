//! Outbox — the persistent send queue (T-142: undo-send +
//! send-later). `OutboxRow` keeps the fully-built MIME in-row so a
//! queued send is one atomic write; callers bound `mime` before
//! insert.

use rusqlite::params;

use crate::error::{MailError, Result};

use super::MailStore;

/// Byte cap on the persisted failure reason (T-298) — the text is already
/// an `IpcError`-sanitized message; the bound keeps the column small.
pub const MAX_OUTBOX_ERROR_LEN: usize = 512;

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
    /// Sanitized reason for the most recent failed attempt (T-298).
    /// `None` until the first failure — honest absence, not a
    /// cleared-after-success flag (success deletes the row).
    pub last_error: Option<String>,
    pub created_unix: i64,
}

impl MailStore {
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
                attempts, last_error, created_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
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
                row.last_error.as_deref(),
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
                    attempts, last_error, created_unix
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
                r.get::<_, Option<String>>(10)?,
                r.get::<_, i64>(11)?,
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
                last_error,
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
                last_error,
                created_unix,
            });
        }
        Ok(out)
    }

    /// Update dispatch timing + attempt count + failure reason (retry
    /// backoff, send-later reschedule). `last_error` is bounded to 512 B
    /// at the store boundary — callers pass already-sanitized text; a
    /// reschedule passes `None` to clear a stale reason. Returns false
    /// when the row is gone.
    pub fn outbox_set_timing(
        &self,
        queue_id: &str,
        not_before_unix: i64,
        attempts: u32,
        last_error: Option<&str>,
    ) -> Result<bool> {
        let bounded_err = last_error.map(|e| {
            let mut end = e.len().min(MAX_OUTBOX_ERROR_LEN);
            while !e.is_char_boundary(end) {
                end -= 1;
            }
            e[..end].to_string()
        });
        let n = self.conn.execute(
            "UPDATE outbox SET not_before_unix = ?2, attempts = ?3, last_error = ?4
             WHERE queue_id = ?1",
            params![queue_id, not_before_unix, attempts as i64, bounded_err],
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
                    attempts, last_error, created_unix
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
                r.get::<_, Option<String>>(10)?,
                r.get::<_, i64>(11)?,
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
                last_error,
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
                last_error,
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
}
