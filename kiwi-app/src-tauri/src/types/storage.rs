//! Storage-diagnostics wire views (T-330) — measured local-store facts.
//!
//! Every field is a real measurement taken by the command that fills it, or an
//! explicit `null` when the value could not be measured. There is no
//! "estimated" or "defaulted" state on this shape: `0` and `null` mean
//! different things and the UI is expected to keep them apart.

use serde::Serialize;

/// `kiwi_storage_stats` snapshot.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatsView {
    /// Real on-disk length of `mail.db` (filesystem metadata). `null` when
    /// there is no file to measure — never a `page_count * page_size`
    /// estimate, and never a fabricated `0`.
    pub db_bytes: Option<u64>,
    /// `SELECT COUNT(*) FROM messages` across every account and folder.
    pub message_count: u64,
    /// `SELECT COUNT(*) FROM folders` (remote, local, and system rows).
    pub folder_count: u64,
    /// Real sum of persisted decoded-attachment payload bytes under
    /// `attachments/`. `null` when that tree could not be measured. Attachment
    /// parts still inside stored bodies are **not** included: no per-part size
    /// is persisted, so this is a payload-tree total, not a mail-wide total.
    pub attachment_bytes: Option<u64>,
    /// Records in the hash-chained `audit.jsonl` store. Counted from the
    /// audit log itself, not from SQL: the audit trail is a file, not a table.
    pub audit_count: u64,
    /// `PRAGMA user_version` of the open database.
    pub schema_version: u32,
    /// `"ok"`, or SQLite's own `PRAGMA integrity_check` error text. A reader
    /// must not treat any non-`"ok"` value as a pass.
    pub integrity_check: String,
}

/// `kiwi_storage_compact` receipt — what one `VACUUM` actually did.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageCompactView {
    /// `mail.db` length measured immediately before the rebuild; `null` when
    /// there is no file to measure.
    pub before_db_bytes: Option<u64>,
    /// `mail.db` length measured immediately after; `null` when there is no
    /// file to measure. `after > before` is possible and honest (a rebuild
    /// can re-grow a file that had free pages at the end).
    pub after_db_bytes: Option<u64>,
}
