//! Message-action wire views (T-146/T-163) — flag patches, delete/move
//! results, attachment saves, rendered bodies.

use serde::{Deserialize, Serialize};

/// Flag/archive patch for `kiwi_update_message`. Each field is
/// tri-state: absent = unchanged.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePatchInput {
    /// Maps to IMAP `\Seen`.
    pub seen: Option<bool>,
    /// Maps to IMAP `\Flagged`.
    pub starred: Option<bool>,
    /// true → move to Archive folder; false → move back to INBOX.
    pub archived: Option<bool>,
}

/// Result of a message patch (post-mutation state).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUpdateView {
    /// Source folder id (the one the caller passed — destination is
    /// `movedToFolderId` when archived).
    pub folder_id: i64,
    pub uid: u64,
    /// Post-mutation flag set.
    pub flags: Vec<String>,
    /// Destination folder id when the message was moved (archive /
    /// unarchive), else null.
    pub moved_to_folder_id: Option<i64>,
}

/// `kiwi_delete_messages` result — counts tell the UI which path ran.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResultView {
    pub folder_id: i64,
    /// Messages moved into Trash (soft delete).
    pub moved_to_trash: u64,
    /// Messages permanently expunged (delete-from-Trash or `permanent`).
    pub deleted: u64,
    /// Trash folder id when a move happened.
    pub trash_folder_id: Option<i64>,
    /// src uid → Trash uid for moved messages (uids are folder-scoped —
    /// a move is a copy under a fresh uid + source delete).
    pub uid_map: std::collections::BTreeMap<u64, u64>,
}

/// `kiwi_move_messages` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResultView {
    pub src_folder_id: i64,
    pub dst_folder_id: i64,
    pub moved: u64,
    /// src uid → dst uid.
    pub uid_map: std::collections::BTreeMap<u64, u64>,
}

/// Result of `kiwi_download_attachment` — what was written where.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentSavedView {
    /// Absolute path written.
    pub path: String,
    /// MIME filename (or generated `attachment-N`).
    pub filename: String,
    /// MIME content type of the part.
    pub content_type: String,
    /// Bytes written.
    pub size: usize,
}

/// `kiwi_render_body` result — the sanitized fragment plus remote-content
/// policy facts for the UI (e.g., "N remote images blocked — allow?").
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedBodyView {
    /// Sanitized HTML fragment, or null for text-only/missing bodies.
    pub html: Option<String>,
    /// Account's remote-content opt-in at render time.
    pub remote_content_allowed: bool,
    /// Remote `img` sources stripped by the sanitizer this render.
    pub remote_images_stripped: u32,
}

/// `kiwi_set_remote_content` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteContentView {
    pub account_id: String,
    pub remote_content_allowed: bool,
}

/// `kiwi_message_unsubscribe` result (T-234). `action` echoes which
/// endpoint was used; exactly one of `httpStatus` / `queueId` is set.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsubscribeResultView {
    /// The endpoint executed: `"http"` | `"mailto"`.
    pub action: &'static str,
    /// True when the request left this process — http: a response was
    /// received (any status); mailto: the message is in the outbox.
    pub executed: bool,
    /// HTTP status for `action=http`. <400 means the endpoint accepted
    /// the unsubscribe; 4xx/5xx is still `executed` (the POST went out)
    /// but signals rejection to the UI.
    pub http_status: Option<u16>,
    /// Outbox queue id for `action=mailto`.
    pub queue_id: Option<String>,
    /// Undo-send deadline for `action=mailto` (normal outbox grace).
    pub undo_window_until_unix: Option<i64>,
}

/// One `(folderId, uid)` coordinate — the `refs` element of the snooze /
/// unsnooze calls (T-255). A selection can span folders because the
/// Snoozed view is account-wide.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRefInput {
    pub folder_id: i64,
    pub uid: i64,
}

/// `kiwi_message_snooze` result (T-255).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnoozeResultView {
    /// Rows that ended the call parked.
    pub snoozed: u64,
    /// The concrete deadline applied to every ref — presets resolve
    /// server-side, so this is what the UI displays.
    pub until_unix: i64,
}

/// `kiwi_message_unsnooze` result (T-255).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsnoozeResultView {
    /// Rows that were actually parked and got released.
    pub unsnoozed: u64,
}

/// One row of `kiwi_list_snoozed` — parked coordinates + the display
/// fields the Snoozed view renders (T-255).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnoozedMessageView {
    /// Folder the message lives in NOW (it never moved — snooze is a
    /// hide-in-place marker, not a folder move).
    pub folder_id: i64,
    pub uid: u64,
    /// Folder name — this is a display list.
    pub folder: String,
    /// Folder id it was parked from (diverges only if it moved while
    /// parked — rules/manual moves carry the parking record).
    pub snoozed_from_folder_id: i64,
    /// Deadline the sweep releases at.
    pub snoozed_until: i64,
    /// When it was parked.
    pub snoozed_at: i64,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub message_id: Option<String>,
    pub date_unix: Option<i64>,
}
