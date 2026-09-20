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
