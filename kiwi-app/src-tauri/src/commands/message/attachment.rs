//! Attachment download (T-146) — extract one attachment from the stored
//! MIME body to a caller-chosen path, size-bounded.

use std::path::Path;
use std::sync::Arc;

use mail_parser::{MessageParser, MimeHeaders};
use tauri::State;

use super::super::{bounded, gate, run_mail_io};
use crate::commands::mail::load_body_raw;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::AttachmentSavedView;

/// One attachment download is bounded — MIME bodies are already size-capped
/// by the store, this guards the decoded part.
const MAX_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;

/// Extract one attachment from the stored MIME body to a caller-chosen path
/// (UI save dialog). Size-bounded; filename/content-type come from the MIME
/// part, not the caller.
#[tauri::command]
pub async fn kiwi_download_attachment(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    attachment_index: i64,
    dest_path: String,
) -> CmdResult<AttachmentSavedView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        download_attachment_impl(s, account_id, folder_id, uid, attachment_index, dest_path)
    })
    .await
}

pub(crate) async fn download_attachment_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    attachment_index: i64,
    dest_path: String,
) -> CmdResult<AttachmentSavedView> {
    bounded("accountId", &account_id, 128)?;
    bounded("destPath", &dest_path, 1024)?;
    if uid < 0 || attachment_index < 0 {
        return Err(IpcError::invalid("uid and attachmentIndex must be >= 0"));
    }
    let raw = load_body_raw(&state, &account_id, folder_id, uid as u64)
        .await?
        .ok_or_else(|| IpcError::not_found("message body not available"))?;
    let msg = MessageParser::default()
        .parse(&raw)
        .ok_or_else(|| IpcError::new("protocol-error", "stored body failed MIME parse"))?;
    let att = msg
        .attachments()
        .nth(attachment_index as usize)
        .ok_or_else(|| IpcError::not_found("no such attachment index"))?;
    let bytes = att.contents();
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(IpcError::invalid("attachment exceeds 50 MiB bound"));
    }
    let filename = att
        .attachment_name()
        .map(|s| s.to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("attachment-{attachment_index}"));
    let content_type = att
        .content_type()
        .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream")))
        .unwrap_or_else(|| "application/octet-stream".into());

    // dest_path is a user-chosen save location (UI dialog). We still bound
    // it: must be absolute-ish (has a parent or is a filename we resolve),
    // never inside the app's own data dir.
    let dest = Path::new(&dest_path);
    let canon_data = state
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| state.data_dir.clone());
    if let Ok(abs) = dest.canonicalize().or_else(|_| {
        dest.parent()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    std::env::current_dir().map(|cwd| cwd.join(dest))
                } else {
                    p.canonicalize()
                        .map(|c| c.join(dest.file_name().unwrap_or_default()))
                }
            })
            .unwrap_or_else(|| Ok(dest.to_path_buf()))
    }) && abs.starts_with(&canon_data)
    {
        return Err(IpcError::invalid(
            "destPath inside the app data dir is refused",
        ));
    }
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, bytes)?;
    let path = dest.to_string_lossy().to_string();
    state.audit.lock().await.record(
        "attachment-saved",
        &format!("{account_id}/f{folder_id}/u{uid}[{attachment_index}] → {filename}"),
        now_unix(),
    )?;
    Ok(AttachmentSavedView {
        path,
        filename,
        content_type,
        size: bytes.len(),
    })
}
