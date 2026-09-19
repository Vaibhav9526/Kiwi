//! T-146 — message actions: flag mutation (read/star/archive), attachment
//! download, sanitized HTML render, per-account remote-content toggle.
//!
//! All commands are lock-gated and run through `run_mail_io` when they can
//! touch a live protocol client (IMAP flag/move write-through).
//!
//! - Flags: local store write-through (`update_flags`) + live `UID STORE`
//!   for IMAP accounts; POP3 is local-only (no server-side flags exist).
//! - Archive: IMAP `UID MOVE` (COPY+DELETE+EXPUNGE fallback inside
//!   kiwi-mail) to the account's "Archive" folder + a local move of the
//!   message row and body file. Unarchive moves back to `INBOX`.
//! - Render: `ammonia` with a strict allowlist — scripts, forms, iframes,
//!   remote styles and remote `img` sources never reach the webview.
//!   Remote content is opt-in per account (`remote_content_allowed`,
//!   default false, audited).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use mail_parser::{MessageParser, MimeHeaders};
use tauri::State;

use kiwi_core::session::Protocol;
use kiwi_mail::account::IncomingProtocol;
use kiwi_mail::store::NewMessageMeta;

use super::mail::{connect_imap, load_body_raw};
use super::{bounded, gate, run_mail_io};
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, now_unix};
use crate::types::{
    AttachmentSavedView, MessagePatchInput, MessageUpdateView, RemoteContentView, RenderedBodyView,
};

/// One attachment download is bounded — MIME bodies are already size-capped
/// by the store, this guards the decoded part.
const MAX_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;
/// Rendered HTML output cap (post-sanitize) — keeps the webview bounded.
const MAX_RENDER_BYTES: usize = 8 * 1024 * 1024;
/// Conventional archive mailbox name (RFC 6154 \Archive special-use).
const ARCHIVE_FOLDER: &str = "Archive";

// ---------------------------------------------------------------------------
// Flag mutation / archive
// ---------------------------------------------------------------------------

/// Patch a message: `seen` → `\Seen`, `starred` → `\Flagged`,
/// `archived` → move to/from the Archive folder.
#[tauri::command]
pub async fn kiwi_update_message(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    patch: MessagePatchInput,
) -> CmdResult<MessageUpdateView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| {
        update_message_impl(s, account_id, folder_id, uid, patch)
    })
    .await
}

pub(crate) async fn update_message_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    patch: MessagePatchInput,
) -> CmdResult<MessageUpdateView> {
    bounded("accountId", &account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    let uid = uid as u64;
    if patch.seen.is_none() && patch.starred.is_none() && patch.archived.is_none() {
        return Err(IpcError::invalid("patch must change at least one flag"));
    }

    let (folder_name, proto, acct) = {
        let store = state.store.lock().await;
        let meta = store
            .folder_meta(folder_id)?
            .ok_or_else(|| IpcError::not_found("unknown folder"))?;
        if meta.account_id != account_id {
            return Err(IpcError::not_found("folder not on account"));
        }
        let acct = store
            .get_account(&account_id)?
            .ok_or_else(|| IpcError::not_found("unknown account"))?;
        (meta.name, acct.incoming.protocol, acct)
    };

    // Current flags → desired flag set.
    let mut flags: Vec<String> = {
        let store = state.store.lock().await;
        let msgs = store.list_messages(folder_id, 10_000)?;
        msgs.iter()
            .find(|m| m.uid == uid)
            .ok_or_else(|| IpcError::not_found("message not in folder"))?
            .flags
            .clone()
    };
    let set_flag = |flags: &mut Vec<String>, name: &str, on: Option<bool>| match on {
        Some(true) if !flags.iter().any(|f| f.eq_ignore_ascii_case(name)) => {
            flags.push(name.to_string())
        }
        Some(false) => flags.retain(|f| !f.eq_ignore_ascii_case(name)),
        _ => {}
    };
    set_flag(&mut flags, "\\Seen", patch.seen);
    set_flag(&mut flags, "\\Flagged", patch.starred);

    // IMAP write-through: one live connection does flags + move together.
    let mut moved_to = None;
    let mut client = if proto == IncomingProtocol::Imap
        && (patch.seen.is_some() || patch.starred.is_some() || patch.archived.is_some())
    {
        let mut c = connect_imap(&state, &acct).await?;
        c.select(&folder_name, false)
            .await
            .map_err(IpcError::from)?;
        Some(c)
    } else {
        None
    };

    if let Some(c) = client.as_mut() {
        // Per-flag ops — "+FLAGS" / "-FLAGS" with SILENT (untagged-only).
        if let Some(v) = patch.seen {
            c.uid_store(
                &uid.to_string(),
                if v { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" },
                &["\\Seen"],
            )
            .await
            .map_err(IpcError::from)?;
        }
        if let Some(v) = patch.starred {
            c.uid_store(
                &uid.to_string(),
                if v { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" },
                &["\\Flagged"],
            )
            .await
            .map_err(IpcError::from)?;
        }
    }

    // Local flag write-through (even when offline — the next sync
    // reconciles; store flags are the list-view source of truth).
    {
        let store = state.store.lock().await;
        store.update_flags(folder_id, uid, &flags)?;
    }

    // Archive: move to Archive folder (or back to INBOX on unarchive).
    if let Some(archived) = patch.archived {
        let target = if archived { ARCHIVE_FOLDER } else { "INBOX" };
        let dest_id = {
            let store = state.store.lock().await;
            store.ensure_folder(&account_id, target)?
        };
        {
            let mut index = state.index.lock().await;
            index.remember_folder(&account_id, dest_id, target);
            index.save(&state.data_dir)?;
        }
        if let Some(c) = &mut client {
            // Mailbox may not exist server-side yet — create is idempotent.
            let _ = c.create_mailbox(target).await;
            c.uid_move(&uid.to_string(), target)
                .await
                .map_err(IpcError::from)?;
        }
        move_local(&state, folder_id, dest_id, uid).await?;
        moved_to = Some(dest_id);
    }

    // Record the connection if one was opened.
    if let Some(c) = &mut client {
        let facts = observe::facts_of(c.transport());
        observe::record_connection(
            &state,
            facts,
            ObservationContext {
                protocol: Protocol::Imap,
                account_id: Some(account_id.clone()),
                starttls_offered: Some(c.has_capability("STARTTLS")),
                auth_mechanism: super::mail::auth_mech_of(&acct.incoming.auth),
                auth_succeeded: Some(true),
                label: "imap update",
            },
        )
        .await;
        let _ = c.logout().await;
    }

    state.audit.lock().await.record(
        "message-updated",
        &format!(
            "{account_id}/f{folder_id}/u{uid}: {:?}",
            patch_summary(&patch)
        ),
        now_unix(),
    )?;

    Ok(MessageUpdateView {
        folder_id,
        uid,
        flags,
        moved_to_folder_id: moved_to,
    })
}

fn patch_summary(p: &MessagePatchInput) -> String {
    let mut s = Vec::new();
    if let Some(v) = p.seen {
        s.push(format!("seen={v}"));
    }
    if let Some(v) = p.starred {
        s.push(format!("starred={v}"));
    }
    if let Some(v) = p.archived {
        s.push(format!("archived={v}"));
    }
    s.join(" ")
}

/// Local move: upsert the meta row into the destination folder (same uid —
/// uids are folder-scoped), copy the stored body, delete the source row.
async fn move_local(
    state: &AppState,
    src_folder: i64,
    dest_folder: i64,
    uid: u64,
) -> CmdResult<()> {
    let store = state.store.lock().await;
    let msgs = store.list_messages(src_folder, 10_000)?;
    let m = msgs
        .iter()
        .find(|m| m.uid == uid)
        .ok_or_else(|| IpcError::not_found("message not in folder"))?
        .clone();
    store.upsert_message(
        dest_folder,
        &NewMessageMeta {
            uid,
            message_id: m.message_id.clone(),
            subject: m.subject.clone(),
            from_addr: m.from_addr.clone(),
            to_addrs: m.to_addrs.clone(),
            date_unix: m.date_unix,
            size: m.size,
            flags: m.flags.clone(),
            has_attachments: m.has_attachments,
            snippet: m.snippet.clone(),
        },
        now_unix(),
    )?;
    // Copy the stored body before deleting the source row (delete removes
    // the row; the body file is folder-scoped, so copy bytes first).
    if let Some(p) = store.body_file(src_folder, uid)?
        && let Ok(bytes) = std::fs::read(&p)
    {
        store.store_body(dest_folder, uid, &bytes)?;
    }
    store.delete_messages(src_folder, &[uid])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attachment download
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Sanitized HTML render + remote-content toggle
// ---------------------------------------------------------------------------

/// Render the message's HTML body through a strict sanitizer. Returns the
/// cleaned fragment + whether remote content is allowed for this account.
#[tauri::command]
pub async fn kiwi_render_body(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<RenderedBodyView> {
    gate(state.inner()).await?;
    let st = state.inner().clone();
    run_mail_io(st, move |s| render_body_impl(s, account_id, folder_id, uid)).await
}

pub(crate) async fn render_body_impl(
    state: Arc<AppState>,
    account_id: String,
    folder_id: i64,
    uid: i64,
) -> CmdResult<RenderedBodyView> {
    bounded("accountId", &account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    let allow_remote = state
        .index
        .lock()
        .await
        .account_meta
        .get(&account_id)
        .map(|m| m.remote_content_allowed)
        .unwrap_or(false);
    let Some(raw) = load_body_raw(&state, &account_id, folder_id, uid as u64).await? else {
        return Ok(RenderedBodyView {
            html: None,
            remote_content_allowed: allow_remote,
            remote_images_stripped: 0,
        });
    };
    let parsed = kiwi_mail::mime::parse_message(&raw).map_err(IpcError::from)?;
    let Some(html) = parsed.html_body else {
        return Ok(RenderedBodyView {
            html: None,
            remote_content_allowed: allow_remote,
            remote_images_stripped: 0,
        });
    };
    let (clean, stripped) = sanitize_html(&html, allow_remote);
    // Post-sanitize bound — pathological documents compress to little but
    // the DOM can still explode; the webview gets a capped fragment.
    let clean = if clean.len() > MAX_RENDER_BYTES {
        clean.chars().take(MAX_RENDER_BYTES).collect()
    } else {
        clean
    };
    Ok(RenderedBodyView {
        html: Some(clean),
        remote_content_allowed: allow_remote,
        remote_images_stripped: stripped,
    })
}

/// Sanitize an HTML fragment for display in the untrusted webview.
///
/// Strict allowlist (no script/style/iframe/form/object/link/meta — they're
/// simply absent from the tag set). `img` is allowed but `src` is
/// filtered: `cid:`/`data:`/relative sources always pass; `http(s)` sources
/// pass only when `allow_remote` — otherwise the attribute is dropped and
/// counted (a stripped src renders as a placeholder, not a network fetch).
///
/// Returns (sanitized_html, remote_images_stripped).
pub fn sanitize_html(html: &str, allow_remote: bool) -> (String, u32) {
    use std::collections::{HashMap, HashSet};
    let stripped = Arc::new(AtomicU32::new(0));
    let stripped_ref = stripped.clone();
    let mut tag_attrs: HashMap<&str, HashSet<&str>> = HashMap::new();
    tag_attrs.insert("a", ["href", "title"].into_iter().collect());
    tag_attrs.insert(
        "img",
        ["src", "alt", "title", "width", "height"]
            .into_iter()
            .collect(),
    );
    tag_attrs.insert("td", ["colspan", "rowspan"].into_iter().collect());
    tag_attrs.insert("th", ["colspan", "rowspan", "scope"].into_iter().collect());
    let out = ammonia::Builder::default()
        .tags(
            [
                "a",
                "abbr",
                "b",
                "blockquote",
                "br",
                "code",
                "dd",
                "del",
                "div",
                "dl",
                "dt",
                "em",
                "figcaption",
                "figure",
                "h1",
                "h2",
                "h3",
                "h4",
                "h5",
                "h6",
                "hr",
                "i",
                "img",
                "ins",
                "li",
                "ol",
                "p",
                "pre",
                "s",
                "span",
                "strike",
                "strong",
                "sub",
                "sup",
                "table",
                "tbody",
                "td",
                "tfoot",
                "th",
                "thead",
                "tr",
                "u",
                "ul",
            ]
            .into_iter()
            .collect(),
        )
        .generic_attributes(["title", "lang", "dir"].into_iter().collect())
        .tag_attributes(tag_attrs)
        .url_schemes(
            ["http", "https", "mailto", "cid", "data"]
                .into_iter()
                .collect(),
        )
        .link_rel(Some("noopener noreferrer nofollow"))
        .attribute_filter(move |element, attribute, value| {
            // Remote-resource filter on <img src> (the only remote-loadable
            // attribute in the allowlist). cid:/data:/relative always pass.
            let v = value.trim().to_ascii_lowercase();
            if element == "img" && attribute == "src" {
                let remote =
                    v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//");
                if remote && !allow_remote {
                    stripped_ref.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
            // Backstop for javascript:/vbscript: on any url-valued attr.
            if v.starts_with("javascript:") || v.starts_with("vbscript:") {
                return None;
            }
            Some(std::borrow::Cow::Borrowed(value))
        })
        .clean(html)
        .to_string();
    (out, stripped.load(Ordering::Relaxed))
}

/// Per-account remote-content opt-in (off by default — remote images and
/// fonts are a tracking surface). Audited.
#[tauri::command]
pub async fn kiwi_set_remote_content(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    allowed: bool,
) -> CmdResult<RemoteContentView> {
    gate(state.inner()).await?;
    bounded("accountId", &account_id, 128)?;
    let exists = state.store.lock().await.get_account(&account_id)?.is_some();
    if !exists {
        return Err(IpcError::not_found("unknown account"));
    }
    {
        let mut index = state.index.lock().await;
        index
            .account_meta
            .entry(account_id.clone())
            .or_default()
            .remote_content_allowed = allowed;
        index.save(&state.data_dir)?;
    }
    state.audit.lock().await.record(
        "remote-content",
        &format!(
            "{account_id}: remote content {}",
            if allowed { "allowed" } else { "blocked" }
        ),
        now_unix(),
    )?;
    Ok(RemoteContentView {
        account_id,
        remote_content_allowed: allowed,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_script_and_event_handlers() {
        let (out, _) = sanitize_html(
            r#"<p onclick="x()">hi<script>alert(1)</script><b>bold</b></p>"#,
            false,
        );
        assert!(out.contains("hi") && out.contains("<b>bold</b>"));
        assert!(!out.contains("script") && !out.contains("onclick"));
    }

    #[test]
    fn sanitize_strips_remote_images_when_off_keeps_when_on() {
        let html = r#"<img src="https://track.example/p.gif"><img src="cid:part1"><img src="data:image/png;base64,AA==">"#;
        let (off, n) = sanitize_html(html, false);
        assert_eq!(n, 1);
        assert!(!off.contains("track.example"));
        assert!(off.contains("cid:part1"));
        assert!(off.contains("data:image/png"));
        let (on, n) = sanitize_html(html, true);
        assert_eq!(n, 0);
        assert!(on.contains("track.example"));
    }

    #[test]
    fn sanitize_drops_javascript_href_and_iframes() {
        let (out, _) = sanitize_html(
            r#"<a href="javascript:alert(1)">x</a><iframe src="https://e"></iframe><a href="https://ok.test">ok</a>"#,
            true,
        );
        assert!(!out.contains("javascript:"));
        assert!(!out.contains("iframe"));
        assert!(out.contains("https://ok.test"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flag_update_local_only_for_pop3() {
        let dir = std::env::temp_dir().join(format!("kiwi-msg-test-{}", std::process::id()));
        let state = AppState::open_test(dir.clone()).unwrap();
        // POP3 account → no live connection is attempted.
        let acct = kiwi_mail::account::MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: kiwi_mail::account::IncomingAccount {
                protocol: IncomingProtocol::Pop3,
                server: kiwi_mail::account::ServerConfig {
                    host: "pop.x.test".into(),
                    port: 995,
                    security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
            outgoing: kiwi_mail::account::OutgoingAccount {
                server: kiwi_mail::account::ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: kiwi_mail::account::AuthRef::None,
            },
        };
        state.store.lock().await.upsert_account(&acct).unwrap();
        let fid = state
            .store
            .lock()
            .await
            .ensure_folder("a1", "INBOX")
            .unwrap();
        state
            .store
            .lock()
            .await
            .upsert_message(
                fid,
                &NewMessageMeta {
                    uid: 7,
                    message_id: None,
                    subject: Some("s".into()),
                    from_addr: None,
                    to_addrs: None,
                    date_unix: None,
                    size: None,
                    flags: vec![],
                    has_attachments: false,
                    snippet: None,
                },
                now_unix(),
            )
            .unwrap();
        let arc = Arc::new(state);
        let v = update_message_impl(
            arc.clone(),
            "a1".into(),
            fid,
            7,
            MessagePatchInput {
                seen: Some(true),
                starred: Some(true),
                archived: None,
            },
        )
        .await
        .unwrap();
        assert!(v.flags.iter().any(|f| f == "\\Seen"));
        assert!(v.flags.iter().any(|f| f == "\\Flagged"));
        let msgs = arc.store.lock().await.list_messages(fid, 10).unwrap();
        assert_eq!(msgs[0].flags.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
