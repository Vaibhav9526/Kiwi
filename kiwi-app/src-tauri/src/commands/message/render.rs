//! Sanitized HTML render + remote-content toggle (T-146). `ammonia` with
//! a strict allowlist — scripts, forms, iframes, remote styles and remote
//! `img` sources never reach the webview. Remote content is opt-in per
//! account (`remote_content_allowed`, default false, audited).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tauri::State;

use super::super::{bounded, gate, run_mail_io};
use crate::commands::mail::load_body_raw;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{RemoteContentView, RenderedBodyView};

/// Rendered HTML output cap (post-sanitize) — keeps the webview bounded.
const MAX_RENDER_BYTES: usize = 8 * 1024 * 1024;

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
