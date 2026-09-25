//! Message actions (T-146 + T-163): flag mutation (read/star/archive),
//! batch delete/move, attachment download, sanitized HTML render,
//! per-account remote-content toggle.
//!
//! All commands are lock-gated and run through `run_mail_io` when they can
//! touch a live protocol client (IMAP flag/move write-through). Layout:
//! one submodule per surface — `update`, `delete`, `attachment`,
//! `render` — with the folder/uid-set helpers they share living here.

pub mod attachment;
pub mod delete;
pub mod junk;
pub mod render;
pub mod snooze;
pub mod unsubscribe;
pub mod update;

pub use attachment::*;
pub use delete::*;
pub use junk::*;
pub use render::*;
pub use snooze::*;
pub use unsubscribe::*;
pub use update::*;

use kiwi_mail::imap::ImapClient;

use crate::error::{CmdResult, IpcError};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Shared delete/move helpers — folder-scoped uid sets, Trash semantics
// ---------------------------------------------------------------------------

/// Conventional trash mailbox names (RFC 6154 \Trash special-use +
/// common vendor names) — matched case-insensitively.
const TRASH_NAMES: &[&str] = &[
    "trash",
    "deleted items",
    "deleted messages",
    "deleted",
    "bin",
    "papierkorb",
];
/// One delete/move call is bounded — uid sets come from the untrusted UI.
const MAX_MOVE_UIDS: usize = 500;

fn uid_set_of(uids: &[u64]) -> String {
    uids.iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn bounded_uids(uids: &[i64]) -> CmdResult<Vec<u64>> {
    if uids.is_empty() {
        return Err(IpcError::invalid("uids must be non-empty"));
    }
    if uids.len() > MAX_MOVE_UIDS {
        return Err(IpcError::invalid("uids exceeds 500 bound"));
    }
    let mut out = Vec::with_capacity(uids.len());
    for u in uids {
        if *u < 0 {
            return Err(IpcError::invalid("uid must be >= 0"));
        }
        out.push(*u as u64);
    }
    Ok(out)
}

/// Validate the folder exists and belongs to `account_id`; return its name.
async fn owned_folder(state: &AppState, account_id: &str, folder_id: i64) -> CmdResult<String> {
    let store = state.store.lock().await;
    let meta = store
        .folder_meta(folder_id)?
        .ok_or_else(|| IpcError::not_found("unknown folder"))?;
    if meta.account_id != account_id {
        return Err(IpcError::not_found("folder not on account"));
    }
    Ok(meta.name)
}

fn is_trash_name(name: &str) -> bool {
    TRASH_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// Resolve the account's Trash folder: local name match → live LIST for a
/// `\Trash` special-use flag → CREATE "Trash". Registers it in the sidecar
/// index either way. Returns `(folder_id, name)`.
async fn resolve_trash(
    state: &AppState,
    account_id: &str,
    client: Option<&mut ImapClient>,
) -> CmdResult<(i64, String)> {
    // 1. Local folders — known names only, no guessing at custom folders.
    {
        let store = state.store.lock().await;
        if let Some(f) = store
            .list_folders(account_id)?
            .into_iter()
            .find(|f| is_trash_name(&f.name))
        {
            return Ok((f.id, f.name));
        }
    }
    // 2. IMAP: prefer the server's \Trash flag over a name guess; no match
    //    → CREATE "Trash" (idempotent — a NO answer means it exists).
    let mut name = "Trash".to_string();
    if let Some(c) = client
        && let Ok(listed) = c.list("", "*").await
    {
        match listed.iter().find(|m| {
            m.flags.iter().any(|fl| fl.eq_ignore_ascii_case("\\Trash")) || is_trash_name(&m.name)
        }) {
            Some(m) => name = m.name.clone(),
            None => {
                let _ = c.create_mailbox("Trash").await;
            }
        }
    }
    let store = state.store.lock().await;
    let id = store.ensure_folder(account_id, &name)?;
    drop(store);
    let mut index = state.index.lock().await;
    index.remember_folder(account_id, id, &name);
    index.save(&state.data_dir)?;
    Ok((id, name))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::now_unix;
    use kiwi_mail::account::IncomingProtocol;
    use kiwi_mail::store::NewMessageMeta;
    use std::sync::Arc;

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
    fn render_cap_is_bytes_and_never_splits_a_char() {
        // Multibyte-heavy payload: 4-byte emoji past a small cap. The old
        // `chars().take(n)` counted *characters* and could emit n chars ×
        // up to 4 bytes — far over the documented 8 MiB byte cap.
        let s: String = "\u{1F600}".repeat(10);
        let capped = render::truncate_to_byte_cap(s.clone(), 9);
        assert!(capped.len() <= 9);
        assert_eq!(capped.len(), 8, "2 emoji × 4B — third doesn't fit");
        let capped = render::truncate_to_byte_cap("ab€cd".to_string(), 4);
        assert_eq!(capped, "ab", "€ spans bytes 2..5 — dropped, never split");
        let capped = render::truncate_to_byte_cap("ab€cd".to_string(), 5);
        assert_eq!(capped, "ab€", "€ fits exactly at cap 5");
        // Under-cap input returns unchanged.
        assert_eq!(render::truncate_to_byte_cap(s, 100).len(), 40);
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
                    category: Default::default(),
                    unsub_http: None,
                    unsub_mailto: None,
                    unsub_oneclick: false,
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
            crate::types::MessagePatchInput {
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

    // -- T-163 delete/move -------------------------------------------------

    /// POP3 account fixture — no live connection is attempted (local-only).
    fn pop3_state(tag: &str) -> (Arc<AppState>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-del-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = AppState::open_test(dir.clone()).unwrap();
        (Arc::new(state), dir)
    }

    async fn seed_pop3(state: &AppState) -> i64 {
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
        for uid in [1u64, 2, 3] {
            state
                .store
                .lock()
                .await
                .upsert_message(
                    fid,
                    &NewMessageMeta {
                        uid,
                        message_id: None,
                        subject: Some(format!("m{uid}")),
                        from_addr: None,
                        to_addrs: None,
                        date_unix: None,
                        size: None,
                        flags: vec![],
                        has_attachments: false,
                        snippet: None,
                        category: Default::default(),
                        unsub_http: None,
                        unsub_mailto: None,
                        unsub_oneclick: false,
                    },
                    now_unix(),
                )
                .unwrap();
        }
        fid
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_soft_moves_to_trash() {
        let (state, dir) = pop3_state("soft");
        let fid = seed_pop3(&state).await;
        let v = delete_messages_impl(state.clone(), "a1".into(), fid, vec![1, 2], None)
            .await
            .unwrap();
        assert_eq!(v.moved_to_trash, 2);
        assert_eq!(v.deleted, 0);
        let trash_id = v.trash_folder_id.unwrap();
        assert_eq!(v.uid_map.len(), 2);
        let store = state.store.lock().await;
        assert_eq!(store.folder_uids(fid).unwrap(), vec![3]);
        assert_eq!(store.folder_uids(trash_id).unwrap().len(), 2);
        // Trash got registered in the sidecar index for folder views.
        drop(store);
        assert!(
            state
                .index
                .lock()
                .await
                .folders
                .get("a1")
                .unwrap()
                .iter()
                .any(|e| e.id == trash_id)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_from_trash_expunges_permanently() {
        let (state, dir) = pop3_state("hard");
        let fid = seed_pop3(&state).await;
        // Trash exists locally → delete from it is the empty-trash path.
        let trash = state
            .store
            .lock()
            .await
            .ensure_folder("a1", "Trash")
            .unwrap();
        state
            .store
            .lock()
            .await
            .move_messages(fid, trash, &[1, 2])
            .unwrap();
        let trash_uids: Vec<i64> = state
            .store
            .lock()
            .await
            .folder_uids(trash)
            .unwrap()
            .iter()
            .map(|u| *u as i64)
            .collect();
        let v = delete_messages_impl(state.clone(), "a1".into(), trash, trash_uids, None)
            .await
            .unwrap();
        assert_eq!(v.deleted, 2);
        assert_eq!(v.moved_to_trash, 0);
        assert!(
            state
                .store
                .lock()
                .await
                .folder_uids(trash)
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_permanent_flag_skips_trash() {
        let (state, dir) = pop3_state("perm");
        let fid = seed_pop3(&state).await;
        let v = delete_messages_impl(state.clone(), "a1".into(), fid, vec![1], Some(true))
            .await
            .unwrap();
        assert_eq!(v.deleted, 1);
        assert!(v.trash_folder_id.is_none());
        assert_eq!(
            state.store.lock().await.folder_uids(fid).unwrap(),
            vec![2, 3]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn move_messages_guards_and_happy_path() {
        let (state, dir) = pop3_state("move");
        let fid = seed_pop3(&state).await;
        let dst = state
            .store
            .lock()
            .await
            .ensure_folder("a1", "Work")
            .unwrap();

        // src == dst → invalid.
        assert!(
            move_messages_impl(state.clone(), "a1".into(), fid, fid, vec![1])
                .await
                .is_err()
        );
        // dst on ANOTHER account → cross-account guard (not-found).
        let other = {
            let store = state.store.lock().await;
            let mut acct = store.get_account("a1").unwrap().unwrap();
            acct.account_id = "a2".into();
            store.upsert_account(&acct).unwrap();
            store.ensure_folder("a2", "Elsewhere").unwrap()
        };
        let err = move_messages_impl(state.clone(), "a1".into(), fid, other, vec![1])
            .await
            .unwrap_err();
        assert_eq!(err.code, "not-found");
        // src still intact — nothing moved.
        assert_eq!(state.store.lock().await.folder_uids(fid).unwrap().len(), 3);

        // Happy path: 1,3 → Work under fresh dst uids.
        let v = move_messages_impl(state.clone(), "a1".into(), fid, dst, vec![1, 3])
            .await
            .unwrap();
        assert_eq!(v.moved, 2);
        assert_eq!(v.uid_map.len(), 2);
        assert!(v.uid_map.values().all(|u| *u > 0));
        assert_eq!(state.store.lock().await.folder_uids(fid).unwrap(), vec![2]);
        assert_eq!(state.store.lock().await.folder_uids(dst).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_uids_validates() {
        assert!(bounded_uids(&[]).is_err());
        assert!(bounded_uids(&[-1]).is_err());
        assert!(bounded_uids(&vec![1i64; 501]).is_err());
        assert_eq!(bounded_uids(&[0, 7]).unwrap(), vec![0, 7]);
    }
}
