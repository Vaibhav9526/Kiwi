//! T-341 conversation mute (Thunderbird "Ignore Thread").
//!
//! A mute hides a conversation from *counts* and from new-mail notifications.
//! It never moves, flags, or deletes mail, and it never touches the server —
//! it is purely a local presentation decision, reversible at any time.
//!
//! ## The conversation id
//!
//! `conversationId` is the list view's own thread key: the two lines
//! `"<accountId>"`, `"<normalized subject>"` joined by a single `\n` — exactly
//! what `kiwi-app/src/threading.ts::buildThreads` puts in `Thread.key` and what
//! the message-list context menu already holds. Accepting that shape means the
//! UI needs no new grouping logic and, more importantly, that **the set the
//! store suppresses is the set the user is looking at**. The store re-derives
//! the key through the same `kiwi_mail::threading::normalize_subject`, so a
//! renderer cannot smuggle in a key that does not match the visible grouping.
//!
//! Honest limitation, carried from `kiwi-mail/src/threading.rs`: this is
//! subject-folding, not RFC 5322 `References` threading. Two unrelated mails
//! sharing a stripped subject mute together, and a reply with a deviating
//! subject is a new conversation. That is exactly how the list already draws
//! threads, so the mute is consistent with the screen — but it is weaker than
//! real threading, and the key must move to the root Message-ID when the IPC
//! exposes `In-Reply-To`/`References`.

use std::sync::Arc;

use tauri::State;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::ThreadMuteView;

/// Bound on the whole `conversationId`. It carries an account id plus a folded
/// subject, so this is generous but still finite.
const MAX_CONVERSATION_ID: usize = 640;

/// Split `"<accountId>\n<normalized subject>"` into its two parts.
///
/// Fails closed rather than guessing: a missing separator, an empty account,
/// or a subject that does not survive normalization is `invalid-input`, never
/// a silently-wrong conversation.
fn split_conversation_id(raw: &str) -> CmdResult<(String, String)> {
    let Some((account_id, subject)) = raw.split_once('\n') else {
        return Err(IpcError::invalid(
            "conversationId must be \"<accountId>\\n<normalizedSubject>\"",
        ));
    };
    bounded("accountId", account_id, 128)?;
    // The stored key is the normalized subject, re-derived here so the value
    // persisted is the canonical one rather than whatever the caller typed.
    let key = kiwi_mail::threading::normalize_subject(subject).ok_or_else(|| {
        IpcError::invalid("conversationId carries no conversation (empty subject)")
    })?;
    if key.len() > kiwi_mail::store::MAX_CONVERSATION_KEY_LEN {
        return Err(IpcError::invalid("conversationId subject is too long"));
    }
    Ok((account_id.to_string(), key))
}

/// `kiwi_thread_set_muted(conversationId, muted)` -> `ThreadMuteView` **[gated]**
///
/// Mute or unmute one conversation. While muted, the conversation's messages
/// are excluded from folder unseen counts (and therefore from the derived
/// smart-folder badges) and never raise a new-mail OS notification. Unmuting
/// restores both immediately.
///
/// Local-only and audited: `thread-muted` / `thread-unmuted` record the account
/// and the conversation key, never a subject line or message id.
#[tauri::command]
pub async fn kiwi_thread_set_muted(
    state: State<'_, Arc<AppState>>,
    conversation_id: String,
    muted: bool,
) -> CmdResult<ThreadMuteView> {
    gate(state.inner()).await?;
    thread_set_muted_impl(state.inner(), &conversation_id, muted).await
}

pub(crate) async fn thread_set_muted_impl(
    state: &AppState,
    conversation_id: &str,
    muted: bool,
) -> CmdResult<ThreadMuteView> {
    // Length-bound only: the `\n` inside the composite id IS the documented
    // separator, so the blanket control-char sweep in `bounded` would reject
    // every legitimate key. Each side is validated after the split.
    if conversation_id.len() > MAX_CONVERSATION_ID {
        return Err(IpcError::invalid(format!(
            "conversationId exceeds {MAX_CONVERSATION_ID} bytes"
        )));
    }
    let (account_id, key) = split_conversation_id(conversation_id)?;
    let now = now_unix();

    // A mute is scoped to a real account: an unknown account id is not-found
    // rather than a mute that silently suppresses nothing.
    let changed = {
        let store = state.store.lock().await;
        if store.get_account(&account_id)?.is_none() {
            return Err(IpcError::not_found("unknown account"));
        }
        let was = store.is_conversation_muted(&account_id, &key)?;
        // Write only on a real transition, so a redundant call is a genuine
        // no-op and `changed` stays honest.
        let changed = was != muted;
        if changed {
            store.set_conversation_muted(&account_id, &key, muted, now)?;
        }
        changed
    };

    // Audited AFTER the effect: a mute is trivially reversible, and the row is
    // the record of what the store now holds. The key is an opaque
    // conversation identifier, not message text.
    state.audit.lock().await.record(
        if muted {
            "thread-muted"
        } else {
            "thread-unmuted"
        },
        &format!("{account_id} conversation={key} changed={changed}"),
        now,
    )?;

    Ok(ThreadMuteView {
        conversation_id: conversation_id.to_string(),
        account_id,
        muted,
        changed,
    })
}

/// `kiwi_thread_list_muted(accountId)` -> `String[]` **[gated]**
///
/// The account's muted conversation keys, sorted. The list view uses this to
/// render a muted thread as muted instead of guessing from a client cache.
#[tauri::command]
pub async fn kiwi_thread_list_muted(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<Vec<String>> {
    gate(state.inner()).await?;
    thread_list_muted_impl(state.inner(), &account_id).await
}

pub(crate) async fn thread_list_muted_impl(
    state: &AppState,
    account_id: &str,
) -> CmdResult<Vec<String>> {
    bounded("accountId", account_id, 128)?;
    let store = state.store.lock().await;
    if store.get_account(account_id)?.is_none() {
        return Err(IpcError::not_found("unknown account"));
    }
    store
        .muted_conversation_keys(account_id)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_mail::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use kiwi_mail::store::NewMessageMeta;
    use kiwi_mail::transport::SocketSecurity;

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-thread-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn account(id: &str) -> MailAccount {
        MailAccount {
            account_id: id.into(),
            display_name: id.into(),
            email: format!("{id}@x.test"),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: format!("{id}@x.test"),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: format!("{id}@x.test"),
            },
        }
    }

    fn meta(uid: u64, subject: &str, seen: bool) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some(subject.into()),
            from_addr: Some("a@x".into()),
            to_addrs: None,
            date_unix: Some(1_758_000_000),
            size: Some(10),
            flags: if seen { vec!["\\Seen".into()] } else { vec![] },
            has_attachments: false,
            snippet: None,
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    /// a1/INBOX: two unseen "Deploy" (one a `Re:`) + one unseen "Invoice".
    async fn seeded(tag: &str) -> (Arc<AppState>, std::path::PathBuf, i64) {
        let dir = test_dir(tag);
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let fid = {
            let store = state.store.lock().await;
            store.upsert_account(&account("a1")).unwrap();
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            store
                .upsert_message(fid, &meta(1, "Deploy", false), 1)
                .unwrap();
            store
                .upsert_message(fid, &meta(2, "Re: Deploy", false), 1)
                .unwrap();
            store
                .upsert_message(fid, &meta(3, "Invoice", false), 1)
                .unwrap();
            fid
        };
        (state, dir, fid)
    }

    /// The headline roundtrip: mute -> counts drop -> unmute -> counts restore.
    #[tokio::test(flavor = "current_thread")]
    async fn mute_drops_unseen_and_unmute_restores() {
        let (state, dir, fid) = seeded("roundtrip").await;
        assert_eq!(
            state.store.lock().await.folder_stats(fid).unwrap().unseen,
            3,
            "3 unseen at rest"
        );

        // The conversation id is the list view's own thread key.
        let conversation = "a1\ndeploy";
        let muted = thread_set_muted_impl(&state, conversation, true)
            .await
            .unwrap();
        assert!(muted.muted && muted.changed);
        assert_eq!(muted.account_id, "a1");
        assert_eq!(
            state.store.lock().await.folder_stats(fid).unwrap().unseen,
            1,
            "both Deploy mails left the unseen count"
        );

        let restored = thread_set_muted_impl(&state, conversation, false)
            .await
            .unwrap();
        assert!(!restored.muted && restored.changed);
        assert_eq!(
            state.store.lock().await.folder_stats(fid).unwrap().unseen,
            3,
            "unmute restored the count"
        );

        // Both transitions are audited with the opaque key, never a subject.
        let log = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("thread-muted"));
        assert!(log.contains("thread-unmuted"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redundant_mute_reports_no_change() {
        let (state, dir, _) = seeded("idempotent").await;
        let first = thread_set_muted_impl(&state, "a1\ndeploy", true)
            .await
            .unwrap();
        assert!(first.changed);
        let again = thread_set_muted_impl(&state, "a1\ndeploy", true)
            .await
            .unwrap();
        assert!(again.muted && !again.changed, "a repeat is a real no-op");
        // Unmuting something already unmuted is likewise a no-op, not an error.
        let noop = thread_set_muted_impl(&state, "a1\ninvoice", false)
            .await
            .unwrap();
        assert!(!noop.changed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_malformed_or_foreign_conversation_id_fails_closed() {
        let (state, dir, _) = seeded("failclosed").await;
        // No separator -> cannot be a conversation key.
        let e = thread_set_muted_impl(&state, "a1deploy", true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid-input");
        // Subject that normalizes to nothing -> no conversation exists.
        let e = thread_set_muted_impl(&state, "a1\n   ", true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid-input");
        // A syntactically fine id for an account that does not exist.
        let e = thread_set_muted_impl(&state, "nope\ndeploy", true)
            .await
            .unwrap_err();
        assert_eq!(e.code, "not-found");
        // The renderer cannot smuggle a raw subject past normalization: the
        // stored key is always the normalized one.
        thread_set_muted_impl(&state, "a1\nRe: [dev] DEPLOY", true)
            .await
            .unwrap();
        assert_eq!(
            thread_list_muted_impl(&state, "a1").await.unwrap(),
            vec!["deploy"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mute_is_lock_gated() {
        let (state, dir, _) = seeded("locked").await;
        state.trust.lock().await.force_lock();
        // Prove the exact check the command runs refuses while locked.
        let e = gate(&state).await.unwrap_err();
        assert_eq!(e.code, "locked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn listing_mutes_is_account_scoped_and_sorted() {
        let (state, dir, _) = seeded("list").await;
        {
            let store = state.store.lock().await;
            store.upsert_account(&account("a2")).unwrap();
        }
        thread_set_muted_impl(&state, "a1\nzeta", true)
            .await
            .unwrap();
        thread_set_muted_impl(&state, "a1\nalpha", true)
            .await
            .unwrap();
        assert_eq!(
            thread_list_muted_impl(&state, "a1").await.unwrap(),
            vec!["alpha", "zeta"],
            "sorted for a stable UI order"
        );
        assert!(
            thread_list_muted_impl(&state, "a2")
                .await
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
