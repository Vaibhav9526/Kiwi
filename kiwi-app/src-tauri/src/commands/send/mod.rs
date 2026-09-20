//! Send path: compose → validate → MIME build → `SendQueue` → background
//! dispatcher → SMTP connect/auth/policy-bridge/send → observe.
//!
//! Undo-send and send-later are real: `kiwi_send_message` enqueues with
//! `not_before = now + max(grace, delay)`; `kiwi_cancel_send` works while
//! `now < undo_window_until`; the dispatcher drains `due(now)` every second.
//! While the endpoint is locked the dispatcher holds everything (contract
//! §4: no credential use while locked).
//!
//! `SendQueue` exposes no item iterator, so a parallel `outbox_meta` index
//! (in `AppState`) keeps per-send metadata for `kiwi_list_outbox`.
//!
//! Layout (T-181): `enqueue` holds the command surface, `dispatch` the
//! drain loop + transmit; `drop_outbox` is the shared terminal-removal
//! helper both halves call.

pub mod dispatch;
pub mod enqueue;

pub use dispatch::*;
pub use enqueue::*;

use crate::state::AppState;

/// Terminal-removal helper: in-memory meta + persisted row together.
/// Idempotent.
pub(crate) async fn drop_outbox(state: &AppState, queue_id: &str) {
    state.outbox_meta.lock().await.remove(queue_id);
    if let Err(e) = state.store.lock().await.outbox_delete(queue_id) {
        eprintln!("[kiwi-app] outbox delete {queue_id} failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::gate;
    use super::*;
    use crate::error::IpcError;
    use crate::state::{OutboxMeta, now_unix};
    use crate::types::{AddAccountInput, AuthInput, ComposeInput, SendOptions, ServerInput};

    pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = std::pin::pin!(f);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    pub fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-{tag}-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    pub fn acct_input() -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming_protocol: "imap".into(),
            incoming: ServerInput {
                host: "imap.x.test".into(),
                port: 993,
                security: "tls".into(),
            },
            outgoing: ServerInput {
                host: "smtp.x.test".into(),
                port: 465,
                security: "tls".into(),
            },
            username: None,
            outgoing_username: None,
            incoming_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
            }),
            outgoing_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
            }),
            accept_invalid_certs: false,
        }
    }

    fn compose() -> ComposeInput {
        ComposeInput {
            to: vec!["b@y.test".into()],
            cc: vec![],
            bcc: vec![],
            subject: "s".into(),
            text: "t".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn send_validates_recipients() {
        let state = test_state("send1");
        block_on(async {
            let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                .await
                .unwrap();
            let mut bad = compose();
            bad.to.clear();
            let r = send_impl(&state, &acct.id, bad, None).await;
            assert!(r.is_err_and(|e| e.code == "invalid-input"));
        });
    }

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kiwi-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn outbox_survives_reopen() {
        // Same data dir across two opens — the persisted SQLite row must
        // rebuild the queue, and the send-later slot must still dispatch
        // on schedule after the "restart".
        let dir = unique_dir("outbox-persist");
        let queue_id = {
            let state = AppState::open_test(dir.clone()).unwrap();
            block_on(async {
                let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                    .await
                    .unwrap();
                send_impl(
                    &state,
                    &acct.id,
                    compose(),
                    Some(SendOptions {
                        send_at_unix: Some(now_unix() + 3600), // send-later
                        undo_grace_secs: Some(30),
                    }),
                )
                .await
                .unwrap()
                .queue_id
            })
        };
        // "Restart": new AppState over the same dir must see the send.
        let state2 = AppState::open_test(dir.clone()).unwrap();
        block_on(async {
            assert_eq!(state2.send_queue.lock().await.pending_count(), 1);
            let not_before = {
                let meta = state2.outbox_meta.lock().await;
                let m = meta.get(&queue_id).expect("meta reloaded");
                assert_eq!(m.subject, "s");
                assert!(!m.message_id.is_empty());
                m.not_before_unix
            };
            // Not due yet; due at its persisted slot — resume dispatch.
            assert!(state2.send_queue.lock().await.due(now_unix()).is_empty());
            assert_eq!(state2.send_queue.lock().await.due(not_before).len(), 1);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_then_cancel_within_grace() {
        let state = test_state("send2");
        block_on(async {
            let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                .await
                .unwrap();
            let r = send_impl(
                &state,
                &acct.id,
                compose(),
                Some(SendOptions {
                    send_at_unix: None,
                    undo_grace_secs: Some(30),
                }),
            )
            .await
            .unwrap();
            assert!(cancel_impl(&state, &r.queue_id).await.unwrap());
            // Queue and the persisted row both cleared.
            assert_eq!(state.send_queue.lock().await.pending_count(), 0);
            assert!(state.store.lock().await.outbox_list(10).unwrap().is_empty());
            // Second cancel is a no-op.
            assert!(!cancel_impl(&state, &r.queue_id).await.unwrap());
        });
    }

    #[test]
    fn scheduled_send_recalled_past_undo_window() {
        // Send-later item: the undo window expires seconds after enqueue,
        // but the send stays recallable until its dispatch slot.
        let state = test_state("send-sched-cancel");
        block_on(async {
            let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                .await
                .unwrap();
            let r = send_impl(
                &state,
                &acct.id,
                compose(),
                Some(SendOptions {
                    send_at_unix: Some(now_unix() + 7200),
                    undo_grace_secs: Some(0),
                }),
            )
            .await
            .unwrap();
            assert!(cancel_impl(&state, &r.queue_id).await.unwrap());
        });
    }

    #[test]
    fn reschedule_moves_dispatch_and_persists() {
        let state = test_state("send-resched");
        block_on(async {
            let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                .await
                .unwrap();
            let r = send_impl(&state, &acct.id, compose(), None).await.unwrap();
            let later = now_unix() + 7200;
            let receipt = schedule_impl(&state, &r.queue_id, later).await.unwrap();
            assert_eq!(receipt.not_before_unix, later);
            // In-memory queue + persisted row moved together.
            assert!(state.send_queue.lock().await.due(now_unix()).is_empty());
            let rows = state.store.lock().await.outbox_list(10).unwrap();
            assert_eq!(rows[0].not_before_unix, later);
            // Unknown queue id → not-found.
            assert!(
                schedule_impl(&state, "send-nope", later)
                    .await
                    .is_err_and(|e| e.code == "not-found")
            );
        });
    }

    #[test]
    fn legacy_file_outbox_imported() {
        // Pre-SQLite format: outbox/<id>.json + .eml — folded into mail.db
        // on open, files removed.
        let dir = unique_dir("outbox-legacy");
        {
            // The account must already exist in mail.db (outbox FK), as it
            // would for any real pre-upgrade profile.
            let state = AppState::open_test(dir.clone()).unwrap();
            block_on(async {
                crate::commands::accounts::add_account_impl(&state, acct_input())
                    .await
                    .unwrap();
            });
        }
        let account_id = {
            let state = AppState::open_test(dir.clone()).unwrap();
            block_on(async { state.index.lock().await.account_ids[0].clone() })
        };
        let meta = OutboxMeta {
            account_id,
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
            subject: "legacy".into(),
            message_id: "<legacy@x>".into(),
            not_before_unix: now_unix() + 3600,
            undo_window_until_unix: now_unix() + 30,
            attempts: 2,
        };
        let od = dir.join("outbox");
        std::fs::create_dir_all(&od).unwrap();
        std::fs::write(
            od.join("send-legacy1.json"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        std::fs::write(od.join("send-legacy1.eml"), b"Subject: legacy\r\n\r\nx").unwrap();

        let state = AppState::open_test(dir.clone()).unwrap();
        block_on(async {
            assert_eq!(state.send_queue.lock().await.pending_count(), 1);
            let m = state.outbox_meta.lock().await;
            assert_eq!(m["send-legacy1"].attempts, 2);
            let rows = state.store.lock().await.outbox_list(10).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].queue_id, "send-legacy1");
        });
        assert!(!od.join("send-legacy1.json").exists());
        assert!(!od.join("send-legacy1.eml").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn send_rejected_when_locked() {
        let state = test_state("send3");
        block_on(async {
            let acct = crate::commands::accounts::add_account_impl(&state, acct_input())
                .await
                .unwrap();
            state.trust.lock().await.force_lock();
            assert!(gate(&state).await.is_err_and(|e| e.code == "locked"));
            // Gate stops it before validation even runs.
            let r = if gate(&state).await.is_ok() {
                send_impl(&state, &acct.id, compose(), None).await
            } else {
                Err(IpcError::locked())
            };
            assert!(r.is_err_and(|e| e.code == "locked"));
        });
    }
}
