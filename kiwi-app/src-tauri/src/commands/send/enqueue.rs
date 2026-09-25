//! Enqueue-side commands: compose → validate → MIME build → `SendQueue`,
//! plus undo-send (`cancel`), send-later reschedule, and the outbox
//! listing. Dispatch lives in `dispatch.rs`.

use std::sync::Arc;

use base64::Engine;
use tauri::State;

use kiwi_mail::mime::{Addr, OutboundAttachment, OutboundMessage, build_message};
use kiwi_mail::smtp::{QueuedSend, SendRequest};

use super::super::{bounded, gate, valid_addr};
use super::drop_outbox;
use crate::error::{CmdResult, IpcError};
use crate::state::{
    AppState, MAX_OUTBOX_ITEM_BYTES, OutboxClass, OutboxMeta, new_id, now_unix, outbox_row_of,
};
use crate::types::{ComposeInput, OutboxItem, SendOptions, SendReceipt};

const MAX_RECIPIENTS: usize = 100;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_ATTACH_TOTAL: usize = 25 * 1024 * 1024;

/// Enqueue a message. The dispatcher sends it when due — after the undo
/// grace window and any send-later delay.
#[tauri::command]
pub async fn kiwi_send_message(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    message: ComposeInput,
    options: Option<SendOptions>,
) -> CmdResult<SendReceipt> {
    gate(state.inner()).await?;
    send_impl(state.inner(), &account_id, message, options).await
}

pub(crate) async fn send_impl(
    state: &AppState,
    account_id: &str,
    message: ComposeInput,
    options: Option<SendOptions>,
) -> CmdResult<SendReceipt> {
    send_impl_class(
        state,
        account_id,
        message,
        options,
        OutboxClass::Ordinary,
    )
    .await
}

pub(crate) async fn send_impl_class(
    state: &AppState,
    account_id: &str,
    message: ComposeInput,
    options: Option<SendOptions>,
    class: OutboxClass,
) -> CmdResult<SendReceipt> {
    bounded("accountId", account_id, 128)?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;

    // --- validate ------------------------------------------------------------
    let all_rcpts: Vec<String> = message
        .to
        .iter()
        .chain(&message.cc)
        .chain(&message.bcc)
        .cloned()
        .collect();
    if all_rcpts.is_empty() {
        return Err(IpcError::invalid("at least one recipient required"));
    }
    if all_rcpts.len() > MAX_RECIPIENTS {
        return Err(IpcError::invalid("too many recipients"));
    }
    for (i, r) in all_rcpts.iter().enumerate() {
        valid_addr(&format!("recipient[{i}]"), r)?;
    }
    bounded("subject", &message.subject, 998)?;
    bounded("text", &message.text, MAX_BODY)?;
    if let Some(h) = &message.html {
        bounded("html", h, MAX_BODY)?;
    }
    for (i, r) in message.references.iter().enumerate() {
        bounded(&format!("references[{i}]"), r, 256)?;
    }
    if let Some(r) = &message.in_reply_to {
        bounded("inReplyTo", r, 256)?;
    }

    let mut total_attach = 0usize;
    let mut attachments = Vec::new();
    for (i, a) in message.attachments.iter().enumerate() {
        bounded(&format!("attachments[{i}].filename"), &a.filename, 256)?;
        bounded(
            &format!("attachments[{i}].contentType"),
            &a.content_type,
            128,
        )?;
        // Bound the *encoded* size first, then the decoded.
        if a.data_b64.len() > (MAX_ATTACH_TOTAL * 4) / 3 + 8 {
            return Err(IpcError::invalid(format!("attachments[{i}] too large")));
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(a.data_b64.as_bytes())
            .map_err(|_| IpcError::invalid(format!("attachments[{i}].dataB64 invalid")))?;
        total_attach += data.len();
        if total_attach > MAX_ATTACH_TOTAL {
            return Err(IpcError::invalid("total attachments exceed 25 MiB"));
        }
        attachments.push(OutboundAttachment {
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            data,
        });
    }

    // --- build MIME (validates serialization now, not at dispatch) ------------
    let outbound = OutboundMessage {
        from: Addr {
            name: if acct.display_name.is_empty() {
                None
            } else {
                Some(acct.display_name.clone())
            },
            email: acct.email.clone(),
        },
        to: message
            .to
            .iter()
            .map(|e| Addr {
                name: None,
                email: e.clone(),
            })
            .collect(),
        cc: message
            .cc
            .iter()
            .map(|e| Addr {
                name: None,
                email: e.clone(),
            })
            .collect(),
        bcc: message
            .bcc
            .iter()
            .map(|e| Addr {
                name: None,
                email: e.clone(),
            })
            .collect(),
        subject: message.subject.clone(),
        text: message.text.clone(),
        html: message.html.clone(),
        in_reply_to: message.in_reply_to.clone(),
        references: message.references.clone(),
        attachments,
        date_unix: now_unix(),
        message_id: new_id("msg"),
    };
    let mime_bytes = build_message(&outbound).map_err(IpcError::from)?;

    // --- enqueue ---------------------------------------------------------------
    let opts = options.unwrap_or(SendOptions {
        send_at_unix: None,
        undo_grace_secs: None,
    });
    let grace = opts.undo_grace_secs.unwrap_or(10).clamp(0, 120) as i64;
    let now = now_unix();
    let delay = opts.send_at_unix.map(|t| (t - now).max(0)).unwrap_or(0);
    let not_before = now + delay.max(grace);
    let undo_until = now + grace;

    let queue_id = new_id("send");
    let meta = OutboxMeta {
        account_id: account_id.to_string(),
        from: acct.email.clone(),
        to: all_rcpts.clone(),
        subject: message.subject.clone(),
        message_id: outbound.message_id.clone(),
        not_before_unix: not_before,
        undo_window_until_unix: undo_until,
        attempts: 0,
        last_error: None,
        class,
    };
    if mime_bytes.len() > MAX_OUTBOX_ITEM_BYTES {
        return Err(IpcError::invalid("queued message exceeds 32 MiB"));
    }
    // Single-attempt class is durable BEFORE the outbox row exists: a crash
    // between the two must not resurrect the item as an ordinary retry.
    if class.is_single_attempt() {
        state.single_attempt.lock().await.mark(&queue_id)?;
    }
    // T-142: persist BEFORE enqueue — a crash between the two must not
    // lose a committed send. One row in mail.db's outbox table is the
    // atomic write (meta + MIME together).
    let row = outbox_row_of(&queue_id, &meta, mime_bytes, now);
    if let Err(e) = state.store.lock().await.outbox_put(&row) {
        if class.is_single_attempt() {
            let _ = state.single_attempt.lock().await.forget(&queue_id);
        }
        return Err(e.into());
    }
    state.send_queue.lock().await.enqueue(QueuedSend {
        queue_id: queue_id.clone(),
        request: SendRequest {
            from: row.from_addr.clone(),
            to: row.to_addrs.clone(),
            message: row.mime.clone(),
        },
        not_before_unix: row.not_before_unix,
        undo_window_until_unix: row.undo_window_until_unix,
        attempts: row.attempts,
    });
    state
        .outbox_meta
        .lock()
        .await
        .insert(queue_id.clone(), meta);
    state.audit.lock().await.record(
        "send-queued",
        &format!(
            "{queue_id} via {account_id}, {} recipient(s)",
            all_rcpts.len()
        ),
        now,
    )?;
    Ok(SendReceipt {
        queue_id,
        not_before_unix: not_before,
        undo_window_until_unix: undo_until,
    })
}

/// Undo-send / unschedule: cancel while the send is still recallable —
/// inside the undo window, or awaiting a future send-later slot.
#[tauri::command]
pub async fn kiwi_cancel_send(
    state: State<'_, Arc<AppState>>,
    queue_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    let cancelled = cancel_impl(state.inner(), &queue_id).await?;
    Ok(serde_json::json!({ "cancelled": cancelled }))
}

pub(crate) async fn cancel_impl(state: &AppState, queue_id: &str) -> CmdResult<bool> {
    bounded("queueId", queue_id, 128)?;
    let cancelled = state.send_queue.lock().await.cancel(queue_id, now_unix());
    if cancelled {
        drop_outbox(state, queue_id).await;
        state
            .audit
            .lock()
            .await
            .record("send-cancelled", queue_id, now_unix())?;
    }
    Ok(cancelled)
}

/// Send-later reschedule: move a pending send's dispatch time. Works on
/// anything still in the queue (grace-window item, scheduled send, or a
/// held retry). The undo window is untouched — rescheduling is not an
/// undo. Audited.
#[tauri::command]
pub async fn kiwi_schedule_send(
    state: State<'_, Arc<AppState>>,
    queue_id: String,
    send_at_unix: i64,
) -> CmdResult<SendReceipt> {
    gate(state.inner()).await?;
    schedule_impl(state.inner(), &queue_id, send_at_unix).await
}

pub(crate) async fn schedule_impl(
    state: &AppState,
    queue_id: &str,
    send_at_unix: i64,
) -> CmdResult<SendReceipt> {
    bounded("queueId", queue_id, 128)?;
    if !state
        .send_queue
        .lock()
        .await
        .reschedule(queue_id, send_at_unix)
    {
        return Err(IpcError::not_found("unknown or already-dispatched send"));
    }
    let (undo_until, attempts) = {
        let mut metas = state.outbox_meta.lock().await;
        match metas.get_mut(queue_id) {
            Some(m) => {
                m.not_before_unix = send_at_unix;
                // A manual reschedule recommits the send — a stale held
                // reason no longer describes intent (T-298).
                m.last_error = None;
                (m.undo_window_until_unix, m.attempts)
            }
            None => (0, 0),
        }
    };
    state
        .store
        .lock()
        .await
        .outbox_set_timing(queue_id, send_at_unix, attempts, None)?;
    state.audit.lock().await.record(
        "send-rescheduled",
        &format!("{queue_id} → {send_at_unix}"),
        now_unix(),
    )?;
    Ok(SendReceipt {
        queue_id: queue_id.to_string(),
        not_before_unix: send_at_unix,
        undo_window_until_unix: undo_until,
    })
}

/// Pending sends (envelope metadata only — bodies never leave this process
/// for a list view).
#[tauri::command]
pub async fn kiwi_list_outbox(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<OutboxItem>> {
    gate(state.inner()).await?;
    list_outbox_impl(state.inner()).await
}

/// Envelope-only list, separated for tests (T-298 state derivation).
pub(crate) async fn list_outbox_impl(state: &AppState) -> CmdResult<Vec<OutboxItem>> {
    let now = now_unix();
    let meta = state.outbox_meta.lock().await;
    Ok(meta
        .iter()
        .map(|(queue_id, m)| OutboxItem {
            queue_id: queue_id.clone(),
            account_id: Some(m.account_id.clone()),
            from: m.from.clone(),
            to: m.to.clone(),
            subject: m.subject.clone(),
            not_before_unix: m.not_before_unix,
            undo_window_until_unix: m.undo_window_until_unix,
            attempts: m.attempts,
            cancelable: now < m.undo_window_until_unix || now < m.not_before_unix,
            // T-298: `attempts > 0` means a prior dispatch failed and the
            // row only persists because retries remain → held. `sending`,
            // `sent`, and `cancelled` are never emitted: the first is a
            // transient invisible to persisted state, the rest drop the row.
            state: if m.attempts > 0 { "held" } else { "queued" }.to_string(),
            last_error: m.last_error.clone(),
        })
        .collect())
}
