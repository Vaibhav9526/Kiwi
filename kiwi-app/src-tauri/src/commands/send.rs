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

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tauri::{Emitter, Manager, State};

use kiwi_core::session::{AuthMechanism, Protocol};
use kiwi_mail::mime::{Addr, OutboundAttachment, OutboundMessage, build_message};
use kiwi_mail::smtp::{QueuedSend, SendRequest, SmtpAuth, SmtpClient, SmtpConfig};
use kiwi_mail::transport::{TlsSettings, Transport};

use super::{bounded, gate, resolve_secret, run_mail_io, valid_addr};
use crate::bridge;
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, OutboxMeta, new_id, now_unix};
use crate::types::{ComposeInput, OutboxEvent, OutboxItem, SendOptions, SendReceipt};

const MAX_RECIPIENTS: usize = 100;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_ATTACH_TOTAL: usize = 25 * 1024 * 1024;
const MAX_ATTEMPTS: u32 = 5;

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
    };
    // T-142: persist BEFORE enqueue — a crash between the two must not
    // lose a committed send.
    crate::state::persist_outbox_item(&state.data_dir, &queue_id, &meta, &mime_bytes)?;
    state.send_queue.lock().await.enqueue(QueuedSend {
        queue_id: queue_id.clone(),
        request: SendRequest {
            from: acct.email.clone(),
            to: all_rcpts.clone(),
            message: mime_bytes,
        },
        not_before_unix: not_before,
        undo_window_until_unix: undo_until,
        attempts: 0,
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

/// Undo-send: cancel while still inside the grace window.
#[tauri::command]
pub async fn kiwi_cancel_send(
    state: State<'_, Arc<AppState>>,
    queue_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    bounded("queueId", &queue_id, 128)?;
    let cancelled = state
        .inner()
        .send_queue
        .lock()
        .await
        .cancel(&queue_id, now_unix());
    if cancelled {
        drop_outbox(state.inner(), &queue_id).await;
        state
            .inner()
            .audit
            .lock()
            .await
            .record("send-cancelled", &queue_id, now_unix())?;
    }
    Ok(serde_json::json!({ "cancelled": cancelled }))
}

/// Terminal-removal helper: in-memory meta + persisted files together.
/// Idempotent.
pub(crate) async fn drop_outbox(state: &AppState, queue_id: &str) {
    state.outbox_meta.lock().await.remove(queue_id);
    crate::state::remove_outbox_item(&state.data_dir, queue_id);
}

/// Pending sends (envelope metadata only — bodies never leave this process
/// for a list view).
#[tauri::command]
pub async fn kiwi_list_outbox(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<OutboxItem>> {
    gate(state.inner()).await?;
    let now = now_unix();
    let meta = state.inner().outbox_meta.lock().await;
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
            cancelable: now < m.undo_window_until_unix,
        })
        .collect())
}

/// Force-drain: send everything pending now (skips remaining grace —
/// "send now" is an explicit user action).
#[tauri::command]
pub async fn kiwi_flush_outbox(state: State<'_, Arc<AppState>>) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    let state = state.inner().clone();
    let due = state.send_queue.lock().await.due(i64::MAX);
    let mut sent = 0u32;
    let mut failed = 0u32;
    let mut held = 0u32;
    for item in due {
        let queue_id = item.queue_id.clone();
        let meta = state.outbox_meta.lock().await.get(&queue_id).cloned();
        let outcome = deliver(state.clone(), item, meta).await;
        match outcome {
            Delivered::Sent => {
                drop_outbox(&state, &queue_id).await;
                sent += 1;
            }
            Delivered::Held => held += 1, // already re-enqueued inside deliver
            Delivered::Blocked | Delivered::Failed => {
                // Blocked is already audited inside deliver_inner.
                drop_outbox(&state, &queue_id).await;
                failed += 1;
            }
        }
    }
    Ok(serde_json::json!({ "sent": sent, "failed": failed, "held": held }))
}

// ---------------------------------------------------------------------------
// Dispatcher — runs inside the Tauri runtime, spawned from setup().
// ---------------------------------------------------------------------------

/// Outcome of one dispatch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    Sent,
    /// Policy bridge unreachable or transport failure — requeue with
    /// backoff while attempts remain (fail closed for policy per §10).
    Held,
    /// Policy `block` — dropped, audited, never transmitted.
    Blocked,
    /// Terminal failure (unknown account, invalid state, max attempts).
    Failed,
}

/// Background drain loop — spawned once from `run()`'s setup hook.
pub async fn outbox_loop(app: tauri::AppHandle) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let state = app.state::<Arc<AppState>>().inner().clone();
        // Locked endpoint: hold everything — no credential use while locked.
        if state.trust.lock().await.state() == kiwi_core::trust::TrustState::Locked {
            continue;
        }
        let due = state.send_queue.lock().await.due(now_unix());
        for item in due {
            let queue_id = item.queue_id.clone();
            let meta = state.outbox_meta.lock().await.get(&queue_id).cloned();
            let account_id = meta.as_ref().map(|m| m.account_id.clone());
            let outcome = deliver(state.clone(), item, meta).await;
            let status = match outcome {
                Delivered::Sent => "sent",
                Delivered::Held => "held",
                Delivered::Blocked => "blocked",
                Delivered::Failed => "failed",
            };
            if !matches!(outcome, Delivered::Held) {
                drop_outbox(&state, &queue_id).await;
            }
            let _ = app.emit(
                "kiwi://outbox",
                OutboxEvent {
                    queue_id,
                    account_id: account_id.unwrap_or_default(),
                    status: status.into(),
                    detail: String::new(),
                    at_unix: now_unix(),
                },
            );
        }
    }
}

/// Deliver one queued send: connect → auth → policy bridge → DATA →
/// observe (via `run_mail_io` — client futures are `!Send`). On a Held
/// outcome with attempts remaining, the item is re-enqueued with linear
/// backoff inside this function — callers only journal the outcome.
pub(crate) async fn deliver(
    state: Arc<AppState>,
    item: QueuedSend,
    meta: Option<OutboxMeta>,
) -> Delivered {
    let queue_id = item.queue_id.clone();
    let attempts = item.attempts;
    run_mail_io(state.clone(), move |s| async move {
        let outcome = match deliver_inner(&s, &item, meta.as_ref()).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[kiwi-app] send {queue_id} failed: {}", e.message);
                match e.code {
                    "policy-unavailable" | "connect-failed" | "tls-failed" | "protocol-error"
                    | "server-reject" | "auth-failed" | "io-error" => Delivered::Held,
                    "policy-blocked" => Delivered::Blocked,
                    _ => Delivered::Failed,
                }
            }
        };
        // Held with attempts left → re-enqueue with linear backoff.
        if matches!(outcome, Delivered::Held) && attempts + 1 < MAX_ATTEMPTS {
            let backoff = 30 * (attempts as i64 + 1);
            s.send_queue.lock().await.enqueue(QueuedSend {
                not_before_unix: now_unix() + backoff,
                undo_window_until_unix: 0,
                attempts: attempts + 1,
                ..item
            });
            let updated_meta = {
                let mut metas = s.outbox_meta.lock().await;
                metas.get_mut(&queue_id).map(|m| {
                    m.attempts = attempts + 1;
                    m.not_before_unix = now_unix() + backoff;
                    m.clone()
                })
            };
            if let Some(m) = updated_meta {
                // Keep the persisted meta in step with the retry state.
                let _ = crate::state::update_outbox_meta(&s.data_dir, &queue_id, &m);
            }
            Ok(Delivered::Held)
        } else {
            // Exhausted retries land as failed; sent/blocked pass through.
            Ok(if matches!(outcome, Delivered::Held) {
                Delivered::Failed
            } else {
                outcome
            })
        }
    })
    .await
    .unwrap_or(Delivered::Failed)
}

/// Facts gathered during one transmit attempt — drive the §11 mailflow
/// emit. Fields stay at observed defaults when the attempt dies early.
#[derive(Default)]
struct AttemptCtx {
    /// Observed negotiated TLS label ("tls1.3", …) of the send connection.
    tls_label: Option<&'static str>,
    /// §10 bridge verdict, when an evaluation ran.
    verdict: Option<bridge::BridgeVerdict>,
    /// §6 security_status — "unknown" until a session observation exists.
    security_status: &'static str,
}

async fn deliver_inner(
    state: &AppState,
    item: &QueuedSend,
    meta: Option<&OutboxMeta>,
) -> CmdResult<Delivered> {
    // Admin endpoint: org binding (config) → KIWI_ADMIN_URL/_ORG env → none.
    let endpoint = bridge::resolve_endpoint(state).await;
    let mut ctx = AttemptCtx::default();
    let result = transmit(state, item, meta, endpoint.as_ref(), &mut ctx).await;

    // §11: emit send-attempt facts regardless of delivery outcome
    // (advisory verdict only — v1 stores the attempt, not delivery status).
    // Outbound events require org_id; emit failures queue-and-retry.
    if let Some(ep) = &endpoint
        && let Some(org) = ep.org_id.as_deref()
    {
        let per_recipient: Vec<(&str, &str)> = item
            .request
            .to
            .iter()
            .map(|r| {
                let v = ctx
                    .verdict
                    .as_ref()
                    .and_then(|vv| vv.results.iter().find(|x| &x.recipient == r))
                    .map(|x| x.verdict.as_str())
                    .unwrap_or("unknown");
                (r.as_str(), v)
            })
            .collect();
        let events = bridge::build_send_attempt_events(
            org,
            &item.request.from,
            &per_recipient,
            ctx.tls_label,
            ctx.security_status,
            meta.map(|m| m.message_id.as_str()),
            now_unix(),
        );
        bridge::emit_events(state, ep, events).await;
    }
    result
}

/// Warn once per process (stderr + audit) — the dev-mode degrade when no
/// admin service is configured at all. Never blocks the send.
async fn warn_once(
    state: &AppState,
    flag: &std::sync::atomic::AtomicBool,
    action: &str,
    msg: &str,
) {
    if flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    eprintln!("[kiwi-app] {msg}");
    let _ = state.audit.lock().await.record(action, msg, now_unix());
}

async fn transmit(
    state: &AppState,
    item: &QueuedSend,
    meta: Option<&OutboxMeta>,
    endpoint: Option<&bridge::AdminEndpoint>,
    ctx: &mut AttemptCtx,
) -> CmdResult<Delivered> {
    let account_id = meta
        .map(|m| m.account_id.as_str())
        .ok_or_else(|| IpcError::not_found("send has no account record"))?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;
    let accept_invalid = state
        .index
        .lock()
        .await
        .account_meta
        .get(account_id)
        .map(|m| m.accept_invalid_certs)
        .unwrap_or(false);
    let secret = resolve_secret(state, &acct.outgoing.auth)?;

    let t = Transport::connect(
        &acct.outgoing.server.host,
        acct.outgoing.server.port,
        acct.outgoing.server.security,
        TlsSettings {
            accept_invalid_certs: accept_invalid,
            extra_roots: Vec::new(),
        },
    )
    .await
    .map_err(IpcError::from)?;
    let mut client = SmtpClient::connect(t, SmtpConfig::default())
        .await
        .map_err(IpcError::from)?;
    if let Some(secret) = secret {
        let auth = match acct.outgoing.auth {
            kiwi_mail::account::AuthRef::XOAuth2 { .. } => SmtpAuth::XOAuth2 {
                user: acct.outgoing.username.clone(),
                token: secret,
            },
            _ => SmtpAuth::Plain {
                user: acct.outgoing.username.clone(),
                password: secret,
            },
        };
        client.authenticate(&auth).await.map_err(IpcError::from)?;
    }

    // Observed TLS of THIS connection — feeds both the §10 evaluation and
    // the §11 event's tls_version.
    ctx.tls_label = client
        .transport()
        .observation()
        .and_then(|o| o.protocol_version.as_deref())
        .map(bridge::tls_version_label);

    // Policy bridge (admin-api §10): evaluate when an org-bound endpoint
    // exists. Unreachable → Err → Held (fail closed). No endpoint at all →
    // warn-log once and proceed (local-first dev degrade).
    match endpoint {
        Some(ep) if ep.org_id.is_some() => {
            let verdict =
                bridge::evaluate_outbound(ep, &acct.email, &item.request.to, ctx.tls_label).await?;
            let blocked = verdict.overall == "block";
            ctx.verdict = Some(verdict);
            if blocked {
                // The connection really happened — record it before dropping.
                let record = record_smtp(state, &client, account_id, &acct.outgoing.auth).await;
                ctx.security_status =
                    bridge::security_status_label(true, record.findings.iter().map(|f| f.severity));
                let verdict = ctx.verdict.as_ref().unwrap();
                let detail = verdict
                    .results
                    .iter()
                    .filter(|r| r.verdict == "block")
                    .map(|r| {
                        let why = r
                            .reasons
                            .iter()
                            .map(|x| {
                                if x.detail.is_empty() {
                                    x.code.clone()
                                } else {
                                    format!("{}:{}", x.code, x.detail)
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("{}[{why}]", r.recipient)
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                state.audit.lock().await.record(
                    "send-blocked",
                    &format!("{}: policy blocked {detail}", item.queue_id),
                    now_unix(),
                )?;
                let _ = client.quit().await;
                return Ok(Delivered::Blocked);
            }
        }
        Some(_) => {
            warn_once(
                state,
                &state.no_org_warned,
                "policy-no-org",
                "admin endpoint configured without org id (KIWI_ADMIN_ORG unset) — \
                 outbound policy evaluation skipped",
            )
            .await;
        }
        None => {
            warn_once(
                state,
                &state.policy_warned,
                "policy-bridge-absent",
                "no kiwi-admin endpoint configured (org binding or KIWI_ADMIN_URL) — \
                 outbound policy checks skipped (dev mode)",
            )
            .await;
        }
    }

    client
        .send_mail(&item.request)
        .await
        .map_err(IpcError::from)?;
    let record = record_smtp(state, &client, account_id, &acct.outgoing.auth).await;
    ctx.security_status =
        bridge::security_status_label(true, record.findings.iter().map(|f| f.severity));
    let _ = client.quit().await;
    Ok(Delivered::Sent)
}

/// Record the SMTP connection observation (shared by sent + blocked paths).
async fn record_smtp(
    state: &AppState,
    client: &SmtpClient,
    account_id: &str,
    auth: &kiwi_mail::account::AuthRef,
) -> crate::state::SessionRecord {
    let facts = observe::facts_of(client.transport());
    let (record, _eval) = observe::record_connection(
        state,
        facts,
        ObservationContext {
            protocol: Protocol::Smtp,
            account_id: Some(account_id.to_string()),
            starttls_offered: client.ehlo_info().map(|e| e.has_starttls()),
            auth_mechanism: match auth {
                kiwi_mail::account::AuthRef::XOAuth2 { .. } => AuthMechanism::XOAuth2,
                kiwi_mail::account::AuthRef::None => AuthMechanism::None,
                _ => AuthMechanism::Plain,
            },
            auth_succeeded: Some(true),
            label: "smtp send",
        },
    )
    .await;
    record
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AddAccountInput, AuthInput, ServerInput};

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

    #[test]
    fn outbox_survives_reopen() {
        // Same data dir across two opens — the persisted item must reload.
        let dir = std::env::temp_dir().join(format!(
            "kiwi-outbox-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
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
            let meta = state2.outbox_meta.lock().await;
            let m = meta.get(&queue_id).expect("meta reloaded");
            assert_eq!(m.subject, "s");
            assert!(!m.message_id.is_empty());
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
            assert!(
                state
                    .send_queue
                    .lock()
                    .await
                    .cancel(&r.queue_id, now_unix())
            );
        });
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
