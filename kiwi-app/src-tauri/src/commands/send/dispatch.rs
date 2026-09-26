//! Dispatch-side: the background outbox drain (`outbox_loop`), flush,
//! and one-send delivery (SMTP connect/auth → policy bridge → DATA →
//! observe). Enqueue lives in `enqueue.rs`.

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager, State};

use kiwi_core::session::{AuthMechanism, Protocol};
use kiwi_mail::account::IncomingProtocol;
use kiwi_mail::smtp::{QueuedSend, SmtpAuth, SmtpClient, SmtpConfig};
use kiwi_mail::transport::{TlsSettings, Transport};

use super::super::{gate, resolve_secret, run_mail_io};
use super::drop_outbox;
use crate::bridge;
use crate::error::{CmdResult, IpcError};
use crate::observe::{self, ObservationContext};
use crate::state::{AppState, OutboxMeta, now_unix};
use crate::types::OutboxEvent;

const MAX_ATTEMPTS: u32 = 5;

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
/// backoff inside this function — callers only journal the outcome. An
/// item in the single-attempt class (a deliverability reservation, which
/// accepts exactly one message) is never re-enqueued, whatever the relay
/// reports.
pub(crate) async fn deliver(
    state: Arc<AppState>,
    item: QueuedSend,
    meta: Option<OutboxMeta>,
) -> Delivered {
    let queue_id = item.queue_id.clone();
    let attempts = item.attempts;
    let single_attempt = meta.as_ref().is_some_and(|m| m.class.is_single_attempt());
    run_mail_io(state.clone(), move |s| async move {
        let mut last_error: Option<String> = None;
        let outcome = match deliver_inner(&s, &item, meta.as_ref()).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[kiwi-app] send {queue_id} failed: {}", e.message);
                // The outbox row tracks retry state but can't say *why* —
                // the failed attempt itself must be tamper-evident.
                // `IpcError` carries code + sanitized message only.
                let _ = s.audit.lock().await.record(
                    "send-attempt-failed",
                    &format!("{queue_id}: {} — {}", e.code, e.message),
                    now_unix(),
                );
                // T-298: the sanitized reason also rides the row so
                // `kiwi_list_outbox` can say why a held send is held.
                last_error = Some(format!("{}: {}", e.code, e.message));
                match e.code {
                    "policy-unavailable" | "connect-failed" | "tls-failed" | "protocol-error"
                    | "server-reject" | "auth-failed" | "io-error" => Delivered::Held,
                    "policy-blocked" => Delivered::Blocked,
                    _ => Delivered::Failed,
                }
            }
        };
        // Held with attempts left → re-enqueue with linear backoff. A
        // single-attempt class never re-enqueues: the destination accepts
        // exactly one message, so an ambiguous failure must not be retried.
        if matches!(outcome, Delivered::Held) && single_attempt {
            let _ = s.audit.lock().await.record(
                "send-single-attempt-abandoned",
                &format!(
                    "{queue_id}: {} — not retried (single-attempt reservation)",
                    last_error.as_deref().unwrap_or("ambiguous failure")
                ),
                now_unix(),
            );
            return Ok(Delivered::Failed);
        }
        if matches!(outcome, Delivered::Held) && attempts + 1 < MAX_ATTEMPTS {
            let backoff = 30 * (attempts as i64 + 1);
            s.send_queue.lock().await.enqueue(QueuedSend {
                not_before_unix: now_unix() + backoff,
                undo_window_until_unix: 0,
                attempts: attempts + 1,
                ..item
            });
            {
                let mut metas = s.outbox_meta.lock().await;
                if let Some(m) = metas.get_mut(&queue_id) {
                    m.attempts = attempts + 1;
                    m.not_before_unix = now_unix() + backoff;
                    m.last_error = last_error.clone();
                }
            }
            // Keep the persisted row in step with the retry state.
            let _ = s.store.lock().await.outbox_set_timing(
                &queue_id,
                now_unix() + backoff,
                attempts + 1,
                last_error.as_deref(),
            );
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
    let mut client = SmtpClient::connect(t, {
        let mut c = SmtpConfig::default();
        // KIWI_DEV_PLAINTEXT fixture seam — loopback hosts only.
        c.allow_plaintext_auth = kiwi_core::dev::plaintext_fixture_for(&acct.outgoing.server.host);
        c
    })
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

    let outcome = client
        .send_mail(&item.request)
        .await
        .map_err(IpcError::from)?;
    // An SMTP transaction that accepted nobody is not a delivery. Without
    // this check a fully-rejected message would be journaled as `sent`.
    if outcome.accepted.is_empty() {
        let _ = client.quit().await;
        return Err(IpcError::new(
            "server-reject",
            format!(
                "no recipient accepted: {} rejected, 0 of {} accepted",
                outcome.rejected.len(),
                item.request.to.len()
            ),
        ));
    }
    if !outcome.rejected.is_empty() {
        let _ = state.audit.lock().await.record(
            "send-partially-rejected",
            &format!(
                "{}: {} of {} recipient(s) rejected by the server",
                item.queue_id,
                outcome.rejected.len(),
                item.request.to.len()
            ),
            now_unix(),
        );
    }
    let record = record_smtp(state, &client, account_id, &acct.outgoing.auth).await;
    ctx.security_status =
        bridge::security_status_label(true, record.findings.iter().map(|f| f.severity));
    let _ = client.quit().await;

    // The send is committed — journal it, then file the Sent copy
    // server-side via IMAP APPEND (the codebase's sent-mail mechanism; a
    // local-only row would be expunged by the next real Sent sync, and
    // POP3 has no remote folders at all). Best-effort: the recipient's
    // server already accepted the mail, so a copy failure is audited but
    // never retried and never flips the outcome.
    let _ = state.audit.lock().await.record(
        "send-sent",
        &format!("{} via {account_id}", item.queue_id),
        now_unix(),
    );
    if matches!(acct.incoming.protocol, IncomingProtocol::Imap)
        && let Err(e) = file_sent_copy(state, &acct, &item.request.message).await
    {
        eprintln!(
            "[kiwi-app] sent copy for {} failed: {}",
            item.queue_id, e.message
        );
        let _ = state.audit.lock().await.record(
            "send-sent-copy-failed",
            &format!("{}: {}", item.queue_id, e.message),
            now_unix(),
        );
    }
    Ok(Delivered::Sent)
}

/// File a copy of the transmitted RFC 5322 message into the account's
/// Sent mailbox via IMAP APPEND — the `\Sent`-flagged LIST entry when
/// the server advertises one (RFC 6154), the conventional "Sent" name
/// otherwise. Opens a dedicated session: the send path owns no IMAP
/// connection.
async fn file_sent_copy(
    state: &AppState,
    acct: &kiwi_mail::account::MailAccount,
    mime: &[u8],
) -> CmdResult<()> {
    let mut client = crate::commands::mail::connect_imap(state, acct).await?;
    let boxes = client.list("", "*").await?;
    let mailbox = boxes
        .iter()
        .find(|b| b.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Sent")))
        .map(|b| b.name.clone())
        .unwrap_or_else(|| "Sent".into());
    client.append(&mailbox, &["\\Seen"], mime).await?;
    let _ = client.logout().await;
    Ok(())
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
