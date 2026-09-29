//! External mail-service integrations (T-227) — the IPC surface for
//! `kiwi-integrations` behind the lock gate. Two tools:
//!
//! ## Temp mail (`integrations_tempmail_*`)
//!
//! One in-memory GuerrillaMail session at a time — `create` mints or
//! replaces it, `poll`/`fetch`/`extend`/`discard` act on it. Every
//! response carries `publicInboxNotice` verbatim (the binding UI
//! disclosure — a public disposable inbox is a hostile-content surface).
//! The session lock is held across the whole provider interaction, so
//! create/discard/extend cannot interleave on one mailbox, a replaced or
//! half-built remote mailbox is retired with a best-effort `forget_me`,
//! and a failed candidate never costs the caller the session they had.
//!
//! `fetch` never returns raw RFC822 to the webview: the synthesized
//! message is parsed by `kiwi_mail::mime` and the HTML body passes
//! through the display-only sanitizer — remote resources AND anchors
//! gone, regardless of any account opt-in (a public inbox must never
//! load remote content or navigate the app).
//!
//! ## Deliverability (`integrations_deliverability_*`)
//!
//! `begin` reserves a single-use address and mints a random single-use
//! anti-replay capability. `send` REQUIRES that capability — the check +
//! consume happen backend-side under the sessions lock, so the webview
//! can neither replay it nor skip it. It is a replay gate, not a trusted
//! user gesture: the renderer that holds it can hand it straight back.
//! `status`/`report` are single-shot calls; the poll loop is the caller's,
//! single-flighted and rate-limit-aware here.
//!
//! The provider slug inside each reservation is a capability secret —
//! it is stored in memory only, never serialized to IPC, never audited.
//! Audit records carry `test_id` + address only.

use std::sync::Arc;

use tauri::State;

use kiwi_integrations::deliverability::spamtester::SPAMTESTER_API;
use kiwi_integrations::deliverability::{DeliverabilityTester, EmailSpamTester};
use kiwi_integrations::tempmail::guerrilla::GUERRILLA_API;
use kiwi_integrations::tempmail::{GuerrillaMail, TempMailProvider};

use super::{bounded, gate};
use crate::commands::message::sanitize_html_display_only;
use crate::commands::send::send_impl_class;
use crate::error::{CmdResult, IpcError};
use crate::state::{
    AppState, DeliverabilitySession, MAX_DELIVERABILITY_SESSIONS, OutboxClass, new_id, now_unix,
    now_unix_ms,
};
use crate::types::{
    ComposeInput, DeliverabilityBeginView, DeliverabilityReportView, DeliverabilitySendView,
    DeliverabilityStatusView, TempDiscardView, TempExtendView, TempMailboxView, TempMessageView,
    TempPollView,
};

/// Rendered-fragment cap — same bound `kiwi_render_body` applies.
const MAX_RENDER_BYTES: usize = 8 * 1024 * 1024;

/// Provider UA label — a constant, never the webview's UA.
const INTEGRATIONS_AGENT: &str = concat!("KIWI/", env!("CARGO_PKG_VERSION"));

/// Backoff hint handed to a second concurrent poll of the same test.
const POLL_BUSY_RETRY_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Temp mail
// ---------------------------------------------------------------------------

/// `kiwi_integrations_tempmail_create(localPart?)` → `TempMailboxView`.
///
/// Creates (or replaces) the app's single disposable-inbox session.
/// `localPart` requests a specific local part (`f=set_email_user`);
/// charset-validated here so bad input is `invalid-input`, not a
/// provider round-trip.
#[tauri::command]
pub async fn kiwi_integrations_tempmail_create(
    state: State<'_, Arc<AppState>>,
    local_part: Option<String>,
) -> CmdResult<TempMailboxView> {
    gate(state.inner()).await?;
    tempmail_create_impl(state.inner(), local_part).await
}

pub(crate) async fn tempmail_create_impl(
    state: &AppState,
    local_part: Option<String>,
) -> CmdResult<TempMailboxView> {
    let local_part = local_part
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(p) = &local_part {
        bounded("localPart", p, kiwi_integrations::tempmail::MAX_LOCAL_PART)?;
        // Same charset the provider enforces — surface as invalid-input.
        let ok = !p.starts_with('.')
            && !p.ends_with('.')
            && !p.contains("..")
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(IpcError::invalid(
                "localPart may contain letters, digits, '.', '_', '-' (no leading/trailing dot)",
            ));
        }
    }

    // One mailbox, one lifecycle: the session lock covers allocation,
    // replacement, and the remote cleanup of whatever it displaces.
    let mut slot = state.tempmail.lock().await;
    // Audit intent first: the next call allocates a public remote mailbox,
    // which cannot be undone by clearing local state.
    state.audit.lock().await.record(
        "tempmail-create-intent",
        "allocating a public disposable inbox via guerrillamail",
        now_unix(),
    )?;

    let gm = GuerrillaMail::new(
        state.integrations_http.clone(),
        GUERRILLA_API,
        INTEGRATIONS_AGENT,
    )
    .map_err(IpcError::from)?;
    let candidate = async {
        let addr = gm.get_email_address().await.map_err(IpcError::from)?;
        let addr = match &local_part {
            Some(p) => gm.set_email_user(p).await.map_err(IpcError::from)?,
            None => addr,
        };
        Ok::<_, IpcError>(addr)
    }
    .await;

    let addr = match candidate {
        Ok(addr) => addr,
        Err(e) => {
            // The provider may already own a remote address for this
            // candidate: retire it, then hand the caller the original
            // failure. The previous session (if any) stays usable.
            let forgotten = gm.forget_me().await.is_ok();
            state.audit.lock().await.record(
                "tempmail-create-failed",
                &format!(
                    "candidate abandoned: {e}; remote forget {}",
                    if forgotten { "ok" } else { "failed" }
                ),
                now_unix(),
            )?;
            return Err(e);
        }
    };

    let view = TempMailboxView {
        address: addr.address.clone(),
        address_created_unix: addr.created_unix,
        public_inbox_notice: kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE,
    };
    let replaced = slot.replace(gm);
    let mut old_forgotten = None;
    if let Some(old) = replaced {
        // Best-effort: a remote cleanup failure must not roll back the
        // replacement, and must not be silent.
        let ok = old.forget_me().await.is_ok();
        old_forgotten = Some(ok);
        state.audit.lock().await.record(
            "tempmail-replaced",
            &format!(
                "previous session retired: remote forget {}",
                if ok { "ok" } else { "failed" }
            ),
            now_unix(),
        )?;
    }
    drop(slot);
    state.audit.lock().await.record(
        "tempmail-create",
        &format!(
            "{} via guerrillamail{}",
            addr.address,
            match old_forgotten {
                Some(true) => " (replaced, previous forgotten)",
                Some(false) => " (replaced, previous remote forget failed)",
                None => "",
            }
        ),
        now_unix(),
    )?;
    Ok(view)
}

/// `kiwi_integrations_tempmail_poll()` → `TempPollView`.
///
/// The session lock is held across the provider await deliberately:
/// `check_email`'s `seq` cursor and `set_email_user`/`forget_me` must not
/// interleave — the mutex serializes the mailbox, and the provider takes
/// no other `AppState` locks (no lock-ordering hazard).
#[tauri::command]
pub async fn kiwi_integrations_tempmail_poll(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<TempPollView> {
    gate(state.inner()).await?;
    tempmail_poll_impl(state.inner()).await
}

pub(crate) async fn tempmail_poll_impl(state: &AppState) -> CmdResult<TempPollView> {
    let sess = state.tempmail.lock().await;
    let Some(gm) = sess.as_ref() else {
        return Err(IpcError::not_found(
            "no active temp-mail session — create one first",
        ));
    };
    let poll = gm.check_email().await.map_err(IpcError::from)?;
    Ok(TempPollView::from_poll(poll))
}

/// `kiwi_integrations_tempmail_fetch(mailId)` → `TempMessageView`.
///
/// The synthesized RFC822 is parsed and sanitized in-process; the webview
/// receives the cleaned fragment + plain text, never raw MIME.
#[tauri::command]
pub async fn kiwi_integrations_tempmail_fetch(
    state: State<'_, Arc<AppState>>,
    mail_id: String,
) -> CmdResult<TempMessageView> {
    gate(state.inner()).await?;
    tempmail_fetch_impl(state.inner(), &mail_id).await
}

pub(crate) async fn tempmail_fetch_impl(
    state: &AppState,
    mail_id: &str,
) -> CmdResult<TempMessageView> {
    bounded("mailId", mail_id, 64)?;
    let sess = state.tempmail.lock().await;
    let Some(gm) = sess.as_ref() else {
        return Err(IpcError::not_found(
            "no active temp-mail session — create one first",
        ));
    };
    let msg = gm.fetch_email(mail_id).await.map_err(IpcError::from)?;
    drop(sess); // provider call done — release the session mutex

    let parsed = kiwi_mail::mime::parse_message(&msg.raw_rfc822).map_err(IpcError::from)?;
    // Remote content hard-off: a public inbox is read-only hostile content;
    // the per-account `remote_content_allowed` opt-in does not apply here.
    // Display-only: anchors are dropped entirely, so a message cannot
    // navigate the webview (real mail keeps its link policy instead).
    let (html, stripped) = match parsed.html_body {
        Some(h) => {
            let (clean, s) = sanitize_html_display_only(&h);
            let clean = if clean.len() > MAX_RENDER_BYTES {
                clean.chars().take(MAX_RENDER_BYTES).collect()
            } else {
                clean
            };
            (Some(clean), s)
        }
        None => (None, 0),
    };
    Ok(TempMessageView {
        mail_id: msg.summary.mail_id,
        from: msg.summary.from,
        subject: msg.summary.subject,
        date: msg.summary.date,
        content_type: msg.content_type,
        html,
        text: parsed.text_body,
        remote_images_stripped: stripped,
        public_inbox_notice: kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE,
    })
}

/// `kiwi_integrations_tempmail_discard()` → `TempDiscardView`.
///
/// Local session state is cleared unconditionally; `forget_me` is
/// best-effort (a dead session may already be gone server-side) and runs
/// under the session lock, so it cannot interleave with a create that is
/// still allocating a replacement.
#[tauri::command]
pub async fn kiwi_integrations_tempmail_discard(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<TempDiscardView> {
    gate(state.inner()).await?;
    tempmail_discard_impl(state.inner()).await
}

pub(crate) async fn tempmail_discard_impl(state: &AppState) -> CmdResult<TempDiscardView> {
    let mut slot = state.tempmail.lock().await;
    let Some(gm) = slot.take() else {
        return Err(IpcError::not_found(
            "no active temp-mail session to discard",
        ));
    };
    let remote_forgotten = gm.forget_me().await.is_ok();
    drop(slot);
    state.audit.lock().await.record(
        "tempmail-discard",
        if remote_forgotten {
            "session forgotten remotely"
        } else {
            "remote forget failed; local session dropped"
        },
        now_unix(),
    )?;
    Ok(TempDiscardView {
        discarded: true,
        remote_forgotten,
        public_inbox_notice: kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE,
    })
}

/// `kiwi_integrations_tempmail_extend()` → `TempExtendView`.
#[tauri::command]
pub async fn kiwi_integrations_tempmail_extend(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<TempExtendView> {
    gate(state.inner()).await?;
    tempmail_extend_impl(state.inner()).await
}

pub(crate) async fn tempmail_extend_impl(state: &AppState) -> CmdResult<TempExtendView> {
    let sess = state.tempmail.lock().await;
    let Some(gm) = sess.as_ref() else {
        return Err(IpcError::not_found(
            "no active temp-mail session — create one first",
        ));
    };
    let out = gm.extend().await.map_err(IpcError::from)?;
    Ok(TempExtendView {
        extended: out.extended,
        expired: out.expired,
        address_created_unix: out.address_created_unix,
        public_inbox_notice: kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE,
    })
}

// ---------------------------------------------------------------------------
// Deliverability
// ---------------------------------------------------------------------------

/// Look up a test's reservation (cloned — the slug stays inside state).
async fn reservation_for(
    state: &AppState,
    test_id: &str,
) -> CmdResult<kiwi_integrations::deliverability::TestReservation> {
    state
        .deliverability
        .lock()
        .await
        .get(test_id)
        .map(|s| s.reservation.clone())
        .ok_or_else(|| IpcError::not_found("unknown deliverability test"))
}

fn spamtester(state: &AppState) -> CmdResult<EmailSpamTester> {
    EmailSpamTester::new(state.integrations_http.clone(), SPAMTESTER_API).map_err(IpcError::from)
}

/// `kiwi_integrations_deliverability_begin()` → `DeliverabilityBeginView`.
///
/// Reserves a single-use test address and mints the consent token the
/// send step requires. The reservation slug never leaves the backend.
#[tauri::command]
pub async fn kiwi_integrations_deliverability_begin(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<DeliverabilityBeginView> {
    gate(state.inner()).await?;
    deliverability_begin_impl(state.inner()).await
}

pub(crate) async fn deliverability_begin_impl(
    state: &AppState,
) -> CmdResult<DeliverabilityBeginView> {
    // Audit intent first: reserving a single-use address is an external,
    // un-undoable effect, and an intent that cannot be recorded aborts it.
    state.audit.lock().await.record(
        "deliverability-begin-intent",
        "reserving a single-use test address via email-spam-tester",
        now_unix(),
    )?;
    let tester = spamtester(state)?;
    let res = tester.reserve_inbox().await.map_err(IpcError::from)?;

    let test_id = new_id("dtest");
    let consent = zeroize::Zeroizing::new(new_id("consent"));
    let view = DeliverabilityBeginView {
        test_id: test_id.clone(),
        address: res.address.clone(),
        expires_at_unix: res.expires_at_unix,
        expires_at_raw: res.expires_at_raw.clone(),
        consent_token: consent.as_str().to_string(),
        consent_notice: crate::types::DELIVERABILITY_CONSENT_NOTICE,
    };
    {
        let mut sessions = state.deliverability.lock().await;
        if sessions.len() >= MAX_DELIVERABILITY_SESSIONS {
            // Evict server-expired tests first; then oldest key order.
            let now = now_unix();
            sessions.retain(|_, s| {
                s.reservation
                    .expires_at_unix
                    .map(|t| t > now as u64)
                    .unwrap_or(true)
            });
            while sessions.len() >= MAX_DELIVERABILITY_SESSIONS {
                if let Some((evicted, _)) = sessions.pop_first() {
                    state
                        .deliverability_cooldown
                        .lock()
                        .expect("deliverability cooldown")
                        .forget(&evicted);
                }
            }
        }
        sessions.insert(
            test_id.clone(),
            DeliverabilitySession {
                reservation: res,
                consent_token: Some(consent),
                consent_consumed: false,
                enqueued: false,
                queue_id: None,
                last_status: None,
            },
        );
    }
    // Audit: test_id + address only — NEVER the slug or the capability.
    state.audit.lock().await.record(
        "deliverability-begin",
        &format!("{test_id} reserved {}", view.address),
        now_unix(),
    )?;
    Ok(view)
}

/// Single-use capability check — constant-time compare on a fixed-format
/// CSPRNG token; consumed on authorize (a failed enqueue still burns it;
/// retry = fresh `begin`).
fn consent_ok(expected: &str, presented: &str) -> bool {
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// `kiwi_integrations_deliverability_send(testId, consentToken, accountId,
/// message)` → `DeliverabilitySendView`.
///
/// The capability minted by `begin` must match the stored one and is
/// consumed atomically under the sessions lock before the send is
/// enqueued — the webview can neither fabricate nor replay it. It is a
/// single-use anti-replay gate, not a trusted user gesture. The
/// message's own `to`/`cc`/`bcc` are ignored: the only recipient is the
/// reserved single-use address. The send rides the outbox in the
/// single-attempt class — a relay-ambiguous failure is never retried into
/// a reservation that accepts exactly one message — and undo-send grace
/// still applies, so dispatch is audited like any send.
#[tauri::command]
pub async fn kiwi_integrations_deliverability_send(
    state: State<'_, Arc<AppState>>,
    test_id: String,
    consent_token: String,
    account_id: String,
    message: ComposeInput,
) -> CmdResult<DeliverabilitySendView> {
    gate(state.inner()).await?;
    let presented = zeroize::Zeroizing::new(consent_token);
    deliverability_send_impl(
        state.inner(),
        &test_id,
        presented.as_str(),
        &account_id,
        message,
    )
    .await
}

pub(crate) async fn deliverability_send_impl(
    state: &AppState,
    test_id: &str,
    consent_token: &str,
    account_id: &str,
    message: ComposeInput,
) -> CmdResult<DeliverabilitySendView> {
    bounded("testId", test_id, 128)?;
    bounded("consentToken", consent_token, 256)?;
    bounded("accountId", account_id, 128)?;

    let address = {
        let sessions = state.deliverability.lock().await;
        let Some(session) = sessions.get(test_id) else {
            return Err(IpcError::not_found("unknown deliverability test"));
        };
        let authorized = session
            .consent_token
            .as_deref()
            .map(|t| consent_ok(t, consent_token))
            .unwrap_or(false);
        if !authorized {
            // Missing, wrong, or already-consumed — one code, no oracle
            // on whether the token was ever valid.
            return Err(IpcError::new(
                "consent-required",
                "deliverability send requires the unconsumed consent token from begin",
            ));
        }
        session.reservation.address.clone()
    };

    // Audit intent before the first irreversible effect (capability
    // consumption + outbox write). An intent that cannot be recorded
    // aborts the send rather than performing it unevidenced.
    state.audit.lock().await.record(
        "deliverability-send-intent",
        &format!("{test_id} enqueue to {address} via {account_id}"),
        now_unix(),
    )?;

    {
        let mut sessions = state.deliverability.lock().await;
        let Some(session) = sessions.get_mut(test_id) else {
            return Err(IpcError::not_found("unknown deliverability test"));
        };
        // Re-check under the lock: a concurrent call may have consumed it
        // while the intent record was being written.
        if !session
            .consent_token
            .as_deref()
            .is_some_and(|t| consent_ok(t, consent_token))
        {
            return Err(IpcError::new(
                "consent-required",
                "deliverability send requires the unconsumed consent token from begin",
            ));
        }
        // Taking the value drops the last copy, which zeroes it.
        session.consent_token = None;
        session.consent_consumed = true;
    }

    let mut forced = message;
    forced.to = vec![address];
    forced.cc = Vec::new();
    forced.bcc = Vec::new();
    let receipt =
        match send_impl_class(state, account_id, forced, None, OutboxClass::SingleAttempt).await {
            Ok(r) => r,
            Err(e) => {
                // The capability is spent; the enqueue is not. Record why and
                // surface the original failure — `enqueued` stays false. A
                // failure record that cannot be written is itself surfaced:
                // evidence is never silently dropped.
                state.audit.lock().await.record(
                    "deliverability-send-failed",
                    &format!("{test_id}: {} — {} (not enqueued)", e.code, e.message),
                    now_unix(),
                )?;
                return Err(e);
            }
        };
    {
        let mut sessions = state.deliverability.lock().await;
        if let Some(session) = sessions.get_mut(test_id) {
            session.enqueued = true;
            session.queue_id = Some(receipt.queue_id.clone());
        }
    }
    state.audit.lock().await.record(
        "deliverability-send",
        &format!("{test_id} enqueued as {}", receipt.queue_id),
        now_unix(),
    )?;
    Ok(DeliverabilitySendView {
        test_id: test_id.to_string(),
        queue_id: receipt.queue_id,
        not_before_unix: receipt.not_before_unix,
        consent_consumed: true,
        enqueued: true,
        single_attempt: true,
    })
}

/// `kiwi_integrations_deliverability_status(testId)` →
/// `DeliverabilityStatusView`. Single-shot; the UI owns the poll loop,
/// and the backend refuses to amplify it: one in-flight poll per test, a
/// cooldown after a provider 429 (served from the last observation, with
/// `retryAfterMs` telling the caller when to come back).
#[tauri::command]
pub async fn kiwi_integrations_deliverability_status(
    state: State<'_, Arc<AppState>>,
    test_id: String,
) -> CmdResult<DeliverabilityStatusView> {
    gate(state.inner()).await?;
    deliverability_status_impl(state.inner(), &test_id).await
}

struct PollGuard<'a> {
    state: &'a AppState,
    test_id: &'a str,
}

impl Drop for PollGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.state.deliverability_polling.lock().map_err(|_| ()) {
            inflight.remove(self.test_id);
        }
    }
}

pub(crate) async fn deliverability_status_impl(
    state: &AppState,
    test_id: &str,
) -> CmdResult<DeliverabilityStatusView> {
    bounded("testId", test_id, 128)?;
    let (res, enqueued, consent_consumed, cached) = {
        let sessions = state.deliverability.lock().await;
        let Some(session) = sessions.get(test_id) else {
            return Err(IpcError::not_found("unknown deliverability test"));
        };
        (
            session.reservation.clone(),
            session.enqueued,
            session.consent_consumed,
            session.last_status.clone(),
        )
    };

    if let Some(remaining) = cooldown_remaining(state, test_id) {
        return match cached {
            Some(last) => Ok(DeliverabilityStatusView::from_status(
                test_id,
                last,
                enqueued,
                consent_consumed,
                Some(remaining),
            )),
            None => Err(IpcError::rate_limited(
                format!("provider rate-limited; poll again after {remaining} ms"),
                Some(remaining),
            )),
        };
    }

    {
        let mut inflight = state
            .deliverability_polling
            .lock()
            .map_err(|_| IpcError::new("internal", "poll guard poisoned"))?;
        if !inflight.insert(test_id.to_string()) {
            return Err(IpcError::new(
                "poll-in-flight",
                "a status poll for this test is already running",
            )
            .with_retry_after(Some(POLL_BUSY_RETRY_MS)));
        }
    }
    let _guard = PollGuard { state, test_id };

    let polled = spamtester(state)?.poll_status(&res).await;
    let status = match polled {
        Ok(s) => s,
        Err(kiwi_integrations::IntegrationError::RateLimited { retry_after_ms }) => {
            let until = state
                .deliverability_cooldown
                .lock()
                .map_err(|_| IpcError::new("internal", "cooldown guard poisoned"))?
                .note(test_id, retry_after_ms, now_unix_ms());
            let remaining = (until - now_unix_ms()).max(0) as u64;
            return Err(IpcError::rate_limited(
                format!("provider rate-limited; poll again after {remaining} ms"),
                Some(remaining),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    {
        let mut sessions = state.deliverability.lock().await;
        if let Some(session) = sessions.get_mut(test_id) {
            session.last_status = Some(status.clone());
        }
    }
    Ok(DeliverabilityStatusView::from_status(
        test_id,
        status,
        enqueued,
        consent_consumed,
        None,
    ))
}

fn cooldown_remaining(state: &AppState, test_id: &str) -> Option<u64> {
    state
        .deliverability_cooldown
        .lock()
        .ok()?
        .remaining(test_id, now_unix_ms())
}

/// `kiwi_integrations_deliverability_report(testId)` →
/// `DeliverabilityReportView`. Meaningful once `status.ready`; the
/// provider decides what an early fetch returns.
#[tauri::command]
pub async fn kiwi_integrations_deliverability_report(
    state: State<'_, Arc<AppState>>,
    test_id: String,
) -> CmdResult<DeliverabilityReportView> {
    gate(state.inner()).await?;
    deliverability_report_impl(state.inner(), &test_id).await
}

pub(crate) async fn deliverability_report_impl(
    state: &AppState,
    test_id: &str,
) -> CmdResult<DeliverabilityReportView> {
    bounded("testId", test_id, 128)?;
    let res = reservation_for(state, test_id).await?;
    let report = spamtester(state)?
        .fetch_report(&res)
        .await
        .map_err(IpcError::from)?;
    Ok(DeliverabilityReportView::from_report(test_id, report))
}

// ---------------------------------------------------------------------------
// Tests — every flow replays recorded fixtures via ScriptedHttp; nothing
// touches the network.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::accounts::add_account_impl;
    use crate::commands::send::tests::{acct_input, test_state};
    use crate::send_consent::{FixedSendConsent, IntegrationDestinationKind};
    use crate::state::{OutboxMeta, PROVIDER_429_COOLDOWN_MS, PollCooldowns};
    use kiwi_integrations::deliverability::MAX_CHECKS;
    use kiwi_integrations::http::{HttpRequest, HttpResponse, ScriptedHttp, Step};

    struct Fixture {
        state: AppState,
        http: Arc<ScriptedHttp>,
    }

    fn state_with(script: Vec<Step>, tag: &str) -> Fixture {
        let http = Arc::new(ScriptedHttp::new(script));
        let state = AppState::open_test_with_http(temp_dir(tag), http.clone()).expect("test state");
        Fixture { state, http }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kiwi-integ-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn audit_log(state: &AppState) -> String {
        std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap_or_default()
    }

    fn compose() -> ComposeInput {
        ComposeInput {
            to: vec!["attacker@elsewhere.example".into()],
            cc: vec![],
            bcc: vec![],
            subject: "probe".into(),
            text: "body".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![],
        }
    }

    fn leaked(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    const GM_ADDR: &str = r#"{"email_addr":"itest01@guerrillamailblock.com","email_timestamp":"1758300000","sid_token":"sid-fixture-1"}"#;
    const GM_ADDR_2: &str = r#"{"email_addr":"itest02@guerrillamailblock.com","email_timestamp":"1758300001","sid_token":"sid-fixture-2"}"#;
    const GM_CHECK: &str = r#"{"list":[{"mail_id":"7001","mail_from":"svc@test.example","mail_subject":"Confirm &lt;kiwi&gt;","mail_excerpt":"Body preview","mail_timestamp":"1758300120","mail_date":"2026-09-25 12:00:00","mail_read":"0","mail_size":"1234"}],"count":"1","email":"itest01@guerrillamailblock.com","stats":{"mail_host":"sharklasers.com"}}"#;
    const GM_FETCH: &str = r#"{"mail_id":"7001","mail_from":"svc@test.example","mail_subject":"Confirm <kiwi>","mail_excerpt":"Body preview","mail_timestamp":"1758300120","mail_date":"2026-09-25 12:00:00","mail_read":"0","mail_size":"1234","content_type":"text/html","mail_body":"<html><body><h1>Hello</h1><script>alert(1)</script><a href=\"https://evil.example/pwn\">click me</a><a href=\"javascript:alert(2)\">js</a><a href=\"data:text/html,x\">data</a><a href=\"mailto:a@b.test\">mail</a><img src=\"https://tracker.example/x.png\"><svg><a xlink:href=\"https://evil.example/svg\">s</a></svg><form action=\"https://evil.example/post\"><input name=\"cc\"></form><div onclick=\"steal()\">text</div></body></html>","att":0,"attachments":[]}"#;
    const GM_EXTEND: &str = r#"{"expired":false,"affected":"1","email_timestamp":"1758300000"}"#;
    const GM_FORGET: &str = "true";

    const ST_RESERVE: &str = r#"{"address":"drop-k7f2@in.email-spam-tester.example","slug":"fx-slug-9u2n4k","expires_at":1758307200}"#;
    const ST_STATUS_PENDING_202: &str = "{}";
    const ST_STATUS_RECEIVED: &str =
        r#"{"analysis_status":"received","checks_done":1,"checks_total":3}"#;
    const ST_STATUS_READY: &str =
        r#"{"analysis_status":"checks_ready","checks_done":3,"checks_total":3}"#;
    const ST_REPORT: &str = r#"{"score_ours":87.0,"score_compat":9.1,"complete":true,"report_url":"https://email-spam-tester.example/r/fx","subscores":{"auth":100000,"infra_spam":80000,"content":90000,"compliance":100000},"checks":[{"id":"spf","category":"auth","status":"pass","title":"SPF","summary":"passes","citations":{"standards":[{"title":"RFC 7208","url":"https://www.rfc-editor.org/rfc/rfc7208"}]}},{"id":"dkim","category":"auth","status":"fail","title":"DKIM","summary":"no signature","citations":{}},{"id":"links","category":"content","status":"warn","title":"Link density","summary":"heavy","citations":{}}]}"#;

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_lifecycle_notice_and_sanitized_fetch() {
        let f = state_with(
            vec![
                Step::get("init", &["f=get_email_address"], 200, GM_ADDR)
                    .respond_headers(&[("set-cookie", "PHPSESSID=sess-1; path=/")]),
                Step::get("poll", &["f=check_email"], 200, GM_CHECK),
                Step::get("fetch", &["f=fetch_email", "email_id=7001"], 200, GM_FETCH),
                Step::post("extend", &["f=extend"], 200, GM_EXTEND),
                Step::post("forget", &["f=forget_me"], 200, GM_FORGET),
            ],
            "tm-life",
        );

        let mb = tempmail_create_impl(&f.state, None).await.unwrap();
        assert_eq!(mb.address, "itest01@guerrillamailblock.com");
        assert!(mb.public_inbox_notice.contains("PUBLIC"));

        let poll = tempmail_poll_impl(&f.state).await.unwrap();
        assert_eq!(poll.messages.len(), 1);
        assert_eq!(poll.messages[0].mail_id, "7001");
        assert!(poll.public_inbox_notice.contains("PUBLIC"));

        let msg = tempmail_fetch_impl(&f.state, "7001").await.unwrap();
        let html = msg.html.expect("html body");
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("click me"));
        assert!(!html.contains("script"));
        assert!(!html.contains("tracker.example"));
        assert_eq!(msg.remote_images_stripped, 1);
        assert!(msg.public_inbox_notice.contains("PUBLIC"));
        assert!(audit_log(&f.state).contains("tempmail-create-intent"));

        let ext = tempmail_extend_impl(&f.state).await.unwrap();
        assert!(ext.extended && !ext.expired);
        let d = tempmail_discard_impl(&f.state).await.unwrap();
        assert!(d.discarded && d.remote_forgotten);
        assert!(
            tempmail_poll_impl(&f.state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_fetch_html_has_no_navigable_anchor() {
        let f = state_with(
            vec![
                Step::get("init", &["f=get_email_address"], 200, GM_ADDR),
                Step::get("fetch", &["f=fetch_email", "email_id=7001"], 200, GM_FETCH),
            ],
            "tm-anchors",
        );
        tempmail_create_impl(&f.state, None).await.unwrap();
        let msg = tempmail_fetch_impl(&f.state, "7001").await.unwrap();
        let html = msg.html.expect("html body");
        let lowered = html.to_ascii_lowercase();
        for forbidden in [
            "<a ",
            "href",
            "xlink",
            "javascript:",
            "data:text/html",
            "mailto:",
            "<form",
            "<input",
            "onclick",
            "<svg",
            "evil.example",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "{forbidden} survived display-only sanitization: {html}"
            );
        }
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_create_with_local_part_and_notice_on_all() {
        let f = state_with(
            vec![
                Step::get("init", &["f=get_email_address"], 200, GM_ADDR),
                Step::post(
                    "rename",
                    &["f=set_email_user", "email_user=mymbox"],
                    200,
                    r#"{"email_addr":"mymbox@sharklasers.com","email_timestamp":"1758300100"}"#,
                ),
            ],
            "tm-local",
        );
        let mb = tempmail_create_impl(&f.state, Some("mymbox".into()))
            .await
            .unwrap();
        assert_eq!(mb.address, "mymbox@sharklasers.com");
        assert!(mb.public_inbox_notice.contains("PUBLIC"));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_poll_without_session_is_not_found() {
        let state = test_state("tm-nosess");
        assert!(
            tempmail_poll_impl(&state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
        assert!(
            tempmail_fetch_impl(&state, "1")
                .await
                .is_err_and(|e| e.code == "not-found")
        );
        assert!(
            tempmail_extend_impl(&state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
        assert!(
            tempmail_discard_impl(&state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_local_part_validated_before_network() {
        let state = test_state("tm-badlp");
        // ScriptedHttp would panic on any request — none must happen.
        assert!(
            tempmail_create_impl(&state, Some("bad..dots".into()))
                .await
                .is_err_and(|e| e.code == "invalid-input")
        );
        assert!(
            tempmail_create_impl(&state, Some(".lead".into()))
                .await
                .is_err_and(|e| e.code == "invalid-input")
        );
        assert!(
            tempmail_create_impl(&state, Some("has space".into()))
                .await
                .is_err_and(|e| e.code == "invalid-input")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_failed_candidate_forgets_remote_and_keeps_old_session() {
        let f = state_with(
            vec![
                Step::get("init-1", &["f=get_email_address"], 200, GM_ADDR),
                Step::get("init-2", &["f=get_email_address"], 200, GM_ADDR_2),
                Step::post("rename-fails", &["f=set_email_user"], 502, "{}"),
                Step::post("forget-candidate", &["f=forget_me"], 200, GM_FORGET),
                Step::get("poll-old", &["f=check_email"], 200, GM_CHECK),
            ],
            "tm-candidate",
        );
        let first = tempmail_create_impl(&f.state, None).await.unwrap();
        assert_eq!(first.address, "itest01@guerrillamailblock.com");

        let failed = tempmail_create_impl(&f.state, Some("newbox".into())).await;
        assert!(failed.is_err_and(|e| e.code == "integration-error"));

        let poll = tempmail_poll_impl(&f.state).await.unwrap();
        assert_eq!(
            poll.address.as_deref(),
            Some("itest01@guerrillamailblock.com")
        );
        let log = audit_log(&f.state);
        assert!(log.contains("tempmail-create-failed"));
        assert!(log.contains("remote forget ok"));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_failed_candidate_keeps_old_session_when_cleanup_fails() {
        let f = state_with(
            vec![
                Step::get("init-1", &["f=get_email_address"], 200, GM_ADDR),
                Step::get("init-2", &["f=get_email_address"], 200, GM_ADDR_2),
                Step::post("rename-fails", &["f=set_email_user"], 502, "{}"),
                Step::post("forget-candidate-fails", &["f=forget_me"], 500, "{}"),
                Step::get("poll-old", &["f=check_email"], 200, GM_CHECK),
            ],
            "tm-candidate2",
        );
        tempmail_create_impl(&f.state, None).await.unwrap();
        assert!(
            tempmail_create_impl(&f.state, Some("newbox".into()))
                .await
                .is_err_and(|e| e.code == "integration-error")
        );
        assert!(
            tempmail_poll_impl(&f.state)
                .await
                .is_ok_and(|p| p.total_new == 1)
        );
        assert!(audit_log(&f.state).contains("remote forget failed"));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_replacement_retires_previous_remote_session() {
        let f = state_with(
            vec![
                Step::get("init-1", &["f=get_email_address"], 200, GM_ADDR),
                Step::get("init-2", &["f=get_email_address"], 200, GM_ADDR_2),
                Step::post("forget-old", &["f=forget_me"], 200, GM_FORGET),
                Step::get("poll-new", &["f=check_email"], 200, GM_CHECK),
            ],
            "tm-replace",
        );
        tempmail_create_impl(&f.state, None).await.unwrap();
        let second = tempmail_create_impl(&f.state, None).await.unwrap();
        assert_eq!(second.address, "itest02@guerrillamailblock.com");
        let log = audit_log(&f.state);
        assert!(log.contains("tempmail-replaced"));
        assert!(log.contains("replaced, previous forgotten"));
        tempmail_poll_impl(&f.state).await.unwrap();
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_create_aborts_when_intent_cannot_be_audited() {
        let f = state_with(
            vec![Step::get("init", &["f=get_email_address"], 200, GM_ADDR)],
            "tm-intent",
        );
        f.state.audit.lock().await.inject_failure();
        let err = tempmail_create_impl(&f.state, None).await.unwrap_err();
        assert_eq!(err.code, "io-error");
        assert_eq!(f.http.unconsumed(), vec!["init"]);
        assert!(
            tempmail_poll_impl(&f.state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_begin_send_status_report_flow() {
        let f = state_with(
            vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get(
                    "pending",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    202,
                    ST_STATUS_PENDING_202,
                ),
                Step::get(
                    "ready",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    200,
                    ST_STATUS_READY,
                ),
                Step::get("report", &["/api/v1/tests/fx-slug-9u2n4k"], 200, ST_REPORT),
            ],
            "d-flow",
        );
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();

        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        assert_eq!(begin.address, "drop-k7f2@in.email-spam-tester.example");
        assert!(!begin.consent_token.is_empty());
        assert!(begin.consent_notice.contains("third-party"));
        assert!(!format!("{begin:?}").contains(&begin.consent_token));

        let bad = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            "consent-wrong",
            &acct.id,
            compose(),
        )
        .await;
        assert!(bad.is_err_and(|e| e.code == "consent-required"));
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        assert!(!audit_log(&f.state).contains("deliverability-send-intent"));

        let st = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(st.analysis_status, "pending");
        assert!(!st.ready && !st.sent && !st.consent_consumed);
        assert!(st.retry_after_ms.is_none());

        let sent = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap();
        assert!(sent.enqueued && sent.consent_consumed && sent.single_attempt);
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 1);
        {
            let meta = f.state.outbox_meta.lock().await;
            let m = meta.get(&sent.queue_id).expect("outbox meta");
            assert_eq!(m.to, vec!["drop-k7f2@in.email-spam-tester.example"]);
            assert!(m.class.is_single_attempt());
        }

        let replay = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await;
        assert!(replay.is_err_and(|e| e.code == "consent-required"));

        let st = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert!(st.ready && st.sent && st.consent_consumed);
        assert_eq!((st.checks_done, st.checks_total), (3, 3));

        let rep = deliverability_report_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(rep.score_ours_milli, Some(87_000));
        assert_eq!(rep.checks.len(), 3);
        assert_eq!(rep.auth_failure_ids, vec!["dkim"]);
        assert_eq!(rep.tallies["auth"].fail, 1);
        assert_eq!(rep.tallies["content"].warn, 1);
        assert_eq!(rep.checks[0].category, "auth");
        assert_eq!(rep.auth_gate.state, "blocked");
        assert!(!rep.auth_gate.clear);
        assert_eq!(rep.auth_gate.failed_ids, vec!["dkim"]);
        assert!(!rep.checks_truncated);
        assert!(rep.evidence_complete);
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_unknown_test_is_not_found() {
        let state = test_state("d-ghost");
        let acct = add_account_impl(&state, acct_input()).await.unwrap();
        let r = deliverability_send_impl(
            &state,
            "dtest-ghost",
            "consent-anything",
            &acct.id,
            compose(),
        )
        .await;
        assert!(r.is_err_and(|e| e.code == "not-found"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_report_gate_blocks_on_auth_failure() {
        let f = state_with(
            vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get("report", &["/api/v1/tests/fx-slug-9u2n4k"], 200, ST_REPORT),
            ],
            "d-gate",
        );
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let rep = deliverability_report_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        let json = serde_json::to_value(&rep).unwrap();
        assert_eq!(json["authGate"]["state"], "blocked");
        assert_eq!(json["authGate"]["clear"], false);
        assert_eq!(json["authGate"]["failedIds"][0], "dkim");
        assert_eq!(json["checksTruncated"], false);
        assert_eq!(json["evidenceComplete"], true);
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_report_truncation_never_reads_as_complete() {
        let checks: Vec<String> = (0..=MAX_CHECKS)
            .map(|i| {
                format!(
                    r#"{{"id":"auth-{i}","category":"auth","status":"pass","title":"t","summary":"s","citations":{{}}}}"#
                )
            })
            .collect();
        let body = format!(
            r#"{{"score_ours":50.0,"score_compat":5.0,"complete":true,"checks":[{}]}}"#,
            checks.join(",")
        );
        let f = state_with(
            vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get(
                    "report",
                    &["/api/v1/tests/fx-slug-9u2n4k"],
                    200,
                    leaked(body),
                ),
            ],
            "d-trunc",
        );
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let rep = deliverability_report_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(rep.checks.len(), MAX_CHECKS);
        assert!(rep.checks_truncated);
        assert!(rep.complete, "the provider flag is preserved verbatim");
        assert!(!rep.evidence_complete);
        assert_eq!(rep.auth_gate.state, "incomplete");
        assert_eq!(rep.auth_gate.gap, Some("truncated-checks"));
        let json = serde_json::to_value(&rep).unwrap();
        assert_eq!(json["complete"], true);
        assert_eq!(json["checksTruncated"], true);
        assert_eq!(json["evidenceComplete"], false);
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_failure_never_marks_enqueued() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "d-nofail",
        );
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let err = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            "acct-does-not-exist",
            compose(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "not-found");
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        assert!(f.state.outbox_meta.lock().await.is_empty());
        {
            let sessions = f.state.deliverability.lock().await;
            let s = sessions.get(&begin.test_id).unwrap();
            assert!(s.consent_consumed, "the capability is spent either way");
            assert!(!s.enqueued, "a failed enqueue is never `sent`");
            assert!(s.queue_id.is_none());
        }
        let log = audit_log(&f.state);
        assert!(log.contains("deliverability-send-intent"));
        assert!(log.contains("deliverability-send-failed"));
        assert!(log.contains("not enqueued"));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_is_durable_single_attempt_class() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "d-class",
        );
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let sent = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap();

        assert!(f.state.single_attempt.lock().await.contains(&sent.queue_id));
        let ordinary = crate::commands::send::send_impl(&f.state, &acct.id, compose(), None)
            .await
            .unwrap();
        assert!(
            !f.state
                .single_attempt
                .lock()
                .await
                .contains(&ordinary.queue_id)
        );
        let on_disk =
            std::fs::read_to_string(f.state.data_dir.join("outbox_single_attempt.json")).unwrap();
        assert!(on_disk.contains(&sent.queue_id));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_send_keeps_the_retryable_class() {
        let f = state_with(vec![], "ordinary-class");
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let sent = crate::commands::send::send_impl(&f.state, &acct.id, compose(), None)
            .await
            .unwrap();
        let meta: OutboxMeta = f
            .state
            .outbox_meta
            .lock()
            .await
            .get(&sent.queue_id)
            .cloned()
            .unwrap();
        assert_eq!(meta.class, OutboxClass::Ordinary);
        assert_eq!(meta.attempts, 0);
        assert!(!f.state.single_attempt.lock().await.contains(&sent.queue_id));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_send_never_prompts_for_native_confirmation() {
        let state = test_state("consent-ordinary");
        let consent = Arc::new(FixedSendConsent::denying());
        *state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&state, acct_input()).await.unwrap();
        crate::commands::send::send_impl(&state, &acct.id, compose(), None)
            .await
            .unwrap();
        assert!(consent.requests().is_empty());
        assert_eq!(state.send_queue.lock().await.pending_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_denial_never_enqueues() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "consent-deny",
        );
        let consent = Arc::new(FixedSendConsent::denying());
        *f.state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let err = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "consent-required");
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        assert!(
            f.state
                .store
                .lock()
                .await
                .outbox_list(10)
                .unwrap()
                .is_empty()
        );
        let sessions = f.state.deliverability.lock().await;
        let session = &sessions[&begin.test_id];
        assert!(session.consent_consumed);
        assert!(!session.enqueued);
        assert!(session.queue_id.is_none());
        drop(sessions);
        let requests = consent.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].destinations[0].kind,
            IntegrationDestinationKind::DeliverabilityTest
        );
        assert_eq!(requests[0].destinations[0].address, begin.address);
        let log = audit_log(&f.state);
        assert!(log.contains("send-consent-denied"));
        assert!(log.contains("deliverability-send-intent"));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_send_to_temp_inbox_prompts_and_can_be_denied() {
        let f = state_with(
            vec![Step::get("init", &["f=get_email_address"], 200, GM_ADDR)],
            "consent-temp",
        );
        let consent = Arc::new(FixedSendConsent::denying());
        *f.state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let mailbox = tempmail_create_impl(&f.state, None).await.unwrap();
        let mut message = compose();
        message.to = vec![mailbox.address.clone()];
        let err = crate::commands::send::send_impl(&f.state, &acct.id, message, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "consent-required");
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        let requests = consent.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].destinations[0].kind,
            IntegrationDestinationKind::TempInbox
        );
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn integration_prompt_burst_is_denied_and_audited() {
        let f = state_with(
            vec![Step::get("init", &["f=get_email_address"], 200, GM_ADDR)],
            "consent-burst",
        );
        let consent = Arc::new(FixedSendConsent::denying());
        *f.state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let mailbox = tempmail_create_impl(&f.state, None).await.unwrap();
        for _ in 0..3 {
            let mut message = compose();
            message.to = vec![mailbox.address.clone()];
            let err = crate::commands::send::send_impl(&f.state, &acct.id, message, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, "consent-required");
        }
        let mut message = compose();
        message.to = vec![mailbox.address.clone()];
        let err = crate::commands::send::send_impl(&f.state, &acct.id, message, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "consent-throttled");
        assert_eq!(consent.requests().len(), 3);
        assert!(audit_log(&f.state).contains("send-consent-burst-denied"));
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_send_to_reserved_address_cannot_bypass_native_confirmation() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "consent-bypass",
        );
        let consent = Arc::new(FixedSendConsent::denying());
        *f.state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let mut message = compose();
        message.to = vec![begin.address.clone()];
        let err = crate::commands::send::send_impl(&f.state, &acct.id, message, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, "consent-required");
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        let requests = consent.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].destinations[0].address, begin.address);
        assert_eq!(
            requests[0].destinations[0].kind,
            IntegrationDestinationKind::DeliverabilityTest
        );
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_approval_prompts_once_then_enqueues() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "consent-approve",
        );
        let consent = Arc::new(FixedSendConsent::approving());
        *f.state.send_consent.lock().unwrap() = consent.clone();
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let sent = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap();
        assert!(sent.enqueued && sent.consent_consumed);
        assert_eq!(consent.requests().len(), 1);
        assert_eq!(
            consent.requests()[0].destinations[0].kind,
            IntegrationDestinationKind::DeliverabilityTest
        );
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_attempt_item_is_never_retried_after_restart() {
        let dir = temp_dir("d-restart");
        let (test_id, queue_id) = {
            let http = Arc::new(ScriptedHttp::new(vec![Step::post(
                "reserve",
                &["/api/v1/inbox"],
                200,
                ST_RESERVE,
            )]));
            let state = AppState::open_test_with_http(dir.clone(), http).unwrap();
            let acct = add_account_impl(&state, acct_input()).await.unwrap();
            let begin = deliverability_begin_impl(&state).await.unwrap();
            let sent = deliverability_send_impl(
                &state,
                &begin.test_id,
                &begin.consent_token,
                &acct.id,
                compose(),
            )
            .await
            .unwrap();
            assert_eq!(state.send_queue.lock().await.pending_count(), 1);
            (begin.test_id.clone(), sent.queue_id)
        };

        let state = AppState::open_test(dir.clone()).unwrap();
        assert_eq!(state.send_queue.lock().await.pending_count(), 0);
        assert!(state.outbox_meta.lock().await.is_empty());
        assert!(state.store.lock().await.outbox_list(10).unwrap().is_empty());
        assert!(!state.single_attempt.lock().await.contains(&queue_id));
        let log = audit_log(&state);
        assert!(log.contains("send-abandoned-no-retry"));
        assert!(log.contains(&queue_id));
        assert!(
            deliverability_status_impl(&state, &test_id)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_begin_aborts_when_intent_cannot_be_audited() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "d-beginintent",
        );
        f.state.audit.lock().await.inject_failure();
        let err = deliverability_begin_impl(&f.state).await.unwrap_err();
        assert_eq!(err.code, "io-error");
        assert_eq!(f.http.unconsumed(), vec!["reserve"]);
        assert!(f.state.deliverability.lock().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_aborts_when_intent_cannot_be_audited() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "d-sendintent",
        );
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        f.state.audit.lock().await.inject_failure();
        let err = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "io-error");
        assert_eq!(f.state.send_queue.lock().await.pending_count(), 0);
        {
            let sessions = f.state.deliverability.lock().await;
            let s = sessions.get(&begin.test_id).unwrap();
            assert!(!s.consent_consumed, "no effect ran, so nothing is spent");
            assert!(!s.enqueued);
            assert!(s.consent_token.is_some());
        }
        let sent = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap();
        assert!(sent.enqueued);
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_send_surfaces_completion_audit_failure() {
        let f = state_with(
            vec![Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE)],
            "d-completeaudit",
        );
        let acct = add_account_impl(&f.state, acct_input()).await.unwrap();
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        f.state.audit.lock().await.inject_failure_after(2);
        let err = deliverability_send_impl(
            &f.state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            compose(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "io-error");
        {
            let sessions = f.state.deliverability.lock().await;
            let s = sessions.get(&begin.test_id).unwrap();
            assert!(s.enqueued, "the queue is real, so the state says so");
        }
        let log = audit_log(&f.state);
        assert!(log.contains("deliverability-send-intent"));
        assert!(log.contains("send-queued"));
        assert!(!log.contains("\"deliverability-send\""));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_poll_rate_limited_sets_a_cooldown() {
        let f = state_with(
            vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get(
                    "first",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    200,
                    ST_STATUS_RECEIVED,
                ),
                Step::get(
                    "limited",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    429,
                    "{}",
                )
                .respond_headers(&[("retry-after", "5")]),
            ],
            "d-429",
        );
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let first = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(first.analysis_status, "received");
        assert_eq!(first.checks_done, 1);

        let limited = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap_err();
        assert_eq!(limited.code, "rate-limited");
        let hint = limited.retry_after_ms.expect("structured retry hint");
        assert!(
            (PROVIDER_429_COOLDOWN_MS..=PROVIDER_429_COOLDOWN_MS + 5_000).contains(&hint),
            "the enforced cooldown must dominate a 5 s server hint: {hint}"
        );
        let json = serde_json::to_value(&limited).unwrap();
        assert_eq!(json["code"], "rate-limited");
        assert_eq!(json["retryAfterMs"], hint);

        let cached = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(cached.analysis_status, "received");
        assert_eq!(cached.checks_done, first.checks_done);
        assert!(cached.retry_after_ms.is_some_and(|ms| ms <= hint));
        f.http.assert_exhausted();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliverability_poll_cooldown_without_a_cached_status_errors() {
        let f = state_with(
            vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get(
                    "limited",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    429,
                    "{}",
                )
                .respond_headers(&[("retry-after", "120")]),
                Step::get(
                    "never-called",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    200,
                    ST_STATUS_READY,
                ),
            ],
            "d-429b",
        );
        let begin = deliverability_begin_impl(&f.state).await.unwrap();
        let err = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap_err();
        assert_eq!(err.code, "rate-limited");
        assert!(err.retry_after_ms.is_some_and(|ms| ms >= 120_000));
        let again = deliverability_status_impl(&f.state, &begin.test_id)
            .await
            .unwrap_err();
        assert_eq!(again.code, "rate-limited");
        assert_eq!(
            f.http.unconsumed(),
            vec!["never-called"],
            "the cooldown must not amplify provider calls"
        );
    }

    #[test]
    fn cooldown_math_is_floor_bounded_and_expiring() {
        let mut c = PollCooldowns::default();
        assert!(c.remaining("t", 1_000).is_none());
        let until = c.note("t", Some(5_000), 1_000);
        assert_eq!(until, 1_000 + PROVIDER_429_COOLDOWN_MS as i64);
        assert_eq!(c.remaining("t", 2_000), Some(29_000));
        assert!(c.remaining("t", until).is_none());
        let _until = c.note("t", Some(600_000), 1_000);
        assert_eq!(c.remaining("t", 1_000), Some(600_000));
        c.forget("t");
        assert!(c.remaining("t", 1_000).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn default_test_state_refuses_provider_network() {
        let state = test_state("integ-offline");
        assert!(
            tempmail_create_impl(&state, None)
                .await
                .is_err_and(|e| e.code == "connect-failed")
        );
        assert!(
            deliverability_begin_impl(&state)
                .await
                .is_err_and(|e| e.code == "connect-failed")
        );
        assert!(
            state.offline_attempts(),
            "the default test transport must have seen both calls"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn integrations_respect_lock_gate() {
        let state = test_state("integ-locked");
        state.trust.lock().await.force_lock();
        assert!(gate(&state).await.is_err_and(|e| e.code == "locked"));
    }

    #[test]
    fn consent_compare_is_exact() {
        assert!(consent_ok("abc", "abc"));
        assert!(!consent_ok("abc", "abd"));
        assert!(!consent_ok("abc", "abcd"));
        assert!(!consent_ok("abc", ""));
    }

    struct SlowHttp {
        inner: ScriptedHttp,
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Notify>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl kiwi_integrations::http::HttpClient for SlowHttp {
        async fn request(
            &self,
            req: HttpRequest,
        ) -> Result<HttpResponse, kiwi_integrations::IntegrationError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered.add_permits(1);
            self.release.notified().await;
            self.inner.request(req).await
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tempmail_lifecycle_is_serialized() {
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(SlowHttp {
            inner: ScriptedHttp::new(vec![
                Step::get("init", &["f=get_email_address"], 200, GM_ADDR),
                Step::post("forget", &["f=forget_me"], 200, GM_FORGET),
            ]),
            entered: entered.clone(),
            release: release.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let state = Arc::new(
            AppState::open_test_with_http(temp_dir("tm-serial"), transport.clone()).unwrap(),
        );

        // create is parked inside the provider, holding the session lock.
        let creating = {
            let s = state.clone();
            tokio::spawn(async move { tempmail_create_impl(&s, None).await })
        };
        entered
            .acquire()
            .await
            .expect("create entered the transport")
            .forget();

        let discarding = {
            let s = state.clone();
            tokio::spawn(async move { tempmail_discard_impl(&s).await })
        };
        // The discard cannot interleave: it waits for create to finish, so
        // it retires the session create just installed.
        release.notify_one();
        let created = creating.await.unwrap().unwrap();
        assert_eq!(created.address, "itest01@guerrillamailblock.com");
        entered
            .acquire()
            .await
            .expect("discard reached the transport")
            .forget();
        release.notify_one();
        let discarded = discarding.await.unwrap().unwrap();
        assert!(discarded.discarded && discarded.remote_forgotten);

        assert!(
            tempmail_poll_impl(&state)
                .await
                .is_err_and(|e| e.code == "not-found"),
            "the discard must have run after the create, not before it"
        );
        transport.inner.assert_exhausted();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deliverability_poll_is_single_flight() {
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(SlowHttp {
            inner: ScriptedHttp::new(vec![
                Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
                Step::get(
                    "poll",
                    &["/api/v1/tests/fx-slug-9u2n4k/status"],
                    200,
                    ST_STATUS_READY,
                ),
            ]),
            entered: entered.clone(),
            release: release.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let state = Arc::new(
            AppState::open_test_with_http(temp_dir("d-single"), transport.clone()).unwrap(),
        );

        let reserving = {
            let s = state.clone();
            tokio::spawn(async move { deliverability_begin_impl(&s).await })
        };
        entered
            .acquire()
            .await
            .expect("reserve entered the transport")
            .forget();
        release.notify_one();
        let begin = reserving.await.unwrap().unwrap();

        let polling = {
            let s = state.clone();
            let id = begin.test_id.clone();
            tokio::spawn(async move { deliverability_status_impl(&s, &id).await })
        };
        entered
            .acquire()
            .await
            .expect("poll entered the transport")
            .forget();

        let second = deliverability_status_impl(&state, &begin.test_id).await;
        let busy = second.unwrap_err();
        assert_eq!(busy.code, "poll-in-flight");
        assert_eq!(busy.retry_after_ms, Some(POLL_BUSY_RETRY_MS));

        release.notify_one();
        let done = polling.await.unwrap().unwrap();
        assert!(done.ready);
        assert_eq!(done.checks_done, 3);
        assert_eq!(
            transport.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one provider call per operation, no amplification"
        );
        transport.inner.assert_exhausted();
    }
}
