//! External mail-service integrations (T-227) — the IPC surface for
//! `kiwi-integrations` behind the lock gate. Two tools:
//!
//! ## Temp mail (`integrations_tempmail_*`)
//!
//! One in-memory GuerrillaMail session at a time — `create` mints or
//! replaces it, `poll`/`fetch`/`extend`/`discard` act on it. Every
//! response carries `publicInboxNotice` verbatim (the binding UI
//! disclosure — a public disposable inbox is a hostile-content surface).
//!
//! `fetch` never returns raw RFC822 to the webview: the synthesized
//! message is parsed by `kiwi_mail::mime` and the HTML body passes
//! through the same `sanitize_html` path as real mail — with remote
//! resources ALWAYS stripped, regardless of any account opt-in (a
//! public inbox must never load remote content: tracking surface).
//!
//! ## Deliverability (`integrations_deliverability_*`)
//!
//! `begin` reserves a single-use address and mints a random consent
//! token. `send` REQUIRES that token — the check + consume happen
//! backend-side under the sessions lock, so the webview cannot skip or
//! replay consent (it is a capability, not a flag). `status`/`report`
//! are single-shot calls; any poll loop is the caller's job.
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
use crate::commands::message::sanitize_html;
use crate::commands::send::send_impl;
use crate::error::{CmdResult, IpcError};
use crate::state::{
    AppState, DeliverabilitySession, MAX_DELIVERABILITY_SESSIONS, new_id, now_unix,
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

    let gm = GuerrillaMail::new(
        state.integrations_http.clone(),
        GUERRILLA_API,
        INTEGRATIONS_AGENT,
    )
    .map_err(IpcError::from)?;
    let mut addr = gm.get_email_address().await.map_err(IpcError::from)?;
    if let Some(p) = &local_part {
        addr = gm.set_email_user(p).await.map_err(IpcError::from)?;
    }
    let view = TempMailboxView {
        address: addr.address.clone(),
        address_created_unix: addr.created_unix,
        public_inbox_notice: kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE,
    };
    // Replace any existing session — the dropped provider carries its
    // session secrets away; nothing was persisted.
    *state.tempmail.lock().await = Some(gm);
    state.audit.lock().await.record(
        "tempmail-create",
        &format!("{} via guerrillamail", addr.address),
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
    let (html, stripped) = match parsed.html_body {
        Some(h) => {
            let (clean, s) = sanitize_html(&h, false);
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
/// best-effort (a dead session may already be gone server-side).
#[tauri::command]
pub async fn kiwi_integrations_tempmail_discard(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<TempDiscardView> {
    gate(state.inner()).await?;
    tempmail_discard_impl(state.inner()).await
}

pub(crate) async fn tempmail_discard_impl(state: &AppState) -> CmdResult<TempDiscardView> {
    let gm = state.tempmail.lock().await.take();
    let Some(gm) = gm else {
        return Err(IpcError::not_found(
            "no active temp-mail session to discard",
        ));
    };
    let remote_forgotten = gm.forget_me().await.is_ok();
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
    let tester = spamtester(state)?;
    let res = tester.reserve_inbox().await.map_err(IpcError::from)?;

    let test_id = new_id("dtest");
    let consent_token = new_id("consent");
    let view = DeliverabilityBeginView {
        test_id: test_id.clone(),
        address: res.address.clone(),
        expires_at_unix: res.expires_at_unix,
        expires_at_raw: res.expires_at_raw.clone(),
        consent_token,
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
                sessions.pop_first();
            }
        }
        sessions.insert(
            test_id.clone(),
            DeliverabilitySession {
                reservation: res,
                consent_token: Some(view.consent_token.clone()),
                sent: false,
            },
        );
    }
    // Audit: test_id + address only — NEVER the slug or consent token.
    state.audit.lock().await.record(
        "deliverability-begin",
        &format!("{test_id} reserved {}", view.address),
        now_unix(),
    )?;
    Ok(view)
}

/// Single-use consent check — constant-time compare on a fixed-format
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
/// CONSENT IS NON-BYPASSABLE: the token minted by `begin` must match the
/// stored one and is consumed atomically under the sessions lock before
/// the send is enqueued — the webview cannot fabricate or replay it.
/// The message's own `to`/`cc`/`bcc` are ignored: the only recipient is
/// the reserved single-use address. The send rides the normal outbox
/// (undo-send grace applies), so dispatch is audited like any send.
#[tauri::command]
pub async fn kiwi_integrations_deliverability_send(
    state: State<'_, Arc<AppState>>,
    test_id: String,
    consent_token: String,
    account_id: String,
    message: ComposeInput,
) -> CmdResult<DeliverabilitySendView> {
    gate(state.inner()).await?;
    deliverability_send_impl(
        state.inner(),
        &test_id,
        &consent_token,
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
        let mut sessions = state.deliverability.lock().await;
        let Some(session) = sessions.get_mut(test_id) else {
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
        session.consent_token = None;
        session.sent = true;
        session.reservation.address.clone()
    };

    let mut forced = message;
    forced.to = vec![address];
    forced.cc = Vec::new();
    forced.bcc = Vec::new();
    let receipt = send_impl(state, account_id, forced, None).await?;
    state.audit.lock().await.record(
        "deliverability-send",
        &format!("{test_id} enqueued as {}", receipt.queue_id),
        now_unix(),
    )?;
    Ok(DeliverabilitySendView {
        test_id: test_id.to_string(),
        queue_id: receipt.queue_id,
        not_before_unix: receipt.not_before_unix,
    })
}

/// `kiwi_integrations_deliverability_status(testId)` →
/// `DeliverabilityStatusView`. Single-shot; the UI owns the poll loop.
#[tauri::command]
pub async fn kiwi_integrations_deliverability_status(
    state: State<'_, Arc<AppState>>,
    test_id: String,
) -> CmdResult<DeliverabilityStatusView> {
    gate(state.inner()).await?;
    deliverability_status_impl(state.inner(), &test_id).await
}

pub(crate) async fn deliverability_status_impl(
    state: &AppState,
    test_id: &str,
) -> CmdResult<DeliverabilityStatusView> {
    bounded("testId", test_id, 128)?;
    let res = reservation_for(state, test_id).await?;
    let sent = state
        .deliverability
        .lock()
        .await
        .get(test_id)
        .map(|s| s.sent)
        .unwrap_or(false);
    let status = spamtester(state)?
        .poll_status(&res)
        .await
        .map_err(IpcError::from)?;
    Ok(DeliverabilityStatusView::from_status(test_id, status, sent))
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
    use kiwi_integrations::http::{ScriptedHttp, Step};

    fn state_with(script: Vec<Step>, tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-integ-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test_with_http(dir, Arc::new(ScriptedHttp::new(script))).unwrap()
    }

    // Recorded responses (synthetic — no real mail ever enters fixtures).
    const GM_ADDR: &str = r#"{"email_addr":"itest01@guerrillamailblock.com","email_timestamp":"1758300000","sid_token":"sid-fixture-1"}"#;
    const GM_CHECK: &str = r#"{"list":[{"mail_id":"7001","mail_from":"svc@test.example","mail_subject":"Confirm &lt;kiwi&gt;","mail_excerpt":"Body preview","mail_timestamp":"1758300120","mail_date":"2026-09-25 12:00:00","mail_read":"0","mail_size":"1234"}],"count":"1","email":"itest01@guerrillamailblock.com","stats":{"mail_host":"sharklasers.com"}}"#;
    const GM_FETCH: &str = r#"{"mail_id":"7001","mail_from":"svc@test.example","mail_subject":"Confirm <kiwi>","mail_excerpt":"Body preview","mail_timestamp":"1758300120","mail_date":"2026-09-25 12:00:00","mail_read":"0","mail_size":"1234","content_type":"text/html","mail_body":"<html><body><h1>Hello</h1><script>alert(1)</script><img src=\"https://tracker.example/x.png\"></body></html>","att":0,"attachments":[]}"#;
    const GM_EXTEND: &str = r#"{"expired":false,"affected":"1","email_timestamp":"1758300000"}"#;
    const GM_FORGET: &str = "true";

    const ST_RESERVE: &str = r#"{"address":"drop-k7f2@in.email-spam-tester.example","slug":"fx-slug-9u2n4k","expires_at":1758307200}"#;
    const ST_STATUS_PENDING_202: &str = "{}";
    const ST_STATUS_READY: &str =
        r#"{"analysis_status":"checks_ready","checks_done":3,"checks_total":3}"#;
    const ST_REPORT: &str = r#"{"score_ours":87.0,"score_compat":9.1,"complete":true,"report_url":"https://email-spam-tester.example/r/fx","subscores":{"auth":100000,"infra_spam":80000,"content":90000,"compliance":100000},"checks":[{"id":"spf","category":"auth","status":"pass","title":"SPF","summary":"passes","citations":{"standards":[{"title":"RFC 7208","url":"https://www.rfc-editor.org/rfc/rfc7208"}]}},{"id":"dkim","category":"auth","status":"fail","title":"DKIM","summary":"no signature","citations":{}},{"id":"links","category":"content","status":"warn","title":"Link density","summary":"heavy","citations":{}}]}"#;

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_lifecycle_notice_and_sanitized_fetch() {
        let http = vec![
            Step::get("init", &["f=get_email_address"], 200, GM_ADDR)
                .respond_headers(&[("set-cookie", "PHPSESSID=sess-1; path=/")]),
            Step::get("poll", &["f=check_email"], 200, GM_CHECK),
            Step::get("fetch", &["f=fetch_email", "email_id=7001"], 200, GM_FETCH),
            Step::post("extend", &["f=extend"], 200, GM_EXTEND),
            Step::post("forget", &["f=forget_me"], 200, GM_FORGET),
        ];
        let state = state_with(http, "tm-life");

        let mb = tempmail_create_impl(&state, None).await.unwrap();
        assert_eq!(mb.address, "itest01@guerrillamailblock.com");
        assert!(mb.public_inbox_notice.contains("PUBLIC"));

        let poll = tempmail_poll_impl(&state).await.unwrap();
        assert_eq!(poll.messages.len(), 1);
        assert_eq!(poll.messages[0].mail_id, "7001");
        assert!(poll.public_inbox_notice.contains("PUBLIC"));

        let msg = tempmail_fetch_impl(&state, "7001").await.unwrap();
        // Script stripped by the sanitizer; remote img src dropped.
        let html = msg.html.expect("html body");
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(!html.contains("script"));
        assert!(!html.contains("tracker.example"));
        assert_eq!(msg.remote_images_stripped, 1);
        assert!(msg.public_inbox_notice.contains("PUBLIC"));

        let ext = tempmail_extend_impl(&state).await.unwrap();
        assert!(ext.extended && !ext.expired);

        let d = tempmail_discard_impl(&state).await.unwrap();
        assert!(d.discarded && d.remote_forgotten);
        // Session gone — poll fails not-found now.
        assert!(
            tempmail_poll_impl(&state)
                .await
                .is_err_and(|e| e.code == "not-found")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tempmail_create_with_local_part_and_notice_on_all() {
        let http = vec![
            Step::get("init", &["f=get_email_address"], 200, GM_ADDR),
            Step::post(
                "rename",
                &["f=set_email_user", "email_user=mymbox"],
                200,
                r#"{"email_addr":"mymbox@sharklasers.com","email_timestamp":"1758300100"}"#,
            ),
        ];
        let state = state_with(http, "tm-local");
        let mb = tempmail_create_impl(&state, Some("mymbox".into()))
            .await
            .unwrap();
        assert_eq!(mb.address, "mymbox@sharklasers.com");
        assert!(mb.public_inbox_notice.contains("PUBLIC"));
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
    async fn deliverability_begin_send_status_report_flow() {
        let http = vec![
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
        ];
        let state = state_with(http, "d-flow");
        let acct = add_account_impl(&state, acct_input()).await.unwrap();

        let begin = deliverability_begin_impl(&state).await.unwrap();
        assert_eq!(begin.address, "drop-k7f2@in.email-spam-tester.example");
        assert!(!begin.consent_token.is_empty());
        assert!(begin.consent_notice.contains("third-party"));

        // Send is gated on the token — wrong token refused, no send queued.
        let msg = crate::types::ComposeInput {
            to: vec!["attacker@elsewhere.example".into()], // ignored
            cc: vec![],
            bcc: vec![],
            subject: "probe".into(),
            text: "body".into(),
            html: None,
            in_reply_to: None,
            references: vec![],
            attachments: vec![],
        };
        let bad = deliverability_send_impl(
            &state,
            &begin.test_id,
            "consent-wrong",
            &acct.id,
            msg.clone(),
        )
        .await;
        assert!(bad.is_err_and(|e| e.code == "consent-required"));
        assert_eq!(state.send_queue.lock().await.pending_count(), 0);

        let st = deliverability_status_impl(&state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(st.analysis_status, "pending");
        assert!(!st.ready && !st.sent);

        // Correct token → one send enqueued to the RESERVED address only.
        let sent =
            deliverability_send_impl(&state, &begin.test_id, &begin.consent_token, &acct.id, msg)
                .await
                .unwrap();
        assert_eq!(state.send_queue.lock().await.pending_count(), 1);
        let meta = state.outbox_meta.lock().await;
        let m = meta.get(&sent.queue_id).expect("outbox meta");
        assert_eq!(m.to, vec!["drop-k7f2@in.email-spam-tester.example"]);
        drop(meta);

        // Token is single-use — replay is refused.
        let replay = deliverability_send_impl(
            &state,
            &begin.test_id,
            &begin.consent_token,
            &acct.id,
            crate::types::ComposeInput {
                to: vec![],
                cc: vec![],
                bcc: vec![],
                subject: "x".into(),
                text: "y".into(),
                html: None,
                in_reply_to: None,
                references: vec![],
                attachments: vec![],
            },
        )
        .await;
        assert!(replay.is_err_and(|e| e.code == "consent-required"));

        let st = deliverability_status_impl(&state, &begin.test_id)
            .await
            .unwrap();
        assert!(st.ready && st.sent);
        assert_eq!((st.checks_done, st.checks_total), (3, 3));

        let rep = deliverability_report_impl(&state, &begin.test_id)
            .await
            .unwrap();
        assert_eq!(rep.score_ours_milli, Some(87_000));
        assert_eq!(rep.checks.len(), 3);
        assert_eq!(rep.auth_failure_ids, vec!["dkim"]);
        assert_eq!(rep.tallies["auth"].fail, 1);
        assert_eq!(rep.tallies["content"].warn, 1);
        assert_eq!(rep.checks[0].category, "auth");
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
            crate::types::ComposeInput {
                to: vec![],
                cc: vec![],
                bcc: vec![],
                subject: "s".into(),
                text: "t".into(),
                html: None,
                in_reply_to: None,
                references: vec![],
                attachments: vec![],
            },
        )
        .await;
        assert!(r.is_err_and(|e| e.code == "not-found"));
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
}
