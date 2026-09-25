//! Unsubscribe execution (T-234, completes F3): turns the stored
//! List-Unsubscribe offer on a message row into exactly one action.
//!
//! - `action = "http"` POSTs the advertised `https:` endpoint through the
//!   shared `HttpClient` seam (`integrations_http` — HTTPS-only, no
//!   redirects, capped response body). When the offer carries the RFC 8058
//!   marker the POST sends the `List-Unsubscribe=One-Click` form body;
//!   otherwise it is a bare POST (the endpoint decides what happens).
//! - `action = "mailto"` enqueues a minimal unsubscribe message through
//!   the normal outbox (`send_impl`) — undo-send grace applies.
//!
//! Consent is enforced here, server-side — the webview's flags are data,
//! not authority:
//!
//! - `mailto` ALWAYS requires `consent: true` — sending a mail from the
//!   user's own address reveals identity to the list operator, so it is
//!   never silent.
//! - `http` requires `oneClick` on the stored offer OR `consent: true`.
//!   A one-click endpoint is already a defined single-request semantic
//!   (RFC 8058 §3) initiated by the user's click; a plain http URL is a
//!   web flow whose side effects are unknown, so it needs the flag.
//!
//! A refused call returns `consent-required` and touches nothing — no
//! HTTP request, no outbox row, no audit entry. Every executed action
//! writes one audit row (`unsubscribe-http` / `unsubscribe-mailto`).

use std::sync::Arc;

use tauri::State;

use kiwi_integrations::http::HttpRequest;
use kiwi_mail::unsub::UnsubscribeInfo;

use super::super::{bounded, gate, valid_addr};
use super::owned_folder;
use crate::commands::send::send_impl;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{ComposeInput, UnsubscribeResultView};

/// RFC 8058 §3 one-click form body.
const ONE_CLICK_BODY: &[u8] = b"List-Unsubscribe=One-Click";

/// `kiwi_message_unsubscribe(accountId, folderId, uid, action, consent)`
/// → `UnsubscribeResultView`.
///
/// `action` is `"http"` or `"mailto"`. `consent` is the caller's explicit
/// consent flag — semantics documented on the module (always required for
/// `mailto`; required for `http` when the offer is not RFC 8058 one-click).
#[tauri::command]
pub async fn kiwi_message_unsubscribe(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    folder_id: i64,
    uid: i64,
    action: String,
    consent: Option<bool>,
) -> CmdResult<UnsubscribeResultView> {
    gate(state.inner()).await?;
    unsubscribe_impl(
        state.inner(),
        &account_id,
        folder_id,
        uid,
        &action,
        consent == Some(true),
    )
    .await
}

pub(crate) async fn unsubscribe_impl(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: i64,
    action: &str,
    consent: bool,
) -> CmdResult<UnsubscribeResultView> {
    bounded("accountId", account_id, 128)?;
    if uid < 0 {
        return Err(IpcError::invalid("uid must be >= 0"));
    }
    // The ref is only meaningful if the folder belongs to the account —
    // same ownership check every message action performs.
    owned_folder(state, account_id, folder_id).await?;
    let offer = state
        .store
        .lock()
        .await
        .unsubscribe_offer(folder_id, uid as u64)?
        .ok_or_else(|| IpcError::not_found("unknown message"))?;

    match action {
        "http" => unsub_http(state, account_id, folder_id, uid, &offer, consent).await,
        "mailto" => unsub_mailto(state, account_id, folder_id, uid, &offer, consent).await,
        _ => Err(IpcError::invalid("action must be \"http\" or \"mailto\"")),
    }
}

/// POST the advertised https endpoint. One-click offers POST the RFC 8058
/// body; other offers need the caller's consent flag.
async fn unsub_http(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: i64,
    offer: &UnsubscribeInfo,
    consent: bool,
) -> CmdResult<UnsubscribeResultView> {
    let url = offer
        .http_url
        .as_deref()
        .ok_or_else(|| IpcError::not_found("message advertises no unsubscribe URL"))?;
    if !offer.one_click && !consent {
        return Err(IpcError::new(
            "consent-required",
            "http unsubscribe on a non-one-click endpoint requires explicit consent",
        ));
    }
    let url = url.trim();
    if !url.starts_with("https://") {
        return Err(IpcError::invalid("stored unsubscribe URL is not https"));
    }
    let req = if offer.one_click {
        HttpRequest::post(url, Some(ONE_CLICK_BODY.to_vec()))
            .header("content-type", "application/x-www-form-urlencoded")
    } else {
        HttpRequest::post(url, None)
    };
    let resp = state
        .integrations_http
        .request(req)
        .await
        .map_err(IpcError::from)?;
    state.audit.lock().await.record(
        "unsubscribe-http",
        &format!("{account_id}/f{folder_id}/u{uid} → http {}", resp.status),
        now_unix(),
    )?;
    Ok(UnsubscribeResultView {
        action: "http",
        executed: true,
        http_status: Some(resp.status),
        queue_id: None,
        undo_window_until_unix: None,
    })
}

/// Enqueue a minimal unsubscribe mail through the normal outbox. Always
/// consent-gated — the send reveals the user's own address.
async fn unsub_mailto(
    state: &AppState,
    account_id: &str,
    folder_id: i64,
    uid: i64,
    offer: &UnsubscribeInfo,
    consent: bool,
) -> CmdResult<UnsubscribeResultView> {
    let addr = offer
        .mailto
        .as_deref()
        .ok_or_else(|| IpcError::not_found("message advertises no unsubscribe address"))?;
    if !consent {
        return Err(IpcError::new(
            "consent-required",
            "unsubscribe mail requires explicit consent — it sends from this account",
        ));
    }
    // Stored value is params-stripped at ingest; revalidate anyway — the
    // boundary rule is check-on-use, not trust-the-store.
    valid_addr("unsubscribeMailto", addr)?;
    let message = ComposeInput {
        to: vec![addr.to_string()],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "unsubscribe".into(),
        text: "unsubscribe".into(),
        html: None,
        in_reply_to: None,
        references: Vec::new(),
        attachments: Vec::new(),
    };
    let receipt = send_impl(state, account_id, message, None).await?;
    state.audit.lock().await.record(
        "unsubscribe-mailto",
        &format!(
            "{} via {account_id} for f{folder_id}/u{uid}",
            receipt.queue_id
        ),
        now_unix(),
    )?;
    Ok(UnsubscribeResultView {
        action: "mailto",
        executed: true,
        http_status: None,
        queue_id: Some(receipt.queue_id),
        undo_window_until_unix: Some(receipt.undo_window_until_unix),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_integrations::http::{ScriptedHttp, Step};
    use kiwi_mail::account::{AuthRef, IncomingAccount, MailAccount, OutgoingAccount};
    use kiwi_mail::store::NewMessageMeta;
    use kiwi_mail::transport::SocketSecurity;
    use kiwi_mail::{account::IncomingProtocol, unsub::UnsubscribeInfo};

    fn state_with(script: Vec<Step>, tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-unsub-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test_with_http(dir, Arc::new(ScriptedHttp::new(script))).unwrap()
    }

    /// Seed a POP3 account (no live connection path), an INBOX folder, and
    /// one message carrying `offer`. Returns `(account_id, folder_id, uid)`.
    async fn seed(state: &AppState, offer: Option<UnsubscribeInfo>) -> (String, i64, i64) {
        let acct = MailAccount {
            account_id: "a1".into(),
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Pop3,
                server: kiwi_mail::account::ServerConfig {
                    host: "pop.x.test".into(),
                    port: 995,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
            outgoing: OutgoingAccount {
                server: kiwi_mail::account::ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                username: "a".into(),
                auth: AuthRef::None,
            },
        };
        let store = state.store.lock().await;
        store.upsert_account(&acct).unwrap();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store
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
        if let Some(info) = offer {
            assert!(store.set_unsubscribe(fid, 7, &info).unwrap());
        }
        ("a1".into(), fid, 7)
    }

    fn offer(http: Option<&str>, mailto: Option<&str>, one_click: bool) -> UnsubscribeInfo {
        UnsubscribeInfo {
            http_url: http.map(str::to_string),
            mailto: mailto.map(str::to_string),
            one_click,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_one_click_posts_rfc8058_body() {
        let state = state_with(
            vec![Step {
                expect_body: Some(b"List-Unsubscribe=One-Click"),
                ..Step::post("unsub", &["unsubscribe.example"], 200, "ok")
                    .expect_header("content-type", "application/x-www-form-urlencoded")
            }],
            "oneclick",
        );
        let (acct, fid, uid) = seed(
            &state,
            Some(offer(
                Some("https://unsubscribe.example/x?token=t1"),
                None,
                true,
            )),
        )
        .await;
        // One-click needs NO consent flag — the marker is the authorization.
        let v = unsubscribe_impl(&state, &acct, fid, uid, "http", false)
            .await
            .unwrap();
        assert_eq!(v.action, "http");
        assert!(v.executed);
        assert_eq!(v.http_status, Some(200));
        assert!(v.queue_id.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_plain_url_needs_consent_then_posts() {
        let state = state_with(
            vec![Step::post("unsub", &["unsubscribe.example"], 202, "")],
            "consent",
        );
        let (acct, fid, uid) = seed(
            &state,
            Some(offer(
                Some("https://unsubscribe.example/leave"),
                None,
                false,
            )),
        )
        .await;
        // No flag → consent-required, and no request leaves the process.
        let denied = unsubscribe_impl(&state, &acct, fid, uid, "http", false)
            .await
            .unwrap_err();
        assert_eq!(denied.code, "consent-required");
        // consent=true → bare POST (no one-click body).
        let v = unsubscribe_impl(&state, &acct, fid, uid, "http", true)
            .await
            .unwrap();
        assert_eq!(v.http_status, Some(202));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_refuses_insecure_stored_url() {
        // A tampered/legacy `http://` row must never reach the transport.
        let state = state_with(vec![], "insecure");
        let (acct, fid, uid) = seed(
            &state,
            Some(offer(Some("http://unsubscribe.example/x"), None, true)),
        )
        .await;
        let err = unsubscribe_impl(&state, &acct, fid, uid, "http", true)
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid-input");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mailto_requires_consent_and_enqueues() {
        let state = state_with(vec![], "mailto");
        let (acct, fid, uid) =
            seed(&state, Some(offer(None, Some("leave@list.example"), false))).await;
        let denied = unsubscribe_impl(&state, &acct, fid, uid, "mailto", false)
            .await
            .unwrap_err();
        assert_eq!(denied.code, "consent-required");
        assert_eq!(state.send_queue.lock().await.pending_count(), 0);

        let v = unsubscribe_impl(&state, &acct, fid, uid, "mailto", true)
            .await
            .unwrap();
        assert_eq!(v.action, "mailto");
        assert!(v.executed);
        assert!(v.queue_id.is_some());
        assert!(v.undo_window_until_unix.is_some());
        assert_eq!(state.send_queue.lock().await.pending_count(), 1);
        // The mail goes ONLY to the advertised unsubscribe address.
        let metas = state.outbox_meta.lock().await;
        let meta = metas.get(v.queue_id.as_deref().unwrap()).unwrap();
        assert_eq!(meta.to, vec!["leave@list.example".to_string()]);
        assert_eq!(meta.subject, "unsubscribe");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_offer_is_not_found() {
        let state = state_with(vec![], "missing");
        let (acct, fid, uid) = seed(&state, None).await;
        let err = unsubscribe_impl(&state, &acct, fid, uid, "http", true)
            .await
            .unwrap_err();
        assert_eq!(err.code, "not-found");
        let err = unsubscribe_impl(&state, &acct, fid, uid, "mailto", true)
            .await
            .unwrap_err();
        assert_eq!(err.code, "not-found");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bad_action_is_invalid_input() {
        let state = state_with(vec![], "badact");
        let (acct, fid, uid) = seed(&state, Some(offer(None, None, false))).await;
        let err = unsubscribe_impl(&state, &acct, fid, uid, "smoke-signal", true)
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid-input");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn locked_gate_blocks() {
        let state = state_with(vec![], "locked");
        let (acct, fid, uid) = seed(&state, Some(offer(None, None, true))).await;
        state.trust.lock().await.force_lock();
        let err = kiwi_message_unsubscribe_impl_gate(&state, &acct, fid, uid)
            .await
            .unwrap_err();
        assert_eq!(err.code, "locked");
    }

    /// The `#[tauri::command]` wrapper itself is the gate site — exercise it.
    async fn kiwi_message_unsubscribe_impl_gate(
        state: &AppState,
        account_id: &str,
        folder_id: i64,
        uid: i64,
    ) -> CmdResult<UnsubscribeResultView> {
        gate(state).await?;
        unsubscribe_impl(state, account_id, folder_id, uid, "http", true).await
    }
}
