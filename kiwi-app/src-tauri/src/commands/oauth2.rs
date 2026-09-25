//! OAuth2 acquisition commands (T-230) — the account-wizard seam for
//! XOAUTH2 providers, over the `kiwi-autoconfig::oauth2` engine
//! (`kiwi.oauth2/1`).
//!
//! Flow:
//!
//! 1. `kiwi_discover_account(email)` — the suggestion carries an `oauth2`
//!    spec when its endpoints are OAuth2-capable.
//! 2. `kiwi_oauth2_begin(provider, email?)` — device-code grants return
//!    `userCode`/`verificationUri` to display; loopback grants return
//!    `authorizeUrl` to open in the system browser (the `127.0.0.1`
//!    listener is already bound and a waiter thread is parked on it).
//! 3. `kiwi_oauth2_poll(ticketId)` — `pending` / `complete` / `error`.
//!    On complete the `TokenSet` is persisted through the
//!    `CredentialStore` seam under `oauth2/<provider>/<email>` — or held
//!    in the session when `begin` was called without an email.
//! 4. `kiwi_add_account` with `incomingAuth/outgoingAuth`
//!    `{kind:"xoauth2", oauth2Ticket}` binds the stored grant to the
//!    account — token material never crosses IPC.
//!
//! `kiwi_oauth2_status(accountId)` reports a stored account's grant
//! posture (presence, expiry, refresh-token flag) without secrets.
//!
//! Secrets discipline (SECURITY.md, oauth2.md §5): the PKCE verifier,
//! device code, and token bytes live only inside `PendingGrant`/
//! `TokenSet` (Zeroizing + redacted Debug) and the OS credential store.
//! IPC sees key names and lifecycle metadata only.

use std::sync::Arc;

use tauri::State;

use kiwi_autoconfig::oauth2::{
    self, OAuthClient, OAuthError, OAuthFlow, OAuthTransport, PendingGrant, PollOutcome,
    ProviderConfig, TokenSet, TransportReply, credential_key, load_tokens,
    provider_id_for_suggestion, save_tokens,
};
use kiwi_integrations::http::HttpClient;
use kiwi_mail::account::AuthRef;

use super::{bounded, gate, valid_addr};
use crate::error::{CmdResult, IpcError};
use crate::state::{
    AppState, MAX_OAUTH2_SESSIONS, OAUTH2_LOOPBACK_TIMEOUT_SECS, OAuth2Session, OAuth2SessionState,
    new_id, now_unix,
};
use crate::types::{
    OAuth2BeginView, OAuth2CancelView, OAuth2PollView, OAuth2SpecView, OAuth2StatusView,
};

/// Poll cadence hint returned for loopback grants — the provider controls
/// device-code pacing but the loopback listener has no such signal; the
/// UI re-polls on this fixed hint.
const LOOPBACK_POLL_HINT_SECS: u64 = 1;

// ---------------------------------------------------------------------------
// Transport bridge — the shared integrations HttpClient IS an OAuthTransport
// (blanket impl), but `&dyn HttpClient` cannot unsize to `&dyn
// OAuthTransport`, so a Clone+Send+Sync newtype re-exposes it.
// ---------------------------------------------------------------------------

/// `Arc<dyn HttpClient>` re-exported as a concrete `OAuthTransport`.
#[derive(Clone)]
pub(crate) struct SharedTransport(pub Arc<dyn HttpClient>);

#[async_trait::async_trait]
impl OAuthTransport for SharedTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<TransportReply, OAuthError> {
        OAuthTransport::post_form(&*self.0, url, form).await
    }
}

// ---------------------------------------------------------------------------
// Config + error mapping
// ---------------------------------------------------------------------------

/// Public client id for a provider — deployment config, never a secret.
/// Resolution order: `KIWI_OAUTH2_<ID>_CLIENT_ID` env (admin-forced)
/// beats the `oauth2.<id>.clientId` global pref (user/provisioned).
async fn client_id_for(state: &AppState, provider_id: &str) -> CmdResult<String> {
    let env_key = format!("KIWI_OAUTH2_{}_CLIENT_ID", provider_id.to_ascii_uppercase());
    if let Ok(v) = std::env::var(&env_key) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let key = crate::state::pref_key(None, &format!("oauth2.{provider_id}.clientId"));
    let pref = state.index.lock().await.prefs.get(&key).cloned();
    if let Some(v) = pref.and_then(|v| v.as_str().map(str::to_string)) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(IpcError::new(
        "oauth2-not-configured",
        format!(
            "no OAuth2 client_id configured for provider {provider_id:?} — \
             set pref `oauth2.{provider_id}.clientId` or env `{env_key}`"
        ),
    ))
}

/// `OAuthError` → IPC `(code, message)`. Codes are contract-stable;
/// messages are already secret-free by construction.
fn oauth_code(e: &OAuthError) -> (&'static str, String) {
    use OAuthError::*;
    match e {
        InsecureUrl => ("oauth2-error", "refused non-HTTPS endpoint".to_string()),
        Transport { kind } => (
            "connect-failed",
            format!("oauth endpoint unreachable ({kind:?})"),
        ),
        BodyTooLarge => ("oauth2-error", "endpoint response too large".to_string()),
        Http { status } => ("oauth2-error", format!("endpoint returned HTTP {status}")),
        Endpoint { error, description } => (
            "oauth2-endpoint",
            match description {
                Some(d) => format!("endpoint error {error}: {d}"),
                None => format!("endpoint error {error}"),
            },
        ),
        Denied => ("oauth2-denied", "user denied authorization".to_string()),
        Expired => ("oauth2-expired", "grant expired".to_string()),
        InvalidGrant => (
            "oauth2-reauth",
            "grant invalid or revoked — re-authorization required".to_string(),
        ),
        StateMismatch => ("oauth2-error", "redirect state mismatch".to_string()),
        Malformed(field) => ("oauth2-error", format!("malformed oauth payload: {field}")),
        UnsupportedGrant { .. } => ("internal", "grant kind mismatch".to_string()),
        Loopback(detail) => ("oauth2-error", format!("loopback listener: {detail}")),
        InvalidConfig(field) => (
            "oauth2-not-configured",
            format!("invalid oauth config: {field}"),
        ),
        CredentialStore(detail) => ("store-error", format!("credential store: {detail}")),
        Entropy => ("internal", "entropy source unavailable".to_string()),
    }
}

fn oauth_ipc_err(e: OAuthError) -> IpcError {
    let (code, message) = oauth_code(&e);
    IpcError::new(code, message)
}

/// Terminal vs transient split for poll: endpoint denials, expiry, and
/// malformed/rejecting responses kill the grant (`status:"error"`);
/// transport failures stay IPC errors so the grant survives a dropped
/// connection.
fn is_terminal(e: &OAuthError) -> bool {
    !matches!(
        e,
        OAuthError::Transport { .. } | OAuthError::CredentialStore(_)
    )
}

// ---------------------------------------------------------------------------
// begin
// ---------------------------------------------------------------------------

/// `kiwi_oauth2_begin(provider, email?) → OAuth2BeginView`.
#[tauri::command]
pub async fn kiwi_oauth2_begin(
    state: State<'_, Arc<AppState>>,
    provider: String,
    email: Option<String>,
) -> CmdResult<OAuth2BeginView> {
    gate(state.inner()).await?;
    oauth2_begin_impl(state.inner(), &provider, email.as_deref()).await
}

pub(crate) async fn oauth2_begin_impl(
    state: &AppState,
    provider: &str,
    email: Option<&str>,
) -> CmdResult<OAuth2BeginView> {
    bounded("provider", provider, 32)?;
    let provider_id = provider.trim().to_ascii_lowercase();
    if !oauth2::KNOWN_PROVIDERS.contains(&provider_id.as_str()) {
        return Err(IpcError::invalid(format!(
            "unknown oauth2 provider {provider:?} (supported: {})",
            oauth2::KNOWN_PROVIDERS.join(", ")
        )));
    }
    let email = email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(e) = &email {
        valid_addr("email", e)?;
    }

    let client_id = client_id_for(state, &provider_id).await?;
    let config = ProviderConfig::by_id(&provider_id, &client_id).map_err(oauth_ipc_err)?;
    let flow = OAuthClient::new(config.clone());
    let http = SharedTransport(state.integrations_http.clone());
    let now = now_unix();
    let grant = flow.begin(&http, now).await.map_err(oauth_ipc_err)?;

    let ticket = new_id("oauth2");
    let (view, session_state) = match grant {
        PendingGrant::Device(g) => {
            let (user_code, verification_uri, verification_uri_complete, expires_at, interval) = (
                g.user_code.clone(),
                g.verification_uri.clone(),
                g.verification_uri_complete.clone(),
                g.expires_at_unix,
                g.poll_interval_secs,
            );
            (
                OAuth2BeginView {
                    ticket_id: ticket.clone(),
                    kind: "device_code".to_string(),
                    authorize_url: None,
                    user_code: Some(user_code),
                    verification_uri: Some(verification_uri),
                    verification_uri_complete,
                    expires_at_unix: Some(expires_at),
                    poll_interval_secs: Some(interval),
                },
                OAuth2SessionState::Device {
                    grant: PendingGrant::Device(g),
                    interval_secs: interval,
                    expires_at_unix: Some(expires_at),
                },
            )
        }
        PendingGrant::Loopback(g) => {
            let authorize_url = g.authorize_url.clone();
            let slot = Arc::new(std::sync::Mutex::new(None));
            spawn_loopback_waiter(
                slot.clone(),
                PendingGrant::Loopback(g),
                config.clone(),
                state.integrations_http.clone(),
            );
            (
                OAuth2BeginView {
                    ticket_id: ticket.clone(),
                    kind: "loopback_code".to_string(),
                    authorize_url: Some(authorize_url),
                    user_code: None,
                    verification_uri: None,
                    verification_uri_complete: None,
                    expires_at_unix: Some(now + OAUTH2_LOOPBACK_TIMEOUT_SECS as i64),
                    poll_interval_secs: Some(LOOPBACK_POLL_HINT_SECS),
                },
                OAuth2SessionState::Loopback { result: slot },
            )
        }
    };

    {
        let mut sessions = state.oauth2_sessions.lock().await;
        if sessions.len() >= MAX_OAUTH2_SESSIONS {
            evict_oauth2_sessions(&mut sessions, now);
            while sessions.len() >= MAX_OAUTH2_SESSIONS {
                // Key order isn't insertion order — evict the OLDEST
                // session by creation time.
                if let Some(oldest) = sessions
                    .iter()
                    .min_by_key(|(_, s)| s.created_unix)
                    .map(|(k, _)| k.clone())
                {
                    sessions.remove(&oldest);
                } else {
                    break;
                }
            }
        }
        sessions.insert(
            ticket.clone(),
            OAuth2Session {
                provider: config,
                email: email.clone(),
                created_unix: now,
                state: session_state,
            },
        );
    }
    state.audit.lock().await.record(
        "oauth2-begin",
        &format!(
            "{provider_id} {} grant {}",
            view.kind,
            email.as_deref().unwrap_or("<no-email-yet>")
        ),
        now,
    )?;
    Ok(view)
}

/// Drop dead sessions first (device-expired, failed); then oldest.
fn evict_oauth2_sessions(
    sessions: &mut std::collections::BTreeMap<String, OAuth2Session>,
    now: i64,
) {
    sessions.retain(|_, s| match &s.state {
        OAuth2SessionState::Device {
            expires_at_unix: Some(exp),
            ..
        } => *exp > now,
        OAuth2SessionState::Device {
            expires_at_unix: None,
            ..
        } => true,
        OAuth2SessionState::Loopback { .. } => {
            s.created_unix + OAUTH2_LOOPBACK_TIMEOUT_SECS as i64 > now
        }
        OAuth2SessionState::Failed { .. } => false,
        OAuth2SessionState::Completed { .. } | OAuth2SessionState::CompletedDeferred { .. } => true,
    });
}

/// Park a thread on the loopback listener: wait for the browser redirect
/// (bounded by [`OAUTH2_LOOPBACK_TIMEOUT_SECS`]), then exchange the code.
/// The grant — listener, PKCE verifier, state — moves into the thread;
/// the slot receives the outcome exactly once.
fn spawn_loopback_waiter(
    slot: Arc<std::sync::Mutex<Option<Result<TokenSet, OAuthError>>>>,
    grant: PendingGrant,
    provider: ProviderConfig,
    http: Arc<dyn HttpClient>,
) {
    std::thread::spawn(move || {
        let result = match grant
            .wait_for_redirect(std::time::Duration::from_secs(OAUTH2_LOOPBACK_TIMEOUT_SECS))
        {
            Err(e) => Err(e),
            Ok(redirect) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match rt {
                    Err(e) => Err(OAuthError::Loopback(format!("runtime: {e}"))),
                    Ok(rt) => rt.block_on(async {
                        let http = SharedTransport(http);
                        OAuthClient::new(provider)
                            .exchange(&http, &grant, &redirect, now_unix())
                            .await
                    }),
                }
            }
        };
        if let Ok(mut slot) = slot.lock() {
            *slot = Some(result);
        }
    });
}

// ---------------------------------------------------------------------------
// poll
// ---------------------------------------------------------------------------

/// `kiwi_oauth2_poll(ticketId) → OAuth2PollView`.
#[tauri::command]
pub async fn kiwi_oauth2_poll(
    state: State<'_, Arc<AppState>>,
    ticket_id: String,
) -> CmdResult<OAuth2PollView> {
    gate(state.inner()).await?;
    oauth2_poll_impl(state.inner(), &ticket_id).await
}

fn pending_view(ticket_id: &str, retry_after_secs: u64) -> OAuth2PollView {
    OAuth2PollView {
        status: "pending".to_string(),
        ticket_id: ticket_id.to_string(),
        retry_after_secs: Some(retry_after_secs),
        provider: None,
        email: None,
        credential_key: None,
        error_code: None,
        error_message: None,
    }
}

fn error_view(ticket_id: &str, code: &'static str, message: String) -> OAuth2PollView {
    OAuth2PollView {
        status: "error".to_string(),
        ticket_id: ticket_id.to_string(),
        retry_after_secs: None,
        provider: None,
        email: None,
        credential_key: None,
        error_code: Some(code.to_string()),
        error_message: Some(message),
    }
}

/// Persist-or-defer on grant completion: email known → `save_tokens` via
/// the CredentialStore seam; unknown → tokens stay in-session until
/// `kiwi_add_account` binds an address.
fn complete_grant(
    state: &AppState,
    session: &mut OAuth2Session,
    tokens: TokenSet,
) -> CmdResult<(Option<String>, Option<String>)> {
    let provider_id = session.provider.id;
    match session.email.clone() {
        Some(email) => {
            save_tokens(state.credentials.as_ref(), provider_id, &email, &tokens)
                .map_err(oauth_ipc_err)?;
            let key = credential_key(provider_id, &email);
            session.state = OAuth2SessionState::Completed {
                credential_key: key.clone(),
            };
            Ok((Some(email), Some(key)))
        }
        None => {
            session.state = OAuth2SessionState::CompletedDeferred { tokens };
            Ok((None, None))
        }
    }
}

pub(crate) async fn oauth2_poll_impl(
    state: &AppState,
    ticket_id: &str,
) -> CmdResult<OAuth2PollView> {
    bounded("ticketId", ticket_id, 64)?;
    // The sessions lock is held across the provider poll deliberately —
    // same reasoning as `tempmail_poll_impl`: one in-flight poll per
    // grant, and the flow takes no other `AppState` locks. A device poll
    // is a single bounded HTTPS POST; the loopback path does no I/O.
    let mut sessions = state.oauth2_sessions.lock().await;
    let Some(session) = sessions.get_mut(ticket_id) else {
        return Err(IpcError::not_found("unknown or expired oauth2 ticket"));
    };
    let now = now_unix();

    let view = match &mut session.state {
        OAuth2SessionState::Device {
            grant,
            interval_secs,
            ..
        } => {
            let http = SharedTransport(state.integrations_http.clone());
            let flow = OAuthClient::new(session.provider.clone());
            match flow.poll(&http, grant, now).await {
                Ok(PollOutcome::Pending) => pending_view(ticket_id, *interval_secs),
                Ok(PollOutcome::SlowDown { retry_after_secs }) => {
                    *interval_secs = retry_after_secs;
                    pending_view(ticket_id, retry_after_secs)
                }
                Ok(PollOutcome::Complete(tokens)) => {
                    let (email, key) = complete_grant(state, session, tokens)?;
                    OAuth2PollView {
                        status: "complete".to_string(),
                        ticket_id: ticket_id.to_string(),
                        retry_after_secs: None,
                        provider: Some(session.provider.id.to_string()),
                        email,
                        credential_key: key,
                        error_code: None,
                        error_message: None,
                    }
                }
                Err(e) if is_terminal(&e) => {
                    let (code, message) = oauth_code(&e);
                    session.state = OAuth2SessionState::Failed {
                        code,
                        message: message.clone(),
                    };
                    error_view(ticket_id, code, message)
                }
                Err(e) => return Err(oauth_ipc_err(e)),
            }
        }
        OAuth2SessionState::Loopback { result } => {
            let settled = result.lock().ok().and_then(|mut s| s.take());
            match settled {
                None => pending_view(ticket_id, LOOPBACK_POLL_HINT_SECS),
                Some(Ok(tokens)) => {
                    let (email, key) = complete_grant(state, session, tokens)?;
                    OAuth2PollView {
                        status: "complete".to_string(),
                        ticket_id: ticket_id.to_string(),
                        retry_after_secs: None,
                        provider: Some(session.provider.id.to_string()),
                        email,
                        credential_key: key,
                        error_code: None,
                        error_message: None,
                    }
                }
                Some(Err(e)) => {
                    let (code, message) = oauth_code(&e);
                    session.state = OAuth2SessionState::Failed {
                        code,
                        message: message.clone(),
                    };
                    error_view(ticket_id, code, message)
                }
            }
        }
        OAuth2SessionState::Completed { credential_key } => OAuth2PollView {
            status: "complete".to_string(),
            ticket_id: ticket_id.to_string(),
            retry_after_secs: None,
            provider: Some(session.provider.id.to_string()),
            email: session.email.clone(),
            credential_key: Some(credential_key.clone()),
            error_code: None,
            error_message: None,
        },
        OAuth2SessionState::CompletedDeferred { .. } => OAuth2PollView {
            status: "complete".to_string(),
            ticket_id: ticket_id.to_string(),
            retry_after_secs: None,
            provider: Some(session.provider.id.to_string()),
            email: None,
            credential_key: None,
            error_code: None,
            error_message: None,
        },
        OAuth2SessionState::Failed { code, message } => {
            error_view(ticket_id, code, message.clone())
        }
    };
    let audit_state = match view.status.as_str() {
        "complete" => Some("oauth2-complete"),
        "error" => Some("oauth2-failed"),
        _ => None,
    };
    let audit_detail = format!("{ticket_id} {} {}", session.provider.id, view.status);
    drop(sessions);
    if let Some(tag) = audit_state {
        state.audit.lock().await.record(tag, &audit_detail, now)?;
    }
    Ok(view)
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------

/// `kiwi_oauth2_cancel(ticketId) → OAuth2CancelView`.
///
/// Drops the session. A loopback grant's listener keeps its OS socket
/// bound in the waiter thread until the grant deadline (bounded, and the
/// slot is gone so the outcome is discarded) — cancelling frees the
/// ticket and the wizard path, not the socket's remaining lifetime.
#[tauri::command]
pub async fn kiwi_oauth2_cancel(
    state: State<'_, Arc<AppState>>,
    ticket_id: String,
) -> CmdResult<OAuth2CancelView> {
    gate(state.inner()).await?;
    oauth2_cancel_impl(state.inner(), &ticket_id).await
}

pub(crate) async fn oauth2_cancel_impl(
    state: &AppState,
    ticket_id: &str,
) -> CmdResult<OAuth2CancelView> {
    bounded("ticketId", ticket_id, 64)?;
    let removed = state.oauth2_sessions.lock().await.remove(ticket_id);
    Ok(OAuth2CancelView {
        cancelled: removed.is_some(),
    })
}

// ---------------------------------------------------------------------------
// status — a stored account's grant posture
// ---------------------------------------------------------------------------

/// `kiwi_oauth2_status(accountId) → OAuth2StatusView`.
#[tauri::command]
pub async fn kiwi_oauth2_status(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> CmdResult<OAuth2StatusView> {
    gate(state.inner()).await?;
    oauth2_status_impl(state.inner(), &account_id).await
}

pub(crate) async fn oauth2_status_impl(
    state: &AppState,
    account_id: &str,
) -> CmdResult<OAuth2StatusView> {
    bounded("accountId", account_id, 128)?;
    let acct = state
        .store
        .lock()
        .await
        .get_account(account_id)?
        .ok_or_else(|| IpcError::not_found("unknown account"))?;

    let (auth_method, credential_key) = match &acct.incoming.auth {
        AuthRef::XOAuth2 { credential_key } => ("xoauth2", Some(credential_key.as_str())),
        AuthRef::Password { credential_key } => ("password", Some(credential_key.as_str())),
        AuthRef::Apop { credential_key } => ("apop", Some(credential_key.as_str())),
        AuthRef::None => ("none", None),
    };
    let credential_present = match credential_key {
        Some(k) => state.credentials.get(k)?.is_some(),
        None => false,
    };
    let now = now_unix();

    // Grant-key form `oauth2/<provider>/<email>` → a parseable TokenSet.
    let mut view = OAuth2StatusView {
        account_id: account_id.to_string(),
        auth_method: auth_method.to_string(),
        provider: None,
        email: None,
        credential_present,
        expires_at_unix: None,
        needs_refresh: None,
        has_refresh_token: None,
    };
    if let Some((provider_id, email)) = credential_key.and_then(parse_oauth2_key) {
        view.provider = Some(provider_id.to_string());
        view.email = Some(email.to_string());
        // Credential present but not a parseable token blob (legacy
        // inline-secret path) — report presence, no lifecycle detail.
        if let Ok(Some(tokens)) = load_tokens(state.credentials.as_ref(), provider_id, email) {
            view.expires_at_unix = tokens.expires_at_unix();
            view.needs_refresh = Some(tokens.needs_refresh(now));
            view.has_refresh_token = Some(tokens.refresh_token().is_some());
        }
    }
    Ok(view)
}

/// Split `oauth2/<provider>/<email>` — the credential-key form
/// `kiwi-autoconfig::oauth2::credential_key` emits.
fn parse_oauth2_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("oauth2/")?;
    let (provider, email) = rest.split_once('/')?;
    if provider.is_empty() || email.is_empty() {
        return None;
    }
    Some((provider, email))
}

// ---------------------------------------------------------------------------
// Ticket → account binding (used by kiwi_add_account, commands/accounts.rs)
// ---------------------------------------------------------------------------

/// Resolve the credential key for a completed OAuth2 ticket referenced by
/// an `AddAccountInput`. Both `incomingAuth` and `outgoingAuth` may name a
/// ticket; when they do they must name the SAME one (one grant covers
/// IMAP+SMTP). Validates grant completeness and email match, persists a
/// deferred grant, and returns the `oauth2/<provider>/<email>` key the
/// `AuthRef`s should carry. `None` when no ticket is referenced.
///
/// Does NOT consume the ticket — `consume_oauth2_ticket` runs only after
/// the account row exists, so a failed add leaves the grant usable.
pub(crate) async fn oauth2_ticket_key(
    state: &AppState,
    input: &crate::types::AddAccountInput,
) -> CmdResult<Option<String>> {
    let ids: Vec<&str> = [input.incoming_auth.as_ref(), input.outgoing_auth.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|a| a.oauth2_ticket.as_deref())
        .collect();
    if ids.is_empty() {
        return Ok(None);
    }
    // Ticket only meaningful on xoauth2 auth.
    for a in [input.incoming_auth.as_ref(), input.outgoing_auth.as_ref()]
        .into_iter()
        .flatten()
    {
        if a.oauth2_ticket.is_some() && a.kind != "xoauth2" {
            return Err(IpcError::invalid(
                "oauth2Ticket is valid only with auth kind \"xoauth2\"",
            ));
        }
    }
    if ids.iter().any(|id| *id != ids[0]) {
        return Err(IpcError::invalid(
            "one OAuth2 grant covers both directions — incomingAuth and \
             outgoingAuth must name the same oauth2Ticket",
        ));
    }
    let ticket = ids[0];
    bounded("oauth2Ticket", ticket, 64)?;

    let mut sessions = state.oauth2_sessions.lock().await;
    let Some(session) = sessions.get_mut(ticket) else {
        return Err(IpcError::new(
            "oauth2-incomplete",
            "oauth2 ticket is unknown or expired",
        ));
    };
    // A grant begun with an email must bind to the same address
    // (normalized, case-insensitive) — else a ticket for alice@ could
    // authorize tokens under bob@'s key.
    if let Some(e) = &session.email
        && !e.eq_ignore_ascii_case(input.email.trim())
    {
        return Err(IpcError::invalid(
            "oauth2 grant was acquired for a different email address",
        ));
    }
    let key = credential_key(session.provider.id, &input.email);
    match &mut session.state {
        OAuth2SessionState::Completed { credential_key } => Ok(Some(credential_key.clone())),
        OAuth2SessionState::CompletedDeferred { tokens } => {
            save_tokens(
                state.credentials.as_ref(),
                session.provider.id,
                &input.email,
                tokens,
            )
            .map_err(oauth_ipc_err)?;
            session.email = Some(input.email.clone());
            session.state = OAuth2SessionState::Completed {
                credential_key: key.clone(),
            };
            Ok(Some(key))
        }
        _ => Err(IpcError::new(
            "oauth2-incomplete",
            "oauth2 grant has not completed — poll until status is \"complete\"",
        )),
    }
}

/// Consume a ticket after the account row exists — one grant binds one
/// account. Best-effort: missing/expired sessions are already gone.
pub(crate) async fn consume_oauth2_ticket(state: &AppState, ticket_id: &str) {
    state.oauth2_sessions.lock().await.remove(ticket_id);
}

// ---------------------------------------------------------------------------
// Browser handoff — the OAuth2 UX needs the system browser, never a webview
// navigation (provider sign-in inside an embedded webview is both blocked
// by Google and a phishing surface).
// ---------------------------------------------------------------------------

/// `kiwi_open_external(url)` — open an HTTPS URL in the system browser.
///
/// Exists for the OAuth2 handoff (`authorizeUrl` / `verificationUri`) but
/// is a generic gated utility. Validation is fail-closed: `https://`
/// scheme only, bounded length, no whitespace/quotes — the URL is passed
/// as a single argv element to the OS opener (no shell parsing anywhere).
#[tauri::command]
pub async fn kiwi_open_external(state: State<'_, Arc<AppState>>, url: String) -> CmdResult<()> {
    gate(state.inner()).await?;
    open_external_impl(&url)
}

pub(crate) fn open_external_impl(url: &str) -> CmdResult<()> {
    bounded("url", url, 2048)?;
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Err(IpcError::invalid(
            "only https:// URLs may be opened in the system browser",
        ));
    }
    if url
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'"' || b == b'\'')
    {
        return Err(IpcError::invalid("url contains whitespace or quotes"));
    }
    let mut cmd = browser_command(url);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| IpcError::new("internal", format!("cannot open system browser: {e}")))?;
    Ok(())
}

/// The OS-native "open this URL" invocation — a direct exec, never a
/// shell, so the URL cannot inject arguments or commands.
#[cfg(target_os = "windows")]
fn browser_command(url: &str) -> std::process::Command {
    let mut c = std::process::Command::new("rundll32");
    c.arg("url.dll,FileProtocolHandler").arg(url);
    c
}
#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> std::process::Command {
    let mut c = std::process::Command::new("open");
    c.arg(url);
    c
}
#[cfg(all(unix, not(target_os = "macos")))]
fn browser_command(url: &str) -> std::process::Command {
    let mut c = std::process::Command::new("xdg-open");
    c.arg(url);
    c
}

/// The `oauth2` spec attached to a discovery suggestion (ipc.md §5) —
/// `Some` only when a shipped provider config can service the endpoint.
pub(crate) fn oauth2_spec_for(
    suggestion: &kiwi_autoconfig::suggest::AccountSuggestion,
) -> Option<OAuth2SpecView> {
    provider_id_for_suggestion(suggestion).map(|id| {
        let grant = ProviderConfig::by_id(id, "")
            .map(|c| c.grant_kind_str().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        OAuth2SpecView {
            provider: id.to_string(),
            grant,
        }
    })
}

// ---------------------------------------------------------------------------
// Tests — ScriptedHttp replays every endpoint call; loopback tests use real
// 127.0.0.1 sockets (the listener is a real bound socket by design).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::accounts::add_account_impl;
    use crate::commands::send::tests::{acct_input, test_state};
    use crate::types::{AddAccountInput, AuthInput};
    use kiwi_integrations::http::{ScriptedHttp, Step};

    fn state_with(script: Vec<Step>, tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-oauth2-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test_with_http(dir, Arc::new(ScriptedHttp::new(script))).unwrap()
    }

    /// Set the provider's client id via the pref path (deterministic — no
    /// env mutation races between parallel tests).
    async fn set_client_id(state: &AppState, provider: &str, id: &str) {
        let key = crate::state::pref_key(None, &format!("oauth2.{provider}.clientId"));
        state
            .index
            .lock()
            .await
            .prefs
            .insert(key, serde_json::Value::String(id.to_string()));
    }

    const MS_DEVICE: &str = r#"{"device_code":"DC-secret","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","verification_uri_complete":"https://microsoft.com/devicelogin?otc=ABCD","expires_in":900,"interval":5}"#;
    const MS_PENDING: &str = r#"{"error":"authorization_pending"}"#;
    const MS_SLOWDOWN: &str = r#"{"error":"slow_down"}"#;
    const MS_TOKEN: &str =
        r#"{"access_token":"AT-1","refresh_token":"RT-1","expires_in":3600,"token_type":"Bearer"}"#;
    const MS_DENIED: &str = r#"{"error":"authorization_declined","error_description":"nope"}"#;

    fn pending_step() -> Step {
        Step::post("poll", &["oauth2/v2.0/token"], 400, MS_PENDING)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn begin_rejects_unknown_provider() {
        let s = state_with(vec![], "badprov");
        let e = oauth2_begin_impl(&s, "aol", None).await.unwrap_err();
        assert_eq!(e.code, "invalid-input");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn begin_requires_client_id() {
        let s = state_with(vec![], "nocid");
        let e = oauth2_begin_impl(&s, "microsoft", Some("u@outlook.com"))
            .await
            .unwrap_err();
        assert_eq!(e.code, "oauth2-not-configured");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn device_begin_poll_complete_persists_tokens() {
        let s = state_with(
            vec![
                Step::post("devcode", &["devicecode"], 200, MS_DEVICE),
                pending_step(),
                Step::post("poll", &["oauth2/v2.0/token"], 400, MS_SLOWDOWN),
                Step::post("poll3", &["oauth2/v2.0/token"], 200, MS_TOKEN),
            ],
            "flow",
        );
        set_client_id(&s, "microsoft", "cid-ms").await;

        let b = oauth2_begin_impl(&s, "microsoft", Some("u@outlook.com"))
            .await
            .unwrap();
        assert_eq!(b.kind, "device_code");
        assert_eq!(b.user_code.as_deref(), Some("ABCD-EFGH"));
        assert_eq!(
            b.verification_uri.as_deref(),
            Some("https://microsoft.com/devicelogin")
        );
        assert_eq!(b.poll_interval_secs, Some(5));

        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "pending");
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "pending");
        assert_eq!(p.retry_after_secs, Some(10)); // interval + slow_down
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "complete");
        assert_eq!(p.provider.as_deref(), Some("microsoft"));
        assert_eq!(
            p.credential_key.as_deref(),
            Some("oauth2/microsoft/u@outlook.com")
        );

        // The blob landed in the credential store — never in the account DB.
        let blob = s
            .credentials
            .get("oauth2/microsoft/u@outlook.com")
            .unwrap()
            .expect("stored blob");
        assert!(blob.contains("AT-1"));
        // Repeat poll is idempotent-complete until the ticket is consumed.
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "complete");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn device_denial_is_terminal_error_status() {
        let s = state_with(
            vec![
                Step::post("devcode", &["devicecode"], 200, MS_DEVICE),
                Step::post("poll", &["oauth2/v2.0/token"], 400, MS_DENIED),
            ],
            "denied",
        );
        set_client_id(&s, "microsoft", "cid-ms").await;
        let b = oauth2_begin_impl(&s, "microsoft", Some("u@outlook.com"))
            .await
            .unwrap();
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "error");
        assert_eq!(p.error_code.as_deref(), Some("oauth2-denied"));
        // Failed state is sticky.
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "error");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_unknown_ticket_and_cancel() {
        let s = state_with(vec![], "ticket");
        assert_eq!(
            oauth2_poll_impl(&s, "oauth2-nope").await.unwrap_err().code,
            "not-found"
        );
        assert!(
            !oauth2_cancel_impl(&s, "oauth2-nope")
                .await
                .unwrap()
                .cancelled
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_account_binds_completed_grant_both_directions() {
        let s = state_with(
            vec![
                Step::post("devcode", &["devicecode"], 200, MS_DEVICE),
                Step::post("poll", &["oauth2/v2.0/token"], 200, MS_TOKEN),
            ],
            "bind",
        );
        set_client_id(&s, "microsoft", "cid-ms").await;
        let b = oauth2_begin_impl(&s, "microsoft", Some("u@outlook.com"))
            .await
            .unwrap();
        let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
        assert_eq!(p.status, "complete");

        let mut input = acct_input();
        input.email = "u@outlook.com".to_string();
        input.incoming.host = "outlook.office365.com".to_string();
        input.outgoing.host = "smtp.office365.com".to_string();
        input.outgoing.port = 587;
        input.outgoing.security = "starttls".to_string();
        input.incoming_auth = Some(AuthInput {
            kind: "xoauth2".to_string(),
            secret: None,
            oauth2_ticket: Some(b.ticket_id.clone()),
        });
        input.outgoing_auth = Some(AuthInput {
            kind: "xoauth2".to_string(),
            secret: None,
            oauth2_ticket: Some(b.ticket_id.clone()),
        });
        let view = add_account_impl(&s, input).await.unwrap();

        let acct = s.store.lock().await.get_account(&view.id).unwrap().unwrap();
        for auth in [&acct.incoming.auth, &acct.outgoing.auth] {
            match auth {
                AuthRef::XOAuth2 { credential_key } => {
                    assert_eq!(credential_key, "oauth2/microsoft/u@outlook.com")
                }
                other => panic!("expected xoauth2 ref, got {other:?}"),
            }
        }
        // Ticket consumed — a second add cannot reuse the grant.
        assert_eq!(
            oauth2_ticket_key(&s, &ticket_only_input(&b.ticket_id))
                .await
                .unwrap_err()
                .code,
            "oauth2-incomplete"
        );

        let st = oauth2_status_impl(&s, &view.id).await.unwrap();
        assert_eq!(st.auth_method, "xoauth2");
        assert_eq!(st.provider.as_deref(), Some("microsoft"));
        assert_eq!(st.email.as_deref(), Some("u@outlook.com"));
        assert!(st.credential_present);
        assert_eq!(st.has_refresh_token, Some(true));
        assert_eq!(st.needs_refresh, Some(false));
    }

    fn ticket_only_input(ticket: &str) -> AddAccountInput {
        let mut input = acct_input();
        input.incoming_auth = Some(AuthInput {
            kind: "xoauth2".to_string(),
            secret: None,
            oauth2_ticket: Some(ticket.to_string()),
        });
        input
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ticket_email_mismatch_rejected() {
        let s = state_with(
            vec![
                Step::post("devcode", &["devicecode"], 200, MS_DEVICE),
                Step::post("poll", &["oauth2/v2.0/token"], 200, MS_TOKEN),
            ],
            "mismatch",
        );
        set_client_id(&s, "microsoft", "cid-ms").await;
        let b = oauth2_begin_impl(&s, "microsoft", Some("alice@outlook.com"))
            .await
            .unwrap();
        assert_eq!(
            oauth2_poll_impl(&s, &b.ticket_id).await.unwrap().status,
            "complete"
        );

        let mut input = ticket_only_input(&b.ticket_id);
        input.email = "bob@outlook.com".to_string();
        let e = oauth2_ticket_key(&s, &input).await.unwrap_err();
        assert_eq!(e.code, "invalid-input");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incomplete_ticket_rejected_by_add_account() {
        let s = state_with(
            vec![Step::post("devcode", &["devicecode"], 200, MS_DEVICE)],
            "incomplete",
        );
        set_client_id(&s, "microsoft", "cid-ms").await;
        let b = oauth2_begin_impl(&s, "microsoft", Some("u@outlook.com"))
            .await
            .unwrap();
        // Never polled to completion.
        let mut input = ticket_only_input(&b.ticket_id);
        input.email = "u@outlook.com".to_string(); // email-match gate runs first
        assert_eq!(
            oauth2_ticket_key(&s, &input).await.unwrap_err().code,
            "oauth2-incomplete"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn legacy_xoauth2_inline_secret_still_works() {
        let s = state_with(vec![], "legacy");
        let mut input = acct_input();
        input.incoming_auth = Some(AuthInput {
            kind: "xoauth2".to_string(),
            secret: Some("blob-material".to_string()),
            oauth2_ticket: None,
        });
        let view = add_account_impl(&s, input).await.unwrap();
        let acct = s.store.lock().await.get_account(&view.id).unwrap().unwrap();
        match &acct.incoming.auth {
            AuthRef::XOAuth2 { credential_key } => {
                assert!(credential_key.starts_with("kiwi/"));
                let stored = s.credentials.get(credential_key).unwrap();
                assert_eq!(stored.as_deref().map(|z| z.as_str()), Some("blob-material"));
            }
            other => panic!("expected xoauth2, got {other:?}"),
        }
        let st = oauth2_status_impl(&s, &view.id).await.unwrap();
        assert_eq!(st.auth_method, "xoauth2");
        assert!(st.credential_present);
        // Legacy key isn't an oauth2/ grant key — no lifecycle detail.
        assert_eq!(st.provider, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_begin_exposes_url_and_polls_complete() {
        // ScriptedHttp answers the code exchange once the waiter sees the
        // redirect. The listener is a REAL 127.0.0.1 socket.
        let s = state_with(
            vec![Step::post(
                "exchange",
                &["oauth2.googleapis.com/token"],
                200,
                r#"{"access_token":"AT-g","refresh_token":"RT-g","expires_in":3600,"token_type":"Bearer"}"#,
            )],
            "loop",
        );
        set_client_id(&s, "google", "cid-g").await;
        let b = oauth2_begin_impl(&s, "google", Some("u@gmail.com"))
            .await
            .unwrap();
        assert_eq!(b.kind, "loopback_code");
        let url = b.authorize_url.unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));

        // Extract the loopback port + CSRF state out of the authorize URL
        // the same way a browser provider round-trip would.
        let redirect_uri_enc = url
            .split("redirect_uri=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let redirect_uri = oauth2::form_decode(&format!("x={redirect_uri_enc}"))
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1;
        let port: u16 = redirect_uri.rsplit(':').next().unwrap().parse().unwrap();
        let state_param = url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        use std::io::Write;
        write!(
            conn,
            "GET /?code=authcode-1&state={state_param} HTTP/1.0\r\nhost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        drop(conn);

        // Poll until the waiter lands the exchange (bounded spin).
        let mut last = None;
        for _ in 0..200 {
            let p = oauth2_poll_impl(&s, &b.ticket_id).await.unwrap();
            if p.status != "pending" {
                last = Some(p);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let p = last.expect("grant never settled");
        assert_eq!(p.status, "complete");
        assert_eq!(
            p.credential_key.as_deref(),
            Some("oauth2/google/u@gmail.com")
        );
        let blob = s
            .credentials
            .get("oauth2/google/u@gmail.com")
            .unwrap()
            .expect("stored blob");
        assert!(blob.contains("AT-g"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_for_password_account() {
        let s = test_state("pwstatus");
        let view = add_account_impl(&s, acct_input()).await.unwrap();
        let st = oauth2_status_impl(&s, &view.id).await.unwrap();
        assert_eq!(st.auth_method, "password");
        assert!(st.credential_present);
        assert_eq!(st.provider, None);
        assert_eq!(st.needs_refresh, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_unknown_account() {
        let s = test_state("ghost");
        assert_eq!(
            oauth2_status_impl(&s, "acct-nope").await.unwrap_err().code,
            "not-found"
        );
    }

    /// `kiwi_open_external` fails closed: non-https schemes, quotes,
    /// whitespace, and oversized URLs are rejected before any spawn.
    /// (The valid case would launch a real browser — not CI-testable.)
    #[test]
    fn open_external_rejects_unsafe_urls() {
        let too_long = "https://a".repeat(500);
        for bad in [
            "http://example.test/",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://exa mple.test/",
            "https://example.test/\"quoted\"",
            "https://example.test/'quoted'",
            "notaurl",
            "",
            too_long.as_str(),
        ] {
            assert_eq!(
                open_external_impl(bad).unwrap_err().code,
                "invalid-input",
                "{bad:?} must be rejected"
            );
        }
    }
}
