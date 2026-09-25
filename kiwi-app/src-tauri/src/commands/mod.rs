//! IPC command implementations — the `kiwi_*` surface the frontend invokes.
//!
//! Rules for every command:
//! - **Lock gate first** unless the command is in the exempt set (ipc.md
//!   §lock-gate + §9d.7): ping, app info, security status, lock, challenge
//!   request/submit (`unlock_challenge` — always exempt), endpoint-signal
//!   collection; `pair_begin`/`pair_status` are exempt only while a
//!   backend-owned pairing flow is live (see `pair.rs::pair_gate`).
//! - **Validate input** — every string bounded, every enum parsed, no panics
//!   on renderer input (SECURITY.md B2: webview is untrusted).
//! - **Delegate** — no business logic here; decisions live in kiwi-mail /
//!   kiwi-core / kiwi-forensics / kiwi-pair.
//! - Errors are `IpcError { code, message }` — codes are the contract.

pub mod accounts;
pub mod autoconfig;
pub mod contacts;
pub mod devices;
pub mod endpoint;
pub mod integrations;
pub mod link;
pub mod mail;
pub mod message;
/// OAuth2 plus the generic gated system-browser handoff. Message-link policy
/// enforcement lives in `commands::link`; the command remains here for the
/// existing OAuth2 API grouping.
pub mod oauth2;
pub mod pair;
pub mod prefs;
pub mod rules;
pub mod sandbox;
pub mod security;
pub mod send;
pub mod system;

use std::sync::Arc;

use kiwi_core::trust::TrustState;
use kiwi_mail::transport::SocketSecurity;
use zeroize::Zeroizing;

use crate::error::{CmdResult, IpcError};
use crate::state::AppState;
use crate::types::SecurityStatusView;

/// The lock-state gate (T-120): while the endpoint trust state is `Locked`,
/// every non-exempt command fails with `code: "locked"`. Enforcement lives
/// at the IPC boundary — the UI cannot bypass it (brief requirement).
pub async fn gate(state: &AppState) -> CmdResult<()> {
    if state.trust.lock().await.state() == TrustState::Locked {
        return Err(IpcError::locked());
    }
    Ok(())
}

/// Build the current `SecurityStatusView` without mutating anything.
pub async fn status_view(state: &AppState) -> SecurityStatusView {
    let device_id = state.index.lock().await.device_id.clone();
    let sessions_observed = state.sessions.lock().await.len() as u64;
    let (tstate, score, signals) = {
        let t = state.trust.lock().await;
        (
            t.state(),
            t.score(),
            t.active_signals()
                .iter()
                .map(crate::types::SignalView::from)
                .collect::<Vec<_>>(),
        )
    };
    let locked = tstate == TrustState::Locked;
    // TrustMachine doesn't re-expose the last required action; derive it
    // deterministically from state + policy the same way `evaluate` does.
    let action = match tstate {
        TrustState::Locked => {
            if state.policy.unlock_requires_authenticator {
                kiwi_core::trust::RequiredAction::RequireAuthenticatorUnlock
            } else {
                kiwi_core::trust::RequiredAction::BlockAccess
            }
        }
        TrustState::Degraded => kiwi_core::trust::RequiredAction::WarnUser,
        TrustState::Trusted => kiwi_core::trust::RequiredAction::None,
    };
    SecurityStatusView {
        trust: crate::types::trust_token(tstate, sessions_observed > 0 || !signals.is_empty())
            .to_string(),
        locked,
        state: crate::types::trust_state(tstate).to_string(),
        score,
        signals,
        required_action: crate::types::required_action(action).to_string(),
        sessions_observed,
        device_id,
    }
}

// ---------------------------------------------------------------------------
// Input validation helpers (SECURITY.md §4: bound + charset + control chars)
// ---------------------------------------------------------------------------

/// Bound a string field; reject control chars except normal whitespace.
pub fn bounded(field: &str, s: &str, max: usize) -> CmdResult<()> {
    if s.len() > max {
        return Err(IpcError::invalid(format!("{field} exceeds {max} bytes")));
    }
    if s.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7F) {
        return Err(IpcError::invalid(format!(
            "{field} contains control characters"
        )));
    }
    Ok(())
}

/// A configured server hostname — printable, no whitespace/controls.
pub fn valid_host(host: &str) -> CmdResult<()> {
    bounded("host", host, 253)?;
    if host.is_empty() || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(IpcError::invalid("host is empty or contains whitespace"));
    }
    Ok(())
}

/// Email-ish address: bounded, one `@`, no controls/space. Deliberately
/// permissive beyond that — the wire protocols validate further.
pub fn valid_addr(field: &str, s: &str) -> CmdResult<()> {
    bounded(field, s, 320)?;
    if s.bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'<' || b == b'>')
        || !s.contains('@')
    {
        return Err(IpcError::invalid(format!("{field} is not a valid address")));
    }
    Ok(())
}

pub fn parse_security(s: &str) -> CmdResult<SocketSecurity> {
    match s {
        "plaintext" => Ok(SocketSecurity::Plaintext),
        "starttls" => Ok(SocketSecurity::StartTls),
        "tls" | "implicit-tls" | "implicit_tls" => Ok(SocketSecurity::ImplicitTls),
        _ => Err(IpcError::invalid(format!(
            "security must be plaintext|starttls|tls, got {s:?}"
        ))),
    }
}

pub fn clamp_u32(v: Option<u32>, default: u32, max: u32) -> u32 {
    v.unwrap_or(default).clamp(1, max)
}

/// Resolve the secret behind an `AuthRef` through the credential store.
/// `None` for `AuthRef::None`; missing stored secret → error (the account
/// references a credential that isn't there — fail closed, loud).
pub fn resolve_secret(
    state: &AppState,
    auth: &kiwi_mail::account::AuthRef,
) -> CmdResult<Option<Zeroizing<String>>> {
    use kiwi_mail::account::AuthRef;
    let key = match auth {
        AuthRef::None => return Ok(None),
        AuthRef::Password { credential_key }
        | AuthRef::XOAuth2 { credential_key }
        | AuthRef::Apop { credential_key } => credential_key,
    };
    match state.credentials.get(key)? {
        Some(s) => Ok(Some(s)),
        Option::None => Err(IpcError::new(
            "auth-failed",
            "stored credential is missing from the OS credential store",
        )),
    }
}

/// Run a mail-I/O workload on a dedicated blocking thread with its own
/// current-thread runtime.
///
/// Why: `kiwi_mail` protocol clients are `!Send`-unfriendly inside futures —
/// `ImapClient`/`SmtpClient` keep `&mut dyn FnMut` SASL continuations and
/// `Transport`/`MailStore` are `!Sync`, so any future that holds those
/// across `.await` cannot be `Send` (Tauri commands must be). `block_on` on
/// a current-thread runtime has no `Send` requirement, and the work returns
/// an owned `CmdResult<T>` across the join.
pub async fn run_mail_io<T, Fut>(
    state: Arc<AppState>,
    f: impl FnOnce(Arc<AppState>) -> Fut + Send + 'static,
) -> CmdResult<T>
where
    T: Send + 'static,
    Fut: std::future::Future<Output = CmdResult<T>>,
{
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| IpcError::new("internal", format!("mail-io runtime: {e}")))
            .map(|rt| rt.block_on(f(state)))
    })
    .await
    .map_err(|e| IpcError::new("internal", format!("mail-io join: {e}")))??
}
