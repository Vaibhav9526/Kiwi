//! Autoconfig discovery command (ipc.md §5, T-178 shape landed in T-230).
//!
//! `kiwi_discover_account(email)` runs `kiwi_autoconfig::discover` — the
//! ordered ISPDB → autoconfig-host → well-known → MX-heuristic pipeline —
//! and returns the winning suggestion plus the per-stage audit trail.
//! When the winning suggestion's endpoints are OAuth2-capable the view
//! carries an `oauth2` spec the wizard feeds straight into
//! `kiwi_oauth2_begin` (ipc.md §9f).
//!
//! Nothing is persisted and no secrets exist here — the caller turns the
//! suggestion into an account via `kiwi_add_account` (+ the OAuth2 grant
//! flow for `xoauth2` suggestions).

use std::sync::Arc;

use tauri::State;

use kiwi_autoconfig::discovery::DiscoveryOutcome;
use kiwi_autoconfig::suggest::{AuthKind, IncomingKind};
use kiwi_mail::transport::SocketSecurity;

use super::{bounded, gate, valid_addr};
use crate::error::{CmdResult, IpcError};
use crate::state::AppState;
use crate::types::{
    DiscoveryOutcomeView, StageAttemptView, SuggestedIncomingView, SuggestedOutgoingView,
    SuggestionView,
};

/// `kiwi_discover_account(email) → DiscoveryOutcomeView`.
#[tauri::command]
pub async fn kiwi_discover_account(
    state: State<'_, Arc<AppState>>,
    email: String,
) -> CmdResult<DiscoveryOutcomeView> {
    gate(state.inner()).await?;
    discover_account_impl(state.inner(), &email).await
}

pub(crate) async fn discover_account_impl(
    state: &AppState,
    email: &str,
) -> CmdResult<DiscoveryOutcomeView> {
    bounded("email", email, 320)?;
    // Discovery runs sync network stages (MX + HTTPS fetches) — it must
    // live on a blocking thread: LiveDiscoveryNet drives a private
    // current-thread runtime per call, and block_on inside an executor
    // worker would panic. The `send` flavor also makes `cargo test`
    // callers free of nesting hazards.
    let net = state.autoconfig_net.clone();
    let email_owned = email.trim().to_string();
    let outcome =
        tokio::task::spawn_blocking(move || kiwi_autoconfig::discover(&email_owned, net.as_ref()))
            .await
            .map_err(|e| IpcError::new("internal", format!("discover join: {e}")))?
            .map_err(|e| match e {
                kiwi_autoconfig::Error::InvalidEmail => valid_addr("email", email)
                    .err()
                    .unwrap_or_else(|| IpcError::invalid("email is not a valid address")),
                // The pipeline is designed to never produce these — fail closed.
                other => IpcError::new("internal", format!("discover: {other}")),
            })?;
    Ok(discovery_view(&outcome))
}

/// `AuthKind` → the §5 wire spelling (matches `AddAccountInput.auth.kind`
/// so a suggestion feeds `kiwi_add_account` verbatim).
fn auth_wire(auth: AuthKind) -> String {
    match auth {
        AuthKind::Password => "password".to_string(),
        AuthKind::XOAuth2 => "xoauth2".to_string(),
    }
}

/// `SocketSecurity` → §5 wire spelling (binding per ipc.md §5).
fn security_wire(security: SocketSecurity) -> String {
    match security {
        SocketSecurity::ImplicitTls => "tls".to_string(),
        SocketSecurity::StartTls => "starttls".to_string(),
        SocketSecurity::Plaintext => "plaintext".to_string(),
    }
}

fn discovery_view(out: &DiscoveryOutcome) -> DiscoveryOutcomeView {
    let s = &out.suggestion;
    DiscoveryOutcomeView {
        email: out.email.clone(),
        domain: out.domain.clone(),
        source: out.source.as_str().to_string(),
        needs_manual_review: out.needs_manual_review,
        suggestion: SuggestionView {
            source: s.source.as_str().to_string(),
            email: s.email.clone(),
            display_name: s.display_name.clone(),
            incoming: SuggestedIncomingView {
                kind: match s.incoming.kind {
                    IncomingKind::Imap => "imap".to_string(),
                    IncomingKind::Pop3 => "pop3".to_string(),
                },
                host: s.incoming.host.clone(),
                port: s.incoming.port,
                security: security_wire(s.incoming.security),
                auth: auth_wire(s.incoming.auth),
                username: s.incoming.username.clone(),
            },
            outgoing: SuggestedOutgoingView {
                host: s.outgoing.host.clone(),
                port: s.outgoing.port,
                security: security_wire(s.outgoing.security),
                auth: auth_wire(s.outgoing.auth),
                username: s.outgoing.username.clone(),
            },
            oauth2: super::oauth2::oauth2_spec_for(s),
        },
        attempts: out
            .attempts
            .iter()
            .map(|a| StageAttemptView {
                source: a.source.as_str().to_string(),
                outcome: a.outcome.as_str().to_string(),
                detail: a.detail.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-disc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gmail_suggestion_carries_google_oauth2_spec() {
        let s = state("gmail");
        // Empty MockNet: ISPDB fixture hits before any network stage.
        let v = discover_account_impl(&s, "someone@gmail.com")
            .await
            .unwrap();
        assert_eq!(v.source, "ispdb");
        assert!(!v.needs_manual_review);
        assert_eq!(v.suggestion.incoming.host, "imap.gmail.com");
        assert_eq!(v.suggestion.incoming.auth, "xoauth2");
        let spec = v.suggestion.oauth2.expect("google spec present");
        assert_eq!(spec.provider, "google");
        assert_eq!(spec.grant, "loopback_code");
        assert_eq!(v.attempts.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outlook_suggestion_carries_microsoft_device_spec() {
        let s = state("outlook");
        let v = discover_account_impl(&s, "u@outlook.com").await.unwrap();
        let spec = v.suggestion.oauth2.expect("microsoft spec present");
        assert_eq!(spec.provider, "microsoft");
        assert_eq!(spec.grant, "device_code");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn password_provider_has_no_oauth2_spec() {
        let s = state("plain");
        // iCloud fixture is password auth — no spec at all.
        let v = discover_account_impl(&s, "u@icloud.com").await.unwrap();
        assert_eq!(v.suggestion.incoming.auth, "password");
        assert!(v.suggestion.oauth2.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsupported_xoauth2_provider_fails_closed_no_spec() {
        let s = state("yahoo");
        // Yahoo is XOAUTH2 in the fixture table but has no shipped client
        // config — the spec is absent (the wizard must not offer a flow
        // it cannot run), not a guess.
        let v = discover_account_impl(&s, "u@yahoo.com").await.unwrap();
        assert_eq!(v.suggestion.incoming.auth, "xoauth2");
        assert!(v.suggestion.oauth2.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_domain_falls_to_flagged_guess() {
        let s = state("miss");
        let v = discover_account_impl(&s, "u@nowhere.invalid")
            .await
            .unwrap();
        assert!(v.needs_manual_review);
        assert_eq!(v.source, "mx_heuristic");
        assert!(v.suggestion.oauth2.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_email_is_invalid_input() {
        let s = state("bad");
        let e = discover_account_impl(&s, "not-an-email").await.unwrap_err();
        assert_eq!(e.code, "invalid-input");
    }
}
