//! System + lock-path commands — all exempt from the lock gate
//! (ipc.md §lock-gate): the renderer must always be able to ask "are we
//! locked?" and drive the unlock flow even while everything else refuses.

use std::sync::Arc;

use tauri::State;

use super::status_view;
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{
    AppInfoView, ChallengeResponseInput, ChallengeView, OrgBindingView, SecurityStatusView,
};

#[tauri::command]
pub async fn kiwi_ping() -> String {
    "kiwi backend ok".to_string()
}

/// App-level facts for settings/pairing surfaces. Exempt: carries no
/// mailbox data.
#[tauri::command]
pub async fn kiwi_app_info(state: State<'_, Arc<AppState>>) -> CmdResult<AppInfoView> {
    app_info(state.inner()).await
}

pub(crate) async fn app_info(state: &AppState) -> CmdResult<AppInfoView> {
    let index = state.index.lock().await;
    let sessions_observed = state.sessions.lock().await.len() as u64;
    Ok(AppInfoView {
        version: env!("CARGO_PKG_VERSION").to_string(),
        contract_version: crate::IPC_CONTRACT_VERSION.to_string(),
        device_id: index.device_id.clone(),
        org: index.org.as_ref().map(|o| OrgBindingView {
            org_id: o.org_id.clone(),
            base_url: o.base_url.clone(),
        }),
        account_count: index.account_ids.len(),
        sessions_observed,
        tray_available: state.tray_live.load(std::sync::atomic::Ordering::Relaxed),
        dev_plaintext: kiwi_core::dev::dev_plaintext_enabled(),
    })
}

/// Endpoint trust / lock state (KIWI-UI-002/005). Exempt.
#[tauri::command]
pub async fn kiwi_security_status(
    state: State<'_, Arc<AppState>>,
) -> CmdResult<SecurityStatusView> {
    Ok(status_view(state.inner()).await)
}

/// Administrative lock — audited elevated action. Exempt (locking while
/// unlocked is the intent; while locked it's a no-op the gate would
/// otherwise block).
#[tauri::command]
pub async fn kiwi_lock(state: State<'_, Arc<AppState>>) -> CmdResult<SecurityStatusView> {
    let state = state.inner();
    state.trust.lock().await.force_lock();
    state
        .audit
        .lock()
        .await
        .record("lock", "manual/administrative lock via IPC", now_unix())?;
    Ok(status_view(state).await)
}

/// `kiwi_dev_unlock({})` — DEV SEAM under `KIWI_DEV_PLAINTEXT=1`. Without a
/// paired authenticator a locked endpoint is unrecoverable; this clears
/// `Locked` without a signature so local fixture development is not bricked.
/// Exempt from the lock gate — unlocking while locked is its entire point.
/// Absent the env var it fails closed (`unsupported-event`); the call is
/// audited either way it resolves, and the status bar carries a persistent
/// DEV chip while the flag is set (THREAT-MODEL RR-12).
#[tauri::command]
pub async fn kiwi_dev_unlock(state: State<'_, Arc<AppState>>) -> CmdResult<SecurityStatusView> {
    dev_unlock_impl(state.inner()).await
}

pub(crate) async fn dev_unlock_impl(state: &AppState) -> CmdResult<SecurityStatusView> {
    if !kiwi_core::dev::dev_plaintext_enabled() {
        return Err(IpcError::new(
            "unsupported-event",
            "kiwi_dev_unlock exists only under KIWI_DEV_PLAINTEXT=1",
        ));
    }
    let outcome = state
        .trust
        .lock()
        .await
        .attempt_unlock(&state.policy, true)
        .map(|s| format!("dev-unlock ok → {s:?}"))
        .unwrap_or_else(|e| format!("dev-unlock refused: {e:?}"));
    state
        .audit
        .lock()
        .await
        .record("dev-unlock", &outcome, now_unix())?;
    Ok(status_view(state).await)
}

/// Compat alias over the canonical §9d path — accepts the legacy `event`
/// arg, but issues through `PairEngine` (persisted challenge + nonce
/// ledger) like `unlock_challenge`. Exempt — this is step 1 of the
/// unlock flow.
#[tauri::command]
pub async fn kiwi_request_challenge(
    state: State<'_, Arc<AppState>>,
    device_id: String,
    event: String,
) -> CmdResult<ChallengeView> {
    request_challenge(state.inner(), &device_id, &event).await
}

pub(crate) async fn request_challenge(
    state: &AppState,
    device_id: &str,
    event: &str,
) -> CmdResult<ChallengeView> {
    let event = crate::types::parse_challenge_event(event)
        .ok_or_else(|| IpcError::invalid("unknown challenge event"))?;
    super::pair::issue_challenge_impl(state, device_id, event).await
}

/// Submit a signed challenge response — step 2 of unlock/pairing.
/// Exempt from the gate by definition (it *is* the unlock path).
///
/// Compat alias: verification is `PairEngine::verify_response` (persistent
/// consume+activate, atomic); the bound post-actions live in
/// `pair::submit_challenge_impl`.
#[tauri::command]
pub async fn kiwi_submit_challenge(
    state: State<'_, Arc<AppState>>,
    response: ChallengeResponseInput,
) -> CmdResult<SecurityStatusView> {
    super::pair::submit_challenge_impl(state.inner(), response).await
}

// ---------------------------------------------------------------------------
// Tests — run the command impls directly against an in-memory AppState.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_state() -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-sys-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    /// Register an Ed25519 device; returns the generated device_id.
    fn register_ed25519_device(state: &AppState, pk: &[u8; 32]) -> String {
        futures_block(super::super::pair::register_device_impl(
            state,
            crate::types::RegisterDeviceInput {
                label: "auth".into(),
                algorithm: "ed25519".into(),
                public_key_b64: base64::engine::general_purpose::STANDARD.encode(pk),
                keystore_ref: None,
            },
        ))
        .unwrap()
        .device_id
    }

    /// Tiny block_on for tests — avoids pulling a runtime dependency.
    fn futures_block<F: std::future::Future>(f: F) -> F::Output {
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

    #[test]
    fn locked_gate_blocks_but_unlock_path_is_exempt() {
        let state = test_state();
        futures_block(async {
            state.trust.lock().await.force_lock();
            assert!(
                super::super::gate(&state)
                    .await
                    .is_err_and(|e| e.code == "locked")
            );
            // The exempt commands still work.
            let s = status_view(&state).await;
            assert!(s.locked);
            assert_eq!(s.state, "locked");
        });
    }

    #[test]
    fn dev_unlock_refuses_without_env_flag() {
        // KIWI_DEV_PLAINTEXT is unset in the test env — the seam must fail
        // closed even on a genuinely locked endpoint.
        assert!(!kiwi_core::dev::dev_plaintext_enabled());
        let state = test_state();
        futures_block(async {
            state.trust.lock().await.force_lock();
            let err = dev_unlock_impl(&state).await.unwrap_err();
            assert_eq!(err.code, "unsupported-event");
            assert!(status_view(&state).await.locked);
        });
    }

    #[test]
    fn challenge_unlock_roundtrip() {
        let state = test_state();
        // Real Ed25519 keypair; the "authenticator" signs canonical bytes.
        let mut sk = [0u8; 32];
        getrandom::fill(&mut sk).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
        let pk = signing.verifying_key().to_bytes();

        futures_block(async {
            let dev_id = register_ed25519_device(&state, &pk);
            // Device starts Pending → verify a pairing challenge activates it.
            let chal = request_challenge(&state, &dev_id, "device-pairing")
                .await
                .unwrap();
            let canonical = base64::engine::general_purpose::STANDARD
                .decode(&chal.canonical_bytes_b64)
                .unwrap();
            let sig = ed25519_dalek::Signer::<ed25519_dalek::Signature>::sign(&signing, &canonical);
            let r = super::super::pair::submit_challenge_impl(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id.clone(),
                    device_id: dev_id.clone(),
                    session_id: chal.session_id.clone(),
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                    decision: None,
                },
            )
            .await;
            assert!(r.is_ok(), "pairing verify failed: {r:?}");

            // Lock the endpoint, then drive the real unlock flow.
            state.trust.lock().await.force_lock();
            let chal = request_challenge(&state, &dev_id, "unlock").await.unwrap();
            let canonical = base64::engine::general_purpose::STANDARD
                .decode(&chal.canonical_bytes_b64)
                .unwrap();
            let sig = ed25519_dalek::Signer::<ed25519_dalek::Signature>::sign(&signing, &canonical);
            let status = super::super::pair::submit_challenge_impl(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id,
                    device_id: dev_id.clone(),
                    session_id: chal.session_id,
                    event: "unlock".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                    decision: None,
                },
            )
            .await
            .unwrap();
            assert!(!status.locked, "unlock must leave the endpoint unlocked");
        });
    }

    #[test]
    fn bad_signature_rejected_and_challenge_not_consumed() {
        let state = test_state();
        let mut sk = [0u8; 32];
        getrandom::fill(&mut sk).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
        let pk = signing.verifying_key().to_bytes();

        futures_block(async {
            let dev_id = register_ed25519_device(&state, &pk);
            let chal = request_challenge(&state, &dev_id, "device-pairing")
                .await
                .unwrap();
            let r = super::super::pair::submit_challenge_impl(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id.clone(),
                    device_id: dev_id.clone(),
                    session_id: chal.session_id.clone(),
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
                    decision: None,
                },
            )
            .await;
            assert!(r.is_err_and(|e| e.code == "invalid-signature"));
            // Failed attempt did not consume the challenge — a retry with a
            // valid signature still works (no DoS on legitimate retry).
            let canonical = base64::engine::general_purpose::STANDARD
                .decode(&chal.canonical_bytes_b64)
                .unwrap();
            let sig = ed25519_dalek::Signer::<ed25519_dalek::Signature>::sign(&signing, &canonical);
            let ok = super::super::pair::submit_challenge_impl(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id,
                    device_id: dev_id.clone(),
                    session_id: chal.session_id,
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                    decision: None,
                },
            )
            .await;
            assert!(ok.is_ok());
        });
    }
}
