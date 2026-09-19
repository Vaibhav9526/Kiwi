//! System + lock-path commands — all exempt from the lock gate
//! (ipc.md §lock-gate): the renderer must always be able to ask "are we
//! locked?" and drive the unlock flow even while everything else refuses.

use std::sync::Arc;

use base64::Engine;
use tauri::State;

use kiwi_core::challenge::{ChallengeResponse, ChallengeSpec};
use kiwi_core::device::DeviceStatus;

use super::{bounded, status_view};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, new_id, now_unix};
use crate::types::{
    AppInfoView, ChallengeResponseInput, ChallengeView, OrgBindingView, SecurityStatusView,
};
use crate::verifier::Ed25519Verifier;

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

/// Issue a bound challenge (unlock / device-pairing / recovery / elevated
/// action). Exempt — this is step 1 of the unlock flow.
///
/// The challenge binds device + app boot session + event; its canonical
/// bytes are returned base64-encoded for the authenticator to sign
/// (contract security-session.md §6).
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
    bounded("deviceId", device_id, 128)?;
    let event = crate::types::parse_challenge_event(event)
        .ok_or_else(|| IpcError::invalid("unknown challenge event"))?;

    // The device must be registered; pairing challenges additionally require
    // the device to still be Pending (an Active device can't re-pair under
    // the same id — revocation is terminal).
    {
        let devices = state.devices.lock().await;
        let dev = devices
            .get(device_id)
            .ok_or_else(|| IpcError::not_found("unknown device"))?;
        if event == kiwi_core::challenge::ChallengeEvent::DevicePairing
            && dev.status != DeviceStatus::Pending
        {
            return Err(IpcError::invalid(
                "device-pairing challenge requires a pending device",
            ));
        }
        if matches!(
            event,
            kiwi_core::challenge::ChallengeEvent::Unlock
                | kiwi_core::challenge::ChallengeEvent::Recovery
        ) && dev.status != DeviceStatus::Active
        {
            return Err(IpcError::new(
                "device-not-active",
                "unlock/recovery requires an active registered device",
            ));
        }
    }

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| IpcError::new("internal", "CSPRNG failure"))?;
    let session_id = state.boot_session_id.clone();
    let challenge = state
        .challenges
        .lock()
        .await
        .issue(
            ChallengeSpec {
                challenge_id: new_id("chal"),
                device_id: device_id.to_string(),
                session_id,
                event,
                nonce,
            },
            now_unix(),
            state.policy.challenge_ttl_secs,
        )
        .ok_or_else(|| {
            // Duplicate nonce from the CSPRNG is a replay indicator, not a
            // retry-able error — surface it as one (contract §6).
            IpcError::new("replay-detected", "challenge nonce collision")
        })?;
    Ok(ChallengeView::from(&challenge))
}

/// Submit a signed challenge response — step 2 of unlock/pairing.
/// Exempt from the gate by definition (it *is* the unlock path).
///
/// Verification: `ChallengeBook::verify` (expiry, single-use, binding) +
/// `Ed25519Verifier` over the registered device public key. On success the
/// bound action runs: `unlock` → `TrustMachine::attempt_unlock`;
/// `device-pairing` → device `Pending → Active`. Other events verify but
/// report `unsupported-event` until their flows land.
#[tauri::command]
pub async fn kiwi_submit_challenge(
    state: State<'_, Arc<AppState>>,
    response: ChallengeResponseInput,
) -> CmdResult<SecurityStatusView> {
    submit_challenge(state.inner(), response).await
}

pub(crate) async fn submit_challenge(
    state: &AppState,
    input: ChallengeResponseInput,
) -> CmdResult<SecurityStatusView> {
    bounded("challengeId", &input.challenge_id, 128)?;
    bounded("deviceId", &input.device_id, 128)?;
    bounded("sessionId", &input.session_id, 128)?;
    let event = crate::types::parse_challenge_event(&input.event)
        .ok_or_else(|| IpcError::invalid("unknown challenge event"))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(input.signature_b64.as_bytes())
        .map_err(|_| IpcError::invalid("signatureB64 is not valid base64"))?;
    if signature.len() > 4096 {
        return Err(IpcError::invalid("signature too large"));
    }

    let (public_key, algorithm) = {
        let devices = state.devices.lock().await;
        let dev = devices
            .get(&input.device_id)
            .ok_or_else(|| IpcError::not_found("unknown device"))?;
        (dev.public_key.key.clone(), dev.public_key.algorithm)
    };
    if !crate::verifier::algorithm_supported(algorithm) {
        return Err(IpcError::new(
            "unsupported-algorithm",
            "device key algorithm has no verifier yet",
        ));
    }

    let resp = ChallengeResponse {
        challenge_id: input.challenge_id.clone(),
        device_id: input.device_id.clone(),
        session_id: input.session_id.clone(),
        event,
        signature,
    };
    state
        .challenges
        .lock()
        .await
        .verify(&resp, &public_key, &Ed25519Verifier, now_unix())?;

    // Verified — perform the bound action.
    let audit_detail = match event {
        kiwi_core::challenge::ChallengeEvent::Unlock => {
            state
                .trust
                .lock()
                .await
                .attempt_unlock(&state.policy, true)?;
            "authenticator-approved unlock".to_string()
        }
        kiwi_core::challenge::ChallengeEvent::DevicePairing => {
            state
                .devices
                .lock()
                .await
                .activate(&input.device_id)
                .map_err(|e| IpcError::new("device-error", format!("activate: {e:?}")))?;
            format!("device paired: {}", input.device_id)
        }
        kiwi_core::challenge::ChallengeEvent::Recovery
        | kiwi_core::challenge::ChallengeEvent::ElevatedAction => {
            return Err(IpcError::new(
                "unsupported-event",
                "challenge verified but this event's flow is not wired yet",
            ));
        }
    };
    state
        .audit
        .lock()
        .await
        .record("challenge-verified", &audit_detail, now_unix())?;
    Ok(status_view(state).await)
}

// ---------------------------------------------------------------------------
// Tests — run the command impls directly against an in-memory AppState.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        futures_block(super::super::devices::register_device_impl(
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
            let r = submit_challenge(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id.clone(),
                    device_id: dev_id.clone(),
                    session_id: chal.session_id.clone(),
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
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
            let status = submit_challenge(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id,
                    device_id: dev_id.clone(),
                    session_id: chal.session_id,
                    event: "unlock".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
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
            let r = submit_challenge(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id.clone(),
                    device_id: dev_id.clone(),
                    session_id: chal.session_id.clone(),
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
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
            let ok = submit_challenge(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id,
                    device_id: dev_id.clone(),
                    session_id: chal.session_id,
                    event: "device-pairing".into(),
                    signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                },
            )
            .await;
            assert!(ok.is_ok());
        });
    }
}
