//! Canonical pairing-engine commands — ipc.md §9d. This module is the ONLY
//! device/challenge/pairing behavior path: `PairEngine` (persisted in
//! `pair.db`) owns tickets, device records, challenge rows, and the nonce
//! replay ledger; the kiwi-core in-memory stand-ins are gone (T-269).
//!
//! The legacy `kiwi_request_challenge` / `kiwi_submit_challenge` /
//! `kiwi_list_devices` / `kiwi_revoke_device` / `kiwi_register_device`
//! names survive as thin aliases over the impls below (§9d.1 ruling —
//! aliases may not carry a second implementation).
//!
//! Lock matrix (§9d.7):
//!   - `unlock_challenge`      — always exempt (it IS the unlock path)
//!   - `pair_begin`/`pair_status` — exempt only while a backend-owned
//!     pairing flow (`AppState.pair_flow`) is live; otherwise gated
//!   - `device_list`/`device_revoke` — gated
//!
//! Ticket/QR secrecy (§9d.2): `ticket` and `qrPayload` leave the process
//! only in the `pair_begin` response for local rendering — they are never
//! logged, audited, written to prefs/evidence, or echoed by `pair_status`.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tauri::State;

use kiwi_core::trust::TrustState;
use kiwi_pair::{ChallengeEvent, ChallengeResponse, ChallengeSpec, PairEngine, TicketState};

use super::{bounded, gate, status_view};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, PairFlow, new_id, now_unix};
use crate::types::{
    ChallengeResponseInput, ChallengeView, DeviceView, PairBeginView, PairStatusView,
    RegisterDeviceInput, SecurityStatusView,
};

/// §9d.11 device-list bound — `device_list` takes no renderer pagination;
/// the scan is capped here and the store's total order applies first.
const DEVICE_LIST_CAP: u32 = 500;

/// The flow-scoped exemption for `pair_begin`/`pair_status` (§9d.7).
/// Unlocked ⇒ the ordinary gate passes. Locked ⇒ a backend-owned flow must
/// be live (unexpired); `pair_status` additionally must present exactly
/// the ticket the flow issued — the flow binds to its capability.
async fn pair_gate(state: &AppState, ticket: Option<&str>) -> CmdResult<()> {
    if state.trust.lock().await.state() != TrustState::Locked {
        return Ok(());
    }
    let flow = state.pair_flow.lock().await;
    let Some(f) = flow.as_ref() else {
        return Err(IpcError::locked());
    };
    if f.expires_unix <= now_unix() {
        return Err(IpcError::locked()); // the flow dies with its ticket
    }
    match ticket {
        None => Ok(()),                     // pair_begin — continue the flow
        Some(t) if t == f.ticket => Ok(()), // pair_status on the bound ticket
        Some(_) => Err(IpcError::locked()),
    }
}

/// §9d.8's canonical desktop-key check, enforced at the IPC boundary even
/// though provisioning already controls the value: `ed25519:` + RFC 4648
/// standard Base64, padded, decoding to exactly 32 bytes — re-encoded
/// byte-for-byte to refuse URL-safe/unpadded spellings.
fn check_desktop_key(key: &str) -> CmdResult<()> {
    let b64 = key.strip_prefix("ed25519:").ok_or_else(|| {
        IpcError::new(
            "unsupported-algorithm",
            "desktop key must carry the ed25519: prefix",
        )
    })?;
    let raw = STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| IpcError::invalid("desktopPublicKeyB64 is not standard Base64"))?;
    if raw.len() != 32 {
        return Err(IpcError::invalid(
            "desktopPublicKeyB64 must decode to 32 bytes",
        ));
    }
    if STANDARD.encode(&raw) != b64 {
        return Err(IpcError::invalid(
            "desktopPublicKeyB64 is not canonical Base64",
        ));
    }
    Ok(())
}

/// §9d.7 first-device TOFU evidence: while the first-ever pairing flow is
/// open (zero registered devices), record the endpoint's executable path +
/// SHA-256 as baseline evidence. Evidence, never authorization — the
/// device still only activates through an authenticator-verified
/// device-pairing challenge. A failed audit write fails the begin.
async fn record_tofu_baseline(state: &AppState) -> CmdResult<()> {
    use sha2::{Digest, Sha256};
    let detail = match std::env::current_exe() {
        Ok(path) => match std::fs::read(&path) {
            Ok(bytes) => format!(
                "exe={} sha256={}",
                path.display(),
                crate::audit::hex(&Sha256::digest(&bytes))
            ),
            Err(_) => format!("exe={} sha256=unavailable", path.display()),
        },
        Err(_) => "exe=unknown sha256=unavailable".to_string(),
    };
    state
        .audit
        .lock()
        .await
        .record("pair-tofu-baseline", &detail, now_unix())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical handlers
// ---------------------------------------------------------------------------

/// `pair_begin({ deviceLabel })` — §9d.2. Renderer supplies ONLY the label;
/// endpoint, desktop key, nonce, and clock are backend-owned.
#[tauri::command]
pub async fn pair_begin(
    state: State<'_, Arc<AppState>>,
    device_label: String,
) -> CmdResult<PairBeginView> {
    pair_begin_impl(state.inner(), &device_label).await
}

pub(crate) async fn pair_begin_impl(
    state: &AppState,
    device_label: &str,
) -> CmdResult<PairBeginView> {
    pair_gate(state, None).await?;
    // Backend-owned identity — provisioned, never renderer-supplied, and
    // failing closed rather than invented when absent.
    let channel = state.pair_channel.clone().ok_or_else(|| {
        IpcError::new(
            "pair-unavailable",
            "no pairing channel is provisioned for this profile",
        )
    })?;
    check_desktop_key(&channel.desktop_public_key_b64)?;
    bounded("deviceLabel", device_label, 128)?;
    let rand = kiwi_pair::os_nonce().map_err(IpcError::from)?;
    let now = now_unix();
    let (ticket, qr, first_device) = {
        let mut engine = state.pair.lock().await;
        let ticket = engine.issue_pairing_ticket(device_label, &rand, now)?;
        let first = engine.list_devices(1)?.is_empty();
        let qr = PairEngine::qr_payload_json(
            &ticket,
            &channel.desktop_endpoint,
            device_label,
            &channel.desktop_public_key_b64,
            now,
        )?;
        (ticket, qr, first)
    };
    // The backend owns the flow: bind it to the ticket we just issued. It
    // dies at ticket expiry (checked in pair_gate).
    *state.pair_flow.lock().await = Some(PairFlow {
        ticket: ticket.ticket.clone(),
        expires_unix: ticket.expires_unix,
    });
    if first_device {
        record_tofu_baseline(state).await?;
    }
    // Audit the ACTION only — the ticket/QR are bearer secrets and never
    // enter audit (§9d.10).
    state.audit.lock().await.record(
        "pair-ticket-issued",
        &format!("label={device_label} expires={}", ticket.expires_unix),
        now,
    )?;
    Ok(PairBeginView {
        ticket: ticket.ticket,
        expires_unix: ticket.expires_unix,
        qr_payload: qr,
    })
}

/// `pair_status({ ticket })` — §9d.3. Read-only; never consumes.
#[tauri::command]
pub async fn pair_status(
    state: State<'_, Arc<AppState>>,
    ticket: String,
) -> CmdResult<PairStatusView> {
    pair_status_impl(state.inner(), &ticket).await
}

pub(crate) async fn pair_status_impl(state: &AppState, ticket: &str) -> CmdResult<PairStatusView> {
    pair_gate(state, Some(ticket)).await?;
    let engine = state.pair.lock().await;
    let status = engine.ticket_status(ticket, now_unix())?;
    let device = match &status.device_id {
        Some(id) => engine.store().get_device(id)?.map(|r| DeviceView::from(&r)),
        None => None,
    };
    Ok(PairStatusView {
        state: match status.state {
            TicketState::AwaitingPhone => "awaiting-phone",
            TicketState::Claimed => "claimed",
            TicketState::Expired => "expired",
        }
        .to_string(),
        device,
        expires_unix: status.expires_unix,
    })
}

/// `unlock_challenge({ deviceId })` — §9d.4. ALWAYS exempt (the
/// authenticator unlock path). Every challenge field except `deviceId` is
/// backend-generated: id, boot session, nonce, fixed `unlock` event, 120 s
/// TTL. The renderer cannot weaken binding or replay protection.
#[tauri::command]
pub async fn unlock_challenge(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> CmdResult<ChallengeView> {
    issue_challenge_impl(state.inner(), &device_id, ChallengeEvent::Unlock).await
}

/// Shared issue path — canonical `unlock_challenge` fixes `Unlock`; the
/// `kiwi_request_challenge` compat alias still parses a caller event, but
/// both delegate to the same persisted `PairEngine` (no second book).
pub(crate) async fn issue_challenge_impl(
    state: &AppState,
    device_id: &str,
    event: ChallengeEvent,
) -> CmdResult<ChallengeView> {
    bounded("deviceId", device_id, 128)?;
    let nonce = kiwi_pair::os_nonce().map_err(IpcError::from)?;
    let challenge = state.pair.lock().await.issue_challenge(
        ChallengeSpec {
            challenge_id: new_id("chal"),
            device_id: device_id.to_string(),
            session_id: state.boot_session_id.clone(),
            event,
            nonce,
        },
        now_unix(),
        kiwi_pair::CHALLENGE_TTL_SECS,
    )?;
    Ok(ChallengeView::from(&challenge))
}

/// `device_list({})` — §9d.5. Safe projection of the persisted device
/// rows: fingerprints + keystore alias, never the raw public key. Total
/// order `registered_unix, device_id` is imposed by the store.
#[tauri::command]
pub async fn device_list(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<DeviceView>> {
    device_list_impl(state.inner()).await
}

pub(crate) async fn device_list_impl(state: &AppState) -> CmdResult<Vec<DeviceView>> {
    gate(state).await?;
    let rows = state.pair.lock().await.list_devices(DEVICE_LIST_CAP)?;
    Ok(rows.iter().map(DeviceView::from).collect())
}

/// `device_revoke({ deviceId })` — §9d.6. Terminal + idempotent (a second
/// call succeeds and does not move `revoked_unix`); audits `device-revoked`
/// on BOTH the transition and the retry, then refreshes trust. Returns the
/// existing `SecurityStatusView` — no caller-visible shape change.
#[tauri::command]
pub async fn device_revoke(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> CmdResult<SecurityStatusView> {
    device_revoke_impl(state.inner(), &device_id).await
}

pub(crate) async fn device_revoke_impl(
    state: &AppState,
    device_id: &str,
) -> CmdResult<SecurityStatusView> {
    gate(state).await?;
    bounded("deviceId", device_id, 128)?;
    state
        .pair
        .lock()
        .await
        .revoke_device(device_id, now_unix())?;
    state
        .audit
        .lock()
        .await
        .record("device-revoked", device_id, now_unix())?;
    state.refresh_trust().await;
    Ok(status_view(state).await)
}

/// `kiwi_register_device` compat path — the manual registration seam until
/// the pairing transport lands. Delegates to the same `PairEngine` so the
/// Ed25519-only/32-byte/label-uniqueness rules apply identically.
pub(crate) async fn register_device_impl(
    state: &AppState,
    input: RegisterDeviceInput,
) -> CmdResult<DeviceView> {
    bounded("label", &input.label, 128)?;
    let algorithm = crate::types::parse_key_algorithm(&input.algorithm)
        .ok_or_else(|| IpcError::invalid("algorithm must be ed25519|ecdsa-p256|rsa3072"))?;
    let key = STANDARD
        .decode(input.public_key_b64.as_bytes())
        .map_err(|_| IpcError::invalid("publicKeyB64 is not valid base64"))?;
    let device_id = new_id("dev");
    {
        let mut engine = state.pair.lock().await;
        engine.register_device(
            &device_id,
            &input.label,
            algorithm,
            &key,
            input.keystore_ref.as_deref(),
            now_unix(),
        )?;
    }
    let row = state
        .pair
        .lock()
        .await
        .store()
        .get_device(&device_id)?
        .ok_or_else(|| IpcError::new("internal", "registered device row missing"))?;
    let view = DeviceView::from(&row);
    state.audit.lock().await.record(
        "device-registered",
        &format!("{} ({})", view.label, view.device_id),
        now_unix(),
    )?;
    Ok(view)
}

/// `kiwi_submit_challenge` compat path — delegates verification to
/// `PairEngine::verify_response` (persisted consume+activate), then runs
/// the bound action exactly as before: `unlock` → `attempt_unlock`;
/// `device-pairing` activation already committed by the engine;
/// `recovery`/`elevated-action` verify then report `unsupported-event`.
pub(crate) async fn submit_challenge_impl(
    state: &AppState,
    input: ChallengeResponseInput,
) -> CmdResult<SecurityStatusView> {
    bounded("challengeId", &input.challenge_id, 128)?;
    bounded("deviceId", &input.device_id, 128)?;
    bounded("sessionId", &input.session_id, 128)?;
    let event = crate::types::parse_challenge_event(&input.event)
        .ok_or_else(|| IpcError::invalid("unknown challenge event"))?;
    let signature = STANDARD
        .decode(input.signature_b64.as_bytes())
        .map_err(|_| IpcError::invalid("signatureB64 is not valid base64"))?;
    if signature.is_empty() || signature.len() > 512 {
        return Err(IpcError::invalid(
            "signatureB64 must decode to 1..=512 bytes",
        ));
    }
    let resp = ChallengeResponse {
        challenge_id: input.challenge_id.clone(),
        device_id: input.device_id.clone(),
        session_id: input.session_id.clone(),
        event,
        signature,
    };
    state.pair.lock().await.verify_response(&resp, now_unix())?;

    // Verified + consumed + (for pairing) activated — atomically, in the
    // engine. Run the bound post-action.
    let audit_detail = match event {
        ChallengeEvent::Unlock => {
            state
                .trust
                .lock()
                .await
                .attempt_unlock(&state.policy, true)?;
            "authenticator-approved unlock".to_string()
        }
        ChallengeEvent::DevicePairing => {
            format!("device paired: {}", input.device_id)
        }
        ChallengeEvent::Recovery | ChallengeEvent::ElevatedAction => {
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
// Tests — §9d wire/gate/persistence behavior at the IPC boundary.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-pair-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

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

    fn code_of(r: CmdResult<impl Sized>) -> &'static str {
        r.err().map(|e| e.code).unwrap_or_default()
    }

    /// Register a pending Ed25519 device straight through the engine.
    fn seed_pending(state: &AppState, label: &str, pk: &[u8; 32]) -> String {
        let device_id = new_id("dev");
        futures_block(async {
            state
                .pair
                .lock()
                .await
                .register_device(
                    &device_id,
                    label,
                    kiwi_pair::KeyAlgorithm::Ed25519,
                    pk,
                    None,
                    now_unix(),
                )
                .unwrap();
        });
        device_id
    }

    /// §9d.4: `unlock_challenge` is exempt while LOCKED and emits the
    /// canonical wire — fixed `"unlock"` event, backend boot session, and
    /// `nonceB64` decoding to exactly 32 bytes. Exercises the full engine
    /// path first: pending device → real pairing signature → active.
    #[test]
    fn unlock_challenge_canonical_wire_while_locked() {
        let state = test_state();
        let signer = kiwi_pair::DeviceSigner::from_seed(&[7u8; 32]);
        futures_block(async {
            let dev_id = seed_pending(&state, "auth", &signer.public_key());
            let chal = issue_challenge_impl(&state, &dev_id, ChallengeEvent::DevicePairing)
                .await
                .unwrap();
            let canonical = STANDARD.decode(&chal.canonical_bytes_b64).unwrap();
            let sig = signer.sign(&canonical);
            submit_challenge_impl(
                &state,
                ChallengeResponseInput {
                    challenge_id: chal.challenge_id,
                    device_id: dev_id.clone(),
                    session_id: chal.session_id,
                    event: "device-pairing".into(),
                    signature_b64: STANDARD.encode(sig),
                },
            )
            .await
            .unwrap();

            // Active now — lock, then the always-exempt unlock path runs.
            state.trust.lock().await.force_lock();
            let chal = issue_challenge_impl(&state, &dev_id, ChallengeEvent::Unlock)
                .await
                .unwrap();
            assert_eq!(chal.event, "unlock");
            assert_eq!(chal.session_id, state.boot_session_id);
            assert_eq!(chal.device_id, dev_id);
            assert_eq!(STANDARD.decode(&chal.nonce_b64).unwrap().len(), 32);
            // A pending device on the same exempt path gets
            // device-not-active — proof the gate did not swallow it.
            let pending = seed_pending(&state, "other", &[8u8; 32]);
            assert_eq!(
                code_of(issue_challenge_impl(&state, &pending, ChallengeEvent::Unlock).await),
                "device-not-active"
            );
        });
    }

    #[test]
    fn pair_begin_fails_closed_without_channel_then_serves_flow() {
        {
            let state = test_state();
            futures_block(async {
                // Unprovisioned backend identity → fail closed, never invented.
                assert_eq!(
                    code_of(pair_begin_impl(&state, "Phone").await),
                    "pair-unavailable"
                );
            });
        }
        let mut state = test_state();
        state.provision_test_pair_channel("wss://10.0.0.2:49310/pair");
        futures_block(async {
            let view = pair_begin_impl(&state, "Pixel 8").await.unwrap();
            assert_eq!(view.ticket.len(), 43);
            assert!(view.qr_payload.contains("\"type\":\"kiwi-pairing\""));
            assert!(view.qr_payload.contains("wss://10.0.0.2:49310/pair"));
            assert!(view.qr_payload.contains("ed25519:"));
            assert!(view.expires_unix > now_unix());
            // The ticket/QR must not enter the audit log.
            let audit =
                std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap_or_default();
            assert!(!audit.contains(&view.ticket));
            assert!(!audit.contains("qrPayload"));

            // While locked with the flow live: status on the BOUND ticket is
            // exempt; a foreign ticket is not.
            state.trust.lock().await.force_lock();
            let s = pair_status_impl(&state, &view.ticket).await.unwrap();
            assert_eq!(s.state, "awaiting-phone");
            assert!(s.device.is_none());
            assert_eq!(
                code_of(pair_status_impl(&state, "aaaaaaaa-bbbb-cccc-dddd").await),
                "locked"
            );
            // Gated commands still refuse while locked mid-flow.
            assert_eq!(code_of(device_list_impl(&state).await), "locked");
            assert_eq!(code_of(device_revoke_impl(&state, "dev-x").await), "locked");
            // begin itself continues the live flow (re-issue).
            assert!(pair_begin_impl(&state, "Pixel 8").await.is_ok());
        });
    }

    #[test]
    fn pair_status_lifecycle_awaiting_claimed_expired_unknown() {
        let mut state = test_state();
        state.provision_test_pair_channel("wss://10.0.0.2:49310/pair");
        futures_block(async {
            let view = pair_begin_impl(&state, "Phone").await.unwrap();

            // Unknown/malformed → invalid, never an oracle.
            assert_eq!(
                code_of(pair_status_impl(&state, "nope").await),
                "pairing-ticket-invalid"
            );

            // Polling is read-only — repeat polls stay awaiting-phone.
            for _ in 0..3 {
                assert_eq!(
                    pair_status_impl(&state, &view.ticket).await.unwrap().state,
                    "awaiting-phone"
                );
            }

            // The transport claims the ticket: consume+register+link atomic.
            let dev_id = new_id("dev");
            state
                .pair
                .lock()
                .await
                .claim_ticket_and_register(
                    &view.ticket,
                    &dev_id,
                    kiwi_pair::KeyAlgorithm::Ed25519,
                    &[9u8; 32],
                    None,
                    now_unix(),
                )
                .unwrap();
            let s = pair_status_impl(&state, &view.ticket).await.unwrap();
            assert_eq!(s.state, "claimed");
            let d = s.device.unwrap();
            assert_eq!(d.device_id, dev_id);
            assert_eq!(d.label, "Phone"); // label comes from the ticket row
            assert_eq!(d.status, "pending");
            assert_eq!(d.algorithm, "ed25519");
            assert_eq!(d.fingerprint.len(), 39); // dash-grouped 16B sha256
            assert!(d.revoked_unix.is_none());
        });
    }

    #[test]
    fn pair_status_on_expired_flow_is_locked_then_expired_when_unlocked() {
        let mut state = test_state();
        state.provision_test_pair_channel("wss://10.0.0.2:49310/pair");
        futures_block(async {
            // Issue the ticket with a past clock so the ROW itself expires
            // (expiry lives in pair.db, not the flow binding).
            let mut engine = state.pair.lock().await;
            let ticket = engine
                .issue_pairing_ticket("Phone", &kiwi_pair::os_nonce().unwrap(), now_unix() - 400)
                .unwrap();
            drop(engine);
            // Backend binds a flow to it — already expired, as if the QR sat
            // on screen past QR_TTL_SECS with the endpoint locked.
            *state.pair_flow.lock().await = Some(PairFlow {
                ticket: ticket.ticket.clone(),
                expires_unix: ticket.expires_unix,
            });
            state.trust.lock().await.force_lock();
            assert_eq!(
                code_of(pair_status_impl(&state, &ticket.ticket).await),
                "locked"
            );
            // Unlocked: the same ticket reports `expired` (unlinked + past).
            state
                .trust
                .lock()
                .await
                .attempt_unlock(&state.policy, true)
                .unwrap();
            let s = pair_status_impl(&state, &ticket.ticket).await.unwrap();
            assert_eq!(s.state, "expired");
            assert!(s.device.is_none());
        });
    }

    #[test]
    fn device_list_ordering_fields_and_label_conflict() {
        let state = test_state();
        futures_block(async {
            let mut engine = state.pair.lock().await;
            let now = now_unix();
            // Same registered_unix → deviceId must break the tie.
            engine
                .register_device(
                    "dev-bbb",
                    "Beta",
                    kiwi_pair::KeyAlgorithm::Ed25519,
                    &[2u8; 32],
                    Some("ks-beta"),
                    now,
                )
                .unwrap();
            engine
                .register_device(
                    "dev-aaa",
                    "Alpha",
                    kiwi_pair::KeyAlgorithm::Ed25519,
                    &[3u8; 32],
                    None,
                    now,
                )
                .unwrap();
            engine
                .register_device(
                    "dev-ccc",
                    "beta", // normalized dup of "Beta" → conflict
                    kiwi_pair::KeyAlgorithm::Ed25519,
                    &[4u8; 32],
                    None,
                    now,
                )
                .unwrap_err();
            drop(engine);

            let rows = device_list_impl(&state).await.unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].device_id, "dev-aaa");
            assert_eq!(rows[1].device_id, "dev-bbb");
            assert_eq!(rows[1].keystore_ref.as_deref(), Some("ks-beta"));
            assert!(!rows[0].fingerprint.is_empty());
            assert_eq!(rows[0].key_fingerprint_tail.len(), 8);
        });
    }

    #[test]
    fn duplicate_label_maps_to_conflict_error() {
        let state = test_state();
        futures_block(async {
            let input = |label: &str, pk: u8| RegisterDeviceInput {
                label: label.into(),
                algorithm: "ed25519".into(),
                public_key_b64: STANDARD.encode([pk; 32]),
                keystore_ref: None,
            };
            register_device_impl(&state, input("  Phone  ", 1))
                .await
                .unwrap();
            let dup = register_device_impl(&state, input("phone", 2)).await;
            assert_eq!(code_of(dup), "conflict");
            // A third distinct label still registers.
            register_device_impl(&state, input("Tablet", 3))
                .await
                .unwrap();
        });
    }

    /// §9d.6 restart-persistence: revoke → drop the AppState (engine/conn
    /// dropped) → reopen on the same profile dir → still revoked, and a
    /// second revoke stays idempotent with the original `revoked_unix`.
    #[test]
    fn revocation_survives_engine_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-pair-revoke-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        {
            let state = AppState::open_test(dir.clone()).unwrap();
            futures_block(async {
                let dev_id = seed_pending(&state, "Phone", &[5u8; 32]);
                device_revoke_impl(&state, &dev_id).await.unwrap();
                let revoked_at = {
                    let engine = state.pair.lock().await;
                    engine
                        .store()
                        .get_device(&dev_id)
                        .unwrap()
                        .unwrap()
                        .revoked_unix
                };
                assert!(revoked_at.is_some());
            });
        } // AppState dropped — engine + SQLite connection closed.

        {
            let state = AppState::open_test(dir.clone()).unwrap();
            futures_block(async {
                let rows = device_list_impl(&state).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].status, "revoked");
                assert!(rows[0].revoked_unix.is_some());
                // Idempotent retry: Ok, revoked_unix unchanged.
                let first = rows[0].revoked_unix.unwrap();
                device_revoke_impl(&state, &rows[0].device_id)
                    .await
                    .unwrap();
                let rows = device_list_impl(&state).await.unwrap();
                assert_eq!(rows[0].revoked_unix, Some(first));
            });
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
