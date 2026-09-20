//! PairEngine — the desktop-side orchestrator for authenticator pairing.
//!
//! Flow (contract §3.2):
//!   1. `issue_pairing_ticket` → QR payload (`qr_payload_json`)
//!   2. phone connects on the pairing channel with the ticket
//!      (`consume_pairing_ticket` — single-use, ≤5 min) and presents its
//!      Ed25519 public key + keystore_ref
//!   3. `register_device` → status `pending`
//!   4. `issue_challenge(DevicePairing)` → phone signs canonical bytes →
//!      `verify_response` → on success the device auto-activates
//!   5. `revoke_device` is terminal — the id can never be re-trusted
//!
//! Replay protection: nonces and consumed challenges are persisted, so
//! replay detection survives restarts (bounded window — nonce ledger
//! retains 1h, challenge table capped at 4096).

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::crypto::{Ed25519Verifier, algorithm_supported};
use crate::store::{ChallengeRow, DeviceRow, PairStore};
use crate::{PairError, Result};
use kiwi_core::challenge::{
    Challenge, ChallengeError, ChallengeEvent, ChallengeResponse, ChallengeSpec, SignatureVerifier,
};
use kiwi_core::device::KeyAlgorithm;

/// Contract §3.1: QR validity ≤ 5 minutes.
pub const QR_TTL_SECS: i64 = 300;
/// Contract §4.2: challenge TTL default.
pub const CHALLENGE_TTL_SECS: u64 = 120;
/// Bounded window — issue-time TTL is clamped to this ceiling.
pub const MAX_TTL_SECS: u64 = 300;

const MAX_ID_LEN: usize = 128;
const MAX_LABEL_LEN: usize = 128;
const MAX_SESSION_LEN: usize = 256;
const MAX_KEYSTORE_REF_LEN: usize = 256;
const MAX_ENDPOINT_LEN: usize = 256;

pub struct PairEngine {
    store: PairStore,
}

/// Single-use pairing ticket issued for the QR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    pub ticket: String,
    pub expires_unix: i64,
}

fn event_name(e: ChallengeEvent) -> &'static str {
    match e {
        ChallengeEvent::Unlock => "unlock",
        ChallengeEvent::DevicePairing => "device-pairing",
        ChallengeEvent::Recovery => "recovery",
        ChallengeEvent::ElevatedAction => "elevated-action",
    }
}

fn event_from_name(s: &str) -> Option<ChallengeEvent> {
    match s {
        "unlock" => Some(ChallengeEvent::Unlock),
        "device-pairing" => Some(ChallengeEvent::DevicePairing),
        "recovery" => Some(ChallengeEvent::Recovery),
        "elevated-action" => Some(ChallengeEvent::ElevatedAction),
        _ => None,
    }
}

fn check_field(field: &'static str, v: &str, max: usize) -> Result<()> {
    if v.is_empty() || v.len() > max || v.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PairError::InvalidField {
            field,
            reason: format!("must be 1..={max} printable chars"),
        });
    }
    Ok(())
}

fn status_of(d: &DeviceRow) -> crate::DeviceStatus {
    match d.status.as_str() {
        "pending" => crate::DeviceStatus::Pending,
        "active" => crate::DeviceStatus::Active,
        "suspended" => crate::DeviceStatus::Suspended,
        _ => crate::DeviceStatus::Revoked,
    }
}

impl PairEngine {
    pub fn open(root: &Path) -> Result<Self> {
        Ok(Self {
            store: PairStore::open(root)?,
        })
    }

    /// In-memory engine — deterministic tests.
    pub fn open_memory() -> Result<Self> {
        Ok(Self {
            store: PairStore::open_memory()?,
        })
    }

    pub fn store(&self) -> &PairStore {
        &self.store
    }

    // ---- pairing tickets --------------------------------------------------

    /// Issue a single-use pairing ticket. `rand` MUST be 32 bytes of CSPRNG
    /// output (use `os_nonce()`); the ticket encodes it base64url — the QR
    /// carries no key material, just this opaque ticket.
    pub fn issue_pairing_ticket(
        &mut self,
        device_label: &str,
        rand: &[u8; 32],
        now: i64,
    ) -> Result<PairingTicket> {
        check_field("device_label", device_label, MAX_LABEL_LEN)?;
        let ticket = URL_SAFE_NO_PAD.encode(rand); // 43 chars, [A-Za-z0-9_-]
        let t = PairingTicket {
            ticket,
            expires_unix: now + QR_TTL_SECS,
        };
        self.store
            .insert_ticket(&t.ticket, device_label, now, t.expires_unix)?;
        Ok(t)
    }

    /// Validate + consume a ticket presented on the pairing channel.
    /// Single-use and expiry-bounded; returns the label bound at issue.
    pub fn consume_pairing_ticket(&mut self, ticket: &str, now: i64) -> Result<String> {
        // Contract §3.1 charset + length gate before any store touch.
        if ticket.len() < 8
            || ticket.len() > 128
            || !ticket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(PairError::InvalidTicket);
        }
        self.store.consume_ticket(ticket, now)
    }

    /// §3.1 QR payload — compact JSON, fixed field set, no secrets.
    /// Deterministic output (sorted keys) for test vectors.
    pub fn qr_payload_json(
        ticket: &PairingTicket,
        desktop_endpoint: &str,
        device_label: &str,
        desktop_public_key_b64: &str,
        issued_unix: i64,
    ) -> Result<String> {
        check_field("desktop_endpoint", desktop_endpoint, MAX_ENDPOINT_LEN)?;
        check_field("device_label", device_label, MAX_LABEL_LEN)?;
        if !desktop_public_key_b64.starts_with("ed25519:") {
            return Err(PairError::UnsupportedAlgorithm(
                "QR desktop key must carry the ed25519: prefix".into(),
            ));
        }
        Ok(serde_json::json!({
            "v": 1,
            "type": "kiwi-pairing",
            "pairing_ticket": ticket.ticket,
            "desktop_endpoint": desktop_endpoint,
            "device_label": device_label,
            "desktop_public_key_b64": desktop_public_key_b64,
            "issued_unix": issued_unix,
            "expires_unix": ticket.expires_unix,
        })
        .to_string())
    }

    // ---- devices ------------------------------------------------------------

    /// Register a device as `pending`. Ed25519 public key only, exactly 32
    /// bytes — other declared algorithms fail closed (contract §5).
    pub fn register_device(
        &mut self,
        device_id: &str,
        label: &str,
        algorithm: KeyAlgorithm,
        public_key: &[u8],
        keystore_ref: Option<&str>,
        now: i64,
    ) -> Result<()> {
        check_field("device_id", device_id, MAX_ID_LEN)?;
        check_field("label", label, MAX_LABEL_LEN)?;
        if let Some(r) = keystore_ref {
            check_field("keystore_ref", r, MAX_KEYSTORE_REF_LEN)?;
        }
        if !algorithm_supported(algorithm) {
            return Err(PairError::UnsupportedAlgorithm(format!("{algorithm:?}")));
        }
        if public_key.len() != 32 {
            return Err(PairError::BadKeyLength(public_key.len()));
        }
        if self.store.get_device(device_id)?.is_some() {
            return Err(PairError::DeviceExists(device_id.into()));
        }
        self.store.insert_device(&DeviceRow {
            device_id: device_id.into(),
            label: label.into(),
            algorithm: "ed25519".into(),
            public_key: public_key.to_vec(),
            keystore_ref: keystore_ref.map(str::to_string),
            status: "pending".into(),
            registered_unix: now,
            last_seen_unix: now,
            revoked_unix: None,
        })
    }

    /// Terminal revocation — the device id can never reactivate (kiwi-core
    /// `RevokedIsTerminal` semantics, persisted). Idempotent: revoking an
    /// already-revoked device returns Ok so operator retries are safe.
    /// Callers MUST audit `device-revoked` (elevated action, rule 11).
    pub fn revoke_device(&mut self, device_id: &str, now: i64) -> Result<()> {
        let d = self
            .store
            .get_device(device_id)?
            .ok_or_else(|| PairError::DeviceNotFound(device_id.into()))?;
        if d.status == "revoked" {
            return Ok(()); // idempotent — terminal state reached already
        }
        self.store.set_device_status(device_id, "revoked", now)?;
        Ok(())
    }

    pub fn suspend_device(&mut self, device_id: &str, now: i64) -> Result<()> {
        let d = self
            .store
            .get_device(device_id)?
            .ok_or_else(|| PairError::DeviceNotFound(device_id.into()))?;
        if d.status == "revoked" {
            return Err(PairError::DeviceRevoked(device_id.into()));
        }
        self.store.set_device_status(device_id, "suspended", now)?;
        Ok(())
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRow>> {
        self.store.list_devices()
    }

    /// Display fingerprint of a registered device's public key.
    pub fn device_fingerprint(&self, device_id: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .get_device(device_id)?
            .map(|d| crate::crypto::device_fingerprint(&d.public_key)))
    }

    // ---- challenges ----------------------------------------------------------

    /// Issue a challenge bound to device+session+event+nonce+expiry.
    /// `spec.nonce` MUST be fresh CSPRNG bytes (`os_nonce()`); a repeat
    /// nonce is `ReplayDetected` (contract §4.3 — audit `replay-detected`).
    ///
    /// Status gate: `DevicePairing` challenges are for `pending` devices;
    /// all other events require `active`. Revoked devices get nothing.
    pub fn issue_challenge(
        &mut self,
        spec: ChallengeSpec,
        now: i64,
        ttl_secs: u64,
    ) -> Result<Challenge> {
        check_field("challenge_id", &spec.challenge_id, MAX_ID_LEN)?;
        check_field("device_id", &spec.device_id, MAX_ID_LEN)?;
        check_field("session_id", &spec.session_id, MAX_SESSION_LEN)?;
        if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
            return Err(PairError::InvalidField {
                field: "ttl_secs",
                reason: format!("must be 1..={MAX_TTL_SECS}"),
            });
        }
        let dev = self
            .store
            .get_device(&spec.device_id)?
            .ok_or_else(|| PairError::DeviceNotFound(spec.device_id.clone()))?;
        match (status_of(&dev), spec.event) {
            (crate::DeviceStatus::Revoked, _) => {
                return Err(PairError::DeviceRevoked(spec.device_id));
            }
            (crate::DeviceStatus::Pending, ChallengeEvent::DevicePairing) => {}
            (crate::DeviceStatus::Active, _) => {}
            (other, _) => return Err(PairError::DeviceNotActive(other)),
        }
        if !self.store.record_nonce(&spec.nonce, now)? {
            return Err(PairError::ReplayDetected);
        }
        self.store.insert_challenge(&ChallengeRow {
            challenge_id: spec.challenge_id.clone(),
            device_id: spec.device_id.clone(),
            session_id: spec.session_id.clone(),
            event: event_name(spec.event).into(),
            nonce: spec.nonce.to_vec(),
            issued_unix: now,
            expires_unix: now + ttl_secs as i64,
            consumed: false,
        })?;
        // Rehydrate the kiwi-core Challenge so canonical_bytes() stays the
        // authoritative encoding — byte-for-byte contract §4.1.
        let mut book = kiwi_core::challenge::ChallengeBook::new();
        book.issue(spec, now, ttl_secs)
            .ok_or(PairError::ReplayDetected)
    }

    /// Verify a device response. Order per contract §6.2 / ChallengeBook:
    /// device not revoked → challenge exists → unexpired → unconsumed →
    /// binding fields match → Ed25519 over canonical bytes → consume.
    /// A successful `device-pairing` verification auto-activates the
    /// device (contract §3.2 step 3). Failed verification never consumes.
    pub fn verify_response(&mut self, resp: &ChallengeResponse, now: i64) -> Result<()> {
        let row = self
            .store
            .get_challenge(&resp.challenge_id)?
            .ok_or(ChallengeError::UnknownChallenge)?;

        let dev = self
            .store
            .get_device(&row.device_id)?
            .ok_or(ChallengeError::UnknownChallenge)?;
        if dev.status == "revoked" {
            return Err(PairError::DeviceRevoked(row.device_id));
        }

        if now >= row.expires_unix {
            return Err(ChallengeError::Expired.into());
        }
        if row.consumed {
            return Err(ChallengeError::AlreadyConsumed.into());
        }
        let event = event_from_name(&row.event).ok_or(ChallengeError::BindingMismatch)?;
        if row.device_id != resp.device_id
            || row.session_id != resp.session_id
            || event != resp.event
        {
            return Err(ChallengeError::BindingMismatch.into());
        }

        let nonce: [u8; 32] = row
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ChallengeError::BindingMismatch)?;
        let mut book = kiwi_core::challenge::ChallengeBook::new();
        let chal = book
            .issue(
                ChallengeSpec {
                    challenge_id: row.challenge_id.clone(),
                    device_id: row.device_id.clone(),
                    session_id: row.session_id.clone(),
                    event,
                    nonce,
                },
                row.issued_unix,
                (row.expires_unix - row.issued_unix) as u64,
            )
            .ok_or(PairError::ReplayDetected)?;

        if !Ed25519Verifier.verify(&dev.public_key, &chal.canonical_bytes(), &resp.signature) {
            return Err(ChallengeError::InvalidSignature.into());
        }

        // Single-use — atomic consume, then post-verification transition.
        self.store.consume_challenge(&row.challenge_id)?;
        if event == ChallengeEvent::DevicePairing {
            self.store
                .set_device_status(&row.device_id, "active", now)?;
        }
        Ok(())
    }
}
