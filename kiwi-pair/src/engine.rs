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
use crate::store::{ChallengeRow, ClaimDevice, DeviceRow, PairStore, TicketRow};
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

/// `pair_status` wire states (ipc.md §9d.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    /// Ticket exists, unclaimed, unexpired — QR still on screen.
    AwaitingPhone,
    /// The claim transaction committed a linked device row.
    Claimed,
    /// No linked device and `now >= expires_unix` — expiry outranks a
    /// consumed-but-unlinked flag (a claimant never wins by expiring).
    Expired,
}

/// Read-only ticket status — the non-mutating lookup §9d.3 requires.
/// `device_id` is `Some` iff `state == Claimed` (the row the ticket
/// claimed into); the ticket string itself is never echoed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketStatus {
    pub state: TicketState,
    pub device_id: Option<String>,
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

/// §9d.3 state machine — order matters: a link wins over expiry, expiry
/// wins over a consumed-but-unlinked flag, and consumed-but-unlinked is an
/// invalid (non-oracle) ticket rather than a claimable or expired one —
/// `None` means "refuse as `InvalidTicket`".
fn ticket_status_of(row: &TicketRow, now: i64) -> Option<TicketStatus> {
    let state = if row.device_id.is_some() {
        TicketState::Claimed
    } else if now >= row.expires_unix {
        TicketState::Expired
    } else if row.consumed {
        // Consumed without a device link — a pre-v2 consume or a claim
        // that never committed. Same refusal as an unknown ticket.
        return None;
    } else {
        TicketState::AwaitingPhone
    };
    Some(TicketStatus {
        state,
        device_id: row.device_id.clone(),
        expires_unix: row.expires_unix,
    })
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
        // Fail the label now rather than letting a phone claim a ticket
        // whose registration would conflict at commit time.
        if self.store.live_label_taken(device_label)? {
            return Err(PairError::DeviceLabelConflict(device_label.into()));
        }
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
    /// New callers should prefer `claim_ticket_and_register` — consuming
    /// without linking leaves an unlinked-consumed row that `pair_status`
    /// must then refuse as `InvalidTicket`.
    pub fn consume_pairing_ticket(&mut self, ticket: &str, now: i64) -> Result<String> {
        // Contract §3.1 charset + length gate before any store touch.
        Self::check_ticket_shape(ticket)?;
        self.store.consume_ticket(ticket, now)
    }

    /// Ticket charset/length gate shared by consume/status paths.
    fn check_ticket_shape(ticket: &str) -> Result<()> {
        if ticket.len() < 8
            || ticket.len() > 128
            || !ticket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(PairError::InvalidTicket);
        }
        Ok(())
    }

    /// Non-mutating ticket status for `pair_status` polls (ipc.md §9d.3).
    /// Unknown, malformed, and consumed-but-unlinked tickets all collapse
    /// to `InvalidTicket` — polling must never be a live-ticket oracle.
    /// This method never consumes; `claim_ticket_and_register` is the only
    /// path that links a ticket to a device.
    pub fn ticket_status(&self, ticket: &str, now: i64) -> Result<TicketStatus> {
        Self::check_ticket_shape(ticket)?;
        let Some(row) = self.store.ticket_row(ticket)? else {
            return Err(PairError::InvalidTicket);
        };
        ticket_status_of(&row, now).ok_or(PairError::InvalidTicket)
    }

    /// Atomic ticket claim + device registration + ticket→device link —
    /// the ONE transaction the trusted pairing channel calls when the
    /// phone presents its ticket and key (ipc.md §9d.3). The label comes
    /// from the ticket (bound at `pair_begin`); the phone supplies
    /// `device_id`, `public_key`, and `keystore_ref`. The device lands
    /// `pending` — only a successful `device-pairing` challenge activates.
    pub fn claim_ticket_and_register(
        &mut self,
        ticket: &str,
        device_id: &str,
        algorithm: KeyAlgorithm,
        public_key: &[u8],
        keystore_ref: Option<&str>,
        now: i64,
    ) -> Result<DeviceRow> {
        Self::check_ticket_shape(ticket)?;
        check_field("device_id", device_id, MAX_ID_LEN)?;
        if let Some(r) = keystore_ref {
            check_field("keystore_ref", r, MAX_KEYSTORE_REF_LEN)?;
        }
        if !algorithm_supported(algorithm) {
            return Err(PairError::UnsupportedAlgorithm(format!("{algorithm:?}")));
        }
        if public_key.len() != 32 {
            return Err(PairError::BadKeyLength(public_key.len()));
        }
        self.store.claim_ticket_and_register(
            ticket,
            &ClaimDevice {
                device_id,
                algorithm: "ed25519",
                public_key,
                keystore_ref,
            },
            now,
        )
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
        if self.store.live_label_taken(label)? {
            return Err(PairError::DeviceLabelConflict(label.into()));
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

    /// Devices in the contract's total order (`registered_unix`, then
    /// `device_id` — ipc.md §9d.5). `limit` is the §9d.11 resource bound.
    pub fn list_devices(&self, limit: u32) -> Result<Vec<DeviceRow>> {
        self.store.list_devices(limit)
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
            // Pairing challenges are exclusively for pending devices
            // (ipc.md §9d.4: an active device cannot re-pair under the
            // same id — PAIR-1 fix).
            (crate::DeviceStatus::Active, ChallengeEvent::DevicePairing) => {
                return Err(PairError::DeviceNotActive(crate::DeviceStatus::Active));
            }
            (crate::DeviceStatus::Active, _) => {}
            (other, _) => return Err(PairError::DeviceNotActive(other)),
        }
        // Nonce + challenge insert are one transaction (PAIR-8): a failed
        // insert cannot burn the nonce, and a replayed nonce cannot leave
        // a half-written challenge.
        if !self.store.record_nonce_and_insert_challenge(
            &spec.nonce,
            now,
            &ChallengeRow {
                challenge_id: spec.challenge_id.clone(),
                device_id: spec.device_id.clone(),
                session_id: spec.session_id.clone(),
                event: event_name(spec.event).into(),
                nonce: spec.nonce.to_vec(),
                issued_unix: now,
                expires_unix: now + ttl_secs as i64,
                consumed: false,
            },
        )? {
            return Err(PairError::ReplayDetected);
        }
        // Rehydrate the kiwi-core Challenge so canonical_bytes() stays the
        // authoritative encoding — byte-for-byte contract §4.1.
        let mut book = kiwi_core::challenge::ChallengeBook::new();
        book.issue(spec, now, ttl_secs)
            .ok_or(PairError::ReplayDetected)
    }

    /// Verify a device response. Order per contract §6.2 / ChallengeBook:
    /// challenge exists → linked device exists and not revoked →
    /// unexpired → unconsumed → binding fields match → Ed25519 over
    /// canonical bytes → consume (+ pairing activation) atomically.
    /// A successful `device-pairing` verification auto-activates the
    /// device (contract §3.2 step 3). Failed verification never consumes.
    pub fn verify_response(&mut self, resp: &ChallengeResponse, now: i64) -> Result<()> {
        // §9d.8 bounds on the response strings before any store touch.
        check_field("challenge_id", &resp.challenge_id, MAX_ID_LEN)?;
        check_field("device_id", &resp.device_id, MAX_ID_LEN)?;
        check_field("session_id", &resp.session_id, MAX_SESSION_LEN)?;
        if resp.signature.is_empty() || resp.signature.len() > 512 {
            return Err(PairError::InvalidField {
                field: "signature",
                reason: "must be 1..=512 bytes".into(),
            });
        }
        let row = self
            .store
            .get_challenge(&resp.challenge_id)?
            .ok_or(ChallengeError::UnknownChallenge)?;

        // The challenge's linked device is required — a missing row is a
        // missing DEVICE (`not-found` semantics, PAIR-4), not an unknown
        // challenge; the challenge id demonstrably existed.
        let dev = self
            .store
            .get_device(&row.device_id)?
            .ok_or_else(|| PairError::DeviceNotFound(row.device_id.clone()))?;
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

        // Single-use — consume AND (for pairing) activate in one
        // transaction. The atomic UPDATE must report a flip: a false
        // return means another engine instance consumed the row between
        // our read and our write — that is AlreadyConsumed, NOT success
        // (PAIR-5 / §9d.11.3).
        let activate =
            (event == ChallengeEvent::DevicePairing).then_some((row.device_id.as_str(), now));
        if !self
            .store
            .consume_challenge_and_activate(&row.challenge_id, activate)?
        {
            return Err(ChallengeError::AlreadyConsumed.into());
        }
        Ok(())
    }
}
