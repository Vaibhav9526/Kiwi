//! Authenticator challenge binding — the deterministic core of the
//! approve/deny protocol used for unlock, device pairing, and recovery.
//!
//! Binding rules (SECURITY.md rules 4, 10):
//! - every challenge binds device + session + event + nonce + expiry;
//! - a challenge is single-use — replay must fail;
//! - the cryptographic check is delegated to a `SignatureVerifier` over the
//!   canonical challenge bytes; the private key never leaves the device.
//!
//! Nonces must come from an OS CSPRNG by callers (Phase 4 wiring: `getrandom`
//! or equivalent). This module never generates pseudo-randomness itself.

use std::collections::BTreeMap;

/// What the challenge authorizes. The event is part of the signed payload —
/// a signature for `Unlock` can never be replayed as `DevicePairing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallengeEvent {
    /// Approve leaving `TrustState::Locked`.
    Unlock,
    /// Approve registering a new device (`DeviceStatus::Pending → Active`).
    DevicePairing,
    /// Approve an account recovery flow.
    Recovery,
    /// Approve an audited elevated/admin action.
    ElevatedAction,
}

impl ChallengeEvent {
    fn tag(self) -> u8 {
        match self {
            ChallengeEvent::Unlock => 0x01,
            ChallengeEvent::DevicePairing => 0x02,
            ChallengeEvent::Recovery => 0x03,
            ChallengeEvent::ElevatedAction => 0x04,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    pub event: ChallengeEvent,
    /// 32-byte single-use nonce from a CSPRNG, supplied at issue time.
    pub nonce: [u8; 32],
    pub issued_unix: i64,
    pub expires_unix: i64,
    consumed: bool,
}

impl Challenge {
    /// Canonical byte string the device signs. Fixed order, length-prefixed
    /// fields — every bound element is covered, so tampering with any of
    /// them invalidates the signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        push_field(&mut v, b"kiwi-challenge-v1");
        push_field(&mut v, self.challenge_id.as_bytes());
        push_field(&mut v, self.device_id.as_bytes());
        push_field(&mut v, self.session_id.as_bytes());
        v.push(self.event.tag());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.issued_unix.to_be_bytes());
        v.extend_from_slice(&self.expires_unix.to_be_bytes());
        v
    }
}

fn push_field(v: &mut Vec<u8>, field: &[u8]) {
    v.extend_from_slice(&(field.len() as u32).to_be_bytes());
    v.extend_from_slice(field);
}

/// Parameters for issuing a challenge. `nonce` MUST be 32 bytes of CSPRNG
/// output supplied by the caller — this crate never generates randomness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSpec {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    pub event: ChallengeEvent,
    /// 32-byte single-use nonce from a CSPRNG.
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    /// Binding fields echoed by the responder; must match the challenge.
    pub device_id: String,
    pub session_id: String,
    pub event: ChallengeEvent,
    /// Device signature over `challenge.canonical_bytes()`.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    UnknownChallenge,
    Expired,
    AlreadyConsumed,
    /// Device/session/event fields don't match the issued challenge.
    BindingMismatch,
    /// `SignatureVerifier` rejected the response signature.
    InvalidSignature,
}

/// Verifies an authenticator signature over canonical challenge bytes.
/// Implementations must use established signature schemes (Ed25519 /
/// ECDSA P-256 / RSA-PSS) with the device's registered public key — the
/// Phase-4 mobile authenticator supplies the concrete verifier. There is no
/// accept-all implementation in non-test code.
pub trait SignatureVerifier {
    fn verify(&self, device_public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Issues and verifies challenges; enforces single-use.
#[derive(Default)]
pub struct ChallengeBook {
    challenges: BTreeMap<String, Challenge>,
    /// Recent nonces — a nonce seen twice is a replay indicator.
    seen_nonces: Vec<[u8; 32]>,
}

impl ChallengeBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a bound challenge. Returns `None` if `spec.nonce` was already
    /// used — callers should treat a duplicate nonce as an incident
    /// (`SignalKind::ReplayDetected`).
    pub fn issue(&mut self, spec: ChallengeSpec, now: i64, ttl_secs: u64) -> Option<Challenge> {
        if self.seen_nonces.contains(&spec.nonce) {
            return None;
        }
        self.seen_nonces.push(spec.nonce);
        let c = Challenge {
            challenge_id: spec.challenge_id,
            device_id: spec.device_id,
            session_id: spec.session_id,
            event: spec.event,
            nonce: spec.nonce,
            issued_unix: now,
            expires_unix: now + ttl_secs as i64,
            consumed: false,
        };
        self.challenges.insert(c.challenge_id.clone(), c.clone());
        Some(c)
    }

    /// Verify a response. Checks, in order: existence → expiry → single-use
    /// → binding fields → signature over canonical bytes. Consumes the
    /// challenge only on full success, so a failed attempt does not
    /// denial-of-service a legitimate retry; replay of a consumed challenge
    /// always fails.
    pub fn verify(
        &mut self,
        resp: &ChallengeResponse,
        device_public_key: &[u8],
        verifier: &dyn SignatureVerifier,
        now: i64,
    ) -> Result<(), ChallengeError> {
        let c = self
            .challenges
            .get_mut(&resp.challenge_id)
            .ok_or(ChallengeError::UnknownChallenge)?;

        if now >= c.expires_unix {
            return Err(ChallengeError::Expired);
        }
        if c.consumed {
            return Err(ChallengeError::AlreadyConsumed);
        }
        if c.device_id != resp.device_id || c.session_id != resp.session_id || c.event != resp.event
        {
            return Err(ChallengeError::BindingMismatch);
        }
        if !verifier.verify(device_public_key, &c.canonical_bytes(), &resp.signature) {
            return Err(ChallengeError::InvalidSignature);
        }
        c.consumed = true;
        Ok(())
    }

    /// Test/admin introspection.
    pub fn is_consumed(&self, challenge_id: &str) -> Option<bool> {
        self.challenges.get(challenge_id).map(|c| c.consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double — NOT shipped. Real verification arrives with the Phase-4
    /// authenticator (Ed25519/ECDSA per contracts/authenticator.md).
    struct FixedVerifier(bool);
    impl SignatureVerifier for FixedVerifier {
        fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
            self.0
        }
    }

    const NONCE: [u8; 32] = [7u8; 32];
    const NONCE2: [u8; 32] = [9u8; 32];

    fn spec(id: &str, session: &str, nonce: [u8; 32]) -> ChallengeSpec {
        ChallengeSpec {
            challenge_id: id.into(),
            device_id: "dev1".into(),
            session_id: session.into(),
            event: ChallengeEvent::Unlock,
            nonce,
        }
    }

    fn issue(book: &mut ChallengeBook, nonce: [u8; 32]) -> Challenge {
        book.issue(spec("c1", "sess1", nonce), 1000, 120)
            .expect("fresh nonce")
    }

    fn resp_for(c: &Challenge) -> ChallengeResponse {
        ChallengeResponse {
            challenge_id: c.challenge_id.clone(),
            device_id: c.device_id.clone(),
            session_id: c.session_id.clone(),
            event: c.event,
            signature: b"sig".to_vec(),
        }
    }

    #[test]
    fn correct_binding_and_signature_verifies() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let r = resp_for(&c);
        assert_eq!(b.verify(&r, b"pk", &FixedVerifier(true), 1050), Ok(()));
        assert_eq!(b.is_consumed("c1"), Some(true));
    }

    #[test]
    fn consumed_challenge_cannot_be_replayed() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let r = resp_for(&c);
        b.verify(&r, b"pk", &FixedVerifier(true), 1050).unwrap();
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(true), 1060),
            Err(ChallengeError::AlreadyConsumed)
        );
    }

    #[test]
    fn expired_challenge_fails() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let r = resp_for(&c);
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(true), 1200),
            Err(ChallengeError::Expired)
        );
    }

    #[test]
    fn wrong_device_binding_fails() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let mut r = resp_for(&c);
        r.device_id = "dev2".into();
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(true), 1050),
            Err(ChallengeError::BindingMismatch)
        );
        // Failed binding must NOT consume the challenge.
        assert_eq!(b.is_consumed("c1"), Some(false));
    }

    #[test]
    fn wrong_event_binding_fails() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let mut r = resp_for(&c);
        r.event = ChallengeEvent::Recovery;
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(true), 1050),
            Err(ChallengeError::BindingMismatch)
        );
    }

    #[test]
    fn bad_signature_fails() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let r = resp_for(&c);
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(false), 1050),
            Err(ChallengeError::InvalidSignature)
        );
        assert_eq!(b.is_consumed("c1"), Some(false));
    }

    #[test]
    fn unknown_challenge_fails() {
        let mut b = ChallengeBook::new();
        let r = ChallengeResponse {
            challenge_id: "nope".into(),
            device_id: "dev1".into(),
            session_id: "sess1".into(),
            event: ChallengeEvent::Unlock,
            signature: vec![],
        };
        assert_eq!(
            b.verify(&r, b"pk", &FixedVerifier(true), 1050),
            Err(ChallengeError::UnknownChallenge)
        );
    }

    #[test]
    fn duplicate_nonce_rejected_at_issue() {
        let mut b = ChallengeBook::new();
        assert!(issue(&mut b, NONCE).challenge_id == "c1");
        assert!(b.issue(spec("c2", "sess2", NONCE), 1001, 120).is_none());
        assert!(b.issue(spec("c2", "sess2", NONCE2), 1001, 120).is_some());
    }

    #[test]
    fn canonical_bytes_cover_all_bound_fields() {
        let mut b = ChallengeBook::new();
        let c = issue(&mut b, NONCE);
        let bytes = c.canonical_bytes();
        assert!(bytes.windows(32).any(|w| w == NONCE));
        assert!(bytes.windows(4).any(|w| w == b"dev1"));
        assert!(bytes.windows(5).any(|w| w == b"sess1"));
        assert!(bytes.contains(&ChallengeEvent::Unlock.tag()));
    }
}
