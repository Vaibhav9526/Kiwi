//! Challenge-response signature verification for authenticator-bound actions
//! (contracts/security-session.md §6). Ed25519 over the challenge's canonical
//! bytes, against the registered device public key. This is the concrete
//! `SignatureVerifier` the Phase-4 mobile authenticator's keys verify against;
//! device registration accepts Ed25519 public keys (32 bytes) today and
//! returns `unsupported-algorithm` for the other declared algorithms until
//! their verifiers land.

use kiwi_core::challenge::SignatureVerifier;
use kiwi_core::device::KeyAlgorithm;

/// Ed25519 verifier for `ChallengeBook::verify`.
pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, device_public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(key_bytes): Result<[u8; 32], _> = device_public_key.try_into() else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        ed25519_dalek::Verifier::verify(&vk, message, &sig).is_ok()
    }
}

/// Whether a registered device's key algorithm has a live verifier.
pub fn algorithm_supported(alg: KeyAlgorithm) -> bool {
    matches!(alg, KeyAlgorithm::Ed25519)
}
