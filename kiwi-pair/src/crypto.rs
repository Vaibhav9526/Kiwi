//! Ed25519 verification, device-key fingerprints, and entropy helpers.
//!
//! `Ed25519Verifier` is the concrete `SignatureVerifier` for
//! `kiwi_core::challenge::ChallengeBook` — byte-identical semantics to the
//! kiwi-app desktop verifier. Ed25519 is the only live algorithm
//! (contract §1): `ecdsa-p256`/`rsa3072` are reserved names that fail
//! closed until verifiers land.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{PairError, Result};
use kiwi_core::challenge::SignatureVerifier;
use kiwi_core::device::KeyAlgorithm;

/// Ed25519 verifier over canonical challenge bytes.
pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, device_public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(key_bytes): std::result::Result<[u8; 32], _> = device_public_key.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(signature) else {
            return false;
        };
        Verifier::verify(&vk, message, &sig).is_ok()
    }
}

/// Whether a registered device's key algorithm has a live verifier.
/// Fail-closed: Ed25519 only today.
pub fn algorithm_supported(alg: KeyAlgorithm) -> bool {
    matches!(alg, KeyAlgorithm::Ed25519)
}

/// Device-side signer. This is the deterministic fixture / mobile-parity
/// helper — production signing happens inside the phone's platform
/// keystore (contract §5); raw private keys never cross into kiwi-app.
pub struct DeviceSigner {
    key: SigningKey,
}

impl DeviceSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Ed25519 is deterministic — same key + message → same signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

/// Human-comparable fingerprint of a device's public key:
/// `SHA-256(key)[..16]` as uppercase hex, dash-grouped in 4s —
/// `6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20` for the all-zero key.
/// Display-only; never a trust decision input.
pub fn device_fingerprint(public_key: &[u8]) -> String {
    let h = Sha256::digest(public_key);
    let mut s = String::with_capacity(39);
    for (i, b) in h[..16].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push('-');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// 32 bytes of OS CSPRNG output for challenge nonces / pairing tickets.
/// The crate never generates pseudo-randomness itself — tests inject
/// fixed values for determinism.
pub fn os_nonce() -> Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| PairError::Entropy(e.to_string()))?;
    Ok(n)
}
