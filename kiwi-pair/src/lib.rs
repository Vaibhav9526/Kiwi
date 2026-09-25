//! kiwi-pair — desktop-side engine for the mobile authenticator protocol
//! (`docs/contracts/authenticator.md`, `docs/contracts/pair.md`).
//!
//! Responsibilities (T-174):
//!   - Ed25519 challenge issue + verify over kiwi-core canonical bytes
//!     (`crypto::Ed25519Verifier` implements `SignatureVerifier`)
//!   - persistent pairing records in SQLite (`store::PairStore`) —
//!     devices, pairing tickets, challenges, seen nonces
//!   - nonce + timestamp replay protection inside a bounded window
//!   - terminal device revocation
//!   - `device_fingerprint` — human-comparable key display string
//!
//! Security posture (SECURITY.md rules 4, 6, 8–10): Ed25519 only — other
//! declared algorithms fail closed; private keys never appear here (the
//! phone's keystore signs; desktop only verifies); nonces are caller-
//! supplied CSPRNG bytes (`os_nonce()` wraps `getrandom`); all stored
//! strings are length-bounded; a consumed or expired challenge can never
//! verify again.

mod crypto;
mod engine;
mod store;

pub use crypto::{
    DeviceSigner, Ed25519Verifier, algorithm_supported, device_fingerprint, os_nonce,
};
pub use engine::{
    CHALLENGE_TTL_SECS, MAX_TTL_SECS, PairEngine, PairingTicket, QR_TTL_SECS, TicketState,
    TicketStatus,
};
pub use store::{ChallengeRow, ClaimDevice, DeviceRow, PairStore, TicketRow};

pub use kiwi_core::challenge::{
    Challenge, ChallengeBook, ChallengeError, ChallengeEvent, ChallengeResponse, ChallengeSpec,
    SignatureVerifier,
};
pub use kiwi_core::device::{DeviceStatus, KeyAlgorithm};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PairError {
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("challenge error: {0:?}")]
    Challenge(ChallengeError),
    #[error("unsupported key algorithm (ed25519 only): {0}")]
    UnsupportedAlgorithm(String),
    #[error("public key must be exactly 32 bytes, got {0}")]
    BadKeyLength(usize),
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("pairing ticket invalid")]
    InvalidTicket,
    #[error("pairing ticket already consumed")]
    TicketConsumed,
    #[error("pairing ticket expired")]
    TicketExpired,
    #[error("device already registered: {0}")]
    DeviceExists(String),
    /// A non-revoked device already carries this label (normalized).
    /// ipc.md §9d maps this to `conflict` — duplicate display names are
    /// never silently merged into the device list.
    #[error("a live device already uses label: {0}")]
    DeviceLabelConflict(String),
    #[error("unknown device: {0}")]
    DeviceNotFound(String),
    /// Revocation is terminal — the device id can never be re-trusted.
    #[error("device revoked: {0}")]
    DeviceRevoked(String),
    /// A challenge nonce was already issued — replay indicator
    /// (contract §4.3; callers should audit `replay-detected`).
    #[error("nonce already issued — replay detected")]
    ReplayDetected,
    #[error("challenge requires an active device (status {0:?})")]
    DeviceNotActive(DeviceStatus),
    #[error("randomness unavailable: {0}")]
    Entropy(String),
}

// ChallengeError is a plain kiwi-core enum (not std::error::Error).
impl From<ChallengeError> for PairError {
    fn from(e: ChallengeError) -> Self {
        PairError::Challenge(e)
    }
}

pub type Result<T> = std::result::Result<T, PairError>;
