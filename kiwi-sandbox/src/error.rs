//! Sandbox error type (contract: `docs/contracts/sandbox.md` §Errors).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    /// Provider absent — the normal degradation path, not a failure.
    #[error("sandbox unavailable: {0}")]
    Unavailable(String),
    /// Base image not provisioned yet.
    #[error("sandbox base image missing: {0}")]
    ImageMissing(String),
    /// VM/distro failed to start or spec rejected.
    #[error("sandbox create failed: {0}")]
    Create(String),
    /// Guest-side agent/command failure.
    #[error("sandbox guest error: {0}")]
    GuestError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
