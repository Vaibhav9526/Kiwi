//! Structured IPC errors — the wire shape every command failure takes.
//!
//! The frontend receives `{ code, message }`; `code` is a stable,
//! machine-checkable token (contract: `docs/contracts/ipc.md` §errors) and
//! `message` is a sanitized human-readable detail. Error payloads must never
//! contain secrets, tokens, or key material (SECURITY.md §4).

use serde::Serialize;

/// Result type for every IPC command implementation.
pub type CmdResult<T> = Result<T, IpcError>;

/// A structured command failure. `code` is the contract-stable field.
#[derive(Debug, Clone, Serialize)]
pub struct IpcError {
    /// Stable machine-readable error code (see ipc.md error catalog).
    pub code: &'static str,
    /// Sanitized human-readable detail — never secrets.
    pub message: String,
}

impl IpcError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The lock-state gate's error: every gated command returns this while
    /// the endpoint trust state is `Locked` (ipc.md §lock-gate).
    pub fn locked() -> Self {
        Self::new(
            "locked",
            "endpoint is locked; complete authenticator unlock to continue",
        )
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid-input", message)
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new("not-found", what)
    }

    pub fn sandbox_unavailable(why: impl Into<String>) -> Self {
        Self::new("sandbox-unavailable", why)
    }

    pub fn sandbox_failed(why: impl Into<String>) -> Self {
        Self::new("sandbox-failed", why)
    }

    pub fn sandbox_required() -> Self {
        Self::new(
            "sandbox-required",
            "risky message link must be opened through kiwi_sandbox_open_link",
        )
    }

    pub fn link_denied() -> Self {
        Self::new("link-denied", "message link is not allowed by policy")
    }
}

impl From<kiwi_mail::error::MailError> for IpcError {
    fn from(e: kiwi_mail::error::MailError) -> Self {
        use kiwi_mail::error::MailError::*;
        let (code, msg) = match &e {
            Io(_) => ("connect-failed", e.to_string()),
            Tls(_) => ("tls-failed", e.to_string()),
            Protocol { .. } => ("protocol-error", e.to_string()),
            Auth(_) => ("auth-failed", e.to_string()),
            ServerReject { .. } => ("server-reject", e.to_string()),
            Store(_) => ("store-error", e.to_string()),
            PolicyRejected(_) => ("policy-blocked", e.to_string()),
            InvalidInput(_) => ("invalid-input", e.to_string()),
            Locked(_) => ("locked", e.to_string()),
        };
        Self::new(code, msg)
    }
}

impl From<kiwi_sandbox::SandboxError> for IpcError {
    fn from(e: kiwi_sandbox::SandboxError) -> Self {
        match e {
            kiwi_sandbox::SandboxError::Unavailable(why) => Self::sandbox_unavailable(why),
            other => Self::sandbox_failed(other.to_string()),
        }
    }
}

impl From<kiwi_core::trust::UnlockError> for IpcError {
    fn from(e: kiwi_core::trust::UnlockError) -> Self {
        use kiwi_core::trust::UnlockError::*;
        match e {
            NotLocked => Self::new("not-locked", "endpoint is not locked"),
            AuthenticatorRequired => Self::new(
                "authenticator-required",
                "unlock requires an approved authenticator challenge",
            ),
        }
    }
}

impl From<kiwi_core::challenge::ChallengeError> for IpcError {
    fn from(e: kiwi_core::challenge::ChallengeError) -> Self {
        use kiwi_core::challenge::ChallengeError::*;
        match e {
            UnknownChallenge => Self::new("unknown-challenge", "unknown challenge id"),
            Expired => Self::new("expired", "challenge expired"),
            AlreadyConsumed => Self::new(
                "already-consumed",
                "challenge already consumed (replay rejected)",
            ),
            BindingMismatch => Self::new(
                "binding-mismatch",
                "response binding does not match the issued challenge",
            ),
            InvalidSignature => Self::new("invalid-signature", "response signature invalid"),
        }
    }
}

impl From<kiwi_pair::PairError> for IpcError {
    /// The §9d.9 mapping is normative: semantic names survive the boundary,
    /// payloads never echo device ids, tickets, or key material. Store/Io
    /// displays can contain object names/paths → fixed generic messages.
    fn from(e: kiwi_pair::PairError) -> Self {
        use kiwi_core::challenge::ChallengeError as CE;
        use kiwi_pair::PairError::*;
        match e {
            Challenge(CE::UnknownChallenge) => {
                Self::new("unknown-challenge", "unknown challenge id")
            }
            Challenge(CE::Expired) => Self::new("challenge-expired", "challenge expired"),
            Challenge(CE::AlreadyConsumed) => Self::new(
                "already-consumed",
                "challenge already consumed (replay rejected)",
            ),
            Challenge(CE::BindingMismatch) => Self::new(
                "binding-mismatch",
                "response binding does not match the issued challenge",
            ),
            Challenge(CE::InvalidSignature) => {
                Self::new("invalid-signature", "response signature invalid")
            }
            DeviceNotFound(_) => Self::not_found("unknown device"),
            DeviceNotActive(status) => Self::new(
                "device-not-active",
                format!("challenge requires an active device (status {status:?})"),
            ),
            DeviceRevoked(_) => Self::new("device-revoked", "device is revoked (terminal)"),
            DeviceExists(_) => Self::new("device-exists", "device id already registered"),
            DeviceLabelConflict(_) => {
                Self::new("conflict", "a live device already uses that label")
            }
            ReplayDetected => Self::new("replay-detected", "challenge nonce collision"),
            UnsupportedAlgorithm(_) => {
                Self::new("unsupported-algorithm", "unsupported key algorithm")
            }
            BadKeyLength(n) => {
                Self::invalid(format!("publicKey must be exactly 32 bytes, got {n}"))
            }
            InvalidField { field, reason } => Self::invalid(format!("{field}: {reason}")),
            InvalidTicket => Self::new("pairing-ticket-invalid", "pairing ticket invalid"),
            TicketConsumed => Self::new("pairing-ticket-consumed", "pairing ticket consumed"),
            TicketExpired => Self::new("pairing-ticket-expired", "pairing ticket expired"),
            Entropy(_) => Self::new("internal", "randomness unavailable"),
            Store(_) => Self::new("store-error", "pairing store error"),
            Io(_) => Self::new("io-error", "local file/IO error"),
        }
    }
}

impl From<kiwi_integrations::IntegrationError> for IpcError {
    /// Integration errors are pre-sanitized at the crate boundary — no URLs,
    /// no capability secrets, no provider internals (integrations contract
    /// §1). We forward only the coarse message + a stable code.
    fn from(e: kiwi_integrations::IntegrationError) -> Self {
        use kiwi_integrations::IntegrationError::*;
        use kiwi_integrations::TransportKind;
        let (code, msg) = match &e {
            Transport {
                kind: TransportKind::Connect | TransportKind::Timeout,
            } => ("connect-failed", e.to_string()),
            Transport { .. } => ("integration-error", e.to_string()),
            Http { status } => (
                "integration-error",
                format!("provider returned unexpected HTTP {status}"),
            ),
            RateLimited { retry_after_ms } => (
                "rate-limited",
                match retry_after_ms {
                    Some(ms) => format!("provider rate-limited; retry after {ms} ms"),
                    None => "provider rate-limited".to_string(),
                },
            ),
            Expired => (
                "expired",
                "provider reports the address or test expired".to_string(),
            ),
            NotFound => ("not-found", "not found on provider".to_string()),
            AnalysisFailed => (
                "integration-error",
                "provider-side analysis failed".to_string(),
            ),
            Malformed(field) => (
                "integration-error",
                format!("provider response malformed ({field})"),
            ),
            BodyTooLarge => (
                "integration-error",
                "provider response too large".to_string(),
            ),
            InsecureUrl => (
                "integration-error",
                "refused non-HTTPS provider URL".to_string(),
            ),
            NoSession => ("not-found", "no active temp-mail session".to_string()),
            ProviderRejected(why) => (
                "server-reject",
                format!("provider rejected the request: {why}"),
            ),
        };
        Self::new(code, msg)
    }
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        Self::new("io-error", e.to_string())
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IpcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_serializes_to_stable_shape() {
        let e = IpcError::locked();
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["code"], "locked");
        assert!(v["message"].is_string());
    }
}
