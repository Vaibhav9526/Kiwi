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
            Locked(_) => ("locked", e.to_string()),
        };
        Self::new(code, msg)
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
