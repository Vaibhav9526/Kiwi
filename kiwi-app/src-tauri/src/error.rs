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
    /// Structured backoff hint in milliseconds. Present only when the
    /// failure carries a server-sent or backend-enforced wait, so a caller
    /// can poll on the provider's cadence instead of parsing prose.
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl IpcError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    pub fn rate_limited(message: impl Into<String>, retry_after_ms: Option<u64>) -> Self {
        Self {
            code: "rate-limited",
            message: message.into(),
            retry_after_ms,
        }
    }

    /// Same failure, re-issued with a backoff hint.
    #[must_use]
    pub fn with_retry_after(mut self, retry_after_ms: Option<u64>) -> Self {
        self.retry_after_ms = retry_after_ms;
        self
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
        let (code, msg, retry_after_ms) = match &e {
            Transport {
                kind: TransportKind::Connect | TransportKind::Timeout,
            } => ("connect-failed", e.to_string(), None),
            Transport { .. } => ("integration-error", e.to_string(), None),
            Http { status } => (
                "integration-error",
                format!("provider returned unexpected HTTP {status}"),
                None,
            ),
            RateLimited { retry_after_ms } => (
                "rate-limited",
                match retry_after_ms {
                    Some(ms) => format!("provider rate-limited; retry after {ms} ms"),
                    None => "provider rate-limited".to_string(),
                },
                *retry_after_ms,
            ),
            Expired => (
                "expired",
                "provider reports the address or test expired".to_string(),
                None,
            ),
            NotFound => ("not-found", "not found on provider".to_string(), None),
            AnalysisFailed => (
                "integration-error",
                "provider-side analysis failed".to_string(),
                None,
            ),
            Malformed(field) => (
                "integration-error",
                format!("provider response malformed ({field})"),
                None,
            ),
            BodyTooLarge => (
                "integration-error",
                "provider response too large".to_string(),
                None,
            ),
            InsecureUrl => (
                "integration-error",
                "refused non-HTTPS provider URL".to_string(),
                None,
            ),
            NoSession => ("not-found", "no active temp-mail session".to_string(), None),
            ProviderRejected(why) => (
                "server-reject",
                format!("provider rejected the request: {why}"),
                None,
            ),
        };
        match retry_after_ms {
            None => Self::new(code, msg),
            Some(ms) => Self::new(code, msg).with_retry_after(Some(ms)),
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

    #[test]
    fn backoff_hint_is_structured_and_absent_otherwise() {
        let hinted = IpcError::rate_limited("provider rate-limited", Some(1_500));
        let v = serde_json::to_value(&hinted).unwrap();
        assert_eq!(v["code"], "rate-limited");
        assert_eq!(v["retryAfterMs"], 1_500);
        assert_eq!(hinted.retry_after_ms, Some(1_500));

        // Every other failure keeps the two-field shape: a caller must not
        // have to distinguish "no hint" from "hint is zero".
        for e in [IpcError::locked(), IpcError::not_found("gone")] {
            let v = serde_json::to_value(&e).unwrap();
            assert!(v.get("retryAfterMs").is_none());
            assert_eq!(e.retry_after_ms, None);
        }

        // A hint can also be attached to a non-rate-limited code (the poll
        // single-flight gate) without changing the code itself.
        let busy = IpcError::new("poll-in-flight", "already running").with_retry_after(Some(5_000));
        let v = serde_json::to_value(&busy).unwrap();
        assert_eq!(v["code"], "poll-in-flight");
        assert_eq!(v["retryAfterMs"], 5_000);
        assert!(
            serde_json::to_value(IpcError::new("poll-in-flight", "already running"))
                .unwrap()
                .get("retryAfterMs")
                .is_none()
        );
    }

    #[test]
    fn provider_rate_limit_hint_survives_the_error_mapping() {
        use kiwi_integrations::IntegrationError as E;
        let hinted: IpcError = E::RateLimited {
            retry_after_ms: Some(2_500),
        }
        .into();
        assert_eq!(hinted.code, "rate-limited");
        assert_eq!(hinted.retry_after_ms, Some(2_500));
        assert_eq!(
            serde_json::to_value(&hinted).unwrap()["retryAfterMs"],
            2_500
        );

        let bare: IpcError = E::RateLimited {
            retry_after_ms: None,
        }
        .into();
        assert_eq!(bare.code, "rate-limited");
        assert_eq!(bare.retry_after_ms, None);
        assert!(
            serde_json::to_value(&bare)
                .unwrap()
                .get("retryAfterMs")
                .is_none()
        );

        // Non-rate-limited provider failures never grow a backoff hint.
        for e in [E::NotFound, E::Expired, E::BodyTooLarge] {
            let mapped: IpcError = e.into();
            assert_eq!(mapped.retry_after_ms, None, "{}", mapped.code);
        }
    }
}
