//! System / lock-path wire views — status bar, challenges, app info.

use serde::{Deserialize, Serialize};

use kiwi_core::challenge::Challenge;
use kiwi_core::trust::TrustSignal;

use super::{challenge_event, severity, signal_kind};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalView {
    pub kind: String,
    pub severity: String,
    pub penalty: u32,
    pub evidence_ref: String,
}

impl From<&TrustSignal> for SignalView {
    fn from(s: &TrustSignal) -> Self {
        Self {
            kind: signal_kind(s.kind).to_string(),
            severity: severity(s.severity).to_string(),
            penalty: s.penalty,
            evidence_ref: s.evidence_ref.clone(),
        }
    }
}

/// The security bar / lock overlay payload (`kiwi_security_status`,
/// KIWI-UI-002/005).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusView {
    /// ui-surfaces §2 token: secure|warning|danger|unknown.
    pub trust: String,
    pub locked: bool,
    /// kiwi-core trust state: trusted|degraded|locked.
    pub state: String,
    pub score: u32,
    pub required_action: String,
    pub signals: Vec<SignalView>,
    /// Count of connection observations behind this verdict.
    pub sessions_observed: u64,
    pub device_id: String,
}

/// ipc.md §9d.4 `PairChallengeView` — `nonceB64` is the ONLY nonce field
/// (RFC 4648 standard Base64, padded, exactly 32 decoded bytes); the
/// legacy `nonceHex` spelling is withdrawn.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeView {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    /// "unlock" | "device-pairing" | "recovery" | "elevated-action".
    pub event: String,
    pub nonce_b64: String,
    pub issued_unix: i64,
    pub expires_unix: i64,
    /// Exact bytes the authenticator must sign (canonical per contract §6).
    pub canonical_bytes_b64: String,
}

impl From<&Challenge> for ChallengeView {
    fn from(c: &Challenge) -> Self {
        use base64::Engine;
        Self {
            challenge_id: c.challenge_id.clone(),
            device_id: c.device_id.clone(),
            session_id: c.session_id.clone(),
            event: challenge_event(c.event).to_string(),
            nonce_b64: base64::engine::general_purpose::STANDARD.encode(c.nonce),
            issued_unix: c.issued_unix,
            expires_unix: c.expires_unix,
            canonical_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(c.canonical_bytes()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponseInput {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    /// "unlock" | "device-pairing" | "recovery" | "elevated-action".
    pub event: String,
    /// Base64-encoded device signature over the challenge canonical bytes.
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfoView {
    pub version: String,
    pub contract_version: String,
    pub device_id: String,
    pub org: Option<OrgBindingView>,
    pub account_count: usize,
    pub sessions_observed: u64,
    /// Whether a tray icon actually exists (T-345) — false on platforms
    /// with no tray surface; the close-to-tray pref is then inert and the
    /// settings UI must say so rather than pretend the toggle works.
    pub tray_available: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgBindingView {
    pub org_id: String,
    pub base_url: String,
}
