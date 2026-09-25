//! Device wire views — authenticator registry, projected from kiwi-pair's
//! persisted `DeviceRow` (ipc.md §9d.5 `PairDeviceView`).

use serde::{Deserialize, Serialize};

use kiwi_core::device::KeyAlgorithm;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub device_id: String,
    pub label: String,
    /// "ed25519" — the only live verifier (ecdsa-p256/rsa3072 fail closed).
    pub algorithm: String,
    /// "pending" | "active" | "suspended" | "revoked".
    pub status: String,
    pub registered_unix: i64,
    /// Registration time; advanced by `set_device_status` — notably by a
    /// successful device-pairing verification (§9d.5). NOT a "last
    /// authenticated" signal.
    pub last_seen_unix: i64,
    /// sha256 tail of the public key — display fingerprint (ui-surfaces §3).
    pub key_fingerprint_tail: String,
    /// Dash-grouped SHA-256 fingerprint for human out-of-band comparison —
    /// display only, never a trust input (§9d.5).
    pub fingerprint: String,
    /// Opaque keystore alias on the device — never key material.
    pub keystore_ref: Option<String>,
    /// Set iff status == "revoked" (terminal).
    pub revoked_unix: Option<i64>,
}

impl From<&kiwi_pair::DeviceRow> for DeviceView {
    fn from(d: &kiwi_pair::DeviceRow) -> Self {
        use sha2::{Digest, Sha256};
        let fp = crate::audit::hex(&Sha256::digest(&d.public_key));
        Self {
            device_id: d.device_id.clone(),
            label: d.label.clone(),
            algorithm: d.algorithm.clone(),
            status: d.status.clone(),
            registered_unix: d.registered_unix,
            last_seen_unix: d.last_seen_unix,
            key_fingerprint_tail: fp[fp.len().saturating_sub(8)..].to_string(),
            fingerprint: kiwi_pair::device_fingerprint(&d.public_key),
            keystore_ref: d.keystore_ref.clone(),
            revoked_unix: d.revoked_unix,
        }
    }
}

/// `pair_begin` response (ipc.md §9d.2). `ticket`/`qrPayload` are BEARER
/// SECRETS returned for local-only rendering — they never enter logs,
/// prefs, evidence, or any other trust boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairBeginView {
    /// 43-char base64url bearer ticket.
    pub ticket: String,
    pub expires_unix: i64,
    /// Compact JSON string rendered verbatim as the QR payload.
    pub qr_payload: String,
}

/// `pair_status` response (ipc.md §9d.3) — the ticket is never echoed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairStatusView {
    /// "awaiting-phone" | "claimed" | "expired".
    pub state: String,
    /// The linked device iff `state == "claimed"`.
    pub device: Option<DeviceView>,
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceInput {
    pub label: String,
    /// "ed25519" | "ecdsa-p256" | "rsa3072".
    pub algorithm: String,
    /// Base64-encoded raw public key (32 bytes for ed25519).
    pub public_key_b64: String,
    #[serde(default)]
    pub keystore_ref: Option<String>,
}

/// Renderer-side algorithm spelling. `PairEngine` itself only accepts
/// `Ed25519` for registration and verification — the other two parse so the
/// engine can return its `unsupported-algorithm` error rather than
/// `invalid-input` (§9d.9 keeps those codes distinct).
pub fn parse_key_algorithm(s: &str) -> Option<KeyAlgorithm> {
    Some(match s {
        "ed25519" => KeyAlgorithm::Ed25519,
        "ecdsa-p256" => KeyAlgorithm::EcdsaP256,
        "rsa3072" => KeyAlgorithm::Rsa3072,
        _ => return Option::None,
    })
}
