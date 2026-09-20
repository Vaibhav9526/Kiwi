//! Device / endpoint wire views — authenticator registry, endpoint
//! signal reports.

use serde::{Deserialize, Serialize};

use kiwi_core::device::{Device, DeviceStatus, KeyAlgorithm};

use super::SecurityStatusView;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub device_id: String,
    pub label: String,
    /// "ed25519" | "ecdsa-p256" | "rsa3072".
    pub algorithm: String,
    /// "pending" | "active" | "suspended" | "revoked".
    pub status: String,
    pub registered_unix: i64,
    pub last_seen_unix: i64,
    /// sha256 tail of the public key — display fingerprint (ui-surfaces §3).
    pub key_fingerprint_tail: String,
}

impl From<&Device> for DeviceView {
    fn from(d: &Device) -> Self {
        use sha2::{Digest, Sha256};
        let fp = {
            let mut h = Sha256::new();
            h.update(&d.public_key.key);
            crate::audit::hex(&h.finalize())
        };
        Self {
            device_id: d.device_id.clone(),
            label: d.label.clone(),
            algorithm: key_algorithm(d.public_key.algorithm).to_string(),
            status: device_status(d.status).to_string(),
            registered_unix: d.registered_unix,
            last_seen_unix: d.last_seen_unix,
            key_fingerprint_tail: fp[fp.len().saturating_sub(8)..].to_string(),
        }
    }
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointReportView {
    pub collected_at_unix: i64,
    pub observations: Vec<crate::signals::EndpointObservation>,
    /// Full trust verdict after folding these signals in.
    pub status: SecurityStatusView,
}

pub fn key_algorithm(a: KeyAlgorithm) -> &'static str {
    match a {
        KeyAlgorithm::Ed25519 => "ed25519",
        KeyAlgorithm::EcdsaP256 => "ecdsa-p256",
        KeyAlgorithm::Rsa3072 => "rsa3072",
    }
}

pub fn parse_key_algorithm(s: &str) -> Option<KeyAlgorithm> {
    Some(match s {
        "ed25519" => KeyAlgorithm::Ed25519,
        "ecdsa-p256" => KeyAlgorithm::EcdsaP256,
        "rsa3072" => KeyAlgorithm::Rsa3072,
        _ => return Option::None,
    })
}

pub fn device_status(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Suspended => "suspended",
        DeviceStatus::Revoked => "revoked",
    }
}
