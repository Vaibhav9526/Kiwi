//! Device identity: registration, verification, suspension, revocation.
//!
//! A `Device` is an endpoint holding an asymmetric keypair whose private key
//! lives in a platform keystore (Android Keystore / iOS Secure Enclave /
//! OS credential store). kiwi-core stores only the public key and status —
//! never private material (SECURITY.md rule 8).
//!
//! Revocation is terminal: a revoked device id can never reactivate; a new
//! registration gets a fresh id. This makes clone/replay of an old identity
//! detectable rather than silently re-trusted.

use std::collections::BTreeMap;

use crate::trust::SignalKind;

/// Established algorithms only — no invented crypto (SECURITY.md rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa3072,
}

/// Public half of a device's keypair. The private key never leaves the
/// device's platform keystore and is never represented in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublicKey {
    pub algorithm: KeyAlgorithm,
    /// Raw public key bytes (algorithm-defined encoding).
    pub key: Vec<u8>,
    /// Opaque reference to the private key's keystore handle on the device,
    /// e.g. a KeyStore alias. Not sensitive, but not secret either.
    pub keystore_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceStatus {
    /// Registered but not yet verified via pairing challenge.
    Pending,
    Active,
    /// Temporarily distrusted (e.g. integrity signal); recoverable.
    Suspended,
    /// Terminal — never usable again under this device id.
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    /// Human label, e.g. "Vaibhav's Pixel".
    pub label: String,
    pub public_key: DevicePublicKey,
    pub status: DeviceStatus,
    pub registered_unix: i64,
    pub last_seen_unix: i64,
    /// Currently active endpoint indicators measured for this device.
    pub endpoint_signals: Vec<SignalKind>,
}

impl Device {
    /// Map device status to the trust signal it implies, if any.
    pub fn trust_signal(&self) -> Option<SignalKind> {
        match self.status {
            DeviceStatus::Pending => Some(SignalKind::NewDeviceUnverified),
            DeviceStatus::Suspended => Some(SignalKind::DeviceSuspended),
            DeviceStatus::Revoked => Some(SignalKind::DeviceRevoked),
            DeviceStatus::Active => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    Duplicate,
    NotFound,
    /// Revoked devices are terminal and cannot transition.
    RevokedIsTerminal,
}

/// In-memory registry; persistence lands behind a repository interface
/// (ADR-003) in a later phase.
#[derive(Default)]
pub struct DeviceRegistry {
    devices: BTreeMap<String, Device>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new device in `Pending`. The caller must complete a pairing
    /// challenge (`challenge` module) before `activate` is meaningful.
    pub fn register(&mut self, device: Device) -> Result<(), RegistryError> {
        if self.devices.contains_key(&device.device_id) {
            return Err(RegistryError::Duplicate);
        }
        let mut d = device;
        d.status = DeviceStatus::Pending;
        self.devices.insert(d.device_id.clone(), d);
        Ok(())
    }

    pub fn get(&self, device_id: &str) -> Option<&Device> {
        self.devices.get(device_id)
    }

    fn transition(&mut self, device_id: &str, next: DeviceStatus) -> Result<(), RegistryError> {
        let d = self
            .devices
            .get_mut(device_id)
            .ok_or(RegistryError::NotFound)?;
        if d.status == DeviceStatus::Revoked {
            return Err(RegistryError::RevokedIsTerminal);
        }
        d.status = next;
        Ok(())
    }

    pub fn activate(&mut self, device_id: &str) -> Result<(), RegistryError> {
        self.transition(device_id, DeviceStatus::Active)
    }

    pub fn suspend(&mut self, device_id: &str) -> Result<(), RegistryError> {
        self.transition(device_id, DeviceStatus::Suspended)
    }

    /// Revocation is terminal and must be audited by the caller
    /// (elevated action — SECURITY.md rule 11).
    pub fn revoke(&mut self, device_id: &str) -> Result<(), RegistryError> {
        self.transition(device_id, DeviceStatus::Revoked)
    }

    /// Trust signals implied by a device's current status + measurements.
    pub fn device_signals(&self, device_id: &str) -> Vec<SignalKind> {
        match self.devices.get(device_id) {
            Some(d) => {
                let mut v: Vec<SignalKind> = d.endpoint_signals.clone();
                if let Some(k) = d.trust_signal() {
                    v.push(k);
                }
                v
            }
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: &str) -> Device {
        Device {
            device_id: id.into(),
            label: "test device".into(),
            public_key: DevicePublicKey {
                algorithm: KeyAlgorithm::Ed25519,
                key: vec![0u8; 32],
                keystore_ref: None,
            },
            status: DeviceStatus::Active,
            registered_unix: 1_758_000_000,
            last_seen_unix: 1_758_000_000,
            endpoint_signals: vec![],
        }
    }

    #[test]
    fn register_starts_pending_then_activates() {
        let mut r = DeviceRegistry::new();
        r.register(dev("d1")).unwrap();
        assert_eq!(r.get("d1").unwrap().status, DeviceStatus::Pending);
        assert_eq!(
            r.device_signals("d1"),
            vec![SignalKind::NewDeviceUnverified]
        );
        r.activate("d1").unwrap();
        assert_eq!(r.get("d1").unwrap().status, DeviceStatus::Active);
        assert!(r.device_signals("d1").is_empty());
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut r = DeviceRegistry::new();
        r.register(dev("d1")).unwrap();
        assert_eq!(r.register(dev("d1")), Err(RegistryError::Duplicate));
    }

    #[test]
    fn revocation_is_terminal() {
        let mut r = DeviceRegistry::new();
        r.register(dev("d1")).unwrap();
        r.activate("d1").unwrap();
        r.revoke("d1").unwrap();
        assert_eq!(r.activate("d1"), Err(RegistryError::RevokedIsTerminal));
        assert_eq!(r.suspend("d1"), Err(RegistryError::RevokedIsTerminal));
        assert_eq!(r.device_signals("d1"), vec![SignalKind::DeviceRevoked]);
    }

    #[test]
    fn unknown_device_errors() {
        let mut r = DeviceRegistry::new();
        assert_eq!(r.activate("nope"), Err(RegistryError::NotFound));
    }
}
