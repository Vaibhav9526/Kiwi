//! OS credential store binding for `kiwi_mail::account::CredentialStore`.
//!
//! Secrets (mail passwords, OAuth tokens) live in the platform keystore —
//! Windows Credential Manager on this host — keyed by `credential_key`
//! (service `kiwi.mail`). Nothing secret ever enters the mail store,
//! the sidecar index, logs, or IPC responses (SECURITY.md rules 6, 8).

use keyring::Entry;
use zeroize::Zeroizing;

use kiwi_mail::account::CredentialStore;
use kiwi_mail::error::{MailError, Result};

const SERVICE: &str = "kiwi.mail";

fn cred_err(e: keyring::Error) -> MailError {
    // keyring error text describes the OS failure only — no secret values.
    MailError::Protocol {
        protocol: "credstore",
        detail: format!("credential store: {e}"),
    }
}

/// Stateless binding: a fresh `Entry` per call keeps the store trivially
/// `Send + Sync` and leaves lifetime management to the OS backend.
pub struct OsCredentialStore;

impl OsCredentialStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(key: &str) -> Result<Entry> {
        Entry::new(SERVICE, key).map_err(cred_err)
    }
}

impl CredentialStore for OsCredentialStore {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>> {
        match Self::entry(key)?.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(cred_err(e)),
        }
    }

    fn set(&self, key: &str, secret: &str) -> Result<()> {
        Self::entry(key)?.set_password(secret).map_err(cred_err)
    }

    fn delete(&self, key: &str) -> Result<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(cred_err(e)),
        }
    }
}
