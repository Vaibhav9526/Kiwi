//! Account/server/credential model; OAuth2 token storage boundaries.
//!
//! Accounts describe *where* to connect (host, port, socket security, auth
//! kind). Secrets never live in this model — `AuthRef` carries a
//! `credential_key` resolved through [`CredentialStore`], the seam the app
//! layer binds to an OS credential store (SECURITY.md rules 6, 8).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::transport::SocketSecurity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncomingProtocol {
    Imap,
    Pop3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub security: SocketSecurity,
}

/// How to authenticate — the secret itself is fetched from the store by key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthRef {
    /// USER/PASS-style password under `credential_key`.
    Password { credential_key: String },
    /// OAuth2/XOAUTH2 bearer token under `credential_key`.
    XOAuth2 { credential_key: String },
    /// POP3 APOP (needs banner; falls back to USER/PASS semantics upstream).
    Apop { credential_key: String },
    /// No authentication (e.g. local test servers).
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingAccount {
    pub protocol: IncomingProtocol,
    pub server: ServerConfig,
    pub auth: AuthRef,
    /// IMAP mailbox/POP3 drop name for login (usually the email address).
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingAccount {
    pub server: ServerConfig,
    pub auth: AuthRef,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailAccount {
    pub account_id: String,
    pub display_name: String,
    pub email: String,
    pub incoming: IncomingAccount,
    pub outgoing: OutgoingAccount,
}

/// Boundary between the account model and wherever secrets actually live
/// (OS credential store / keychain in the Tauri layer). Implementations must
/// never log secret material.
pub trait CredentialStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>>;
    fn set(&self, key: &str, secret: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-memory credential store — **tests and local development only**.
/// The shipped product binds `CredentialStore` to the OS keystore via the
/// Tauri layer; do not treat this as durable secret storage.
#[derive(Default)]
pub struct MemoryCredentialStore {
    inner: std::sync::Mutex<std::collections::BTreeMap<String, Zeroizing<String>>>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self.inner.lock().unwrap().get(key).map(|s| {
            Zeroizing::new(s.as_str().to_string())
        }))
    }
    fn set(&self, key: &str, secret: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .insert(key.to_string(), Zeroizing::new(secret.to_string()));
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_store_roundtrip_no_debug_leak() {
        let store = MemoryCredentialStore::new();
        store.set("acct/imap", "s3cret").unwrap();
        let got = store.get("acct/imap").unwrap().unwrap();
        assert_eq!(got.as_str(), "s3cret");
        store.delete("acct/imap").unwrap();
        assert!(store.get("acct/imap").unwrap().is_none());
        // account model itself contains no secrets
        let acct = MailAccount {
            account_id: "a1".into(),
            display_name: "d".into(),
            email: "u@x.test".into(),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::Password {
                    credential_key: "acct/imap".into(),
                },
                username: "u@x.test".into(),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 587,
                    security: SocketSecurity::StartTls,
                },
                auth: AuthRef::Password {
                    credential_key: "acct/smtp".into(),
                },
                username: "u@x.test".into(),
            },
        };
        let json = serde_json::to_string(&acct).unwrap();
        assert!(!json.contains("s3cret"));
    }
}
