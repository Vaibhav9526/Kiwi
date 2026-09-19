//! SecureMail identity: account model and account sessions.
//!
//! Credential ownership stays with Thunderbird / the OS credential store —
//! this module models account *identity*, bound devices, and session
//! lifecycle only. No passwords, tokens, or OAuth secrets exist here
//! (SECURITY.md rule 6).

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Suspended,
    /// Account is mid-recovery; normal sessions stay blocked until the
    /// recovery flow completes per `RecoveryPolicy`.
    RecoveryPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    /// Recovery must be approved by a registered authenticator device.
    pub requires_authenticator: bool,
    /// Bound on consecutive failed recovery attempts before the account
    /// must be suspended — a measurable control, not a guarantee.
    pub max_failed_attempts: u32,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            requires_authenticator: true,
            max_failed_attempts: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureMailAccount {
    pub account_id: String,
    pub status: AccountStatus,
    pub created_unix: i64,
    /// Device ids bound to this account (see `device::DeviceRegistry`).
    pub registered_devices: BTreeSet<String>,
    pub recovery: RecoveryPolicy,
}

impl SecureMailAccount {
    pub fn new(account_id: impl Into<String>, created_unix: i64) -> Self {
        Self {
            account_id: account_id.into(),
            status: AccountStatus::Active,
            created_unix,
            registered_devices: BTreeSet::new(),
            recovery: RecoveryPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSessionState {
    Active,
    Expired,
    /// Killed by user, admin, or trust engine (e.g. lock event).
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSession {
    pub session_id: String,
    pub account_id: String,
    /// The device this session is bound to — sessions must not float
    /// between endpoints.
    pub device_id: String,
    pub state: AccountSessionState,
    pub issued_unix: i64,
    pub expires_unix: i64,
}

impl AccountSession {
    /// Effective state at `now`: an Active session past expiry reports Expired.
    pub fn state_at(&self, now: i64) -> AccountSessionState {
        match self.state {
            AccountSessionState::Active if now >= self.expires_unix => {
                AccountSessionState::Expired
            }
            s => s,
        }
    }
}

/// In-memory session book; persistence behind a repository interface later.
#[derive(Default)]
pub struct SessionBook {
    sessions: BTreeMap<String, AccountSession>,
}

impl SessionBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(
        &mut self,
        session_id: impl Into<String>,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        now: i64,
        ttl_secs: u64,
    ) -> AccountSession {
        let s = AccountSession {
            session_id: session_id.into(),
            account_id: account_id.into(),
            device_id: device_id.into(),
            state: AccountSessionState::Active,
            issued_unix: now,
            expires_unix: now + ttl_secs as i64,
        };
        self.sessions.insert(s.session_id.clone(), s.clone());
        s
    }

    pub fn revoke(&mut self, session_id: &str) -> bool {
        match self.sessions.get_mut(session_id) {
            Some(s) => {
                s.state = AccountSessionState::Revoked;
                true
            }
            None => false,
        }
    }

    /// Valid = exists, Active, bound to `device_id`, and unexpired at `now`.
    pub fn is_valid(&self, session_id: &str, device_id: &str, now: i64) -> bool {
        self.sessions.get(session_id).is_some_and(|s| {
            s.device_id == device_id && s.state_at(now) == AccountSessionState::Active
        })
    }

    /// Revoke every session bound to a device — used on device revocation
    /// and lock events so a stolen device cannot keep live sessions.
    pub fn revoke_all_for_device(&mut self, device_id: &str) -> usize {
        let mut n = 0;
        for s in self.sessions.values_mut() {
            if s.device_id == device_id && s.state == AccountSessionState::Active {
                s.state = AccountSessionState::Revoked;
                n += 1;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_validity_requires_active_unexpired_bound_device() {
        let mut b = SessionBook::new();
        b.issue("s1", "acct1", "dev1", 1000, 600);
        assert!(b.is_valid("s1", "dev1", 1200));
        assert!(!b.is_valid("s1", "dev1", 1601), "expired");
        assert!(!b.is_valid("s1", "dev2", 1200), "wrong device");
        assert!(!b.is_valid("nope", "dev1", 1200), "unknown");
    }

    #[test]
    fn revoke_terminates_session() {
        let mut b = SessionBook::new();
        b.issue("s1", "acct1", "dev1", 1000, 600);
        assert!(b.revoke("s1"));
        assert!(!b.is_valid("s1", "dev1", 1100));
    }

    #[test]
    fn device_revocation_kills_all_its_sessions() {
        let mut b = SessionBook::new();
        b.issue("s1", "acct1", "dev1", 1000, 600);
        b.issue("s2", "acct1", "dev1", 1000, 600);
        b.issue("s3", "acct1", "dev2", 1000, 600);
        assert_eq!(b.revoke_all_for_device("dev1"), 2);
        assert!(!b.is_valid("s1", "dev1", 1100));
        assert!(b.is_valid("s3", "dev2", 1100));
    }
}
