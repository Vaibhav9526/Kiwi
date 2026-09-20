//! Stage 5 — manual entry: the always-available fallback.
//!
//! Discovery never fails to return a usable suggestion: when every
//! network stage misses, the caller still gets a fully-formed
//! [`ManualEntry`] pre-seeded with the email address and a placeholder
//! host pair that the user must review. Nothing here is asserted as
//! correct — `source = manual` + `needs_manual_review = true`.

use crate::suggest::{
    AccountSuggestion, AuthKind, IncomingKind, IncomingSuggestion, OutgoingSuggestion,
    SuggestionSource,
};
use kiwi_mail::transport::SocketSecurity;

/// User-editable account fields (exactly the subset the app UI exposes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManualEntry {
    /// IMAP or POP3.
    pub incoming_kind: IncomingKind,
    /// Incoming host.
    pub incoming_host: String,
    /// Incoming port.
    pub incoming_port: u16,
    /// Incoming socket security.
    pub incoming_security: SocketSecurity,
    /// Incoming credential kind.
    pub incoming_auth: AuthKind,
    /// SMTP submission host.
    pub outgoing_host: String,
    /// SMTP submission port.
    pub outgoing_port: u16,
    /// Outgoing socket security.
    pub outgoing_security: SocketSecurity,
    /// Outgoing credential kind.
    pub outgoing_auth: AuthKind,
    /// Login name for both servers (empty = use the email address).
    pub username: String,
}

impl ManualEntry {
    /// Blank entry seeded from an address: `imap.<domain>:993` and
    /// `smtp.<domain>:587`, password auth, username = address. Placeholder
    /// values only — the user edits them.
    #[must_use]
    pub fn blank(email: &str) -> Self {
        let domain = crate::split_email(email)
            .map(|(_, d)| d.as_str().to_string())
            .unwrap_or_else(|_| "example.invalid".to_string());
        Self {
            incoming_kind: IncomingKind::Imap,
            incoming_host: format!("imap.{domain}"),
            incoming_port: 993,
            incoming_security: SocketSecurity::ImplicitTls,
            incoming_auth: AuthKind::Password,
            outgoing_host: format!("smtp.{domain}"),
            outgoing_port: 587,
            outgoing_security: SocketSecurity::StartTls,
            outgoing_auth: AuthKind::Password,
            username: String::new(),
        }
    }

    /// Pre-fill an editor from a discovered suggestion (user then edits).
    #[must_use]
    pub fn from_suggestion(s: &AccountSuggestion) -> Self {
        Self {
            incoming_kind: s.incoming.kind,
            incoming_host: s.incoming.host.clone(),
            incoming_port: s.incoming.port,
            incoming_security: s.incoming.security,
            incoming_auth: s.incoming.auth,
            outgoing_host: s.outgoing.host.clone(),
            outgoing_port: s.outgoing.port,
            outgoing_security: s.outgoing.security,
            outgoing_auth: s.outgoing.auth,
            username: s.incoming.username.clone(),
        }
    }

    /// Override the incoming endpoint.
    #[must_use]
    pub fn with_incoming(mut self, host: &str, port: u16, security: SocketSecurity) -> Self {
        self.incoming_host = host.to_string();
        self.incoming_port = port;
        self.incoming_security = security;
        self
    }

    /// Override the outgoing endpoint.
    #[must_use]
    pub fn with_outgoing(mut self, host: &str, port: u16, security: SocketSecurity) -> Self {
        self.outgoing_host = host.to_string();
        self.outgoing_port = port;
        self.outgoing_security = security;
        self
    }

    /// Validate into an [`AccountSuggestion`] (`source = manual`).
    /// `None` when host/port/username fail bounds — the UI must fix them.
    #[must_use]
    pub fn to_suggestion(&self, email: &str) -> Option<AccountSuggestion> {
        let (local, domain) = crate::split_email(email).ok()?;
        let username = if self.username.trim().is_empty() {
            format!("{local}@{}", domain.as_str())
        } else {
            self.username.trim().to_string()
        };
        AccountSuggestion {
            source: SuggestionSource::Manual,
            email: format!("{local}@{}", domain.as_str()),
            display_name: local,
            incoming: IncomingSuggestion {
                kind: self.incoming_kind,
                host: self.incoming_host.trim().to_string(),
                port: self.incoming_port,
                security: self.incoming_security,
                auth: self.incoming_auth,
                username: username.clone(),
            },
            outgoing: OutgoingSuggestion {
                host: self.outgoing_host.trim().to_string(),
                port: self.outgoing_port,
                security: self.outgoing_security,
                auth: self.outgoing_auth,
                username,
            },
        }
        .checked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::{IncomingKind, SuggestionSource};

    #[test]
    fn blank_entry_is_placeholder_with_placeholders() {
        let m = ManualEntry::blank("u@selfhosted.test");
        assert_eq!(m.incoming_host, "imap.selfhosted.test");
        assert_eq!(m.incoming_port, 993);
        assert_eq!(m.incoming_security, SocketSecurity::ImplicitTls);
        assert_eq!(m.outgoing_host, "smtp.selfhosted.test");
        assert_eq!(m.outgoing_port, 587);
        assert_eq!(m.outgoing_security, SocketSecurity::StartTls);
        assert_eq!(m.incoming_auth, AuthKind::Password);
        assert_eq!(m.username, ""); // empty = use email address
        let s = m.to_suggestion("u@selfhosted.test").unwrap();
        assert_eq!(s.source, SuggestionSource::Manual);
        assert_eq!(s.incoming.username, "u@selfhosted.test");
        // to_mail_account conversion exists via AccountSuggestion — this
        // test only covers the manual fallback shape; pipeline tests in
        // discovery.rs cover the full mapping.
        let _ = s;
    }

    #[test]
    fn blank_entry_handles_invalid_email_domain() {
        // Manual fallback must never panic on a bad address.
        let m = ManualEntry::blank("not-an-email");
        assert_eq!(m.incoming_host, "imap.example.invalid");
    }

    #[test]
    fn edits_apply_and_validate() {
        let m = ManualEntry::blank("u@x.test")
            .with_incoming("mail.corp.test", 143, SocketSecurity::StartTls)
            .with_outgoing("relay.corp.test", 25, SocketSecurity::Plaintext);
        let s = m.to_suggestion("u@x.test").unwrap();
        assert_eq!(s.incoming.host, "mail.corp.test");
        assert_eq!(s.incoming.port, 143);
        assert_eq!(s.incoming.security, SocketSecurity::StartTls);
        assert_eq!(s.outgoing.host, "relay.corp.test");
        assert_eq!(s.outgoing.security, SocketSecurity::Plaintext);
        assert_eq!(s.incoming.kind, IncomingKind::Imap);
        // Custom username sticks.
        let m2 = ManualEntry {
            username: "  login@corp.test  ".into(),
            ..m
        };
        let s2 = m2.to_suggestion("u@x.test").unwrap();
        assert_eq!(s2.incoming.username, "login@corp.test");
        assert_eq!(s2.outgoing.username, "login@corp.test");
    }

    #[test]
    fn host_validation_is_enforced() {
        // Empty host / whitespace-only username → checked() rejects.
        let bad = ManualEntry {
            incoming_host: "   ".into(),
            ..ManualEntry::blank("u@x.test")
        };
        assert!(bad.to_suggestion("u@x.test").is_none());
        // Invalid email → None, not panic.
        assert!(
            ManualEntry::blank("u@x.test")
                .to_suggestion("bogus")
                .is_none()
        );
    }

    #[test]
    fn from_suggestion_prefills_fields() {
        let s = crate::ispdb::lookup_email("a@gmail.com").unwrap();
        let m = ManualEntry::from_suggestion(&s);
        assert_eq!(m.incoming_host, "imap.gmail.com");
        assert_eq!(m.incoming_port, 993);
        assert_eq!(m.incoming_auth, AuthKind::XOAuth2);
        // Round-trip: same suggestion re-derived (modulo display name).
        let s2 = m.to_suggestion("a@gmail.com").unwrap();
        assert_eq!(s2.incoming, s.incoming);
        assert_eq!(s2.outgoing, s.outgoing);
    }
}
