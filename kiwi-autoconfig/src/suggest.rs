//! Output shape: one suggestion per stage, mapping 1:1 onto
//! `kiwi_mail::account` structs. No secrets anywhere — `username` is the
//! login name (usually the full email); credential keys are derived by the
//! app layer, never here.

use kiwi_mail::account::{AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig};
use kiwi_mail::transport::SocketSecurity;

/// How the account authenticates — carries no secret material, only which
/// credential kind the server expects (`AuthRef` selects the store key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// USER/PASS-style password (incl. CRAM-MD5 / app-password servers).
    Password,
    /// OAuth2/XOAUTH2 bearer token (Gmail, Microsoft 365).
    XOAuth2,
}

impl AuthKind {
    /// Stable wire spelling (autoconfig XML vocabulary).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::XOAuth2 => "oauth2",
        }
    }
}

/// Which incoming protocol a suggestion uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncomingKind {
    /// IMAP (preferred whenever offered).
    Imap,
    /// POP3.
    Pop3,
}

impl IncomingKind {
    /// Stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
        }
    }
}

/// Where a suggestion came from (first hit wins in [`crate::discover`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionSource {
    /// Local ISPDB-style fixture table.
    Ispdb,
    /// `autoconfig.<domain>` HTTPS document.
    AutoconfigHost,
    /// `<domain>/.well-known/autoconfig` HTTPS document.
    WellKnown,
    /// MX-derived provider/pattern guess.
    MxHeuristic,
    /// Caller-supplied / user-typed fallback.
    Manual,
}

impl SuggestionSource {
    /// Stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ispdb => "ispdb",
            Self::AutoconfigHost => "autoconfig_host",
            Self::WellKnown => "well_known",
            Self::MxHeuristic => "mx_heuristic",
            Self::Manual => "manual",
        }
    }
}

/// Incoming server suggestion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IncomingSuggestion {
    /// IMAP or POP3.
    pub kind: IncomingKind,
    /// Server hostname (validated, ≤253 chars).
    pub host: String,
    /// Server port (validated sane: 1..=65535, well-known-checked).
    pub port: u16,
    /// Socket security.
    pub security: SocketSecurity,
    /// Credential kind the server expects.
    pub auth: AuthKind,
    /// Login name (usually the full email address).
    pub username: String,
}

/// Outgoing (SMTP submission) suggestion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OutgoingSuggestion {
    /// Server hostname.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Socket security.
    pub security: SocketSecurity,
    /// Credential kind the server expects.
    pub auth: AuthKind,
    /// Login name.
    pub username: String,
}

/// One complete account suggestion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountSuggestion {
    /// Where it came from.
    pub source: SuggestionSource,
    /// Email address it was derived for.
    pub email: String,
    /// Display name seed (local part; app may let the user edit).
    pub display_name: String,
    /// Incoming server.
    pub incoming: IncomingSuggestion,
    /// Outgoing server.
    pub outgoing: OutgoingSuggestion,
}

impl AccountSuggestion {
    /// Validate + normalize a candidate (host/port/username bounds,
    /// security-vs-port sanity). Returns `None` when unusable — callers
    /// skip to the next stage instead of failing.
    #[must_use]
    pub fn checked(mut self) -> Option<Self> {
        self.incoming.host = crate::DomainName::parse(&self.incoming.host).ok()?.as_str().to_string();
        self.outgoing.host = crate::DomainName::parse(&self.outgoing.host).ok()?.as_str().to_string();
        if self.incoming.port == 0 || self.outgoing.port == 0 {
            return None;
        }
        if self.incoming.username.is_empty()
            || self.incoming.username.len() > 256
            || self.outgoing.username.is_empty()
            || self.outgoing.username.len() > 256
        {
            return None;
        }
        // Port/security sanity (warn-level mismatch still accepted except
        // for plaintext on a TLS-only well-known port).
        if self.incoming.security == SocketSecurity::Plaintext
            && matches!(self.incoming.port, 993 | 995)
        {
            return None;
        }
        if self.outgoing.security == SocketSecurity::Plaintext
            && matches!(self.outgoing.port, 465)
        {
            return None;
        }
        Some(self)
    }

    /// Map onto the `kiwi-mail` account shape. `account_id` and
    /// `credential_key`s are derived deterministically from the email
    /// (app layer binds them to the OS keystore; no secrets here).
    #[must_use]
    pub fn to_mail_account(&self) -> MailAccount {
        let stem = self.email.trim().to_ascii_lowercase();
        let incoming = IncomingAccount {
            protocol: match self.incoming.kind {
                IncomingKind::Imap => IncomingProtocol::Imap,
                IncomingKind::Pop3 => IncomingProtocol::Pop3,
            },
            server: ServerConfig {
                host: self.incoming.host.clone(),
                port: self.incoming.port,
                security: self.incoming.security,
            },
            auth: match self.incoming.auth {
                AuthKind::Password => AuthRef::Password { credential_key: format!("autoconfig/{stem}/incoming") },
                AuthKind::XOAuth2 => AuthRef::XOAuth2 { credential_key: format!("autoconfig/{stem}/incoming") },
            },
            username: self.incoming.username.clone(),
        };
        let outgoing = OutgoingAccount {
            server: ServerConfig {
                host: self.outgoing.host.clone(),
                port: self.outgoing.port,
                security: self.outgoing.security,
            },
            auth: match self.outgoing.auth {
                AuthKind::Password => AuthRef::Password { credential_key: format!("autoconfig/{stem}/outgoing") },
                AuthKind::XOAuth2 => AuthRef::XOAuth2 { credential_key: format!("autoconfig/{stem}/outgoing") },
            },
            username: self.outgoing.username.clone(),
        };
        MailAccount {
            account_id: format!("autoconfig:{stem}"),
            display_name: self.display_name.clone(),
            email: self.email.clone(),
            incoming,
            outgoing,
        }
    }
}
