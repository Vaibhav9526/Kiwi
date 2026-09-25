//! Provider configurations — the fixed, published endpoint facts per
//! OAuth2-capable mail provider. `client_id` is deployment config, never
//! shipped: it arrives from app settings/environment (contract §9).
//!
//! Only public-client shapes exist here: no client secrets anywhere in the
//! model (installed apps cannot hold secrets — PKCE and the device code
//! carry the security).

use super::{GrantKind, OAuthError};
use crate::suggest::{AccountSuggestion, AuthKind};

/// A provider's fixed OAuth2 surface plus the deployment-supplied
/// `client_id`. URLs are owned `String`s because the Microsoft endpoints
/// embed a tenant path segment.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Stable id for credential keys / UI: `"google"`, `"microsoft"`.
    pub id: &'static str,
    /// Human-readable name.
    pub display_name: &'static str,
    /// Which grant `begin()` produces.
    pub grant_kind: GrantKind,
    /// Authorize endpoint (auth-code grants only; `None` for device-code).
    pub authorize_url: Option<String>,
    /// Device-code endpoint (device grants only).
    pub device_code_url: Option<String>,
    /// Token endpoint (exchange, poll, refresh).
    pub token_url: String,
    /// Requested scopes (space-joined on the wire).
    pub scopes: Vec<String>,
    /// Extra authorize-query pairs (Google: `access_type=offline`,
    /// `prompt=consent` so a refresh token is always issued).
    pub authorize_extra: Vec<(String, String)>,
    /// Public client id — supplied at runtime, not a secret.
    pub client_id: String,
}

/// The shipped provider registry. `client_id` is a parameter — the table
/// only carries endpoint facts.
pub const KNOWN_PROVIDERS: &[&str] = &["google", "microsoft"];

impl ProviderConfig {
    /// Google (Gmail/Google Workspace): auth-code + loopback + PKCE.
    ///
    /// Scope `https://mail.google.com/` covers IMAP+SMTP XOAUTH2.
    /// `access_type=offline` + `prompt=consent` guarantees a refresh token
    /// on every interactive grant (re-authorization included).
    #[must_use]
    pub fn google(client_id: &str) -> Self {
        Self {
            id: "google",
            display_name: "Google",
            grant_kind: GrantKind::LoopbackCode,
            authorize_url: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            device_code_url: None,
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            scopes: vec!["https://mail.google.com/".to_string()],
            authorize_extra: vec![
                ("access_type".to_string(), "offline".to_string()),
                ("prompt".to_string(), "consent".to_string()),
            ],
            client_id: client_id.to_string(),
        }
    }

    /// Microsoft 365 / Outlook.com: device-code grant on the `common`
    /// tenant (personal + work/school accounts).
    ///
    /// `offline_access` is required for refresh tokens; the
    /// `outlook.office.com` scopes cover IMAP + SMTP AUTH XOAUTH2.
    #[must_use]
    pub fn microsoft(client_id: &str) -> Self {
        Self::microsoft_tenant(client_id, "common").expect("default tenant is valid")
    }

    /// Microsoft on a specific tenant (GUID or domain form, e.g.
    /// `consumers`, `organizations`, `<tenant>.onmicrosoft.com`).
    /// Tenant is charset-validated — it is interpolated into URL paths.
    pub fn microsoft_tenant(client_id: &str, tenant: &str) -> Result<Self, OAuthError> {
        if tenant.is_empty()
            || tenant.len() > 128
            || !tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(OAuthError::InvalidConfig("tenant"));
        }
        let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
        Ok(Self {
            id: "microsoft",
            display_name: "Microsoft",
            grant_kind: GrantKind::DeviceCode,
            authorize_url: None,
            device_code_url: Some(format!("{base}/devicecode")),
            token_url: format!("{base}/token"),
            scopes: vec![
                "https://outlook.office.com/IMAP.AccessAsUser.All".to_string(),
                "https://outlook.office.com/SMTP.Send".to_string(),
                "offline_access".to_string(),
            ],
            authorize_extra: Vec::new(),
            client_id: client_id.to_string(),
        })
    }

    /// Registry lookup by id. `Err(InvalidConfig("provider"))` for unknown
    /// ids — fail closed, never guess endpoints.
    pub fn by_id(id: &str, client_id: &str) -> Result<Self, OAuthError> {
        match id {
            "google" => Ok(Self::google(client_id)),
            "microsoft" => Ok(Self::microsoft(client_id)),
            _ => Err(OAuthError::InvalidConfig("provider")),
        }
    }

    /// Space-joined scope parameter for form bodies.
    #[must_use]
    pub fn scope_param(&self) -> String {
        self.scopes.join(" ")
    }

    /// Grant kind this provider's `begin()` produces — wire spelling.
    #[must_use]
    pub fn grant_kind_str(&self) -> &'static str {
        self.grant_kind.as_str()
    }

    /// Validate the client id shape (non-empty printable ASCII, bounded).
    /// Runs at `begin()` — the config itself stays lenient so tests can
    /// build arbitrary fixtures.
    pub(crate) fn check_client_id(&self) -> Result<(), OAuthError> {
        let id = &self.client_id;
        if id.is_empty() || id.len() > 256 || !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(OAuthError::InvalidConfig("client_id"));
        }
        Ok(())
    }
}

/// Mail endpoints each shipped provider's tokens are valid for (published
/// hosts — both the ISPDB fixture table and the MX-hint table resolve to
/// these, so a custom-domain Google Workspace / M365 tenant is recognized
/// the same way `user@gmail.com` is).
const PROVIDER_MAIL_HOSTS: &[(&str, &[&str])] = &[
    (
        "google",
        &["imap.gmail.com", "pop.gmail.com", "smtp.gmail.com"],
    ),
    (
        "microsoft",
        &["outlook.office365.com", "smtp.office365.com"],
    ),
];

/// OAuth2 provider id for a discovery suggestion's incoming endpoint —
/// present only when the suggestion needs XOAUTH2 **and** its mail host is
/// one a shipped provider config can mint tokens for. `None` for
/// password-auth suggestions and for XOAUTH2 providers without a client
/// config (Yahoo, AOL — they fail closed in the wizard, not here).
#[must_use]
pub fn provider_id_for_suggestion(s: &AccountSuggestion) -> Option<&'static str> {
    // POP3 can't consume a bearer token (kiwi-mail XOAUTH2 is IMAP+SMTP
    // only) — never offer the wizard a grant it cannot use.
    if s.incoming.auth != AuthKind::XOAuth2
        || !matches!(s.incoming.kind, crate::suggest::IncomingKind::Imap)
    {
        return None;
    }
    let host = s
        .incoming
        .host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    PROVIDER_MAIL_HOSTS
        .iter()
        .find(|(_, hosts)| hosts.contains(&host.as_str()))
        .map(|(id, _)| *id)
}
