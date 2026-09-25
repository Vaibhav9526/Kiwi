//! Wire views for the OAuth2 acquisition commands (T-230,
//! `kiwi.oauth2/1` + ipc.md §9f). No view ever carries token material,
//! the PKCE verifier, or the device code — `credentialKey` is a key
//! *name* in the OS credential store, not a secret.

use serde::Serialize;

/// OAuth2 provider spec carried on a discovery suggestion (ipc.md §5):
/// present when the suggestion's endpoints are ones a shipped provider
/// config can mint tokens for. `provider` feeds `kiwi_oauth2_begin`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2SpecView {
    /// `ProviderConfig::by_id` id — `"google"` | `"microsoft"`.
    pub provider: String,
    /// Grant shape `begin` will produce: `"loopback_code" | "device_code"`.
    pub grant: String,
}

/// `kiwi_oauth2_begin` result — the ticket + whatever the user must see.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2BeginView {
    /// Opaque grant handle for `kiwi_oauth2_poll` / `kiwi_oauth2_cancel`
    /// and the `oauth2Ticket` field of `kiwi_add_account`'s auth input.
    pub ticket_id: String,
    /// `"loopback_code"` (open `authorizeUrl` in the system browser) or
    /// `"device_code"` (display `userCode` + `verificationUri`).
    pub kind: String,
    /// Browser URL to open (loopback grants only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    /// Short code the user types at `verificationUri` (device grants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    /// Page the user opens to approve (device grants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri: Option<String>,
    /// Pre-filled approval URL when the provider supplies one (device).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Grant deadline (unix seconds) — the UI's outer bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    /// Suggested poll cadence (device grants; RFC 8628 `interval`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u64>,
}

/// `kiwi_oauth2_poll` result — a grant state, not an IPC error. Terminal
/// failures (denied / expired / endpoint reject) arrive as
/// `status: "error"` so the wizard can render them; transient transport
/// failures still surface as IPC errors (the grant stays alive).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2PollView {
    /// `"pending"` | `"complete"` | `"error"`.
    pub status: String,
    pub ticket_id: String,
    /// Seconds to wait before the next poll (device grants: interval or
    /// the `slow_down` backoff; loopback: a fixed UI hint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Provider id — set once the grant completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Email the grant was bound to — set on complete when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Credential-store key the `TokenSet` was persisted under — set on
    /// complete when the email was known at `begin`. A key *name*, not a
    /// secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_key: Option<String>,
    /// Stable error code when `status == "error"` (§11 vocabulary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Sanitized human detail — never secret material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// `kiwi_oauth2_status` result — what a stored account's OAuth2 posture
/// looks like without revealing token material.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2StatusView {
    pub account_id: String,
    /// `"xoauth2"` | `"password"` | `"apop"` | `"none"` (incoming side).
    pub auth_method: String,
    /// Provider id when the account's credential key is an
    /// `oauth2/<provider>/<email>` grant key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Account email parsed from the grant key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// A credential exists at the account's key (any auth kind).
    pub credential_present: bool,
    /// Access-token expiry when a parseable `TokenSet` is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    /// True when the stored token is inside (or past) the refresh window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_refresh: Option<bool>,
    /// True when the stored grant carries a refresh token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_refresh_token: Option<bool>,
}

/// `kiwi_oauth2_cancel` result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2CancelView {
    pub cancelled: bool,
}
