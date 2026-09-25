//! OAuth2 token acquisition for XOAUTH2 providers (T-195).
//!
//! Contract `docs/contracts/oauth2.md` (`kiwi.oauth2/1`) is authoritative.
//! Two grant shapes are supported, per provider policy:
//!
//! - **Authorization code + loopback redirect + PKCE** (RFC 8252 / RFC 7636)
//!   — Google. [`OAuthClient::begin`] binds a `127.0.0.1` listener, returns a
//!   [`PendingGrant::Loopback`] carrying the `authorize_url` for the system
//!   browser; [`OAuthClient::exchange`] redeems the captured redirect.
//! - **Device code** (RFC 8628) — Microsoft. `begin` POSTs the device-code
//!   endpoint; `poll` advances `authorization_pending → slow_down →
//!   complete/denied/expired`.
//!
//! Token lifecycle: [`OAuthClient::refresh`] rotates/preserves refresh
//! tokens; [`save_tokens`]/[`load_tokens`]/[`delete_tokens`] serialize a
//! [`TokenSet`] through the `CredentialStore` seam — never a database,
//! never a plaintext file, never a log line (`Debug` impls are redacted).
//!
//! All endpoints are reached through the [`OAuthTransport`] seam — a narrow
//! form-POST contract blanket-implemented for every
//! `kiwi_integrations::http::HttpClient`, so production uses
//! `ReqwestClient` (reqwest + rustls, HTTPS-only, no redirects, bounded
//! bodies) and tests replay [`kiwi_integrations::http::ScriptedHttp`]
//! fixtures. Nothing in this module opens a socket itself.
//!
//! Time is injected (`now_unix`, seconds since epoch) — the module never
//! reads a wall clock, keeping expiry logic deterministic under test.

mod flow;
mod loopback;
mod pkce;
mod provider;
mod token;
mod transport;

pub use flow::OAuthClient;
pub use loopback::LoopbackListener;
pub use pkce::GrantSecrets;
pub use provider::{KNOWN_PROVIDERS, ProviderConfig};
pub use token::TokenSet;
pub use transport::{
    MAX_TOKEN_BODY, OAuthTransport, TransportReply, form_decode, form_encode, live_transport,
};

use async_trait::async_trait;
use zeroize::Zeroizing;

use kiwi_integrations::{IntegrationError, TransportKind};
use kiwi_mail::account::{AuthRef, CredentialStore};

/// Contract identifier (`docs/contracts/oauth2.md`).
pub const CONTRACT_VERSION: &str = "kiwi.oauth2/1";

/// Expiry safety margin: consumers must refresh when
/// `now >= expires_at_unix - EXPIRY_SKEW_SECS`.
pub const EXPIRY_SKEW_SECS: i64 = 60;

/// Cap on a single token/secret field inside a `TokenSet` (bytes).
pub const MAX_TOKEN_FIELD: usize = 8 * 1024;

/// RFC 8628 device-flow grant type URI.
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Default device-code poll interval when the provider omits `interval`.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Additional wait per RFC 8628 §3.5 `slow_down` signal.
pub const SLOWDOWN_BACKOFF_SECS: u64 = 5;

/// Which grant a provider's `begin()` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// Authorization code + loopback redirect + PKCE (Google).
    LoopbackCode,
    /// Device code (Microsoft).
    DeviceCode,
}

impl GrantKind {
    /// Wire spelling for contract evidence.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoopbackCode => "loopback_code",
            Self::DeviceCode => "device_code",
        }
    }
}

/// In-flight grant returned by [`OAuthFlow::begin`]. **Not serializable and
/// not `Clone`**: the PKCE verifier, `state`, device code, and bound
/// loopback socket are transient grant secrets — they must not be persisted
/// or logged (the `Debug` impls redact them).
#[derive(Debug)]
pub enum PendingGrant {
    /// Loopback auth-code grant. `listener` holds the bound socket; drop the
    /// grant (or let `exchange` finish) to close it.
    Loopback(LoopbackGrant),
    /// Device-code grant carrying the user-facing code + poll handle.
    Device(DeviceGrant),
}

/// Loopback auth-code branch of [`PendingGrant`].
pub struct LoopbackGrant {
    /// URL the user must open in a browser.
    pub authorize_url: String,
    /// `http://127.0.0.1:{port}` — echoed verbatim in the code exchange.
    pub redirect_uri: String,
    /// CSRF token echoed back by the provider; `exchange` requires a match.
    pub state: String,
    /// PKCE verifier — sent only to the token endpoint at exchange time.
    pub(crate) code_verifier: Zeroizing<String>,
    /// Bound 127.0.0.1 listener; drives [`PendingGrant::wait_for_redirect`].
    pub(crate) listener: LoopbackListener,
}

/// Redacted `Debug` — verifier is grant material, never logged.
impl std::fmt::Debug for LoopbackGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackGrant")
            .field("authorize_url", &self.authorize_url)
            .field("redirect_uri", &self.redirect_uri)
            .field("state", &self.state)
            .field("code_verifier", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Device-code branch of [`PendingGrant`].
pub struct DeviceGrant {
    /// Poll handle — a transient secret; sent only to the token endpoint.
    pub(crate) device_code: Zeroizing<String>,
    /// Code the user types at `verification_uri`.
    pub user_code: String,
    /// Page the user opens to approve access.
    pub verification_uri: String,
    /// Optional provider-supplied URL embedding the code (Microsoft emits one).
    pub verification_uri_complete: Option<String>,
    /// Absolute grant expiry (unix seconds).
    pub expires_at_unix: i64,
    /// Provider-requested poll cadence.
    pub poll_interval_secs: u64,
}

/// Redacted `Debug` — the device code is a poll credential, never logged.
impl std::fmt::Debug for DeviceGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceGrant")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .finish_non_exhaustive()
    }
}

impl PendingGrant {
    /// Which grant shape this is.
    #[must_use]
    pub fn kind(&self) -> GrantKind {
        match self {
            Self::Loopback(_) => GrantKind::LoopbackCode,
            Self::Device(_) => GrantKind::DeviceCode,
        }
    }

    /// Browser URL for auth-code grants (`None` for device grants).
    #[must_use]
    pub fn authorize_url(&self) -> Option<&str> {
        match self {
            Self::Loopback(g) => Some(&g.authorize_url),
            Self::Device(_) => None,
        }
    }

    /// User-facing code for device grants (`None` for loopback grants).
    #[must_use]
    pub fn user_code(&self) -> Option<&str> {
        match self {
            Self::Device(g) => Some(&g.user_code),
            Self::Loopback(_) => None,
        }
    }

    /// Verification page for device grants.
    #[must_use]
    pub fn verification_uri(&self) -> Option<&str> {
        match self {
            Self::Device(g) => Some(&g.verification_uri),
            Self::Loopback(_) => None,
        }
    }

    /// Block until the browser hits the loopback listener (or `timeout`).
    ///
    /// Blocking: callers on async runtimes should use `spawn_blocking` or a
    /// thread. Returns `Err(UnsupportedGrant)` for device grants — they have
    /// no listener.
    pub fn wait_for_redirect(
        &self,
        timeout: std::time::Duration,
    ) -> Result<RedirectOutcome, OAuthError> {
        match self {
            Self::Loopback(g) => g.listener.wait(timeout),
            Self::Device(_) => Err(OAuthError::UnsupportedGrant {
                expected: GrantKind::LoopbackCode,
            }),
        }
    }
}

/// Parsed provider redirect — `code`+`state` on success, `error`(+optional
/// `error_description`) on user denial. Public so apps may also parse a
/// manually pasted redirect URL ([`RedirectOutcome::from_query`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectOutcome {
    /// Authorization code (present on success).
    pub code: Option<String>,
    /// CSRF state echoed by the provider.
    pub state: Option<String>,
    /// OAuth error code (e.g. `access_denied`).
    pub error: Option<String>,
    /// Human-readable error text (bounded, display-only).
    pub error_description: Option<String>,
}

impl RedirectOutcome {
    /// Parse a redirect target: a raw query string (`code=…&state=…`) or a
    /// full URL whose query part is used. Bounded: input over 8 KiB is
    /// rejected.
    pub fn from_query(input: &str) -> Result<Self, OAuthError> {
        if input.len() > loopback::MAX_REQUEST_LINE {
            return Err(OAuthError::Malformed("redirect too long"));
        }
        let query = match input.split_once('?') {
            Some((_, q)) => q.split('#').next().unwrap_or(""),
            None => input.split('#').next().unwrap_or(""),
        };
        let pairs = form_decode(query).map_err(|_| OAuthError::Malformed("redirect query"))?;
        let mut out = Self::default();
        for (k, v) in pairs {
            match k.as_str() {
                "code" => out.code = Some(v),
                "state" => out.state = Some(v),
                "error" => out.error = Some(v),
                "error_description" => {
                    out.error_description = Some(v.chars().take(256).collect());
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Result of one device-code [`OAuthFlow::poll`].
#[derive(Debug)]
pub enum PollOutcome {
    /// `authorization_pending` — user has not finished; keep polling.
    Pending,
    /// `slow_down` — RFC 8628 §3.5: wait `retry_after_secs` before the next
    /// poll (base interval + 5 s; callers SHOULD keep the larger cadence).
    SlowDown {
        /// Seconds to wait before the next poll.
        retry_after_secs: u64,
    },
    /// Grant completed — a full [`TokenSet`].
    Complete(TokenSet),
}

/// Errors from grant acquisition/lifecycle. No variant ever carries token,
/// verifier, device-code, or credential material — transport failures are
/// classified by [`TransportKind`] only (the underlying message embeds the
/// request URL); endpoint error text is length-bounded.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Endpoint URL was not `https://` — refused before any socket opened.
    #[error("refused non-HTTPS URL")]
    InsecureUrl,
    /// Transport failure; classified, never carries URL/provider text.
    #[error("transport failure ({kind:?})")]
    Transport {
        /// Coarse failure class for retry/UI decisions.
        kind: TransportKind,
    },
    /// Response body exceeded the byte cap.
    #[error("response body too large")]
    BodyTooLarge,
    /// Non-2xx status with no parseable OAuth error payload.
    #[error("unexpected HTTP status {status}")]
    Http {
        /// HTTP status code.
        status: u16,
    },
    /// Endpoint returned an OAuth `{error, error_description}` payload not
    /// mapped to a dedicated variant. `error` is the machine code;
    /// `description` is provider text, capped at 256 chars.
    #[error("oauth endpoint error {error}")]
    Endpoint {
        /// OAuth error code (e.g. `temporarily_unavailable`).
        error: String,
        /// Provider-supplied description (bounded).
        description: Option<String>,
    },
    /// User denied access (`access_denied` / `authorization_declined`).
    #[error("user denied authorization")]
    Denied,
    /// Grant or device code expired before completion (`expired_token`,
    /// loopback deadline, or local expiry check).
    #[error("grant expired")]
    Expired,
    /// `invalid_grant` on refresh/exchange — the stored grant is dead; the
    /// account needs interactive re-authorization.
    #[error("grant invalid or revoked — re-authorization required")]
    InvalidGrant,
    /// Redirect `state` did not match the pending grant (CSRF guard).
    #[error("redirect state mismatch")]
    StateMismatch,
    /// Response or redirect did not match the expected shape. Names the
    /// missing/invalid field, never its content.
    #[error("malformed oauth payload: {0}")]
    Malformed(&'static str),
    /// A method was called on the wrong grant shape for this provider.
    #[error("grant kind mismatch — expected {}", expected.as_str())]
    UnsupportedGrant {
        /// The grant kind this provider produces.
        expected: GrantKind,
    },
    /// Loopback listener I/O or wait deadline.
    #[error("loopback listener: {0}")]
    Loopback(String),
    /// Provider/client configuration rejected (client id, tenant, scopes).
    #[error("invalid oauth config: {0}")]
    InvalidConfig(&'static str),
    /// OS credential store failure (error text only — never secret material).
    #[error("credential store: {0}")]
    CredentialStore(String),
    /// CSPRNG failure while minting PKCE/state material.
    #[error("entropy source unavailable")]
    Entropy,
}

impl From<IntegrationError> for OAuthError {
    fn from(e: IntegrationError) -> Self {
        match e {
            IntegrationError::Transport { kind } => Self::Transport { kind },
            IntegrationError::InsecureUrl => Self::InsecureUrl,
            IntegrationError::BodyTooLarge => Self::BodyTooLarge,
            IntegrationError::Http { status } => Self::Http { status },
            _ => Self::Transport {
                kind: TransportKind::Other,
            },
        }
    }
}

/// The acquisition/lifecycle contract every provider implements.
///
/// Method semantics differ by [`GrantKind`]: `exchange` applies only to
/// [`GrantKind::LoopbackCode`], `poll` only to [`GrantKind::DeviceCode`];
/// calling the wrong one returns [`OAuthError::UnsupportedGrant`].
/// `begin_with` is the deterministic seam — `begin` mints fresh entropy.
#[async_trait]
pub trait OAuthFlow: Send + Sync {
    /// Provider id (`"google"`, `"microsoft"`, …) — used in credential keys.
    fn provider_id(&self) -> &str;

    /// The grant kind [`OAuthFlow::begin`] will produce.
    fn grant_kind(&self) -> GrantKind;

    /// Begin a grant with fresh entropy. Equivalent to
    /// `begin_with(http, None, now_unix)`.
    async fn begin(
        &self,
        http: &dyn OAuthTransport,
        now_unix: i64,
    ) -> Result<PendingGrant, OAuthError>;

    /// Begin a grant; `secrets` pins PKCE/state material for tests —
    /// device-code flows ignore it (they mint no client secrets).
    async fn begin_with(
        &self,
        http: &dyn OAuthTransport,
        secrets: Option<&GrantSecrets>,
        now_unix: i64,
    ) -> Result<PendingGrant, OAuthError>;

    /// Redeem a loopback redirect (`code`+`state`) for a [`TokenSet`].
    /// Validates `state` before any network call. `Err(UnsupportedGrant)`
    /// for device-code providers.
    async fn exchange(
        &self,
        http: &dyn OAuthTransport,
        grant: &PendingGrant,
        redirect: &RedirectOutcome,
        now_unix: i64,
    ) -> Result<TokenSet, OAuthError>;

    /// One device-code poll. `Err(UnsupportedGrant)` for auth-code
    /// providers. `Err(Expired)` without a network call once the grant's
    /// `expires_at_unix` has passed.
    async fn poll(
        &self,
        http: &dyn OAuthTransport,
        grant: &PendingGrant,
        now_unix: i64,
    ) -> Result<PollOutcome, OAuthError>;

    /// Exchange the refresh token for a fresh [`TokenSet`]. A rotated
    /// refresh token replaces the old one; a response without one preserves
    /// it (Google semantics). `Err(InvalidGrant)` means the grant is dead —
    /// the account needs interactive re-authorization.
    async fn refresh(
        &self,
        http: &dyn OAuthTransport,
        tokens: &TokenSet,
        now_unix: i64,
    ) -> Result<TokenSet, OAuthError>;
}

// ---------------------------------------------------------------------------
// Credential-store seam (contract §5)
// ---------------------------------------------------------------------------

/// Deterministic credential key for a provider grant:
/// `oauth2/<provider_id>/<lowercased email>`.
#[must_use]
pub fn credential_key(provider_id: &str, email: &str) -> String {
    format!(
        "oauth2/{}/{}",
        provider_id,
        email.trim().to_ascii_lowercase()
    )
}

/// `AuthRef` for both incoming and outgoing sides of a completed grant —
/// one OAuth grant covers IMAP+SMTP, so both share one credential key.
#[must_use]
pub fn auth_ref(provider_id: &str, email: &str) -> AuthRef {
    AuthRef::XOAuth2 {
        credential_key: credential_key(provider_id, email),
    }
}

/// Persist a [`TokenSet`] through the `CredentialStore` seam (OS keystore).
/// This is the ONLY supported persistence path — never a DB row, never a
/// plaintext file (contract §5; SECURITY.md rules 8, 16).
pub fn save_tokens(
    store: &dyn CredentialStore,
    provider_id: &str,
    email: &str,
    tokens: &TokenSet,
) -> Result<(), OAuthError> {
    store
        .set(&credential_key(provider_id, email), &tokens.to_blob())
        .map_err(|e| OAuthError::CredentialStore(e.to_string()))
}

/// Load a persisted [`TokenSet`]; `None` when no grant is stored.
pub fn load_tokens(
    store: &dyn CredentialStore,
    provider_id: &str,
    email: &str,
) -> Result<Option<TokenSet>, OAuthError> {
    let blob = store
        .get(&credential_key(provider_id, email))
        .map_err(|e| OAuthError::CredentialStore(e.to_string()))?;
    blob.map(|b| TokenSet::from_blob(&b)).transpose()
}

/// Remove a persisted grant (account removal / explicit sign-out).
pub fn delete_tokens(
    store: &dyn CredentialStore,
    provider_id: &str,
    email: &str,
) -> Result<(), OAuthError> {
    store
        .delete(&credential_key(provider_id, email))
        .map_err(|e| OAuthError::CredentialStore(e.to_string()))
}

/// The connect-time lifecycle helper: load the stored grant, refresh it if
/// it is inside the expiry skew window, persist any rotated refresh token,
/// and return a usable [`TokenSet`]. `Err(InvalidGrant)` when the grant is
/// dead (re-authorize), `Ok(None)` when no grant exists at all.
pub async fn ensure_fresh(
    http: &dyn OAuthTransport,
    flow: &dyn OAuthFlow,
    store: &dyn CredentialStore,
    email: &str,
    now_unix: i64,
) -> Result<Option<TokenSet>, OAuthError> {
    let Some(tokens) = load_tokens(store, flow.provider_id(), email)? else {
        return Ok(None);
    };
    if !tokens.needs_refresh(now_unix) {
        return Ok(Some(tokens));
    }
    let fresh = flow.refresh(http, &tokens, now_unix).await?;
    save_tokens(store, flow.provider_id(), email, &fresh)?;
    Ok(Some(fresh))
}

#[cfg(test)]
mod tests;
