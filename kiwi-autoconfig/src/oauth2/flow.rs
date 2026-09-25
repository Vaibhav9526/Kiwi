//! `OAuthClient` — the [`OAuthFlow`] implementation, dispatching on the
//! provider's [`GrantKind`]. All endpoint traffic goes through the injected
//! [`OAuthTransport`]; all clock reads arrive as `now_unix` parameters.

use async_trait::async_trait;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::loopback::LoopbackListener;
use super::provider::ProviderConfig;
use super::token::TokenSet;
use super::transport::MAX_TOKEN_BODY;
use super::{
    DEFAULT_POLL_INTERVAL_SECS, DEVICE_CODE_GRANT, DeviceGrant, GrantKind, GrantSecrets,
    LoopbackGrant, OAuthError, OAuthFlow, OAuthTransport, PendingGrant, PollOutcome,
    RedirectOutcome, SLOWDOWN_BACKOFF_SECS, form_encode,
};

/// An OAuth2 client bound to one provider configuration. Construct via
/// [`OAuthClient::google`]/[`OAuthClient::microsoft`] or
/// [`ProviderConfig::by_id`].
pub struct OAuthClient {
    provider: ProviderConfig,
}

impl OAuthClient {
    /// Wrap a provider config. `client_id` is validated at `begin()`.
    #[must_use]
    pub fn new(provider: ProviderConfig) -> Self {
        Self { provider }
    }

    /// Google provider preset (auth-code + loopback + PKCE).
    #[must_use]
    pub fn google(client_id: &str) -> Self {
        Self::new(ProviderConfig::google(client_id))
    }

    /// Microsoft provider preset on the `common` tenant (device code).
    #[must_use]
    pub fn microsoft(client_id: &str) -> Self {
        Self::new(ProviderConfig::microsoft(client_id))
    }

    /// The bound provider configuration.
    #[must_use]
    pub fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    fn begin_loopback(&self, secrets: Option<&GrantSecrets>) -> Result<PendingGrant, OAuthError> {
        let owned;
        let secrets = match secrets {
            Some(s) => s,
            None => {
                owned = GrantSecrets::generate()?;
                &owned
            }
        };
        let listener = LoopbackListener::bind()?;
        let redirect_uri = listener.redirect_uri();
        let authorize_url = self.authorize_url(&redirect_uri, secrets);
        Ok(PendingGrant::Loopback(LoopbackGrant {
            authorize_url,
            redirect_uri,
            state: secrets.state.clone(),
            code_verifier: Zeroizing::new(secrets.code_verifier.to_string()),
            listener,
        }))
    }

    fn authorize_url(&self, redirect_uri: &str, secrets: &GrantSecrets) -> String {
        let base = self.provider.authorize_url.as_deref().unwrap_or_default();
        let scope = self.provider.scope_param();
        let mut pairs: Vec<(&str, &str)> = vec![
            ("client_id", &self.provider.client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", &scope),
            ("state", &secrets.state),
            ("code_challenge", &secrets.code_challenge),
            ("code_challenge_method", "S256"),
        ];
        for (k, v) in &self.provider.authorize_extra {
            pairs.push((k.as_str(), v.as_str()));
        }
        format!("{base}?{}", form_encode(&pairs))
    }

    async fn begin_device(
        &self,
        http: &dyn OAuthTransport,
        now_unix: i64,
    ) -> Result<PendingGrant, OAuthError> {
        let url = self
            .provider
            .device_code_url
            .as_deref()
            .ok_or(OAuthError::InvalidConfig("device_code_url"))?;
        let reply = http
            .post_form(
                url,
                &[
                    ("client_id", self.provider.client_id.as_str()),
                    ("scope", self.provider.scope_param().as_str()),
                ],
            )
            .await?;
        if !(200..300).contains(&reply.status) {
            return Err(endpoint_error(&reply));
        }
        let resp: DeviceCodeResponse = serde_json::from_slice(&reply.body)
            .map_err(|_| OAuthError::Malformed("device code json"))?;
        let device_code = resp
            .device_code
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::Malformed("device_code"))?;
        if device_code.len() > super::MAX_TOKEN_FIELD
            || !device_code.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(OAuthError::Malformed("device_code"));
        }
        let user_code = resp
            .user_code
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .ok_or(OAuthError::Malformed("user_code"))?;
        let verification_uri = resp
            .verification_uri
            .filter(|s| s.starts_with("https://") && s.len() <= 1024)
            .ok_or(OAuthError::Malformed("verification_uri"))?;
        let expires_in = resp
            .expires_in
            .filter(|e| *e > 0)
            .ok_or(OAuthError::Malformed("expires_in"))?;
        Ok(PendingGrant::Device(DeviceGrant {
            device_code: Zeroizing::new(device_code),
            user_code,
            verification_uri,
            verification_uri_complete: resp
                .verification_uri_complete
                .filter(|s| s.starts_with("https://") && s.len() <= 1024),
            expires_at_unix: now_unix.saturating_add(expires_in.min(31_536_000)),
            poll_interval_secs: resp
                .interval
                .filter(|i| *i > 0 && *i <= 300)
                .unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
        }))
    }
}

#[async_trait]
impl OAuthFlow for OAuthClient {
    fn provider_id(&self) -> &str {
        self.provider.id
    }

    fn grant_kind(&self) -> GrantKind {
        self.provider.grant_kind
    }

    async fn begin(
        &self,
        http: &dyn OAuthTransport,
        now_unix: i64,
    ) -> Result<PendingGrant, OAuthError> {
        self.begin_with(http, None, now_unix).await
    }

    async fn begin_with(
        &self,
        http: &dyn OAuthTransport,
        secrets: Option<&GrantSecrets>,
        now_unix: i64,
    ) -> Result<PendingGrant, OAuthError> {
        self.provider.check_client_id()?;
        match self.provider.grant_kind {
            GrantKind::LoopbackCode => self.begin_loopback(secrets),
            GrantKind::DeviceCode => self.begin_device(http, now_unix).await,
        }
    }

    async fn exchange(
        &self,
        http: &dyn OAuthTransport,
        grant: &PendingGrant,
        redirect: &RedirectOutcome,
        now_unix: i64,
    ) -> Result<TokenSet, OAuthError> {
        let PendingGrant::Loopback(g) = grant else {
            return Err(OAuthError::UnsupportedGrant {
                expected: GrantKind::LoopbackCode,
            });
        };
        // Provider signalled failure on the redirect (e.g. user cancelled).
        if let Some(err) = &redirect.error {
            return Err(map_error_code(err, redirect.error_description.as_deref()));
        }
        // CSRF guard — checked before any network call.
        match (&redirect.state, g.state.as_str()) {
            (Some(echoed), want) if echoed == want => {}
            _ => return Err(OAuthError::StateMismatch),
        }
        let code = redirect
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or(OAuthError::Malformed("code"))?;
        let reply = http
            .post_form(
                &self.provider.token_url,
                &[
                    ("client_id", self.provider.client_id.as_str()),
                    ("code", code),
                    ("redirect_uri", g.redirect_uri.as_str()),
                    ("grant_type", "authorization_code"),
                    ("code_verifier", g.code_verifier.as_str()),
                ],
            )
            .await?;
        token_reply(reply, now_unix)
    }

    async fn poll(
        &self,
        http: &dyn OAuthTransport,
        grant: &PendingGrant,
        now_unix: i64,
    ) -> Result<PollOutcome, OAuthError> {
        let PendingGrant::Device(g) = grant else {
            return Err(OAuthError::UnsupportedGrant {
                expected: GrantKind::DeviceCode,
            });
        };
        if now_unix >= g.expires_at_unix {
            return Err(OAuthError::Expired);
        }
        let reply = http
            .post_form(
                &self.provider.token_url,
                &[
                    ("grant_type", DEVICE_CODE_GRANT),
                    ("client_id", self.provider.client_id.as_str()),
                    ("device_code", g.device_code.as_str()),
                ],
            )
            .await?;
        if (200..300).contains(&reply.status) {
            return Ok(PollOutcome::Complete(TokenSet::from_response(
                &reply.body,
                now_unix,
            )?));
        }
        match parse_error(&reply) {
            Some(payload) => match payload.error.as_str() {
                "authorization_pending" => Ok(PollOutcome::Pending),
                "slow_down" => Ok(PollOutcome::SlowDown {
                    retry_after_secs: g.poll_interval_secs + SLOWDOWN_BACKOFF_SECS,
                }),
                _ => Err(map_error_code(
                    &payload.error,
                    payload.error_description.as_deref(),
                )),
            },
            None => Err(OAuthError::Http { status: reply.status }),
        }
    }

    async fn refresh(
        &self,
        http: &dyn OAuthTransport,
        tokens: &TokenSet,
        now_unix: i64,
    ) -> Result<TokenSet, OAuthError> {
        let refresh_token = tokens
            .refresh_token()
            .ok_or(OAuthError::InvalidGrant)?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.provider.client_id.as_str()),
            ("refresh_token", refresh_token),
        ];
        // RFC 6749 §6: scope is optional and must not widen the grant.
        if let Some(scope) = tokens.scope() {
            form.push(("scope", scope));
        }
        let reply = http.post_form(&self.provider.token_url, &form).await?;
        let mut fresh = token_reply(reply, now_unix)?;
        // Provider did not rotate the refresh token (Google semantics) —
        // keep the existing one so the grant stays renewable.
        if fresh.refresh_token().is_none() {
            fresh.set_refresh_token(tokens.refresh_token());
        }
        Ok(fresh)
    }
}

/// `/devicecode` response shape (RFC 8628 §3.2 + Microsoft
/// `verification_uri_complete`). Unknown fields ignored.
#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    expires_in: Option<i64>,
    interval: Option<u64>,
}

/// OAuth error payload (`error`, `error_description`) — bounded strings.
#[derive(Deserialize)]
struct ErrorPayload {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Parse a token-endpoint response: 2xx → validated [`TokenSet`], else the
/// mapped endpoint/HTTP error.
fn token_reply(reply: super::TransportReply, now_unix: i64) -> Result<TokenSet, OAuthError> {
    if (200..300).contains(&reply.status) {
        TokenSet::from_response(&reply.body, now_unix)
    } else {
        Err(endpoint_error(&reply))
    }
}

/// Map a non-2xx reply: OAuth error payload when parseable, else bare
/// `Http{status}`.
fn endpoint_error(reply: &super::TransportReply) -> OAuthError {
    match parse_error(reply) {
        Some(p) => map_error_code(&p.error, p.error_description.as_deref()),
        None => OAuthError::Http { status: reply.status },
    }
}

fn parse_error(reply: &super::TransportReply) -> Option<ErrorPayload> {
    if reply.body.len() > MAX_TOKEN_BODY {
        return None;
    }
    serde_json::from_slice(&reply.body)
        .ok()
        .map(|mut p: ErrorPayload| {
            p.error = p.error.chars().take(128).collect();
            p.error_description = p
                .error_description
                .map(|d| d.chars().take(256).collect());
            p
        })
}

/// RFC 6749/8628 error vocabulary → dedicated variants; anything else is a
/// bounded `Endpoint` error. Never carries secret material.
fn map_error_code(code: &str, description: Option<&str>) -> OAuthError {
    let description = description.map(|d| d.chars().take(256).collect());
    match code {
        "access_denied" | "authorization_declined" => OAuthError::Denied,
        "expired_token" => OAuthError::Expired,
        "invalid_grant" | "bad_verification_code" => OAuthError::InvalidGrant,
        other => OAuthError::Endpoint {
            error: other.chars().take(128).collect(),
            description,
        },
    }
}
