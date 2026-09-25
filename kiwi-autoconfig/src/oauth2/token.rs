//! `TokenSet` — the OAuth token lifecycle model.
//!
//! Holds access token + optional refresh token + absolute expiry. Secrets
//! are `Zeroizing` and redacted from `Debug`. Persistence goes through the
//! `CredentialStore` seam as a versioned JSON blob ([`TokenSet::to_blob`]);
//! the blob is a *secret-bearing serialization* — it is never a DB row,
//! never a log line, never a plaintext file (contract §5).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{EXPIRY_SKEW_SECS, MAX_TOKEN_FIELD, OAuthError};

/// A completed OAuth2 grant: bearer token + refresh material + expiry.
///
/// Constructed only from validated token-endpoint responses
/// ([`TokenSet::from_response`]) or a stored blob ([`TokenSet::from_blob`]).
/// Secret fields are private — use the `&str` accessors; `Debug` shows
/// metadata only.
pub struct TokenSet {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    expires_at_unix: Option<i64>,
    token_type: String,
    scope: Option<String>,
}

/// Wire shape of `POST /token` and `/devicecode`→poll success responses.
/// Unknown fields (`id_token`, `ext_expires_in`, …) are ignored by design.
#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

/// Secret-bearing persistence shape — the JSON written to
/// `CredentialStore`. `v` pins the blob format for forward-compat.
#[derive(Serialize, Deserialize)]
struct TokenBlob {
    v: u32,
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<i64>,
    token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Blob schema version.
const BLOB_VERSION: u32 = 1;

/// Upper bound on `expires_in` honoured from a provider (1 year — any
/// larger value is a bug or hostile and is clamped, not trusted).
const MAX_EXPIRES_IN: i64 = 31_536_000;

impl TokenSet {
    /// Direct constructor for tests / hand-built sets. Field validation
    /// matches [`TokenSet::from_response`]; prefer that for wire input.
    pub fn bearer(
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at_unix: Option<i64>,
        scope: Option<&str>,
    ) -> Result<Self, OAuthError> {
        check_token_field("access_token", access_token)?;
        if let Some(rt) = refresh_token {
            check_token_field("refresh_token", rt)?;
        }
        let scope = scope.filter(|s| !s.is_empty());
        if let Some(sc) = scope {
            check_len("scope", sc)?;
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token.to_string()),
            refresh_token: refresh_token.map(|r| Zeroizing::new(r.to_string())),
            expires_at_unix,
            token_type: "Bearer".to_string(),
            scope: scope.map(str::to_string),
        })
    }

    /// Validate + convert a token-endpoint response body. `now_unix` turns
    /// relative `expires_in` into an absolute expiry.
    pub(crate) fn from_response(body: &[u8], now_unix: i64) -> Result<Self, OAuthError> {
        let resp: TokenResponse =
            serde_json::from_slice(body).map_err(|_| OAuthError::Malformed("token json"))?;
        let access = resp
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or(OAuthError::Malformed("access_token"))?;
        check_token_field("access_token", &access)?;
        if let Some(rt) = &resp.refresh_token {
            check_token_field("refresh_token", rt)?;
        }
        let scope = resp.scope.filter(|s| !s.is_empty());
        if let Some(sc) = &scope {
            check_len("scope", sc)?;
        }
        let token_type = resp.token_type.unwrap_or_else(|| "Bearer".to_string());
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(OAuthError::Malformed("token_type"));
        }
        let expires_at_unix = resp.expires_in.map(|secs| {
            let clamped = secs.clamp(0, MAX_EXPIRES_IN);
            now_unix.saturating_add(clamped)
        });
        Ok(Self {
            access_token: Zeroizing::new(access),
            refresh_token: resp.refresh_token.map(Zeroizing::new),
            expires_at_unix,
            token_type: "Bearer".to_string(),
            scope,
        })
    }

    /// Bearer token for SASL XOAUTH2 (`auth=Bearer <token>`) construction.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Refresh token, if the provider issued one. Absence means the grant
    /// cannot be refreshed — re-authorization is required on expiry.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref().map(|z| z.as_str())
    }

    /// Absolute access-token expiry (unix seconds), if the provider set one.
    #[must_use]
    pub fn expires_at_unix(&self) -> Option<i64> {
        self.expires_at_unix
    }

    /// Granted scope string (provider-echoed), if any.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Keep an existing refresh token when a refresh response omits one
    /// (Google semantics — old refresh token remains valid).
    pub(crate) fn set_refresh_token(&mut self, refresh_token: Option<&str>) {
        if let Some(rt) = refresh_token {
            self.refresh_token = Some(Zeroizing::new(rt.to_string()));
        }
    }

    /// `true` when the access token is expired or inside
    /// [`EXPIRY_SKEW_SECS`] of expiry — i.e. `refresh()` should run before
    /// connecting. `false` when no expiry was recorded.
    #[must_use]
    pub fn needs_refresh(&self, now_unix: i64) -> bool {
        match self.expires_at_unix {
            Some(exp) => now_unix >= exp - EXPIRY_SKEW_SECS,
            None => false,
        }
    }

    /// Serialize for the `CredentialStore` seam. Output is secret-bearing —
    /// pass straight to `store.set()`, never to a log/DB/file.
    #[must_use]
    pub fn to_blob(&self) -> String {
        let blob = TokenBlob {
            v: BLOB_VERSION,
            access_token: self.access_token.to_string(),
            refresh_token: self.refresh_token.as_ref().map(|z| z.to_string()),
            expires_at_unix: self.expires_at_unix,
            token_type: self.token_type.clone(),
            scope: self.scope.clone(),
        };
        // Serialization of this fully-owned shape cannot fail.
        serde_json::to_string(&blob).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parse a blob from `CredentialStore`. Unknown `v` fails closed —
    /// never silently accept a schema we did not write.
    pub fn from_blob(json: &str) -> Result<Self, OAuthError> {
        let blob: TokenBlob =
            serde_json::from_str(json).map_err(|_| OAuthError::Malformed("token blob"))?;
        if blob.v != BLOB_VERSION {
            return Err(OAuthError::Malformed("blob version"));
        }
        Self::bearer(
            &blob.access_token,
            blob.refresh_token.as_deref(),
            blob.expires_at_unix,
            blob.scope.as_deref(),
        )
    }
}

/// Redacted `Debug`: metadata only, never token material.
impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &if self.refresh_token.is_some() {
                    "<redacted>"
                } else {
                    "<absent>"
                },
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Token material: printable ASCII, no whitespace/CTLs, length-bounded.
fn check_token_field(field: &'static str, value: &str) -> Result<(), OAuthError> {
    check_len(field, value)?;
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(OAuthError::Malformed(field));
    }
    Ok(())
}

fn check_len(field: &'static str, value: &str) -> Result<(), OAuthError> {
    if value.is_empty() || value.len() > MAX_TOKEN_FIELD {
        return Err(OAuthError::Malformed(field));
    }
    Ok(())
}
