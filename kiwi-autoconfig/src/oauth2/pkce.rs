//! PKCE (RFC 7636) + CSRF-state material for the loopback auth-code grant.
//!
//! `S256` is the only supported challenge method — `plain` is never emitted.
//! Generated material comes from the OS CSPRNG (`getrandom`); tests inject
//! fixed secrets via [`GrantSecrets::fixed`] for fully deterministic request
//! bodies.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::OAuthError;

/// Base64url charset (RFC 4648 §5, no padding) — also the PKCE verifier
/// charset.
const UNRESERVED_B64URL: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Byte lengths fed to the CSPRNG: 32 B state → 43 chars, 64 B verifier →
/// 86 chars (inside the RFC 7636 43–128 window).
const STATE_BYTES: usize = 32;
const VERIFIER_BYTES: usize = 64;

/// Per-grant secret material for an auth-code flow: `state` (CSRF) and the
/// PKCE `code_verifier`, plus the derived `code_challenge`
/// (`BASE64URL(SHA-256(verifier))`). Debug never prints the verifier.
#[derive(Debug)]
pub struct GrantSecrets {
    /// CSRF token sent as `state` and checked on redirect.
    pub state: String,
    /// PKCE verifier — sent only to the token endpoint at exchange.
    pub code_verifier: Zeroizing<String>,
    /// `S256` challenge — safe to embed in the authorize URL.
    pub code_challenge: String,
}

impl GrantSecrets {
    /// Mint fresh secrets from the OS CSPRNG.
    pub fn generate() -> Result<Self, OAuthError> {
        let mut state = [0u8; STATE_BYTES];
        let mut verifier = [0u8; VERIFIER_BYTES];
        getrandom::fill(&mut state).map_err(|_| OAuthError::Entropy)?;
        getrandom::fill(&mut verifier).map_err(|_| OAuthError::Entropy)?;
        Self::fixed(
            &URL_SAFE_NO_PAD.encode(state),
            &URL_SAFE_NO_PAD.encode(verifier),
        )
    }

    /// Deterministic secrets — validates charset/length like real output:
    /// verifier must satisfy RFC 7636 (43–128 chars, unreserved set); state
    /// must be 16–128 unreserved chars.
    pub fn fixed(state: &str, verifier: &str) -> Result<Self, OAuthError> {
        if !(16..=128).contains(&state.len()) || !state.bytes().all(|b| UNRESERVED_B64URL.contains(&b))
        {
            return Err(OAuthError::InvalidConfig("state"));
        }
        if !(43..=128).contains(&verifier.len())
            || !verifier.bytes().all(|b| UNRESERVED_B64URL.contains(&b))
        {
            return Err(OAuthError::InvalidConfig("code_verifier"));
        }
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Ok(Self {
            state: state.to_string(),
            code_verifier: Zeroizing::new(verifier.to_string()),
            code_challenge: challenge,
        })
    }
}
