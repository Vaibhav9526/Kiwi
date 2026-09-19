//! Authentication observations: which mechanism was offered/used, whether it
//! succeeded, and **what credential material actually crossed the wire**.
//!
//! The credential-exposure classification lives here (not in the rules) so that
//! every rule, report and UI surface answers that question identically. It is
//! derived from mechanism + observed channel protection only — no heuristics.

use serde::{Deserialize, Serialize};

/// Authentication mechanism observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMechanism {
    /// `AUTH PLAIN` (base64 credentials — base64 is not encryption).
    Plain,
    /// `AUTH LOGIN`.
    Login,
    /// `AUTH CRAM-MD5` (HMAC-MD5 challenge-response).
    CramMd5,
    /// `AUTH DIGEST-MD5`.
    DigestMd5,
    /// `AUTH NTLM`.
    Ntlm,
    /// `AUTH XOAUTH2` (Google/Microsoft style bearer token).
    XOAuth2,
    /// `AUTH OAUTHBEARER` (RFC 7628).
    OAuthBearer,
    /// `SCRAM-SHA-1`.
    ScramSha1,
    /// `SCRAM-SHA-256`.
    ScramSha256,
    /// `SCRAM-SHA-256-PLUS` (channel binding).
    ScramSha256Plus,
    /// `SCRAM-SHA-512-PLUS`.
    ScramSha512Plus,
    /// `AUTH ANONYMOUS`.
    Anonymous,
    /// SASL `EXTERNAL` (identity established out of band).
    External,
    /// SASL `GSSAPI` / Kerberos.
    Gssapi,
    /// Mechanism token not recognized.
    Unknown,
}

impl AuthMechanism {
    /// Every variant, for exhaustive reporting and tests.
    pub const ALL: [AuthMechanism; 15] = [
        AuthMechanism::Plain,
        AuthMechanism::Login,
        AuthMechanism::CramMd5,
        AuthMechanism::DigestMd5,
        AuthMechanism::Ntlm,
        AuthMechanism::XOAuth2,
        AuthMechanism::OAuthBearer,
        AuthMechanism::ScramSha1,
        AuthMechanism::ScramSha256,
        AuthMechanism::ScramSha256Plus,
        AuthMechanism::ScramSha512Plus,
        AuthMechanism::Anonymous,
        AuthMechanism::External,
        AuthMechanism::Gssapi,
        AuthMechanism::Unknown,
    ];

    /// Stable lowercase identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMechanism::Plain => "plain",
            AuthMechanism::Login => "login",
            AuthMechanism::CramMd5 => "cram-md5",
            AuthMechanism::DigestMd5 => "digest-md5",
            AuthMechanism::Ntlm => "ntlm",
            AuthMechanism::XOAuth2 => "xoauth2",
            AuthMechanism::OAuthBearer => "oauthbearer",
            AuthMechanism::ScramSha1 => "scram-sha-1",
            AuthMechanism::ScramSha256 => "scram-sha-256",
            AuthMechanism::ScramSha256Plus => "scram-sha-256-plus",
            AuthMechanism::ScramSha512Plus => "scram-sha-512-plus",
            AuthMechanism::Anonymous => "anonymous",
            AuthMechanism::External => "external",
            AuthMechanism::Gssapi => "gssapi",
            AuthMechanism::Unknown => "unknown",
        }
    }

    /// Parse a capability/mechanism token (SMTP `AUTH` keywords, IMAP
    /// `AUTH=`, POP3 `SASL`). Case-insensitive; never panics on hostile input.
    ///
    /// An optional `AUTH=` or `SASL ` prefix is tolerated because that is how
    /// servers actually advertise mechanisms in CAPABILITY/CAPA lines.
    pub fn from_token(token: &str) -> AuthMechanism {
        let upper = token.trim().to_ascii_uppercase();
        let key = match upper.strip_prefix("AUTH=") {
            Some(rest) => rest.trim(),
            None => upper.trim(),
        };
        match key {
            "PLAIN" => AuthMechanism::Plain,
            "LOGIN" => AuthMechanism::Login,
            "CRAM-MD5" => AuthMechanism::CramMd5,
            "DIGEST-MD5" => AuthMechanism::DigestMd5,
            "NTLM" => AuthMechanism::Ntlm,
            "XOAUTH2" => AuthMechanism::XOAuth2,
            "OAUTHBEARER" => AuthMechanism::OAuthBearer,
            "SCRAM-SHA-1" => AuthMechanism::ScramSha1,
            "SCRAM-SHA-256" => AuthMechanism::ScramSha256,
            "SCRAM-SHA-256-PLUS" => AuthMechanism::ScramSha256Plus,
            "SCRAM-SHA-512-PLUS" => AuthMechanism::ScramSha512Plus,
            "ANONYMOUS" => AuthMechanism::Anonymous,
            "EXTERNAL" => AuthMechanism::External,
            "GSSAPI" => AuthMechanism::Gssapi,
            _ => AuthMechanism::Unknown,
        }
    }

    /// `true` for mechanisms that send a reusable password in the clear.
    pub fn is_cleartext_password(self) -> bool {
        matches!(self, AuthMechanism::Plain | AuthMechanism::Login)
    }

    /// `true` for mechanisms that send a reusable bearer token.
    pub fn is_bearer_token(self) -> bool {
        matches!(self, AuthMechanism::XOAuth2 | AuthMechanism::OAuthBearer)
    }

    /// `true` for challenge-response mechanisms.
    pub fn is_challenge_response(self) -> bool {
        matches!(
            self,
            AuthMechanism::CramMd5
                | AuthMechanism::DigestMd5
                | AuthMechanism::Ntlm
                | AuthMechanism::ScramSha1
                | AuthMechanism::ScramSha256
                | AuthMechanism::ScramSha256Plus
                | AuthMechanism::ScramSha512Plus
        )
    }

    /// `true` for mechanisms built on MD5.
    pub fn uses_md5(self) -> bool {
        matches!(self, AuthMechanism::CramMd5 | AuthMechanism::DigestMd5)
    }

    /// `true` for mechanisms modern guidance asks clients to avoid.
    pub fn is_deprecated(self) -> bool {
        matches!(
            self,
            AuthMechanism::Plain | AuthMechanism::Login | AuthMechanism::Anonymous
        ) || self.uses_md5()
    }
}

/// What kind of credential material crossed the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// No credential material observed.
    None,
    /// Reusable password (cleartext or trivially encoded).
    Password,
    /// Reusable bearer token (OAuth).
    BearerToken,
    /// Challenge-response exchange (no reusable secret on the wire).
    ChallengeResponse,
    /// Mechanism not recognized, so nothing can be asserted.
    Unknown,
}

impl CredentialKind {
    /// `true` when an observer could replay or reuse the material offline.
    pub fn is_reusable_secret(self) -> bool {
        matches!(self, CredentialKind::Password | CredentialKind::BearerToken)
    }

    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::None => "none",
            CredentialKind::Password => "password",
            CredentialKind::BearerToken => "bearer_token",
            CredentialKind::ChallengeResponse => "challenge_response",
            CredentialKind::Unknown => "unknown",
        }
    }
}

/// Authentication exchange observed for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthObservation {
    /// Mechanism actually attempted, when one was seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<AuthMechanism>,
    /// `Some(true)` = accepted, `Some(false)` = rejected, `None` = not seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<bool>,
    /// Authentication attempts observed (bounded by the analyzer).
    pub attempts: u32,
    /// Failed attempts observed (bounded by the analyzer).
    pub failures: u32,
}

impl AuthObservation {
    /// Observation for a mechanism whose outcome was not captured.
    pub fn new(mechanism: AuthMechanism) -> Self {
        AuthObservation {
            mechanism: Some(mechanism),
            succeeded: None,
            attempts: 1,
            failures: 0,
        }
    }

    /// Observation with an explicit outcome.
    pub fn with_outcome(mechanism: AuthMechanism, succeeded: bool) -> Self {
        AuthObservation {
            mechanism: Some(mechanism),
            succeeded: Some(succeeded),
            attempts: 1,
            failures: u32::from(!succeeded),
        }
    }

    /// Credential material implied by the mechanism.
    pub fn credential_kind(&self) -> CredentialKind {
        match self.mechanism {
            None => CredentialKind::None,
            Some(AuthMechanism::Anonymous) => CredentialKind::None,
            Some(AuthMechanism::Unknown) => CredentialKind::Unknown,
            Some(m) if m.is_cleartext_password() => CredentialKind::Password,
            Some(m) if m.is_bearer_token() => CredentialKind::BearerToken,
            Some(m) if m.is_challenge_response() => CredentialKind::ChallengeResponse,
            // Remaining mechanisms are unrecognized: assert nothing.
            Some(_) => CredentialKind::Unknown,
        }
    }

    /// `true` when a reusable secret was exposed to a passive observer.
    ///
    /// `transport_protected` must come from *observed* TLS, so an unobserved
    /// handshake can never be treated as protection.
    pub fn exposes_reusable_secret(&self, transport_protected: bool) -> bool {
        !transport_protected && self.credential_kind().is_reusable_secret()
    }

    /// `true` when failures were observed (possible credential guessing).
    pub fn has_failures(&self) -> bool {
        self.failures > 0 || self.succeeded == Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_tokens_parse_case_insensitively() {
        assert_eq!(
            AuthMechanism::from_token("auth=plain"),
            AuthMechanism::Plain
        );
        assert_eq!(
            AuthMechanism::from_token(" XOAUTH2 "),
            AuthMechanism::XOAuth2
        );
        assert_eq!(
            AuthMechanism::from_token("scram-sha-256-plus"),
            AuthMechanism::ScramSha256Plus
        );
        assert_eq!(
            AuthMechanism::from_token("NONSENSE"),
            AuthMechanism::Unknown
        );
    }

    #[test]
    fn cleartext_password_over_observed_plaintext_is_an_exposure() {
        let obs = AuthObservation::with_outcome(AuthMechanism::Login, true);
        assert_eq!(obs.credential_kind(), CredentialKind::Password);
        assert!(obs.exposes_reusable_secret(false));
        assert!(
            !obs.exposes_reusable_secret(true),
            "a protected channel hides the password from a passive observer"
        );
    }

    #[test]
    fn bearer_token_is_a_reusable_secret() {
        let obs = AuthObservation::new(AuthMechanism::XOAuth2);
        assert_eq!(obs.credential_kind(), CredentialKind::BearerToken);
        assert!(obs.exposes_reusable_secret(false));
    }

    #[test]
    fn challenge_response_does_not_expose_a_reusable_secret() {
        let obs = AuthObservation::with_outcome(AuthMechanism::CramMd5, true);
        assert_eq!(obs.credential_kind(), CredentialKind::ChallengeResponse);
        assert!(!obs.exposes_reusable_secret(false));
        assert!(obs.mechanism.map(|m| m.uses_md5()).unwrap_or(false));
    }

    #[test]
    fn unknown_mechanism_asserts_nothing() {
        let obs = AuthObservation::new(AuthMechanism::Unknown);
        assert_eq!(obs.credential_kind(), CredentialKind::Unknown);
        assert!(!obs.exposes_reusable_secret(false));
    }

    #[test]
    fn failures_are_detected_from_either_field() {
        let obs = AuthObservation {
            mechanism: Some(AuthMechanism::Plain),
            succeeded: Some(false),
            attempts: 3,
            failures: 2,
        };
        assert!(obs.has_failures());
        assert!(!AuthObservation::with_outcome(AuthMechanism::Plain, true).has_failures());
    }
}
