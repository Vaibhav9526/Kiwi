//! `kiwi-autoconfig` — account autodiscovery (T-135).
//!
//! Four-stage pipeline for turning an email address into a
//! [`kiwi_mail::account::MailAccount`]-shaped config:
//!
//! 1. **ISPDB-style fixture lookup** ([`ispdb`]) — local table of known
//!    providers (ships with fixtures for major providers; fully offline).
//! 2. **Autoconfig XML fetch+parse** ([`autoconfig_xml`]) — Thunderbird-style
//!    `clientConfig` documents fetched from `https://autoconfig.<domain>/…`
//!    then `https://<domain>/.well-known/autoconfig/…`, parsed with a
//!    dependency-free bounded parser (no XXE, no DTD, no network in tests).
//! 3. **MX-derived heuristics** ([`heuristics`]) — MX host → provider hints
//!    (Google Workspace, Microsoft 365, …) or `mail.<domain>`-style guesses.
//! 4. **Manual entry fallback** — always available; every outcome converts
//!    cleanly into a user-editable [`ManualEntry`].
//!
//! All network access goes through the [`DiscoveryNet`] trait so the entire
//! suite runs offline with [`MockNet`] + fixture XML.
//!
//! [`oauth2`] (T-195) is the exception to "never opens connections": it is
//! the grant-acquisition half of account setup. It keeps the same seam
//! discipline — every endpoint call goes through `oauth2::OAuthTransport`
//! (a narrow form-POST contract over the `kiwi-integrations` HTTPS seam),
//! tokens persist only via `kiwi_mail::account::CredentialStore`, and no
//! test touches the live network.

#![warn(missing_docs)]

pub mod autoconfig_xml;
pub mod discovery;
pub mod heuristics;
pub mod ispdb;
pub mod manual;
pub mod net;
pub mod oauth2;
pub mod suggest;

pub use autoconfig_xml::{ClientConfig, OAuth2Spec, ServerSpec};
pub use discovery::{
    DiscoveryOutcome, StageAttempt, StageOutcome, autoconfig_host_url, discover,
    discover_with_table, well_known_url,
};
pub use heuristics::MxHint;
pub use ispdb::{ISPDB_FIXTURES, IspdbEntry};
pub use manual::ManualEntry;
pub use net::{DiscoveryNet, MockNet, MxRecord};
pub use suggest::AccountSuggestion as Suggestion;
pub use suggest::{
    AccountSuggestion, AuthKind, IncomingKind, IncomingSuggestion, OutgoingSuggestion,
    SuggestionSource,
};

/// Contract identifier (`docs/contracts/autoconfig.md`).
pub const CONTRACT_VERSION: &str = "kiwi.autoconfig/1";

/// Max email address length accepted (RFC 5321 §4.5.3.1.3: 256 incl. <>).
pub const MAX_EMAIL_LEN: usize = 256;
/// Max domain/host length (RFC 1035: 253).
pub const MAX_DOMAIN_LEN: usize = 253;
/// Max autoconfig XML document size accepted (256 KiB).
pub const MAX_XML_LEN: usize = 256 * 1024;
/// Max XML nesting depth (bounded parse).
pub const MAX_XML_DEPTH: usize = 32;
/// Max servers / MX records / ISPDB entries examined per stage.
pub const MAX_CANDIDATES: usize = 16;

/// Shared error type: parsing/validation failures only. Network/DNS
/// trouble is NOT an error — stages are skipped and discovery falls
/// through to the next stage (ultimately manual entry).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Email address failed validation.
    #[error("invalid email address")]
    InvalidEmail,
    /// A domain/host string failed validation.
    #[error("invalid domain name")]
    InvalidDomain,
    /// Input exceeded a length bound.
    #[error("input too long")]
    TooLong,
    /// Autoconfig XML failed to parse or validate.
    #[error("malformed autoconfig XML: {0}")]
    MalformedXml(&'static str),
}

/// Lowercase-ASCII domain name with bounds enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DomainName(String);

impl DomainName {
    /// Parse + normalize: trim, strip one trailing dot, lowercase ASCII,
    /// enforce label/length bounds.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let t = raw.trim().trim_end_matches('.');
        if t.is_empty() || t.len() > MAX_DOMAIN_LEN {
            return Err(Error::InvalidDomain);
        }
        for label in t.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(Error::InvalidDomain);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(Error::InvalidDomain);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(Error::InvalidDomain);
            }
        }
        Ok(Self(t.to_ascii_lowercase()))
    }

    /// Borrow the normalized name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Split an email address into `(local, domain)`. Rejects empty local,
/// missing/double `@`, overlong input, and invalid domains.
pub fn split_email(email: &str) -> Result<(String, DomainName), Error> {
    let t = email.trim();
    if t.is_empty() || t.len() > MAX_EMAIL_LEN {
        return Err(Error::InvalidEmail);
    }
    let (local, domain) = t.rsplit_once('@').ok_or(Error::InvalidEmail)?;
    if local.is_empty() || local.len() > 64 {
        return Err(Error::InvalidEmail);
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&b))
    {
        return Err(Error::InvalidEmail);
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(Error::InvalidEmail);
    }
    Ok((
        local.to_string(),
        DomainName::parse(domain).map_err(|_| Error::InvalidEmail)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_parse_normalizes_and_bounds() {
        let d = DomainName::parse("  EXAMPLE.Test.  ").unwrap();
        assert_eq!(d.as_str(), "example.test");
        assert_eq!(d.to_string(), "example.test");
        // Trailing dot stripped; all-dot is rejected. (No "last @" rule for
        // domains: `trim_end_matches('.')` removes every trailing dot, and
        // empty labels after that are rejected.)
        assert_eq!(
            DomainName::parse("example.test..").unwrap().as_str(),
            "example.test"
        );
        // Empty label / leading-trailing hyphen / bad bytes.
        assert!(DomainName::parse("bad..domain").is_err());
        assert!(DomainName::parse("-bad.domain").is_err());
        assert!(DomainName::parse("bad-.domain").is_err());
        assert!(DomainName::parse("under_score.test").is_err());
        assert!(DomainName::parse("").is_err());
        assert!(DomainName::parse(&"a".repeat(MAX_DOMAIN_LEN + 1)).is_err());
        // 63-char label ok, 64-char label rejected.
        assert!(DomainName::parse(&format!("{}.test", "a".repeat(63))).is_ok());
        assert!(DomainName::parse(&format!("{}.test", "a".repeat(64))).is_err());
    }

    #[test]
    fn split_email_accepts_and_normalizes() {
        let (local, domain) = split_email("  User@EXAMPLE.Test ").unwrap();
        assert_eq!(local, "User"); // local part case is preserved
        assert_eq!(domain.as_str(), "example.test");
        // `@` is not in the local-part charset, so "a@b@c.test" is rejected.
        assert!(split_email("a@b@c.test").is_err());
    }

    #[test]
    fn split_email_rejects_bad_input() {
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "@example.test",
            "user@",
            ".dot@example.test",
            "dot.@example.test",
            "do..t@example.test",
            "sp ace@example.test",
            &"x".repeat(MAX_EMAIL_LEN + 1),
        ] {
            assert_eq!(split_email(bad), Err(Error::InvalidEmail), "input: {bad:?}");
        }
        // 64-char local part is the limit.
        assert!(split_email(&format!("{}@x.test", "a".repeat(64))).is_ok());
        assert!(split_email(&format!("{}@x.test", "a".repeat(65))).is_err());
    }

    #[test]
    fn contract_version_is_stable() {
        assert_eq!(CONTRACT_VERSION, "kiwi.autoconfig/1");
    }
}
