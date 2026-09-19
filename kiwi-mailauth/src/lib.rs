//! `kiwi-mailauth` — deterministic SPF / DKIM / DMARC checks (T-122).
//!
//! Modules: [`dns`] (lookup abstraction + mock), [`spf`] (RFC 7208),
//! [`dkim`] (RFC 6376), [`dmarc`] (RFC 7489).
//!
//! Rules: deterministic (no clock/RNG/floats in verdicts); never invent
//! findings (no record -> `none`); DNS errors -> `temperror`, never
//! hard-fail; typed `Serialize` results for the forensics evidence model.

#![warn(missing_docs)]

pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod spf;

/// Contract identifier (`docs/contracts/mailauth.md`).
pub const CONTRACT_VERSION: &str = "kiwi.mailauth/1";

/// Max DNS name length (RFC 1035: 253).
pub const MAX_DOMAIN_LEN: usize = 253;
/// Max single label length (RFC 1035: 63).
pub const MAX_LABEL_LEN: usize = 63;
/// Max raw DNS text record length accepted (bounded evidence).
pub const MAX_TXT_LEN: usize = 4096;
/// Max bytes the DKIM canonicalizer will hash (4 MiB).
pub const MAX_CANON_BYTES: usize = 4 * 1024 * 1024;

/// Lowercase-ASCII domain name with bounds enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DomainName(String);

impl DomainName {
    /// Parse + normalize: trim, strip one trailing dot, lowercase ASCII,
    /// enforce label/length bounds. Underscore accepted (needed for
    /// `_dmarc` / `_domainkey` query names); per-module validators decide
    /// what is legal where.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let t = raw.trim().trim_end_matches('.');
        if t.is_empty() || t.len() > MAX_DOMAIN_LEN {
            return Err(Error::InvalidDomain);
        }
        for label in t.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(Error::InvalidDomain);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Error::InvalidDomain);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(Error::InvalidDomain);
            }
        }
        let mut lower = String::with_capacity(t.len());
        for b in t.bytes() {
            lower.push((b as char).to_ascii_lowercase());
        }
        Ok(Self(lower))
    }

    /// Borrow the normalized name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` equals `other` or is a subdomain of it.
    pub fn is_subdomain_of(&self, other: &DomainName) -> bool {
        self.0 == other.0 || self.0.ends_with(&format!(".{}", other.0))
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Org-domain heuristic: last two labels (`a.b.c` -> `b.c`).
/// Limitation (documented, not hidden): NOT the Public Suffix List;
/// multi-label suffixes (`co.uk`) over-approximate. Callers needing exact
/// PSL behaviour supply the org domain explicitly (see dmarc input).
pub fn org_domain_heuristic(domain: &DomainName) -> DomainName {
    let labels: Vec<&str> = domain.as_str().split('.').collect();
    if labels.len() <= 2 {
        return domain.clone();
    }
    let tail = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    DomainName::parse(&tail).unwrap_or_else(|_| domain.clone())
}

/// Shared error type (parsing/validation only — DNS verdicts are results).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A domain/host-label string failed validation.
    #[error("invalid domain name")]
    InvalidDomain,
    /// An IP literal failed to parse.
    #[error("invalid IP address")]
    InvalidIp,
    /// A record or header exceeded a length bound.
    #[error("input too long")]
    TooLong,
    /// A tag-list, mechanism, or modifier failed to parse.
    #[error("malformed record: {0}")]
    Malformed(&'static str),
}
