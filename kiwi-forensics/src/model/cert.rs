//! Certificate presentation metadata and hostname matching.
//!
//! # Scope boundary (see `docs/SECURITY.md` rule 2)
//!
//! This crate does **not** validate X.509 signatures or build a trust path:
//! that is NSS's job in the live product (`docs/ARCHITECTURE.md` §3) and would
//! require a vetted crypto library plus a trust store. Certificate metadata is
//! therefore *supplied by an adapter*:
//!
//! - Phase 2 (live): the Thunderbird/NSS integration layer supplies the chain
//!   NSS actually validated, including [`TrustState`].
//! - Phase 5 (capture): a capture-derived X.509 parser supplies the *presented*
//!   chain with [`TrustState::NotEvaluated`].
//!
//! Consequences respected by the rules and the report:
//! - a capture-based report must never claim "chain verified";
//! - unverifiable facts become a report-level limitation, not a finding;
//! - everything here is either adapter-declared or a deterministic
//!   string/time comparison (expiry, self-issuance, hostname match).

use serde::{Deserialize, Serialize};

use super::SafeText;

/// Maximum certificates retained from one presented chain (bound on untrusted input).
pub const MAX_CHAIN_LEN: usize = 16;

/// Maximum subject alternative names retained per certificate.
pub const MAX_SAN_ENTRIES: usize = 64;

/// Trust evaluation state for a certificate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// No path validation was performed (capture-only analysis).
    NotEvaluated,
    /// A local trust anchor validated this chain (NSS/TLS consumer path).
    TrustedByLocalAnchor,
    /// Validation was performed and failed.
    Untrusted,
    /// Rejected by the trust layer (revocation, policy).
    Revoked,
    /// Validation attempted; result unknown.
    Unknown,
}

impl TrustState {
    /// `true` only when a trust layer actually validated the chain.
    pub fn is_validated(self) -> bool {
        matches!(self, TrustState::TrustedByLocalAnchor)
    }

    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustState::NotEvaluated => "not_evaluated",
            TrustState::TrustedByLocalAnchor => "trusted_by_local_anchor",
            TrustState::Untrusted => "untrusted",
            TrustState::Revoked => "revoked",
            TrustState::Unknown => "unknown",
        }
    }
}

/// Distinguished name, reduced to the attributes the engine reasons about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistinguishedName {
    /// `CN` attribute, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<SafeText>,
    /// `O` attribute, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<SafeText>,
    /// Full RFC 4514-style string, sanitized and bounded.
    pub raw: SafeText,
}

impl DistinguishedName {
    /// Build from an adapter-provided RFC 4514 string.
    pub fn from_raw(raw: &str) -> Self {
        DistinguishedName {
            common_name: None,
            organization: None,
            raw: SafeText::new(raw),
        }
    }

    /// Attach an explicit common name.
    pub fn with_common_name(mut self, cn: &str) -> Self {
        self.common_name = Some(SafeText::new(cn));
        self
    }

    /// Attach an explicit organization.
    pub fn with_organization(mut self, org: &str) -> Self {
        self.organization = Some(SafeText::new(org));
        self
    }
}

/// Signature algorithm of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// MD2-based signature — broken.
    Md2,
    /// MD5-based signature — broken (practical collisions).
    Md5,
    /// SHA-1-based signature — deprecated for certificate signing.
    Sha1,
    /// SHA-224-based signature.
    Sha224,
    /// SHA-256-based signature.
    Sha256,
    /// SHA-384-based signature.
    Sha384,
    /// SHA-512-based signature.
    Sha512,
    /// Algorithm not recognized.
    Unknown,
}

impl SignatureAlgorithm {
    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::Md2 => "md2",
            SignatureAlgorithm::Md5 => "md5",
            SignatureAlgorithm::Sha1 => "sha1",
            SignatureAlgorithm::Sha224 => "sha224",
            SignatureAlgorithm::Sha256 => "sha256",
            SignatureAlgorithm::Sha384 => "sha384",
            SignatureAlgorithm::Sha512 => "sha512",
            SignatureAlgorithm::Unknown => "unknown",
        }
    }

    /// `true` for MD2/MD5 (collision-broken).
    pub fn is_broken(self) -> bool {
        matches!(self, SignatureAlgorithm::Md2 | SignatureAlgorithm::Md5)
    }

    /// `true` for algorithms no longer acceptable for certificate signing.
    pub fn is_deprecated(self) -> bool {
        self.is_broken() || matches!(self, SignatureAlgorithm::Sha1)
    }

    /// Parse an adapter-provided algorithm name, case-insensitively and
    /// tolerating separators: `"sha256WithRSAEncryption"`,
    /// `"ecdsa-with-SHA256"`, `"SHA1"`.
    ///
    /// Longest-match order is deliberate so a SHA-2 name is never mistaken for
    /// SHA-1.
    pub fn from_name(name: &str) -> SignatureAlgorithm {
        let normalized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if normalized.contains("md5") {
            SignatureAlgorithm::Md5
        } else if normalized.contains("md2") {
            SignatureAlgorithm::Md2
        } else if normalized.contains("sha512") {
            SignatureAlgorithm::Sha512
        } else if normalized.contains("sha384") {
            SignatureAlgorithm::Sha384
        } else if normalized.contains("sha256") {
            SignatureAlgorithm::Sha256
        } else if normalized.contains("sha224") {
            SignatureAlgorithm::Sha224
        } else if normalized.contains("sha1") || normalized.starts_with("sha") {
            // Bare `*WithRSAEncryption` / `sha` names denote SHA-1.
            SignatureAlgorithm::Sha1
        } else {
            SignatureAlgorithm::Unknown
        }
    }
}

/// Public-key algorithm of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicKeyAlgorithm {
    /// RSA.
    Rsa,
    /// DSA — legacy for TLS server certificates.
    Dsa,
    /// Elliptic curve (ECDSA).
    Ec,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// Algorithm not recognized.
    Unknown,
}

impl PublicKeyAlgorithm {
    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            PublicKeyAlgorithm::Rsa => "rsa",
            PublicKeyAlgorithm::Dsa => "dsa",
            PublicKeyAlgorithm::Ec => "ec",
            PublicKeyAlgorithm::Ed25519 => "ed25519",
            PublicKeyAlgorithm::Ed448 => "ed448",
            PublicKeyAlgorithm::Unknown => "unknown",
        }
    }

    /// `true` for algorithms modern mail-TLS deployments should not use.
    pub fn is_discouraged(self) -> bool {
        matches!(self, PublicKeyAlgorithm::Dsa)
    }

    /// Parse an adapter-provided key algorithm name (case-insensitive).
    pub fn from_name(name: &str) -> PublicKeyAlgorithm {
        let normalized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if normalized.contains("ed25519") {
            PublicKeyAlgorithm::Ed25519
        } else if normalized.contains("ed448") {
            PublicKeyAlgorithm::Ed448
        } else if normalized.contains("rsa") {
            PublicKeyAlgorithm::Rsa
        } else if normalized.contains("dsa") {
            PublicKeyAlgorithm::Dsa
        } else if normalized.contains("ec") || normalized.contains("elliptic") {
            PublicKeyAlgorithm::Ec
        } else {
            PublicKeyAlgorithm::Unknown
        }
    }
}

/// Result of comparing a server name against a certificate identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnameMatch {
    /// The presented identity covers the server name.
    Match,
    /// The presented identity is present but does not cover the server name.
    Mismatch,
    /// No usable identity (or no server name) was available.
    Indeterminate,
}

impl HostnameMatch {
    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            HostnameMatch::Match => "match",
            HostnameMatch::Mismatch => "mismatch",
            HostnameMatch::Indeterminate => "indeterminate",
        }
    }
}

/// One certificate as presented on the wire (leaf first in the chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Subject alternative names of type dNSName / iPAddress, already filtered
    /// by the adapter. Values are sanitized and count-bounded by the adapter.
    pub subject_alt_names: Vec<SafeText>,
    /// `notBefore` as Unix epoch milliseconds.
    pub not_before_unix_ms: i64,
    /// `notAfter` as Unix epoch milliseconds.
    pub not_after_unix_ms: i64,
    /// Serial number as lowercase hex, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<SafeText>,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// Public-key algorithm.
    pub public_key_algorithm: PublicKeyAlgorithm,
    /// Public-key size in bits, when the adapter can report it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_bits: Option<u32>,
    /// `true` when the basic constraints mark this certificate as a CA.
    pub is_ca: bool,
    /// SHA-256 fingerprint as lowercase hex, when the adapter can report it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_fingerprint: Option<SafeText>,
    /// Size of the DER encoding, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_der_len: Option<u64>,
}

impl CertificateInfo {
    /// `true` when the certificate is its own issuer (self-issued).
    ///
    /// This is a string comparison on the adapter-provided names; it is not a
    /// signature check.
    pub fn is_self_issued(&self) -> bool {
        !self.subject.raw.is_empty() && self.subject.raw == self.issuer.raw
    }

    /// Compare a server name against this certificate's identity.
    ///
    /// Deterministic, RFC 6125-inspired: dNSName SANs are authoritative when
    /// present, `CN` is only consulted when no SAN is available, and a wildcard
    /// matches exactly one left-most label.
    pub fn hostname_match(&self, server_name: &str) -> HostnameMatch {
        let host = normalize_dns_name(server_name);
        if host.is_empty() {
            return HostnameMatch::Indeterminate;
        }
        let mut san_present = false;
        for san in &self.subject_alt_names {
            let candidate = normalize_dns_name(san.as_str());
            if candidate.is_empty() {
                continue;
            }
            san_present = true;
            if dns_name_matches(&candidate, &host) {
                return HostnameMatch::Match;
            }
        }
        if san_present {
            // Presence of SANs means CN must not be used as a fallback.
            return HostnameMatch::Mismatch;
        }
        match self.subject.common_name.as_ref() {
            Some(cn) => {
                let candidate = normalize_dns_name(cn.as_str());
                if candidate.is_empty() {
                    HostnameMatch::Indeterminate
                } else if dns_name_matches(&candidate, &host) {
                    HostnameMatch::Match
                } else {
                    HostnameMatch::Mismatch
                }
            }
            None => HostnameMatch::Indeterminate,
        }
    }
}

/// Lowercase a DNS name and drop a single trailing dot. No other rewriting:
/// the engine does not attempt IDNA or punycode conversion.
fn normalize_dns_name(name: &str) -> String {
    let trimmed = name.trim();
    let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    without_dot.to_ascii_lowercase()
}

/// Match a certificate DNS name pattern against a host name.
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    let Some(dot) = host.find('.') else {
        return false;
    };
    // The wildcard label must be non-empty and the remainder must match exactly,
    // so `*.example.com` never matches `a.b.example.com`.
    dot > 0 && host.get(dot + 1..) == Some(suffix)
}

/// A deterministic certificate condition, in the order reports list them.
///
/// This enum is *data*, not judgement: severity, impact text and remediation are
/// assigned by the rule engine. Keeping them apart means the same condition
/// cannot be graded differently by different callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateProblem {
    /// `notBefore` is later than the observation time.
    NotYetValid,
    /// `notAfter` is earlier than the observation time.
    Expired,
    /// Validity ends within the configured warning window.
    ExpiringSoon,
    /// The presented chain is a single self-issued certificate.
    SelfIssued,
    /// The leaf identity does not cover the server name.
    HostnameMismatch,
    /// MD2/MD5 signature (collision-broken).
    BrokenSignatureAlgorithm,
    /// SHA-1 signature (deprecated for certificate signing).
    DeprecatedSignatureAlgorithm,
    /// Public key shorter than the configured minimum.
    WeakPublicKey,
    /// Public-key algorithm not recommended for mail TLS (for example DSA).
    DiscouragedPublicKeyAlgorithm,
    /// The capture ended before the full chain was observed.
    ChainTruncated,
    /// No trust layer validated the chain (capture-only input).
    TrustNotValidated,
    /// A trust layer rejected the chain.
    TrustRejected,
}

impl CertificateProblem {
    /// Stable lowercase identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            CertificateProblem::NotYetValid => "not_yet_valid",
            CertificateProblem::Expired => "expired",
            CertificateProblem::ExpiringSoon => "expiring_soon",
            CertificateProblem::SelfIssued => "self_issued",
            CertificateProblem::HostnameMismatch => "hostname_mismatch",
            CertificateProblem::BrokenSignatureAlgorithm => "broken_signature_algorithm",
            CertificateProblem::DeprecatedSignatureAlgorithm => "deprecated_signature_algorithm",
            CertificateProblem::WeakPublicKey => "weak_public_key",
            CertificateProblem::DiscouragedPublicKeyAlgorithm => "discouraged_public_key_algorithm",
            CertificateProblem::ChainTruncated => "chain_truncated",
            CertificateProblem::TrustNotValidated => "trust_not_validated",
            CertificateProblem::TrustRejected => "trust_rejected",
        }
    }
}

/// Certificate thresholds used when deriving [`CertificateProblem`] values.
///
/// Defaults follow current mainstream guidance; deployments may tighten them
/// through the rule engine's policy object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertThresholds {
    /// Minimum RSA modulus size in bits.
    pub min_rsa_key_bits: u32,
    /// Minimum elliptic-curve field size in bits.
    pub min_ec_key_bits: u32,
    /// Report [`CertificateProblem::ExpiringSoon`] when a certificate expires
    /// within this many **milliseconds** of the observation time.
    ///
    /// Milliseconds, not seconds: certificate validity and observation time are
    /// both Unix epoch milliseconds, and a unit mismatch here would silently
    /// suppress expiry warnings (~30 days is 2,592,000 s but 2,592,000,000 ms).
    pub expiry_warning_ms: i64,
    /// Treat a single self-issued certificate as acceptable.
    pub allow_self_issued: bool,
    /// Treat SHA-1 certificate signatures as acceptable.
    pub allow_sha1_signatures: bool,
}

impl Default for CertThresholds {
    fn default() -> Self {
        CertThresholds {
            min_rsa_key_bits: 2048,
            min_ec_key_bits: 256,
            expiry_warning_ms: 30 * 24 * 60 * 60 * 1000,
            allow_self_issued: false,
            allow_sha1_signatures: false,
        }
    }
}

/// Certificate chain as presented for one session (leaf first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatePresentation {
    /// Presented chain, leaf first, bounded to [`MAX_CHAIN_LEN`].
    pub chain: Vec<CertificateInfo>,
    /// Trust evaluation state reported by the supplying adapter.
    pub trust: TrustState,
    /// `true` when the adapter had to drop certificates to stay within bounds.
    pub chain_truncated: bool,
    /// Traceability anchors for the presented certificates.
    pub sources: Vec<super::SourceRef>,
}

impl CertificatePresentation {
    /// Build a presentation with no evidence anchors; the chain is bounded and
    /// `chain_truncated` is set automatically when entries were dropped.
    pub fn new(chain: Vec<CertificateInfo>, trust: TrustState) -> Self {
        let chain_truncated = chain.len() > MAX_CHAIN_LEN;
        CertificatePresentation {
            chain: chain.into_iter().take(MAX_CHAIN_LEN).collect(),
            trust,
            chain_truncated,
            sources: Vec::new(),
        }
    }

    /// Leaf (server) certificate, when one was presented.
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.chain.first()
    }

    /// `true` when the presentation is a single self-issued certificate.
    pub fn is_self_signed_chain(&self) -> bool {
        match self.leaf() {
            Some(leaf) => leaf.is_self_issued() && self.chain.len() <= 1,
            None => false,
        }
    }

    /// Hostname comparison against the leaf certificate.
    pub fn hostname_match(&self, server_name: &str) -> HostnameMatch {
        match self.leaf() {
            Some(leaf) => leaf.hostname_match(server_name),
            None => HostnameMatch::Indeterminate,
        }
    }

    /// Derive the ordered list of certificate conditions.
    ///
    /// `server_name` and `observed_at_unix_ms` are supplied by the caller, so
    /// the result is reproducible: the engine never reads the system clock and
    /// never invents a server name. Only conditions derivable from the supplied
    /// metadata are reported.
    ///
    /// When `server_name` is empty, a hostname mismatch is *not* reported.
    pub fn problems(
        &self,
        server_name: &str,
        observed_at_unix_ms: i64,
        thresholds: &CertThresholds,
    ) -> Vec<CertificateProblem> {
        let mut problems = Vec::new();
        let Some(leaf) = self.leaf() else {
            if self.chain_truncated {
                problems.push(CertificateProblem::ChainTruncated);
            }
            return problems;
        };

        if leaf.not_before_unix_ms > observed_at_unix_ms {
            problems.push(CertificateProblem::NotYetValid);
        }
        if leaf.not_after_unix_ms < observed_at_unix_ms {
            problems.push(CertificateProblem::Expired);
        } else if leaf.not_after_unix_ms.saturating_sub(observed_at_unix_ms)
            <= thresholds.expiry_warning_ms
        {
            problems.push(CertificateProblem::ExpiringSoon);
        }
        if self.is_self_signed_chain() && !thresholds.allow_self_issued {
            problems.push(CertificateProblem::SelfIssued);
        }
        if !server_name.trim().is_empty()
            && self.hostname_match(server_name) == HostnameMatch::Mismatch
        {
            problems.push(CertificateProblem::HostnameMismatch);
        }
        if leaf.signature_algorithm.is_broken() {
            problems.push(CertificateProblem::BrokenSignatureAlgorithm);
        } else if leaf.signature_algorithm.is_deprecated() && !thresholds.allow_sha1_signatures {
            problems.push(CertificateProblem::DeprecatedSignatureAlgorithm);
        }
        if leaf.public_key_algorithm.is_discouraged() {
            problems.push(CertificateProblem::DiscouragedPublicKeyAlgorithm);
        }
        if let Some(bits) = leaf.public_key_bits {
            let minimum = match leaf.public_key_algorithm {
                PublicKeyAlgorithm::Rsa | PublicKeyAlgorithm::Dsa => {
                    Some(thresholds.min_rsa_key_bits)
                }
                PublicKeyAlgorithm::Ec => Some(thresholds.min_ec_key_bits),
                PublicKeyAlgorithm::Ed25519
                | PublicKeyAlgorithm::Ed448
                | PublicKeyAlgorithm::Unknown => None,
            };
            if minimum.map(|min| bits < min).unwrap_or(false) {
                problems.push(CertificateProblem::WeakPublicKey);
            }
        }
        if self.chain_truncated {
            problems.push(CertificateProblem::ChainTruncated);
        }
        match self.trust {
            TrustState::NotEvaluated => problems.push(CertificateProblem::TrustNotValidated),
            TrustState::Untrusted | TrustState::Revoked => {
                problems.push(CertificateProblem::TrustRejected)
            }
            TrustState::TrustedByLocalAnchor | TrustState::Unknown => {}
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;
    const NOW: i64 = 1_700_000_000_000;

    fn cert(subject: &str, issuer: &str, sans: &[&str], not_after: i64) -> CertificateInfo {
        CertificateInfo {
            // Adapters declare CN explicitly; the test helper mirrors that by
            // taking it from the `CN=`-prefixed fixture string.
            subject: dn(subject),
            issuer: DistinguishedName::from_raw(issuer),
            subject_alt_names: sans.iter().map(|s| SafeText::new(s)).collect(),
            not_before_unix_ms: NOW - 10 * DAY_MS,
            not_after_unix_ms: not_after,
            serial_hex: None,
            signature_algorithm: SignatureAlgorithm::Sha256,
            public_key_algorithm: PublicKeyAlgorithm::Rsa,
            public_key_bits: Some(2048),
            is_ca: false,
            sha256_fingerprint: None,
            raw_der_len: None,
        }
    }

    fn dn(raw: &str) -> DistinguishedName {
        let name = DistinguishedName::from_raw(raw);
        match raw.strip_prefix("CN=") {
            Some(cn) => name.with_common_name(cn),
            None => name,
        }
    }

    fn valid_leaf() -> CertificateInfo {
        cert(
            "CN=mail.example.test",
            "CN=Test CA",
            &["mail.example.test", "smtp.example.test"],
            NOW + 200 * DAY_MS,
        )
    }

    #[test]
    fn signature_algorithm_names_parse_longest_match_first() {
        assert_eq!(
            SignatureAlgorithm::from_name("sha256WithRSAEncryption"),
            SignatureAlgorithm::Sha256
        );
        assert_eq!(
            SignatureAlgorithm::from_name("ecdsa-with-SHA384"),
            SignatureAlgorithm::Sha384
        );
        assert_eq!(
            SignatureAlgorithm::from_name("SHA1"),
            SignatureAlgorithm::Sha1
        );
        assert_eq!(
            SignatureAlgorithm::from_name("md5WithRSA"),
            SignatureAlgorithm::Md5
        );
        assert_eq!(
            SignatureAlgorithm::from_name("1.3.14.3.2.29"),
            SignatureAlgorithm::Unknown
        );
    }

    #[test]
    fn public_key_algorithm_names_parse() {
        assert_eq!(
            PublicKeyAlgorithm::from_name("id-ecPublicKey"),
            PublicKeyAlgorithm::Ec
        );
        assert_eq!(
            PublicKeyAlgorithm::from_name("rsaEncryption"),
            PublicKeyAlgorithm::Rsa
        );
        assert_eq!(
            PublicKeyAlgorithm::from_name("ed25519"),
            PublicKeyAlgorithm::Ed25519
        );
        assert_eq!(
            PublicKeyAlgorithm::from_name(""),
            PublicKeyAlgorithm::Unknown
        );
    }

    #[test]
    fn san_entries_are_authoritative_and_wildcards_match_one_label() {
        let leaf = valid_leaf();
        assert_eq!(
            leaf.hostname_match("mail.example.test"),
            HostnameMatch::Match
        );
        assert_eq!(
            leaf.hostname_match("MAIL.EXAMPLE.TEST."),
            HostnameMatch::Match
        );
        assert_eq!(
            leaf.hostname_match("other.example.test"),
            HostnameMatch::Mismatch
        );

        let wildcard = cert(
            "CN=ignored",
            "CN=Test CA",
            &["*.example.test"],
            NOW + DAY_MS,
        );
        assert_eq!(
            wildcard.hostname_match("smtp.example.test"),
            HostnameMatch::Match
        );
        assert_eq!(
            wildcard.hostname_match("a.b.example.test"),
            HostnameMatch::Mismatch,
            "a wildcard must not span multiple labels"
        );
    }

    #[test]
    fn cn_is_not_used_when_sans_are_present() {
        let leaf = cert(
            "CN=mail.example.test",
            "CN=Test CA",
            &["other.example.test"],
            NOW + DAY_MS,
        );
        assert_eq!(
            leaf.hostname_match("mail.example.test"),
            HostnameMatch::Mismatch,
            "CN must not override a non-matching SAN set"
        );
    }

    #[test]
    fn cn_is_used_when_no_san_is_available() {
        let leaf = cert("CN=mail.example.test", "CN=Test CA", &[], NOW + DAY_MS);
        assert_eq!(
            leaf.hostname_match("mail.example.test"),
            HostnameMatch::Match
        );
        assert_eq!(
            leaf.hostname_match("evil.example.test"),
            HostnameMatch::Mismatch
        );
        let mut no_identity = cert("CN=x", "CN=x", &[], NOW + DAY_MS);
        no_identity.subject.common_name = None;
        assert_eq!(
            no_identity.hostname_match("mail.example.test"),
            HostnameMatch::Indeterminate
        );
    }

    #[test]
    fn empty_server_name_is_indeterminate_and_suppresses_the_problem() {
        let presentation =
            CertificatePresentation::new(vec![valid_leaf()], TrustState::NotEvaluated);
        assert_eq!(
            presentation.hostname_match(""),
            HostnameMatch::Indeterminate
        );
        assert!(
            !presentation
                .problems("", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::HostnameMismatch)
        );
        assert!(
            presentation
                .problems("evil.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::HostnameMismatch)
        );
    }

    #[test]
    fn validity_problems_are_derived_from_observation_time() {
        let expired = CertificatePresentation::new(
            vec![cert(
                "CN=mail.example.test",
                "CN=Test CA",
                &["mail.example.test"],
                NOW - DAY_MS,
            )],
            TrustState::NotEvaluated,
        );
        let problems = expired.problems("mail.example.test", NOW, &CertThresholds::default());
        assert!(problems.contains(&CertificateProblem::Expired));
        assert!(!problems.contains(&CertificateProblem::ExpiringSoon));

        let mut not_yet = valid_leaf();
        not_yet.not_before_unix_ms = NOW + DAY_MS;
        let presentation = CertificatePresentation::new(vec![not_yet], TrustState::NotEvaluated);
        assert!(
            presentation
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::NotYetValid)
        );

        let soon = CertificatePresentation::new(
            vec![cert(
                "CN=mail.example.test",
                "CN=Test CA",
                &["mail.example.test"],
                NOW + 5 * DAY_MS,
            )],
            TrustState::NotEvaluated,
        );
        assert!(
            soon.problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::ExpiringSoon),
            "a certificate expiring in 5 days must be flagged within the 30-day window"
        );
    }

    #[test]
    fn self_issued_handling_follows_thresholds() {
        let self_signed = CertificatePresentation::new(
            vec![cert(
                "CN=mail.example.test",
                "CN=mail.example.test",
                &["mail.example.test"],
                NOW + DAY_MS,
            )],
            TrustState::NotEvaluated,
        );
        assert!(self_signed.is_self_signed_chain());
        assert!(
            self_signed
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::SelfIssued)
        );

        let permissive = CertThresholds {
            allow_self_issued: true,
            ..CertThresholds::default()
        };
        assert!(
            !self_signed
                .problems("mail.example.test", NOW, &permissive)
                .contains(&CertificateProblem::SelfIssued)
        );
    }

    #[test]
    fn weak_keys_and_deprecated_signatures_are_reported() {
        let mut leaf = valid_leaf();
        leaf.public_key_bits = Some(1024);
        leaf.signature_algorithm = SignatureAlgorithm::Sha1;
        let presentation = CertificatePresentation::new(vec![leaf], TrustState::NotEvaluated);
        let problems = presentation.problems("mail.example.test", NOW, &CertThresholds::default());
        assert!(problems.contains(&CertificateProblem::WeakPublicKey));
        assert!(problems.contains(&CertificateProblem::DeprecatedSignatureAlgorithm));

        let permissive = CertThresholds {
            allow_sha1_signatures: true,
            ..CertThresholds::default()
        };
        assert!(
            !presentation
                .problems("mail.example.test", NOW, &permissive)
                .contains(&CertificateProblem::DeprecatedSignatureAlgorithm)
        );
    }

    #[test]
    fn capture_presented_chain_is_flagged_as_not_validated() {
        let untrusted_presentation =
            CertificatePresentation::new(vec![valid_leaf()], TrustState::NotEvaluated);
        assert!(
            untrusted_presentation
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::TrustNotValidated)
        );

        let validated =
            CertificatePresentation::new(vec![valid_leaf()], TrustState::TrustedByLocalAnchor);
        assert!(
            !validated
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::TrustNotValidated)
        );
    }

    #[test]
    fn chain_length_is_bounded() {
        let chain: Vec<CertificateInfo> = (0..40).map(|_| valid_leaf()).collect();
        let presentation = CertificatePresentation::new(chain, TrustState::NotEvaluated);
        assert_eq!(presentation.chain.len(), MAX_CHAIN_LEN);
        assert!(presentation.chain_truncated);
        assert!(
            presentation
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .contains(&CertificateProblem::ChainTruncated)
        );
    }

    #[test]
    fn missing_certificate_reports_nothing() {
        let empty = CertificatePresentation::new(Vec::new(), TrustState::NotEvaluated);
        assert!(empty.leaf().is_none());
        assert!(
            empty
                .problems("mail.example.test", NOW, &CertThresholds::default())
                .is_empty()
        );
    }
}
