//! Security policy: the deployment-tunable thresholds rules evaluate against.
//!
//! Defaults are the strict, mail-industry-sane values from RFC 8314 (implicit TLS
//! or STARTTLS for submission/access) and RFC 8996 (SSL 3.0, TLS 1.0 and TLS 1.1
//! deprecated). A policy never changes *what* is measured — only which
//! measurements become findings and at what severity — so evidence stays
//! comparable across policy configurations.

use serde::{Deserialize, Serialize};

use crate::model::{CertThresholds, TlsVersion, VersionComparison};

/// Thresholds and expectations for one analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Minimum acceptable negotiated TLS version.
    pub min_tls_version: TlsVersion,
    /// Require TLS at all (mail in the clear becomes a finding).
    pub require_tls: bool,
    /// Require STARTTLS upgrade on ports that offer it.
    pub require_starttls: bool,
    /// Require forward secrecy (ephemeral key exchange).
    pub require_forward_secrecy: bool,
    /// Require TLS 1.3 specifically (off by default; TLS 1.2 is acceptable).
    pub require_tls13: bool,
    /// Treat NULL/EXPORT/anonymous suites as findings.
    pub reject_broken_ciphers: bool,
    /// Treat RC4/3DES/DES/IDEA/SEED suites as findings.
    pub reject_weak_ciphers: bool,
    /// Report CBC-mode and deprecated-MAC suites as hardening items.
    pub report_legacy_ciphers: bool,
    /// Report deprecated authentication mechanisms (PLAIN/LOGIN/CRAM-MD5/NTLM).
    pub report_deprecated_auth: bool,
    /// Report cleartext-password mechanisms even when the channel is protected.
    pub report_cleartext_auth_under_tls: bool,
    /// Number of observed authentication failures that becomes a finding.
    pub max_auth_failures: u32,
    /// Report services speaking plaintext on an implicit-TLS port.
    pub strict_implicit_tls_ports: bool,
    /// Report parameters that could not be classified (never guessed).
    pub report_unrecognized_parameters: bool,
    /// Certificate thresholds.
    pub cert: CertThresholds,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        SecurityPolicy {
            min_tls_version: TlsVersion::Tls12,
            require_tls: true,
            require_starttls: true,
            require_forward_secrecy: true,
            require_tls13: false,
            reject_broken_ciphers: true,
            reject_weak_ciphers: true,
            report_legacy_ciphers: true,
            report_deprecated_auth: true,
            report_cleartext_auth_under_tls: true,
            max_auth_failures: 3,
            strict_implicit_tls_ports: true,
            report_unrecognized_parameters: true,
            cert: CertThresholds::default(),
        }
    }
}

impl SecurityPolicy {
    /// Stricter profile for high-assurance accounts: TLS 1.3 only.
    pub fn strict() -> Self {
        SecurityPolicy {
            min_tls_version: TlsVersion::Tls13,
            require_tls13: true,
            ..SecurityPolicy::default()
        }
    }

    /// Relaxed profile for legacy/test environments.
    ///
    /// Still *measures* everything; it only stops **reporting** as findings what
    /// the environment cannot change. Tests use it to prove that policy
    /// suppression does not suppress evidence.
    pub fn permissive() -> Self {
        SecurityPolicy {
            min_tls_version: TlsVersion::Tls10,
            require_tls: false,
            require_starttls: false,
            require_forward_secrecy: false,
            require_tls13: false,
            reject_broken_ciphers: false,
            reject_weak_ciphers: false,
            report_legacy_ciphers: false,
            report_deprecated_auth: false,
            report_cleartext_auth_under_tls: false,
            max_auth_failures: u32::MAX,
            strict_implicit_tls_ports: false,
            report_unrecognized_parameters: false,
            cert: CertThresholds {
                allow_self_issued: true,
                allow_sha1_signatures: true,
                ..CertThresholds::default()
            },
        }
    }

    /// The floor rules actually enforce: `require_tls13` is a shorthand for
    /// a TLS 1.3 minimum and wins over `min_tls_version` when set.
    /// `strict()` sets both; a custom policy may raise the flag alone.
    pub fn effective_min_tls_version(&self) -> TlsVersion {
        if self.require_tls13 {
            TlsVersion::Tls13
        } else {
            self.min_tls_version
        }
    }

    /// `true` when a negotiated version satisfies the version floor.
    ///
    /// An unrecognized version is **not** treated as acceptable: it is reported
    /// separately so the operator sees "we could not tell" instead of a pass.
    pub fn version_acceptable(&self, version: TlsVersion) -> bool {
        matches!(
            version.compare_to(self.effective_min_tls_version()),
            VersionComparison::Equal | VersionComparison::Above
        )
    }
}
