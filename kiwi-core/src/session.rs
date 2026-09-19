//! Normalized `SecuritySession` model — the canonical representation of one
//! observed mail-protocol connection (SMTP/IMAP/POP3) as seen by the
//! Thunderbird integration hooks or reconstructed by the forensics engine.
//!
//! This model carries *observed facts only*. Classification of weakness is
//! the deterministic rules engine's job; credentials are never represented.

/// Contract/schema version for the serialized form of `SecuritySession`.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Smtp,
    Imap,
    Pop3,
}

/// How the transport is protected. `StartTls` means the session negotiated an
/// upgrade on a cleartext port; `Tls` means implicit TLS from connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportSecurity {
    Plaintext,
    StartTls,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsVersion {
    Unknown,
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl TlsVersion {
    /// Versions deprecated by RFC 8996 (SSLv3, TLS 1.0, TLS 1.1) or unknown.
    pub fn is_deprecated(self) -> bool {
        matches!(
            self,
            TlsVersion::Ssl3 | TlsVersion::Tls1_0 | TlsVersion::Tls1_1 | TlsVersion::Unknown
        )
    }
}

/// Negotiated cipher facts as reported by NSS. No strength classification
/// here — that belongs to the deterministic rules engine (kiwi-forensics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherSuite {
    /// IANA cipher-suite code point when known (e.g. 0x1301 = TLS_AES_128_GCM_SHA256).
    pub iana_id: Option<u16>,
    /// IANA name as negotiated, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
    pub name: String,
    /// Whether the negotiated suite provides forward secrecy
    /// (ephemeral DH/ECDH key exchange — TLS 1.3 suites are always true).
    pub forward_secrecy: bool,
}

/// Key-exchange group actually used for this handshake, when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExchangeGroup {
    X25519,
    SecP256r1,
    SecP384r1,
    SecP521r1,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    /// Non-ephemeral key transport (e.g. RSA kx) — never forward-secret.
    StaticKeyTransport,
    Other(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    pub subject_dn: String,
    pub issuer_dn: String,
    /// Serial number, lowercase hex, no separators.
    pub serial_hex: String,
    /// Validity window, seconds since Unix epoch.
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    /// e.g. "sha256WithRSAEncryption", "ecdsa-with-SHA384", "Ed25519".
    pub signature_algorithm: String,
    /// e.g. "rsaEncryption", "id-ecPublicKey", "Ed25519".
    pub public_key_algorithm: String,
    pub public_key_bits: u32,
    /// SHA-256 fingerprint of the DER cert, lowercase hex.
    pub sha256_fingerprint: String,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainValidation {
    /// NSS validated the chain to a trust anchor for this server name.
    Valid,
    /// Chain built but signature/path validation failed.
    Invalid,
    /// Chain did not reach a trust anchor (includes self-signed leaves).
    Untrusted,
    /// A certificate in the chain is expired or not yet valid.
    Expired,
    /// Leaf does not match the server hostname.
    HostnameMismatch,
    /// Validation could not be performed (e.g. plaintext transport).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertChainSummary {
    pub leaf: Option<CertificateSummary>,
    /// Number of certificates presented by the server, leaf included.
    pub presented_len: u8,
    pub validation: ChainValidation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMechanism {
    /// No authentication performed/observed on this session.
    None,
    Plain,
    Login,
    CramMd5,
    ScramSha1,
    ScramSha256,
    XOAuth2,
    OAuthBearer,
    Ntlm,
    Gssapi,
    /// Client-certificate authentication.
    ClientCertificate,
    Other(String),
    Unknown,
}

/// Where this `SecuritySession` observation came from. Provenance is part of
/// the evidence trail and must never be guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionSource {
    /// Observed live by a Thunderbird integration hook.
    ThunderbirdHook,
    /// Reconstructed by kiwi-forensics from packet capture.
    ForensicPcap,
    /// Synthetic data from a test fixture.
    TestFixture,
}

/// One normalized observed mail connection.
///
/// Invariant: this struct must never contain credentials, message bodies,
/// or private key material (SECURITY.md rules 6, 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySession {
    /// Always `SCHEMA_VERSION` for structures produced by this crate version.
    pub schema_version: u32,
    /// Opaque identifier assigned by the producer; unique per observation.
    pub session_id: String,
    /// SecureMail account this session is bound to, if any.
    pub account_id: Option<String>,
    /// Registered device identity, if bound.
    pub device_id: Option<String>,
    pub protocol: Protocol,
    /// Server identity as configured by the user (not attacker-controlled
    /// greeting strings).
    pub server_host: String,
    pub server_port: u16,
    pub transport: TransportSecurity,
    /// Negotiated TLS version; `None` when transport is `Plaintext`.
    pub tls_version: Option<TlsVersion>,
    /// Negotiated cipher suite; `None` when not applicable/observed.
    pub cipher_suite: Option<CipherSuite>,
    /// Key-exchange group used, when observed.
    pub key_exchange_group: Option<KeyExchangeGroup>,
    /// Server certificate chain facts, when TLS was in use.
    pub cert_chain: Option<CertChainSummary>,
    /// Whether the server advertised STARTTLS (`None` = capability unknown).
    pub starttls_offered: Option<bool>,
    /// Whether a STARTTLS upgrade was actually performed.
    pub starttls_used: bool,
    /// Authentication mechanism negotiated, if any.
    pub auth_mechanism: AuthMechanism,
    /// `Some(false)` on observed auth failure; `None` when not attempted.
    pub auth_succeeded: Option<bool>,
    /// Session establishment time, seconds since Unix epoch.
    pub established_unix: i64,
    pub source: SessionSource,
}

impl SecuritySession {
    /// Convenience accessor: negotiated suite forward-secrecy flag.
    /// TLS 1.3 implies forward secrecy even if the suite record is sparse.
    pub fn has_forward_secrecy(&self) -> bool {
        if self.tls_version == Some(TlsVersion::Tls1_3) {
            return true;
        }
        self.cipher_suite
            .as_ref()
            .map(|c| c.forward_secrecy)
            .unwrap_or(false)
    }
}
