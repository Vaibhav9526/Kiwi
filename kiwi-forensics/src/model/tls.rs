//! TLS handshake observations and deterministic cipher-suite classification.
//!
//! Everything here is *derived from observed wire data*: the version from the
//! record/`ServerHello` version, the cipher suite from its IANA id. Nothing is
//! inferred from server-provided strings or from AI output (`prompt.md` §12:
//! TLS version detection and cipher classification are deterministic-engine
//! authority).

use serde::{Deserialize, Serialize};

use super::SafeText;
use super::cipher_table;

/// A TLS/SSL protocol version as seen on the wire.
///
/// `Unknown(u16)` preserves the raw value so unrecognized or nonsense values
/// remain reportable — a capture is untrusted input.
///
/// Wire form (FSV-1): unit variants are snake_case strings (`"tls12"`);
/// `Unknown` is externally tagged `{"unknown": <u16>}` — never the bare
/// string, which would lose the raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// SSL 2.0 (`0x0002`) — broken, never acceptable.
    Ssl2,
    /// SSL 3.0 (`0x0300`) — broken (POODLE), never acceptable.
    Ssl3,
    /// TLS 1.0 (`0x0301`) — obsolete per RFC 8996.
    Tls10,
    /// TLS 1.1 (`0x0302`) — obsolete per RFC 8996.
    Tls11,
    /// TLS 1.2 (`0x0303`).
    Tls12,
    /// TLS 1.3 (`0x0304`).
    Tls13,
    /// Unrecognized version; raw 16-bit wire value retained.
    Unknown(u16),
}

/// Sentinel `Unknown` payload for the legacy bare string `"unknown"`. The
/// old contract form carried no raw wire value; `0xFFFF` marks "raw lost in
/// migration" without inventing a version — it is outside the assigned
/// 0x03xx TLS range and the GREASE `0x?A?A` set, so no real observation can
/// legitimately carry it. Never fabricate any other value into `Unknown`.
pub const LEGACY_UNKNOWN_WIRE: u16 = 0xFFFF;

const TLS_VERSION_TAGS: &[&str] = &[
    "ssl2",
    "ssl3",
    "tls10",
    "tls11",
    "tls12",
    "tls13",
    "{\"unknown\":u16}",
];

/// FSV-1 read path: canonical snake_case tags plus the `{"unknown":N}`
/// object, and the legacy `as_str()` spellings (`"tls1.2"`, `"ssl3.0"`,
/// bare `"unknown"`) accepted — normalized, never re-emitted.
impl<'de> Deserialize<'de> for TlsVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Tag(String),
            Unknown { unknown: u16 },
        }
        match Repr::deserialize(deserializer)? {
            Repr::Unknown { unknown } => Ok(TlsVersion::Unknown(unknown)),
            Repr::Tag(s) => match s.as_str() {
                "ssl2" | "ssl2.0" => Ok(TlsVersion::Ssl2),
                "ssl3" | "ssl3.0" => Ok(TlsVersion::Ssl3),
                "tls10" | "tls1.0" => Ok(TlsVersion::Tls10),
                "tls11" | "tls1.1" => Ok(TlsVersion::Tls11),
                "tls12" | "tls1.2" => Ok(TlsVersion::Tls12),
                "tls13" | "tls1.3" => Ok(TlsVersion::Tls13),
                "unknown" => Ok(TlsVersion::Unknown(LEGACY_UNKNOWN_WIRE)),
                other => Err(serde::de::Error::unknown_variant(other, TLS_VERSION_TAGS)),
            },
        }
    }
}

/// Result of ordering two [`TlsVersion`] values.
///
/// A dedicated enum keeps the rules readable: the question is always "is the
/// observed version below the required floor?" and an unrecognized version must
/// answer *indeterminate* rather than pass silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionComparison {
    /// Observed version is older than the reference.
    Below,
    /// Observed version equals the reference.
    Equal,
    /// Observed version is newer than the reference.
    Above,
    /// Either side is unknown, so no ordering can be asserted.
    Indeterminate,
}

impl TlsVersion {
    /// Compare against a reference version without inventing an ordering for
    /// unrecognized versions.
    pub fn compare_to(self, reference: TlsVersion) -> VersionComparison {
        match (self.rank(), reference.rank()) {
            (Some(a), Some(b)) if a < b => VersionComparison::Below,
            (Some(a), Some(b)) if a == b => VersionComparison::Equal,
            (Some(_), Some(_)) => VersionComparison::Above,
            _ => VersionComparison::Indeterminate,
        }
    }

    /// Monotonic rank for known versions; `None` for [`TlsVersion::Unknown`].
    ///
    /// SSL and TLS are treated as one ordered family: SSL 2.0 < SSL 3.0 <
    /// TLS 1.0 < … < TLS 1.3, which matches how "too old" is judged in practice.
    pub fn rank(self) -> Option<u8> {
        match self {
            TlsVersion::Ssl2 => Some(0),
            TlsVersion::Ssl3 => Some(1),
            TlsVersion::Tls10 => Some(2),
            TlsVersion::Tls11 => Some(3),
            TlsVersion::Tls12 => Some(4),
            TlsVersion::Tls13 => Some(5),
            TlsVersion::Unknown(_) => None,
        }
    }

    /// 16-bit wire value, including the raw value of an unrecognized version.
    pub fn wire_value(self) -> u16 {
        match self {
            TlsVersion::Ssl2 => 0x0002,
            TlsVersion::Ssl3 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
            TlsVersion::Unknown(raw) => raw,
        }
    }

    /// Classify a raw 16-bit wire value.
    pub fn from_wire(raw: u16) -> TlsVersion {
        match raw {
            0x0002 => TlsVersion::Ssl2,
            0x0300 => TlsVersion::Ssl3,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            other => TlsVersion::Unknown(other),
        }
    }

    /// `true` for SSL 2.0/3.0.
    pub fn is_ssl(self) -> bool {
        matches!(self, TlsVersion::Ssl2 | TlsVersion::Ssl3)
    }

    /// `true` for versions deprecated by RFC 8996 (SSL 3.0, TLS 1.0, TLS 1.1).
    pub fn is_rfc8996_deprecated(self) -> bool {
        matches!(
            self,
            TlsVersion::Ssl3 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }

    /// `true` when TLS 1.3 protects the session.
    pub fn is_tls13(self) -> bool {
        matches!(self, TlsVersion::Tls13)
    }

    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsVersion::Ssl2 => "ssl2.0",
            TlsVersion::Ssl3 => "ssl3.0",
            TlsVersion::Tls10 => "tls1.0",
            TlsVersion::Tls11 => "tls1.1",
            TlsVersion::Tls12 => "tls1.2",
            TlsVersion::Tls13 => "tls1.3",
            TlsVersion::Unknown(_) => "unknown",
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Unknown(raw) => write!(f, "unknown(0x{raw:04x})"),
            other => f.write_str(other.as_str()),
        }
    }
}

/// TLS key-establishment mechanism (how the premaster secret is agreed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyExchange {
    /// No key exchange (NULL suites).
    Null,
    /// Static RSA key transport: the premaster secret is encrypted to the
    /// server's long-term key — **no forward secrecy**.
    Rsa,
    /// Static Diffie-Hellman bound to a certificate key — no forward secrecy.
    DhStatic,
    /// Ephemeral Diffie-Hellman (`DHE`) — forward secrecy.
    Dhe,
    /// Static ECDH bound to a certificate key — no forward secrecy.
    EcdhStatic,
    /// Ephemeral ECDH (`ECDHE`) — forward secrecy.
    Ecdhe,
    /// Pre-shared key without an ephemeral exchange — no forward secrecy.
    Psk,
    /// PSK combined with ephemeral DH (`DHE_PSK`) — forward secrecy.
    PskDhe,
    /// PSK combined with ephemeral ECDH (`ECDHE_PSK`) — forward secrecy.
    PskEcdhe,
    /// Anonymous DH: the server is never authenticated — MITM is trivial.
    Anonymous,
    /// Mechanism not recognized.
    Unknown,
}

impl KeyExchange {
    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyExchange::Null => "null",
            KeyExchange::Rsa => "rsa",
            KeyExchange::DhStatic => "dh_static",
            KeyExchange::Dhe => "dhe",
            KeyExchange::EcdhStatic => "ecdh_static",
            KeyExchange::Ecdhe => "ecdhe",
            KeyExchange::Psk => "psk",
            KeyExchange::PskDhe => "psk_dhe",
            KeyExchange::PskEcdhe => "psk_ecdhe",
            KeyExchange::Anonymous => "anonymous",
            KeyExchange::Unknown => "unknown",
        }
    }

    /// Forward-secrecy assessment implied by this mechanism.
    ///
    /// `Psk` alone is [`ForwardSecrecy::Unknown`] (a PSK deployment may still
    /// rotate keys out of band), while the ephemeral variants are `Yes`.
    pub fn forward_secrecy(self) -> ForwardSecrecy {
        match self {
            KeyExchange::Dhe | KeyExchange::Ecdhe | KeyExchange::PskDhe | KeyExchange::PskEcdhe => {
                ForwardSecrecy::Yes
            }
            KeyExchange::Rsa | KeyExchange::DhStatic | KeyExchange::EcdhStatic => {
                ForwardSecrecy::No
            }
            // DH_anon uses ephemeral keys, so the *session* has forward secrecy,
            // but it has no authentication at all: that is a stronger finding
            // (broken suite) which fires independently.
            KeyExchange::Anonymous => ForwardSecrecy::Yes,
            KeyExchange::Psk | KeyExchange::Null | KeyExchange::Unknown => ForwardSecrecy::Unknown,
        }
    }

    /// `true` for mechanisms that leave the session open to an active MITM
    /// because the server is never authenticated.
    pub fn is_unauthenticated(self) -> bool {
        matches!(self, KeyExchange::Anonymous | KeyExchange::Null)
    }
}

/// Forward-secrecy assessment for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardSecrecy {
    /// Ephemeral key agreement observed.
    Yes,
    /// Non-ephemeral key establishment observed (RSA transport, static DH/ECDH).
    No,
    /// Mechanism unknown; forward secrecy can be asserted neither way.
    Unknown,
}

impl ForwardSecrecy {
    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardSecrecy::Yes => "yes",
            ForwardSecrecy::No => "no",
            ForwardSecrecy::Unknown => "unknown",
        }
    }
}

/// Bulk encryption algorithm of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkCipher {
    /// No encryption at all (`NULL`).
    Null,
    /// RC4 with a 40-bit key (EXPORT).
    Rc4_40,
    /// RC4 with a 128-bit key.
    Rc4_128,
    /// RC2 with a 40-bit key (EXPORT).
    Rc2_40,
    /// Single DES (56-bit).
    Des,
    /// Single DES with a 40-bit key (EXPORT).
    Des40,
    /// Triple DES (2-key/3-key EDE). Legacy `as_str()` spelling `3des`
    /// accepted on read (FSV-1 migration).
    #[serde(alias = "3des")]
    TripleDes,
    /// IDEA in CBC mode.
    Idea,
    /// SEED in CBC mode.
    Seed,
    /// Camellia-128 in CBC mode.
    Camellia128Cbc,
    /// AES-128 in CBC mode.
    Aes128Cbc,
    /// AES-256 in CBC mode.
    Aes256Cbc,
    /// AES-128-GCM (AEAD).
    Aes128Gcm,
    /// AES-256-GCM (AEAD).
    Aes256Gcm,
    /// AES-128-CCM (AEAD).
    Aes128Ccm,
    /// ChaCha20-Poly1305 (AEAD).
    #[serde(alias = "chacha20_poly1305")]
    ChaCha20Poly1305,
    /// Algorithm not recognized.
    Unknown,
}

impl BulkCipher {
    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            BulkCipher::Null => "null",
            BulkCipher::Rc4_40 => "rc4_40",
            BulkCipher::Rc4_128 => "rc4_128",
            BulkCipher::Rc2_40 => "rc2_40",
            BulkCipher::Des => "des",
            BulkCipher::Des40 => "des40",
            BulkCipher::TripleDes => "3des",
            BulkCipher::Idea => "idea",
            BulkCipher::Seed => "seed",
            BulkCipher::Camellia128Cbc => "camellia128_cbc",
            BulkCipher::Aes128Cbc => "aes128_cbc",
            BulkCipher::Aes256Cbc => "aes256_cbc",
            BulkCipher::Aes128Gcm => "aes128_gcm",
            BulkCipher::Aes256Gcm => "aes256_gcm",
            BulkCipher::Aes128Ccm => "aes128_ccm",
            BulkCipher::ChaCha20Poly1305 => "chacha20_poly1305",
            BulkCipher::Unknown => "unknown",
        }
    }

    /// `true` when the suite provides no confidentiality.
    pub fn is_null(self) -> bool {
        matches!(self, BulkCipher::Null)
    }

    /// `true` for deliberately weakened (EXPORT-era) key sizes.
    pub fn is_export_grade(self) -> bool {
        matches!(
            self,
            BulkCipher::Rc4_40 | BulkCipher::Rc2_40 | BulkCipher::Des40
        )
    }

    /// `true` for deprecated 56/64-bit block ciphers and RC4.
    pub fn is_weak_legacy(self) -> bool {
        matches!(
            self,
            BulkCipher::Rc4_40
                | BulkCipher::Rc4_128
                | BulkCipher::Rc2_40
                | BulkCipher::Des
                | BulkCipher::Des40
                | BulkCipher::TripleDes
                | BulkCipher::Idea
                | BulkCipher::Seed
        )
    }

    /// `true` when the suite uses CBC mode (deprecated by modern guidance).
    pub fn is_cbc(self) -> bool {
        matches!(
            self,
            BulkCipher::Aes128Cbc
                | BulkCipher::Aes256Cbc
                | BulkCipher::Camellia128Cbc
                | BulkCipher::Des
                | BulkCipher::Des40
                | BulkCipher::TripleDes
                | BulkCipher::Idea
                | BulkCipher::Seed
                | BulkCipher::Rc2_40
        )
    }

    /// `true` for AEAD constructions.
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            BulkCipher::Aes128Gcm
                | BulkCipher::Aes256Gcm
                | BulkCipher::Aes128Ccm
                | BulkCipher::ChaCha20Poly1305
        )
    }

    /// Nominal key size in bits, when the algorithm has a fixed key size.
    pub fn key_bits(self) -> Option<u16> {
        match self {
            BulkCipher::Rc4_40 | BulkCipher::Rc2_40 | BulkCipher::Des40 => Some(40),
            BulkCipher::Des => Some(56),
            BulkCipher::TripleDes => Some(112),
            BulkCipher::Rc4_128
            | BulkCipher::Idea
            | BulkCipher::Seed
            | BulkCipher::Camellia128Cbc => Some(128),
            BulkCipher::Aes128Cbc | BulkCipher::Aes128Gcm | BulkCipher::Aes128Ccm => Some(128),
            BulkCipher::Aes256Cbc | BulkCipher::Aes256Gcm => Some(256),
            BulkCipher::ChaCha20Poly1305 => Some(256),
            BulkCipher::Null | BulkCipher::Unknown => None,
        }
    }
}

/// Message authentication construction of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacAlgorithm {
    /// No MAC at all.
    Null,
    /// HMAC-MD5.
    HmacMd5,
    /// HMAC-SHA-1.
    HmacSha1,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// Integrity provided by the AEAD construction itself.
    Aead,
    /// Algorithm not recognized.
    Unknown,
}

impl MacAlgorithm {
    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            MacAlgorithm::Null => "null",
            MacAlgorithm::HmacMd5 => "hmac_md5",
            MacAlgorithm::HmacSha1 => "hmac_sha1",
            MacAlgorithm::HmacSha256 => "hmac_sha256",
            MacAlgorithm::HmacSha384 => "hmac_sha384",
            MacAlgorithm::Aead => "aead",
            MacAlgorithm::Unknown => "unknown",
        }
    }

    /// `true` when the MAC is absent (no integrity protection).
    pub fn is_absent(self) -> bool {
        matches!(self, MacAlgorithm::Null)
    }

    /// `true` for MD5/SHA-1 based MACs.
    pub fn is_deprecated_hash(self) -> bool {
        matches!(self, MacAlgorithm::HmacMd5 | MacAlgorithm::HmacSha1)
    }
}

/// Deterministic strength classification of a cipher suite.
///
/// Deliberately coarse: five classes with a documented derivation
/// ([`CipherStrength::classify`]) rather than a numeric "entropy score", so the
/// same suite always lands in the same class and the class can be explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherStrength {
    /// No confidentiality/integrity, or no peer authentication
    /// (NULL, EXPORT, anonymous).
    Broken,
    /// Cryptographically weak primitives (RC4, single DES, 3DES, IDEA, SEED).
    Weak,
    /// Deployed but deprecated by modern guidance (CBC mode, MD5/SHA-1 MACs).
    Legacy,
    /// Sound AEAD/bulk cipher without forward secrecy, or otherwise
    /// unobjectionable-but-not-ideal composition.
    Acceptable,
    /// AEAD with forward secrecy.
    Strong,
    /// Parameters not recognized, so no class can be assigned.
    Unknown,
}

impl CipherStrength {
    /// Derive the strength class from the suite's parameters.
    ///
    /// The derivation is intentionally ordered and total: every combination of
    /// parameters maps to exactly one class, and this is the only place where
    /// classification happens.
    pub fn classify(
        key_exchange: KeyExchange,
        bulk: BulkCipher,
        mac: MacAlgorithm,
    ) -> CipherStrength {
        if matches!(bulk, BulkCipher::Unknown) || matches!(mac, MacAlgorithm::Unknown) {
            return CipherStrength::Unknown;
        }
        // No confidentiality, no integrity, or no peer authentication.
        if bulk.is_null()
            || mac.is_absent()
            || bulk.is_export_grade()
            || key_exchange.is_unauthenticated()
        {
            return CipherStrength::Broken;
        }
        // Weak primitives remain weak even with forward secrecy.
        if bulk.is_weak_legacy() {
            return CipherStrength::Weak;
        }
        // CBC mode (or a deprecated hash) is deprecated, not broken.
        if bulk.is_cbc() || mac.is_deprecated_hash() {
            return CipherStrength::Legacy;
        }
        // Modern AEAD: strong only when the key establishment is ephemeral.
        if bulk.is_aead() {
            return match key_exchange.forward_secrecy() {
                ForwardSecrecy::Yes => CipherStrength::Strong,
                ForwardSecrecy::No => CipherStrength::Acceptable,
                ForwardSecrecy::Unknown => CipherStrength::Acceptable,
            };
        }
        CipherStrength::Unknown
    }

    /// `true` for suites that must never be negotiated in a production client.
    pub fn is_broken(self) -> bool {
        matches!(self, CipherStrength::Broken)
    }

    /// `true` for classes below "acceptable".
    pub fn is_below_acceptable(self) -> bool {
        matches!(
            self,
            CipherStrength::Broken | CipherStrength::Weak | CipherStrength::Legacy
        )
    }

    /// `true` when the suite cannot be classified.
    pub fn is_unknown(self) -> bool {
        matches!(self, CipherStrength::Unknown)
    }

    /// Stable identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            CipherStrength::Broken => "broken",
            CipherStrength::Weak => "weak",
            CipherStrength::Legacy => "legacy",
            CipherStrength::Acceptable => "acceptable",
            CipherStrength::Strong => "strong",
            CipherStrength::Unknown => "unknown",
        }
    }
}

/// A negotiated (or enumerated) TLS cipher suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuite {
    /// IANA id from the wire / NSS.
    pub iana_id: u16,
    /// Official IANA name; `None` when the id is unrecognized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Key-establishment mechanism.
    pub key_exchange: KeyExchange,
    /// Bulk encryption algorithm.
    pub bulk: BulkCipher,
    /// MAC / AEAD construction.
    pub mac: MacAlgorithm,
    /// Derived strength class.
    pub strength: CipherStrength,
    /// `false` when the id is absent from the classifier table, in which case
    /// every parameter above is `Unknown` and no judgement may be made.
    pub recognized: bool,
}

impl CipherSuite {
    /// Classify a suite from its IANA id.
    pub fn from_iana(iana_id: u16) -> Self {
        match cipher_table::lookup(iana_id) {
            Some(params) => CipherSuite {
                iana_id,
                name: Some(params.name.to_string()),
                key_exchange: params.key_exchange,
                bulk: params.bulk,
                mac: params.mac,
                strength: CipherStrength::classify(params.key_exchange, params.bulk, params.mac),
                recognized: true,
            },
            None => CipherSuite {
                iana_id,
                name: None,
                key_exchange: KeyExchange::Unknown,
                bulk: BulkCipher::Unknown,
                mac: MacAlgorithm::Unknown,
                strength: CipherStrength::Unknown,
                recognized: false,
            },
        }
    }

    /// Forward-secrecy assessment implied by the suite's key exchange.
    pub fn forward_secrecy(&self) -> ForwardSecrecy {
        self.key_exchange.forward_secrecy()
    }

    /// Human-readable suite label for evidence/remediation text.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("unrecognized(0x{:04x})", self.iana_id),
        }
    }
}

/// TLS handshake metadata observed for one session.
///
/// Every field is wire-derived or adapter-supplied; none of it is inferred.
/// `sources` carries the chain of custody for the handshake frames so that a
/// finding about the version or suite points at bytes, not at prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsObservation {
    /// Negotiated protocol version.
    pub version: TlsVersion,
    /// Negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// SNI value the client sent, when present and captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<SafeText>,
    /// ALPN protocol identifiers observed, bounded by the caller.
    pub alpn: Vec<SafeText>,
    /// `true` when a complete handshake was observed.
    pub handshake_complete: bool,
    /// `true` when the server resumed a previous session (no new key exchange).
    pub session_resumed: bool,
    /// Traceability anchors for the handshake bytes.
    pub sources: Vec<super::SourceRef>,
}

impl TlsObservation {
    /// Create an observation with no SNI, no ALPN and a complete handshake.
    pub fn new(version: TlsVersion, cipher_suite: CipherSuite) -> Self {
        TlsObservation {
            version,
            cipher_suite,
            sni: None,
            alpn: Vec::new(),
            handshake_complete: true,
            session_resumed: false,
            sources: Vec::new(),
        }
    }

    /// Convenience constructor from a raw IANA cipher-suite id.
    pub fn from_wire(version: TlsVersion, cipher_suite_id: u16) -> Self {
        TlsObservation::new(version, CipherSuite::from_iana(cipher_suite_id))
    }

    /// Set the SNI value (sanitized).
    pub fn with_sni(mut self, sni: &str) -> Self {
        self.sni = Some(SafeText::new(sni));
        self
    }

    /// Attach a traceability anchor.
    pub fn with_source(mut self, source: super::SourceRef) -> Self {
        self.sources.push(source);
        self
    }

    /// Forward-secrecy assessment implied by the negotiated suite.
    pub fn forward_secrecy(&self) -> ForwardSecrecy {
        self.cipher_suite.forward_secrecy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering_never_guesses() {
        assert_eq!(
            TlsVersion::Tls10.compare_to(TlsVersion::Tls12),
            VersionComparison::Below
        );
        assert_eq!(
            TlsVersion::Tls13.compare_to(TlsVersion::Tls12),
            VersionComparison::Above
        );
        assert_eq!(
            TlsVersion::Tls12.compare_to(TlsVersion::Tls12),
            VersionComparison::Equal
        );
        assert_eq!(
            TlsVersion::Unknown(0x0399).compare_to(TlsVersion::Tls12),
            VersionComparison::Indeterminate
        );
    }

    #[test]
    fn version_wire_values_round_trip() {
        for v in [
            TlsVersion::Ssl2,
            TlsVersion::Ssl3,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ] {
            assert_eq!(TlsVersion::from_wire(v.wire_value()), v);
        }
        assert_eq!(
            TlsVersion::from_wire(0x7f17),
            TlsVersion::Unknown(0x7f17),
            "unassigned wire values must stay unknown"
        );
    }

    #[test]
    fn null_and_export_suites_are_broken() {
        assert_eq!(
            CipherSuite::from_iana(0x0000).strength,
            CipherStrength::Broken,
            "TLS_NULL_WITH_NULL_NULL"
        );
        assert_eq!(
            CipherSuite::from_iana(0x0003).strength,
            CipherStrength::Broken,
            "EXPORT-grade RC4"
        );
        assert_eq!(
            CipherSuite::from_iana(0x0034).strength,
            CipherStrength::Broken,
            "anonymous DH is unauthenticated"
        );
    }

    #[test]
    fn rc4_and_3des_are_weak_and_cbc_is_legacy() {
        assert_eq!(
            CipherSuite::from_iana(0x0005).strength,
            CipherStrength::Weak
        );
        assert_eq!(
            CipherSuite::from_iana(0x000A).strength,
            CipherStrength::Weak
        );
        assert_eq!(
            CipherSuite::from_iana(0x002F).strength,
            CipherStrength::Legacy,
            "RSA+AES-CBC-SHA1"
        );
    }

    #[test]
    fn aead_is_strong_only_with_forward_secrecy() {
        let ecdhe_gcm = CipherSuite::from_iana(0xC02F);
        assert_eq!(ecdhe_gcm.strength, CipherStrength::Strong);
        assert_eq!(ecdhe_gcm.forward_secrecy(), ForwardSecrecy::Yes);

        let rsa_gcm = CipherSuite::from_iana(0x009C);
        assert_eq!(rsa_gcm.strength, CipherStrength::Acceptable);
        assert_eq!(rsa_gcm.forward_secrecy(), ForwardSecrecy::No);
    }

    #[test]
    fn unrecognized_suite_yields_no_judgement() {
        let unknown = CipherSuite::from_iana(0x00FF);
        assert!(!unknown.recognized);
        assert_eq!(unknown.strength, CipherStrength::Unknown);
        assert_eq!(unknown.key_exchange, KeyExchange::Unknown);
        assert_eq!(unknown.label(), "unrecognized(0x00ff)");
    }
}
