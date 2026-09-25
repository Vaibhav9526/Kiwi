//! FSV-1 wire-vocabulary tests (docs/audits/for-serde-vocab-1.md, T-245).
//!
//! `fixtures/fsv1_canonical.json` pins every tag the writer may emit —
//! lower snake_case unit variants and externally tagged data variants.
//! `fixtures/fsv1_legacy.json` pins every spelling the reader must still
//! accept from version-1 / contract-prose documents. Dual-read,
//! single-write: nothing below may emit a legacy form.

use std::fmt::Debug;

use kiwi_forensics::analyzers::Direction;
use kiwi_forensics::findings::diff::ChangeKind;
use kiwi_forensics::findings::{
    Confidence, EvidenceKind, EvidenceValue, FindingCategory, Severity,
};
use kiwi_forensics::model::{
    AuthMechanism, BulkCipher, CertificateProblem, CipherStrength, CredentialKind, ForwardSecrecy,
    HostnameMatch, KeyExchange, LEGACY_UNKNOWN_WIRE, MacAlgorithm, PeerRole, Protocol,
    PublicKeyAlgorithm, SignatureAlgorithm, TlsVersion, TransportSecurity, TrustState,
    VersionComparison,
};
use kiwi_forensics::pcap::{CaptureFormat, LinkType};
use kiwi_forensics::score::Grade;
use serde::Serialize;
use serde_json::Value;

fn canonical() -> Value {
    serde_json::from_str(include_str!("fixtures/fsv1_canonical.json"))
        .expect("canonical fixture parses")
}

fn legacy() -> Value {
    serde_json::from_str(include_str!("fixtures/fsv1_legacy.json")).expect("legacy fixture parses")
}

fn de<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v} must deserialize: {e}"))
}

fn ser<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|e| panic!("must serialize: {e}"))
}

/// Every fixture entry deserializes to the matching variant and every
/// variant re-serializes to the fixture tag byte-for-byte (single-write).
fn assert_canonical<T>(key: &str, variants: Vec<T>)
where
    T: serde::de::DeserializeOwned + Serialize + PartialEq + Debug,
{
    let fixture = canonical();
    let tags = fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"));
    assert_eq!(
        tags.len(),
        variants.len(),
        "{key}: fixture must list every variant exactly once"
    );
    for (tag, variant) in tags.iter().zip(variants.iter()) {
        let parsed: T = de(tag);
        assert_eq!(&parsed, variant, "{key}: tag {tag} maps to wrong variant");
        let emitted = ser(variant);
        assert_eq!(
            &emitted, tag,
            "{key}: {variant:?} must emit its canonical tag"
        );
    }
}

/// Every legacy entry deserializes to the expected variant and re-serializes
/// to the CANONICAL tag — never back to the legacy spelling. `canon_idx` is
/// the variant's index in the canonical fixture's array for the same key;
/// `None` marks a lossy legacy form whose emitted payload legitimately
/// differs from the fixture entry (e.g. the `LEGACY_UNKNOWN_WIRE` sentinel).
fn assert_legacy<T>(key: &str, pairs: Vec<(Option<usize>, T)>)
where
    T: serde::de::DeserializeOwned + Serialize + PartialEq + Debug,
{
    let fixture = legacy();
    let canon = canonical();
    let tags = fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"));
    assert_eq!(tags.len(), pairs.len());
    for (legacy_tag, (canon_idx, variant)) in tags.iter().zip(pairs.iter()) {
        let parsed: T = de(legacy_tag);
        assert_eq!(
            &parsed, variant,
            "{key}: legacy tag {legacy_tag} maps to wrong variant"
        );
        if let Some(idx) = canon_idx {
            let emitted = ser(&parsed);
            assert_eq!(
                &emitted, &canon[key][*idx],
                "{key}: legacy {legacy_tag} must normalize to canonical tag on write"
            );
        }
    }
}

#[test]
fn fsv1_canonical_fixture_covers_every_enum() {
    let v = canonical();

    assert_canonical::<TlsVersion>(
        "tls_version",
        vec![
            TlsVersion::Ssl2,
            TlsVersion::Ssl3,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
            TlsVersion::Unknown(513),
        ],
    );
    assert_canonical::<VersionComparison>(
        "version_comparison",
        vec![
            VersionComparison::Below,
            VersionComparison::Equal,
            VersionComparison::Above,
            VersionComparison::Indeterminate,
        ],
    );
    assert_canonical::<KeyExchange>(
        "key_exchange",
        vec![
            KeyExchange::Null,
            KeyExchange::Rsa,
            KeyExchange::DhStatic,
            KeyExchange::Dhe,
            KeyExchange::EcdhStatic,
            KeyExchange::Ecdhe,
            KeyExchange::Psk,
            KeyExchange::PskDhe,
            KeyExchange::PskEcdhe,
            KeyExchange::Anonymous,
            KeyExchange::Unknown,
        ],
    );
    assert_canonical::<ForwardSecrecy>(
        "forward_secrecy",
        vec![
            ForwardSecrecy::Yes,
            ForwardSecrecy::No,
            ForwardSecrecy::Unknown,
        ],
    );
    assert_canonical::<BulkCipher>(
        "bulk_cipher",
        vec![
            BulkCipher::Null,
            BulkCipher::Rc4_40,
            BulkCipher::Rc4_128,
            BulkCipher::Rc2_40,
            BulkCipher::Des,
            BulkCipher::Des40,
            BulkCipher::TripleDes,
            BulkCipher::Idea,
            BulkCipher::Seed,
            BulkCipher::Camellia128Cbc,
            BulkCipher::Aes128Cbc,
            BulkCipher::Aes256Cbc,
            BulkCipher::Aes128Gcm,
            BulkCipher::Aes256Gcm,
            BulkCipher::Aes128Ccm,
            BulkCipher::ChaCha20Poly1305,
            BulkCipher::Unknown,
        ],
    );
    assert_canonical::<MacAlgorithm>(
        "mac_algorithm",
        vec![
            MacAlgorithm::Null,
            MacAlgorithm::HmacMd5,
            MacAlgorithm::HmacSha1,
            MacAlgorithm::HmacSha256,
            MacAlgorithm::HmacSha384,
            MacAlgorithm::Aead,
            MacAlgorithm::Unknown,
        ],
    );
    assert_canonical::<CipherStrength>(
        "cipher_strength",
        vec![
            CipherStrength::Broken,
            CipherStrength::Weak,
            CipherStrength::Legacy,
            CipherStrength::Acceptable,
            CipherStrength::Strong,
            CipherStrength::Unknown,
        ],
    );
    assert_canonical::<AuthMechanism>(
        "auth_mechanism",
        vec![
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
        ],
    );
    assert_canonical::<CredentialKind>(
        "credential_kind",
        vec![
            CredentialKind::None,
            CredentialKind::Password,
            CredentialKind::BearerToken,
            CredentialKind::ChallengeResponse,
            CredentialKind::Unknown,
        ],
    );
    assert_canonical::<Protocol>(
        "protocol",
        vec![
            Protocol::Smtp,
            Protocol::Imap,
            Protocol::Pop3,
            Protocol::Unknown,
        ],
    );
    assert_canonical::<TransportSecurity>(
        "transport_security",
        vec![
            TransportSecurity::Plaintext,
            TransportSecurity::StartTls,
            TransportSecurity::ImplicitTls,
            TransportSecurity::Unknown,
        ],
    );
    assert_canonical::<TrustState>(
        "trust_state",
        vec![
            TrustState::NotEvaluated,
            TrustState::TrustedByLocalAnchor,
            TrustState::Untrusted,
            TrustState::Revoked,
            TrustState::Unknown,
        ],
    );
    assert_canonical::<SignatureAlgorithm>(
        "signature_algorithm",
        vec![
            SignatureAlgorithm::Md2,
            SignatureAlgorithm::Md5,
            SignatureAlgorithm::Sha1,
            SignatureAlgorithm::Sha224,
            SignatureAlgorithm::Sha256,
            SignatureAlgorithm::Sha384,
            SignatureAlgorithm::Sha512,
            SignatureAlgorithm::Unknown,
        ],
    );
    assert_canonical::<PublicKeyAlgorithm>(
        "public_key_algorithm",
        vec![
            PublicKeyAlgorithm::Rsa,
            PublicKeyAlgorithm::Dsa,
            PublicKeyAlgorithm::Ec,
            PublicKeyAlgorithm::Ed25519,
            PublicKeyAlgorithm::Ed448,
            PublicKeyAlgorithm::Unknown,
        ],
    );
    assert_canonical::<HostnameMatch>(
        "hostname_match",
        vec![
            HostnameMatch::Match,
            HostnameMatch::Mismatch,
            HostnameMatch::Indeterminate,
        ],
    );
    assert_canonical::<CertificateProblem>(
        "certificate_problem",
        vec![
            CertificateProblem::NotYetValid,
            CertificateProblem::Expired,
            CertificateProblem::ExpiringSoon,
            CertificateProblem::SelfIssued,
            CertificateProblem::HostnameMismatch,
            CertificateProblem::BrokenSignatureAlgorithm,
            CertificateProblem::DeprecatedSignatureAlgorithm,
            CertificateProblem::WeakPublicKey,
            CertificateProblem::DiscouragedPublicKeyAlgorithm,
            CertificateProblem::ChainTruncated,
            CertificateProblem::TrustNotValidated,
            CertificateProblem::TrustRejected,
        ],
    );
    assert_canonical::<PeerRole>(
        "peer_role",
        vec![PeerRole::Client, PeerRole::Server, PeerRole::Unknown],
    );
    assert_canonical::<Severity>(
        "severity",
        vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ],
    );
    assert_canonical::<Confidence>(
        "confidence",
        vec![Confidence::Tentative, Confidence::Firm, Confidence::Certain],
    );
    assert_canonical::<FindingCategory>(
        "finding_category",
        vec![
            FindingCategory::Transport,
            FindingCategory::Cipher,
            FindingCategory::KeyExchange,
            FindingCategory::Certificate,
            FindingCategory::Authentication,
            FindingCategory::StartTls,
            FindingCategory::Protocol,
            FindingCategory::CaptureIntegrity,
        ],
    );
    assert_canonical::<EvidenceKind>(
        "evidence_kind",
        vec![
            EvidenceKind::TransportState,
            EvidenceKind::TlsVersion,
            EvidenceKind::CipherSuite,
            EvidenceKind::KeyExchange,
            EvidenceKind::ForwardSecrecy,
            EvidenceKind::CertificateAttribute,
            EvidenceKind::CertificateTrust,
            EvidenceKind::AuthMechanism,
            EvidenceKind::AuthOutcome,
            EvidenceKind::StartTlsNegotiation,
            EvidenceKind::ProtocolCapability,
            EvidenceKind::CaptureMetadata,
            EvidenceKind::SessionStructure,
        ],
    );
    assert_canonical::<EvidenceValue>(
        "evidence_value",
        vec![
            EvidenceValue::Text {
                value: "tls12".into(),
            },
            EvidenceValue::Number { value: 993 },
            EvidenceValue::Bool { value: true },
            EvidenceValue::Bytes {
                digest_hex: "ab12".into(),
                len: 4,
            },
            EvidenceValue::List {
                values: vec!["one".into(), "two".into()],
            },
            EvidenceValue::Unavailable {
                reason: "not observed in capture".into(),
            },
        ],
    );
    assert_canonical::<ChangeKind>(
        "change_kind",
        vec![
            ChangeKind::New,
            ChangeKind::Resolved,
            ChangeKind::Unchanged,
            ChangeKind::SeverityIncreased,
            ChangeKind::SeverityDecreased,
        ],
    );
    assert_canonical::<Direction>("direction", vec![Direction::Client, Direction::Server]);
    assert_canonical::<Grade>(
        "grade",
        vec![Grade::A, Grade::B, Grade::C, Grade::D, Grade::F],
    );
    assert_canonical::<CaptureFormat>(
        "capture_format",
        vec![
            CaptureFormat::ClassicPcap { nanosecond: true },
            CaptureFormat::PcapNg,
        ],
    );
    assert_canonical::<LinkType>("link_type", vec![LinkType::Ethernet, LinkType::Other(239)]);

    // Fixture covers all 26 serde-carrying enums in one place.
    assert_eq!(v.as_object().unwrap().len(), 27, "26 enum keys + comment");
}

#[test]
fn fsv1_legacy_spellings_accepted_on_read() {
    // Dotted legacy TLS names normalize to the canonical snake tags.
    assert_legacy::<TlsVersion>(
        "tls_version",
        vec![
            (Some(0), TlsVersion::Ssl2),
            (Some(1), TlsVersion::Ssl3),
            (Some(2), TlsVersion::Tls10),
            (Some(3), TlsVersion::Tls11),
            (Some(4), TlsVersion::Tls12),
            (Some(5), TlsVersion::Tls13),
            // bare "unknown" re-emits {"unknown":65535} — the sentinel, not
            // the fixture's 0x0201 value (lossy legacy, none expected).
            (None, TlsVersion::Unknown(LEGACY_UNKNOWN_WIRE)),
        ],
    );
    assert_legacy::<TransportSecurity>(
        "transport_security",
        vec![(Some(1), TransportSecurity::StartTls)],
    );
    assert_legacy::<AuthMechanism>(
        "auth_mechanism",
        vec![
            (Some(2), AuthMechanism::CramMd5),
            (Some(3), AuthMechanism::DigestMd5),
            (Some(5), AuthMechanism::XOAuth2),
            (Some(6), AuthMechanism::OAuthBearer), // "oauthbearer"
            (Some(6), AuthMechanism::OAuthBearer), // "oauth_bearer" alias
            (Some(7), AuthMechanism::ScramSha1),
            (Some(8), AuthMechanism::ScramSha256),
            (Some(9), AuthMechanism::ScramSha256Plus),
            (Some(10), AuthMechanism::ScramSha512Plus),
        ],
    );
    assert_legacy::<BulkCipher>(
        "bulk_cipher",
        vec![
            (Some(6), BulkCipher::TripleDes),
            (Some(15), BulkCipher::ChaCha20Poly1305),
        ],
    );
    assert_legacy::<ChangeKind>(
        "change_kind",
        vec![(Some(0), ChangeKind::New), (Some(2), ChangeKind::Unchanged)],
    );
    assert_legacy::<Grade>(
        "grade",
        vec![
            (Some(0), Grade::A),
            (Some(1), Grade::B),
            (Some(2), Grade::C),
            (Some(3), Grade::D),
            (Some(4), Grade::F),
        ],
    );
    assert_legacy::<CaptureFormat>(
        "capture_format",
        vec![
            (Some(0), CaptureFormat::ClassicPcap { nanosecond: false }),
            (Some(1), CaptureFormat::PcapNg),
        ],
    );
    assert_legacy::<LinkType>(
        "link_type",
        vec![(Some(0), LinkType::Ethernet), (Some(1), LinkType::Other(6))],
    );
}

#[test]
fn tls_unknown_never_fabricates_a_wire_value() {
    // Canonical object form keeps the raw value (0x4A4A = GREASE-pattern
    // u16, i.e. a genuinely unrecognized on-wire version).
    let kept: TlsVersion = de(&serde_json::json!({"unknown": 19018}));
    assert_eq!(kept, TlsVersion::Unknown(0x4A4A));
    assert_eq!(kept.wire_value(), 0x4A4A);
    assert_eq!(ser(&kept), serde_json::json!({"unknown": 19018}));

    // Bare legacy string cannot carry a payload → documented sentinel only.
    let lost: TlsVersion = de(&Value::from("unknown"));
    assert_eq!(lost, TlsVersion::Unknown(LEGACY_UNKNOWN_WIRE));
    assert_eq!(
        ser(&lost),
        serde_json::json!({"unknown": 65535}),
        "sentinel re-emits as the object form, never the bare string"
    );
}

#[test]
fn unknown_tags_fail_closed() {
    // FOR-6 posture: an unrecognized variant is an error, not a silent
    // "unknown" mapping — a typo must not read as an unobserved value.
    assert!(serde_json::from_value::<TlsVersion>(Value::from("tls14")).is_err());
    assert!(serde_json::from_value::<TlsVersion>(Value::from("tls1.4")).is_err());
    assert!(serde_json::from_value::<AuthMechanism>(Value::from("scram-sha-3")).is_err());
    assert!(serde_json::from_value::<Grade>(Value::from("E")).is_err());
    assert!(serde_json::from_value::<TransportSecurity>(Value::from("weird")).is_err());
    assert!(serde_json::from_value::<CaptureFormat>(Value::from("raw")).is_err());
}

#[test]
fn report_json_crosses_the_migration_boundary() {
    // v1 report with legacy spellings (uppercase grade, `kiwi.forensics/1`)
    // reads into the typed model without loss.
    let v1 = serde_json::json!({
        "contract_version": "kiwi.forensics/1",
        "scoring_model_version": "kiwi-score-1",
        "rule_catalog_version": 1,
        "scope": "legacy-fixture",
        "sessions_evaluated": 0,
        "findings": [],
        "score": {
            "score": 95,
            "grade": "A",
            "deduction_points": 5,
            "counts": {"info": 1, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "dimmed_repeats": 0,
            "model_version": "kiwi-score-1"
        },
        "limitations": [],
        "generated_from": "test-fixture"
    });
    let report = kiwi_forensics::report::Report::from_json(&v1.to_string())
        .expect("v1 report must still read");
    assert_eq!(report.score.grade, Grade::A);
    assert_eq!(report.contract_version, "kiwi.forensics/1");

    // Re-emitted output is single-write canonical: lowercase grade, and the
    // writer stamps the current contract version on new reports.
    let new_report = kiwi_forensics::report::ReportBuilder::new("x", "test-fixture").build();
    assert_eq!(
        new_report.contract_version,
        kiwi_forensics::CONTRACT_VERSION
    );
    let json = new_report.to_json();
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["score"]["grade"],
        Value::from("a"),
        "new reports emit FSV-1 tags only"
    );
    assert!(kiwi_forensics::report::Report::from_json(&json).is_ok());
}
