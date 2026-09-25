//! Certificate-presentation rules.
//!
//! The model derives deterministic [`CertificateProblem`] conditions from
//! adapter-supplied metadata (`CertificatePresentation::problems`); rules map
//! each condition to exactly one finding with severity, impact and
//! remediation. Per the crate's scope boundary, a capture-only presentation
//! (`TrustState::NotEvaluated`) yields `TrustNotValidated` context — the
//! engine never claims "chain verified".

use super::{Rule, RuleContext, ids};
use crate::findings::{
    Confidence, Evidence, EvidenceKind, EvidenceValue, Finding, FindingCategory, Remediation,
    Severity,
};
use crate::model::CertificateProblem;

/// Register the certificate rules: one rule per [`CertificateProblem`].
pub fn register(rules: &mut Vec<Box<dyn Rule>>) {
    for (problem, spec) in &RULE_SPECS {
        rules.push(Box::new(CertRule {
            problem: *problem,
            spec,
        }));
    }
}

/// One rule per certificate condition.
///
/// A struct (rather than a shared `fn`) so the problem→spec wiring lives in
/// the type itself: no runtime lookup, no fallible access, nothing to drift.
struct CertRule {
    problem: CertificateProblem,
    spec: &'static RuleSpec,
}

impl Rule for CertRule {
    fn id(&self) -> &'static str {
        self.spec.id
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Certificate
    }

    fn title(&self) -> &'static str {
        self.spec.title
    }

    fn description(&self) -> &'static str {
        self.spec.description
    }

    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        emit_if_present(ctx, self.problem, self.spec)
    }
}

/// Static per-problem grading: title, description, severity, confidence,
/// impact and remediation. One entry per [`CertificateProblem`]; a test
/// asserts the table is exhaustive so a new problem variant cannot slip
/// through ungraded.
struct RuleSpec {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    confidence: Confidence,
    impact: &'static str,
    remediation_summary: &'static str,
    remediation_steps: &'static [&'static str],
    references: &'static [&'static str],
}

static RULE_SPECS: [(CertificateProblem, RuleSpec); 12] = [
    (
        CertificateProblem::Expired,
        RuleSpec {
            id: ids::CERT_EXPIRED,
            title: "Certificate expired",
            description: "The server certificate was already expired at the observation time.",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            impact: "Clients must reject expired certificates; any acceptance is a validation failure, and recorded sessions were never properly authenticated.",
            remediation_summary: "Replace the expired certificate.",
            remediation_steps: &[
                "Renew the certificate through the issuing CA.",
                "Verify the renewed chain covers the server name before deploying.",
            ],
            references: &["RFC 5280 §4.1.2.5"],
        },
    ),
    (
        CertificateProblem::NotYetValid,
        RuleSpec {
            id: ids::CERT_NOT_YET_VALID,
            title: "Certificate not yet valid",
            description: "The server certificate's validity period had not started at the observation time.",
            severity: Severity::High,
            confidence: Confidence::Certain,
            impact: "A not-yet-valid certificate cannot authenticate the peer; acceptance suggests clock skew or a misissued certificate.",
            remediation_summary: "Check clocks and the certificate issuance date.",
            remediation_steps: &[
                "Verify the client and server clocks before changing anything.",
                "If clocks are correct, reissue with a valid start date.",
            ],
            references: &["RFC 5280 §4.1.2.5"],
        },
    ),
    (
        CertificateProblem::ExpiringSoon,
        RuleSpec {
            id: ids::CERT_EXPIRING_SOON,
            title: "Certificate expires soon",
            description: "The server certificate expires within the configured warning window.",
            severity: Severity::Low,
            confidence: Confidence::Certain,
            impact: "Imminent expiry causes outages and tempts operators into dangerous bypasses.",
            remediation_summary: "Schedule renewal before expiry.",
            remediation_steps: &["Renew the certificate and confirm automated renewal covers it."],
            references: &[],
        },
    ),
    (
        CertificateProblem::SelfIssued,
        RuleSpec {
            id: ids::CERT_SELF_ISSUED,
            title: "Self-issued certificate presented alone",
            description: "The peer presented a single self-issued certificate with no chain to a trust anchor.",
            severity: Severity::High,
            confidence: Confidence::Certain,
            impact: "Without a trust anchor anyone can mint an identical certificate; the peer is unauthenticated unless the key was pinned out of band.",
            remediation_summary: "Replace with a CA-issued certificate or pin the key explicitly.",
            remediation_steps: &[
                "Obtain a certificate from a trusted CA covering the server name.",
                "If self-issuance is intentional, pin the exact public key and document the exception.",
            ],
            references: &[],
        },
    ),
    (
        CertificateProblem::HostnameMismatch,
        RuleSpec {
            id: ids::CERT_HOSTNAME_MISMATCH,
            title: "Certificate does not cover the server name",
            description: "Neither the SANs nor the CN of the leaf certificate match the server the client connected to.",
            severity: Severity::High,
            confidence: Confidence::Certain,
            impact: "The certificate may belong to a different service — or to an attacker presenting a valid certificate for the wrong name.",
            remediation_summary: "Present a certificate that covers the server name.",
            remediation_steps: &[
                "Add the server name to the SAN list and reissue.",
                "Verify the client connected to the intended host (DNS hijack check).",
            ],
            references: &["RFC 6125"],
        },
    ),
    (
        CertificateProblem::BrokenSignatureAlgorithm,
        RuleSpec {
            id: ids::CERT_BROKEN_SIGNATURE,
            title: "Broken signature algorithm (MD2/MD5)",
            description: "The leaf certificate is signed with MD2 or MD5, both practically forgeable.",
            severity: Severity::High,
            confidence: Confidence::Certain,
            impact: "Collision attacks allow forging a CA signature, completely defeating authentication.",
            remediation_summary: "Reissue with SHA-256 or better.",
            remediation_steps: &["Replace every MD2/MD5-signed certificate in the chain."],
            references: &[],
        },
    ),
    (
        CertificateProblem::DeprecatedSignatureAlgorithm,
        RuleSpec {
            id: ids::CERT_DEPRECATED_SIGNATURE,
            title: "Deprecated signature algorithm (SHA-1)",
            description: "The leaf certificate is signed with SHA-1, deprecated for certificate signing.",
            severity: Severity::Medium,
            confidence: Confidence::Certain,
            impact: "Chosen-prefix collisions make SHA-1 signatures untrustworthy; browsers and platforms already reject them.",
            remediation_summary: "Reissue with SHA-256 or better.",
            remediation_steps: &[
                "Replace SHA-1-signed certificates before clients start hard-failing.",
            ],
            references: &[],
        },
    ),
    (
        CertificateProblem::WeakPublicKey,
        RuleSpec {
            id: ids::CERT_WEAK_KEY,
            title: "Public key below minimum size",
            description: "The leaf public key is shorter than the configured minimum (2048-bit RSA / 256-bit EC by default).",
            severity: Severity::High,
            confidence: Confidence::Certain,
            impact: "Undersized keys are factorable or enumerable with modest resources, exposing past and future sessions.",
            remediation_summary: "Reissue with an adequately sized key.",
            remediation_steps: &["Generate a 2048-bit RSA (or 256-bit EC) key and reissue."],
            references: &[],
        },
    ),
    (
        CertificateProblem::DiscouragedPublicKeyAlgorithm,
        RuleSpec {
            id: ids::CERT_DISCOURAGED_KEY_ALGORITHM,
            title: "Discouraged public-key algorithm",
            description: "The leaf key uses an algorithm not recommended for mail TLS (for example DSA).",
            severity: Severity::Medium,
            confidence: Confidence::Certain,
            impact: "Weak ecosystem support and limited security review make these algorithms a liability.",
            remediation_summary: "Reissue with RSA or ECDSA.",
            remediation_steps: &["Migrate the key algorithm to RSA-2048+ or ECDSA P-256+."],
            references: &[],
        },
    ),
    (
        CertificateProblem::ChainTruncated,
        RuleSpec {
            id: ids::CERT_CHAIN_TRUNCATED,
            title: "Chain truncated by capture or bounds",
            description: "Certificates were dropped to stay within bounds, or the capture ended before the full chain was observed.",
            severity: Severity::Info,
            confidence: Confidence::Firm,
            impact: "Analysis covers only the observed prefix of the chain; missing intermediates limit trust conclusions.",
            remediation_summary: "Capture the complete handshake.",
            remediation_steps: &[
                "Ensure the capture includes the full handshake so every certificate is visible.",
            ],
            references: &[],
        },
    ),
    (
        CertificateProblem::TrustNotValidated,
        RuleSpec {
            id: ids::CERT_TRUST_NOT_VALIDATED,
            title: "Chain trust was not validated",
            description: "No trust layer validated the presented chain (capture-only analysis).",
            severity: Severity::Info,
            confidence: Confidence::Certain,
            impact: "Attribute findings still hold, but no claim about chain-of-trust validity can be made from this input.",
            remediation_summary: "No action; context for interpreting the other findings.",
            remediation_steps: &[
                "Validate the chain in a live client when a trust verdict is needed.",
            ],
            references: &[],
        },
    ),
    (
        CertificateProblem::TrustRejected,
        RuleSpec {
            id: ids::CERT_TRUST_REJECTED,
            title: "Trust layer rejected the chain",
            description: "A trust layer evaluated the presented chain and rejected it (untrusted anchor or revocation).",
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            impact: "The peer failed authentication: continuing means talking to an unverified party.",
            remediation_summary: "Do not trust this peer until the rejection cause is resolved.",
            remediation_steps: &[
                "Read the trust layer's rejection reason (unknown anchor vs revocation).",
                "Install the correct anchor or replace the revoked certificate.",
            ],
            references: &[],
        },
    ),
];

/// Emit the finding for `problem` when the derived conditions contain it.
fn emit_if_present(
    ctx: &RuleContext<'_>,
    problem: CertificateProblem,
    spec: &'static RuleSpec,
) -> Vec<Finding> {
    let Some(certs) = &ctx.session.certificates else {
        return Vec::new();
    };
    let server_name = ctx.session.server.address.as_str();
    let conditions = certs.problems(
        server_name,
        ctx.session.started_at_unix_ms,
        &ctx.policy.cert,
    );
    if !conditions.contains(&problem) {
        return Vec::new();
    }
    let fingerprint = certs
        .leaf()
        .and_then(|leaf| leaf.sha256_fingerprint.as_ref())
        .map(|fp| fp.as_str().to_string());
    let mut builder = Finding::builder(
        spec.id,
        crate::RULE_CATALOG_VERSION,
        FindingCategory::Certificate,
        spec.severity,
        spec.confidence,
        ctx.session,
    )
    .title(spec.title)
    .description(spec.description)
    .impact(spec.impact)
    .remediation(
        Remediation::new(spec.remediation_summary, spec.remediation_steps)
            .with_references(spec.references),
    )
    .evidence(Evidence::new(
        if problem == CertificateProblem::ChainTruncated {
            EvidenceKind::CaptureMetadata
        } else if problem == CertificateProblem::TrustNotValidated
            || problem == CertificateProblem::TrustRejected
        {
            EvidenceKind::CertificateTrust
        } else {
            EvidenceKind::CertificateAttribute
        },
        "certificate condition derived from adapter metadata",
        EvidenceValue::text(problem.as_str()),
        ctx.session_anchor(),
    ));
    for reference in spec.references {
        builder = builder.reference(reference);
    }
    // Stable artifact identity: the leaf fingerprint when the adapter reports
    // one, so re-scans line the same certificate up across captures.
    builder = builder.discriminator(fingerprint.as_deref().unwrap_or("leaf"));
    vec![builder.build()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CertificateInfo, CertificatePresentation, ConnectionSecurityEvent, DistinguishedName,
        Endpoint, Protocol, PublicKeyAlgorithm, SessionId, SignatureAlgorithm, TrustState,
    };
    use crate::rules::SecurityPolicy;

    const NOW: i64 = 1_700_000_000_000;
    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    fn session_with(certs: CertificatePresentation) -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label("t:imap:993"),
            Protocol::Imap,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 993),
            NOW,
        )
        .with_certificates(certs)
    }

    fn leaf() -> CertificateInfo {
        CertificateInfo {
            subject: DistinguishedName::from_raw("CN=mail.example.test")
                .with_common_name("mail.example.test"),
            issuer: DistinguishedName::from_raw("CN=Test CA"),
            subject_alt_names: vec![crate::model::SafeText::new("mail.example.test")],
            not_before_unix_ms: NOW - 30 * DAY_MS,
            not_after_unix_ms: NOW + 300 * DAY_MS,
            serial_hex: None,
            signature_algorithm: SignatureAlgorithm::Sha256,
            public_key_algorithm: PublicKeyAlgorithm::Rsa,
            public_key_bits: Some(2048),
            is_ca: false,
            sha256_fingerprint: None,
            raw_der_len: None,
        }
    }

    fn engine() -> super::super::RuleEngine {
        super::super::RuleEngine::new(SecurityPolicy::default())
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn spec_table_covers_every_problem() {
        // Twelve problems, twelve specs, twelve distinct rule ids.
        assert_eq!(RULE_SPECS.len(), 12);
        let mut ids: Vec<&str> = RULE_SPECS.iter().map(|(_, s)| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 12, "duplicate rule id in RULE_SPECS");
        for id in ids {
            assert!(id.starts_with("KIWI-CERT-"), "unexpected id {id}");
        }
    }

    #[test]
    fn healthy_chain_reports_only_trust_context() {
        let s = session_with(CertificatePresentation::new(
            vec![leaf()],
            TrustState::NotEvaluated,
        ));
        let findings = engine().evaluate_session(&s);
        // NotEvaluated is capture-only input: exactly one context finding.
        assert_eq!(rule_ids(&findings), vec![ids::CERT_TRUST_NOT_VALIDATED]);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn expired_leaf_is_critical() {
        let mut bad = leaf();
        bad.not_after_unix_ms = NOW - DAY_MS;
        let s = session_with(CertificatePresentation::new(
            vec![bad],
            TrustState::NotEvaluated,
        ));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::CERT_EXPIRED));
        let expired = findings
            .iter()
            .find(|f| f.rule_id == ids::CERT_EXPIRED)
            .expect("expired finding present");
        assert_eq!(expired.severity, Severity::Critical);
        assert!(expired.has_evidence());
    }

    #[test]
    fn trusted_anchor_suppresses_trust_context() {
        let s = session_with(CertificatePresentation::new(
            vec![leaf()],
            TrustState::TrustedByLocalAnchor,
        ));
        let findings = engine().evaluate_session(&s);
        assert!(
            findings.is_empty(),
            "unexpected findings: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_certificates_means_no_cert_findings() {
        let s = ConnectionSecurityEvent::new(
            SessionId::from_label("t:imap:993"),
            Protocol::Imap,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 993),
            NOW,
        );
        let findings = engine().evaluate_session(&s);
        assert!(
            !findings
                .iter()
                .any(|f| f.category == FindingCategory::Certificate),
            "cert findings without a presentation"
        );
    }
}
