//! TLS-version, cipher-suite and key-exchange rules.
//!
//! All three answer one question about the *negotiated* protection: which
//! protocol version, which suite, and whether the key establishment gives
//! forward secrecy. Classification comes from the model
//! ([`CipherStrength::classify`], [`KeyExchange::forward_secrecy`]); rules only
//! map classes to findings under the [`SecurityPolicy`].

use super::{FnRule, Rule, RuleContext, ids};
use crate::findings::{
    Confidence, Evidence, EvidenceKind, EvidenceValue, Finding, FindingCategory, Remediation,
    Severity,
};
use crate::model::{CipherStrength, ForwardSecrecy, TlsVersion, VersionComparison};

/// Register the TLS / cipher / key-exchange rules.
pub fn register(rules: &mut Vec<Box<dyn Rule>>) {
    rules.push(Box::new(FnRule::new(
        ids::TLS_VERSION_BELOW_FLOOR,
        FindingCategory::Transport,
        "Negotiated TLS version below the policy floor",
        "Detects a session whose TLS version is older than the minimum acceptable version.",
        rule_version_below_floor,
    )));
    rules.push(Box::new(FnRule::new(
        ids::TLS_VERSION_DEPRECATED,
        FindingCategory::Transport,
        "Deprecated TLS/SSL version negotiated",
        "Detects SSL 3.0, TLS 1.0 or TLS 1.1, deprecated by RFC 8996.",
        rule_version_deprecated,
    )));
    rules.push(Box::new(FnRule::new(
        ids::TLS_VERSION_UNKNOWN,
        FindingCategory::Transport,
        "TLS version could not be classified",
        "Records an unrecognized version wire value instead of guessing.",
        rule_version_unknown,
    )));
    rules.push(Box::new(FnRule::new(
        ids::TLS_HANDSHAKE_MISSING,
        FindingCategory::Transport,
        "TLS claimed but no handshake observed",
        "Detects a session classified as TLS-protected with no handshake metadata.",
        rule_handshake_missing,
    )));
    rules.push(Box::new(FnRule::new(
        ids::TLS_SESSION_RESUMED,
        FindingCategory::Transport,
        "TLS session resumed: key exchange not observed",
        "Records that resumption limits key-exchange analysis for this session.",
        rule_session_resumed,
    )));
    rules.push(Box::new(FnRule::new(
        ids::CIPHER_BROKEN,
        FindingCategory::Cipher,
        "Broken cipher suite negotiated",
        "Detects NULL, EXPORT or anonymous suites: no confidentiality, integrity or authentication.",
        rule_cipher_broken,
    )));
    rules.push(Box::new(FnRule::new(
        ids::CIPHER_WEAK,
        FindingCategory::Cipher,
        "Weak cipher suite negotiated",
        "Detects RC4, single DES, 3DES, IDEA or SEED bulk ciphers.",
        rule_cipher_weak,
    )));
    rules.push(Box::new(FnRule::new(
        ids::CIPHER_LEGACY,
        FindingCategory::Cipher,
        "Legacy cipher suite negotiated",
        "Detects CBC-mode or deprecated-MAC suites as a hardening item.",
        rule_cipher_legacy,
    )));
    rules.push(Box::new(FnRule::new(
        ids::CIPHER_UNRECOGNIZED,
        FindingCategory::Cipher,
        "Cipher suite not recognized",
        "Records an unrecognized suite id instead of judging it.",
        rule_cipher_unrecognized,
    )));
    rules.push(Box::new(FnRule::new(
        ids::KEX_NO_FORWARD_SECRECY,
        FindingCategory::KeyExchange,
        "Key exchange without forward secrecy",
        "Detects static RSA/DH/ECDH key establishment: later key compromise decrypts this session.",
        rule_kex_no_forward_secrecy,
    )));
    rules.push(Box::new(FnRule::new(
        ids::KEX_UNAUTHENTICATED,
        FindingCategory::KeyExchange,
        "Unauthenticated key exchange",
        "Detects anonymous or NULL key exchange: the server is never authenticated.",
        rule_kex_unauthenticated,
    )));
    rules.push(Box::new(FnRule::new(
        ids::KEX_UNKNOWN,
        FindingCategory::KeyExchange,
        "Key exchange could not be classified",
        "Records an unrecognized key-exchange mechanism instead of guessing.",
        rule_kex_unknown,
    )));
}

fn tls_evidence(ctx: &RuleContext<'_>, summary: &str, value: EvidenceValue) -> Evidence {
    Evidence::new(
        EvidenceKind::TlsVersion,
        summary,
        value,
        ctx.session_anchor(),
    )
}

fn rule_version_below_floor(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    // `require_tls13` raises the effective floor over `min_tls_version`.
    let floor = ctx.policy.effective_min_tls_version();
    if !matches!(tls.version.compare_to(floor), VersionComparison::Below) {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::TLS_VERSION_BELOW_FLOOR,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::High,
            Confidence::Certain,
            ctx.session,
        )
        .title("Negotiated TLS version below the policy floor")
        .description(&format!(
            "The session negotiated {}, below the required minimum {}.",
            tls.version, floor,
        ))
        .impact("Older protocol versions lack modern handshake integrity and AEAD-only negotiation; known downgrade and truncation attacks apply.")
        .remediation(
            Remediation::new(
                "Raise the negotiated version to the policy floor or above.",
                &[
                    "Require TLS 1.2 minimum (TLS 1.3 preferred) in the account settings.",
                    "Disable SSL 2.0/3.0 and TLS 1.0/1.1 on both client policy and server, if controlled.",
                    "Re-test after the change; a peer that cannot negotiate up must be treated as legacy.",
                ],
            )
            .with_references(&["RFC 8996", "RFC 8314 §3"]),
        )
        .reference("RFC 8996")
        .evidence(tls_evidence(
            ctx,
            "negotiated TLS version",
            EvidenceValue::text(tls.version.as_str()),
        ))
        .evidence(tls_evidence(
            ctx,
            "policy minimum TLS version",
            EvidenceValue::text(floor.as_str()),
        ))
        .build(),
    ]
}

fn rule_version_deprecated(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    // SSL 2.0 has its own wire presence but the same operational meaning here:
    // a version with no place in production mail transport.
    if !tls.version.is_ssl() && !tls.version.is_rfc8996_deprecated() {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::TLS_VERSION_DEPRECATED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::High,
            Confidence::Certain,
            ctx.session,
        )
        .title("Deprecated TLS/SSL version negotiated")
        .description(&format!(
            "The session negotiated {}, deprecated for all use by RFC 8996.",
            tls.version,
        ))
        .impact("POODLE-style padding attacks and weakened handshake integrity apply to these versions regardless of cipher choice.")
        .remediation(
            Remediation::new(
                "Remove deprecated versions from negotiation.",
                &[
                    "Disable SSL 2.0/3.0 and TLS 1.0/1.1 wherever the version floor is configured.",
                    "Prefer implicit TLS with a modern minimum version.",
                ],
            )
            .with_references(&["RFC 8996"]),
        )
        .reference("RFC 8996")
        .evidence(tls_evidence(
            ctx,
            "negotiated TLS version",
            EvidenceValue::text(tls.version.as_str()),
        ))
        .build(),
    ]
}

fn rule_version_unknown(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if !ctx.policy.report_unrecognized_parameters {
        return Vec::new();
    }
    let TlsVersion::Unknown(raw) = tls.version else {
        return Vec::new();
    };
    vec![
        Finding::builder(
            ids::TLS_VERSION_UNKNOWN,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::Medium,
            Confidence::Firm,
            ctx.session,
        )
        .title("TLS version could not be classified")
        .description(&format!(
            "The handshake carried version wire value 0x{raw:04x}, which matches no known TLS or SSL version."
        ))
        .impact("An unrecognized version may be a corrupt capture, a proprietary extension, or an active manipulation; no protection claim can be made for this session.")
        .remediation(Remediation::new(
            "Investigate the anomalous version value.",
            &[
                "Verify the capture integrity around the handshake frames.",
                "Re-test the peer; a reproducible unknown version deserves a vendor or operator ticket.",
            ],
        ))
        .evidence(tls_evidence(
            ctx,
            "unrecognized version wire value",
            EvidenceValue::number(i64::from(raw)),
        ))
        .build(),
    ]
}

fn rule_handshake_missing(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if ctx.session.tls.is_some() || !ctx.session.transport.is_protected() {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::TLS_HANDSHAKE_MISSING,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::Medium,
            Confidence::Firm,
            ctx.session,
        )
        .title("TLS claimed but no handshake observed")
        .description(&format!(
            "The session is classified as {} but carries no handshake metadata.",
            ctx.session.transport.as_str(),
        ))
        .impact("Without handshake bytes the version, suite and peer identity cannot be verified; the protection claim rests on classification alone.")
        .remediation(Remediation::new(
            "Capture or observe the handshake before trusting the session.",
            &[
                "Ensure analysis starts at connection setup so the handshake is visible.",
                "Until then, treat the session as unvalidated transport.",
            ],
        ))
        .evidence(Evidence::new(
            EvidenceKind::TransportState,
            "transport classification without handshake",
            EvidenceValue::text(ctx.session.transport.as_str()),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_session_resumed(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if !tls.session_resumed {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::TLS_SESSION_RESUMED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Transport,
            Severity::Info,
            Confidence::Certain,
            ctx.session,
        )
        .title("TLS session resumed: key exchange not observed")
        .description("The server resumed a previous session, so no fresh key exchange was observed and forward-secrecy findings are suppressed for this session.")
        .impact("Resumption analysis is limited to the negotiated parameters; key-exchange judgements require a full handshake capture.")
        .remediation(Remediation::new(
            "No action required; capture a full handshake for complete analysis.",
            &["Force a fresh handshake (disable resumption in a test client) when key-exchange evidence is needed."],
        ))
        .evidence(tls_evidence(
            ctx,
            "session resumption observed",
            EvidenceValue::boolean(true),
        ))
        .build(),
    ]
}

fn cipher_evidence(ctx: &RuleContext<'_>, summary: &str, value: EvidenceValue) -> Evidence {
    Evidence::new(
        EvidenceKind::CipherSuite,
        summary,
        value,
        ctx.session_anchor(),
    )
}

fn suite_label(ctx: &RuleContext<'_>) -> Option<String> {
    ctx.session.tls.as_ref().map(|tls| tls.cipher_suite.label())
}

fn rule_cipher_broken(ctx: &RuleContext<'_>) -> Vec<Finding> {
    // `reject_broken_ciphers` gates reporting like its weak/legacy
    // siblings — the suite is still classified and the evidence recorded;
    // only the finding is suppressed.
    if !ctx.policy.reject_broken_ciphers {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.cipher_suite.strength != CipherStrength::Broken {
        return Vec::new();
    }
    let Some(label) = suite_label(ctx) else {
        return Vec::new();
    };
    vec![
        Finding::builder(
            ids::CIPHER_BROKEN,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Cipher,
            Severity::Critical,
            Confidence::Certain,
            ctx.session,
        )
        .title("Broken cipher suite negotiated")
        .description(&format!(
            "The session negotiated {label}: NULL, EXPORT-grade or anonymous key exchange."
        ))
        .impact("There is no meaningful confidentiality, integrity or server authentication; passive and active attackers both succeed trivially.")
        .remediation(
            Remediation::new(
                "Prohibit broken suites on every negotiating peer.",
                &[
                    "Restrict the client to AEAD suites with ephemeral key exchange.",
                    "Remove NULL, EXPORT and anonymous suites from any server under KIWI control.",
                    "Re-test; a peer that only offers broken suites must not carry mail.",
                ],
            )
            .with_references(&["RFC 9325"]),
        )
        .reference("RFC 9325")
        .evidence(cipher_evidence(
            ctx,
            "negotiated cipher suite",
            EvidenceValue::text(&label),
        ))
        .discriminator(&label)
        .build(),
    ]
}

fn rule_cipher_weak(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.reject_weak_ciphers {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.cipher_suite.strength != CipherStrength::Weak {
        return Vec::new();
    }
    let Some(label) = suite_label(ctx) else {
        return Vec::new();
    };
    vec![
        Finding::builder(
            ids::CIPHER_WEAK,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Cipher,
            Severity::High,
            Confidence::Certain,
            ctx.session,
        )
        .title("Weak cipher suite negotiated")
        .description(&format!(
            "The session negotiated {label}, built on a cryptographically weak primitive (RC4, single DES, 3DES, IDEA or SEED)."
        ))
        .impact("Practical attacks exist against these primitives; recorded traffic can be decrypted and sessions forged.")
        .remediation(
            Remediation::new(
                "Move negotiation to AEAD suites.",
                &["Prefer TLS 1.3 or ECDHE+AES-GCM / ChaCha20-Poly1305 suites.", "Disable RC4, DES, 3DES, IDEA and SEED suites."],
            )
            .with_references(&["RFC 9325"]),
        )
        .reference("RFC 9325")
        .evidence(cipher_evidence(
            ctx,
            "negotiated cipher suite",
            EvidenceValue::text(&label),
        ))
        .discriminator(&label)
        .build(),
    ]
}

fn rule_cipher_legacy(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.report_legacy_ciphers {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.cipher_suite.strength != CipherStrength::Legacy {
        return Vec::new();
    }
    let Some(label) = suite_label(ctx) else {
        return Vec::new();
    };
    vec![
        Finding::builder(
            ids::CIPHER_LEGACY,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Cipher,
            Severity::Low,
            Confidence::Certain,
            ctx.session,
        )
        .title("Legacy cipher suite negotiated")
        .description(&format!(
            "The session negotiated {label}: CBC mode or a deprecated MAC. Functional, but below modern guidance."
        ))
        .impact("Lucky13-style padding-oracle and collision attacks are the concern; migrate before the guidance becomes a mandate.")
        .remediation(
            Remediation::new(
                "Prefer AEAD suites over CBC compositions.",
                &["Enable TLS 1.3 or ECDHE+GCM suites so negotiation settles above CBC."],
            )
            .with_references(&["RFC 9325"]),
        )
        .reference("RFC 9325")
        .evidence(cipher_evidence(
            ctx,
            "negotiated cipher suite",
            EvidenceValue::text(&label),
        ))
        .discriminator(&label)
        .build(),
    ]
}

fn rule_cipher_unrecognized(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.report_unrecognized_parameters {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.cipher_suite.recognized {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::CIPHER_UNRECOGNIZED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Cipher,
            Severity::Info,
            Confidence::Certain,
            ctx.session,
        )
        .title("Cipher suite not recognized")
        .description(&format!(
            "The handshake negotiated suite id 0x{:04x}, absent from the classifier table. No strength judgement is made.",
            tls.cipher_suite.iana_id,
        ))
        .impact("An unrecognized suite may be proprietary, very new, or hostile; strength cannot be asserted either way.")
        .remediation(Remediation::new(
            "Identify the suite before trusting the session.",
            &[
                "Look up the IANA id in the current TLS registry.",
                "Update the classifier table if the suite is legitimate.",
            ],
        ))
        .evidence(cipher_evidence(
            ctx,
            "unrecognized suite id",
            EvidenceValue::number(i64::from(tls.cipher_suite.iana_id)),
        ))
        .build(),
    ]
}

fn kex_evidence(ctx: &RuleContext<'_>, summary: &str, value: EvidenceValue) -> Evidence {
    Evidence::new(
        EvidenceKind::KeyExchange,
        summary,
        value,
        ctx.session_anchor(),
    )
}

/// `true` when key-exchange judgements apply: a handshake exists, is complete,
/// and is not a resumption (resumption performs no fresh key exchange).
fn kex_observable(ctx: &RuleContext<'_>) -> bool {
    ctx.session
        .tls
        .as_ref()
        .map(|tls| tls.handshake_complete && !tls.session_resumed)
        .unwrap_or(false)
}

fn rule_kex_no_forward_secrecy(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.require_forward_secrecy || !kex_observable(ctx) {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.forward_secrecy() != ForwardSecrecy::No {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::KEX_NO_FORWARD_SECRECY,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::KeyExchange,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("Key exchange without forward secrecy")
        .description(&format!(
            "The session used {} key establishment: anyone who later obtains the server's long-term key can decrypt this traffic.",
            tls.cipher_suite.key_exchange.as_str(),
        ))
        .impact("A future server-key compromise retroactively exposes recorded mail; long-lived credentials in the session are the prize.")
        .remediation(
            Remediation::new(
                "Negotiate ephemeral key exchange.",
                &["Prefer ECDHE suites (or TLS 1.3, which is forward-secret by construction).", "Disable static RSA/DH/ECDH suites."],
            )
            .with_references(&["RFC 9325"]),
        )
        .reference("RFC 9325")
        .evidence(kex_evidence(
            ctx,
            "key-exchange mechanism",
            EvidenceValue::text(tls.cipher_suite.key_exchange.as_str()),
        ))
        .evidence(Evidence::new(
            EvidenceKind::ForwardSecrecy,
            "forward-secrecy assessment",
            EvidenceValue::text(tls.forward_secrecy().as_str()),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_kex_unauthenticated(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !kex_observable(ctx) {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if !tls.cipher_suite.key_exchange.is_unauthenticated() {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::KEX_UNAUTHENTICATED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::KeyExchange,
            Severity::Critical,
            Confidence::Certain,
            ctx.session,
        )
        .title("Unauthenticated key exchange")
        .description("The session used anonymous or NULL key exchange: the server never authenticated itself, so any active peer could be speaking.")
        .impact("Man-in-the-middle is trivial; the TLS layer authenticates nothing.")
        .remediation(
            Remediation::new(
                "Require certificate-authenticated suites.",
                &["Disable anonymous and NULL suites everywhere.", "Verify the server presents a chain covering its hostname."],
            )
            .with_references(&["RFC 9325"]),
        )
        .reference("RFC 9325")
        .evidence(kex_evidence(
            ctx,
            "key-exchange mechanism",
            EvidenceValue::text(tls.cipher_suite.key_exchange.as_str()),
        ))
        .build(),
    ]
}

fn rule_kex_unknown(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.report_unrecognized_parameters || !kex_observable(ctx) {
        return Vec::new();
    }
    let Some(tls) = &ctx.session.tls else {
        return Vec::new();
    };
    if tls.forward_secrecy() != ForwardSecrecy::Unknown {
        return Vec::new();
    }
    // Unrecognized suites already report via CIPHER_UNRECOGNIZED; an
    // unrecognized *mechanism inside a recognized suite table* is a distinct gap.
    if !tls.cipher_suite.recognized {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::KEX_UNKNOWN,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::KeyExchange,
            Severity::Info,
            Confidence::Certain,
            ctx.session,
        )
        .title("Key exchange could not be classified")
        .description("The suite is recognized but its forward-secrecy property cannot be established (for example PSK without an ephemeral exchange).")
        .impact("No forward-secrecy claim can be made for this session.")
        .remediation(Remediation::new(
            "Prefer suites with explicit ephemeral exchange.",
            &["Negotiate ECDHE suites or TLS 1.3 so the property is observable."],
        ))
        .evidence(kex_evidence(
            ctx,
            "key-exchange mechanism",
            EvidenceValue::text(tls.cipher_suite.key_exchange.as_str()),
        ))
        .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ConnectionSecurityEvent, Endpoint, Protocol, SessionId, TlsObservation, TlsVersion,
    };
    use crate::rules::SecurityPolicy;

    fn session() -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label("t:smtp:587"),
            Protocol::Smtp,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 587),
            1_700_000_000_000,
        )
    }

    fn engine() -> super::super::RuleEngine {
        super::super::RuleEngine::new(SecurityPolicy::default())
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn tls10_fires_below_floor_and_deprecated() {
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls10, 0xC02F));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::TLS_VERSION_BELOW_FLOOR));
        assert!(ids.contains(&ids::TLS_VERSION_DEPRECATED));
        // ECDHE+GCM is strong: no cipher or kex findings expected.
        assert!(!ids.contains(&ids::CIPHER_BROKEN));
        assert!(!ids.contains(&ids::KEX_NO_FORWARD_SECRECY));
    }

    #[test]
    fn tls13_strong_suite_is_quiet() {
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls13, 0x1301));
        let findings = engine().evaluate_session(&s);
        assert!(
            findings.is_empty(),
            "unexpected findings: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unknown_version_reports_without_guessing() {
        let s = session().with_tls(TlsObservation::from_wire(
            TlsVersion::Unknown(0x0399),
            0xC02F,
        ));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::TLS_VERSION_UNKNOWN));
        // Unknown is indeterminate: must NOT also fire the floor rule.
        assert!(!ids.contains(&ids::TLS_VERSION_BELOW_FLOOR));
    }

    #[test]
    fn rsa_gcm_reports_no_forward_secrecy() {
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls12, 0x009C));
        let findings = engine().evaluate_session(&s);
        assert!(rule_ids(&findings).contains(&ids::KEX_NO_FORWARD_SECRECY));
    }

    #[test]
    fn resumed_session_suppresses_kex_and_notes_limitation() {
        let mut tls = TlsObservation::from_wire(TlsVersion::Tls12, 0x009C);
        tls.session_resumed = true;
        let s = session().with_tls(tls);
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::TLS_SESSION_RESUMED));
        assert!(!ids.contains(&ids::KEX_NO_FORWARD_SECRECY));
    }

    #[test]
    fn null_suite_is_critical() {
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls12, 0x0000));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::CIPHER_BROKEN));
        assert!(ids.contains(&ids::KEX_UNAUTHENTICATED));
        let broken = findings
            .iter()
            .find(|f| f.rule_id == ids::CIPHER_BROKEN)
            .expect("broken finding present");
        assert_eq!(broken.severity, Severity::Critical);
        assert!(broken.has_evidence());
    }

    #[test]
    fn permissive_suppresses_broken_cipher_like_its_siblings() {
        // FOR-4/T-247: `reject_broken_ciphers` gates KIWI-CIPHER-001 the
        // same way `reject_weak_ciphers`/`report_legacy_ciphers` gate
        // CIPHER-002/003 — the suite is still classified upstream.
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls12, 0x0000));
        let findings =
            super::super::RuleEngine::new(SecurityPolicy::permissive()).evaluate_session(&s);
        assert!(!rule_ids(&findings).contains(&ids::CIPHER_BROKEN));
    }

    #[test]
    fn require_tls13_raises_the_effective_floor() {
        // FOR-4/T-247: `require_tls13` is a shorthand floor — a TLS 1.2
        // session is below it even when `min_tls_version` stays at 1.2,
        // and the evidence reports the effective floor.
        let s = session().with_tls(TlsObservation::from_wire(TlsVersion::Tls12, 0xC02F));
        let policy = SecurityPolicy {
            require_tls13: true,
            ..SecurityPolicy::default()
        };
        let findings = super::super::RuleEngine::new(policy).evaluate_session(&s);
        let floor = findings
            .iter()
            .find(|f| f.rule_id == ids::TLS_VERSION_BELOW_FLOOR)
            .expect("TLS 1.2 must be below the raised floor");
        assert!(floor.description.contains("tls1.3"));
    }

    #[test]
    fn missing_handshake_with_tls_classification_is_flagged() {
        use crate::model::TransportSecurity;
        let s = session().with_transport(TransportSecurity::ImplicitTls);
        let findings = engine().evaluate_session(&s);
        assert!(rule_ids(&findings).contains(&ids::TLS_HANDSHAKE_MISSING));
    }
}
