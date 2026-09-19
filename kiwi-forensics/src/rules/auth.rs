//! Authentication-observation rules.
//!
//! The model classifies credential exposure
//! ([`AuthObservation::exposes_reusable_secret`]); rules map mechanism,
//! outcome and channel observations to findings. An unrecognized mechanism
//! asserts nothing — there is deliberately no rule for it.

use super::{FnRule, Rule, RuleContext, ids};
use crate::findings::{
    Confidence, Evidence, EvidenceKind, EvidenceValue, Finding, FindingCategory, Remediation,
    Severity,
};

/// Register the authentication rules.
pub fn register(rules: &mut Vec<Box<dyn Rule>>) {
    rules.push(Box::new(FnRule::new(
        ids::AUTH_REUSABLE_SECRET_EXPOSED,
        FindingCategory::Authentication,
        "Reusable credential crossed an unprotected channel",
        "Detects a password or bearer token observed where no TLS protects it.",
        rule_reusable_secret_exposed,
    )));
    rules.push(Box::new(FnRule::new(
        ids::AUTH_DEPRECATED_MECHANISM,
        FindingCategory::Authentication,
        "Deprecated authentication mechanism in use",
        "Detects PLAIN, LOGIN, ANONYMOUS or MD5-based mechanisms.",
        rule_deprecated_mechanism,
    )));
    rules.push(Box::new(FnRule::new(
        ids::AUTH_FAILURE,
        FindingCategory::Authentication,
        "Authentication failure observed",
        "Records observed authentication failures below the guessing threshold.",
        rule_auth_failure,
    )));
    rules.push(Box::new(FnRule::new(
        ids::AUTH_REPEATED_FAILURES,
        FindingCategory::Authentication,
        "Repeated authentication failures",
        "Detects failure counts at or above the guessing threshold.",
        rule_repeated_failures,
    )));
    rules.push(Box::new(FnRule::new(
        ids::AUTH_MD5_MECHANISM,
        FindingCategory::Authentication,
        "MD5-based authentication mechanism",
        "Detects CRAM-MD5 or DIGEST-MD5: challenge-response, but MD5.",
        rule_md5_mechanism,
    )));
    rules.push(Box::new(FnRule::new(
        ids::AUTH_NOT_OBSERVED,
        FindingCategory::Authentication,
        "No authentication observed on a protected session",
        "Records that a protected session carried no visible authentication.",
        rule_auth_not_observed,
    )));
}

fn mechanism_evidence(ctx: &RuleContext<'_>, summary: &str, mechanism: &str) -> Evidence {
    Evidence::new(
        EvidenceKind::AuthMechanism,
        summary,
        EvidenceValue::text(mechanism),
        ctx.session_anchor(),
    )
}

fn observed_mechanism(ctx: &RuleContext<'_>) -> Option<&'static str> {
    ctx.session
        .auth
        .as_ref()
        .and_then(|auth| auth.mechanism)
        .map(|m| m.as_str())
}

fn rule_reusable_secret_exposed(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(auth) = &ctx.session.auth else {
        return Vec::new();
    };
    if !auth.exposes_reusable_secret(ctx.session.is_encrypted()) {
        return Vec::new();
    }
    let mechanism = observed_mechanism(ctx).unwrap_or("unobserved");
    vec![
        Finding::builder(
            ids::AUTH_REUSABLE_SECRET_EXPOSED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Critical,
            Confidence::Certain,
            ctx.session,
        )
        .title("Reusable credential crossed an unprotected channel")
        .description(&format!(
            "A {mechanism} credential was observed without TLS protection: a passive observer can reuse it directly."
        ))
        .impact("Account takeover with no further effort — the credential is the account until it is rotated.")
        .remediation(
            Remediation::new(
                "Stop sending reusable credentials in the clear and rotate the exposed one.",
                &[
                    "Require TLS before authentication on this account.",
                    "Change the password or revoke the token that was exposed.",
                    "Prefer SCRAM or OAuth bearer flows over cleartext passwords even under TLS.",
                ],
            ),
        )
        .evidence(mechanism_evidence(
            ctx,
            "authentication mechanism carrying the credential",
            mechanism,
        ))
        .evidence(Evidence::new(
            EvidenceKind::AuthOutcome,
            "reusable secret exposed to a passive observer",
            EvidenceValue::boolean(true),
            ctx.session_anchor(),
        ))
        .discriminator(mechanism)
        .build(),
    ]
}

fn rule_deprecated_mechanism(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if !ctx.policy.report_deprecated_auth {
        return Vec::new();
    }
    let Some(auth) = &ctx.session.auth else {
        return Vec::new();
    };
    let Some(mechanism) = auth.mechanism else {
        return Vec::new();
    };
    if !mechanism.is_deprecated() {
        return Vec::new();
    }
    let name = mechanism.as_str();
    vec![
        Finding::builder(
            ids::AUTH_DEPRECATED_MECHANISM,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("Deprecated authentication mechanism in use")
        .description(&format!(
            "The session authenticated with {name}, which modern guidance asks clients to avoid."
        ))
        .impact("Cleartext-equivalent passwords, MD5 challenge-response or anonymous access widen every other weakness in the session.")
        .remediation(
            Remediation::new(
                "Migrate to a modern mechanism.",
                &["Prefer SCRAM-SHA-256(-PLUS) or OAuth bearer flows.", "Disable PLAIN/LOGIN except inside correctly negotiated TLS, and retire CRAM-MD5/DIGEST-MD5/NTLM."],
            ),
        )
        .evidence(mechanism_evidence(
            ctx,
            "deprecated mechanism observed",
            name,
        ))
        .discriminator(name)
        .build(),
    ]
}

fn rule_auth_failure(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(auth) = &ctx.session.auth else {
        return Vec::new();
    };
    if !auth.has_failures() || auth.failures >= ctx.policy.max_auth_failures {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::AUTH_FAILURE,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Low,
            Confidence::Certain,
            ctx.session,
        )
        .title("Authentication failure observed")
        .description(&format!(
            "The session shows {} failed authentication attempt(s): wrong credentials, or the start of guessing.",
            auth.failures.max(1),
        ))
        .impact("A single failure is usually user error; the record matters because repeated failures escalate to a guessing finding.")
        .remediation(Remediation::new(
            "Verify the stored credential if the failure repeats.",
            &["Check the account password or token; investigate the peer if failures accumulate."],
        ))
        .evidence(Evidence::new(
            EvidenceKind::AuthOutcome,
            "failed authentication attempts observed",
            EvidenceValue::number(i64::from(auth.failures)),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_repeated_failures(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(auth) = &ctx.session.auth else {
        return Vec::new();
    };
    if auth.failures < ctx.policy.max_auth_failures {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::AUTH_REPEATED_FAILURES,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("Repeated authentication failures")
        .description(&format!(
            "The session shows {} failed attempts, at or above the guessing threshold of {}.",
            auth.failures, ctx.policy.max_auth_failures,
        ))
        .impact("Sustained failures indicate credential guessing or a stuck client hammering a revoked credential; either way the account is under pressure.")
        .remediation(
            Remediation::new(
                "Treat the account as probed.",
                &[
                    "Rate-limit or block the source if it is remote.",
                    "Rotate the credential if guessing cannot be ruled out.",
                    "Check the audit log for parallel attempts on sibling accounts.",
                ],
            ),
        )
        .evidence(Evidence::new(
            EvidenceKind::AuthOutcome,
            "failed attempts at or above threshold",
            EvidenceValue::number(i64::from(auth.failures)),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

fn rule_md5_mechanism(ctx: &RuleContext<'_>) -> Vec<Finding> {
    let Some(auth) = &ctx.session.auth else {
        return Vec::new();
    };
    let Some(mechanism) = auth.mechanism else {
        return Vec::new();
    };
    if !mechanism.uses_md5() {
        return Vec::new();
    }
    let name = mechanism.as_str();
    vec![
        Finding::builder(
            ids::AUTH_MD5_MECHANISM,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Medium,
            Confidence::Certain,
            ctx.session,
        )
        .title("MD5-based authentication mechanism")
        .description(&format!(
            "The session used {name}: challenge-response, but built on collision-broken MD5."
        ))
        .impact("Offline dictionary attacks against captured challenges are practical; the mechanism gives less protection than its challenge-response shape suggests.")
        .remediation(
            Remediation::new(
                "Replace MD5 mechanisms with SCRAM-SHA-256 or better.",
                &["Disable CRAM-MD5 and DIGEST-MD5 on clients and servers under KIWI control."],
            ),
        )
        .evidence(mechanism_evidence(ctx, "MD5-based mechanism observed", name))
        .discriminator(name)
        .build(),
    ]
}

fn rule_auth_not_observed(ctx: &RuleContext<'_>) -> Vec<Finding> {
    if ctx.session.auth.is_some() || !ctx.session.is_encrypted() {
        return Vec::new();
    }
    vec![
        Finding::builder(
            ids::AUTH_NOT_OBSERVED,
            crate::RULE_CATALOG_VERSION,
            FindingCategory::Authentication,
            Severity::Info,
            Confidence::Firm,
            ctx.session,
        )
        .title("No authentication observed on a protected session")
        .description("The session is TLS-protected but no authentication exchange was visible: the capture may predate it, or the session is genuinely anonymous.")
        .impact("Without an observed login, account-scoped conclusions cannot be drawn for this session.")
        .remediation(Remediation::new(
            "Capture the session from authentication onward when account context matters.",
            &["Ensure analysis starts before the AUTH exchange."],
        ))
        .evidence(Evidence::new(
            EvidenceKind::AuthOutcome,
            "no authentication exchange visible on a protected session",
            EvidenceValue::boolean(false),
            ctx.session_anchor(),
        ))
        .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthMechanism, AuthObservation, ConnectionSecurityEvent, Endpoint, Protocol, SessionId,
        TransportSecurity,
    };
    use crate::rules::SecurityPolicy;

    fn plaintext_session(auth: AuthObservation) -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label("t:smtp:25"),
            Protocol::Smtp,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 25),
            1_700_000_000_000,
        )
        .with_transport(TransportSecurity::Plaintext)
        .with_auth(auth)
    }

    fn engine() -> super::super::RuleEngine {
        super::super::RuleEngine::new(SecurityPolicy::default())
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn cleartext_login_in_plaintext_is_critical() {
        let s = plaintext_session(AuthObservation::with_outcome(AuthMechanism::Login, true));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::AUTH_REUSABLE_SECRET_EXPOSED));
        assert!(ids.contains(&ids::AUTH_DEPRECATED_MECHANISM));
        let exposed = findings
            .iter()
            .find(|f| f.rule_id == ids::AUTH_REUSABLE_SECRET_EXPOSED)
            .expect("exposure finding present");
        assert_eq!(exposed.severity, Severity::Critical);
        assert!(exposed.has_evidence());
    }

    #[test]
    fn protected_login_is_not_an_exposure() {
        let s = ConnectionSecurityEvent::new(
            SessionId::from_label("t:imap:993"),
            Protocol::Imap,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 993),
            1_700_000_000_000,
        )
        .with_transport(TransportSecurity::ImplicitTls)
        .with_auth(AuthObservation::with_outcome(AuthMechanism::Login, true));
        let findings = engine().evaluate_session(&s);
        assert!(
            !rule_ids(&findings).contains(&ids::AUTH_REUSABLE_SECRET_EXPOSED),
            "TLS-protected password is not exposed to a passive observer"
        );
    }

    #[test]
    fn failures_escalate_at_threshold() {
        let mut auth = AuthObservation::with_outcome(AuthMechanism::Plain, false);
        auth.failures = 2;
        let below = engine().evaluate_session(&plaintext_session(auth.clone()));
        assert!(rule_ids(&below).contains(&ids::AUTH_FAILURE));
        assert!(!rule_ids(&below).contains(&ids::AUTH_REPEATED_FAILURES));
        auth.failures = 3;
        let at = engine().evaluate_session(&plaintext_session(auth));
        assert!(rule_ids(&at).contains(&ids::AUTH_REPEATED_FAILURES));
        assert!(
            !rule_ids(&at).contains(&ids::AUTH_FAILURE),
            "threshold finding replaces the single-failure record"
        );
    }

    #[test]
    fn unknown_mechanism_asserts_nothing() {
        let s = plaintext_session(AuthObservation::new(AuthMechanism::Unknown));
        let findings = engine().evaluate_session(&s);
        assert!(
            !findings
                .iter()
                .any(|f| f.category == FindingCategory::Authentication),
            "unknown mechanism must not produce auth findings"
        );
    }

    #[test]
    fn cram_md5_reports_md5_and_deprecated() {
        let s = plaintext_session(AuthObservation::new(AuthMechanism::CramMd5));
        let findings = engine().evaluate_session(&s);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&ids::AUTH_MD5_MECHANISM));
        assert!(ids.contains(&ids::AUTH_DEPRECATED_MECHANISM));
        // Challenge-response leaks no reusable secret even in the clear.
        assert!(!ids.contains(&ids::AUTH_REUSABLE_SECRET_EXPOSED));
    }
}
