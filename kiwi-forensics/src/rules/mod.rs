//! Deterministic rule engine.
//!
//! Contract:
//! - a rule reads only [`ConnectionSecurityEvent`] fields and the
//!   [`SecurityPolicy`] — never the clock, network or filesystem;
//! - a rule emits a finding only with at least one typed [`Evidence`] item; the
//!   engine drops evidence-less findings and counts them as a diagnostic;
//! - the engine — not the rule — stamps `rule_id` and `rule_version` on emitted
//!   findings, so a finding cannot misreport its producer;
//! - output order is deterministic: severity (worst first), rule id, then
//!   subject identity.

pub mod auth;
pub mod certificate;
pub mod crypto;
pub mod policy;
pub mod transport;

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, FindingCategory};
use crate::model::{ConnectionSecurityEvent, SourceRef};

pub use policy::SecurityPolicy;

/// Stable rule identifiers.
///
/// Code and `docs/contracts/forensics.md` refer to these constants, and a test
/// asserts that every registered rule uses one of them, so rule ids cannot drift
/// silently between documentation and implementation.
pub mod ids {
    /// Plaintext mail transport observed.
    pub const TRANSPORT_PLAINTEXT: &str = "KIWI-TRANSPORT-001";
    /// Plaintext service on an implicit-TLS port (465/993/995).
    pub const TRANSPORT_IMPLICIT_PORT_PLAINTEXT: &str = "KIWI-TRANSPORT-002";
    /// Protocol could not be identified.
    pub const PROTOCOL_UNKNOWN: &str = "KIWI-PROTO-001";
    /// STARTTLS stripping / downgrade indicator.
    pub const STARTTLS_STRIPPING: &str = "KIWI-STARTTLS-001";
    /// Server did not advertise STARTTLS where the protocol expects it.
    pub const STARTTLS_NOT_ADVERTISED: &str = "KIWI-STARTTLS-002";
    /// Server advertised STARTTLS but the client never attempted it.
    pub const STARTTLS_NOT_ATTEMPTED: &str = "KIWI-STARTTLS-003";
    /// Server refused the STARTTLS upgrade.
    pub const STARTTLS_REFUSED: &str = "KIWI-STARTTLS-004";
    /// Negotiated TLS version below the policy floor.
    pub const TLS_VERSION_BELOW_FLOOR: &str = "KIWI-TLS-001";
    /// Negotiated version deprecated by RFC 8996 (TLS 1.0/1.1) or SSL 3.0.
    pub const TLS_VERSION_DEPRECATED: &str = "KIWI-TLS-002";
    /// Negotiated TLS version could not be classified.
    pub const TLS_VERSION_UNKNOWN: &str = "KIWI-TLS-003";
    /// Transport claims TLS but no handshake was observed.
    pub const TLS_HANDSHAKE_MISSING: &str = "KIWI-TLS-004";
    /// Session was resumed, so the key exchange was not observed.
    pub const TLS_SESSION_RESUMED: &str = "KIWI-TLS-005";
    /// Broken cipher suite (NULL/EXPORT/anonymous).
    pub const CIPHER_BROKEN: &str = "KIWI-CIPHER-001";
    /// Weak cipher suite (RC4/3DES/DES/IDEA/SEED).
    pub const CIPHER_WEAK: &str = "KIWI-CIPHER-002";
    /// Legacy cipher suite (CBC mode / deprecated MAC).
    pub const CIPHER_LEGACY: &str = "KIWI-CIPHER-003";
    /// Cipher suite not recognized by the classifier.
    pub const CIPHER_UNRECOGNIZED: &str = "KIWI-CIPHER-004";
    /// Key exchange does not provide forward secrecy.
    pub const KEX_NO_FORWARD_SECRECY: &str = "KIWI-KEX-001";
    /// Key exchange provides no peer authentication (anonymous).
    pub const KEX_UNAUTHENTICATED: &str = "KIWI-KEX-002";
    /// Key exchange could not be classified.
    pub const KEX_UNKNOWN: &str = "KIWI-KEX-003";
    /// Certificate expired relative to the observation time.
    pub const CERT_EXPIRED: &str = "KIWI-CERT-001";
    /// Certificate not yet valid.
    pub const CERT_NOT_YET_VALID: &str = "KIWI-CERT-002";
    /// Certificate expires within the configured warning window.
    pub const CERT_EXPIRING_SOON: &str = "KIWI-CERT-003";
    /// Self-issued certificate presented alone.
    pub const CERT_SELF_ISSUED: &str = "KIWI-CERT-004";
    /// Certificate identity does not cover the server name.
    pub const CERT_HOSTNAME_MISMATCH: &str = "KIWI-CERT-005";
    /// MD2/MD5 certificate signature.
    pub const CERT_BROKEN_SIGNATURE: &str = "KIWI-CERT-006";
    /// SHA-1 certificate signature.
    pub const CERT_DEPRECATED_SIGNATURE: &str = "KIWI-CERT-007";
    /// Public key below the configured minimum size.
    pub const CERT_WEAK_KEY: &str = "KIWI-CERT-008";
    /// Public-key algorithm not recommended for mail TLS.
    pub const CERT_DISCOURAGED_KEY_ALGORITHM: &str = "KIWI-CERT-009";
    /// Presented chain was truncated by the capture or the adapter.
    pub const CERT_CHAIN_TRUNCATED: &str = "KIWI-CERT-010";
    /// No trust layer validated the presented chain.
    pub const CERT_TRUST_NOT_VALIDATED: &str = "KIWI-CERT-011";
    /// A trust layer rejected the chain.
    pub const CERT_TRUST_REJECTED: &str = "KIWI-CERT-012";
    /// A reusable credential crossed an unprotected channel.
    pub const AUTH_REUSABLE_SECRET_EXPOSED: &str = "KIWI-AUTH-001";
    /// Deprecated authentication mechanism in use.
    pub const AUTH_DEPRECATED_MECHANISM: &str = "KIWI-AUTH-002";
    /// Authentication failure observed.
    pub const AUTH_FAILURE: &str = "KIWI-AUTH-003";
    /// Repeated authentication failures (possible credential guessing).
    pub const AUTH_REPEATED_FAILURES: &str = "KIWI-AUTH-004";
    /// MD5-based authentication mechanism.
    pub const AUTH_MD5_MECHANISM: &str = "KIWI-AUTH-005";
    /// No authentication observed on a protected session.
    pub const AUTH_NOT_OBSERVED: &str = "KIWI-AUTH-006";
}

/// Inputs available to a rule.
#[derive(Debug, Clone, Copy)]
pub struct RuleContext<'a> {
    /// Session being evaluated.
    pub session: &'a ConnectionSecurityEvent,
    /// Policy in force.
    pub policy: &'a SecurityPolicy,
}

impl RuleContext<'_> {
    /// Evidence anchor for the session as a whole.
    pub fn session_anchor(&self) -> SourceRef {
        self.session
            .sources
            .first()
            .cloned()
            .unwrap_or_else(|| SourceRef::session_only(self.session.id.clone()))
    }
}

/// A deterministic security rule.
pub trait Rule: Send + Sync {
    /// Stable rule id (see [`ids`]).
    fn id(&self) -> &'static str;
    /// Rule implementation version.
    fn version(&self) -> u16 {
        crate::RULE_CATALOG_VERSION
    }
    /// Subject area.
    fn category(&self) -> FindingCategory;
    /// One-line title.
    fn title(&self) -> &'static str;
    /// What the rule detects, in one sentence.
    fn description(&self) -> &'static str;
    /// Evaluate the rule for one session.
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding>;
}

/// Rule implemented by a plain function with a static descriptor.
///
/// Chosen over one struct per rule so the catalog stays a single readable list
/// and every rule body sits next to the evidence it constructs.
pub struct FnRule {
    id: &'static str,
    category: FindingCategory,
    title: &'static str,
    description: &'static str,
    evaluate: fn(&RuleContext<'_>) -> Vec<Finding>,
}

impl FnRule {
    /// Register a rule function.
    pub fn new(
        id: &'static str,
        category: FindingCategory,
        title: &'static str,
        description: &'static str,
        evaluate: fn(&RuleContext<'_>) -> Vec<Finding>,
    ) -> Self {
        FnRule {
            id,
            category,
            title,
            description,
            evaluate,
        }
    }
}

impl Rule for FnRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn category(&self) -> FindingCategory {
        self.category
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        (self.evaluate)(ctx)
    }
}

/// Machine-readable description of a registered rule (docs, UI, audits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDescriptor {
    /// Stable rule id.
    pub id: String,
    /// Rule version.
    pub version: u16,
    /// Subject area.
    pub category: FindingCategory,
    /// One-line title.
    pub title: String,
    /// What the rule detects.
    pub description: String,
}

/// Engine run diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationDiagnostics {
    /// Sessions evaluated.
    pub sessions_evaluated: u32,
    /// Findings dropped because they carried no evidence.
    ///
    /// Must always be zero in production; surfaced rather than swallowed so a
    /// rule bug is visible instead of silently reducing findings.
    pub dropped_without_evidence: u32,
}

/// The rule engine: a policy plus an ordered set of rules.
pub struct RuleEngine {
    policy: SecurityPolicy,
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    /// Build the default engine for a policy.
    pub fn new(policy: SecurityPolicy) -> Self {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        transport::register(&mut rules);
        crypto::register(&mut rules);
        certificate::register(&mut rules);
        auth::register(&mut rules);
        RuleEngine { policy, rules }
    }

    /// Build an engine from an explicit rule set (tests, or callers wanting a subset).
    pub fn with_rules(policy: SecurityPolicy, rules: Vec<Box<dyn Rule>>) -> Self {
        RuleEngine { policy, rules }
    }

    /// Policy in force.
    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    /// Registered rule descriptors, in registration order.
    pub fn catalog(&self) -> Vec<RuleDescriptor> {
        self.rules
            .iter()
            .map(|rule| RuleDescriptor {
                id: rule.id().to_string(),
                version: rule.version(),
                category: rule.category(),
                title: rule.title().to_string(),
                description: rule.description().to_string(),
            })
            .collect()
    }

    /// Evaluate one session.
    pub fn evaluate_session(&self, session: &ConnectionSecurityEvent) -> Vec<Finding> {
        self.evaluate_session_with_diagnostics(session).0
    }

    /// Evaluate one session, returning findings plus diagnostics.
    pub fn evaluate_session_with_diagnostics(
        &self,
        session: &ConnectionSecurityEvent,
    ) -> (Vec<Finding>, EvaluationDiagnostics) {
        let ctx = RuleContext {
            session,
            policy: &self.policy,
        };
        let mut findings: Vec<Finding> = Vec::new();
        let mut diagnostics = EvaluationDiagnostics {
            sessions_evaluated: 1,
            dropped_without_evidence: 0,
        };
        for rule in &self.rules {
            for mut finding in rule.evaluate(&ctx) {
                // The engine is authoritative for provenance.
                finding.rule_id = rule.id().to_string();
                finding.rule_version = rule.version();
                if finding.has_evidence() {
                    findings.push(finding);
                } else {
                    diagnostics.dropped_without_evidence += 1;
                }
            }
        }
        sort_findings(&mut findings);
        (findings, diagnostics)
    }

    /// Evaluate many sessions, returning findings plus diagnostics.
    pub fn evaluate_with_diagnostics(
        &self,
        sessions: &[ConnectionSecurityEvent],
    ) -> (Vec<Finding>, EvaluationDiagnostics) {
        let mut all = Vec::new();
        let mut diagnostics = EvaluationDiagnostics::default();
        for session in sessions {
            let (findings, session_diagnostics) = self.evaluate_session_with_diagnostics(session);
            diagnostics.sessions_evaluated += session_diagnostics.sessions_evaluated;
            diagnostics.dropped_without_evidence += session_diagnostics.dropped_without_evidence;
            all.extend(findings);
        }
        sort_findings(&mut all);
        (all, diagnostics)
    }

    /// Evaluate many sessions (findings only).
    pub fn evaluate(&self, sessions: &[ConnectionSecurityEvent]) -> Vec<Finding> {
        self.evaluate_with_diagnostics(sessions).0
    }
}

/// Deterministic finding order: severity (worst first), rule id, subject.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.subject.key_text().cmp(&b.subject.key_text()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });
}
