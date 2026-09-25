//! Forensic report aggregate + JSON renderer.
//!
//! A [`Report`] is the crate's top-level output: versioned provenance, the
//! findings, the deterministic score, explicit [`Limitation`]s for everything
//! the input could not establish, and optional [`AiEnrichment`] that must
//! cite the deterministic keys it grounds in (contract §8, prompt.md §12).
//! JSON is the canonical rendering; HTML/PDF are views over this aggregate.

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, FindingKey};
use crate::model::SafeText;
use crate::score::{SecurityScore, score_findings};

/// Limitation codes: facts the input could not establish.
///
/// A limitation is never a peer fault — it records where analysis stopped so
/// a reader cannot mistake absence of evidence for evidence of health.
pub mod limitation_codes {
    /// Capture-only input: no trust layer validated the chain.
    pub const CHAIN_UNVERIFIED: &str = "chain-unverified";
    /// Resumed session or missing handshake: no fresh key exchange observed.
    pub const KEX_UNOBSERVED: &str = "kex-unobserved";
    /// Session protocol could not be identified.
    pub const PROTOCOL_UNKNOWN: &str = "protocol-unknown";
    /// Protected session with no visible authentication exchange.
    pub const AUTH_UNOBSERVED: &str = "auth-unobserved";
    /// Transport classification unknown.
    pub const TRANSPORT_UNKNOWN: &str = "transport-unknown";
    /// AI enrichment cited finding keys absent from this report.
    pub const AI_UNCITED_KEYS: &str = "ai-uncited-keys";
    /// Reassembled stream(s) had TCP sequence gaps; bytes across the gaps
    /// were not analyzed.
    pub const STREAM_GAP: &str = "stream-gap";
    /// Reassembly bounds dropped segments or refused flows; those bytes
    /// were not analyzed.
    pub const CAPTURE_OVER_LIMIT: &str = "capture-over-limit";
    /// The engine dropped finding(s) for lack of evidence; a rule needs
    /// review (must be 0 in production).
    pub const EVIDENCELESS_DROPPED: &str = "rule-dropped-without-evidence";
}

/// One explicit boundary of the analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limitation {
    /// Stable code (`limitation_codes::*`).
    pub code: String,
    /// What could not be established, in one sanitized sentence.
    pub detail: String,
}

impl Limitation {
    /// Build a limitation (sanitized and bounded).
    pub fn new(code: &str, detail: &str) -> Self {
        Limitation {
            code: SafeText::new(code).as_str().to_string(),
            detail: SafeText::new(detail).as_str().to_string(),
        }
    }
}

/// Evidence-marker codes a session substantiates (contract §8).
///
/// Pure over the record: a code means the *observation* could not show the
/// thing — resumed sessions, missing handshakes, invisible auth — never that
/// the peer failed at it. Aggregation paths (capture pipeline, live report)
/// count these per session and emit one limitation per code.
pub fn session_limitation_codes(
    session: &crate::model::ConnectionSecurityEvent,
) -> Vec<&'static str> {
    let mut codes = Vec::with_capacity(3);
    if session.transport == crate::model::TransportSecurity::Unknown {
        codes.push(limitation_codes::TRANSPORT_UNKNOWN);
    }
    // Resumed/partial handshake, or a STARTTLS upgrade the server accepted
    // whose handshake bytes the capture never showed.
    let kex_unobserved = session
        .tls
        .as_ref()
        .is_some_and(|t| t.session_resumed || !t.handshake_complete)
        || session
            .starttls
            .as_ref()
            .is_some_and(|s| s.server_reply_ok == Some(true) && !s.handshake_completed);
    if kex_unobserved {
        codes.push(limitation_codes::KEX_UNOBSERVED);
    }
    if session.is_encrypted() && session.auth.as_ref().is_none_or(|a| a.attempts == 0) {
        codes.push(limitation_codes::AUTH_UNOBSERVED);
    }
    codes
}

/// AI-authored text grounded in deterministic findings.
///
/// Never authoritative: consumers must render it alongside the cited
/// findings, labeled as AI-generated. The builder moves citations to keys
/// absent from the report into an `ai-uncited-keys` limitation instead of
/// silently keeping them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiEnrichment {
    /// Deterministic finding keys this text grounds in (`finding_id()` form).
    pub finding_keys: Vec<String>,
    /// The AI-authored text (bounded, sanitized).
    pub text: String,
    /// Model that produced the text, for auditability.
    pub model_id: String,
}

impl AiEnrichment {
    /// Build enrichment (sanitized and bounded).
    pub fn new(finding_keys: Vec<String>, text: &str, model_id: &str) -> Self {
        AiEnrichment {
            finding_keys: finding_keys
                .into_iter()
                .take(64)
                .map(|k| SafeText::new(&k).as_str().to_string())
                .collect(),
            text: SafeText::new(text).as_str().to_string(),
            model_id: SafeText::new(model_id).as_str().to_string(),
        }
    }
}

/// Top-level forensic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Finding/evidence/report contract version (`kiwi.forensics/2`).
    pub contract_version: String,
    /// Scoring model version (`kiwi-score-2`).
    pub scoring_model_version: String,
    /// Rule catalog version the findings were produced with.
    pub rule_catalog_version: u16,
    /// What was analyzed (account label, capture name, …).
    pub scope: String,
    /// Sessions evaluated.
    pub sessions_evaluated: u32,
    /// Findings, worst-first (see `sort_findings`).
    pub findings: Vec<Finding>,
    /// Deterministic score over the findings.
    pub score: SecurityScore,
    /// Explicit analysis boundaries.
    pub limitations: Vec<Limitation>,
    /// Optional AI-authored grounding-checked text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_enrichment: Option<AiEnrichment>,
    /// Provenance: `"live"`, capture path, or `"test-fixture"`.
    pub generated_from: String,
}

/// Assemble a [`Report`] from evaluated findings.
#[derive(Debug, Clone)]
pub struct ReportBuilder {
    scope: String,
    sessions_evaluated: u32,
    findings: Vec<Finding>,
    limitations: Vec<Limitation>,
    ai_enrichment: Option<AiEnrichment>,
    generated_from: String,
}

impl ReportBuilder {
    /// Start a report for a scope.
    pub fn new(scope: &str, generated_from: &str) -> Self {
        ReportBuilder {
            scope: SafeText::new(scope).as_str().to_string(),
            sessions_evaluated: 0,
            findings: Vec::new(),
            limitations: Vec::new(),
            ai_enrichment: None,
            generated_from: SafeText::new(generated_from).as_str().to_string(),
        }
    }

    /// Record evaluated sessions and their findings.
    pub fn add_session_findings(mut self, sessions: u32, findings: Vec<Finding>) -> Self {
        self.sessions_evaluated += sessions;
        self.findings.extend(findings);
        self
    }

    /// Record an analysis boundary.
    pub fn limitation(mut self, limitation: Limitation) -> Self {
        self.limitations.push(limitation);
        self
    }

    /// Attach AI text after grounding it in the report's findings.
    ///
    /// Citations to finding keys absent from this report are dropped from
    /// the enrichment and recorded as an `ai-uncited-keys` limitation, so
    /// ungrounded AI text can never pass as grounded.
    pub fn ai_enrichment(mut self, enrichment: AiEnrichment) -> Self {
        let known: Vec<String> = self.findings.iter().map(|f| f.finding_id()).collect();
        let (kept, dropped): (Vec<String>, Vec<String>) = enrichment
            .finding_keys
            .into_iter()
            .partition(|key| known.iter().any(|k| k == key));
        if !dropped.is_empty() {
            self.limitations.push(Limitation::new(
                limitation_codes::AI_UNCITED_KEYS,
                &format!(
                    "AI enrichment cited {} unknown finding key(s); citations dropped.",
                    dropped.len()
                ),
            ));
        }
        self.ai_enrichment = Some(AiEnrichment {
            finding_keys: kept,
            text: enrichment.text,
            model_id: enrichment.model_id,
        });
        self
    }

    /// Finish the report, scoring the findings with the default policy.
    pub fn build(mut self) -> Report {
        crate::rules::sort_findings(&mut self.findings);
        let score = score_findings(&self.findings, &crate::score::ScoringPolicy::default());
        Report {
            contract_version: crate::CONTRACT_VERSION.to_string(),
            scoring_model_version: crate::SCORING_MODEL_VERSION.to_string(),
            rule_catalog_version: crate::RULE_CATALOG_VERSION,
            scope: self.scope,
            sessions_evaluated: self.sessions_evaluated,
            findings: self.findings,
            score,
            limitations: self.limitations,
            ai_enrichment: self.ai_enrichment,
            generated_from: self.generated_from,
        }
    }
}

impl Report {
    /// Canonical JSON rendering (pretty).
    ///
    /// Serialization of this shape cannot fail (all fields are plain
    /// serializable data); the fallback preserves totality without panicking.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| String::from("{}"))
    }

    /// Parse a report back (import, re-scan comparison).
    pub fn from_json(json: &str) -> serde_json::Result<Report> {
        serde_json::from_str(json)
    }

    /// Stable finding keys for re-scan comparison.
    pub fn finding_keys(&self) -> Vec<FindingKey> {
        self.findings.iter().map(|f| f.key()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        Confidence, Evidence, EvidenceKind, EvidenceValue, FindingCategory, Severity,
    };
    use crate::model::{
        AuthMechanism, AuthObservation, ConnectionSecurityEvent, Endpoint, Protocol, SessionId,
        SourceRef, StartTlsObservation, TlsObservation, TlsVersion, TransportSecurity,
    };

    fn session() -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label("t:smtp:587"),
            Protocol::Smtp,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 587),
            1_700_000_000_000,
        )
    }

    fn finding() -> Finding {
        Finding::builder(
            "KIWI-TRANSPORT-001",
            1,
            FindingCategory::Transport,
            Severity::High,
            Confidence::Certain,
            &session(),
        )
        .title("t")
        .description("d")
        .impact("i")
        .evidence(Evidence::new(
            EvidenceKind::TransportState,
            "s",
            EvidenceValue::text("plaintext"),
            SourceRef::session_only(SessionId::from_label("t:smtp:587")),
        ))
        .build()
    }

    #[test]
    fn json_round_trip_preserves_report() {
        let report = ReportBuilder::new("account:test", "test-fixture")
            .add_session_findings(1, vec![finding()])
            .limitation(Limitation::new(
                limitation_codes::CHAIN_UNVERIFIED,
                "capture-only input",
            ))
            .build();
        assert_eq!(
            report.score.score, 75,
            "one High/Certain finding deducts 25"
        );
        let json = report.to_json();
        let back = Report::from_json(&json).expect("report parses");
        assert_eq!(back, report);
    }

    #[test]
    fn ungrounded_ai_citations_become_limitations() {
        let f = finding();
        let key = f.finding_id();
        let enrichment = AiEnrichment::new(
            vec![key, "KIWI-TLS-001|smtp:other.test:25".to_string()],
            "summary text",
            "test-model",
        );
        let report = ReportBuilder::new("account:test", "test-fixture")
            .add_session_findings(1, vec![f])
            .ai_enrichment(enrichment)
            .build();
        let ai = report.ai_enrichment.expect("enrichment kept");
        assert_eq!(ai.finding_keys.len(), 1, "unknown citation dropped");
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.code == limitation_codes::AI_UNCITED_KEYS),
            "drop recorded as limitation"
        );
    }

    // FOR-10: the promised evidence markers must classify real session
    // states and must not fire where the fact was observed.
    #[test]
    fn limitation_codes_classify_unobserved_facts() {
        let base = session();
        // Default fixture: transport Unknown, no tls, no auth → only the
        // transport marker applies (unprotected, so auth-unobserved cannot).
        assert_eq!(
            session_limitation_codes(&base),
            vec![limitation_codes::TRANSPORT_UNKNOWN]
        );

        // Resumed session: TLS observed, no fresh key exchange.
        let resumed = {
            let mut s = session().with_transport(TransportSecurity::ImplicitTls);
            let mut tls = TlsObservation::from_wire(TlsVersion::Tls13, 0x1301);
            tls.session_resumed = true;
            s = s.with_tls(tls);
            s
        };
        let codes = session_limitation_codes(&resumed);
        assert!(codes.contains(&limitation_codes::KEX_UNOBSERVED));
        assert!(codes.contains(&limitation_codes::AUTH_UNOBSERVED));

        // Incomplete handshake (capture dropped handshake bytes).
        let partial = {
            let mut s = session().with_transport(TransportSecurity::ImplicitTls);
            let mut tls = TlsObservation::from_wire(TlsVersion::Tls12, 0xC02F);
            tls.handshake_complete = false;
            s = s.with_tls(tls);
            s
        };
        assert!(
            session_limitation_codes(&partial).contains(&limitation_codes::KEX_UNOBSERVED),
            "missing handshake is unobserved key exchange"
        );

        // STARTTLS accepted but handshake never observed in the capture.
        let upgrade_unseen = session()
            .with_transport(TransportSecurity::Plaintext)
            .with_starttls(StartTlsObservation {
                handshake_completed: false,
                ..StartTlsObservation::upgraded()
            });
        assert!(
            session_limitation_codes(&upgrade_unseen).contains(&limitation_codes::KEX_UNOBSERVED),
            "accepted upgrade without observed handshake"
        );

        // Healthy observed session: no markers at all.
        let healthy = session()
            .with_transport(TransportSecurity::ImplicitTls)
            .with_tls(TlsObservation::from_wire(TlsVersion::Tls13, 0x1301))
            .with_auth(AuthObservation::with_outcome(AuthMechanism::Plain, true));
        assert!(
            session_limitation_codes(&healthy).is_empty(),
            "fully observed session emits nothing"
        );

        // Protected + zero-attempt auth exchange still counts as unobserved.
        let zero_attempts = session()
            .with_transport(TransportSecurity::ImplicitTls)
            .with_tls(TlsObservation::from_wire(TlsVersion::Tls13, 0x1301))
            .with_auth(AuthObservation {
                mechanism: None,
                succeeded: None,
                attempts: 0,
                failures: 0,
            });
        assert!(
            session_limitation_codes(&zero_attempts).contains(&limitation_codes::AUTH_UNOBSERVED)
        );
    }
}
