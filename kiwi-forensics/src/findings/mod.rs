//! Findings, evidence and re-scan diffs.
//!
//! A [`Finding`] is the only thing this crate reports. It is always backed by
//! typed [`Evidence`] carrying a [`crate::model::SourceRef`] chain of custody,
//! so no conclusion can exist without the bytes that produced it
//! (`prompt.md` §2.5).
//!
//! Severity and confidence are assigned by rules from a fixed table — never by
//! AI, never by a floating-point heuristic (`prompt.md` §12).

pub mod diff;

use serde::{Deserialize, Serialize};

use crate::model::{Protocol, SafeText, SessionId, SourceRef};

/// How serious a finding is.
///
/// Ordering is meaningful (`Info < Low < … < Critical`) so reports sort by
/// severity without a lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context only; contributes no score deduction.
    Info,
    /// Hardening opportunity.
    Low,
    /// Real weakness with limited direct impact.
    Medium,
    /// Weakness that undermines confidentiality, integrity or authentication.
    High,
    /// No confidentiality/integrity/authentication, or credential exposure.
    Critical,
}

impl Severity {
    /// All severities, weakest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Score points deducted at full weight (see [`crate::score`]).
    pub fn weight_points(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 12,
            Severity::High => 25,
            Severity::Critical => 40,
        }
    }

    /// Stable lowercase identifier for JSON output and finding ids.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// How certain the *observation* behind a finding is.
///
/// Deliberately about evidence strength, not severity: a `Tentative` finding can
/// still be `Critical`, and the scorer reduces its weight accordingly
/// ([`Confidence::multiplier_bp`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The input could support this, but evidence is incomplete (for example a
    /// truncated capture).
    Tentative,
    /// Strong evidence with a stated caveat (for example a stripping indicator
    /// that depends on the capture point observing both peers).
    Firm,
    /// Directly observed, not open to more than one reading.
    Certain,
}

impl Confidence {
    /// All confidences, weakest first.
    pub const ALL: [Confidence; 3] = [Confidence::Tentative, Confidence::Firm, Confidence::Certain];

    /// Integer multiplier in basis points (`10000` = 1.0). Integers keep scoring
    /// reproducible across platforms.
    pub fn multiplier_bp(self) -> u32 {
        match self {
            Confidence::Tentative => 5_000,
            Confidence::Firm => 8_500,
            Confidence::Certain => 10_000,
        }
    }

    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }
}

/// Subject area of a finding; drives report grouping and UI placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Transport protection as a whole (plaintext mail, implicit-TLS port misuse).
    Transport,
    /// Cipher-suite selection.
    Cipher,
    /// Key exchange / forward secrecy.
    KeyExchange,
    /// Certificate presentation and trust.
    Certificate,
    /// Authentication mechanism and outcome.
    Authentication,
    /// STARTTLS/STLS negotiation, downgrade and stripping indicators.
    /// Canonical tag is `start_tls`; legacy `as_str()` spelling `starttls`
    /// accepted on read (FSV-1).
    #[serde(alias = "starttls")]
    StartTls,
    /// Protocol-level expectations.
    Protocol,
    /// Properties of the capture or observation itself (never a peer fault).
    CaptureIntegrity,
}

impl FindingCategory {
    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingCategory::Transport => "transport",
            FindingCategory::Cipher => "cipher",
            FindingCategory::KeyExchange => "key_exchange",
            FindingCategory::Certificate => "certificate",
            FindingCategory::Authentication => "authentication",
            FindingCategory::StartTls => "starttls",
            FindingCategory::Protocol => "protocol",
            FindingCategory::CaptureIntegrity => "capture_integrity",
        }
    }
}

/// What kind of observation an evidence item records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Transport classification (plaintext / STARTTLS / implicit TLS).
    TransportState,
    /// Negotiated TLS version.
    TlsVersion,
    /// Negotiated cipher suite.
    CipherSuite,
    /// Key-exchange mechanism or named group.
    KeyExchange,
    /// Forward-secrecy assessment.
    ForwardSecrecy,
    /// A certificate attribute (subject, issuer, validity, signature, key).
    CertificateAttribute,
    /// Certificate chain trust verdict.
    CertificateTrust,
    /// Authentication mechanism observed.
    AuthMechanism,
    /// Authentication outcome observed.
    AuthOutcome,
    /// STARTTLS/STLS negotiation state. Canonical tag `start_tls_negotiation`;
    /// legacy `starttls_negotiation` accepted on read (FSV-1).
    #[serde(alias = "starttls_negotiation")]
    StartTlsNegotiation,
    /// Server capability advertisement.
    ProtocolCapability,
    /// Capture-level metadata (file, frames, truncation).
    CaptureMetadata,
    /// Session structure (endpoints, port choice).
    SessionStructure,
}

impl EvidenceKind {
    /// Stable lowercase identifier for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::TransportState => "transport_state",
            EvidenceKind::TlsVersion => "tls_version",
            EvidenceKind::CipherSuite => "cipher_suite",
            EvidenceKind::KeyExchange => "key_exchange",
            EvidenceKind::ForwardSecrecy => "forward_secrecy",
            EvidenceKind::CertificateAttribute => "certificate_attribute",
            EvidenceKind::CertificateTrust => "certificate_trust",
            EvidenceKind::AuthMechanism => "auth_mechanism",
            EvidenceKind::AuthOutcome => "auth_outcome",
            EvidenceKind::StartTlsNegotiation => "starttls_negotiation",
            EvidenceKind::ProtocolCapability => "protocol_capability",
            EvidenceKind::CaptureMetadata => "capture_metadata",
            EvidenceKind::SessionStructure => "session_structure",
        }
    }
}

/// Typed evidence value.
///
/// Typed rather than free text so a report, a UI and a test can all assert on the
/// same value, and so redaction can be structural rather than textual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceValue {
    /// Bounded, sanitized text (versions, suite names, mechanism names).
    Text {
        /// The sanitized value.
        value: String,
    },
    /// Integer value (ports, bit lengths, counts, timestamps).
    Number {
        /// The value.
        value: i64,
    },
    /// Boolean value (flags such as "advertised" or "succeeded").
    Bool {
        /// The value.
        value: bool,
    },
    /// Opaque bytes referenced by length and digest — never stored raw.
    Bytes {
        /// Digest (for example SHA-256) in lowercase hex.
        digest_hex: String,
        /// Length in bytes.
        len: u64,
    },
    /// Ordered list of bounded values.
    List {
        /// The values.
        values: Vec<String>,
    },
    /// Value was present but not interpretable, with the reason recorded.
    Unavailable {
        /// Why the value could not be established.
        reason: String,
    },
}

impl EvidenceValue {
    /// Build a sanitized text value.
    pub fn text(raw: &str) -> Self {
        EvidenceValue::Text {
            value: SafeText::new(raw).as_str().to_string(),
        }
    }

    /// Build a numeric value.
    pub fn number(value: i64) -> Self {
        EvidenceValue::Number { value }
    }

    /// Build a boolean value.
    pub fn boolean(value: bool) -> Self {
        EvidenceValue::Bool { value }
    }

    /// Build a bounded list of sanitized values.
    pub fn list<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        EvidenceValue::List {
            values: values
                .into_iter()
                .take(Self::MAX_LIST_ITEMS)
                .map(|v| SafeText::new(v.as_ref()).as_str().to_string())
                .collect(),
        }
    }

    /// Record that a value exists but could not be interpreted.
    pub fn unavailable(reason: &str) -> Self {
        EvidenceValue::Unavailable {
            reason: SafeText::new(reason).as_str().to_string(),
        }
    }

    /// Record opaque bytes by digest and length.
    ///
    /// Used for certificate DER and other buffers that must be referenceable —
    /// and comparable across scans — without storing the raw bytes in a report
    /// (`docs/SECURITY.md`: no message content or credentials leave the machine).
    pub fn bytes(digest_hex: &str, len: u64) -> Self {
        EvidenceValue::Bytes {
            digest_hex: SafeText::new(digest_hex).as_str().to_string(),
            len,
        }
    }

    /// Maximum entries retained in a list value.
    pub const MAX_LIST_ITEMS: usize = 64;

    /// Human-readable rendering used by report renderers and UI tooltips.
    pub fn display_text(&self) -> String {
        match self {
            EvidenceValue::Text { value } => value.clone(),
            EvidenceValue::Number { value } => value.to_string(),
            EvidenceValue::Bool { value } => value.to_string(),
            EvidenceValue::Bytes { digest_hex, len } => {
                format!("{len} bytes (digest {digest_hex})")
            }
            EvidenceValue::List { values } => values.join(", "),
            EvidenceValue::Unavailable { reason } => format!("unavailable: {reason}"),
        }
    }
}

/// One typed observation supporting a finding.
///
/// Evidence is what makes a finding reproducible: `source` carries the session
/// and, for capture-derived analysis, the frame numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What kind of observation this is.
    pub kind: EvidenceKind,
    /// Deterministic, one-line statement of what the value proves.
    pub summary: String,
    /// The observed value.
    pub value: EvidenceValue,
    /// Chain of custody for the observation.
    pub source: SourceRef,
}

impl Evidence {
    /// Build evidence from a typed value.
    pub fn new(kind: EvidenceKind, summary: &str, value: EvidenceValue, source: SourceRef) -> Self {
        Evidence {
            kind,
            summary: SafeText::new(summary).as_str().to_string(),
            value,
            source,
        }
    }
}

/// What the operator should do about a finding.
///
/// Remediation is authored next to the rule so the recommendation can never drift
/// away from the detection logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    /// One-line summary of the fix.
    pub summary: String,
    /// Concrete steps, in order.
    pub steps: Vec<String>,
    /// Supporting standards or vendor documentation.
    pub references: Vec<String>,
}

impl Remediation {
    /// Build remediation text (sanitized and bounded).
    pub fn new(summary: &str, steps: &[&str]) -> Self {
        Remediation {
            summary: SafeText::new(summary).as_str().to_string(),
            steps: steps
                .iter()
                .take(16)
                .map(|s| SafeText::new(s).as_str().to_string())
                .collect(),
            references: Vec::new(),
        }
    }

    /// Attach supporting references (RFCs, vendor docs).
    pub fn with_references(mut self, references: &[&str]) -> Self {
        self.references = references
            .iter()
            .take(16)
            .map(|s| SafeText::new(s).as_str().to_string())
            .collect();
        self
    }
}

/// What a finding is about — the identity used for re-scan diffing.
///
/// `key_text()` deliberately excludes the session id: two captures of the same
/// server on different days must line up so a re-scan can show improvement or
/// regression instead of "everything is new".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSubject {
    /// Session the finding was produced from (provenance, not identity).
    pub session_id: SessionId,
    /// Mail protocol of the session.
    pub protocol: Protocol,
    /// Configured/observed server host.
    pub server_host: SafeText,
    /// Server port.
    pub server_port: u16,
    /// Account binding, when the producer knows it (live sessions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<SafeText>,
    /// Optional secondary identity for findings about a specific artifact
    /// (cipher-suite label, certificate fingerprint, auth mechanism).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<SafeText>,
}

impl FindingSubject {
    /// Build the subject from a session.
    pub fn from_session(session: &crate::model::ConnectionSecurityEvent) -> Self {
        FindingSubject {
            session_id: session.id.clone(),
            protocol: session.protocol,
            server_host: session.server.address.clone(),
            server_port: session.server.port,
            account_id: None,
            discriminator: None,
        }
    }

    /// Attach an artifact discriminator (cipher label, fingerprint, mechanism).
    pub fn with_discriminator(mut self, discriminator: &str) -> Self {
        self.discriminator = Some(SafeText::new(discriminator));
        self
    }

    /// Attach an account binding.
    pub fn with_account(mut self, account_id: &str) -> Self {
        self.account_id = Some(SafeText::new(account_id));
        self
    }

    /// Stable identity text used by [`FindingKey`].
    pub fn key_text(&self) -> String {
        let mut key = format!(
            "{}:{}:{}",
            self.protocol.as_str(),
            self.server_host.as_str(),
            self.server_port
        );
        if let Some(discriminator) = &self.discriminator {
            key.push('#');
            key.push_str(discriminator.as_str());
        }
        key
    }
}

/// Identity of a finding for re-scan comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FindingKey {
    /// Rule that produced the finding.
    pub rule_id: String,
    /// Subject identity ([`FindingSubject::key_text`]).
    pub subject_key: String,
}

impl FindingKey {
    /// Stable string form, used in reports and as a map key.
    pub fn as_string(&self) -> String {
        format!("{}|{}", self.rule_id, self.subject_key)
    }
}

/// A single deterministic security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Rule identifier, for example `KIWI-TLS-002`.
    pub rule_id: String,
    /// Rule implementation version; a bump means the decision logic changed.
    pub rule_version: u16,
    /// Subject area.
    pub category: FindingCategory,
    /// Severity assigned by the rule.
    pub severity: Severity,
    /// Evidence strength assigned by the rule.
    pub confidence: Confidence,
    /// One-line title.
    pub title: String,
    /// What was observed, in plain language.
    pub description: String,
    /// Why it matters.
    pub impact: String,
    /// What to do about it.
    pub remediation: Remediation,
    /// Typed supporting observations (never empty for an accepted finding).
    pub evidence: Vec<Evidence>,
    /// What the finding is about.
    pub subject: FindingSubject,
    /// Observation time (Unix epoch milliseconds), supplied by the caller.
    pub observed_at_unix_ms: i64,
    /// Chain of custody for the session as a whole.
    pub sources: Vec<SourceRef>,
    /// Supporting standards references.
    pub references: Vec<String>,
}

impl Finding {
    /// Start building a finding; the session supplies subject and time.
    pub fn builder(
        rule_id: &str,
        rule_version: u16,
        category: FindingCategory,
        severity: Severity,
        confidence: Confidence,
        session: &crate::model::ConnectionSecurityEvent,
    ) -> FindingBuilder {
        FindingBuilder {
            finding: Finding {
                rule_id: rule_id.to_string(),
                rule_version,
                category,
                severity,
                confidence,
                title: String::new(),
                description: String::new(),
                impact: String::new(),
                remediation: Remediation::new("No remediation specified.", &[]),
                evidence: Vec::new(),
                subject: FindingSubject::from_session(session),
                observed_at_unix_ms: session.started_at_unix_ms,
                sources: session.sources.clone(),
                references: Vec::new(),
            },
        }
    }

    /// Stable identity for re-scan comparison.
    pub fn key(&self) -> FindingKey {
        FindingKey {
            rule_id: self.rule_id.clone(),
            subject_key: self.subject.key_text(),
        }
    }

    /// Human-facing unique id, used in reports and audit records.
    pub fn finding_id(&self) -> String {
        format!("{}|{}", self.rule_id, self.subject.key_text())
    }

    /// `true` when the finding carries at least one evidence item.
    ///
    /// The rule engine never emits a finding that fails this check
    /// (`prompt.md` §2.5: no evidence, no finding).
    pub fn has_evidence(&self) -> bool {
        !self.evidence.is_empty()
    }
}

/// Fluent builder for [`Finding`]s.
///
/// Keeps rule implementations short and routes all rule-authored prose through
/// `SafeText`, so sanitization cannot be forgotten at a call site.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    /// Set the title.
    pub fn title(mut self, title: &str) -> Self {
        self.finding.title = SafeText::new(title).as_str().to_string();
        self
    }

    /// Describe what was observed.
    pub fn description(mut self, description: &str) -> Self {
        self.finding.description = SafeText::new(description).as_str().to_string();
        self
    }

    /// State why it matters.
    pub fn impact(mut self, impact: &str) -> Self {
        self.finding.impact = SafeText::new(impact).as_str().to_string();
        self
    }

    /// Attach the remediation.
    pub fn remediation(mut self, remediation: Remediation) -> Self {
        self.finding.remediation = remediation;
        self
    }

    /// Attach one evidence item.
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.finding.evidence.push(evidence);
        self
    }

    /// Override the subject discriminator (for artifact-specific findings).
    pub fn discriminator(mut self, discriminator: &str) -> Self {
        let subject = self
            .finding
            .subject
            .clone()
            .with_discriminator(discriminator);
        self.finding.subject = subject;
        self
    }

    /// Attach an account binding.
    pub fn account(mut self, account_id: &str) -> Self {
        let subject = self.finding.subject.clone().with_account(account_id);
        self.finding.subject = subject;
        self
    }

    /// Attach a supporting standards reference.
    pub fn reference(mut self, reference: &str) -> Self {
        self.finding
            .references
            .push(SafeText::new(reference).as_str().to_string());
        self
    }

    /// Finish the finding.
    pub fn build(self) -> Finding {
        self.finding
    }
}

/// Counts of findings per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// Number of informational findings.
    pub info: u32,
    /// Number of low-severity findings.
    pub low: u32,
    /// Number of medium-severity findings.
    pub medium: u32,
    /// Number of high-severity findings.
    pub high: u32,
    /// Number of critical findings.
    pub critical: u32,
}

impl SeverityCounts {
    /// Count a slice of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = SeverityCounts::default();
        for finding in findings {
            match finding.severity {
                Severity::Info => counts.info += 1,
                Severity::Low => counts.low += 1,
                Severity::Medium => counts.medium += 1,
                Severity::High => counts.high += 1,
                Severity::Critical => counts.critical += 1,
            }
        }
        counts
    }

    /// Total number of findings.
    pub fn total(&self) -> u32 {
        self.info + self.low + self.medium + self.high + self.critical
    }

    /// Worst severity present, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        let mut worst: Option<Severity> = None;
        for severity in Severity::ALL {
            let present = match severity {
                Severity::Info => self.info > 0,
                Severity::Low => self.low > 0,
                Severity::Medium => self.medium > 0,
                Severity::High => self.high > 0,
                Severity::Critical => self.critical > 0,
            };
            if present {
                worst = Some(severity);
            }
        }
        worst
    }
}
