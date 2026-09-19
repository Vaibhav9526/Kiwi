//! Deterministic SMTP/IMAP/POP3 trace analyzers.
//!
//! # Input model
//!
//! An analyzer consumes a [`ProtocolTrace`]: an already-reassembled, ordered list
//! of application-layer lines with a direction. That boundary is deliberate —
//! TCP reassembly is a separate, much larger problem (see the Phase-5
//! interface in `crate::pcap::reassembly`), and keeping the analyzers
//! they are fully testable with synthetic traces and no packets at all.
//!
//! # Rules the analyzers obey
//!
//! - **Untrusted text.** Every line is bounded ([`AnalyzerLimits`]), and only
//!   command verbs and protocol keywords are ever copied into evidence. AUTH
//!   initial responses, passwords, tokens and message data are never stored
//!   (`docs/contracts/forensics.md` §4).
//! - **Absence is not evidence.** A missing handshake is not called an attack
//!   here: the analyzers record observations, and `KIWI-STARTTLS-001` decides,
//!   requiring a *positive* indicator.
//! - **No guessing.** An unrecognized protocol stays [`Protocol::Unknown`] and an
//!   unrecognized mechanism stays `Unknown`, so rules report "we could not tell"
//!   instead of inventing a conclusion.

pub mod imap;
pub mod pop3;
pub mod smtp;

use serde::{Deserialize, Serialize};

use crate::model::{
    AuthMechanism, AuthObservation, CertificatePresentation, ConnectionSecurityEvent, Endpoint,
    Protocol, SafeText, SessionId, SourceRef, StartTlsObservation, TlsObservation,
    TransportSecurity,
};

/// Which peer produced a trace line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Line sent by the mail client.
    Client,
    /// Line sent by the mail server.
    Server,
}

/// One application-layer line of a mail session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceLine {
    /// Which peer sent it.
    pub direction: Direction,
    /// Sanitized line text (control characters removed, bounded).
    pub text: SafeText,
    /// Capture time of the line, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_unix_ms: Option<i64>,
    /// Capture frames that carried this line.
    pub frames: Vec<u64>,
}

impl TraceLine {
    /// Build a line (text is sanitized).
    pub fn new(direction: Direction, text: &str) -> Self {
        TraceLine {
            direction,
            text: SafeText::new(text),
            at_unix_ms: None,
            frames: Vec::new(),
        }
    }

    /// Build a client line.
    pub fn client(text: &str) -> Self {
        TraceLine::new(Direction::Client, text)
    }

    /// Build a server line.
    pub fn server(text: &str) -> Self {
        TraceLine::new(Direction::Server, text)
    }

    /// Attach a capture time.
    pub fn at(mut self, at_unix_ms: i64) -> Self {
        self.at_unix_ms = Some(at_unix_ms);
        self
    }

    /// Attach capture frames (bounded).
    pub fn with_frames(mut self, frames: &[u64]) -> Self {
        self.frames = frames.iter().copied().take(64).collect();
        self
    }
}

/// A reassembled mail session, ready for analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolTrace {
    /// Protocol as identified by the reassembler; `Unknown` triggers sniffing.
    pub protocol: Protocol,
    /// Capture identity used in the deterministic session id.
    pub source_tag: String,
    /// Capture-local session ordinal.
    pub session_index: u64,
    /// Client endpoint.
    pub client: Endpoint,
    /// Server endpoint.
    pub server: Endpoint,
    /// Session start (Unix epoch milliseconds), supplied by the caller.
    pub started_at_unix_ms: i64,
    /// Ordered application-layer lines.
    pub lines: Vec<TraceLine>,
    /// TLS handshake metadata, when the reassembler decoded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsObservation>,
    /// Certificate metadata supplied by an adapter (never parsed here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<CertificatePresentation>,
    /// `true` when the trace is known to be incomplete.
    pub truncated: bool,
}

impl ProtocolTrace {
    /// Build an empty trace for a session.
    pub fn new(
        source_tag: &str,
        protocol: Protocol,
        client: Endpoint,
        server: Endpoint,
        started_at_unix_ms: i64,
    ) -> Self {
        ProtocolTrace {
            protocol,
            source_tag: source_tag.to_string(),
            session_index: 0,
            client,
            server,
            started_at_unix_ms,
            lines: Vec::new(),
            tls: None,
            certificates: None,
            truncated: false,
        }
    }

    /// Append a line.
    pub fn push(&mut self, line: TraceLine) -> &mut Self {
        self.lines.push(line);
        self
    }

    /// Set the capture-local session ordinal.
    pub fn with_index(mut self, index: u64) -> Self {
        self.session_index = index;
        self
    }

    /// Attach TLS handshake metadata.
    pub fn with_tls(mut self, tls: TlsObservation) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Attach certificate metadata.
    pub fn with_certificates(mut self, certificates: CertificatePresentation) -> Self {
        self.certificates = Some(certificates);
        self
    }

    /// Mark the trace as incomplete.
    pub fn truncated(mut self) -> Self {
        self.truncated = true;
        self
    }

    /// Session identity for this trace.
    pub fn session_id(&self) -> SessionId {
        SessionId::new(
            &self.source_tag,
            self.protocol,
            self.client.port,
            self.server.port,
            self.session_index,
        )
    }
}

/// Bounds applied while analysing a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerLimits {
    /// Maximum lines examined (default 100,000).
    pub max_lines: usize,
    /// Maximum characters examined per line (default 4096).
    pub max_line_chars: usize,
    /// Maximum capability tokens retained (default 64).
    pub max_capabilities: usize,
    /// Maximum authentication attempts counted (default 64).
    pub max_auth_attempts: u32,
}

impl Default for AnalyzerLimits {
    fn default() -> Self {
        AnalyzerLimits {
            max_lines: 100_000,
            max_line_chars: 4_096,
            max_capabilities: 64,
            max_auth_attempts: 64,
        }
    }
}

/// Result of analysing one trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisOutcome {
    /// The normalized session handed to the rule engine.
    pub session: ConnectionSecurityEvent,
    /// Protocol actually used for analysis (after sniffing, if needed).
    pub analyzed_as: Protocol,
    /// Lines examined.
    pub lines_examined: usize,
    /// `true` when a limit cut the analysis short.
    pub truncated: bool,
}

/// Observations collected by a protocol analyzer.
///
/// Shared by all three analyzers so that the session-construction logic lives in
/// exactly one place (`finalize`), and protocol differences stay inside the
/// per-protocol parsers.
#[derive(Debug, Default, Clone)]
pub(crate) struct TraceFacts {
    /// Capability/keyword tokens advertised by the server.
    pub capabilities: Vec<String>,
    /// Server advertised STARTTLS/STLS.
    pub advertised_starttls: bool,
    /// Client requested the upgrade.
    pub starttls_requested: bool,
    /// Server reply to the upgrade: `Some(true)` accepted, `Some(false)` refused.
    pub starttls_reply: Option<bool>,
    /// Mail-protocol data observed *after* an accepted upgrade with no handshake:
    /// the positive downgrade/stripping indicator.
    pub application_data_after_accepted_upgrade: bool,
    /// Authentication mechanism used.
    pub auth_mechanism: Option<AuthMechanism>,
    /// Authentication outcome.
    pub auth_succeeded: Option<bool>,
    /// Attempts observed.
    pub auth_attempts: u32,
    /// Failures observed.
    pub auth_failures: u32,
    /// Credentials were sent while the upgrade request was unresolved.
    pub auth_after_starttls_request: bool,
    /// Count of plaintext application-protocol lines seen.
    pub plaintext_application_lines: u32,
    /// Redacted excerpt (command verbs and reply codes only).
    pub excerpt: Option<String>,
}

impl TraceFacts {
    /// Record an advertised capability token (bounded, de-duplicated).
    pub(crate) fn add_capability(&mut self, token: &str, limits: &AnalyzerLimits) {
        if self.capabilities.len() >= limits.max_capabilities {
            return;
        }
        let token = bounded_line(token, 64);
        if token.is_empty() || self.capabilities.contains(&token) {
            return;
        }
        if token.eq_ignore_ascii_case("STARTTLS") || token.eq_ignore_ascii_case("STLS") {
            self.advertised_starttls = true;
        }
        self.capabilities.push(token);
    }

    /// Record an authentication attempt (bounded).
    pub(crate) fn note_auth_attempt(&mut self, mechanism: AuthMechanism, limits: &AnalyzerLimits) {
        if self.auth_attempts >= limits.max_auth_attempts {
            return;
        }
        self.auth_attempts = self.auth_attempts.saturating_add(1);
        self.auth_mechanism = Some(mechanism);
    }

    /// Record the outcome of the most recent authentication attempt.
    pub(crate) fn note_auth_outcome(&mut self, succeeded: bool) {
        self.auth_succeeded = Some(succeeded);
        if !succeeded {
            self.auth_failures = self.auth_failures.saturating_add(1);
        }
    }

    /// Set the redacted excerpt once (first interesting exchange wins).
    pub(crate) fn note_excerpt(&mut self, excerpt: &str) {
        if self.excerpt.is_none() {
            let bounded = bounded_line(excerpt, 120);
            if !bounded.is_empty() {
                self.excerpt = Some(bounded);
            }
        }
    }
}

/// Analyze a trace with the analyzer for its protocol.
///
/// A trace whose protocol is [`Protocol::Unknown`] is sniffed from its greeting
/// lines; if sniffing fails, the session stays `Unknown` and the engine reports
/// `KIWI-PROTO-001` rather than guessing (see `rules::transport`).
pub fn analyze(trace: &ProtocolTrace, limits: &AnalyzerLimits) -> AnalysisOutcome {
    let analyzed_as = if trace.protocol == Protocol::Unknown {
        sniff_protocol(trace)
    } else {
        trace.protocol
    };
    match analyzed_as {
        Protocol::Smtp => smtp::analyze(trace, limits, analyzed_as),
        Protocol::Imap => imap::analyze(trace, limits, analyzed_as),
        Protocol::Pop3 => pop3::analyze(trace, limits, analyzed_as),
        Protocol::Unknown => finalize(trace, Protocol::Unknown, TraceFacts::default(), limits, 0),
    }
}

/// Identify a protocol from greeting lines, without guessing.
pub fn sniff_protocol(trace: &ProtocolTrace) -> Protocol {
    for line in trace.lines.iter().take(8) {
        let text = line.text.as_str();
        let upper = text.to_ascii_uppercase();
        if upper.starts_with("* OK")
            || upper.starts_with("* PREAUTH")
            || upper.starts_with("* BYE")
            || upper.contains("IMAP4REV")
        {
            return Protocol::Imap;
        }
        if upper.starts_with("+OK") || upper.starts_with("-ERR") {
            return Protocol::Pop3;
        }
        if upper.starts_with("220") && (upper.contains("SMTP") || upper.contains("ESMTP")) {
            return Protocol::Smtp;
        }
    }
    // Fall back to the port only as a last resort, and only for well-known ports.
    Protocol::from_well_known_port(trace.server.port).unwrap_or(Protocol::Unknown)
}

/// Build the normalized session from collected facts.
///
/// Single place where a trace becomes rule input, for all three protocols.
pub(crate) fn finalize(
    trace: &ProtocolTrace,
    analyzed_as: Protocol,
    facts: TraceFacts,
    limits: &AnalyzerLimits,
    lines_examined: usize,
) -> AnalysisOutcome {
    let session_id = SessionId::new(
        &trace.source_tag,
        analyzed_as,
        trace.client.port,
        trace.server.port,
        trace.session_index,
    );
    let frames: Vec<u64> = trace
        .lines
        .iter()
        .flat_map(|line| line.frames.iter().copied())
        .take(256)
        .collect();

    let handshake_observed = trace.tls.is_some();
    let transport = if handshake_observed {
        if facts.starttls_requested {
            TransportSecurity::StartTls
        } else {
            TransportSecurity::ImplicitTls
        }
    } else if !trace.lines.is_empty() {
        // Plaintext protocol text was readable, so the channel was not protected.
        TransportSecurity::Plaintext
    } else {
        TransportSecurity::Unknown
    };

    let mut session = ConnectionSecurityEvent::new(
        session_id.clone(),
        analyzed_as,
        trace.client.clone(),
        trace.server.clone(),
        trace.started_at_unix_ms,
    )
    .with_transport(transport)
    .with_capabilities(
        facts
            .capabilities
            .iter()
            .take(limits.max_capabilities)
            .cloned(),
    );

    if let Some(tls) = &trace.tls {
        session = session.with_tls(tls.clone());
    }
    if let Some(certificates) = &trace.certificates {
        session = session.with_certificates(certificates.clone());
    }
    if facts.advertised_starttls || facts.starttls_requested || facts.starttls_reply.is_some() {
        session = session.with_starttls(StartTlsObservation {
            advertised_by_server: facts.advertised_starttls,
            client_requested: facts.starttls_requested,
            server_reply_ok: facts.starttls_reply,
            handshake_completed: handshake_observed,
            application_data_before_tls: facts.application_data_after_accepted_upgrade,
            plaintext_auth_after_request: facts.auth_after_starttls_request && !handshake_observed,
        });
    }
    if facts.auth_attempts > 0 || facts.auth_mechanism.is_some() || facts.auth_succeeded.is_some() {
        session = session.with_auth(AuthObservation {
            mechanism: facts.auth_mechanism,
            succeeded: facts.auth_succeeded,
            attempts: facts.auth_attempts,
            failures: facts.auth_failures,
        });
    }

    let excerpt = facts.excerpt.unwrap_or_default();
    session = session.with_source(
        SourceRef::session_only(session_id)
            .with_frames(frames)
            .with_excerpt(&excerpt),
    );

    AnalysisOutcome {
        session,
        analyzed_as,
        lines_examined,
        truncated: trace.truncated || lines_examined < trace.lines.len(),
    }
}

/// Truncate a line to `max_chars` characters (never splits a character).
pub(crate) fn bounded_line(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Split a line into bounded, sanitized tokens.
pub(crate) fn tokens(line: &str, max_tokens: usize) -> Vec<String> {
    line.split_whitespace()
        .take(max_tokens)
        .map(|token| bounded_line(token, 64))
        .filter(|token| !token.is_empty())
        .collect()
}

/// Command verb of a client line, if it looks like one.
///
/// Only the verb is ever retained from a client command: arguments may contain
/// credentials or message data (`docs/contracts/forensics.md` §4).
pub(crate) fn command_verb(line: &str) -> Option<String> {
    let first = line.split_whitespace().next()?;
    let verb: String = first
        .chars()
        .take(32)
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if verb.is_empty() {
        None
    } else {
        Some(verb.to_ascii_uppercase())
    }
}

/// Reply code of a server line: SMTP/ESMTP 3-digit code, IMAP status word, or the
/// POP3 `+OK`/`-ERR` status.
pub(crate) fn reply_code(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("+OK") {
        return Some("+OK".to_string());
    }
    if upper.starts_with("-ERR") {
        return Some("-ERR".to_string());
    }
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() == 3 {
        return Some(digits);
    }
    // IMAP tagged response: "<tag> OK|NO|BAD".
    let mut parts = tokens(trimmed, 3).into_iter();
    let _tag = parts.next()?;
    let status = parts.next()?;
    match status.as_str() {
        "OK" | "NO" | "BAD" | "BYE" => Some(status),
        _ => None,
    }
}

/// Classify a 3-digit SMTP-style reply code.
pub(crate) fn smtp_reply_outcome(line: &str) -> Option<bool> {
    let code = reply_code(line)?;
    let first = code.chars().next()?;
    if code.len() == 3 && first.is_ascii_digit() {
        return match first {
            '2' => Some(true),
            '4' | '5' => Some(false),
            _ => None,
        };
    }
    None
}

/// Build a redacted excerpt from a command verb and an optional reply code.
pub(crate) fn redacted_exchange(verb: &str, reply: Option<&str>) -> String {
    match reply {
        Some(reply) => format!("{verb} -> {reply}"),
        None => verb.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleEngine, SecurityPolicy};

    const NOW: i64 = 1_700_000_000_000;

    fn trace(protocol: Protocol, server_port: u16, lines: Vec<TraceLine>) -> ProtocolTrace {
        let mut t = ProtocolTrace::new(
            "t",
            protocol,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", server_port),
            NOW,
        );
        for line in lines {
            t.push(line);
        }
        t
    }

    fn engine() -> RuleEngine {
        RuleEngine::new(SecurityPolicy::default())
    }

    fn rule_ids(findings: &[crate::findings::Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn smtp_stripped_upgrade_end_to_end() {
        let t = trace(
            Protocol::Smtp,
            587,
            vec![
                TraceLine::server("220 fake ESMTP"),
                TraceLine::server("250-fake"),
                TraceLine::server("250-STARTTLS"),
                TraceLine::client("STARTTLS"),
                TraceLine::server("220 2.0.0 ready"),
                TraceLine::client("AUTH PLAIN AGFsaWNlAHNlY3JldA=="),
                TraceLine::server("235 ok"),
            ],
        );
        let outcome = analyze(&t, &AnalyzerLimits::default());
        assert_eq!(outcome.analyzed_as, Protocol::Smtp);
        assert!(
            outcome
                .session
                .starttls
                .as_ref()
                .is_some_and(|s| s.is_stripping_indicator())
        );
        let findings = engine().evaluate_session(&outcome.session);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"KIWI-STARTTLS-001"), "got {ids:?}");
        assert!(ids.contains(&"KIWI-AUTH-001"), "got {ids:?}");
    }

    #[test]
    fn imap_login_failure_end_to_end() {
        let t = trace(
            Protocol::Imap,
            143,
            vec![
                TraceLine::server("* OK fake IMAP4rev1"),
                TraceLine::client("a001 CAPABILITY"),
                TraceLine::server("* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"),
                TraceLine::server("a001 OK done"),
                TraceLine::client("a002 LOGIN alice secret"),
                TraceLine::server("a002 NO invalid credentials"),
            ],
        );
        let outcome = analyze(&t, &AnalyzerLimits::default());
        let auth = outcome.session.auth.as_ref().expect("auth observed");
        assert_eq!(auth.failures, 1);
        let findings = engine().evaluate_session(&outcome.session);
        assert!(
            rule_ids(&findings).contains(&"KIWI-AUTH-003"),
            "got {:?}",
            rule_ids(&findings)
        );
    }

    #[test]
    fn pop3_apop_reports_md5_without_exposure() {
        let t = trace(
            Protocol::Pop3,
            110,
            vec![
                TraceLine::server("+OK fake"),
                TraceLine::client("CAPA"),
                TraceLine::server("+OK"),
                TraceLine::server("STLS"),
                TraceLine::server("."),
                TraceLine::client("APOP alice 1a2b3c"),
                TraceLine::server("+OK logged in"),
            ],
        );
        let outcome = analyze(&t, &AnalyzerLimits::default());
        let findings = engine().evaluate_session(&outcome.session);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"KIWI-AUTH-005"), "got {ids:?}");
        assert!(
            !ids.contains(&"KIWI-AUTH-001"),
            "challenge-response leaks nothing: {ids:?}"
        );
    }

    #[test]
    fn sniffing_identifies_protocols_without_guessing() {
        let smtp = trace(
            Protocol::Unknown,
            2525,
            vec![TraceLine::server("220 fake ESMTP")],
        );
        assert_eq!(
            analyze(&smtp, &AnalyzerLimits::default()).analyzed_as,
            Protocol::Smtp
        );
        let pop3 = trace(Protocol::Unknown, 1110, vec![TraceLine::server("+OK fake")]);
        assert_eq!(
            analyze(&pop3, &AnalyzerLimits::default()).analyzed_as,
            Protocol::Pop3
        );
        let imap = trace(
            Protocol::Unknown,
            1143,
            vec![TraceLine::server("* OK fake")],
        );
        assert_eq!(
            analyze(&imap, &AnalyzerLimits::default()).analyzed_as,
            Protocol::Imap
        );
        let unknown = trace(Protocol::Unknown, 9999, vec![TraceLine::server("HELLO?")]);
        assert_eq!(
            analyze(&unknown, &AnalyzerLimits::default()).analyzed_as,
            Protocol::Unknown
        );
    }
}
