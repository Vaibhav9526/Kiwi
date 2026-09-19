//! Normalized connection/protocol/security model.
//!
//! This is the *only* shape in which analyzers, rules and reports exchange
//! security state. It is deliberately independent of Thunderbird/NSS types so
//! that (a) fixtures can be synthetic, and (b) the same model can later be fed
//! from a live NSS observation adapter (`docs/ARCHITECTURE.md` §3, T-011).

pub mod auth;
pub mod cert;
pub mod cipher_table;
pub mod protocol;
pub mod tls;

use serde::{Deserialize, Serialize};

pub use auth::{AuthMechanism, AuthObservation, CredentialKind};
pub use cert::{CertificatePresentation, CertificateProblem, DistinguishedName, TrustState};
pub use protocol::{Protocol, TransportSecurity};
pub use tls::{
    CipherStrength, CipherSuite, ForwardSecrecy, KeyExchange, TlsObservation, TlsVersion,
};

/// Bounded, human-readable string taken from untrusted input.
///
/// Every string that originates in a capture, a protocol line, or an external
/// API passes through here so that reports/logs cannot be inflated or
/// log-injected (`docs/SECURITY.md`, input validation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SafeText(String);

impl SafeText {
    /// Maximum retained characters for a single value.
    pub const MAX_LEN: usize = 256;

    /// Sanitize arbitrary input into a bounded, control-character-free value.
    ///
    /// - strips ASCII control characters and DEL (prevents log injection),
    /// - collapses runs of whitespace to a single space,
    /// - truncates on a character boundary to [`SafeText::MAX_LEN`].
    pub fn new(raw: &str) -> Self {
        let mut out = String::with_capacity(raw.len().min(SafeText::MAX_LEN));
        let mut pending_space = false;
        let mut count = 0usize;
        for ch in raw.chars() {
            if ch.is_control() || ch == '\u{7f}' {
                pending_space = count > 0;
                continue;
            }
            if ch.is_whitespace() {
                pending_space = count > 0;
                continue;
            }
            if pending_space {
                out.push(' ');
                count += 1;
                pending_space = false;
            }
            if count >= SafeText::MAX_LEN {
                break;
            }
            out.push(ch);
            count += 1;
        }
        SafeText(out)
    }

    /// Borrow the sanitized value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` when nothing survived sanitization.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for SafeText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Network endpoint identity.
///
/// Addresses stay sanitized text: captures may hold non-IP L2 identifiers and
/// the engine never needs a numeric address representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    /// IPv4/IPv6 literal or other capture-level address text.
    pub address: SafeText,
    /// TCP port.
    pub port: u16,
}

impl Endpoint {
    /// Construct an endpoint from untrusted address text and a port.
    pub fn new(address: &str, port: u16) -> Self {
        Endpoint {
            address: SafeText::new(address),
            port,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

/// Which side of the conversation a peer represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    /// Local mail client (Thunderbird).
    Client,
    /// Remote mail server.
    Server,
    /// Direction could not be determined from the capture.
    Unknown,
}

impl PeerRole {
    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerRole::Client => "client",
            PeerRole::Server => "server",
            PeerRole::Unknown => "unknown",
        }
    }
}

/// Stable identity of an analyzed session.
///
/// Format: `<source-tag>:<protocol>:<client-port>-<server-port>:<index>`.
/// The index is the capture-local ordinal, so ids are reproducible for a given
/// capture and stable across re-scans of that capture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Build a deterministic session id.
    pub fn new(
        source_tag: &str,
        protocol: Protocol,
        client_port: u16,
        server_port: u16,
        index: u64,
    ) -> Self {
        SessionId(format!(
            "{}:{}:{}-{}:{}",
            SafeText::new(source_tag).as_str(),
            protocol.as_str(),
            client_port,
            server_port,
            index
        ))
    }

    /// Build a session id from an explicit label (analyzers and tests).
    pub fn from_label(label: &str) -> Self {
        SessionId(SafeText::new(label).as_str().to_string())
    }

    /// Borrow the id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Traceability anchor: where a piece of evidence physically came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Analyzed session id.
    pub session_id: SessionId,
    /// Capture frame numbers (1-based, as in `tcpdump`/Wireshark) when the
    /// evidence came from a capture file. Empty for live observations.
    pub frames: Vec<u64>,
    /// Byte offsets inside a reconstructed stream, when known.
    pub stream_offsets: Vec<u64>,
    /// Redacted, sanitized excerpt of the observed bytes/line.
    ///
    /// Never contains credentials — see the redaction rules in
    /// `docs/contracts/forensics.md` §4.
    pub excerpt: SafeText,
}

impl SourceRef {
    /// Anchor referencing only a session (no frame-level detail available).
    pub fn session_only(session_id: SessionId) -> Self {
        SourceRef {
            session_id,
            frames: Vec::new(),
            stream_offsets: Vec::new(),
            excerpt: SafeText::new(""),
        }
    }

    /// Attach an already-redacted excerpt.
    pub fn with_excerpt(mut self, excerpt: &str) -> Self {
        self.excerpt = SafeText::new(excerpt);
        self
    }

    /// Attach capture frame numbers.
    pub fn with_frames(mut self, frames: Vec<u64>) -> Self {
        self.frames = frames;
        self
    }

    /// Attach reconstructed-stream byte offsets.
    pub fn with_offsets(mut self, offsets: Vec<u64>) -> Self {
        self.stream_offsets = offsets;
        self
    }
}

/// Observed STARTTLS/STLS negotiation for one session.
///
/// Every field is an *observation*: `false` means "not seen in this capture",
/// which for `handshake_completed` is not by itself proof of an attack. The
/// STARTTLS rules therefore escalate only when a positive stripping indicator
/// (`application_data_before_tls` or `plaintext_auth_after_request`) is also
/// present, and mark confidence accordingly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartTlsObservation {
    /// Server advertised the STARTTLS/STLS capability (SMTP `250-STARTTLS`,
    /// IMAP `CAPABILITY` containing `STARTTLS`, POP3 `CAPA` containing `STLS`).
    pub advertised_by_server: bool,
    /// Client sent the upgrade command (`STARTTLS`/`STLS`).
    pub client_requested: bool,
    /// Server reply to the upgrade command: `Some(true)` = ready, `Some(false)`
    /// = explicitly refused (temporary/permanent error), `None` = no reply seen.
    pub server_reply_ok: Option<bool>,
    /// A TLS handshake was observed after the request.
    pub handshake_completed: bool,
    /// Mail protocol commands/responses (other than the upgrade handshake)
    /// observed *after* the upgrade request and before any TLS record.
    ///
    /// This is the primary stripping/downgrade indicator: a correct peer either
    /// upgrades immediately or refuses and then speaks plaintext, but it never
    /// continues the pre-upgrade conversation across the request.
    pub application_data_before_tls: bool,
    /// Credentials were sent in cleartext after the upgrade request.
    pub plaintext_auth_after_request: bool,
}

impl StartTlsObservation {
    /// An observation where the server never offered STARTTLS.
    pub fn not_advertised() -> Self {
        StartTlsObservation {
            advertised_by_server: false,
            client_requested: false,
            server_reply_ok: None,
            handshake_completed: false,
            application_data_before_tls: false,
            plaintext_auth_after_request: false,
        }
    }

    /// A correct, fully observed upgrade.
    pub fn upgraded() -> Self {
        StartTlsObservation {
            advertised_by_server: true,
            client_requested: true,
            server_reply_ok: Some(true),
            handshake_completed: true,
            application_data_before_tls: false,
            plaintext_auth_after_request: false,
        }
    }

    /// Positive indicator that the upgrade was prevented or bypassed.
    pub fn is_stripping_indicator(&self) -> bool {
        self.advertised_by_server
            && self.client_requested
            && !self.handshake_completed
            && (self.application_data_before_tls || self.plaintext_auth_after_request)
    }
}

/// One normalized mail-transport session: the unit that rules evaluate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSecurityEvent {
    /// Deterministic session identity.
    pub id: SessionId,
    /// Mail protocol (may be `Unknown`; rules must then stay conservative).
    pub protocol: Protocol,
    /// Client endpoint (local Thunderbird or sending peer).
    pub client: Endpoint,
    /// Server endpoint.
    pub server: Endpoint,
    /// Session start, Unix epoch milliseconds (supplied by the caller — never
    /// read from the system clock, to keep analysis reproducible).
    pub started_at_unix_ms: i64,
    /// Transport protection classification.
    pub transport: TransportSecurity,
    /// Server capability tokens as advertised in the session (bounded count).
    pub capabilities: Vec<SafeText>,
    /// TLS handshake metadata, when a handshake was captured.
    pub tls: Option<TlsObservation>,
    /// Certificate chain presentation, when certificates were captured.
    pub certificates: Option<CertificatePresentation>,
    /// STARTTLS negotiation observation, when the protocol exposes one.
    pub starttls: Option<StartTlsObservation>,
    /// Authentication observation, when authentication was seen.
    pub auth: Option<AuthObservation>,
    /// Traceability anchors for this session (frames, excerpts).
    pub sources: Vec<SourceRef>,
}

impl ConnectionSecurityEvent {
    /// Maximum retained capability tokens per session (bound on untrusted input).
    pub const MAX_CAPABILITIES: usize = 64;

    /// Create a session with conservative defaults.
    ///
    /// Defaults are chosen so that an under-specified session cannot be scored
    /// as healthy: transport starts as [`TransportSecurity::Unknown`] and no
    /// observation is asserted.
    pub fn new(
        id: SessionId,
        protocol: Protocol,
        client: Endpoint,
        server: Endpoint,
        started_at_unix_ms: i64,
    ) -> Self {
        ConnectionSecurityEvent {
            id,
            protocol,
            client,
            server,
            started_at_unix_ms,
            transport: TransportSecurity::Unknown,
            capabilities: Vec::new(),
            tls: None,
            certificates: None,
            starttls: None,
            auth: None,
            sources: Vec::new(),
        }
    }

    /// Set the transport classification.
    pub fn with_transport(mut self, transport: TransportSecurity) -> Self {
        self.transport = transport;
        self
    }

    /// Replace capabilities; input is truncated to [`Self::MAX_CAPABILITIES`].
    pub fn with_capabilities<I, S>(mut self, caps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.capabilities = caps
            .into_iter()
            .take(Self::MAX_CAPABILITIES)
            .map(|c| SafeText::new(c.as_ref()))
            .collect();
        self
    }

    /// Set TLS handshake metadata.
    pub fn with_tls(mut self, tls: TlsObservation) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Set certificate presentation metadata.
    pub fn with_certificates(mut self, certs: CertificatePresentation) -> Self {
        self.certificates = Some(certs);
        self
    }

    /// Set the STARTTLS observation.
    pub fn with_starttls(mut self, starttls: StartTlsObservation) -> Self {
        self.starttls = Some(starttls);
        self
    }

    /// Set the authentication observation.
    pub fn with_auth(mut self, auth: AuthObservation) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Append a traceability anchor.
    pub fn with_source(mut self, source: SourceRef) -> Self {
        self.sources.push(source);
        self
    }

    /// Negotiated TLS version actually protecting this session, if any.
    pub fn negotiated_tls_version(&self) -> Option<TlsVersion> {
        self.tls.as_ref().map(|t| t.version)
    }

    /// `true` when the session is known to be cryptographically protected.
    pub fn is_encrypted(&self) -> bool {
        self.transport.is_protected()
    }

    /// `true` when the server advertised the given capability (case-insensitive).
    pub fn advertises(&self, capability: &str) -> bool {
        let needle = capability.trim();
        self.capabilities
            .iter()
            .any(|c| c.as_str().eq_ignore_ascii_case(needle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ConnectionSecurityEvent {
        ConnectionSecurityEvent::new(
            SessionId::from_label("t:imap:143"),
            Protocol::Imap,
            Endpoint::new("10.0.0.5", 51000),
            Endpoint::new("mail.example.test", 143),
            1_700_000_000_000,
        )
    }

    #[test]
    fn safe_text_strips_control_characters_and_collapses_space() {
        let t = SafeText::new("INJECT\r\nFAKE  LOG\tline");
        assert_eq!(t.as_str(), "INJECT FAKE LOG line");
        assert!(!t.as_str().contains('\n'));
    }

    #[test]
    fn safe_text_is_bounded() {
        let long = "A".repeat(10_000);
        assert_eq!(
            SafeText::new(&long).as_str().chars().count(),
            SafeText::MAX_LEN
        );
    }

    #[test]
    fn session_defaults_are_conservative() {
        let s = session();
        assert_eq!(s.transport, TransportSecurity::Unknown);
        assert!(!s.is_encrypted());
        assert!(s.tls.is_none());
        assert!(s.negotiated_tls_version().is_none());
    }

    #[test]
    fn capability_list_is_bounded_and_case_insensitive() {
        let caps: Vec<String> = (0..500).map(|i| format!("CAP{i}")).collect();
        let s = session().with_capabilities(caps);
        assert_eq!(
            s.capabilities.len(),
            ConnectionSecurityEvent::MAX_CAPABILITIES
        );
        let s = session().with_capabilities(["starttls"]);
        assert!(s.advertises("STARTTLS"));
        assert!(!s.advertises("AUTH=PLAIN"));
    }

    #[test]
    fn session_id_is_deterministic() {
        let a = SessionId::new("cap.pcap", Protocol::Smtp, 40000, 587, 3);
        let b = SessionId::new("cap.pcap", Protocol::Smtp, 40000, 587, 3);
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "cap.pcap:smtp:40000-587:3");
    }

    #[test]
    fn starttls_stripping_indicator_requires_positive_evidence() {
        let mut obs = StartTlsObservation::upgraded();
        obs.handshake_completed = false;
        // No application data across the request -> absence of observation only.
        assert!(!obs.is_stripping_indicator());
        obs.application_data_before_tls = true;
        assert!(obs.is_stripping_indicator());
        // Never advertised at all: not a stripping indicator.
        assert!(!StartTlsObservation::not_advertised().is_stripping_indicator());
    }
}
