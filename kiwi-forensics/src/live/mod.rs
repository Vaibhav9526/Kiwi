//! Live adapter: `kiwi-mail` transport observations become rule input.
//!
//! The adapter is a pure, total mapping from the owned [`LiveTlsObservation`]
//! mirror struct to [`ConnectionSecurityEvent`]. It takes no dependency on
//! `kiwi-mail` (which owns tokio/rustls/x509): the mail crate converts its
//! `transport::TlsObservation` into the mirror at the IPC/module boundary,
//! which keeps this crate's dependency surface at serde-only and keeps the
//! mapping unit-testable with zero I/O.
//!
//! Conservatism rules (binding):
//! - anything the live observation does not establish stays absent (`None`)
//!   or `Unknown` — never guessed;
//! - DER bytes never cross this boundary (redaction contract §4): only the
//!   peer-certificate *count* travels; parsed `CertificateInfo` arrives later
//!   via the full T-107 wiring from `kiwi-mail`'s x509-parser;
//! - a non-empty but unparsed chain sets `chain_truncated` so reports show an
//!   explicit completeness limitation instead of silent partial analysis.

use crate::model::{
    CertificatePresentation, ConnectionSecurityEvent, Endpoint, Protocol, SessionId,
    TlsObservation, TlsVersion, TransportSecurity, TrustState,
};

/// Socket-security mode of the live connection (mirrors
/// `kiwi_mail::transport::SocketSecurity` without depending on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketMode {
    /// Plaintext socket, no TLS expected.
    Plaintext,
    /// TLS from the first byte (465/993/995).
    ImplicitTls,
    /// Plaintext first, STARTTLS/STLS upgrade later.
    StartTls,
}

/// Certificate verdict recorded by the live verifier (mirrors
/// `kiwi_mail::transport::CertVerdict` without depending on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCertVerdict {
    /// Chain validated against the trust store.
    Valid,
    /// Validation failed (generic).
    Invalid,
    /// Unknown issuer / no anchor.
    Untrusted,
    /// Chain invalid due to expiry.
    Expired,
    /// Chain invalid due to server-name mismatch.
    HostnameMismatch,
    /// Verdict could not be established.
    Unknown,
}

/// Owned live-TLS observation for one connection.
///
/// Constructed by the `kiwi-mail` side from its `transport::TlsObservation`;
/// every field is optional-or-counted so a partial observation still maps.
#[derive(Debug, Clone, Default)]
pub struct LiveTlsObservation {
    /// rustls protocol-version debug name (e.g. `"TLSv1_3"`), when known.
    pub version_name: Option<String>,
    /// IANA cipher-suite code point, when the suite was identified.
    pub cipher_suite_iana: Option<u16>,
    /// Key-exchange group name (informational only; classification uses the
    /// suite table, never this string).
    pub key_exchange_group: Option<String>,
    /// Number of DER peer certificates presented (bytes never cross).
    pub peer_cert_count: usize,
    /// `true` when the session started plaintext and upgraded.
    pub upgraded_via_starttls: bool,
    /// Verdict recorded by the live chain verifier, when a handshake ran.
    pub cert_verdict: Option<LiveCertVerdict>,
}

/// Parse a rustls version debug name (`"TLSv1_3"`, …).
///
/// Unrecognized names map to `Unknown(0xFFFF)` — the reserved code point is
/// used as an explicit "unrecognized" sentinel, documented here and surfaced
/// by the `KIWI-TLS-003` rule rather than guessed.
pub fn parse_version_name(name: &str) -> TlsVersion {
    match name {
        "SSLv2" => TlsVersion::Ssl2,
        "SSLv3" | "SSLv3_0" => TlsVersion::Ssl3,
        "TLSv1" | "TLSv1_0" => TlsVersion::Tls10,
        "TLSv1_1" => TlsVersion::Tls11,
        "TLSv1_2" => TlsVersion::Tls12,
        "TLSv1_3" => TlsVersion::Tls13,
        _ => TlsVersion::Unknown(0xFFFF),
    }
}

/// Map a live verifier verdict to the forensics trust state.
pub fn map_verdict(verdict: LiveCertVerdict) -> TrustState {
    match verdict {
        LiveCertVerdict::Valid => TrustState::TrustedByLocalAnchor,
        LiveCertVerdict::Invalid
        | LiveCertVerdict::Untrusted
        | LiveCertVerdict::Expired
        | LiveCertVerdict::HostnameMismatch => TrustState::Untrusted,
        LiveCertVerdict::Unknown => TrustState::Unknown,
    }
}

/// Build a [`ConnectionSecurityEvent`] from one live connection.
///
/// Pure function of its input: no clock, no I/O. `server_host` seeds
/// hostname matching once parsed chains arrive; `index` keeps the session
/// id deterministic per caller.
pub fn event_from_live(input: &LiveSessionInput<'_>) -> ConnectionSecurityEvent {
    let id = SessionId::new(
        input.source_tag,
        input.protocol,
        input.client_port,
        input.server_port,
        input.index,
    );
    let mut event = ConnectionSecurityEvent::new(
        id,
        input.protocol,
        Endpoint::new("local-client", input.client_port),
        Endpoint::new(input.server_host, input.server_port),
        input.started_at_unix_ms,
    );

    let Some(obs) = input.observation else {
        // No handshake ran. A plaintext socket is known-plaintext; anything
        // else is unclassifiable (an implicit-TLS socket without a handshake
        // means the observation was lost, not that the wire was clear).
        event.transport = match input.mode {
            SocketMode::Plaintext => TransportSecurity::Plaintext,
            SocketMode::ImplicitTls | SocketMode::StartTls => TransportSecurity::Unknown,
        };
        return event;
    };

    event.transport = match input.mode {
        SocketMode::Plaintext => TransportSecurity::Plaintext,
        SocketMode::ImplicitTls => TransportSecurity::ImplicitTls,
        SocketMode::StartTls => {
            if obs.upgraded_via_starttls {
                TransportSecurity::StartTls
            } else {
                TransportSecurity::Plaintext
            }
        }
    };

    let version = obs
        .version_name
        .as_deref()
        .map_or(TlsVersion::Unknown(0xFFFF), parse_version_name);
    let suite = obs
        .cipher_suite_iana
        .map_or(crate::model::CipherSuite::from_iana(0xFFFF), |id| {
            crate::model::CipherSuite::from_iana(id)
        });
    let mut tls = TlsObservation::new(version, suite);
    tls.handshake_complete = true;
    event.tls = Some(tls);

    if obs.peer_cert_count > 0 || obs.cert_verdict.is_some() {
        let trust = obs.cert_verdict.map_or(TrustState::Unknown, map_verdict);
        let mut presentation = CertificatePresentation::new(Vec::new(), trust);
        // DER was counted but not parsed by this adapter: mark the chain
        // truncated so the incompleteness is explicit, never silent.
        if obs.peer_cert_count > 0 {
            presentation.chain_truncated = true;
        }
        event.certificates = Some(presentation);
    }

    if obs.upgraded_via_starttls {
        event.starttls = Some(crate::model::StartTlsObservation::upgraded());
    }

    event
}

/// Inputs for [`event_from_live`], bundled so the adapter entry point stays
/// a one-argument pure function (and stays clear of `too_many_arguments`).
#[derive(Debug, Clone)]
pub struct LiveSessionInput<'a> {
    /// Capture/source tag seeding the session id (e.g. `"live"`).
    pub source_tag: &'a str,
    /// Mail protocol of the connection.
    pub protocol: Protocol,
    /// Configured server hostname (never greeting strings).
    pub server_host: &'a str,
    /// Server port.
    pub server_port: u16,
    /// Local client port.
    pub client_port: u16,
    /// Caller ordinal keeping the session id deterministic.
    pub index: u64,
    /// Socket-security mode of the connection.
    pub mode: SocketMode,
    /// Handshake observation, when one ran.
    pub observation: Option<&'a LiveTlsObservation>,
    /// Session start, Unix epoch milliseconds (caller-supplied).
    pub started_at_unix_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleEngine, SecurityPolicy};

    fn engine() -> RuleEngine {
        RuleEngine::new(SecurityPolicy::default())
    }

    fn strong_tls13() -> LiveTlsObservation {
        LiveTlsObservation {
            version_name: Some("TLSv1_3".to_string()),
            cipher_suite_iana: Some(0x1301),
            key_exchange_group: Some("x25519".to_string()),
            peer_cert_count: 2,
            upgraded_via_starttls: false,
            cert_verdict: Some(LiveCertVerdict::Valid),
        }
    }

    fn input(
        protocol: Protocol,
        server_port: u16,
        client_port: u16,
        index: u64,
        mode: SocketMode,
        obs: Option<&LiveTlsObservation>,
    ) -> LiveSessionInput<'_> {
        LiveSessionInput {
            source_tag: "live",
            protocol,
            server_host: "mail.example.test",
            server_port,
            client_port,
            index,
            mode,
            observation: obs,
            started_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn implicit_tls13_valid_chain_is_quiet_except_truncation_note() {
        let obs = strong_tls13();
        let event = event_from_live(&input(
            Protocol::Imap,
            993,
            51000,
            0,
            SocketMode::ImplicitTls,
            Some(&obs),
        ));
        assert_eq!(event.transport, TransportSecurity::ImplicitTls);
        let findings = engine().evaluate_session(&event);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        // No version/cipher/kex/trust findings for a healthy handshake…
        assert!(
            !ids.iter().any(|id| id.starts_with("KIWI-TLS-00")
                || id.starts_with("KIWI-CIPHER-")
                || id.starts_with("KIWI-KEX-")
                || *id == "KIWI-CERT-012"),
            "unexpected findings: {ids:?}"
        );
        // …but the unparsed DER count must surface as an explicit limitation.
        assert!(
            ids.contains(&"KIWI-CERT-010"),
            "unparsed chain must be flagged truncated, got {ids:?}"
        );
    }

    #[test]
    fn expired_verdict_becomes_trust_rejected() {
        let mut obs = strong_tls13();
        obs.cert_verdict = Some(LiveCertVerdict::Expired);
        let event = event_from_live(&input(
            Protocol::Smtp,
            465,
            51001,
            1,
            SocketMode::ImplicitTls,
            Some(&obs),
        ));
        let findings = engine().evaluate_session(&event);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"KIWI-CERT-012"), "got {ids:?}");
    }

    #[test]
    fn plaintext_socket_without_handshake_is_plaintext() {
        let event = event_from_live(&input(
            Protocol::Smtp,
            25,
            51002,
            2,
            SocketMode::Plaintext,
            None,
        ));
        assert_eq!(event.transport, TransportSecurity::Plaintext);
        assert!(event.tls.is_none());
        let findings = engine().evaluate_session(&event);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"KIWI-TRANSPORT-001"), "got {ids:?}");
    }

    #[test]
    fn unrecognized_version_string_is_never_guessed() {
        let mut obs = strong_tls13();
        obs.version_name = Some("TLSv9_FUTURE".to_string());
        let event = event_from_live(&input(
            Protocol::Imap,
            993,
            51003,
            3,
            SocketMode::ImplicitTls,
            Some(&obs),
        ));
        assert_eq!(
            event.negotiated_tls_version(),
            Some(TlsVersion::Unknown(0xFFFF))
        );
        let findings = engine().evaluate_session(&event);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"KIWI-TLS-003"), "got {ids:?}");
        assert!(
            !ids.contains(&"KIWI-TLS-001"),
            "unknown version must not feed the floor rule, got {ids:?}"
        );
    }

    #[test]
    fn version_names_parse() {
        assert_eq!(parse_version_name("TLSv1_3"), TlsVersion::Tls13);
        assert_eq!(parse_version_name("TLSv1_2"), TlsVersion::Tls12);
        assert_eq!(parse_version_name("TLSv1"), TlsVersion::Tls10);
        assert_eq!(parse_version_name("SSLv3"), TlsVersion::Ssl3);
    }
}
