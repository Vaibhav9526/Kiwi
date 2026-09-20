//! Observation pipeline: one live mail connection → `SecuritySession`
//! (kiwi-core) → trust signals → `ConnectionSecurityEvent` (kiwi-forensics
//! live adapter) → deterministic findings → bounded journals in `AppState`.
//!
//! Every network-touching command (verify, test, sync, send) ends its
//! connection through `record_connection` so the trust engine and the
//! finding feed always see real transport facts. Nothing here invents
//! data: absent observations stay `None`/`Unknown` (SECURITY.md A2).
//!
//! `Transport`/`MailStore` are `!Sync` (dyn stream, rusqlite internals), so
//! the async half of this module takes an owned [`TransportFacts`] snapshot
//! — no borrowed transport or store ever crosses an `.await`.

use kiwi_core::session::{
    AuthMechanism, CertChainSummary, CertificateSummary, ChainValidation, KeyExchangeGroup,
    Protocol, SCHEMA_VERSION, SecuritySession, TlsVersion, TransportSecurity,
};
use kiwi_core::trust::{SignalKind, SignalSeverity, TrustEvaluation, TrustSignal};
use kiwi_forensics::findings::Finding;
use kiwi_forensics::live::{
    LiveAuthObservation, LiveCertVerdict, LiveSessionInput, LiveTlsObservation, SocketMode,
    event_from_live,
};
use kiwi_forensics::rules::{RuleEngine, SecurityPolicy};
use kiwi_mail::transport::{CertVerdict, SocketSecurity, TlsObservation, Transport};
use sha2::{Digest, Sha256};

use crate::state::{AppState, MAX_FINDINGS, MAX_SESSIONS, SessionRecord, now_unix, now_unix_ms};

/// Owned snapshot of a `Transport`'s observation — extracted synchronously
/// (never borrow `Transport` into an async context; it is `!Sync`).
#[derive(Debug, Clone)]
pub struct TransportFacts {
    pub host: String,
    pub port: u16,
    pub security: SocketSecurity,
    pub observation: Option<TlsObservation>,
}

/// Snapshot a live transport. Call while the client is still open.
pub fn facts_of(t: &Transport) -> TransportFacts {
    TransportFacts {
        host: t.host().to_string(),
        port: t.port(),
        security: t.socket_security(),
        observation: t.observation().cloned(),
    }
}

/// What one established connection observed — inputs `record_connection`
/// cannot read off the transport itself.
pub struct ObservationContext {
    pub protocol: Protocol,
    pub account_id: Option<String>,
    /// STARTTLS advertised by the server (EHLO/CAPABILITY/CAPA), when the
    /// protocol client knows — `None` = unknown.
    pub starttls_offered: Option<bool>,
    pub auth_mechanism: AuthMechanism,
    /// `Some(false)` on an observed auth failure.
    pub auth_succeeded: Option<bool>,
    /// Short label for the security event view ("imap sync", "smtp send").
    pub label: &'static str,
}

/// Record a finished/established connection: build the `SecuritySession`,
/// derive trust signals, run the forensics rule engine, journal everything,
/// and re-evaluate endpoint trust. Returns the trust evaluation so callers
/// can react (e.g. abort a send when the connection hard-locks the session).
pub async fn record_connection(
    state: &AppState,
    facts: TransportFacts,
    ctx: ObservationContext,
) -> (SessionRecord, TrustEvaluation) {
    let session = security_session(state, &facts, &ctx);
    let signals = state.policy.session_signals(&session);
    let findings = forensics_findings(&facts, &ctx, &session.session_id);

    let record = SessionRecord {
        session,
        signals,
        findings,
        label: ctx.label.to_string(),
    };

    // sessions then findings: sequential locks, never nested.
    {
        let mut sessions = state.sessions.lock().await;
        if sessions.len() >= MAX_SESSIONS {
            sessions.pop_front();
        }
        sessions.push_back(record.clone());
    }
    {
        let mut findings = state.findings.lock().await;
        for f in &record.findings {
            if findings.len() >= MAX_FINDINGS
                && let Some(oldest) = findings.keys().next().cloned()
            {
                findings.remove(&oldest);
            }
            findings.insert(f.finding_id(), f.clone());
        }
    }
    let eval = state.refresh_trust().await;
    (record, eval)
}

/// Map a device-status `SignalKind` (kiwi-core returns kinds only) to a full
/// `TrustSignal` — severity/penalty table lives here until kiwi-core owns it
/// (noted gap; evidence_ref points at the device record).
pub fn device_signal(device_id: &str, kind: SignalKind) -> TrustSignal {
    let (severity, penalty) = match kind {
        SignalKind::NewDeviceUnverified => (SignalSeverity::Medium, 15),
        SignalKind::DeviceSuspended => (SignalSeverity::High, 40),
        SignalKind::DeviceRevoked => (SignalSeverity::Critical, 100),
        SignalKind::RemoteSessionIndicator => (SignalSeverity::Medium, 20),
        SignalKind::EndpointIntegrityFailure => (SignalSeverity::High, 40),
        _ => (SignalSeverity::Low, 10),
    };
    TrustSignal {
        kind,
        severity,
        penalty,
        evidence_ref: format!("device:{device_id}:{:?}", kind),
    }
}

fn security_session(
    state: &AppState,
    f: &TransportFacts,
    ctx: &ObservationContext,
) -> SecuritySession {
    let obs = f.observation.as_ref();
    let transport = match f.security {
        SocketSecurity::Plaintext => TransportSecurity::Plaintext,
        SocketSecurity::ImplicitTls => TransportSecurity::Tls,
        SocketSecurity::StartTls => {
            if obs.is_some_and(|o| o.upgraded_via_starttls) {
                TransportSecurity::StartTls
            } else {
                TransportSecurity::Plaintext
            }
        }
    };
    let tls_version = obs.and_then(|o| tls_version(o.protocol_version.as_deref()));
    let forward_secrecy = match (tls_version, obs.and_then(|o| o.cipher_suite_iana)) {
        (Some(TlsVersion::Tls1_3), _) => true,
        (_, Some(iana)) => {
            kiwi_forensics::model::CipherSuite::from_iana(iana).forward_secrecy()
                == kiwi_forensics::model::ForwardSecrecy::Yes
        }
        _ => false,
    };
    let cert_chain = obs
        .filter(|o| o.cert_verdict.is_some() || !o.peer_certificates.is_empty())
        .map(|o| CertChainSummary {
            leaf: o
                .peer_certificates
                .first()
                .and_then(|der| cert_summary(der)),
            presented_len: o.peer_certificates.len().min(u8::MAX as usize) as u8,
            validation: o
                .cert_verdict
                .map_or(ChainValidation::Unknown, chain_validation),
        });
    SecuritySession {
        schema_version: SCHEMA_VERSION,
        session_id: state.next_session_id(match ctx.protocol {
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
        }),
        account_id: ctx.account_id.clone(),
        device_id: None,
        protocol: ctx.protocol,
        server_host: f.host.clone(),
        server_port: f.port,
        transport,
        tls_version,
        cipher_suite: obs.and_then(|o| {
            o.cipher_suite
                .clone()
                .map(|name| kiwi_core::session::CipherSuite {
                    iana_id: o.cipher_suite_iana,
                    name,
                    forward_secrecy,
                })
        }),
        key_exchange_group: obs.and_then(|o| o.key_exchange_group.as_deref().map(kex_group)),
        cert_chain,
        starttls_offered: ctx.starttls_offered,
        starttls_used: obs.is_some_and(|o| o.upgraded_via_starttls),
        auth_mechanism: ctx.auth_mechanism.clone(),
        auth_succeeded: ctx.auth_succeeded,
        established_unix: now_unix(),
        // Live client observation (contract field name predates the pivot).
        source: kiwi_core::session::SessionSource::ThunderbirdHook,
    }
}

fn forensics_findings(
    f: &TransportFacts,
    ctx: &ObservationContext,
    session_id: &str,
) -> Vec<Finding> {
    let obs = f.observation.as_ref().map(|o| LiveTlsObservation {
        version_name: o.protocol_version.clone(),
        cipher_suite_iana: o.cipher_suite_iana,
        key_exchange_group: o.key_exchange_group.clone(),
        peer_cert_count: o.peer_certificates.len(),
        upgraded_via_starttls: o.upgraded_via_starttls,
        cert_verdict: o.cert_verdict.map(|v| match v {
            CertVerdict::Valid => LiveCertVerdict::Valid,
            CertVerdict::Invalid => LiveCertVerdict::Invalid,
            CertVerdict::Untrusted => LiveCertVerdict::Untrusted,
            CertVerdict::Expired => LiveCertVerdict::Expired,
            CertVerdict::HostnameMismatch => LiveCertVerdict::HostnameMismatch,
            CertVerdict::Unknown => LiveCertVerdict::Unknown,
        }),
    });
    let mode = match f.security {
        SocketSecurity::Plaintext => SocketMode::Plaintext,
        SocketSecurity::ImplicitTls => SocketMode::ImplicitTls,
        SocketSecurity::StartTls => SocketMode::StartTls,
    };
    let event = event_from_live(&LiveSessionInput {
        source_tag: session_id,
        protocol: match ctx.protocol {
            Protocol::Smtp => kiwi_forensics::model::Protocol::Smtp,
            Protocol::Imap => kiwi_forensics::model::Protocol::Imap,
            Protocol::Pop3 => kiwi_forensics::model::Protocol::Pop3,
        },
        server_host: &f.host,
        server_port: f.port,
        client_port: 0,
        index: 0,
        mode,
        observation: obs.as_ref(),
        started_at_unix_ms: now_unix_ms(),
        // T-164-adjacent (contract §11): observed auth facts now flow —
        // AUTH rules (001–006) are live, not capture-only.
        auth: live_auth_of(ctx).as_ref(),
    });
    let engine = RuleEngine::new(SecurityPolicy::default());
    let mut findings = engine.evaluate_session(&event);
    if let Some(acct) = &ctx.account_id {
        for f in &mut findings {
            f.subject = f.subject.clone().with_account(acct);
        }
    }
    findings
}

/// Map the core `AuthMechanism` observation into the forensics adapter's
/// auth input — contract forensics.md §11: `from_token` over the core
/// spelling; `none` → no observation at all (AUTH rules stay silent);
/// `client-cert` → `External`; `other:<name>` → `from_token(<name>)`
/// (`Unknown` on mismatch — conservatism, not guessing). `attempts` is 1
/// whenever a mechanism was observed; `failures` is 1 on `succeeded ==
/// Some(false)`; `succeeded` passes verbatim.
fn live_auth_of(ctx: &ObservationContext) -> Option<LiveAuthObservation> {
    use kiwi_forensics::model::AuthMechanism as FAuth;
    let spelling = crate::types::auth_mechanism(&ctx.auth_mechanism);
    let mechanism = match spelling.as_str() {
        "none" => return None,
        "client-cert" => FAuth::External,
        s => FAuth::from_token(s.strip_prefix("other:").unwrap_or(s)),
    };
    Some(LiveAuthObservation {
        mechanism: Some(mechanism),
        succeeded: ctx.auth_succeeded,
        attempts: 1,
        failures: u32::from(ctx.auth_succeeded == Some(false)),
    })
}

fn tls_version(name: Option<&str>) -> Option<TlsVersion> {
    Some(match name? {
        "TLSv1_3" => TlsVersion::Tls1_3,
        "TLSv1_2" => TlsVersion::Tls1_2,
        "TLSv1_1" => TlsVersion::Tls1_1,
        "TLSv1" | "TLSv1_0" => TlsVersion::Tls1_0,
        "SSLv3" | "SSLv3_0" => TlsVersion::Ssl3,
        _ => TlsVersion::Unknown,
    })
}

fn kex_group(name: &str) -> KeyExchangeGroup {
    match name.to_ascii_lowercase().as_str() {
        "x25519" => KeyExchangeGroup::X25519,
        "secp256r1" => KeyExchangeGroup::SecP256r1,
        "secp384r1" => KeyExchangeGroup::SecP384r1,
        "secp521r1" => KeyExchangeGroup::SecP521r1,
        "ffdhe2048" => KeyExchangeGroup::Ffdhe2048,
        "ffdhe3072" => KeyExchangeGroup::Ffdhe3072,
        "ffdhe4096" => KeyExchangeGroup::Ffdhe4096,
        "unknown" => KeyExchangeGroup::Unknown,
        other => KeyExchangeGroup::Other(other.to_string()),
    }
}

fn chain_validation(v: CertVerdict) -> ChainValidation {
    match v {
        CertVerdict::Valid => ChainValidation::Valid,
        CertVerdict::Invalid => ChainValidation::Invalid,
        CertVerdict::Untrusted => ChainValidation::Untrusted,
        CertVerdict::Expired => ChainValidation::Expired,
        CertVerdict::HostnameMismatch => ChainValidation::HostnameMismatch,
        CertVerdict::Unknown => ChainValidation::Unknown,
    }
}

/// Parse a leaf certificate DER into the contract `CertificateSummary`.
/// Returns `None` on unparseable input — an unparsed cert is an absence of
/// fact, not a guess (x509-parser boundary: DER is untrusted input, bounded
/// by rustls' own capture).
fn cert_summary(der: &[u8]) -> Option<CertificateSummary> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let tbs = &cert.tbs_certificate;
    let fingerprint = {
        let mut h = Sha256::new();
        h.update(der);
        crate::audit::hex(&h.finalize())
    };
    Some(CertificateSummary {
        subject_dn: tbs.subject.to_string(),
        issuer_dn: tbs.issuer.to_string(),
        serial_hex: crate::audit::hex(&tbs.serial.to_bytes_be()),
        not_before_unix: tbs.validity.not_before.timestamp(),
        not_after_unix: tbs.validity.not_after.timestamp(),
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        public_key_algorithm: tbs.subject_pki.algorithm.algorithm.to_string(),
        public_key_bits: tbs
            .subject_pki
            .parsed()
            .ok()
            .map(|pk| pk.key_size())
            .unwrap_or(0) as u32,
        sha256_fingerprint: fingerprint,
        is_self_signed: tbs.subject == tbs.issuer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_names_map() {
        assert_eq!(tls_version(Some("TLSv1_3")), Some(TlsVersion::Tls1_3));
        assert_eq!(tls_version(Some("TLSv1_2")), Some(TlsVersion::Tls1_2));
        assert_eq!(tls_version(Some("TLSv9")), Some(TlsVersion::Unknown));
        assert_eq!(tls_version(None), None);
    }

    #[test]
    fn kex_names_map() {
        assert_eq!(kex_group("X25519"), KeyExchangeGroup::X25519);
        assert_eq!(kex_group("secp256r1"), KeyExchangeGroup::SecP256r1);
        assert!(matches!(kex_group("mlkem768"), KeyExchangeGroup::Other(_)));
    }

    // T-164-adjacent: §11 auth threading into the live adapter.
    fn ctx_with(mech: AuthMechanism, succeeded: Option<bool>) -> ObservationContext {
        ObservationContext {
            protocol: Protocol::Imap,
            account_id: None,
            starttls_offered: None,
            auth_mechanism: mech,
            auth_succeeded: succeeded,
            label: "test",
        }
    }

    #[test]
    fn auth_threading_none_stays_absent() {
        // "none" → no LiveAuthObservation at all — AUTH rules stay silent.
        assert!(live_auth_of(&ctx_with(AuthMechanism::None, None)).is_none());
    }

    #[test]
    fn auth_threading_maps_verbatim_and_counts() {
        use kiwi_forensics::model::AuthMechanism as FAuth;
        let ok = live_auth_of(&ctx_with(AuthMechanism::Login, Some(true))).unwrap();
        assert_eq!(ok.mechanism, Some(FAuth::Login));
        assert_eq!(ok.succeeded, Some(true));
        assert_eq!((ok.attempts, ok.failures), (1, 0));

        let fail = live_auth_of(&ctx_with(AuthMechanism::Plain, Some(false))).unwrap();
        assert_eq!(fail.mechanism, Some(FAuth::Plain));
        assert_eq!((fail.attempts, fail.failures), (1, 1));

        // client-cert → External; other:<name> → from_token; unknown → Unknown.
        let cert = live_auth_of(&ctx_with(AuthMechanism::ClientCertificate, None)).unwrap();
        assert_eq!(cert.mechanism, Some(FAuth::External));
        let other = live_auth_of(&ctx_with(
            AuthMechanism::Other("digest-md5".into()),
            Some(true),
        ))
        .unwrap();
        assert_eq!(other.mechanism, Some(FAuth::DigestMd5));
        let bogus = live_auth_of(&ctx_with(AuthMechanism::Other("zzz".into()), None)).unwrap();
        assert_eq!(bogus.mechanism, Some(FAuth::Unknown));
        let unk = live_auth_of(&ctx_with(AuthMechanism::Unknown, None)).unwrap();
        assert_eq!(unk.mechanism, Some(FAuth::Unknown));
    }
}
