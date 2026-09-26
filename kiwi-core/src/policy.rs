//! Trust/lock policy and the deterministic session→signal mapping.
//!
//! `TrustPolicy` is the knob-set an org or the local default config supplies.
//! `session_signals` converts observed `SecuritySession` facts into
//! `TrustSignal`s — the trust engine's inputs. Deep weakness classification
//! and forensic findings remain kiwi-forensics' job; this mapping only
//! covers indicators the lock decision needs at session-establish time.

use std::collections::BTreeSet;

use crate::session::{AuthMechanism, SecuritySession, TlsVersion, TransportSecurity};
use crate::trust::{SignalKind, SignalSeverity, TrustSignal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Score below this → `Degraded`.
    pub degrade_threshold: u32,
    /// Score below this → `Locked`.
    pub lock_threshold: u32,
    /// Signal kinds that lock immediately regardless of score.
    pub hard_lock: BTreeSet<SignalKind>,
    /// Minimum acceptable negotiated TLS version, if the org pins one.
    pub min_tls_version: Option<TlsVersion>,
    /// When true, leaving `Locked` requires a verified authenticator
    /// challenge (challenge::ChallengeBook::verify).
    pub unlock_requires_authenticator: bool,
    /// When true, `Degraded` returns to `Trusted` once signals clear.
    pub auto_recover_degraded: bool,
    /// Authenticator challenge time-to-live, seconds.
    pub challenge_ttl_secs: u64,
    /// Account-session time-to-live, seconds.
    pub session_ttl_secs: u64,
}

impl Default for TrustPolicy {
    /// Conservative local-first defaults; orgs may tighten via kiwi-admin.
    fn default() -> Self {
        Self {
            degrade_threshold: 80,
            lock_threshold: 40,
            hard_lock: [
                SignalKind::DeviceRevoked,
                SignalKind::ReplayDetected,
                SignalKind::PolicyViolation,
                SignalKind::CertificateHostnameMismatch,
                SignalKind::CertificateInvalid,
            ]
            .into_iter()
            .collect(),
            min_tls_version: Some(TlsVersion::Tls1_2),
            unlock_requires_authenticator: true,
            auto_recover_degraded: true,
            challenge_ttl_secs: 120,
            session_ttl_secs: 12 * 60 * 60,
        }
    }
}

impl TrustPolicy {
    /// Deterministically map a session observation to trust signals.
    /// Every signal carries an `evidence_ref`; callers attach the real
    /// evidence/finding id when persisting.
    pub fn session_signals(&self, s: &SecuritySession) -> Vec<TrustSignal> {
        self.session_signals_ex(s, crate::dev::plaintext_fixture_for(&s.server_host))
    }

    /// `session_signals` with the dev-plaintext-loopback exemption decided by
    /// the caller — tests pass `dev_fixture` explicitly so the policy outcome
    /// never depends on process env.
    pub fn session_signals_ex(&self, s: &SecuritySession, dev_fixture: bool) -> Vec<TrustSignal> {
        let mut out = Vec::new();
        let mut push = |kind: SignalKind, severity: SignalSeverity, penalty: u32| {
            out.push(TrustSignal {
                kind,
                severity,
                penalty,
                evidence_ref: format!("sess:{}", s.session_id),
            })
        };

        match s.transport {
            TransportSecurity::Plaintext if dev_fixture => {
                // KIWI_DEV_PLAINTEXT + loopback host: the plaintext session is
                // still recorded as evidence but does not lock. The downgrade
                // cascade does not apply — a fixture server without TLS is the
                // declared shape, not a suspicious omission.
                push(SignalKind::PlaintextTransport, SignalSeverity::Info, 0);
            }
            TransportSecurity::Plaintext => {
                push(SignalKind::PlaintextTransport, SignalSeverity::High, 45);
                if s.starttls_offered == Some(true) && !s.starttls_used {
                    push(
                        SignalKind::StartTlsDowngradeSuspected,
                        SignalSeverity::Critical,
                        45,
                    );
                }
            }
            TransportSecurity::StartTls | TransportSecurity::Tls => {
                if let Some(v) = s.tls_version {
                    if v.is_deprecated() {
                        push(SignalKind::DeprecatedTlsVersion, SignalSeverity::High, 40);
                    }
                    if let Some(min) = self.min_tls_version
                        && v < min
                    {
                        push(SignalKind::PolicyViolation, SignalSeverity::Critical, 100);
                    }
                }
                if !s.has_forward_secrecy() {
                    push(SignalKind::NoForwardSecrecy, SignalSeverity::Medium, 25);
                }
                if let Some(chain) = &s.cert_chain {
                    use crate::session::ChainValidation::*;
                    match chain.validation {
                        Invalid => push(
                            SignalKind::CertificateInvalid,
                            SignalSeverity::Critical,
                            100,
                        ),
                        Expired => push(SignalKind::CertificateExpired, SignalSeverity::High, 60),
                        Untrusted => {
                            push(SignalKind::CertificateUntrusted, SignalSeverity::High, 60)
                        }
                        HostnameMismatch => push(
                            SignalKind::CertificateHostnameMismatch,
                            SignalSeverity::Critical,
                            100,
                        ),
                        Valid | Unknown => {}
                    }
                }
            }
        }

        if s.auth_succeeded == Some(false) {
            push(SignalKind::RepeatedAuthFailure, SignalSeverity::Medium, 20);
        }

        let credentialed_mech = matches!(
            s.auth_mechanism,
            AuthMechanism::Plain | AuthMechanism::Login | AuthMechanism::CramMd5
        );
        if credentialed_mech && s.transport == TransportSecurity::Plaintext {
            if dev_fixture {
                // Declared fixture auth — evidence kept, no penalty.
                push(SignalKind::WeakAuthMechanism, SignalSeverity::Info, 0);
            } else {
                push(SignalKind::WeakAuthMechanism, SignalSeverity::High, 40);
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::*;

    fn base_session() -> SecuritySession {
        SecuritySession {
            schema_version: SCHEMA_VERSION,
            session_id: "s1".into(),
            account_id: Some("acct1".into()),
            device_id: Some("dev1".into()),
            protocol: Protocol::Imap,
            server_host: "imap.example.test".into(),
            server_port: 993,
            transport: TransportSecurity::Tls,
            tls_version: Some(TlsVersion::Tls1_3),
            cipher_suite: Some(CipherSuite {
                iana_id: Some(0x1302),
                name: "TLS_AES_256_GCM_SHA384".into(),
                forward_secrecy: true,
            }),
            key_exchange_group: Some(KeyExchangeGroup::X25519),
            cert_chain: Some(CertChainSummary {
                leaf: None,
                presented_len: 2,
                validation: ChainValidation::Valid,
            }),
            starttls_offered: None,
            starttls_used: false,
            auth_mechanism: AuthMechanism::XOAuth2,
            auth_succeeded: Some(true),
            established_unix: 1_758_000_000,
            source: SessionSource::ThunderbirdHook,
        }
    }

    #[test]
    fn clean_tls13_session_yields_no_signals() {
        let s = base_session();
        assert!(TrustPolicy::default().session_signals(&s).is_empty());
    }

    #[test]
    fn loopback_dev_fixture_records_evidence_without_lock_cascade() {
        let mut s = base_session();
        s.transport = TransportSecurity::Plaintext;
        s.tls_version = None;
        s.cipher_suite = None;
        s.cert_chain = None;
        s.server_host = "127.0.0.1".into();
        s.auth_mechanism = AuthMechanism::Login;
        // Dev-exempt: signal kept as Info evidence; no High/Critical cascade.
        let sigs = TrustPolicy::default().session_signals_ex(&s, true);
        let pt = sigs
            .iter()
            .find(|x| x.kind == SignalKind::PlaintextTransport)
            .expect("plaintext signal still recorded");
        assert_eq!(pt.severity, SignalSeverity::Info);
        assert_eq!(pt.penalty, 0);
        assert!(
            !sigs
                .iter()
                .any(|x| x.kind == SignalKind::StartTlsDowngradeSuspected)
        );
        assert!(
            sigs.iter()
                .all(|x| x.severity == SignalSeverity::Info && x.penalty == 0)
        );
        // Not exempt: identical session keeps the locking cascade.
        let sigs = TrustPolicy::default().session_signals_ex(&s, false);
        let pt = sigs
            .iter()
            .find(|x| x.kind == SignalKind::PlaintextTransport)
            .unwrap();
        assert_eq!(pt.severity, SignalSeverity::High);
        assert_eq!(pt.penalty, 45);
        assert!(
            sigs.iter()
                .any(|x| x.kind == SignalKind::WeakAuthMechanism
                    && x.severity == SignalSeverity::High)
        );
    }

    #[test]
    fn plaintext_yields_high_penalty_signal() {
        let mut s = base_session();
        s.transport = TransportSecurity::Plaintext;
        s.tls_version = None;
        s.cipher_suite = None;
        s.cert_chain = None;
        let sigs = TrustPolicy::default().session_signals(&s);
        assert!(
            sigs.iter()
                .any(|x| x.kind == SignalKind::PlaintextTransport)
        );
    }

    #[test]
    fn starttls_offered_but_unused_suspects_downgrade() {
        let mut s = base_session();
        s.transport = TransportSecurity::Plaintext;
        s.tls_version = None;
        s.starttls_offered = Some(true);
        s.starttls_used = false;
        let sigs = TrustPolicy::default().session_signals(&s);
        assert!(
            sigs.iter()
                .any(|x| x.kind == SignalKind::StartTlsDowngradeSuspected)
        );
    }

    #[test]
    fn deprecated_tls_flagged() {
        let mut s = base_session();
        s.tls_version = Some(TlsVersion::Tls1_0);
        let sigs = TrustPolicy::default().session_signals(&s);
        assert!(
            sigs.iter()
                .any(|x| x.kind == SignalKind::DeprecatedTlsVersion)
        );
    }

    #[test]
    fn below_min_tls_is_policy_violation() {
        let mut s = base_session();
        s.tls_version = Some(TlsVersion::Tls1_1);
        let sigs = TrustPolicy::default().session_signals(&s);
        assert!(sigs.iter().any(|x| x.kind == SignalKind::PolicyViolation));
    }

    #[test]
    fn hostname_mismatch_is_hard_lock_candidate() {
        let mut s = base_session();
        s.cert_chain = Some(CertChainSummary {
            leaf: None,
            presented_len: 1,
            validation: ChainValidation::HostnameMismatch,
        });
        let policy = TrustPolicy::default();
        let sigs = policy.session_signals(&s);
        assert!(sigs.iter().any(|x| policy.hard_lock.contains(&x.kind)));
    }

    #[test]
    fn plaintext_auth_is_weak_mechanism() {
        let mut s = base_session();
        s.transport = TransportSecurity::Plaintext;
        s.tls_version = None;
        s.auth_mechanism = AuthMechanism::Plain;
        let sigs = TrustPolicy::default().session_signals(&s);
        assert!(sigs.iter().any(|x| x.kind == SignalKind::WeakAuthMechanism));
    }
}
