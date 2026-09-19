//! Endpoint/session trust engine.
//!
//! The trust decision is a pure function of measurable signals + policy.
//! `Trusted → Degraded → Locked`; `Locked` is sticky and can only be left via
//! an authorized unlock path (authenticator-bound by default — see
//! `crate::challenge`). This engine makes no compromise claims; it records
//! indicators and reduces trust deterministically (SECURITY.md rule 3).

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustState {
    Trusted,
    Degraded,
    Locked,
}

/// Measurable indicators that reduce trust. Every variant maps to something
/// observable — no speculation, no "malware detected" style claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalKind {
    // --- Transport / cryptographic indicators (from SecuritySession) ---
    PlaintextTransport,
    /// Server advertised STARTTLS earlier but session stayed cleartext.
    StartTlsDowngradeSuspected,
    DeprecatedTlsVersion,
    WeakCipherSuite,
    NoForwardSecrecy,
    CertificateInvalid,
    CertificateExpired,
    CertificateUntrusted,
    CertificateHostnameMismatch,
    /// Cert fingerprint for a known server changed unexpectedly.
    CertificateUnexpectedChange,
    /// AUTH PLAIN/LOGIN-style mechanism over a non-TLS transport.
    WeakAuthMechanism,
    RepeatedAuthFailure,

    // --- Endpoint / session indicators ---
    NewDeviceUnverified,
    RemoteSessionIndicator,
    EndpointIntegrityFailure,
    DeviceSuspended,

    // --- Hard-lock indicators ---
    DeviceRevoked,
    /// Authenticator challenge replay or binding violation observed.
    ReplayDetected,
    /// Connection violates an explicit policy floor (e.g. min TLS version).
    PolicyViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// One measured indicator with its deterministic trust penalty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustSignal {
    pub kind: SignalKind,
    pub severity: SignalSeverity,
    /// Trust-score deduction, 0..=100.
    pub penalty: u32,
    /// Reference to the evidence record backing this signal
    /// (finding/evidence id). Never a free-text-only conclusion.
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredAction {
    None,
    /// Surface a warning; mail flow may continue.
    WarnUser,
    /// Access withheld until a fresh successful authentication.
    RequireReauth,
    /// Access withheld until authenticator-approved unlock completes.
    RequireAuthenticatorUnlock,
    /// Hard stop: no mailbox access, no credential use on this session.
    BlockAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEvaluation {
    pub state: TrustState,
    /// 0..=100, 100 = no adverse indicators.
    pub score: u32,
    pub signals: Vec<TrustSignal>,
    pub required_action: RequiredAction,
}

/// Stateful per-session/per-device trust tracker enforcing legal transitions.
pub struct TrustMachine {
    state: TrustState,
    score: u32,
    active: Vec<TrustSignal>,
    /// Kinds that fired since the last `Trusted` state — audit trail.
    history: Vec<SignalKind>,
}

impl TrustMachine {
    pub fn new() -> Self {
        Self {
            state: TrustState::Trusted,
            score: 100,
            active: Vec::new(),
            history: Vec::new(),
        }
    }

    pub fn state(&self) -> TrustState {
        self.state
    }

    pub fn score(&self) -> u32 {
        self.score
    }

    pub fn active_signals(&self) -> &[TrustSignal] {
        &self.active
    }

    pub fn history(&self) -> &[SignalKind] {
        &self.history
    }

    /// Deterministically evaluate `signals` against `policy` and apply the
    /// resulting transition. `Locked` never self-recovers here — even a clean
    /// evaluation leaves a locked machine locked.
    pub fn evaluate(
        &mut self,
        policy: &crate::policy::TrustPolicy,
        signals: Vec<TrustSignal>,
    ) -> TrustEvaluation {
        let eval = evaluate(policy, &signals);
        self.score = eval.score;
        self.active = signals;
        for s in &self.active {
            self.history.push(s.kind);
        }
        match eval.state {
            TrustState::Locked => self.state = TrustState::Locked,
            TrustState::Degraded => {
                if self.state != TrustState::Locked {
                    self.state = TrustState::Degraded;
                }
            }
            TrustState::Trusted => {
                if self.state == TrustState::Degraded && policy.auto_recover_degraded {
                    self.state = TrustState::Trusted;
                }
                // Trusted stays Trusted; Locked stays Locked.
            }
        }
        TrustEvaluation {
            state: self.state,
            ..eval
        }
    }

    /// Attempt to leave `Locked`. When `policy.unlock_requires_authenticator`
    /// is set, `authenticator_approved` must be the result of a successfully
    /// verified, device+session+event-bound challenge — callers pass `true`
    /// only after `challenge::ChallengeBook::verify` returned `Ok`.
    ///
    /// On approval the machine lands in `Degraded` if adverse signals are
    /// still active, otherwise `Trusted`.
    pub fn attempt_unlock(
        &mut self,
        policy: &crate::policy::TrustPolicy,
        authenticator_approved: bool,
    ) -> Result<TrustState, UnlockError> {
        if self.state != TrustState::Locked {
            return Err(UnlockError::NotLocked);
        }
        if policy.unlock_requires_authenticator && !authenticator_approved {
            return Err(UnlockError::AuthenticatorRequired);
        }
        self.state = if self.active.is_empty() {
            TrustState::Trusted
        } else {
            TrustState::Degraded
        };
        Ok(self.state)
    }

    /// Administrative lock — always allowed, always audited by the caller.
    pub fn force_lock(&mut self) {
        self.state = TrustState::Locked;
    }
}

impl Default for TrustMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    NotLocked,
    AuthenticatorRequired,
}

/// Pure evaluation: score = 100 − Σ penalties (clamped); hard-lock kinds and
/// score below `policy.lock_threshold` produce `Locked`.
pub fn evaluate(policy: &crate::policy::TrustPolicy, signals: &[TrustSignal]) -> TrustEvaluation {
    let score = 100u32.saturating_sub(signals.iter().map(|s| s.penalty).sum::<u32>());

    let hard_lock: BTreeSet<SignalKind> = signals
        .iter()
        .map(|s| s.kind)
        .filter(|k| policy.hard_lock.contains(k))
        .collect();

    let (state, required_action) = if !hard_lock.is_empty() || score < policy.lock_threshold {
        (
            TrustState::Locked,
            if policy.unlock_requires_authenticator {
                RequiredAction::RequireAuthenticatorUnlock
            } else {
                RequiredAction::BlockAccess
            },
        )
    } else if score < policy.degrade_threshold
        || signals.iter().any(|s| s.severity >= SignalSeverity::Medium)
    {
        (TrustState::Degraded, RequiredAction::WarnUser)
    } else {
        (TrustState::Trusted, RequiredAction::None)
    };

    TrustEvaluation {
        state,
        score,
        signals: signals.to_vec(),
        required_action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TrustPolicy;

    fn sig(kind: SignalKind, severity: SignalSeverity, penalty: u32) -> TrustSignal {
        TrustSignal {
            kind,
            severity,
            penalty,
            evidence_ref: format!("ev-{kind:?}"),
        }
    }

    #[test]
    fn clean_signals_stay_trusted() {
        let mut m = TrustMachine::new();
        let e = m.evaluate(&TrustPolicy::default(), vec![]);
        assert_eq!(e.state, TrustState::Trusted);
        assert_eq!(e.score, 100);
        assert_eq!(e.required_action, RequiredAction::None);
    }

    #[test]
    fn weak_signals_degrade() {
        let mut m = TrustMachine::new();
        let e = m.evaluate(
            &TrustPolicy::default(),
            vec![sig(
                SignalKind::NoForwardSecrecy,
                SignalSeverity::Medium,
                25,
            )],
        );
        assert_eq!(e.state, TrustState::Degraded);
        assert_eq!(e.required_action, RequiredAction::WarnUser);
    }

    #[test]
    fn score_below_lock_threshold_locks() {
        let mut m = TrustMachine::new();
        let e = m.evaluate(
            &TrustPolicy::default(),
            vec![
                sig(SignalKind::DeprecatedTlsVersion, SignalSeverity::High, 40),
                sig(SignalKind::WeakCipherSuite, SignalSeverity::High, 40),
            ],
        );
        assert_eq!(e.state, TrustState::Locked);
        assert_eq!(
            e.required_action,
            RequiredAction::RequireAuthenticatorUnlock
        );
    }

    #[test]
    fn hard_lock_signal_locks_regardless_of_score() {
        let mut m = TrustMachine::new();
        // DeviceRevoked is a hard-lock kind in the default policy; penalty is
        // deliberately tiny to prove score doesn't matter.
        let e = m.evaluate(
            &TrustPolicy::default(),
            vec![sig(SignalKind::DeviceRevoked, SignalSeverity::Critical, 1)],
        );
        assert_eq!(e.state, TrustState::Locked);
    }

    #[test]
    fn locked_does_not_self_recover() {
        let mut m = TrustMachine::new();
        m.evaluate(
            &TrustPolicy::default(),
            vec![sig(SignalKind::DeviceRevoked, SignalSeverity::Critical, 1)],
        );
        let e = m.evaluate(&TrustPolicy::default(), vec![]);
        assert_eq!(e.state, TrustState::Locked, "clean eval must not unlock");
    }

    #[test]
    fn degraded_auto_recovers_when_signals_clear() {
        let mut m = TrustMachine::new();
        m.evaluate(
            &TrustPolicy::default(),
            vec![sig(
                SignalKind::NoForwardSecrecy,
                SignalSeverity::Medium,
                25,
            )],
        );
        assert_eq!(m.state(), TrustState::Degraded);
        let e = m.evaluate(&TrustPolicy::default(), vec![]);
        assert_eq!(e.state, TrustState::Trusted);
    }

    #[test]
    fn unlock_requires_authenticator_when_policy_says_so() {
        let policy = TrustPolicy::default();
        let mut m = TrustMachine::new();
        m.evaluate(
            &policy,
            vec![sig(SignalKind::DeviceRevoked, SignalSeverity::Critical, 1)],
        );
        assert_eq!(
            m.attempt_unlock(&policy, false),
            Err(UnlockError::AuthenticatorRequired)
        );
        assert_eq!(m.state(), TrustState::Locked);
        // Revoked-device signal is still active → unlock lands in Degraded.
        assert_eq!(m.attempt_unlock(&policy, true), Ok(TrustState::Degraded));
        // Signals cleared → auto-recovery returns to Trusted.
        assert_eq!(m.evaluate(&policy, vec![]).state, TrustState::Trusted);
    }

    #[test]
    fn unlock_lands_degraded_when_signals_persist() {
        let policy = TrustPolicy::default();
        let mut m = TrustMachine::new();
        m.evaluate(
            &policy,
            vec![
                sig(SignalKind::DeviceRevoked, SignalSeverity::Critical, 1),
                sig(
                    SignalKind::RemoteSessionIndicator,
                    SignalSeverity::Medium,
                    20,
                ),
            ],
        );
        assert_eq!(m.attempt_unlock(&policy, true), Ok(TrustState::Degraded));
    }

    #[test]
    fn unlock_on_unlocked_machine_is_error() {
        let mut m = TrustMachine::new();
        assert_eq!(
            m.attempt_unlock(&TrustPolicy::default(), true),
            Err(UnlockError::NotLocked)
        );
    }
}
