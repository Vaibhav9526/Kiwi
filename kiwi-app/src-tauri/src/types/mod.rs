//! Wire types for the IPC contract (`docs/contracts/ipc.md`).
//!
//! kiwi-core/kiwi-mail domain types deliberately carry no serde derives;
//! these view structs are the stable frontend-facing shapes. All field
//! names are camelCase on the wire (`ui-surfaces.md` §3). Severity tokens
//! are exactly the `ui-surfaces.md` §2 vocabulary: `secure | warning |
//! danger | unknown` (+ orthogonal `locked`).
//!
//! Layout mirrors `commands/` domains (T-181): the views live in
//! per-domain files, re-exported flat so `crate::types::X` stays stable.
//! The enum→wire-string maps below are shared vocabulary — a spelling
//! used by two domains lives here exactly once.

pub mod accounts;
pub mod contacts;
pub mod devices;
pub mod endpoint;
pub mod integrations;
pub mod mail;
pub mod message;
pub mod oauth2;
pub mod prefs;
pub mod rules;
pub mod security;
pub mod send;
pub mod storage;
pub mod system;
pub mod templates;
pub mod thread;

pub use accounts::*;
pub use contacts::*;
pub use devices::*;
pub use endpoint::*;
pub use integrations::*;
pub use mail::*;
pub use message::*;
pub use oauth2::*;
pub use prefs::*;
pub use rules::*;
pub use security::*;
pub use send::*;
pub use storage::*;
pub use system::*;
pub use templates::*;
pub use thread::*;

use kiwi_core::session::{AuthMechanism, Protocol, SessionSource, TlsVersion, TransportSecurity};
use kiwi_core::trust::{RequiredAction, SignalKind, SignalSeverity, TrustState};
use kiwi_mail::transport::SocketSecurity;

// ---------------------------------------------------------------------------
// Enum → wire-string maps (contract spellings — security-session.md §3/§4)
// ---------------------------------------------------------------------------

pub fn signal_kind(k: SignalKind) -> &'static str {
    use SignalKind::*;
    match k {
        PlaintextTransport => "plaintext-transport",
        StartTlsDowngradeSuspected => "starttls-downgrade-suspected",
        DeprecatedTlsVersion => "deprecated-tls-version",
        WeakCipherSuite => "weak-cipher-suite",
        NoForwardSecrecy => "no-forward-secrecy",
        CertificateInvalid => "certificate-invalid",
        CertificateExpired => "certificate-expired",
        CertificateUntrusted => "certificate-untrusted",
        CertificateHostnameMismatch => "certificate-hostname-mismatch",
        CertificateUnexpectedChange => "certificate-unexpected-change",
        WeakAuthMechanism => "weak-auth-mechanism",
        RepeatedAuthFailure => "repeated-auth-failure",
        NewDeviceUnverified => "new-device-unverified",
        RemoteSessionIndicator => "remote-session-indicator",
        EndpointIntegrityFailure => "endpoint-integrity-failure",
        DeviceSuspended => "device-suspended",
        DeviceRevoked => "device-revoked",
        ReplayDetected => "replay-detected",
        PolicyViolation => "policy-violation",
    }
}

pub fn severity(s: SignalSeverity) -> &'static str {
    match s {
        SignalSeverity::Info => "info",
        SignalSeverity::Low => "low",
        SignalSeverity::Medium => "medium",
        SignalSeverity::High => "high",
        SignalSeverity::Critical => "critical",
    }
}

pub fn trust_state(s: TrustState) -> &'static str {
    match s {
        TrustState::Trusted => "trusted",
        TrustState::Degraded => "degraded",
        TrustState::Locked => "locked",
    }
}

/// ui-surfaces §2 severity token for the overall trust verdict.
pub fn trust_token(s: TrustState, ever_evaluated: bool) -> &'static str {
    if !ever_evaluated {
        return "unknown";
    }
    match s {
        TrustState::Trusted => "secure",
        TrustState::Degraded => "warning",
        TrustState::Locked => "danger",
    }
}

pub fn required_action(a: RequiredAction) -> &'static str {
    match a {
        RequiredAction::None => "none",
        RequiredAction::WarnUser => "warn-user",
        RequiredAction::RequireReauth => "require-reauth",
        RequiredAction::RequireAuthenticatorUnlock => "require-authenticator-unlock",
        RequiredAction::BlockAccess => "block-access",
    }
}

pub fn protocol(p: Protocol) -> &'static str {
    match p {
        Protocol::Smtp => "smtp",
        Protocol::Imap => "imap",
        Protocol::Pop3 => "pop3",
    }
}

pub fn transport(t: TransportSecurity) -> &'static str {
    match t {
        TransportSecurity::Plaintext => "plaintext",
        TransportSecurity::StartTls => "starttls",
        TransportSecurity::Tls => "tls",
    }
}

/// `ServerView.security` / `ServerInput.security` spelling (ipc.md §5).
pub fn socket_security(s: SocketSecurity) -> &'static str {
    match s {
        SocketSecurity::Plaintext => "plaintext",
        SocketSecurity::StartTls => "starttls",
        SocketSecurity::ImplicitTls => "tls",
    }
}

/// `SessionView.source` spelling — provenance, never guessed
/// (security-session.md §2). `live-client` supersedes the pre-pivot
/// `thunderbird-hook`: KIWI is a standalone client, so a live observation has
/// no Thunderbird hook behind it and emitting that name would be a false
/// provenance claim. `ForensicPcap`/`TestFixture` are unchanged.
pub fn session_source(s: SessionSource) -> &'static str {
    match s {
        SessionSource::ThunderbirdHook => "live-client",
        SessionSource::ForensicPcap => "forensic-pcap",
        SessionSource::TestFixture => "test-fixture",
    }
}

pub fn tls_version(v: TlsVersion) -> &'static str {
    match v {
        TlsVersion::Ssl3 => "ssl3",
        TlsVersion::Tls1_0 => "tls1.0",
        TlsVersion::Tls1_1 => "tls1.1",
        TlsVersion::Tls1_2 => "tls1.2",
        TlsVersion::Tls1_3 => "tls1.3",
        TlsVersion::Unknown => "unknown",
    }
}

/// Core-spelling label for an `AuthMechanism` — also the spelling the
/// forensics adapter maps via `from_token` (contract §11).
pub(crate) fn auth_mechanism(a: &AuthMechanism) -> String {
    use AuthMechanism::*;
    match a {
        None => "none".into(),
        Plain => "plain".into(),
        Login => "login".into(),
        CramMd5 => "cram-md5".into(),
        ScramSha1 => "scram-sha-1".into(),
        ScramSha256 => "scram-sha-256".into(),
        XOAuth2 => "xoauth2".into(),
        OAuthBearer => "oauthbearer".into(),
        Ntlm => "ntlm".into(),
        Gssapi => "gssapi".into(),
        ClientCertificate => "client-cert".into(),
        Other(s) => format!("other:{s}"),
        Unknown => "unknown".into(),
    }
}

pub fn challenge_event(e: kiwi_core::challenge::ChallengeEvent) -> &'static str {
    use kiwi_core::challenge::ChallengeEvent::*;
    match e {
        Unlock => "unlock",
        DevicePairing => "device-pairing",
        Recovery => "recovery",
        ElevatedAction => "elevated-action",
    }
}

pub fn parse_challenge_event(s: &str) -> Option<kiwi_core::challenge::ChallengeEvent> {
    use kiwi_core::challenge::ChallengeEvent::*;
    Some(match s {
        "unlock" => Unlock,
        "device-pairing" => DevicePairing,
        "recovery" => Recovery,
        "elevated-action" => ElevatedAction,
        _ => return Option::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiwi_core::challenge::ChallengeEvent;
    use kiwi_core::session::KeyExchangeGroup;
    use kiwi_core::trust::{RequiredAction, SignalKind, SignalSeverity, TrustState};

    /// T-260: pin every security-session enum → wire spelling against
    /// `security-session.md` §2/§3. The audit that produced SS-2 read each
    /// mapper once by eye; this makes a spelling change a failing test
    /// instead of a silent contract drift. A *new* core variant already fails
    /// to compile at its mapper (exhaustive match), so these assert the
    /// documented strings for the variants that exist today.
    #[test]
    fn session_enums_match_contract_spellings() {
        // §2 SecuritySession
        assert_eq!(protocol(Protocol::Smtp), "smtp");
        assert_eq!(protocol(Protocol::Imap), "imap");
        assert_eq!(protocol(Protocol::Pop3), "pop3");

        assert_eq!(transport(TransportSecurity::Plaintext), "plaintext");
        assert_eq!(transport(TransportSecurity::StartTls), "starttls");
        assert_eq!(transport(TransportSecurity::Tls), "tls");

        assert_eq!(tls_version(TlsVersion::Ssl3), "ssl3");
        assert_eq!(tls_version(TlsVersion::Tls1_0), "tls1.0");
        assert_eq!(tls_version(TlsVersion::Tls1_1), "tls1.1");
        assert_eq!(tls_version(TlsVersion::Tls1_2), "tls1.2");
        assert_eq!(tls_version(TlsVersion::Tls1_3), "tls1.3");
        assert_eq!(tls_version(TlsVersion::Unknown), "unknown");

        // §2 `source` — SS-2. `live-client`, never the pre-pivot
        // `thunderbird-hook`: provenance is never a false claim.
        assert_eq!(
            session_source(SessionSource::ThunderbirdHook),
            "live-client"
        );
        assert_eq!(session_source(SessionSource::ForensicPcap), "forensic-pcap");
        assert_eq!(session_source(SessionSource::TestFixture), "test-fixture");

        // §2 `auth_mechanism` (ipc.md §3 pins "xoauth2" as a session-view token)
        assert_eq!(auth_mechanism(&AuthMechanism::None), "none");
        assert_eq!(auth_mechanism(&AuthMechanism::Plain), "plain");
        assert_eq!(auth_mechanism(&AuthMechanism::Login), "login");
        assert_eq!(auth_mechanism(&AuthMechanism::CramMd5), "cram-md5");
        assert_eq!(auth_mechanism(&AuthMechanism::ScramSha1), "scram-sha-1");
        assert_eq!(auth_mechanism(&AuthMechanism::ScramSha256), "scram-sha-256");
        assert_eq!(auth_mechanism(&AuthMechanism::XOAuth2), "xoauth2");
        assert_eq!(auth_mechanism(&AuthMechanism::OAuthBearer), "oauthbearer");
        assert_eq!(auth_mechanism(&AuthMechanism::Ntlm), "ntlm");
        assert_eq!(auth_mechanism(&AuthMechanism::Gssapi), "gssapi");
        assert_eq!(
            auth_mechanism(&AuthMechanism::ClientCertificate),
            "client-cert"
        );
        assert_eq!(
            auth_mechanism(&AuthMechanism::Other("sp".into())),
            "other:sp"
        );
        assert_eq!(auth_mechanism(&AuthMechanism::Unknown), "unknown");
    }

    /// §3 trust signals + lock-state vocabulary.
    #[test]
    fn trust_enums_match_contract_spellings() {
        assert_eq!(
            signal_kind(SignalKind::PlaintextTransport),
            "plaintext-transport"
        );
        assert_eq!(
            signal_kind(SignalKind::StartTlsDowngradeSuspected),
            "starttls-downgrade-suspected"
        );
        assert_eq!(
            signal_kind(SignalKind::DeprecatedTlsVersion),
            "deprecated-tls-version"
        );
        assert_eq!(
            signal_kind(SignalKind::WeakCipherSuite),
            "weak-cipher-suite"
        );
        assert_eq!(
            signal_kind(SignalKind::NoForwardSecrecy),
            "no-forward-secrecy"
        );
        assert_eq!(
            signal_kind(SignalKind::CertificateInvalid),
            "certificate-invalid"
        );
        assert_eq!(
            signal_kind(SignalKind::CertificateExpired),
            "certificate-expired"
        );
        assert_eq!(
            signal_kind(SignalKind::CertificateUntrusted),
            "certificate-untrusted"
        );
        assert_eq!(
            signal_kind(SignalKind::CertificateHostnameMismatch),
            "certificate-hostname-mismatch"
        );
        assert_eq!(
            signal_kind(SignalKind::CertificateUnexpectedChange),
            "certificate-unexpected-change"
        );
        assert_eq!(
            signal_kind(SignalKind::WeakAuthMechanism),
            "weak-auth-mechanism"
        );
        assert_eq!(
            signal_kind(SignalKind::RepeatedAuthFailure),
            "repeated-auth-failure"
        );
        assert_eq!(
            signal_kind(SignalKind::NewDeviceUnverified),
            "new-device-unverified"
        );
        assert_eq!(
            signal_kind(SignalKind::RemoteSessionIndicator),
            "remote-session-indicator"
        );
        assert_eq!(
            signal_kind(SignalKind::EndpointIntegrityFailure),
            "endpoint-integrity-failure"
        );
        assert_eq!(signal_kind(SignalKind::DeviceSuspended), "device-suspended");
        assert_eq!(signal_kind(SignalKind::DeviceRevoked), "device-revoked");
        assert_eq!(signal_kind(SignalKind::ReplayDetected), "replay-detected");
        assert_eq!(signal_kind(SignalKind::PolicyViolation), "policy-violation");

        assert_eq!(severity(SignalSeverity::Info), "info");
        assert_eq!(severity(SignalSeverity::Low), "low");
        assert_eq!(severity(SignalSeverity::Medium), "medium");
        assert_eq!(severity(SignalSeverity::High), "high");
        assert_eq!(severity(SignalSeverity::Critical), "critical");

        assert_eq!(trust_state(TrustState::Trusted), "trusted");
        assert_eq!(trust_state(TrustState::Degraded), "degraded");
        assert_eq!(trust_state(TrustState::Locked), "locked");

        // ui-surfaces §2 trust tokens (orthogonal to the contract §3 state names)
        assert_eq!(trust_token(TrustState::Trusted, true), "secure");
        assert_eq!(trust_token(TrustState::Degraded, true), "warning");
        assert_eq!(trust_token(TrustState::Locked, true), "danger");
        assert_eq!(
            trust_token(TrustState::Trusted, false),
            "unknown",
            "never-evaluated is absent evidence, not clean"
        );

        assert_eq!(required_action(RequiredAction::None), "none");
        assert_eq!(required_action(RequiredAction::WarnUser), "warn-user");
        assert_eq!(
            required_action(RequiredAction::RequireReauth),
            "require-reauth"
        );
        assert_eq!(
            required_action(RequiredAction::RequireAuthenticatorUnlock),
            "require-authenticator-unlock"
        );
        assert_eq!(required_action(RequiredAction::BlockAccess), "block-access");
    }

    /// §2 `key_exchange_group` + `cert_chain.validation` are `SecuritySession`
    /// field mappers in `types/security.rs`, not shared vocabulary. Pinned
    /// here for the same reason as the maps above.
    #[test]
    fn key_exchange_and_validation_spellings_are_pinned() {
        use crate::types::security::{chain_validation, kex};
        use kiwi_core::session::ChainValidation;

        assert_eq!(kex(&KeyExchangeGroup::X25519), "x25519");
        assert_eq!(kex(&KeyExchangeGroup::SecP256r1), "secp256r1");
        assert_eq!(kex(&KeyExchangeGroup::SecP384r1), "secp384r1");
        assert_eq!(kex(&KeyExchangeGroup::SecP521r1), "secp521r1");
        assert_eq!(kex(&KeyExchangeGroup::Ffdhe2048), "ffdhe2048");
        assert_eq!(kex(&KeyExchangeGroup::Ffdhe3072), "ffdhe3072");
        assert_eq!(kex(&KeyExchangeGroup::Ffdhe4096), "ffdhe4096");
        assert_eq!(kex(&KeyExchangeGroup::StaticKeyTransport), "static");
        assert_eq!(kex(&KeyExchangeGroup::Other("psk".into())), "other:psk");
        assert_eq!(kex(&KeyExchangeGroup::Unknown), "unknown");

        assert_eq!(chain_validation(ChainValidation::Valid), "valid");
        assert_eq!(chain_validation(ChainValidation::Invalid), "invalid");
        assert_eq!(chain_validation(ChainValidation::Untrusted), "untrusted");
        assert_eq!(chain_validation(ChainValidation::Expired), "expired");
        assert_eq!(
            chain_validation(ChainValidation::HostnameMismatch),
            "hostname-mismatch"
        );
        assert_eq!(chain_validation(ChainValidation::Unknown), "unknown");
    }

    /// T-260 input side: an unrecognized enum spelling must fail closed, never
    /// silently coerce to a safe-looking default.
    #[test]
    fn challenge_event_parse_round_trips_and_fails_closed() {
        for (wire, expected) in [
            ("unlock", ChallengeEvent::Unlock),
            ("device-pairing", ChallengeEvent::DevicePairing),
            ("recovery", ChallengeEvent::Recovery),
            ("elevated-action", ChallengeEvent::ElevatedAction),
        ] {
            assert_eq!(challenge_event(expected), wire);
            assert_eq!(parse_challenge_event(wire), Some(expected));
        }
        for bad in ["", "Unlock", "unlock ", "unlock\n", "pairing", "unknown"] {
            assert_eq!(
                parse_challenge_event(bad),
                None,
                "{bad:?} must be rejected, not coerced"
            );
        }
    }
}
