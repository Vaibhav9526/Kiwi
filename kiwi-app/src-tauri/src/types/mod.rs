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
pub mod system;

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
pub use system::*;

use kiwi_core::session::{AuthMechanism, Protocol, TlsVersion, TransportSecurity};
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
