//! Wire types for the IPC contract (`docs/contracts/ipc.md`).
//!
//! kiwi-core/kiwi-mail domain types deliberately carry no serde derives;
//! these view structs are the stable frontend-facing shapes. All field
//! names are camelCase on the wire (`ui-surfaces.md` §3). Severity tokens
//! are exactly the `ui-surfaces.md` §2 vocabulary: `secure | warning |
//! danger | unknown` (+ orthogonal `locked`).

use serde::{Deserialize, Serialize};

use kiwi_core::challenge::Challenge;
use kiwi_core::device::{Device, DeviceStatus, KeyAlgorithm};
use kiwi_core::session::{
    AuthMechanism, ChainValidation, KeyExchangeGroup, Protocol, SecuritySession, TlsVersion,
    TransportSecurity,
};
use kiwi_core::trust::{RequiredAction, SignalKind, SignalSeverity, TrustSignal, TrustState};
use kiwi_mail::account::MailAccount;
use kiwi_mail::store::{FolderMeta, MessageMeta};

// ---------------------------------------------------------------------------
// Security views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalView {
    pub kind: String,
    pub severity: String,
    pub penalty: u32,
    pub evidence_ref: String,
}

impl From<&TrustSignal> for SignalView {
    fn from(s: &TrustSignal) -> Self {
        Self {
            kind: signal_kind(s.kind).to_string(),
            severity: severity(s.severity).to_string(),
            penalty: s.penalty,
            evidence_ref: s.evidence_ref.clone(),
        }
    }
}

/// The security bar / lock overlay payload (`kiwi_security_status`,
/// KIWI-UI-002/005).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusView {
    /// ui-surfaces §2 token: secure|warning|danger|unknown.
    pub trust: String,
    pub locked: bool,
    /// kiwi-core trust state: trusted|degraded|locked.
    pub state: String,
    pub score: u32,
    pub required_action: String,
    pub signals: Vec<SignalView>,
    /// Count of connection observations behind this verdict.
    pub sessions_observed: u64,
    pub device_id: String,
}

/// One observed connection (session detail / cert viewer, KIWI-UI-003/008).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub schema_version: u32,
    pub session_id: String,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub protocol: String,
    pub server_host: String,
    pub server_port: u16,
    /// "plaintext" | "starttls" | "tls".
    pub transport: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<CipherSuiteView>,
    pub key_exchange_group: Option<String>,
    pub cert_chain: Option<CertChainView>,
    pub starttls_offered: Option<bool>,
    pub starttls_used: bool,
    pub auth_mechanism: String,
    pub auth_succeeded: Option<bool>,
    /// Unix seconds.
    pub established_unix: i64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuiteView {
    pub iana_id: Option<u16>,
    pub name: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertChainView {
    pub leaf: Option<CertView>,
    pub presented_len: u8,
    pub validation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertView {
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_hex: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: u32,
    pub sha256_fingerprint: String,
    pub is_self_signed: bool,
}

/// Security-center event row (KIWI-UI-010).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRow {
    pub id: String,
    pub ts_unix: i64,
    pub account_id: Option<String>,
    /// "imap sync" / "smtp send" / "imap login" / …
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub detail_ref: String,
}

// ---------------------------------------------------------------------------
// Challenge / device views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeView {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    /// "unlock" | "device-pairing" | "recovery" | "elevated-action".
    pub event: String,
    pub nonce_hex: String,
    pub issued_unix: i64,
    pub expires_unix: i64,
    /// Exact bytes the authenticator must sign (canonical per contract §6).
    pub canonical_bytes_b64: String,
}

impl From<&Challenge> for ChallengeView {
    fn from(c: &Challenge) -> Self {
        use base64::Engine;
        Self {
            challenge_id: c.challenge_id.clone(),
            device_id: c.device_id.clone(),
            session_id: c.session_id.clone(),
            event: challenge_event(c.event).to_string(),
            nonce_hex: crate::audit::hex(&c.nonce),
            issued_unix: c.issued_unix,
            expires_unix: c.expires_unix,
            canonical_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(c.canonical_bytes()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponseInput {
    pub challenge_id: String,
    pub device_id: String,
    pub session_id: String,
    /// "unlock" | "device-pairing" | "recovery" | "elevated-action".
    pub event: String,
    /// Base64-encoded device signature over the challenge canonical bytes.
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub device_id: String,
    pub label: String,
    /// "ed25519" | "ecdsa-p256" | "rsa3072".
    pub algorithm: String,
    /// "pending" | "active" | "suspended" | "revoked".
    pub status: String,
    pub registered_unix: i64,
    pub last_seen_unix: i64,
    /// sha256 tail of the public key — display fingerprint (ui-surfaces §3).
    pub key_fingerprint_tail: String,
}

impl From<&Device> for DeviceView {
    fn from(d: &Device) -> Self {
        use sha2::{Digest, Sha256};
        let fp = {
            let mut h = Sha256::new();
            h.update(&d.public_key.key);
            crate::audit::hex(&h.finalize())
        };
        Self {
            device_id: d.device_id.clone(),
            label: d.label.clone(),
            algorithm: key_algorithm(d.public_key.algorithm).to_string(),
            status: device_status(d.status).to_string(),
            registered_unix: d.registered_unix,
            last_seen_unix: d.last_seen_unix,
            key_fingerprint_tail: fp[fp.len().saturating_sub(8)..].to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Mail views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    /// ui-surfaces §2 token.
    pub trust: String,
    pub unread: u64,
    pub color: String,
    /// "imap" | "pop3".
    pub protocol: String,
    pub incoming_host: String,
    pub incoming_port: u16,
    pub outgoing_host: String,
    pub outgoing_port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderView {
    /// Mail-store row id — the `folderId` argument for other commands.
    pub id: i64,
    pub account_id: String,
    pub name: String,
    pub uid_validity: Option<u64>,
    pub uid_next: Option<u64>,
    pub highest_uid: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    pub id: i64,
    pub folder_id: i64,
    pub uid: u64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub date_unix: Option<i64>,
    pub size: Option<u64>,
    pub flags: Vec<String>,
    pub unread: bool,
    pub starred: bool,
    pub has_attachments: bool,
    pub snippet: Option<String>,
    /// Whether the full body is already stored locally.
    pub body_stored: bool,
    /// `In-Reply-To` msg-id (header-chain threading, T-169). `None` until
    /// known — the field is populated from the sync-time header fetch or
    /// lazily from a stored body.
    pub in_reply_to: Option<String>,
    /// `References` msg-id chain, root-first.
    pub references: Vec<String>,
}

impl From<&MessageMeta> for MessageView {
    fn from(m: &MessageMeta) -> Self {
        let seen = m.flags.iter().any(|f| f == "\\Seen");
        let starred = m.flags.iter().any(|f| f == "\\Flagged");
        Self {
            id: m.id,
            folder_id: m.folder_id,
            uid: m.uid,
            message_id: m.message_id.clone(),
            subject: m.subject.clone(),
            from: m.from_addr.clone(),
            to: m.to_addrs.clone(),
            date_unix: m.date_unix,
            size: m.size,
            flags: m.flags.clone(),
            unread: !seen,
            starred,
            has_attachments: m.has_attachments,
            snippet: m.snippet.clone(),
            body_stored: m.body_path.is_some(),
            // Filled by the caller from the threading-header cache
            // (`AppIndex::thread_headers`) — `MessageMeta` doesn't carry
            // these headers yet (store schema gap, tracked).
            in_reply_to: None,
            references: Vec::new(),
        }
    }
}

impl From<&FolderMeta> for FolderView {
    fn from(f: &FolderMeta) -> Self {
        Self {
            id: f.id,
            account_id: f.account_id.clone(),
            name: f.name.clone(),
            uid_validity: f.uid_validity,
            uid_next: f.uid_next,
            highest_uid: f.highest_uid,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub filename: Option<String>,
    pub content_type: String,
    pub size: usize,
}

/// Full message body view (reader, KIWI-UI-017). HTML is delivered raw from
/// the parsed MIME tree — the frontend renders it sanitized with remote
/// content blocked (SECURITY.md rule 12; ui-surfaces §4.4).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageBodyView {
    pub folder_id: i64,
    pub uid: u64,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub date_unix: Option<i64>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<AttachmentView>,
    /// `false` when the body could not be fetched/parsed yet.
    pub body_present: bool,
    /// `In-Reply-To` / `References` from the parsed body — authoritative
    /// when `body_present` (T-169; reply composer + threading).
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Command payloads (inputs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInput {
    pub host: String,
    pub port: u16,
    /// "plaintext" | "starttls" | "tls" (implicit).
    pub security: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInput {
    /// "password" | "xoauth2" | "apop" (POP3 only) | "none".
    pub kind: String,
    /// The secret itself — stored into the OS credential store on
    /// `kiwi_add_account`, used transiently by `kiwi_verify_server`.
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddAccountInput {
    pub display_name: String,
    pub email: String,
    /// "imap" | "pop3".
    pub incoming_protocol: String,
    pub incoming: ServerInput,
    pub outgoing: ServerInput,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub outgoing_username: Option<String>,
    #[serde(default)]
    pub incoming_auth: Option<AuthInput>,
    #[serde(default)]
    pub outgoing_auth: Option<AuthInput>,
    /// Explicit user consent for cert-validation failures (setup wizard
    /// "accept once"). Recorded per account + audited. Default false.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

/// One-shot server probe for the setup wizard (KIWI-UI-019) — connects,
/// optionally authenticates, returns the full TLS observation + findings.
/// Nothing is persisted except the session record.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyServerInput {
    /// "smtp" | "imap" | "pop3".
    pub protocol: String,
    pub server: ServerInput,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthInput>,
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepView {
    pub stage: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub ok: bool,
    pub steps: Vec<StepView>,
    /// Present when a connection was established (even if auth later failed).
    pub session: Option<SessionView>,
    /// Deterministic findings produced by this session's observation.
    pub findings: Vec<kiwi_forensics::findings::Finding>,
    /// Endpoint trust after folding this session in.
    pub trust: SecurityStatusView,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInput {
    pub filename: String,
    pub content_type: String,
    /// Base64 payload — decoded server-side with a size bound.
    pub data_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeInput {
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    /// Plain-text body (required; may be empty string).
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOptions {
    /// Send-later: earliest dispatch (unix seconds).
    #[serde(default)]
    pub send_at_unix: Option<i64>,
    /// Undo-send grace window in seconds (default 10, capped at 120).
    #[serde(default)]
    pub undo_grace_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendReceipt {
    pub queue_id: String,
    /// Earliest dispatch time (unix seconds).
    pub not_before_unix: i64,
    /// Undo-send cancel deadline (unix seconds).
    pub undo_window_until_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxItem {
    pub queue_id: String,
    pub account_id: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub not_before_unix: i64,
    pub undo_window_until_unix: i64,
    pub attempts: u32,
    /// Whether `kiwi_cancel_send` can still undo it.
    pub cancelable: bool,
}

/// `kiwi://outbox` event payload — emitted by the dispatcher.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxEvent {
    pub queue_id: String,
    pub account_id: String,
    /// "sent" | "failed" | "held" | "blocked".
    pub status: String,
    pub detail: String,
    pub at_unix: i64,
}

/// `kiwi_delete_messages` result — counts tell the UI which path ran.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResultView {
    pub folder_id: i64,
    /// Messages moved into Trash (soft delete).
    pub moved_to_trash: u64,
    /// Messages permanently expunged (delete-from-Trash or `permanent`).
    pub deleted: u64,
    /// Trash folder id when a move happened.
    pub trash_folder_id: Option<i64>,
    /// src uid → Trash uid for moved messages (uids are folder-scoped —
    /// a move is a copy under a fresh uid + source delete).
    pub uid_map: std::collections::BTreeMap<u64, u64>,
}

/// `kiwi_move_messages` result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResultView {
    pub src_folder_id: i64,
    pub dst_folder_id: i64,
    pub moved: u64,
    /// src uid → dst uid.
    pub uid_map: std::collections::BTreeMap<u64, u64>,
}

/// `kiwi_finding_detail` result — one finding + the session that produced
/// it (T-164; finding dialog KIWI-UI-004).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingDetailView {
    /// The full `kiwi.forensics/1` finding, evidence included.
    pub finding: kiwi_forensics::findings::Finding,
    /// The session it was observed in — `None` when the session ring has
    /// already evicted it (findings outlive sessions on purpose).
    pub session: Option<SessionView>,
    /// Trust signals from that same session.
    pub signals: Vec<SignalView>,
    /// Other finding ids produced by the same session.
    pub sibling_finding_ids: Vec<String>,
}

/// `kiwi://mail-changed` event payload — emitted by the live-sync worker
/// (T-157) after a sync pass changed stored mail. `folder`/`folderId` are
/// set for folder-scoped passes (IDLE wake, poll); `null` marks the full
/// connect-time pass.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailChangedEvent {
    pub account_id: String,
    pub folder: Option<String>,
    pub folder_id: Option<i64>,
    /// "sync" | "idle" | "poll".
    pub reason: String,
    pub new_messages: u64,
    pub flag_updates: u64,
    pub expunged: u64,
    pub at_unix: i64,
}

/// `kiwi_sync_status` row — one per configured account (T-157).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusView {
    pub account_id: String,
    /// "pending" | "connecting" | "syncing" | "idle" | "polling" |
    /// "backoff" | "paused-locked" | "stopped"
    pub state: String,
    pub last_sync_unix: Option<i64>,
    pub last_error: Option<String>,
    pub next_retry_unix: Option<i64>,
    pub folders_synced: u64,
    pub new_messages: u64,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfoView {
    pub version: String,
    pub contract_version: String,
    pub device_id: String,
    pub org: Option<OrgBindingView>,
    pub account_count: usize,
    pub sessions_observed: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgBindingView {
    pub org_id: String,
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceInput {
    pub label: String,
    /// "ed25519" | "ecdsa-p256" | "rsa3072".
    pub algorithm: String,
    /// Base64-encoded raw public key (32 bytes for ed25519).
    pub public_key_b64: String,
    #[serde(default)]
    pub keystore_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointReportView {
    pub collected_at_unix: i64,
    pub observations: Vec<crate::signals::EndpointObservation>,
    /// Full trust verdict after folding these signals in.
    pub status: SecurityStatusView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetailView {
    pub session: SessionView,
    pub signals: Vec<SignalView>,
    pub findings: Vec<kiwi_forensics::findings::Finding>,
    pub label: String,
}

/// Per-folder sync outcome. IMAP fills the `newMessages/…` set; POP3 fills
/// `downloaded/…` (POP3 has no remote flag/expunge model).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReportView {
    /// "imap" | "pop3".
    pub protocol: String,
    pub folder: String,
    pub folder_id: i64,
    #[serde(default)]
    pub new_messages: u64,
    #[serde(default)]
    pub flag_updates: u64,
    #[serde(default)]
    pub expunged: u64,
    #[serde(default)]
    pub remote_exists: u64,
    #[serde(default)]
    pub uid_validity_reset: bool,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub deleted_remote: u64,
}

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

fn kex(k: &KeyExchangeGroup) -> String {
    match k {
        KeyExchangeGroup::X25519 => "x25519".into(),
        KeyExchangeGroup::SecP256r1 => "secp256r1".into(),
        KeyExchangeGroup::SecP384r1 => "secp384r1".into(),
        KeyExchangeGroup::SecP521r1 => "secp521r1".into(),
        KeyExchangeGroup::Ffdhe2048 => "ffdhe2048".into(),
        KeyExchangeGroup::Ffdhe3072 => "ffdhe3072".into(),
        KeyExchangeGroup::Ffdhe4096 => "ffdhe4096".into(),
        KeyExchangeGroup::StaticKeyTransport => "static".into(),
        KeyExchangeGroup::Other(s) => format!("other:{s}"),
        KeyExchangeGroup::Unknown => "unknown".into(),
    }
}

fn chain_validation(v: ChainValidation) -> &'static str {
    match v {
        ChainValidation::Valid => "valid",
        ChainValidation::Invalid => "invalid",
        ChainValidation::Untrusted => "untrusted",
        ChainValidation::Expired => "expired",
        ChainValidation::HostnameMismatch => "hostname-mismatch",
        ChainValidation::Unknown => "unknown",
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

pub fn key_algorithm(a: KeyAlgorithm) -> &'static str {
    match a {
        KeyAlgorithm::Ed25519 => "ed25519",
        KeyAlgorithm::EcdsaP256 => "ecdsa-p256",
        KeyAlgorithm::Rsa3072 => "rsa3072",
    }
}

pub fn parse_key_algorithm(s: &str) -> Option<KeyAlgorithm> {
    Some(match s {
        "ed25519" => KeyAlgorithm::Ed25519,
        "ecdsa-p256" => KeyAlgorithm::EcdsaP256,
        "rsa3072" => KeyAlgorithm::Rsa3072,
        _ => return Option::None,
    })
}

pub fn device_status(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Suspended => "suspended",
        DeviceStatus::Revoked => "revoked",
    }
}

pub fn account_view(a: &MailAccount, trust: &str, unread: u64, color: &str) -> AccountView {
    AccountView {
        id: a.account_id.clone(),
        email: a.email.clone(),
        display_name: a.display_name.clone(),
        trust: trust.to_string(),
        unread,
        color: color.to_string(),
        protocol: match a.incoming.protocol {
            kiwi_mail::account::IncomingProtocol::Imap => "imap".into(),
            kiwi_mail::account::IncomingProtocol::Pop3 => "pop3".into(),
        },
        incoming_host: a.incoming.server.host.clone(),
        incoming_port: a.incoming.server.port,
        outgoing_host: a.outgoing.server.host.clone(),
        outgoing_port: a.outgoing.server.port,
    }
}

impl From<&SecuritySession> for SessionView {
    fn from(s: &SecuritySession) -> Self {
        Self {
            schema_version: s.schema_version,
            session_id: s.session_id.clone(),
            account_id: s.account_id.clone(),
            device_id: s.device_id.clone(),
            protocol: protocol(s.protocol).to_string(),
            server_host: s.server_host.clone(),
            server_port: s.server_port,
            transport: transport(s.transport).to_string(),
            tls_version: s.tls_version.map(tls_version).map(str::to_string),
            cipher_suite: s.cipher_suite.as_ref().map(|c| CipherSuiteView {
                iana_id: c.iana_id,
                name: c.name.clone(),
                forward_secrecy: c.forward_secrecy,
            }),
            key_exchange_group: s.key_exchange_group.as_ref().map(kex),
            cert_chain: s.cert_chain.as_ref().map(|c| CertChainView {
                leaf: c.leaf.as_ref().map(|l| CertView {
                    subject_dn: l.subject_dn.clone(),
                    issuer_dn: l.issuer_dn.clone(),
                    serial_hex: l.serial_hex.clone(),
                    not_before_unix: l.not_before_unix,
                    not_after_unix: l.not_after_unix,
                    signature_algorithm: l.signature_algorithm.clone(),
                    public_key_algorithm: l.public_key_algorithm.clone(),
                    public_key_bits: l.public_key_bits,
                    sha256_fingerprint: l.sha256_fingerprint.clone(),
                    is_self_signed: l.is_self_signed,
                }),
                presented_len: c.presented_len,
                validation: chain_validation(c.validation).to_string(),
            }),
            starttls_offered: s.starttls_offered,
            starttls_used: s.starttls_used,
            auth_mechanism: auth_mechanism(&s.auth_mechanism),
            auth_succeeded: s.auth_succeeded,
            established_unix: s.established_unix,
            source: match s.source {
                kiwi_core::session::SessionSource::ThunderbirdHook => "live-client",
                kiwi_core::session::SessionSource::ForensicPcap => "forensic-pcap",
                kiwi_core::session::SessionSource::TestFixture => "test-fixture",
            }
            .to_string(),
        }
    }
}

/// Aggregate severity token for one account's observed sessions.
pub fn account_trust_token(records: impl Iterator<Item = SignalSeverity>) -> &'static str {
    let mut worst = SignalSeverity::Info;
    let mut seen = false;
    for s in records {
        seen = true;
        if s > worst {
            worst = s;
        }
    }
    if !seen {
        return "unknown";
    }
    match worst {
        SignalSeverity::Info | SignalSeverity::Low => "secure",
        SignalSeverity::Medium => "warning",
        SignalSeverity::High | SignalSeverity::Critical => "danger",
    }
}

// ---------------------------------------------------------------------------
// T-146 — message actions
// ---------------------------------------------------------------------------

/// Flag/archive patch for `kiwi_update_message`. Each field is
/// tri-state: absent = unchanged.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePatchInput {
    /// Maps to IMAP `\Seen`.
    pub seen: Option<bool>,
    /// Maps to IMAP `\Flagged`.
    pub starred: Option<bool>,
    /// true → move to Archive folder; false → move back to INBOX.
    pub archived: Option<bool>,
}

/// Result of a message patch (post-mutation state).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUpdateView {
    /// Source folder id (the one the caller passed — destination is
    /// `movedToFolderId` when archived).
    pub folder_id: i64,
    pub uid: u64,
    /// Post-mutation flag set.
    pub flags: Vec<String>,
    /// Destination folder id when the message was moved (archive /
    /// unarchive), else null.
    pub moved_to_folder_id: Option<i64>,
}

/// Result of `kiwi_download_attachment` — what was written where.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentSavedView {
    /// Absolute path written.
    pub path: String,
    /// MIME filename (or generated `attachment-N`).
    pub filename: String,
    /// MIME content type of the part.
    pub content_type: String,
    /// Bytes written.
    pub size: usize,
}

/// `kiwi_render_body` result — the sanitized fragment plus remote-content
/// policy facts for the UI (e.g., "N remote images blocked — allow?").
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedBodyView {
    /// Sanitized HTML fragment, or null for text-only/missing bodies.
    pub html: Option<String>,
    /// Account's remote-content opt-in at render time.
    pub remote_content_allowed: bool,
    /// Remote `img` sources stripped by the sanitizer this render.
    pub remote_images_stripped: u32,
}

/// `kiwi_set_remote_content` result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteContentView {
    pub account_id: String,
    pub remote_content_allowed: bool,
}

// ---------------------------------------------------------------------------
// T-175 — contacts + prefs views.
// ---------------------------------------------------------------------------

/// `Contact` on the wire — camelCase per kiwi.contacts/1 §2; the mapping
/// is mechanical and one-to-one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    pub id: String,
    pub display_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub name_prefix: Option<String>,
    pub name_suffix: Option<String>,
    pub org: Option<String>,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    /// `{address, label?}` — the crate's snake_case is already
    /// camelCase-compatible for these single-word fields.
    pub emails: Vec<kiwi_contacts::ContactEmail>,
    pub phones: Vec<kiwi_contacts::ContactPhone>,
    pub source_uid: Option<String>,
    pub rev_unix: Option<i64>,
    pub created_unix: i64,
    pub updated_unix: i64,
}

/// `ContactInput` — `Contact` minus the store-owned fields (`id`,
/// `createdUnix`, `updatedUnix`; kiwi.contacts/1 §3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInput {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub name_prefix: Option<String>,
    #[serde(default)]
    pub name_suffix: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub emails: Vec<kiwi_contacts::ContactEmail>,
    #[serde(default)]
    pub phones: Vec<kiwi_contacts::ContactPhone>,
    #[serde(default)]
    pub source_uid: Option<String>,
    #[serde(default)]
    pub rev_unix: Option<i64>,
}

impl ContactInput {
    /// Crate `Contact` — store-owned fields get placeholder values;
    /// `insert`/`update` overwrite `created`/`updated`, and `id` comes
    /// from the caller's `contactId` (or is store-assigned when empty).
    pub fn into_contact(self, id: String) -> kiwi_contacts::Contact {
        kiwi_contacts::Contact {
            id,
            display_name: self.display_name,
            given_name: self.given_name,
            family_name: self.family_name,
            middle_name: self.middle_name,
            name_prefix: self.name_prefix,
            name_suffix: self.name_suffix,
            org: self.org,
            title: self.title,
            notes: self.notes,
            tags: self.tags,
            emails: self.emails,
            phones: self.phones,
            source_uid: self.source_uid,
            rev_unix: self.rev_unix,
            created_unix: 0,
            updated_unix: 0,
        }
    }
}

impl From<kiwi_contacts::Contact> for ContactView {
    fn from(c: kiwi_contacts::Contact) -> Self {
        ContactView {
            id: c.id,
            display_name: c.display_name,
            given_name: c.given_name,
            family_name: c.family_name,
            middle_name: c.middle_name,
            name_prefix: c.name_prefix,
            name_suffix: c.name_suffix,
            org: c.org,
            title: c.title,
            notes: c.notes,
            tags: c.tags,
            emails: c.emails,
            phones: c.phones,
            source_uid: c.source_uid,
            rev_unix: c.rev_unix,
            created_unix: c.created_unix,
            updated_unix: c.updated_unix,
        }
    }
}

/// `kiwi_import_vcards` result (contacts.md §5.2): the contacts that
/// imported, plus one issue row per card that did not.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VCardImportView {
    pub contacts: Vec<ContactView>,
    pub issues: Vec<ImportIssueView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportIssueView {
    pub card_index: usize,
    pub detail: String,
}

/// `kiwi_contact_tags` row — `{tag, count}`, most-used first.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagCountView {
    pub tag: String,
    pub count: u64,
}

/// `kiwi_prefs_list` row — `{key, value}` within one scope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefEntryView {
    pub key: String,
    pub value: serde_json::Value,
}
