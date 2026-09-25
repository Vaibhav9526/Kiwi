//! Security-domain wire views — sessions, certs, findings, events.

use serde::Serialize;

use kiwi_core::session::{ChainValidation, KeyExchangeGroup, SecuritySession};

use super::{SignalView, auth_mechanism, protocol, session_source, tls_version, transport};

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

/// `kiwi_finding_detail` result — one finding + the session that produced
/// it (T-164; finding dialog KIWI-UI-004).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingDetailView {
    /// The full `kiwi.forensics/2` finding, evidence included (FSV-1 tags).
    pub finding: kiwi_forensics::findings::Finding,
    /// The session it was observed in — `None` when the session ring has
    /// already evicted it (findings outlive sessions on purpose).
    pub session: Option<SessionView>,
    /// Trust signals from that same session.
    pub signals: Vec<SignalView>,
    /// Other finding ids produced by the same session.
    pub sibling_finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetailView {
    pub session: SessionView,
    pub signals: Vec<SignalView>,
    pub findings: Vec<kiwi_forensics::findings::Finding>,
    pub label: String,
}

/// Result of one sandbox-open request. `target` is sanitized for display and
/// audit: URL userinfo/query/fragment and host attachment paths are removed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxOpenView {
    pub session_id: String,
    pub target: String,
    /// Stable link/attachment evidence reasons — never target text.
    pub evidence_reasons: Vec<String>,
    pub report: kiwi_sandbox::AnalysisReport,
}

/// One recorded sandbox open (T-300). `target` is the sanitized display
/// target: a redacted URL for links, the `attachment:f<id>/u<uid>` coordinate
/// for attachments — never a raw path, filename, or payload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxSessionView {
    pub session_id: String,
    /// `link | attachment`.
    pub kind: &'static str,
    pub target: String,
    /// `clean | noted | failed`, or `null` when no message evidence matched
    /// the target (absent evidence, never a fabricated "clean").
    pub risk_verdict: Option<&'static str>,
    /// Bounded stable evidence reason codes; never the matched target text.
    pub evidence_reasons: Vec<String>,
    pub opened_at_unix: i64,
    /// `completed` — a T-266 open always tears down before it is recorded, so
    /// there is no live guest and no expiry to report.
    pub state: &'static str,
    /// Always `null` for a torn-down session (no guest to expire). Reserved
    /// so a future live-session provider can populate it without a wire change.
    pub expires_at_unix: Option<i64>,
}

impl From<&crate::state::SandboxSessionRecord> for SandboxSessionView {
    fn from(record: &crate::state::SandboxSessionRecord) -> Self {
        Self {
            session_id: record.session_id.clone(),
            kind: record.kind.as_str(),
            target: record.target.clone(),
            risk_verdict: record.risk_verdict,
            evidence_reasons: record.evidence_reasons.clone(),
            opened_at_unix: record.opened_at_unix,
            state: "completed",
            expires_at_unix: None,
        }
    }
}

/// Bounded list of recorded sandbox sessions, newest first. `sessions` is
/// empty when nothing has been opened — absence is not an error.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxSessionsView {
    pub sessions: Vec<SandboxSessionView>,
}

/// Backend policy for one clicked message link. Reasons are bounded stable
/// evidence codes; the target URL itself is not persisted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkClickVerdict {
    /// `allow | requireConfirm | requireSandbox | deny`.
    pub action: String,
    pub reasons: Vec<String>,
}

/// Stable wire spelling for an observed key-exchange group (§2). Visible to
/// the sibling test module that pins the security-session vocabulary.
pub(crate) fn kex(k: &KeyExchangeGroup) -> String {
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

/// Stable wire spelling for a reported chain-validation verdict (§2) — the
/// NSS/observation result as-is, never a KIWI strength re-judgement.
pub(crate) fn chain_validation(v: ChainValidation) -> &'static str {
    match v {
        ChainValidation::Valid => "valid",
        ChainValidation::Invalid => "invalid",
        ChainValidation::Untrusted => "untrusted",
        ChainValidation::Expired => "expired",
        ChainValidation::HostnameMismatch => "hostname-mismatch",
        ChainValidation::Unknown => "unknown",
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
            source: session_source(s.source).to_string(),
        }
    }
}
