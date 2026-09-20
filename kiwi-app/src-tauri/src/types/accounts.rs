//! Account-domain wire views — account list rows, setup/probe payloads.

use serde::{Deserialize, Serialize};

use kiwi_core::trust::SignalSeverity;
use kiwi_mail::account::MailAccount;

use super::{SecurityStatusView, SessionView};

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
