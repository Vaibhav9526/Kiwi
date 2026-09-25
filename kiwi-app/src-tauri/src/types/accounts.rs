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
    /// Completed-grant ticket from `kiwi_oauth2_begin`/`_poll` (T-230).
    /// Valid only with `kind: "xoauth2"`; when present the backend binds
    /// the already-stored grant (`oauth2/<provider>/<email>` key) to BOTH
    /// auth directions — token material never crosses IPC.
    #[serde(default)]
    pub oauth2_ticket: Option<String>,
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

// ---------------------------------------------------------------------------
// Autoconfig discovery (kiwi_discover_account, ipc.md §5 — T-230)
// ---------------------------------------------------------------------------

/// One server side of a discovery suggestion.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedIncomingView {
    /// "imap" | "pop3".
    pub kind: String,
    pub host: String,
    pub port: u16,
    /// "tls" | "starttls" | "plaintext".
    pub security: String,
    /// "password" | "xoauth2" — same spelling `AddAccountInput` takes.
    pub auth: String,
    pub username: String,
}

/// Outgoing side (SMTP) of a discovery suggestion.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedOutgoingView {
    pub host: String,
    pub port: u16,
    /// "tls" | "starttls" | "plaintext".
    pub security: String,
    /// "password" | "xoauth2".
    pub auth: String,
    pub username: String,
}

/// The winning suggestion — feeds `kiwi_add_account` fields verbatim.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestionView {
    /// "ispdb" | "autoconfig_host" | "well_known" | "mx_heuristic" | "manual".
    pub source: String,
    pub email: String,
    pub display_name: String,
    pub incoming: SuggestedIncomingView,
    pub outgoing: SuggestedOutgoingView,
    /// OAuth2 provider spec when the suggestion's endpoints are ones a
    /// shipped provider config can mint tokens for — the wizard passes
    /// `provider` straight to `kiwi_oauth2_begin` (ipc.md §9f).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<crate::types::oauth2::OAuth2SpecView>,
}

/// One discovery stage's outcome — the audit trail the UI may render.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageAttemptView {
    pub source: String,
    /// "hit" | "miss" | "unreachable" | "malformed" | "unsupported".
    pub outcome: String,
    pub detail: String,
}

/// `kiwi_discover_account` result (ipc.md §5 shape + `oauth2` spec).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryOutcomeView {
    pub email: String,
    pub domain: String,
    /// Winning stage's source token (same vocabulary as attempts).
    pub source: String,
    /// True ⇒ UI must ask before persisting (pattern guess / manual).
    pub needs_manual_review: bool,
    pub suggestion: SuggestionView,
    pub attempts: Vec<StageAttemptView>,
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
