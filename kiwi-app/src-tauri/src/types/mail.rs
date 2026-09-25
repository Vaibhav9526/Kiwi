//! Mail-read wire views — folders, message lists, bodies, sync reports.

use serde::Serialize;

use kiwi_mail::store::{FolderMeta, MessageMeta};

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
    /// Deterministic inbox tab slug (T-201: "primary" | "newsletters" |
    /// "social" | "notifications" | "other").
    pub category: String,
    /// Unsubscribe https URL, when the sender advertised one (T-202).
    /// Safe default action: open it (POST when `unsubscribe_one_click`).
    pub unsubscribe_url: Option<String>,
    /// Unsubscribe mailto address (parameters stripped), when advertised.
    /// Consent-gated fallback — never auto-send.
    pub unsubscribe_mailto: Option<String>,
    /// RFC 8058 one-click marker on the unsubscribe URL.
    pub unsubscribe_one_click: bool,
    /// True when a `mailto:` option exists: composing to it requires
    /// explicit user consent and must never be auto-sent.
    pub unsubscribe_requires_consent: bool,
    /// SPF / DKIM / DMARC verdicts stamped at ingest (T-232). `None` until
    /// the body has been fetched and evaluated — "not evaluated" is distinct
    /// from a `none` verdict, so the pill must render unknown, not safe.
    pub auth: Option<AuthView>,
}

/// Authentication-Results verdicts for the UI security pill (T-232).
///
/// Verdict strings are the `kiwi.mailauth/1` vocabulary: `pass`, `fail`,
/// `softfail`, `neutral`, `none`, `temperror`, `permerror`. Per SECURITY.md
/// rule 1/2 the pill must treat `none` (no record) and `temperror` (could not
/// check) as *absence of evidence*, never as a pass or a finding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthView {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
    /// Policy that would apply on DMARC failure (`none` when aligned).
    pub dmarc_policy: String,
    /// DKIM signing domain (`d=`) when a signature parsed.
    pub dkim_domain: Option<String>,
    /// The stamped RFC 8601 header value, for the evidence popover.
    pub header_value: Option<String>,
    /// Bounded evidence (explanations + evidence refs), never a finding.
    pub evidence: Option<serde_json::Value>,
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
            category: m.category.as_str().to_string(),
            unsubscribe_url: m.unsub_http.clone(),
            unsubscribe_mailto: m.unsub_mailto.clone(),
            unsubscribe_one_click: m.unsub_oneclick,
            unsubscribe_requires_consent: m.unsub_mailto.is_some(),
            // T-232: real verdicts, or None when the body has not been
            // evaluated yet (which the pill must show as unknown).
            auth: m.auth.as_ref().map(|a| AuthView {
                spf: a.spf.clone(),
                dkim: a.dkim.clone(),
                dmarc: a.dmarc.clone(),
                dmarc_policy: a.dmarc_policy.clone(),
                dkim_domain: a.dkim_domain.clone(),
                header_value: a.header_value.clone(),
                evidence: a.evidence.clone(),
            }),
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
