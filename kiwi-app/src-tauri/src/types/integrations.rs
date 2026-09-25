//! Wire views for the external-integrations surface (T-227) — temp mail
//! and deliverability testing. Providers are `kiwi-integrations`; these
//! structs are the stable camelCase shapes the webview consumes
//! (ipc.md §9e).
//!
//! Two disclosures ride every response:
//! - `publicInboxNotice` on every temp-mail answer — the binding warning
//!   from `kiwi-integrations::tempmail::PUBLIC_INBOX_NOTICE`, forwarded
//!   verbatim so the copy can never drift or be omitted by a view.
//! - `consentNotice` on `deliverability_begin` — what the consent token
//!   gates; the token itself is verified backend-side (§9e).

use std::collections::BTreeMap;

use kiwi_integrations::deliverability::{
    AnalysisStatus, CategoryTally, CheckCategory, CheckEvidence, CheckStatus, DeliverabilityReport,
    TestStatus,
};
use kiwi_integrations::tempmail::{InboxPoll, TempMessageSummary};
use serde::Serialize;

/// The mandated disclosure — one place, so every view shares the instance.
fn public_inbox_notice() -> &'static str {
    kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE
}

/// Mandatory consent copy for the deliverability send flow — the backend
/// enforces it via the single-use token; this text is what the UI shows
/// before the user hands the token back.
pub const DELIVERABILITY_CONSENT_NOTICE: &str = "Sending the test message transmits it through a \
     third-party service (email-spam-tester.com) via your configured relay. Consent is a \
     single-use token minted by the backend; the send cannot proceed without it.";

// ---------------------------------------------------------------------------
// Temp mail
// ---------------------------------------------------------------------------

/// `kiwi_integrations_tempmail_create` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempMailboxView {
    /// The live disposable address (public — see the notice).
    pub address: String,
    /// Server-side creation time, unix seconds, when the API reports it.
    /// GM addresses die 60 min later; `tempmail_extend` buys one extra hour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_created_unix: Option<u64>,
    /// Mandatory UI disclosure — always present.
    pub public_inbox_notice: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempMessageSummaryView {
    pub mail_id: String,
    pub from: String,
    pub subject: String,
    pub excerpt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_unix: Option<u64>,
    pub date: String,
    pub read: bool,
}

impl From<TempMessageSummary> for TempMessageSummaryView {
    fn from(m: TempMessageSummary) -> Self {
        Self {
            mail_id: m.mail_id,
            from: m.from,
            subject: m.subject,
            excerpt: m.excerpt,
            timestamp_unix: m.timestamp_unix,
            date: m.date,
            read: m.read,
        }
    }
}

/// `kiwi_integrations_tempmail_poll` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempPollView {
    pub messages: Vec<TempMessageSummaryView>,
    /// Total unseen on the server — may exceed `messages.len()`.
    pub total_new: u64,
    /// Address the server answered for (session resync signal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub public_inbox_notice: &'static str,
}

impl TempPollView {
    pub fn from_poll(p: InboxPoll) -> Self {
        Self {
            messages: p
                .messages
                .into_iter()
                .map(TempMessageSummaryView::from)
                .collect(),
            total_new: p.total_new,
            address: p.address,
            public_inbox_notice: public_inbox_notice(),
        }
    }
}

/// `kiwi_integrations_tempmail_fetch` answer. `html` is the sanitized
/// fragment — remote resources are always stripped for a public inbox
/// regardless of account settings. `text` is the plain body when present.
/// The raw RFC822 never crosses IPC.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempMessageView {
    pub mail_id: String,
    pub from: String,
    pub subject: String,
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Remote `img` sources dropped during sanitization.
    pub remote_images_stripped: u32,
    pub public_inbox_notice: &'static str,
}

/// `kiwi_integrations_tempmail_discard` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempDiscardView {
    /// Local session cleared — always true on success.
    pub discarded: bool,
    /// Whether the server acknowledged `forget_me`. The local session is
    /// discarded either way; `false` means the provider may still hold the
    /// address until it ages out.
    pub remote_forgotten: bool,
    pub public_inbox_notice: &'static str,
}

/// `kiwi_integrations_tempmail_extend` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempExtendView {
    /// The address got its extra hour.
    pub extended: bool,
    /// Server says the address already expired (nothing to extend).
    pub expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_created_unix: Option<u64>,
    pub public_inbox_notice: &'static str,
}

// ---------------------------------------------------------------------------
// Deliverability
// ---------------------------------------------------------------------------

/// `kiwi_integrations_deliverability_begin` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverabilityBeginView {
    /// Opaque session key for `status`/`report`/`send`. Not a secret.
    pub test_id: String,
    /// The single-use address to send the test message to.
    pub address: String,
    /// Address expiry, unix seconds, when the server reports a number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// Expiry verbatim when it wasn't numeric (e.g. ISO-8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_raw: Option<String>,
    /// Single-use consent capability — `deliverability_send` consumes it.
    /// Opaque to the UI; passing it back is the consent gesture. The
    /// provider slug it guards never leaves the backend.
    pub consent_token: String,
    /// What the consent covers — mandatory UI copy.
    pub consent_notice: &'static str,
}

/// `kiwi_integrations_deliverability_send` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverabilitySendView {
    pub test_id: String,
    /// Outbox queue id — undo-send still applies within the grace window.
    pub queue_id: String,
    /// Earliest dispatch (unix seconds).
    pub not_before_unix: i64,
}

/// `kiwi_integrations_deliverability_status` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverabilityStatusView {
    pub test_id: String,
    /// `pending` | `received` | `analyzing` | `checks_ready` | `failed` |
    /// an unknown forward-compat string.
    pub analysis_status: String,
    pub checks_done: u32,
    pub checks_total: u32,
    /// `checks_ready` — the report is fetchable.
    pub ready: bool,
    /// Consent already consumed + send enqueued (the backend tracks it;
    /// the UI cannot infer send state from status alone).
    pub sent: bool,
}

/// `kiwi_integrations_deliverability_report` answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverabilityReportView {
    pub test_id: String,
    /// Service's 0–100 score ×1000; `null` when incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_ours_milli: Option<u64>,
    /// Classic 0–10 score ×1000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_compat_milli: Option<u64>,
    /// `false` = some checks could not run; the score is optimistic.
    pub complete: bool,
    /// Human-readable report page (share this, not the JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
    /// Server-supplied per-category subscores (milli), keyed by category.
    pub subscores: BTreeMap<String, u64>,
    /// Deterministic per-category outcome counts computed from `checks`.
    pub tallies: BTreeMap<String, CategoryTallyView>,
    /// Per-check evidence, wire order.
    pub checks: Vec<CheckView>,
    /// `id`s of failed `auth` checks — the gate set for the UI banner.
    pub auth_failure_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryTallyView {
    pub pass: u32,
    pub warn: u32,
    pub fail: u32,
    pub skip: u32,
    pub other: u32,
}

impl From<CategoryTally> for CategoryTallyView {
    fn from(t: CategoryTally) -> Self {
        Self {
            pass: t.pass,
            warn: t.warn,
            fail: t.fail,
            skip: t.skip,
            other: t.other,
        }
    }
}

/// One check's evidence record.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckView {
    pub id: String,
    /// Normalized bucket: `auth` | `infra_spam` | `content` | `compliance`
    /// | `other`.
    pub category: &'static str,
    /// The provider's raw category string (verbatim — may be new/unknown).
    pub category_raw: String,
    /// `pass` | `warn` | `fail` | `skip` | unknown string.
    pub status: String,
    pub title: String,
    pub summary: String,
    pub citations: Vec<CitedSourceView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CitedSourceView {
    /// Wire kind: `standards` | `receiver` | … (forward-compat strings).
    pub kind: String,
    pub title: String,
    pub url: String,
}

pub(crate) fn category_wire(c: CheckCategory) -> &'static str {
    match c {
        CheckCategory::Auth => "auth",
        CheckCategory::InfraSpam => "infra_spam",
        CheckCategory::Content => "content",
        CheckCategory::Compliance => "compliance",
        CheckCategory::Other => "other",
    }
}

pub(crate) fn analysis_status_wire(s: &AnalysisStatus) -> String {
    match s {
        AnalysisStatus::Pending => "pending".to_string(),
        AnalysisStatus::Received => "received".to_string(),
        AnalysisStatus::Analyzing => "analyzing".to_string(),
        AnalysisStatus::ChecksReady => "checks_ready".to_string(),
        AnalysisStatus::Failed => "failed".to_string(),
        AnalysisStatus::Other(s) => s.clone(),
    }
}

fn check_status_wire(s: &CheckStatus) -> String {
    match s {
        CheckStatus::Pass => "pass".to_string(),
        CheckStatus::Warn => "warn".to_string(),
        CheckStatus::Fail => "fail".to_string(),
        CheckStatus::Skip => "skip".to_string(),
        CheckStatus::Other(s) => s.clone(),
    }
}

impl DeliverabilityStatusView {
    pub fn from_status(test_id: &str, s: TestStatus, sent: bool) -> Self {
        Self {
            test_id: test_id.to_string(),
            analysis_status: analysis_status_wire(&s.analysis_status),
            checks_done: s.checks_done,
            checks_total: s.checks_total,
            ready: s.ready(),
            sent,
        }
    }
}

impl DeliverabilityReportView {
    pub fn from_report(test_id: &str, r: DeliverabilityReport) -> Self {
        // Borrow before any field moves out of `r`.
        let auth_failure_ids = r
            .auth_failures()
            .iter()
            .map(|c: &&CheckEvidence| c.id.clone())
            .collect();
        let checks = r
            .checks
            .iter()
            .map(|c| CheckView {
                id: c.id.clone(),
                category: category_wire(c.category()),
                category_raw: c.category_raw.clone(),
                status: check_status_wire(&c.status),
                title: c.title.clone(),
                summary: c.summary.clone(),
                citations: c
                    .citations
                    .iter()
                    .map(|cs| CitedSourceView {
                        kind: cs.kind.clone(),
                        title: cs.title.clone(),
                        url: cs.url.clone(),
                    })
                    .collect(),
            })
            .collect();
        Self {
            test_id: test_id.to_string(),
            score_ours_milli: r.score_ours_milli,
            score_compat_milli: r.score_compat_milli,
            complete: r.complete,
            report_url: r.report_url,
            subscores: r.subscores,
            tallies: r
                .tallies
                .into_iter()
                .map(|(k, t)| (k, CategoryTallyView::from(t)))
                .collect(),
            checks,
            auth_failure_ids,
        }
    }
}
