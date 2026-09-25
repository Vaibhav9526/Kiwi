//! Wire views for the external-integrations surface (T-227) — temp mail
//! and deliverability testing. Providers are `kiwi-integrations`; these
//! structs are the stable camelCase shapes the webview consumes
//! (ipc.md §9e).
//!
//! Two disclosures ride every response:
//! - `publicInboxNotice` on every temp-mail answer — the binding warning
//!   from `kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE`, forwarded
//!   verbatim so the copy can never drift or be omitted by a view.
//! - `consentNotice` on `deliverability_begin` — the third-party
//!   disclosure plus what the capability token is (a single-use replay
//!   guard, not proof of a trusted user gesture); the token itself is
//!   verified backend-side (§9e).

use std::collections::BTreeMap;

use kiwi_integrations::deliverability::{
    AnalysisStatus, AuthEvidenceGap, AuthGate, CategoryTally, CheckCategory, CheckEvidence,
    CheckStatus, DeliverabilityReport, TestStatus,
};
use kiwi_integrations::tempmail::{InboxPoll, TempMessageSummary};
use serde::Serialize;
use zeroize::Zeroize;

/// The mandated disclosure — one place, so every view shares the instance.
fn public_inbox_notice() -> &'static str {
    kiwi_integrations::tempmail::PUBLIC_INBOX_NOTICE
}

/// Mandatory copy for the deliverability send flow: the third-party
/// disclosure, plus the honest description of what the token is. The token
/// is a single-use anti-replay capability verified backend-side — it is not
/// evidence of a human decision, and the copy must not claim otherwise.
pub const DELIVERABILITY_CONSENT_NOTICE: &str = "Sending the test message transmits it through a \
     third-party service (email-spam-tester.com) via your configured relay. The backend's \
     single-use token is a replay guard for this one send, not proof of your approval — send only \
     when you intend the message to leave your relay.";

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
#[derive(Clone, Serialize)]
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
    /// Single-use anti-replay capability — `deliverability_send` consumes
    /// it. Opaque to the UI; passing it back is the replay gate. The
    /// provider slug it guards never leaves the backend.
    pub consent_token: String,
    /// What the capability covers — mandatory UI copy.
    pub consent_notice: &'static str,
}

impl std::fmt::Debug for DeliverabilityBeginView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliverabilityBeginView")
            .field("test_id", &self.test_id)
            .field("address", &self.address)
            .field("consent_token", &"[redacted]")
            .field("consent_notice", &self.consent_notice)
            .finish()
    }
}

impl Drop for DeliverabilityBeginView {
    fn drop(&mut self) {
        self.consent_token.zeroize();
    }
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
    /// The single-use capability was burned by this call (it is never
    /// returned to the UI again, whatever the enqueue outcome was).
    pub consent_consumed: bool,
    /// A message is queued for the reserved address. `true` only when the
    /// enqueue actually succeeded.
    pub enqueued: bool,
    /// The queued send is single-attempt: an ambiguous relay failure is
    /// never retried into the single-use reservation.
    pub single_attempt: bool,
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
    /// A send is enqueued for this test (set only after a successful
    /// enqueue; the backend tracks it, the UI cannot infer send state
    /// from status alone).
    pub sent: bool,
    /// The single-use capability was already consumed, whatever the
    /// enqueue outcome was.
    pub consent_consumed: bool,
    /// The provider was not called: this answer was served from the
    /// backend's last observation and the caller must wait this long
    /// before the next poll.
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
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
    /// `false` = some checks could not run; the score is optimistic. The
    /// provider's own flag: it says nothing about KIWI's own client-side
    /// cap, which is `checks_truncated`.
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
    /// `id`s of failed `auth` checks observed before any evidence gap —
    /// the display set for the UI banner. Not a decision procedure: use
    /// `auth_gate`.
    pub auth_failure_ids: Vec<String>,
    /// The fail-closed authentication gate for this report. Only
    /// `state == "clear"` means the evidence is complete and clean;
    /// `blocked` and `incomplete` both forbid acting on the report.
    pub auth_gate: AuthGateView,
    /// KIWI kept only the first `MAX_CHECKS` checks: a failure may exist
    /// in the part the client never saw, so `complete` must never be read
    /// as "nothing was dropped".
    pub checks_truncated: bool,
    /// `complete` AND not truncated — the only combination in which the
    /// provider's flag and the client-side cap agree.
    pub evidence_complete: bool,
}

/// The crate's fail-closed `AuthGate`, flattened for the wire.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthGateView {
    /// `clear` | `blocked` | `incomplete`.
    pub state: &'static str,
    /// The single boolean a caller may act on: true only for `clear`.
    pub clear: bool,
    /// Failing auth check ids seen so far (empty when the gate is clear).
    pub failed_ids: Vec<String>,
    /// Why the evidence cannot be trusted: `no-auth-checks` |
    /// `unknown-auth-status` | `unknown-category` | `truncated-checks`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<&'static str>,
}

impl From<AuthGate> for AuthGateView {
    fn from(g: AuthGate) -> Self {
        let state = match &g {
            AuthGate::Clear => "clear",
            AuthGate::Blocked { .. } => "blocked",
            AuthGate::Incomplete { .. } => "incomplete",
        };
        Self {
            state,
            clear: g.clear(),
            failed_ids: g.failed_ids().to_vec(),
            gap: g.gap().map(auth_gap_wire),
        }
    }
}

pub(crate) fn auth_gap_wire(g: AuthEvidenceGap) -> &'static str {
    match g {
        AuthEvidenceGap::NoAuthChecks => "no-auth-checks",
        AuthEvidenceGap::UnknownAuthStatus => "unknown-auth-status",
        AuthEvidenceGap::UnknownCategory => "unknown-category",
        AuthEvidenceGap::TruncatedChecks => "truncated-checks",
    }
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
    pub fn from_status(
        test_id: &str,
        s: TestStatus,
        sent: bool,
        consent_consumed: bool,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self {
            test_id: test_id.to_string(),
            analysis_status: analysis_status_wire(&s.analysis_status),
            checks_done: s.checks_done,
            checks_total: s.checks_total,
            ready: s.ready(),
            sent,
            consent_consumed,
            retry_after_ms,
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
        let checks_truncated = r.checks_truncated;
        let complete = r.complete;
        let auth_gate = AuthGateView::from(r.auth_gate());
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
            complete,
            report_url: r.report_url,
            subscores: r.subscores,
            tallies: r
                .tallies
                .into_iter()
                .map(|(k, t)| (k, CategoryTallyView::from(t)))
                .collect(),
            checks,
            auth_failure_ids,
            auth_gate,
            checks_truncated,
            evidence_complete: complete && !checks_truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, category: &str, status: &str) -> CheckEvidence {
        CheckEvidence {
            id: id.into(),
            category_raw: category.into(),
            status: match status {
                "pass" => CheckStatus::Pass,
                "warn" => CheckStatus::Warn,
                "fail" => CheckStatus::Fail,
                "skip" => CheckStatus::Skip,
                other => CheckStatus::Other(other.into()),
            },
            title: id.into(),
            summary: String::new(),
            citations: Vec::new(),
        }
    }

    fn report(checks: Vec<CheckEvidence>, truncated: bool) -> DeliverabilityReport {
        DeliverabilityReport {
            score_ours_milli: Some(87_000),
            score_compat_milli: Some(9_100),
            complete: true,
            report_url: None,
            subscores: BTreeMap::new(),
            tallies: BTreeMap::new(),
            checks,
            checks_truncated: truncated,
        }
    }

    #[test]
    fn complete_never_hides_client_truncation() {
        let v = DeliverabilityReportView::from_report(
            "dtest-1",
            report(vec![check("spf", "auth", "pass")], true),
        );
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["complete"], true);
        assert_eq!(json["checksTruncated"], true);
        assert_eq!(json["evidenceComplete"], false);
        assert_eq!(json["authGate"]["state"], "incomplete");
        assert_eq!(json["authGate"]["clear"], false);
        assert_eq!(json["authGate"]["gap"], "truncated-checks");
    }

    #[test]
    fn gate_states_survive_the_wire() {
        let clear = DeliverabilityReportView::from_report(
            "dtest-2",
            report(vec![check("spf", "auth", "pass")], false),
        );
        assert!(clear.auth_gate.clear);
        assert_eq!(clear.auth_gate.state, "clear");
        assert!(clear.evidence_complete);

        let blocked = DeliverabilityReportView::from_report(
            "dtest-3",
            report(
                vec![check("spf", "auth", "pass"), check("dkim", "auth", "fail")],
                false,
            ),
        );
        assert_eq!(blocked.auth_gate.state, "blocked");
        assert_eq!(blocked.auth_gate.failed_ids, vec!["dkim"]);
        assert_eq!(blocked.auth_failure_ids, vec!["dkim"]);

        let unknown_status = DeliverabilityReportView::from_report(
            "dtest-4",
            report(vec![check("spf", "auth", "quantum")], false),
        );
        assert_eq!(unknown_status.auth_gate.state, "incomplete");
        assert_eq!(unknown_status.auth_gate.gap, Some("unknown-auth-status"));
        assert!(unknown_status.auth_failure_ids.is_empty());

        let no_auth = DeliverabilityReportView::from_report(
            "dtest-5",
            report(vec![check("links", "content", "warn")], false),
        );
        assert_eq!(no_auth.auth_gate.gap, Some("no-auth-checks"));

        let unknown_cat = DeliverabilityReportView::from_report(
            "dtest-6",
            report(
                vec![
                    check("spf", "auth", "pass"),
                    check("x", "brand-new", "fail"),
                ],
                false,
            ),
        );
        assert_eq!(unknown_cat.auth_gate.gap, Some("unknown-category"));
    }

    #[test]
    fn begin_view_debug_never_carries_the_capability() {
        let v = DeliverabilityBeginView {
            test_id: "dtest-7".into(),
            address: "drop@e2e.example".into(),
            expires_at_unix: Some(1),
            expires_at_raw: None,
            consent_token: "consent-secret-value".into(),
            consent_notice: "n",
        };
        let line = format!("{v:?}");
        assert!(!line.contains("consent-secret-value"));
        assert!(line.contains("[redacted]"));
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["consentToken"], "consent-secret-value");
        assert_eq!(json["testId"], "dtest-7");
    }

    #[test]
    fn status_view_serializes_the_backoff_hint() {
        let v = DeliverabilityStatusView::from_status(
            "dtest-8",
            TestStatus {
                analysis_status: AnalysisStatus::Pending,
                checks_done: 0,
                checks_total: 0,
            },
            false,
            true,
            Some(30_000),
        );
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["retryAfterMs"], 30_000);
        assert_eq!(json["consentConsumed"], true);
        assert_eq!(json["sent"], false);
        let plain = DeliverabilityStatusView::from_status(
            "dtest-9",
            TestStatus {
                analysis_status: AnalysisStatus::ChecksReady,
                checks_done: 3,
                checks_total: 3,
            },
            true,
            true,
            None,
        );
        assert!(
            serde_json::to_value(&plain)
                .unwrap()
                .get("retryAfterMs")
                .is_none()
        );
    }
}
