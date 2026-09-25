//! `DeliverabilityTester` — outbound-mail deliverability testing behind a
//! clean boundary.
//!
//! Flow (all three steps are single-shot; the caller drives any loop):
//!
//! 1. `reserve_inbox` → a **single-use** address + `slug`. The slug is a
//!    capability secret: anyone holding it can poll and read the report —
//!    [`TestSlug`] redacts on `Debug` and must never be logged.
//! 2. Caller sends the real message (through the real relay — that is the
//!    point of the measurement) to `reservation.address`.
//! 3. `poll_status` → 202/pending → `received` → `analyzing` → `checks_ready`
//!    (or `failed` / 410-expired). At `checks_ready`, `fetch_report`.
//!
//! Report model is evidence-first like everything else in KIWI: per-check
//! records carry `status`/`category`/`summary`/`citations`; aggregate scores
//! are integers in milli-units (`score_ours_milli` = the service's 0–100
//! scale ×1000; `score_compat_milli` = the classic 0–10 ×1000) so the crate
//! stays float-free and deterministic.
//!
//! Two invariants a consumer must not re-derive differently:
//!
//! - The slug is a capability: it is representable only as [`TestSlug`], is
//!   never serializable, and is zeroized on drop.
//! - The send decision is [`DeliverabilityReport::auth_gate`], which is
//!   fail-closed. [`DeliverabilityReport::auth_failures`] is a display set and
//!   is *not* a decision procedure.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::IntegrationError;
use crate::secret::SecretString;

pub mod spamtester;
pub use spamtester::EmailSpamTester;

/// Per-check cap — the provider's check count is documented as ~41 and
/// grows over time; 512 is generous headroom, not a promise. A report with
/// more checks than this is marked [`DeliverabilityReport::checks_truncated`]
/// and the authentication gate refuses to pass.
pub const MAX_CHECKS: usize = 512;
/// Cap on free-text fields inside the report.
pub const MAX_TEXT: usize = 16 * 1024;
/// Cap on citations per check.
pub const MAX_CITATIONS: usize = 64;

/// Capability secret for a reserved test.
///
/// `Debug`/`Display` print `([redacted])`, the inner buffer is zeroized on
/// drop, and the type implements **no** `serde` traits: the slug is
/// representable in Rust, never representable in JSON, a log line, or an IPC
/// payload. The only way to read it is [`TestSlug::as_str`], which is
/// `pub(crate)` and exists solely to build request URLs.
#[derive(Clone)]
pub struct TestSlug(SecretString);

impl TestSlug {
    /// Wrap an already-validated slug (see `parse_reservation`).
    pub(crate) fn new(s: String) -> Self {
        Self(SecretString::new(s))
    }

    /// Borrow the secret for request building. Internal use only.
    pub(crate) fn as_str(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for TestSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TestSlug([redacted])")
    }
}

impl fmt::Display for TestSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A reserved single-use test address. `Debug` redacts the slug; the type is
/// not serializable, so a reservation cannot be written to the audit log, the
/// mail store, or an IPC response.
#[derive(Debug, Clone)]
pub struct TestReservation {
    /// Where to send the test message (public sink address; domain is
    /// provider-assigned — never hardcode it).
    pub address: String,
    /// Capability secret for status/report calls. Never logged.
    pub slug: TestSlug,
    /// Expiry as unix seconds when the server sent a number/parseable string.
    pub expires_at_unix: Option<u64>,
    /// Expiry verbatim when it wasn't numeric (e.g. ISO-8601).
    pub expires_at_raw: Option<String>,
}

/// `analysis_status` values, in lifecycle order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisStatus {
    /// HTTP 202 — nothing has arrived at the address yet. Synthesized by the
    /// provider from the 202 status code, not from a body field.
    Pending,
    /// Message received, queued for analysis.
    Received,
    /// Analysis running.
    Analyzing,
    /// Checks are final — `fetch_report` now.
    ChecksReady,
    /// Server-side analysis failed. Reachable only through `Deserialize`;
    /// [`DeliverabilityTester::poll_status`] converts it into
    /// [`IntegrationError::AnalysisFailed`], so a caller never has to treat
    /// it as a success status.
    Failed,
    /// Anything new the service adds — forward-compatible, treated as
    /// "still working" by [`TestStatus::ready`].
    Other(String),
}

impl AnalysisStatus {
    fn from_wire(s: &str) -> Self {
        match s {
            "received" => Self::Received,
            "analyzing" => Self::Analyzing,
            "checks_ready" => Self::ChecksReady,
            "failed" => Self::Failed,
            other => Self::Other(other.into()),
        }
    }
    fn as_wire(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Received => "received",
            Self::Analyzing => "analyzing",
            Self::ChecksReady => "checks_ready",
            Self::Failed => "failed",
            Self::Other(s) => s,
        }
    }
}

impl Serialize for AnalysisStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}
impl<'de> Deserialize<'de> for AnalysisStatus {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(d)?))
    }
}

/// One `poll_status` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestStatus {
    pub analysis_status: AnalysisStatus,
    pub checks_done: u32,
    /// Server-reported total; reads move over time, never assert equality
    /// with a constant in consumers.
    pub checks_total: u32,
}

impl TestStatus {
    /// `checks_ready` — report fetchable. `failed` surfaces via Err/Failed.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.analysis_status == AnalysisStatus::ChecksReady
    }
}

/// Check outcome. `skip` = check did not apply (not pass, not fail).
/// Unknown statuses map to [`CheckStatus::Other`] — the service adds checks
/// over time; forward-compat is required, not optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
    Other(String),
}

impl CheckStatus {
    fn from_wire(s: &str) -> Self {
        match s {
            "pass" => Self::Pass,
            "warn" => Self::Warn,
            "fail" => Self::Fail,
            "skip" => Self::Skip,
            other => Self::Other(other.into()),
        }
    }
    fn as_wire(&self) -> &str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Other(s) => s,
        }
    }
}

impl Serialize for CheckStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}
impl<'de> Deserialize<'de> for CheckStatus {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(d)?))
    }
}

/// Known check categories. The four the service ships today; `Other`
/// keeps unknown categories intact rather than failing the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckCategory {
    Auth,
    InfraSpam,
    Content,
    Compliance,
    Other,
}

impl CheckCategory {
    /// Map a wire category string to the enum (case-insensitive; tolerates
    /// `infra`/`infrastructure`/`infraSpam` spellings for the infra bucket).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "auth" | "authentication" => Self::Auth,
            "infraspam" | "infra" | "infrastructure" => Self::InfraSpam,
            "content" => Self::Content,
            "compliance" => Self::Compliance,
            _ => Self::Other,
        }
    }
}

/// A quoted source behind a check — e.g. an RFC section or a receiver's
/// published rule. `kind` is the wire key (`standards`, `receiver`, …).
///
/// `url` is only ever a validated, capability-free public link: the provider
/// value is dropped (and this sentinel stored instead) when it is not HTTPS,
/// carries userinfo or a fragment, exceeds the length bound, or embeds the
/// reservation slug in raw or percent-encoded form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitedSource {
    pub kind: String,
    pub title: String,
    /// Validated public URL, or [`CitedSource::REJECTED_URL`].
    pub url: String,
}

impl CitedSource {
    /// Sentinel `url` for a citation whose provider URL failed validation.
    /// Empty on purpose: a redacted link must not be renderable as a link.
    pub const REJECTED_URL: &'static str = "";
}

/// One check's evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckEvidence {
    pub id: String,
    /// Raw category string from the wire (use [`CheckEvidence::category`]).
    pub category_raw: String,
    pub status: CheckStatus,
    pub title: String,
    pub summary: String,
    pub citations: Vec<CitedSource>,
}

impl CheckEvidence {
    /// Typed category bucket.
    #[must_use]
    pub fn category(&self) -> CheckCategory {
        CheckCategory::parse(&self.category_raw)
    }
}

/// Deterministic per-category tallies — computed from `checks[]`, never
/// trusted from the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryTally {
    pub pass: u32,
    pub warn: u32,
    pub fail: u32,
    pub skip: u32,
    pub other: u32,
}

/// Why the authentication evidence in a report cannot be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEvidenceGap {
    /// No `auth`-category check at all: absence of evidence is not a pass.
    NoAuthChecks,
    /// An `auth` check carried a status this build does not recognize.
    UnknownAuthStatus,
    /// A check carried a category this build does not recognize, so it may be
    /// an authentication check filed under a new bucket.
    UnknownCategory,
    /// `checks[]` exceeded [`MAX_CHECKS`] and the tail was dropped: a failure
    /// could exist in the part KIWI never saw.
    TruncatedChecks,
}

/// Fail-closed authentication gate. Only [`AuthGate::Clear`] permits sending;
/// an unknown status, an unknown category, a truncated check list, or a
/// complete absence of `auth` evidence all block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthGate {
    /// Recognized, complete auth evidence with no failure.
    Clear,
    /// Recognized auth failure(s); the gate blocks.
    Blocked {
        /// Ids of the failing auth checks.
        failed_ids: Vec<String>,
    },
    /// The evidence itself is incomplete, so nothing can be concluded. Any
    /// failure observed before the gap is still reported.
    Incomplete {
        /// Ids of the failing auth checks seen so far (may be empty).
        failed_ids: Vec<String>,
        /// Why the evidence cannot be trusted.
        gap: AuthEvidenceGap,
    },
}

impl AuthGate {
    /// The only state that allows the test message to be sent.
    #[must_use]
    pub fn clear(&self) -> bool {
        matches!(self, Self::Clear)
    }

    /// Failing auth check ids, whether the gate blocked or went incomplete.
    #[must_use]
    pub fn failed_ids(&self) -> &[String] {
        match self {
            Self::Clear => &[],
            Self::Blocked { failed_ids } | Self::Incomplete { failed_ids, .. } => failed_ids,
        }
    }

    /// The evidence gap, when there is one.
    #[must_use]
    pub fn gap(&self) -> Option<AuthEvidenceGap> {
        match self {
            Self::Incomplete { gap, .. } => Some(*gap),
            _ => None,
        }
    }
}

/// The report. `subscores` carries the server's per-category scores when the
/// wire has them (milli-units, keyed by raw category); `tallies` is always
/// populated — it is the deterministic evidence KIWI stands on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverabilityReport {
    /// 0–100 scale ×1000 (service's score; weights auth+infra). `None` when
    /// the server reports null (e.g. incomplete analysis).
    pub score_ours_milli: Option<u64>,
    /// Classic 0–10 SpamAssassin-scale score ×1000.
    pub score_compat_milli: Option<u64>,
    /// `false` = some checks could not run; the score is optimistic.
    pub complete: bool,
    /// Human-readable report page URL, or `None` when the provider's value
    /// failed validation (not HTTPS, userinfo, fragment, over-length, or
    /// carrying the reservation slug).
    pub report_url: Option<String>,
    /// Server-supplied per-category subscores (milli), when present.
    /// Known categories are normalized via [`CheckCategory`]; unknown
    /// categories are kept under their raw key.
    pub subscores: BTreeMap<String, u64>,
    /// Deterministic per-category outcome tallies from `checks`.
    pub tallies: BTreeMap<String, CategoryTally>,
    /// Per-check evidence, wire order, capped at [`MAX_CHECKS`].
    pub checks: Vec<CheckEvidence>,
    /// The provider sent more than [`MAX_CHECKS`] checks and KIWI kept the
    /// first `MAX_CHECKS`. The server's own `complete` flag is preserved
    /// separately and says nothing about this client-side cap.
    #[serde(default)]
    pub checks_truncated: bool,
}

impl DeliverabilityReport {
    /// Every `auth`-category check with the exact `fail` status — the display
    /// set only. Callers making a send decision must use
    /// [`DeliverabilityReport::auth_gate`]: this list silently omits an
    /// unknown status and anything past the client-side cap.
    #[must_use]
    pub fn auth_failures(&self) -> Vec<&CheckEvidence> {
        self.checks
            .iter()
            .filter(|c| c.category() == CheckCategory::Auth && c.status == CheckStatus::Fail)
            .collect()
    }

    /// The fail-closed authentication gate for this report.
    ///
    /// Order of evidence problems, most severe first: a truncated check list
    /// (failures may exist past the cap), an unrecognized `auth` status, an
    /// unrecognized category anywhere in the report, and finally a report with
    /// no `auth` check at all. Any of them yields
    /// [`AuthGate::Incomplete`]; only a complete, recognized, failure-free
    /// auth set yields [`AuthGate::Clear`].
    #[must_use]
    pub fn auth_gate(&self) -> AuthGate {
        let mut failed_ids = Vec::new();
        let mut auth_checks = 0usize;
        let mut unknown_auth_status = false;
        let mut unknown_category = false;

        for c in &self.checks {
            match c.category() {
                CheckCategory::Auth => {
                    auth_checks += 1;
                    match c.status {
                        CheckStatus::Fail => failed_ids.push(c.id.clone()),
                        CheckStatus::Other(_) => unknown_auth_status = true,
                        CheckStatus::Pass | CheckStatus::Warn | CheckStatus::Skip => {}
                    }
                }
                CheckCategory::Other => unknown_category = true,
                CheckCategory::InfraSpam | CheckCategory::Content | CheckCategory::Compliance => {}
            }
        }

        let gap = if self.checks_truncated {
            Some(AuthEvidenceGap::TruncatedChecks)
        } else if unknown_auth_status {
            Some(AuthEvidenceGap::UnknownAuthStatus)
        } else if unknown_category {
            Some(AuthEvidenceGap::UnknownCategory)
        } else if auth_checks == 0 {
            Some(AuthEvidenceGap::NoAuthChecks)
        } else {
            None
        };

        match gap {
            Some(gap) => AuthGate::Incomplete { failed_ids, gap },
            None if !failed_ids.is_empty() => AuthGate::Blocked { failed_ids },
            None => AuthGate::Clear,
        }
    }
}

/// Deliverability-tester contract. Implementations: [`EmailSpamTester`].
///
/// Implementors must: HTTPS only; treat `slug` as a credential (never in
/// logs/errors); single-shot calls (sleep/poll loops belong to the caller —
/// keeps the engine deterministic and testable).
#[async_trait]
pub trait DeliverabilityTester: Send + Sync {
    /// Stable provider id, e.g. `"email-spam-tester"`.
    fn name(&self) -> &'static str;

    /// Reserve a single-use inbox (`POST /inbox`). The address accepts
    /// exactly one message and expires ~1h after reservation.
    async fn reserve_inbox(&self) -> Result<TestReservation, IntegrationError>;

    /// One status poll (`GET /tests/{slug}/status`). 202 maps to
    /// [`AnalysisStatus::Pending`]; 410 → [`IntegrationError::Expired`].
    async fn poll_status(&self, res: &TestReservation) -> Result<TestStatus, IntegrationError>;

    /// Fetch the report (`GET /tests/{slug}`) — meaningful once
    /// [`TestStatus::ready`]; earlier calls race the server. Before letting a
    /// message be sent, the caller must consult
    /// [`DeliverabilityReport::auth_gate`].
    async fn fetch_report(
        &self,
        res: &TestReservation,
    ) -> Result<DeliverabilityReport, IntegrationError>;
}
