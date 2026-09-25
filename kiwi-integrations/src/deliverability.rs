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

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::IntegrationError;

pub mod spamtester;
pub use spamtester::EmailSpamTester;

/// Per-check cap — the provider's check count is documented as ~41 and
/// grows over time; 512 is generous headroom, not a promise.
pub const MAX_CHECKS: usize = 512;
/// Cap on free-text fields inside the report.
pub const MAX_TEXT: usize = 16 * 1024;
/// Cap on citations per check.
pub const MAX_CITATIONS: usize = 64;

/// Capability secret for a reserved test. `Debug`/`Display` print
/// `[redacted]`; serialize only for transport to the caller — never log it,
/// never write it to the audit log or SQLite.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TestSlug(String);

impl TestSlug {
    /// Borrow the secret for request building. Internal use only.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for TestSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestSlug([redacted])")
    }
}

impl std::fmt::Display for TestSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A reserved single-use test address.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// HTTP 202 — nothing has arrived at the address yet.
    Pending,
    /// Message received, queued for analysis.
    Received,
    /// Analysis running.
    Analyzing,
    /// Checks are final — `fetch_report` now.
    ChecksReady,
    /// Server-side analysis failed (terminal for this reservation).
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitedSource {
    pub kind: String,
    pub title: String,
    pub url: String,
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
    /// Human-readable report page URL (hand people the page, not the JSON).
    pub report_url: Option<String>,
    /// Server-supplied per-category subscores (milli), when present.
    /// Known categories are normalized via [`CheckCategory`]; unknown
    /// categories are kept under their raw key.
    pub subscores: BTreeMap<String, u64>,
    /// Deterministic per-category outcome tallies from `checks`.
    pub tallies: BTreeMap<String, CategoryTally>,
    /// Per-check evidence, wire order.
    pub checks: Vec<CheckEvidence>,
}

impl DeliverabilityReport {
    /// Every `auth`-category check that failed — the "stop at the door" set
    /// (a message can score well on content while DKIM signs with the wrong
    /// domain).
    #[must_use]
    pub fn auth_failures(&self) -> Vec<&CheckEvidence> {
        self.checks
            .iter()
            .filter(|c| c.category() == CheckCategory::Auth && c.status == CheckStatus::Fail)
            .collect()
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
    /// [`TestStatus::ready`]; earlier calls race the server.
    async fn fetch_report(
        &self,
        res: &TestReservation,
    ) -> Result<DeliverabilityReport, IntegrationError>;
}
