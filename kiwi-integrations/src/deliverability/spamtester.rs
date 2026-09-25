//! [`DeliverabilityTester`] over email-spam-tester.com's v1 API.
//!
//! Wire contract (documented behavior):
//!
//! - `POST {base}/inbox` → `{address, slug, expires_at}` — the address takes
//!   **exactly one** message and expires ~1h after reservation.
//! - `GET {base}/tests/{slug}/status` → `202` while nothing has arrived; `200`
//!   with `{analysis_status: received|analyzing|checks_ready|failed,
//!   checks_done, checks_total}`; `410` once the address expired; `404`
//!   unknown slug; `429` rate-limited. All errors carry JSON bodies.
//! - `GET {base}/tests/{slug}` → report `{score_ours, score_compat, complete,
//!   report_url, subscores?, checks[]}` — each check `{id, category, status,
//!   title, summary, citations{<kind>: [{title,url}]}}`.
//!
//! The `slug` is a **capability secret**: possession authorizes polling +
//! reading the report. It is carried in `TestSlug` (Debug/Display redacted),
//! never placed in error strings — URLs containing it are dropped by the
//! transport-error rule in [`crate::http`].

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{
    AnalysisStatus, CheckEvidence, CheckStatus, CitedSource, DeliverabilityReport,
    DeliverabilityTester, MAX_CHECKS, MAX_CITATIONS, MAX_TEXT, TestReservation, TestSlug,
    TestStatus,
};
use crate::error::IntegrationError;
use crate::http::{HttpClient, HttpRequest, HttpResponse, ReqwestClient};

/// Production base — HTTPS only, hardcoded.
pub const SPAMTESTER_API: &str = "https://email-spam-tester.com/api/v1";

/// email-spam-tester deliverability provider.
pub struct EmailSpamTester {
    http: Arc<dyn HttpClient>,
    base: String,
}

impl std::fmt::Debug for EmailSpamTester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailSpamTester")
            .field("base", &self.base)
            .finish()
    }
}

impl EmailSpamTester {
    /// Provider over an injected transport. `base` must be `https://` —
    /// enforced here, not at first request.
    pub fn new(http: Arc<dyn HttpClient>, base: &str) -> Result<Self, IntegrationError> {
        let base = base.trim_end_matches('/');
        crate::http::check_https_base(base)?;
        Ok(Self {
            http,
            base: base.to_string(),
        })
    }

    /// Provider over the live reqwest transport (`SPAMTESTER_API`, 30 s).
    pub fn live() -> Result<Self, IntegrationError> {
        let http = ReqwestClient::new(crate::http::DEFAULT_TIMEOUT_MS)?;
        Self::new(Arc::new(http), SPAMTESTER_API)
    }

    async fn call(&self, req: HttpRequest) -> Result<HttpResponse, IntegrationError> {
        let resp = self
            .http
            .request(req.header("accept", "application/json"))
            .await?;
        match resp.status {
            200..=299 => Ok(resp),
            404 => Err(IntegrationError::NotFound),
            410 => Err(IntegrationError::Expired),
            429 => Err(IntegrationError::RateLimited {
                retry_after_ms: resp
                    .header_values("retry-after")
                    .next()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|s| s.min(3600) * 1000),
            }),
            s => Err(IntegrationError::Http { status: s }),
        }
    }
}

#[async_trait]
impl DeliverabilityTester for EmailSpamTester {
    fn name(&self) -> &'static str {
        "email-spam-tester"
    }

    async fn reserve_inbox(&self) -> Result<TestReservation, IntegrationError> {
        let resp = self
            .call(HttpRequest::post(
                format!("{}/inbox", self.base),
                Some(Vec::new()),
            ))
            .await?;
        let v = resp.json()?;
        parse_reservation(&v)
    }

    async fn poll_status(&self, res: &TestReservation) -> Result<TestStatus, IntegrationError> {
        let url = format!("{}/tests/{}/status", self.base, q(res.slug.as_str()));
        let resp = self.call(HttpRequest::get(url)).await?;
        if resp.status == 202 {
            return Ok(TestStatus {
                analysis_status: AnalysisStatus::Pending,
                checks_done: 0,
                checks_total: 0,
            });
        }
        let v = resp.json()?;
        let status = v
            .get("analysis_status")
            .and_then(Value::as_str)
            .map(AnalysisStatus::from_wire)
            .ok_or(IntegrationError::Malformed("analysis_status"))?;
        if status == AnalysisStatus::Failed {
            return Err(IntegrationError::AnalysisFailed);
        }
        Ok(TestStatus {
            analysis_status: status,
            checks_done: ju32(&v, "checks_done").unwrap_or(0),
            checks_total: ju32(&v, "checks_total").unwrap_or(0),
        })
    }

    async fn fetch_report(
        &self,
        res: &TestReservation,
    ) -> Result<DeliverabilityReport, IntegrationError> {
        let url = format!("{}/tests/{}", self.base, q(res.slug.as_str()));
        let resp = self.call(HttpRequest::get(url)).await?;
        let v = resp.json()?;
        parse_report(&v)
    }
}

// ---------------------------------------------------------------------------
// Parsing (pure; fixture-tested)
// ---------------------------------------------------------------------------

fn parse_reservation(v: &Value) -> Result<TestReservation, IntegrationError> {
    let address = v
        .get("address")
        .and_then(Value::as_str)
        .map(|s| s.trim().chars().take(320).collect::<String>())
        .filter(|s| s.contains('@') && !s.bytes().any(|b| b.is_ascii_control()))
        .ok_or(IntegrationError::Malformed("address"))?;
    let slug_raw = v
        .get("slug")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or(IntegrationError::Malformed("slug"))?;
    let (expires_at_unix, expires_at_raw) = match v.get("expires_at") {
        Some(Value::Number(n)) => (n.as_u64(), None),
        Some(Value::String(s)) => match s.trim().parse::<u64>() {
            Ok(n) => (Some(n), None),
            Err(_) => (None, Some(s.chars().take(64).collect())),
        },
        _ => (None, None),
    };
    Ok(TestReservation {
        address,
        slug: TestSlug(slug_raw.to_string()),
        expires_at_unix,
        expires_at_raw,
    })
}

/// Report parser — tolerant on optional fields, strict on shape. Scores land
/// in milli-units (floats never cross the boundary). `checks[]` truncated at
/// `MAX_CHECKS` (the service documents ~41 and growing).
fn parse_report(v: &Value) -> Result<DeliverabilityReport, IntegrationError> {
    let checks_v = v
        .get("checks")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::Malformed("checks"))?;

    let mut checks = Vec::with_capacity(checks_v.len().min(MAX_CHECKS));
    let mut tallies: std::collections::BTreeMap<String, super::CategoryTally> =
        std::collections::BTreeMap::new();

    for (i, c) in checks_v.iter().take(MAX_CHECKS).enumerate() {
        let Some(obj) = c.as_object() else {
            return Err(IntegrationError::Malformed("checks[] entry"));
        };
        let status = obj
            .get("status")
            .and_then(Value::as_str)
            .map(CheckStatus::from_wire)
            .ok_or(IntegrationError::Malformed("checks[].status"))?;
        let category_raw = obj
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .chars()
            .take(64)
            .collect::<String>();
        let id = obj
            .get("id")
            .and_then(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            })
            .unwrap_or_else(|| format!("check-{i}"));
        let citations = parse_citations(obj.get("citations"));

        let tally = tallies
            .entry(category_raw.to_ascii_lowercase())
            .or_default();
        match status {
            CheckStatus::Pass => tally.pass += 1,
            CheckStatus::Warn => tally.warn += 1,
            CheckStatus::Fail => tally.fail += 1,
            CheckStatus::Skip => tally.skip += 1,
            CheckStatus::Other(_) => tally.other += 1,
        }

        checks.push(CheckEvidence {
            id: id.chars().take(128).collect(),
            category_raw,
            status,
            title: text(obj.get("title")),
            summary: text(obj.get("summary")),
            citations,
        });
    }

    let subscores = v
        .get("subscores")
        .or_else(|| v.get("scores"))
        .map(|s| match s.as_object() {
            Some(m) => m
                .iter()
                .filter_map(|(k, val)| milli(val).map(|m| (k.clone(), m)))
                .collect(),
            None => std::collections::BTreeMap::new(),
        })
        .unwrap_or_default();

    Ok(DeliverabilityReport {
        score_ours_milli: v.get("score_ours").and_then(milli),
        score_compat_milli: v.get("score_compat").and_then(milli),
        complete: v.get("complete").and_then(Value::as_bool).unwrap_or(false),
        report_url: v
            .get("report_url")
            .and_then(Value::as_str)
            .map(|s| s.chars().take(2048).collect()),
        subscores,
        tallies,
        checks,
    })
}

/// `citations` is an object of `kind -> [{title,url}]`; flattened to a list
/// preserving `kind` so a consumer can group. Unknown shapes are dropped.
fn parse_citations(v: Option<&Value>) -> Vec<CitedSource> {
    let mut out = Vec::new();
    let Some(obj) = v.and_then(Value::as_object) else {
        return out;
    };
    for (kind, list) in obj {
        let Some(arr) = list.as_array() else { continue };
        for e in arr.iter().take(MAX_CITATIONS) {
            let Some(t) = e.get("title").and_then(Value::as_str) else {
                continue;
            };
            out.push(CitedSource {
                kind: kind.chars().take(32).collect(),
                title: t.chars().take(MAX_TEXT).collect(),
                url: e
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .chars()
                    .take(2048)
                    .collect(),
            });
            if out.len() >= MAX_CITATIONS {
                return out;
            }
        }
    }
    out
}

/// JSON number → milli-units (`value * 1000`, rounded). Floats stay inside
/// this function — everything downstream is integer.
fn milli(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n
            .as_f64()
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| (f * 1000.0).round() as u64),
        _ => None,
    }
}

fn ju32(v: &Value, key: &str) -> Option<u32> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

/// Capped string field (missing/non-string → empty).
fn text(v: Option<&Value>) -> String {
    v.and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(MAX_TEXT)
        .collect()
}

/// Percent-encode a URL path segment (unreserved chars pass through).
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ScriptedHttp, Step};
    use std::sync::Arc;

    fn est(steps: Vec<Step>) -> (EmailSpamTester, Arc<ScriptedHttp>) {
        let http = Arc::new(ScriptedHttp::new(steps));
        let t = EmailSpamTester::new(http.clone(), "https://email-spam-tester.com/api/v1").unwrap();
        (t, http)
    }

    const RESERVE_JSON: &str = r#"{"address":"test-abc@in.email-spam-tester.com",
        "slug":"s3cr3t-capability-slug","expires_at":1758307200}"#;

    const REPORT_JSON: &str = r#"{
        "score_ours": 87, "score_compat": 9.1, "complete": true,
        "report_url": "https://email-spam-tester.com/r/s3cr3t",
        "subscores": {"auth": 95, "infra_spam": 80, "content": 88, "compliance": 100},
        "checks": [
            {"id":"dkim-align","category":"auth","status":"fail",
             "title":"DKIM alignment","summary":"d= platform domain, not From domain",
             "citations":{"standards":[{"title":"RFC 6376 §3.1.1","url":"https://rfc.test/6376"}]}},
            {"id":"rbl","category":"infra_spam","status":"pass",
             "title":"Blocklists","summary":"sender IP not listed","citations":{}},
            {"id":"links","category":"content","status":"warn",
             "title":"Link/image text mismatch","summary":"visible text ≠ href"},
            {"id":"bulk-tol","category":"compliance","status":"skip",
             "title":"Bulk sender rules","summary":"not a bulk sender"}
        ]}"#;

    #[tokio::test]
    async fn reserve_poll_report_happy_path() {
        let (t, http) = est(vec![
            Step::post("reserve", &["/inbox"], 200, RESERVE_JSON),
            Step::get(
                "status-pending",
                &["/tests/s3cr3t-capability-slug/status"],
                202,
                "{}",
            ),
            Step::get(
                "status-ready",
                &["/tests/s3cr3t-capability-slug/status"],
                200,
                r#"{"analysis_status":"checks_ready","checks_done":41,"checks_total":41}"#,
            ),
            Step::get(
                "report",
                &["/tests/s3cr3t-capability-slug"],
                200,
                REPORT_JSON,
            ),
        ]);

        let res = t.reserve_inbox().await.unwrap();
        assert_eq!(res.address, "test-abc@in.email-spam-tester.com");
        assert_eq!(res.expires_at_unix, Some(1_758_307_200));
        assert_eq!(format!("{:?}", res.slug), "TestSlug([redacted])");

        let s = t.poll_status(&res).await.unwrap();
        assert_eq!(s.analysis_status, AnalysisStatus::Pending);
        assert!(!s.ready());

        let s = t.poll_status(&res).await.unwrap();
        assert!(s.ready());
        assert_eq!(s.checks_done, 41);

        let r = t.fetch_report(&res).await.unwrap();
        assert_eq!(r.score_ours_milli, Some(87_000));
        assert_eq!(r.score_compat_milli, Some(9_100));
        assert!(r.complete);
        assert_eq!(r.checks.len(), 4);
        assert_eq!(r.subscores["auth"], 95_000);
        assert_eq!(r.tallies["auth"].fail, 1);
        assert_eq!(r.tallies["content"].warn, 1);
        assert_eq!(r.tallies["compliance"].skip, 1);
        // auth_failures: exactly the DKIM check, citation preserved
        let fails = r.auth_failures();
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].id, "dkim-align");
        assert_eq!(fails[0].citations[0].kind, "standards");
        assert_eq!(fails[0].citations[0].title, "RFC 6376 §3.1.1");
        assert!(http.is_exhausted());
    }

    #[tokio::test]
    async fn status_410_404_429_map() {
        for (status, want) in [
            (410u16, IntegrationError::Expired),
            (404, IntegrationError::NotFound),
            (
                429,
                IntegrationError::RateLimited {
                    retry_after_ms: None,
                },
            ),
        ] {
            let (t, _http) = est(vec![
                Step::post("reserve", &["/inbox"], 200, RESERVE_JSON),
                Step::get("status", &["/status"], status, "{}"),
            ]);
            let res = t.reserve_inbox().await.unwrap();
            assert_eq!(t.poll_status(&res).await.unwrap_err(), want);
        }
    }

    #[tokio::test]
    async fn analysis_failed_maps_to_error() {
        let (t, _http) = est(vec![
            Step::post("reserve", &["/inbox"], 200, RESERVE_JSON),
            Step::get(
                "status",
                &["/status"],
                200,
                r#"{"analysis_status":"failed"}"#,
            ),
        ]);
        let res = t.reserve_inbox().await.unwrap();
        assert_eq!(
            t.poll_status(&res).await.unwrap_err(),
            IntegrationError::AnalysisFailed
        );
    }

    #[tokio::test]
    async fn unknown_status_and_category_are_forward_compatible() {
        let (t, _http) = est(vec![
            Step::post("reserve", &["/inbox"], 200, RESERVE_JSON),
            Step::get(
                "status",
                &["/status"],
                200,
                r#"{"analysis_status":"quantum_reviewing","checks_done":3,"checks_total":42}"#,
            ),
            Step::get(
                "report",
                &["/tests/"],
                200,
                r#"{"score_ours":null,"score_compat":null,"complete":false,
                    "checks":[{"id":"x1","category":"ai_judgment","status":"meh","title":"t","summary":"s"}]}"#,
            ),
        ]);
        let res = t.reserve_inbox().await.unwrap();
        let s = t.poll_status(&res).await.unwrap();
        assert_eq!(
            s.analysis_status,
            AnalysisStatus::Other("quantum_reviewing".into())
        );
        assert!(!s.ready());
        let r = t.fetch_report(&res).await.unwrap();
        assert_eq!(r.score_ours_milli, None);
        assert!(!r.complete);
        assert_eq!(r.checks[0].status, CheckStatus::Other("meh".into()));
        assert_eq!(r.tallies["ai_judgment"].other, 1);
        assert!(r.auth_failures().is_empty());
    }

    #[tokio::test]
    async fn malformed_reservation_rejected() {
        let (t, _h) = est(vec![Step::post(
            "reserve",
            &["/inbox"],
            200,
            r#"{"address":"no-at-sign","slug":"x"}"#,
        )]);
        assert_eq!(
            t.reserve_inbox().await.unwrap_err(),
            IntegrationError::Malformed("address")
        );
        let (t, _h) = est(vec![Step::post(
            "reserve",
            &["/inbox"],
            200,
            r#"{"address":"a@b.c"}"#,
        )]);
        assert_eq!(
            t.reserve_inbox().await.unwrap_err(),
            IntegrationError::Malformed("slug")
        );
    }

    #[test]
    fn slug_never_leaks_into_debug_or_display() {
        let t = TestSlug("super-secret-slug".into());
        assert!(!format!("{t:?}").contains("secret"));
        assert!(!format!("{t}").contains("secret"));
        assert!(!format!("{t:?}").is_empty()); // prints [redacted]
    }
}
