//! End-to-end recorded-fixture flows through the public API only.
//!
//! These tests replay recorded HTTP exchanges via `ScriptedHttp` — no live
//! calls, no network. Fixtures live in `tests/fixtures/` and mirror the
//! providers' documented response shapes.

use std::sync::Arc;

use kiwi_integrations::IntegrationError;
use kiwi_integrations::deliverability::{
    AnalysisStatus, CheckCategory, CheckStatus, DeliverabilityTester, EmailSpamTester,
};
use kiwi_integrations::http::{HttpClient, ScriptedHttp, Step};
use kiwi_integrations::tempmail::{GuerrillaMail, TempMailProvider};

// Recorded fixtures (synthetic — never from real mail; SECURITY.md §4).
const GM_ADDR: &str = include_str!("fixtures/guerrilla/get_email_address.json");
const GM_CHECK: &str = include_str!("fixtures/guerrilla/check_email.json");
const GM_FETCH: &str = include_str!("fixtures/guerrilla/fetch_email.json");
const GM_EXTEND: &str = include_str!("fixtures/guerrilla/extend.json");
const ST_RESERVE: &str = include_str!("fixtures/spamtester/reserve.json");
const ST_STATUS: &str = include_str!("fixtures/spamtester/status_ready.json");
const ST_REPORT: &str = include_str!("fixtures/spamtester/report.json");

fn scripted(steps: Vec<Step>) -> Arc<ScriptedHttp> {
    Arc::new(ScriptedHttp::new(steps))
}

/// Full GuerrillaMail lifecycle as a `dyn` object — proving the trait is
/// object-safe across the boundary the IPC layer will use.
#[tokio::test]
async fn guerrilla_full_lifecycle_via_trait_object() {
    let http = scripted(vec![
        Step::get(
            "init",
            &["f=get_email_address", "ip=127.0.0.1", "agent=KIWI-fixture"],
            200,
            GM_ADDR,
        )
        .respond_headers(&[("set-cookie", "PHPSESSID=phpsess-1; path=/; HttpOnly")]),
        Step::post(
            "rename",
            &["f=set_email_user", "email_user=kctest02"],
            200,
            r#"{"email_addr":"kctest02@sharklasers.com","email_timestamp":"1758300100"}"#,
        )
        .expect_header("cookie", "PHPSESSID=phpsess-1"),
        Step::get("poll", &["f=check_email", "seq=0"], 200, GM_CHECK)
            .expect_header("cookie", "PHPSESSID=phpsess-1")
            // Server rotates the session mid-flight — client must track it.
            .respond_headers(&[("set-cookie", "PHPSESSID=phpsess-2; path=/")]),
        Step::get("fetch", &["f=fetch_email", "email_id=9002"], 200, GM_FETCH)
            .expect_header("cookie", "PHPSESSID=phpsess-2"),
        Step::post("extend", &["f=extend"], 200, GM_EXTEND)
            .expect_header("cookie", "PHPSESSID=phpsess-2"),
        Step::post(
            "forget",
            &["f=forget_me", "email_addr=kctest02%40sharklasers.com"],
            200,
            "true",
        )
        .expect_header("cookie", "PHPSESSID=phpsess-2"),
    ]);
    let gm = GuerrillaMail::new(
        http.clone(),
        "https://api.guerrillamail.com/ajax.php",
        "KIWI-fixture",
    )
    .unwrap();
    let p: &dyn TempMailProvider = &gm;

    assert_eq!(p.name(), "guerrillamail");
    let a = p.get_email_address().await.unwrap();
    assert_eq!(a.address, "kctest01@guerrillamailblock.com");

    let a = p.set_email_user("kctest02").await.unwrap();
    assert_eq!(a.address, "kctest02@sharklasers.com");
    assert_eq!(p.address().as_deref(), Some("kctest02@sharklasers.com"));

    let poll = p.check_email().await.unwrap();
    assert_eq!(poll.messages.len(), 2);
    assert_eq!(poll.total_new, 2);
    assert_eq!(poll.messages[0].mail_id, "9002");
    assert_eq!(poll.messages[0].subject, "Confirm your sign-up <kiwi>");
    // Server echoes the live address — session resync honored.
    assert_eq!(poll.address.as_deref(), Some("kctest02@sharklasers.com"));

    let msg = p.fetch_email("9002").await.unwrap();
    let raw = String::from_utf8(msg.raw_rfc822).unwrap();
    assert!(raw.contains("Subject: Confirm your sign-up <kiwi>\r\n"));
    assert!(raw.contains("Content-Type: text/html\r\n"));
    assert!(raw.contains("https://example-service.test/c?t=abc"));
    assert!(raw.contains("X-Kiwi-Temp-Provider: guerrillamail"));

    let ext = p.extend().await.unwrap();
    assert!(ext.extended && !ext.expired);

    p.forget_me().await.unwrap();
    assert_eq!(p.address(), None);
    assert!(http.is_exhausted());
}

/// Deliverability flow: reserve → pending → ready → report. The slug travels
/// in the URL path — fixture asserts the exact (percent-encoded) placement.
#[tokio::test]
async fn spamtester_reserve_status_report_flow() {
    let http = scripted(vec![
        Step::post("reserve", &["/api/v1/inbox"], 200, ST_RESERVE),
        Step::get(
            "pending",
            &["/api/v1/tests/fx-slug-9u2n4k/status"],
            202,
            "{}",
        ),
        Step::get(
            "ready",
            &["/api/v1/tests/fx-slug-9u2n4k/status"],
            200,
            ST_STATUS,
        ),
        Step::get("report", &["/api/v1/tests/fx-slug-9u2n4k"], 200, ST_REPORT),
    ]);
    let t = EmailSpamTester::new(http.clone(), "https://email-spam-tester.com/api/v1").unwrap();
    let t: &dyn DeliverabilityTester = &t;

    let res = t.reserve_inbox().await.unwrap();
    assert_eq!(res.address, "drop-k7f2@in.email-spam-tester.example");
    assert_eq!(res.expires_at_unix, Some(1_758_307_200));

    let s = t.poll_status(&res).await.unwrap();
    assert_eq!(s.analysis_status, AnalysisStatus::Pending);

    let s = t.poll_status(&res).await.unwrap();
    assert!(s.ready());
    assert_eq!((s.checks_done, s.checks_total), (41, 41));

    let r = t.fetch_report(&res).await.unwrap();
    assert_eq!(r.score_ours_milli, Some(87_000));
    assert_eq!(r.score_compat_milli, Some(9_100));
    assert!(r.complete);
    assert_eq!(r.subscores["infra_spam"], 80_000);
    assert_eq!(r.checks.len(), 5);
    // Deterministic tallies from checks[]:
    assert_eq!(r.tallies["auth"].pass, 1);
    assert_eq!(r.tallies["auth"].fail, 1);
    assert_eq!(r.tallies["infra_spam"].pass, 1);
    assert_eq!(r.tallies["content"].warn, 1);
    assert_eq!(r.tallies["compliance"].skip, 1);
    // The auth gate: exactly one failure, with both citation kinds.
    let fails = r.auth_failures();
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].citations.len(), 2);
    assert_eq!(fails[0].category(), CheckCategory::Auth);
    assert_eq!(fails[0].status, CheckStatus::Fail);
    assert!(http.is_exhausted());
}

/// A transport that always fails — providers must map it to the sanitized
/// `Transport` error, never panic, never leak the URL.
struct FailingHttp;
#[async_trait::async_trait]
impl HttpClient for FailingHttp {
    async fn request(
        &self,
        _req: kiwi_integrations::http::HttpRequest,
    ) -> Result<kiwi_integrations::http::HttpResponse, IntegrationError> {
        Err(IntegrationError::Transport {
            kind: kiwi_integrations::TransportKind::Connect,
        })
    }
}

#[tokio::test]
async fn transport_failure_is_classified_not_leaked() {
    let t = EmailSpamTester::new(Arc::new(FailingHttp), "https://api.test/v1").unwrap();
    let err = t.reserve_inbox().await.unwrap_err();
    // No URL, no slug material, no provider message — just the class.
    assert_eq!(err.to_string(), "transport failure (Connect)");
}

#[tokio::test]
async fn non_https_base_rejected_before_transport() {
    let http: Arc<dyn HttpClient> = Arc::new(FailingHttp);
    assert!(matches!(
        EmailSpamTester::new(http.clone(), "http://insecure.test/api/v1"),
        Err(IntegrationError::InsecureUrl)
    ));
    assert!(matches!(
        GuerrillaMail::new(http, "ftp://x/", "a"),
        Err(IntegrationError::InsecureUrl)
    ));
}
