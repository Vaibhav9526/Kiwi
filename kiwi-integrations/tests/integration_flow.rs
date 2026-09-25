//! End-to-end recorded-fixture flows through the public API only.
//!
//! These tests replay recorded HTTP exchanges via `ScriptedHttp` — no live
//! calls, no network. Fixtures live in `tests/fixtures/` and mirror the
//! providers' documented response shapes.
//!
//! Every step pins the complete request (`Step::get_exact` / `post_exact`:
//! method, whole URL, exact header set) and every test ends with
//! `assert_exhausted`, so an un-called provider operation and a mis-shaped
//! request both fail the run rather than passing on a half-replayed script.

use std::sync::Arc;

use kiwi_integrations::IntegrationError;
use kiwi_integrations::deliverability::{
    AnalysisStatus, AuthEvidenceGap, AuthGate, CheckCategory, CheckStatus, CitedSource,
    DeliverabilityTester, EmailSpamTester,
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

const GM_BASE: &str = "https://api.guerrillamail.com/ajax.php";
const ST_BASE: &str = "https://email-spam-tester.com/api/v1";
/// The recorded reservation slug (synthetic).
const ST_SLUG: &str = "fx-slug-9u2n4k";
const JSON: (&str, &str) = ("accept", "application/json");
const COOKIE_1: (&str, &str) = ("cookie", "PHPSESSID=phpsess-1");
const COOKIE_2: (&str, &str) = ("cookie", "PHPSESSID=phpsess-2");

fn scripted(steps: Vec<Step>) -> Arc<ScriptedHttp> {
    Arc::new(ScriptedHttp::new(steps))
}

/// Full GuerrillaMail lifecycle as a `dyn` object — proving the trait is
/// object-safe across the boundary the IPC layer will use.
#[tokio::test]
async fn guerrilla_full_lifecycle_via_trait_object() {
    let http = scripted(vec![
        Step::get_exact(
            "init",
            "https://api.guerrillamail.com/ajax.php?f=get_email_address&ip=127.0.0.1&agent=KIWI-fixture&lang=en",
            200,
            GM_ADDR,
        )
        .expect_header(JSON.0, JSON.1)
        .respond_headers(&[("set-cookie", "PHPSESSID=phpsess-1; path=/; HttpOnly")]),
        Step::post_exact(
            "rename",
            "https://api.guerrillamail.com/ajax.php?f=set_email_user&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01&email_user=kctest02&lang=en",
            200,
            r#"{"email_addr":"kctest02@sharklasers.com","email_timestamp":"1758300100"}"#,
        )
        .expect_header(JSON.0, JSON.1)
        .expect_header(COOKIE_1.0, COOKIE_1.1),
        Step::get_exact(
            "poll",
            "https://api.guerrillamail.com/ajax.php?f=check_email&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01&seq=0",
            200,
            GM_CHECK,
        )
        .expect_header(JSON.0, JSON.1)
        .expect_header(COOKIE_1.0, COOKIE_1.1)
        // Server rotates the session mid-flight — client must track it.
        .respond_headers(&[("set-cookie", "PHPSESSID=phpsess-2; path=/")]),
        Step::get_exact(
            "fetch",
            "https://api.guerrillamail.com/ajax.php?f=fetch_email&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01&email_id=9002",
            200,
            GM_FETCH,
        )
        .expect_header(JSON.0, JSON.1)
        .expect_header(COOKIE_2.0, COOKIE_2.1),
        Step::post_exact(
            "extend",
            "https://api.guerrillamail.com/ajax.php?f=extend&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01",
            200,
            GM_EXTEND,
        )
        .expect_header(JSON.0, JSON.1)
        .expect_header(COOKIE_2.0, COOKIE_2.1),
        Step::post_exact(
            "forget",
            "https://api.guerrillamail.com/ajax.php?f=forget_me&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01&email_addr=kctest02%40sharklasers.com",
            200,
            "true",
        )
        .expect_header(JSON.0, JSON.1)
        .expect_header(COOKIE_2.0, COOKIE_2.1),
    ]);
    let gm = GuerrillaMail::new(http.clone(), GM_BASE, "KIWI-fixture").unwrap();
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
    http.assert_exhausted();
}

/// Deliverability flow: reserve → pending → ready → report. The slug travels
/// in the URL path — the exact-URL steps pin its percent-encoded placement.
#[tokio::test]
async fn spamtester_reserve_status_report_flow() {
    let http = scripted(vec![
        Step::post_exact(
            "reserve",
            "https://email-spam-tester.com/api/v1/inbox",
            200,
            ST_RESERVE,
        )
        .expect_header(JSON.0, JSON.1)
        .body(b""),
        Step::get_exact(
            "pending",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k/status",
            202,
            "{}",
        )
        .expect_header(JSON.0, JSON.1),
        Step::get_exact(
            "ready",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k/status",
            200,
            ST_STATUS,
        )
        .expect_header(JSON.0, JSON.1),
        Step::get_exact(
            "report",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k",
            200,
            ST_REPORT,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let t = EmailSpamTester::new(http.clone(), ST_BASE).unwrap();
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
    assert_eq!(
        r.auth_gate(),
        AuthGate::Blocked {
            failed_ids: vec!["dkim-align".into()]
        }
    );
    assert!(!r.checks_truncated);
    http.assert_exhausted();
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

// ---------------------------------------------------------------------------
// Regressions for the T-286 rulings
// ---------------------------------------------------------------------------

/// The recorded report URL embeds the reservation slug, so it is never handed
/// out: the field is `None` and the citation links survive intact because they
/// carry no capability.
#[tokio::test]
async fn report_url_carrying_the_slug_is_omitted() {
    let http = scripted(vec![
        Step::post_exact(
            "reserve",
            "https://email-spam-tester.com/api/v1/inbox",
            200,
            ST_RESERVE,
        )
        .expect_header(JSON.0, JSON.1),
        Step::get_exact(
            "report",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k",
            200,
            ST_REPORT,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let t = EmailSpamTester::new(http.clone(), ST_BASE).unwrap();
    let res = t.reserve_inbox().await.unwrap();
    let r = t.fetch_report(&res).await.unwrap();
    assert_eq!(r.report_url, None);
    let cited: Vec<&str> = r
        .checks
        .iter()
        .flat_map(|c| c.citations.iter())
        .map(|c| c.url.as_str())
        .collect();
    assert_eq!(cited.len(), 3);
    for url in cited {
        assert!(url.starts_with("https://"), "{url} must stay a public link");
        assert!(!url.contains(ST_SLUG), "{url} leaked the capability");
    }
    http.assert_exhausted();
}

/// A citation whose URL embeds the slug — raw or percent-encoded — is reduced
/// to the rejected sentinel instead of becoming a copyable bearer link.
#[tokio::test]
async fn citation_urls_carrying_the_slug_are_rejected() {
    let http = scripted(vec![
        Step::post_exact(
            "reserve",
            "https://email-spam-tester.com/api/v1/inbox",
            200,
            ST_RESERVE,
        )
        .expect_header(JSON.0, JSON.1),
        Step::get_exact(
            "report",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k",
            200,
            r#"{"complete":true,"checks":[{"id":"spf","category":"auth","status":"pass",
                 "citations":{"receiver":[
                   {"title":"raw","url":"https://reports.test/r/fx-slug-9u2n4k"},
                   {"title":"encoded","url":"https://reports.test/r/fx%2Dslug%2D9u2n4k"},
                   {"title":"userinfo","url":"https://evil.test@reports.test/r"},
                   {"title":"plaintext","url":"http://reports.test/r"},
                   {"title":"good","url":"https://reports.test/r/public"}]}}]}"#,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let t = EmailSpamTester::new(http.clone(), ST_BASE).unwrap();
    let res = t.reserve_inbox().await.unwrap();
    let r = t.fetch_report(&res).await.unwrap();
    let urls: Vec<&str> = r.checks[0]
        .citations
        .iter()
        .map(|c| c.url.as_str())
        .collect();
    assert_eq!(
        urls,
        vec![
            CitedSource::REJECTED_URL,
            CitedSource::REJECTED_URL,
            CitedSource::REJECTED_URL,
            CitedSource::REJECTED_URL,
            "https://reports.test/r/public",
        ]
    );
    assert_eq!(r.auth_gate(), AuthGate::Clear);
    http.assert_exhausted();
}

/// A report whose auth check carries a status this build does not know is not
/// a pass, and neither is one with no auth evidence at all.
#[tokio::test]
async fn auth_gate_never_passes_on_unknown_evidence() {
    for (body, want) in [
        (
            r#"{"complete":true,"checks":[{"id":"dkim","category":"auth","status":"quarantined"}]}"#,
            AuthGate::Incomplete {
                failed_ids: vec![],
                gap: AuthEvidenceGap::UnknownAuthStatus,
            },
        ),
        (
            r#"{"complete":true,"checks":[{"id":"c","category":"content","status":"pass"}]}"#,
            AuthGate::Incomplete {
                failed_ids: vec![],
                gap: AuthEvidenceGap::NoAuthChecks,
            },
        ),
        (
            r#"{"complete":true,"checks":[{"id":"c","category":"brand_new","status":"pass"}]}"#,
            AuthGate::Incomplete {
                failed_ids: vec![],
                gap: AuthEvidenceGap::UnknownCategory,
            },
        ),
    ] {
        let http = scripted(vec![
            Step::post_exact(
                "reserve",
                "https://email-spam-tester.com/api/v1/inbox",
                200,
                ST_RESERVE,
            )
            .expect_header(JSON.0, JSON.1),
            Step::get_exact(
                "report",
                "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k",
                200,
                body,
            )
            .expect_header(JSON.0, JSON.1),
        ]);
        let t = EmailSpamTester::new(http.clone(), ST_BASE).unwrap();
        let res = t.reserve_inbox().await.unwrap();
        let r = t.fetch_report(&res).await.unwrap();
        let gate = r.auth_gate();
        assert_eq!(gate, want);
        assert!(!gate.clear());
        http.assert_exhausted();
    }
}

/// More checks than the client cap: the tail is dropped, the report says so,
/// and the gate refuses even though every retained auth check passed.
#[tokio::test]
async fn over_cap_report_is_marked_and_blocks_the_gate() {
    let checks: Vec<String> = (0..=600)
        .map(|i| format!(r#"{{"id":"auth-{i}","category":"auth","status":"pass","title":"t"}}"#))
        .collect();
    let body: &'static str = Box::leak(
        format!(r#"{{"complete":true,"checks":[{}]}}"#, checks.join(",")).into_boxed_str(),
    );
    let http = scripted(vec![
        Step::post_exact(
            "reserve",
            "https://email-spam-tester.com/api/v1/inbox",
            200,
            ST_RESERVE,
        )
        .expect_header(JSON.0, JSON.1),
        Step::get_exact(
            "report",
            "https://email-spam-tester.com/api/v1/tests/fx-slug-9u2n4k",
            200,
            body,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let t = EmailSpamTester::new(http.clone(), ST_BASE).unwrap();
    let res = t.reserve_inbox().await.unwrap();
    let r = t.fetch_report(&res).await.unwrap();
    assert_eq!(
        r.checks.len(),
        kiwi_integrations::deliverability::MAX_CHECKS
    );
    assert!(r.checks_truncated);
    assert!(r.complete, "the server's own flag is preserved separately");
    assert_eq!(r.auth_gate().gap(), Some(AuthEvidenceGap::TruncatedChecks));
    http.assert_exhausted();
}

/// In-band `{"error": …}` bodies are rejections, not successes, on every
/// operation of both providers.
#[tokio::test]
async fn in_band_error_envelopes_are_never_success() {
    let est_error = scripted(vec![
        Step::post_exact(
            "reserve",
            "https://email-spam-tester.com/api/v1/inbox",
            200,
            r#"{"error":"quota exceeded","address":"a@b.test","slug":"x"}"#,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let t = EmailSpamTester::new(est_error.clone(), ST_BASE).unwrap();
    assert_eq!(
        t.reserve_inbox().await.unwrap_err(),
        IntegrationError::ProviderRejected("provider_error")
    );
    est_error.assert_exhausted();

    let gm = GuerrillaMail::new(
        scripted(vec![Step::get_exact(
            "init",
            "https://api.guerrillamail.com/ajax.php?f=get_email_address&ip=127.0.0.1&agent=KIWI-fixture&lang=en",
            200,
            r#"{"error":"not ownership","email_addr":"a@b.test"}"#,
        )
        .expect_header(JSON.0, JSON.1)]),
        GM_BASE,
        "KIWI-fixture",
    )
    .unwrap();
    assert_eq!(
        gm.get_email_address().await.unwrap_err(),
        IntegrationError::ProviderRejected("not_ownership")
    );
}

/// `forget_me` accepts only the documented `true` token, and the local session
/// is cleared either way.
#[tokio::test]
async fn forget_me_needs_the_exact_success_token() {
    let http = scripted(vec![
        Step::get_exact(
            "init",
            "https://api.guerrillamail.com/ajax.php?f=get_email_address&ip=127.0.0.1&agent=KIWI-fixture&lang=en",
            200,
            GM_ADDR,
        )
        .expect_header(JSON.0, JSON.1),
        Step::post_exact(
            "forget",
            "https://api.guerrillamail.com/ajax.php?f=forget_me&ip=127.0.0.1&agent=KIWI-fixture&sid_token=fixture-token-01&email_addr=kctest01%40guerrillamailblock.com",
            200,
            r#"{"status":"ok"}"#,
        )
        .expect_header(JSON.0, JSON.1),
    ]);
    let gm = GuerrillaMail::new(http.clone(), GM_BASE, "KIWI-fixture").unwrap();
    gm.get_email_address().await.unwrap();
    assert_eq!(
        gm.forget_me().await.unwrap_err(),
        IntegrationError::ProviderRejected("forget_me")
    );
    assert_eq!(
        gm.address().as_deref(),
        Some("kctest01@guerrillamailblock.com")
    );
    http.assert_exhausted();
}

/// The live constructors are environment-gated: an offline run — and every CI
/// run, opt-in or not — cannot reach the network through them.
#[test]
fn live_constructors_are_gated() {
    let opted_in = std::env::var("KIWI_INTEGRATIONS_LIVE").as_deref() == Ok("1");
    let in_ci = std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "0");
    if opted_in && !in_ci {
        return;
    }
    assert!(EmailSpamTester::live().is_err());
    assert!(GuerrillaMail::live().is_err());
}
