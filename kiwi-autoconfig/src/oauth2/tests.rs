//! Recorded-fixture tests for the OAuth2 module. Every endpoint interaction
//! replays `ScriptedHttp` steps — no live calls, deterministic bodies.
//! Loopback-listener tests use real `127.0.0.1` sockets (loopback only).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use kiwi_integrations::http::{ScriptedHttp, Step};
use kiwi_mail::account::{AuthRef, MemoryCredentialStore};

use super::*;

const NOW: i64 = 1_700_000_000;

/// RFC 7636 §B fixed PKCE pair — lets `expect_body` assertions be exact.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const STATE: &str = "state0123456789abcdef";

fn secrets() -> GrantSecrets {
    GrantSecrets::fixed(STATE, VERIFIER).unwrap()
}

fn step(
    name: &'static str,
    url_frag: &'static [&'static str],
    status: u16,
    body: &'static str,
) -> Step {
    Step::post(name, url_frag, status, body)
}

fn expect_body(mut s: Step, body: &str) -> Step {
    let leaked: &'static str = Box::leak(body.to_string().into_boxed_str());
    s.expect_body = Some(leaked.as_bytes());
    s
}

// ---------------------------------------------------------------------------
// PKCE / secrets
// ---------------------------------------------------------------------------

#[test]
fn pkce_rfc7636_vector() {
    let s = secrets();
    assert_eq!(s.code_challenge, CHALLENGE);
    assert_eq!(s.state, STATE);
    assert_eq!(s.code_verifier.as_str(), VERIFIER);
}

#[test]
fn pkce_generate_shape_and_uniqueness() {
    let a = GrantSecrets::generate().unwrap();
    let b = GrantSecrets::generate().unwrap();
    assert_ne!(a.code_verifier.as_str(), b.code_verifier.as_str());
    assert_ne!(a.state, b.state);
    assert!((43..=128).contains(&a.code_verifier.len()));
    assert_eq!(a.code_challenge.len(), 43); // b64url(SHA-256) no pad
}

#[test]
fn pkce_fixed_rejects_bad_material() {
    assert!(GrantSecrets::fixed("short", VERIFIER).is_err());
    assert!(GrantSecrets::fixed(STATE, "too-short").is_err());
    assert!(GrantSecrets::fixed(STATE, &"x".repeat(129)).is_err());
    assert!(GrantSecrets::fixed(STATE, &"!".repeat(50)).is_err()); // bad charset
}

// ---------------------------------------------------------------------------
// Form codec
// ---------------------------------------------------------------------------

#[test]
fn form_encode_strict_percent_encoding() {
    let out = form_encode(&[
        ("a", "hello world"),
        ("b", "https://x.test/p"),
        ("c", "unchanged-._~09"),
    ]);
    assert_eq!(
        out,
        "a=hello%20world&b=https%3A%2F%2Fx.test%2Fp&c=unchanged-._~09"
    );
}

#[test]
fn form_decode_roundtrip_and_rejects_bad_escapes() {
    let pairs = form_decode("a=hello%20world&b=x+y&c=%E2%82%AC").unwrap();
    assert_eq!(
        pairs,
        vec![
            ("a".to_string(), "hello world".to_string()),
            ("b".to_string(), "x y".to_string()),
            ("c".to_string(), "€".to_string()),
        ]
    );
    assert!(form_decode("a=%2").is_err());
    assert!(form_decode("a=%zz").is_err());
    assert!(form_decode("a=%ff%ff").is_err()); // invalid utf-8
    // bare key, empty value, first '=' wins
    assert_eq!(
        form_decode("k&x=a=b").unwrap(),
        vec![("k".into(), "".into()), ("x".into(), "a=b".into())]
    );
}

// ---------------------------------------------------------------------------
// Provider configs
// ---------------------------------------------------------------------------

#[test]
fn google_config_facts() {
    let p = ProviderConfig::google("cid");
    assert_eq!(p.id, "google");
    assert_eq!(p.grant_kind, GrantKind::LoopbackCode);
    assert_eq!(
        p.authorize_url.as_deref(),
        Some("https://accounts.google.com/o/oauth2/v2/auth")
    );
    assert_eq!(p.token_url, "https://oauth2.googleapis.com/token");
    assert_eq!(p.scopes, vec!["https://mail.google.com/".to_string()]);
    assert!(
        p.authorize_extra
            .contains(&("access_type".into(), "offline".into()))
    );
    assert!(p.device_code_url.is_none());
}

#[test]
fn microsoft_config_facts_and_tenant_validation() {
    let p = ProviderConfig::microsoft("cid");
    assert_eq!(p.grant_kind, GrantKind::DeviceCode);
    assert_eq!(
        p.device_code_url.as_deref(),
        Some("https://login.microsoftonline.com/common/oauth2/v2.0/devicecode")
    );
    assert_eq!(
        p.token_url,
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    );
    assert!(p.scope_param().contains("offline_access"));
    let t = ProviderConfig::microsoft_tenant("cid", "contoso.onmicrosoft.com").unwrap();
    assert!(t.token_url.contains("contoso.onmicrosoft.com"));
    for bad in ["", "ten ant", "tenant/evil", &"t".repeat(129), "tënt"] {
        assert!(
            ProviderConfig::microsoft_tenant("cid", bad).is_err(),
            "{bad}"
        );
    }
    assert!(ProviderConfig::by_id("google", "c").is_ok());
    assert!(ProviderConfig::by_id("microsoft", "c").is_ok());
    assert!(ProviderConfig::by_id("evil.example", "c").is_err());
}

#[test]
fn client_id_checked_at_begin() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let http = ScriptedHttp::new(vec![]);
        let flow = OAuthClient::new(ProviderConfig::microsoft("bad id"));
        let err = flow.begin(&http, NOW).await.unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig("client_id")));
        // no network call was consumed
        assert_eq!(http.remaining(), 0);
    });
}

// ---------------------------------------------------------------------------
// TokenSet lifecycle
// ---------------------------------------------------------------------------

#[test]
fn token_response_full_parse() {
    let body = r#"{"access_token":"AT-1","refresh_token":"RT-1","expires_in":3600,"token_type":"Bearer","scope":"openid mail","id_token":"ignored","ext_expires_in":7200}"#;
    let t = TokenSet::from_response(body.as_bytes(), NOW).unwrap();
    assert_eq!(t.access_token(), "AT-1");
    assert_eq!(t.refresh_token(), Some("RT-1"));
    assert_eq!(t.expires_at_unix(), Some(NOW + 3600));
    assert_eq!(t.scope(), Some("openid mail"));
}

#[test]
fn token_response_minimal_and_edge_cases() {
    // only access_token — no expiry, no refresh
    let t = TokenSet::from_response(br#"{"access_token":"AT"}"#, NOW).unwrap();
    assert_eq!(t.expires_at_unix(), None);
    assert_eq!(t.refresh_token(), None);
    // expires_in clamped to sane range
    let t = TokenSet::from_response(br#"{"access_token":"AT","expires_in":999999999999}"#, NOW)
        .unwrap();
    assert_eq!(t.expires_at_unix(), Some(NOW + 31_536_000));
    // empty scope normalizes to absent
    let t = TokenSet::from_response(br#"{"access_token":"AT","scope":""}"#, NOW).unwrap();
    assert_eq!(t.scope(), None);
}

#[test]
fn token_response_rejects_bad_shapes() {
    for (body, why) in [
        (r#"{"refresh_token":"RT"}"#, "missing access_token"),
        (r#"{"access_token":""}"#, "empty access_token"),
        (r#"{"access_token":"A T"}"#, "whitespace in token"),
        (r#"{"access_token":"AT","token_type":"MAC"}"#, "non-bearer"),
        (r#"not json"#, "not json"),
        (
            r#"{"access_token":"AT","expires_in":"soon"}"#,
            "bad expires_in type",
        ),
    ] {
        assert!(
            TokenSet::from_response(body.as_bytes(), NOW).is_err(),
            "case: {why}"
        );
    }
}

#[test]
fn token_expiry_skew_window() {
    let t = TokenSet::bearer("AT", Some("RT"), Some(NOW + 100), None).unwrap();
    assert!(!t.needs_refresh(NOW));
    assert!(!t.needs_refresh(NOW + 39));
    assert!(t.needs_refresh(NOW + 40)); // inside 60s skew
    assert!(t.needs_refresh(NOW + 100));
    let never = TokenSet::bearer("AT", None, None, None).unwrap();
    assert!(!never.needs_refresh(i64::MAX - 1));
}

#[test]
fn token_blob_roundtrip_and_redaction() {
    let t = TokenSet::bearer("AT-secret", Some("RT-secret"), Some(NOW + 60), Some("mail")).unwrap();
    let blob = t.to_blob();
    assert!(blob.contains("AT-secret")); // it IS the secret material — for the keystore only
    let back = TokenSet::from_blob(&blob).unwrap();
    assert_eq!(back.access_token(), "AT-secret");
    assert_eq!(back.refresh_token(), Some("RT-secret"));
    assert_eq!(back.expires_at_unix(), Some(NOW + 60));
    // Debug must never carry secrets
    let dbg = format!("{t:?}");
    assert!(!dbg.contains("AT-secret") && !dbg.contains("RT-secret"));
    assert!(dbg.contains("<redacted>"));
    // wrong version fails closed
    assert!(TokenSet::from_blob(r#"{"v":2,"access_token":"A","token_type":"Bearer"}"#).is_err());
    assert!(TokenSet::from_blob("{}").is_err());
}

// ---------------------------------------------------------------------------
// Device-code flow (Microsoft) — recorded fixtures
// ---------------------------------------------------------------------------

const MS_DEVICE_RESP: &str = r#"{"device_code":"DC-poll-handle","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","verification_uri_complete":"https://microsoft.com/devicelogin?user_code=ABCD-EFGH","expires_in":900,"interval":5,"message":"To sign in, use a web browser"}"#;

fn ms_flow() -> OAuthClient {
    OAuthClient::microsoft("ms-client")
}

fn ms_device_begin_body() -> String {
    "client_id=ms-client&scope=https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20https%3A%2F%2Foutlook.office.com%2FSMTP.Send%20offline_access".to_string()
}

async fn device_grant(flow: &OAuthClient) -> PendingGrant {
    let http = ScriptedHttp::new(vec![expect_body(
        step(
            "devicecode",
            &["login.microsoftonline.com/common/oauth2/v2.0/devicecode"],
            200,
            MS_DEVICE_RESP,
        ),
        &ms_device_begin_body(),
    )]);
    flow.begin(&http, NOW).await.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn device_begin_parses_grant() {
    let grant = device_grant(&ms_flow()).await;
    let PendingGrant::Device(g) = &grant else {
        panic!("expected device grant")
    };
    assert_eq!(grant.kind(), GrantKind::DeviceCode);
    assert_eq!(g.user_code, "ABCD-EFGH");
    assert_eq!(g.verification_uri, "https://microsoft.com/devicelogin");
    assert_eq!(
        g.verification_uri_complete.as_deref(),
        Some("https://microsoft.com/devicelogin?user_code=ABCD-EFGH")
    );
    assert_eq!(g.expires_at_unix, NOW + 900);
    assert_eq!(g.poll_interval_secs, 5);
    // redaction
    let dbg = format!("{grant:?}");
    assert!(!dbg.contains("DC-poll-handle"));
}

#[test]
fn device_begin_validates_response() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        for (body, why) in [
            (r#"{"user_code":"U","verification_uri":"https://x","expires_in":1}"#, "no device_code"),
            (r#"{"device_code":"D","verification_uri":"https://x","expires_in":1}"#, "no user_code"),
            (r#"{"device_code":"D","user_code":"U","verification_uri":"http://x","expires_in":1}"#, "http uri"),
            (r#"{"device_code":"D","user_code":"U","verification_uri":"https://x"}"#, "no expires_in"),
        ] {
            let http = ScriptedHttp::new(vec![step("dc", &["devicecode"], 200, body)]);
            assert!(
                ms_flow().begin(&http, NOW).await.is_err(),
                "case: {why}"
            );
        }
        // non-2xx with oauth error payload maps through endpoint_error
        let http = ScriptedHttp::new(vec![step(
            "dc",
            &["devicecode"],
            400,
            r#"{"error":"invalid_client","error_description":"bad"}"#,
        )]);
        let err = ms_flow().begin(&http, NOW).await.unwrap_err();
        assert!(matches!(err, OAuthError::Endpoint { .. }));
    });
}

#[test]
fn device_poll_pending_slowdown_complete() {
    let flow = ms_flow();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let grant = device_grant(&flow).await;
        // pending → Pending
        let http = ScriptedHttp::new(vec![step(
            "poll",
            &["/token"],
            400,
            r#"{"error":"authorization_pending"}"#,
        )]);
        assert!(matches!(
            flow.poll(&http, &grant, NOW).await.unwrap(),
            PollOutcome::Pending
        ));
        // slow_down → SlowDown(base + 5)
        let http = ScriptedHttp::new(vec![step("poll", &["/token"], 400, r#"{"error":"slow_down"}"#)]);
        match flow.poll(&http, &grant, NOW).await.unwrap() {
            PollOutcome::SlowDown { retry_after_secs } => assert_eq!(retry_after_secs, 10),
            _ => panic!("expected slowdown"),
        }
        // success → Complete(TokenSet); request body carries the grant handle
        let poll_body =
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=ms-client&device_code=DC-poll-handle".to_string();
        let http = ScriptedHttp::new(vec![expect_body(
            step(
                "poll",
                &["login.microsoftonline.com/common/oauth2/v2.0/token"],
                200,
                r#"{"access_token":"AT-ms","refresh_token":"RT-ms","expires_in":3600,"token_type":"Bearer"}"#,
            ),
            &poll_body,
        )]);
        match flow.poll(&http, &grant, NOW).await.unwrap() {
            PollOutcome::Complete(t) => {
                assert_eq!(t.access_token(), "AT-ms");
                assert_eq!(t.refresh_token(), Some("RT-ms"));
                assert_eq!(t.expires_at_unix(), Some(NOW + 3600));
            }
            _ => panic!("expected completion"),
        }
    });
}

#[test]
fn device_poll_terminal_errors() {
    let flow = ms_flow();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let grant = device_grant(&flow).await;
        for (body, expect) in [
            (r#"{"error":"authorization_declined"}"#, "denied"),
            (r#"{"error":"access_denied"}"#, "denied"),
            (r#"{"error":"expired_token"}"#, "expired"),
            (r#"{"error":"bad_verification_code"}"#, "invalid"),
        ] {
            let http = ScriptedHttp::new(vec![step("poll", &["/token"], 400, body)]);
            let err = flow.poll(&http, &grant, NOW).await.unwrap_err();
            match expect {
                "denied" => assert!(matches!(err, OAuthError::Denied)),
                "expired" => assert!(matches!(err, OAuthError::Expired)),
                "invalid" => assert!(matches!(err, OAuthError::InvalidGrant)),
                _ => unreachable!(),
            }
        }
    });
}

#[test]
fn device_poll_short_circuits_when_expired() {
    let flow = ms_flow();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let grant = device_grant(&flow).await; // expires NOW+900
        let http = ScriptedHttp::new(vec![]); // must stay unconsumed
        let err = flow.poll(&http, &grant, NOW + 900).await.unwrap_err();
        assert!(matches!(err, OAuthError::Expired));
    });
}

// ---------------------------------------------------------------------------
// Auth-code + loopback flow (Google) — recorded fixtures
// ---------------------------------------------------------------------------

fn google_flow() -> OAuthClient {
    OAuthClient::google("g-client")
}

#[test]
fn loopback_begin_builds_authorize_url() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let http = ScriptedHttp::new(vec![]); // begin() makes no endpoint call
        let grant = google_flow()
            .begin_with(&http, Some(&secrets()), NOW)
            .await
            .unwrap();
        let PendingGrant::Loopback(g) = &grant else {
            panic!("expected loopback grant")
        };
        assert!(g.redirect_uri.starts_with("http://127.0.0.1:"));
        let url = &g.authorize_url;
        for frag in [
            "https://accounts.google.com/o/oauth2/v2/auth?",
            "client_id=g-client",
            "response_type=code",
            "scope=https%3A%2F%2Fmail.google.com%2F",
            "state=state0123456789abcdef",
            "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method=S256",
            "access_type=offline",
            "prompt=consent",
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A",
        ] {
            assert!(url.contains(frag), "url missing {frag}: {url}");
        }
        // redaction
        assert!(!format!("{grant:?}").contains(VERIFIER));
        assert_eq!(http.remaining(), 0);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn loopback_exchange_redeems_code() {
    let http0 = ScriptedHttp::new(vec![]);
    let grant = google_flow()
        .begin_with(&http0, Some(&secrets()), NOW)
        .await
        .unwrap();
    let PendingGrant::Loopback(g) = &grant else {
        panic!("expected loopback")
    };
    let port = g.redirect_uri.rsplit(':').next().unwrap();
    let expect = format!(
        "client_id=g-client&code=AUTH-CODE&redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}&grant_type=authorization_code&code_verifier={VERIFIER}"
    );
    let http = ScriptedHttp::new(vec![expect_body(
        step(
            "token",
            &["oauth2.googleapis.com/token"],
            200,
            r#"{"access_token":"AT-g","refresh_token":"RT-g","expires_in":3600,"token_type":"Bearer","scope":"https://mail.google.com/"}"#,
        ),
        &expect,
    )]);
    let redirect = RedirectOutcome {
        code: Some("AUTH-CODE".into()),
        state: Some(STATE.into()),
        ..Default::default()
    };
    let tokens = google_flow()
        .exchange(&http, &grant, &redirect, NOW)
        .await
        .unwrap();
    assert_eq!(tokens.access_token(), "AT-g");
    assert_eq!(tokens.refresh_token(), Some("RT-g"));
    assert_eq!(tokens.expires_at_unix(), Some(NOW + 3600));
    assert!(http.is_exhausted());
}

#[tokio::test(flavor = "current_thread")]
async fn loopback_exchange_guards_state_and_errors() {
    let http0 = ScriptedHttp::new(vec![]);
    let grant = google_flow()
        .begin_with(&http0, Some(&secrets()), NOW)
        .await
        .unwrap();
    let flow = google_flow();
    // state mismatch — no request consumed
    let http = ScriptedHttp::new(vec![]);
    let bad = RedirectOutcome {
        code: Some("C".into()),
        state: Some("wrong-state".into()),
        ..Default::default()
    };
    let err = flow.exchange(&http, &grant, &bad, NOW).await.unwrap_err();
    assert!(matches!(err, OAuthError::StateMismatch));
    // provider-side error on redirect
    let denied = RedirectOutcome {
        error: Some("access_denied".into()),
        state: Some(STATE.into()),
        ..Default::default()
    };
    let err = flow
        .exchange(&http, &grant, &denied, NOW)
        .await
        .unwrap_err();
    assert!(matches!(err, OAuthError::Denied));
    // missing code
    let bare = RedirectOutcome {
        state: Some(STATE.into()),
        ..Default::default()
    };
    let err = flow.exchange(&http, &grant, &bare, NOW).await.unwrap_err();
    assert!(matches!(err, OAuthError::Malformed("code")));
    assert_eq!(http.remaining(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_grant_method_is_unsupported() {
    let flow = google_flow();
    let http = ScriptedHttp::new(vec![]);
    let grant = flow.begin_with(&http, Some(&secrets()), NOW).await.unwrap();
    // poll() on a loopback grant
    let err = flow.poll(&http, &grant, NOW).await.unwrap_err();
    assert!(matches!(err, OAuthError::UnsupportedGrant { .. }));
    // exchange() on a device grant
    let mflow = ms_flow();
    let mgrant = device_grant(&mflow).await;
    let redir = RedirectOutcome::default();
    let err = mflow
        .exchange(&http, &mgrant, &redir, NOW)
        .await
        .unwrap_err();
    assert!(matches!(err, OAuthError::UnsupportedGrant { .. }));
    // wait_for_redirect on a device grant
    assert!(matches!(
        mgrant.wait_for_redirect(Duration::from_millis(1)),
        Err(OAuthError::UnsupportedGrant { .. })
    ));
}

// ---------------------------------------------------------------------------
// Refresh semantics
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn refresh_rotates_and_preserves() {
    let rt_tokens = || TokenSet::bearer("AT-old", Some("RT-old"), Some(NOW), Some("s1")).unwrap();
    let flow = ms_flow();
    // Rotated refresh token replaces the old one.
    let body = "grant_type=refresh_token&client_id=ms-client&refresh_token=RT-old&scope=s1";
    let http = ScriptedHttp::new(vec![expect_body(
        step(
            "refresh",
            &["/token"],
            200,
            r#"{"access_token":"AT-new","refresh_token":"RT-new","expires_in":3600,"token_type":"Bearer"}"#,
        ),
        body,
    )]);
    let fresh = flow.refresh(&http, &rt_tokens(), NOW).await.unwrap();
    assert_eq!(fresh.access_token(), "AT-new");
    assert_eq!(fresh.refresh_token(), Some("RT-new"));

    // No refresh_token in response → keep the existing one (Google).
    let http = ScriptedHttp::new(vec![step(
        "refresh",
        &["/token"],
        200,
        r#"{"access_token":"AT-new2","expires_in":3600,"token_type":"Bearer"}"#,
    )]);
    let fresh = flow.refresh(&http, &rt_tokens(), NOW).await.unwrap();
    assert_eq!(fresh.refresh_token(), Some("RT-old"));

    // invalid_grant → InvalidGrant (dead grant → re-authorize)
    let http = ScriptedHttp::new(vec![step(
        "refresh",
        &["/token"],
        400,
        r#"{"error":"invalid_grant","error_description":"revoked"}"#,
    )]);
    let err = flow.refresh(&http, &rt_tokens(), NOW).await.unwrap_err();
    assert!(matches!(err, OAuthError::InvalidGrant));

    // no refresh token at all → InvalidGrant, no request
    let http = ScriptedHttp::new(vec![]);
    let bare = TokenSet::bearer("AT", None, Some(NOW), None).unwrap();
    let err = flow.refresh(&http, &bare, NOW).await.unwrap_err();
    assert!(matches!(err, OAuthError::InvalidGrant));
}

#[test]
fn non_2xx_without_payload_is_http_error() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let flow = ms_flow();
        let http = ScriptedHttp::new(vec![step(
            "refresh",
            &["/token"],
            502,
            "<html>bad gw</html>",
        )]);
        let tokens = TokenSet::bearer("AT", Some("RT"), Some(NOW), None).unwrap();
        let err = flow.refresh(&http, &tokens, NOW).await.unwrap_err();
        assert!(matches!(err, OAuthError::Http { status: 502 }));
    });
}

// ---------------------------------------------------------------------------
// Loopback listener — real 127.0.0.1 sockets
// ---------------------------------------------------------------------------

fn send_get(port: u16, target: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf
}

#[test]
fn listener_captures_redirect_after_noise() {
    let listener = LoopbackListener::bind().unwrap();
    let port = listener.port();
    let handle = std::thread::spawn(move || listener.wait(Duration::from_secs(10)));
    // noise first — must be acknowledged and ignored
    let r = send_get(port, "/favicon.ico");
    assert!(r.starts_with("HTTP/1.1 200"));
    let r = send_get(port, "GARBAGE LINE NO TARGET"); // malformed request line
    assert!(r.starts_with("HTTP/1.1 400"));
    // the real redirect
    send_get(port, "/?code=LC-1&state=st-9");
    let outcome = handle.join().unwrap().unwrap();
    assert_eq!(outcome.code.as_deref(), Some("LC-1"));
    assert_eq!(outcome.state.as_deref(), Some("st-9"));
}

#[test]
fn listener_captures_error_redirect_and_times_out() {
    let listener = LoopbackListener::bind().unwrap();
    let port = listener.port();
    let h = std::thread::spawn(move || listener.wait(Duration::from_secs(10)));
    send_get(
        port,
        "/?error=access_denied&state=s1&error_description=nope",
    );
    let outcome = h.join().unwrap().unwrap();
    assert_eq!(outcome.error.as_deref(), Some("access_denied"));
    assert_eq!(outcome.code, None);

    let listener = LoopbackListener::bind().unwrap();
    let err = listener.wait(Duration::from_millis(50)).unwrap_err();
    assert!(matches!(err, OAuthError::Expired));
}

// ---------------------------------------------------------------------------
// RedirectOutcome parsing
// ---------------------------------------------------------------------------

#[test]
fn redirect_outcome_from_query_and_url() {
    let o = RedirectOutcome::from_query("code=C1&state=S1").unwrap();
    assert_eq!(o.code.as_deref(), Some("C1"));
    assert_eq!(o.state.as_deref(), Some("S1"));
    let o = RedirectOutcome::from_query("http://127.0.0.1:9/?code=C2&state=S2#frag").unwrap();
    assert_eq!(o.code.as_deref(), Some("C2"));
    let o = RedirectOutcome::from_query("error=access_denied&state=S3").unwrap();
    assert_eq!(o.error.as_deref(), Some("access_denied"));
    assert!(o.code.is_none());
    assert!(RedirectOutcome::from_query("bad%escape%2").is_err());
}

// ---------------------------------------------------------------------------
// Credential-store seam
// ---------------------------------------------------------------------------

#[test]
fn credential_key_and_auth_ref_shapes() {
    assert_eq!(
        credential_key("google", "User@GMail.COM"),
        "oauth2/google/user@gmail.com"
    );
    match auth_ref("microsoft", "a@b.test") {
        AuthRef::XOAuth2 { credential_key } => {
            assert_eq!(credential_key, "oauth2/microsoft/a@b.test")
        }
        _ => panic!("expected XOAuth2"),
    }
}

#[test]
fn store_roundtrip_and_absent() {
    let store = MemoryCredentialStore::new();
    let tokens = TokenSet::bearer("AT", Some("RT"), Some(NOW + 60), None).unwrap();
    save_tokens(&store, "google", "u@x.test", &tokens).unwrap();
    let loaded = load_tokens(&store, "google", "u@x.test").unwrap().unwrap();
    assert_eq!(loaded.access_token(), "AT");
    assert!(
        load_tokens(&store, "google", "nobody@x.test")
            .unwrap()
            .is_none()
    );
    store.set("oauth2/google/bad@x.test", "{not json").unwrap();
    assert!(load_tokens(&store, "google", "bad@x.test").is_err());
    delete_tokens(&store, "google", "u@x.test").unwrap();
    assert!(load_tokens(&store, "google", "u@x.test").unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn ensure_fresh_refreshes_and_persists() {
    let store = MemoryCredentialStore::new();
    let stale = TokenSet::bearer("AT-old", Some("RT-old"), Some(NOW + 10), None).unwrap();
    save_tokens(&store, "microsoft", "u@x.test", &stale).unwrap();
    let flow = ms_flow();
    // inside skew → one refresh call, rotated tokens persisted
    let http = ScriptedHttp::new(vec![step(
        "refresh",
        &["/token"],
        200,
        r#"{"access_token":"AT-fresh","refresh_token":"RT-new","expires_in":3600,"token_type":"Bearer"}"#,
    )]);
    let out = ensure_fresh(&http, &flow, &store, "u@x.test", NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.access_token(), "AT-fresh");
    let stored = load_tokens(&store, "microsoft", "u@x.test")
        .unwrap()
        .unwrap();
    assert_eq!(stored.refresh_token(), Some("RT-new"));

    // fresh token → no request at all
    let http = ScriptedHttp::new(vec![]);
    let out = ensure_fresh(&http, &flow, &store, "u@x.test", NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.access_token(), "AT-fresh");

    // no grant stored → None
    let http = ScriptedHttp::new(vec![]);
    assert!(
        ensure_fresh(&http, &flow, &store, "ghost@x.test", NOW)
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Transport mapping (blanket impl over ScriptedHttp)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn transport_post_form_sends_encoded_body_and_headers() {
    let expected = form_encode(&[("k", "v v"), ("s", "https://x/")]);
    let http = ScriptedHttp::new(vec![expect_body(
        Step::post("t", &["https://x.test/token"], 200, "{}")
            .expect_header("content-type", "application/x-www-form-urlencoded"),
        &expected,
    )]);
    let reply = http
        .post_form("https://x.test/token", &[("k", "v v"), ("s", "https://x/")])
        .await
        .unwrap();
    assert_eq!(reply.status, 200);
}

#[test]
fn contract_version_pinned() {
    assert_eq!(CONTRACT_VERSION, "kiwi.oauth2/1");
}
