//! Sync→observe→finding seam test (T-166).
//!
//! A real `kiwi-mail` SMTP client performs a full send against a
//! fixture-shaped local server (dialogue scripted from
//! `tests/fixtures/transcripts/smtp_send_ok.txt`), then the exact
//! observe→adapter→engine path (`LiveSessionInput` → `event_from_live` →
//! `RuleEngine`, mirroring `kiwi-app/src-tauri/src/observe.rs`) must emit
//! the deterministic plaintext-send findings. Hermetic: localhost TCP
//! only, fixed timestamps, no daemon.
//!
//! Auth facts follow the contract §11 threading rule (mechanism observed
//! → 1 attempt; accepted reply → success): the test pins the intended end
//! state that `observe.rs` applies once Agent 7 threads `ctx` through.

use kiwi_forensics::live::{LiveAuthObservation, LiveSessionInput, SocketMode, event_from_live};
use kiwi_forensics::model::{AuthMechanism, Protocol};
use kiwi_forensics::rules::{RuleEngine, SecurityPolicy};
use kiwi_mail::smtp::{SendRequest, SmtpAuth, SmtpClient, SmtpConfig};
use kiwi_mail::transport::{SocketSecurity, TlsSettings, Transport};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

const STARTED_AT_UNIX_MS: i64 = 1_700_000_000_000;
const FIXTURE: &str = "smtp_send_ok.txt";
const PASSWORD: &str = "fixture-pass-1";

/// Server script lines from the fixture: `S:` payloads in order.
fn server_script() -> Vec<String> {
    let path = format!(
        "{}/../tests/fixtures/transcripts/{FIXTURE}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("fixture present");
    text.lines()
        .filter_map(|line| line.strip_prefix("S:"))
        .map(|rest| rest.strip_prefix(' ').unwrap_or(rest).to_string())
        .collect()
}

/// Serve the script: greeting first, then one client line per `S:` block;
/// after a `354` reply, consume body lines through the lone dot and send
/// the queued-reply without waiting (the client is reading, not writing).
/// Multiline `250-` replies go out without waiting. Reads time out so a
/// diverged dialogue fails the test instead of hanging the harness.
async fn serve(mut stream: tokio::net::TcpStream, script: Vec<String>) {
    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader).lines();
    writer
        .write_all(format!("{}\r\n", script[0]).as_bytes())
        .await
        .expect("greeting");
    let mut index = 1usize;
    loop {
        let client = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
            .await
            .expect("read timeout: dialogue diverged")
            .expect("client speaks")
            .expect("no EOF");
        if index == 1 {
            assert!(
                client.to_ascii_uppercase().starts_with("EHLO"),
                "session opens with EHLO, got {client:?}"
            );
        }
        let (next, last) = send_block(&mut writer, &script, index).await;
        index = next;
        if last.starts_with("354") {
            loop {
                let body =
                    tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
                        .await
                        .expect("body timeout")
                        .expect("body")
                        .expect("no EOF in body");
                if body == "." {
                    break;
                }
            }
            index = send_block(&mut writer, &script, index).await.0;
        }
        if client.to_ascii_uppercase().starts_with("QUIT") || index >= script.len() {
            break;
        }
    }
}

/// Send one `S:` block (plus `250-` continuations); return the next index
/// and the last line sent.
async fn send_block(
    writer: &mut tokio::net::tcp::WriteHalf<'_>,
    script: &[String],
    mut index: usize,
) -> (usize, String) {
    let mut last_sent = String::new();
    while index < script.len() {
        last_sent = script[index].clone();
        writer
            .write_all(format!("{last_sent}\r\n").as_bytes())
            .await
            .expect("reply");
        index += 1;
        if !last_sent.starts_with("250-") {
            break;
        }
    }
    (index, last_sent)
}

#[tokio::test]
async fn fixture_send_observes_deterministic_plaintext_findings() {
    let script = server_script();
    assert!(script.len() > 5, "fixture has a full dialogue");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        serve(stream, script).await;
    });

    let transport = Transport::connect(
        "127.0.0.1",
        port,
        SocketSecurity::Plaintext,
        TlsSettings::default(),
    )
    .await
    .expect("connect");
    let mut client = SmtpClient::connect(
        transport,
        SmtpConfig {
            require_starttls: false,
            allow_plaintext_auth: true,
            client_name: "kiwi.local".to_string(),
        },
    )
    .await
    .expect("greeting+EHLO");
    client
        .authenticate(&SmtpAuth::Plain {
            user: "alice@kiwi-test.invalid".to_string(),
            password: Zeroizing::new(PASSWORD.to_string()),
        })
        .await
        .expect("AUTH accepted");
    let outcome = client
        .send_mail(&SendRequest {
            from: "alice@kiwi-test.invalid".to_string(),
            to: vec!["bob@kiwi-test.invalid".to_string()],
            message: b"From: alice@kiwi-test.invalid\r\nTo: bob@kiwi-test.invalid\r\nSubject: seam\r\n\r\nHello from the seam test.\r\n".to_vec(),
        })
        .await
        .expect("send completes");
    assert_eq!(outcome.accepted, vec!["bob@kiwi-test.invalid".to_string()]);
    client.quit().await.expect("quit");

    // Observe exactly like observe.rs: transport facts off the live client.
    let t = client.transport();
    assert_eq!(t.socket_security(), SocketSecurity::Plaintext);
    assert!(t.observation().is_none());
    let auth = LiveAuthObservation {
        mechanism: Some(AuthMechanism::Plain),
        succeeded: Some(true),
        attempts: 1,
        failures: 0,
    };
    let input = LiveSessionInput {
        source_tag: "fixture-send",
        protocol: Protocol::Smtp,
        server_host: "127.0.0.1",
        server_port: t.port(),
        client_port: 0,
        index: 0,
        mode: SocketMode::Plaintext,
        observation: None,
        auth: Some(&auth),
        started_at_unix_ms: STARTED_AT_UNIX_MS,
    };
    let engine = RuleEngine::new(SecurityPolicy::default());
    let first = engine.evaluate_session(&event_from_live(&input));
    let ids: Vec<&str> = first.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"KIWI-TRANSPORT-001"), "got {ids:?}");
    assert!(ids.contains(&"KIWI-AUTH-001"), "got {ids:?}");

    // Deterministic: same observation, same findings, byte-identical JSON.
    let second = engine.evaluate_session(&event_from_live(&input));
    let to_json = |findings: &Vec<kiwi_forensics::findings::Finding>| {
        serde_json::to_string(findings).expect("serializes")
    };
    assert_eq!(to_json(&first), to_json(&second));
    assert!(
        !to_json(&first).contains(PASSWORD),
        "credential never reaches findings"
    );

    server.abort();
}
