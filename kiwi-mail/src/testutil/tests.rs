use super::*;
use crate::transport::{CertVerdict, SocketSecurity, TlsSettings, Transport};
use tokio::io::{DuplexStream, duplex};
use zeroize::Zeroizing;

fn transport_for(end: DuplexStream, host: &str, port: u16, sec: SocketSecurity) -> Transport {
    Transport::from_stream(end, host, port, sec, TlsSettings::default())
}

// ---- SMTP -------------------------------------------------------------

#[tokio::test]
async fn fixture_smtp_send_ok() {
    let (c, s) = duplex(1 << 16);
    let steps = load("smtp_send_ok.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Smtp, None));

    let mut client = crate::smtp::SmtpClient::connect(
        transport_for(c, "fake.kiwi-test.invalid", 25, SocketSecurity::Plaintext),
        crate::smtp::SmtpConfig {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::smtp::SmtpAuth::Plain {
            user: "test-user".into(),
            password: Zeroizing::new("fke-wire".into()),
        })
        .await
        .unwrap();
    let out = client
            .send_mail(&crate::smtp::SendRequest {
                from: "alice@kiwi-test.invalid".into(),
                to: vec!["bob@kiwi-test.invalid".into()],
                message: b"From: alice@kiwi-test.invalid\r\nTo: bob@kiwi-test.invalid\r\nSubject: synthetic hello\r\n\r\nHello from the fixture.\r\n".to_vec(),
            })
            .await
            .unwrap();
    assert_eq!(out.accepted, vec!["bob@kiwi-test.invalid"]);
    client.quit().await.unwrap();
    server.await.unwrap().unwrap();
}

#[test]
fn empty_smtp_expectation_does_not_consume_data_terminator() {
    assert!(script::client_matches(Proto::Smtp, "", ""));
    assert!(!script::client_matches(Proto::Smtp, "", "."));
    assert!(script::client_matches(
        Proto::Smtp,
        "MAIL FROM:<a@x>",
        "MAIL FROM:<a@x> SIZE=42"
    ));
}

#[tokio::test]
async fn fixture_smtp_auth_fail() {
    let (c, s) = duplex(1 << 16);
    let steps = load("smtp_auth_fail.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Smtp, None));

    let mut client = crate::smtp::SmtpClient::connect(
        transport_for(c, "fake.kiwi-test.invalid", 25, SocketSecurity::Plaintext),
        crate::smtp::SmtpConfig {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let r = client
        .authenticate(&crate::smtp::SmtpAuth::Plain {
            user: "wrong-user".into(),
            password: Zeroizing::new("wrong-pass".into()),
        })
        .await;
    assert!(matches!(r, Err(crate::error::MailError::Auth(_))));
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn fixture_smtp_mixed_results() {
    let (c, s) = duplex(1 << 16);
    let steps = load("smtp_auth-mixed-results.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Smtp, None));

    let mut client = crate::smtp::SmtpClient::connect(
        transport_for(c, "fake.kiwi-test.invalid", 25, SocketSecurity::Plaintext),
        crate::smtp::SmtpConfig::default(),
    )
    .await
    .unwrap();
    let out = client
            .send_mail(&crate::smtp::SendRequest {
                from: "crook@evil-test.invalid".into(),
                to: vec!["bob@kiwi-test.invalid".into()],
                message: b"From: boss@kiwi-test.invalid\r\nTo: bob@kiwi-test.invalid\r\nSubject: synthetic spoof\r\n\r\nPlease ignore this synthetic phish.\r\n".to_vec(),
            })
            .await
            .unwrap();
    assert_eq!(out.accepted.len(), 1);
    client.quit().await.unwrap();
    server.await.unwrap().unwrap();
}

/// STARTTLS-stripped transcript: client on a StartTls socket MUST refuse.
#[tokio::test]
async fn fixture_smtp_stripped_fails_closed() {
    let (c, s) = duplex(1 << 16);
    let steps = load("smtp_stripped.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Smtp, None));

    let r = crate::smtp::SmtpClient::connect(
        transport_for(c, "fake.kiwi-test.invalid", 587, SocketSecurity::StartTls),
        crate::smtp::SmtpConfig::default(), // require_starttls = true
    )
    .await;
    assert!(matches!(r, Err(crate::error::MailError::Protocol { .. })));
    server.await.unwrap().unwrap();
}

// ---- POP3 -------------------------------------------------------------

#[tokio::test]
async fn fixture_pop3_retr() {
    let (c, s) = duplex(1 << 16);
    let steps = load("pop3_retr.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Pop3, None));

    let mut client = crate::pop3::Pop3Client::connect(
        transport_for(c, "fake.kiwi-test.invalid", 110, SocketSecurity::Plaintext),
        crate::pop3::Pop3Config {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::pop3::Pop3Auth::UserPass {
            user: "test-user@kiwi-test.invalid".into(),
            password: Zeroizing::new("dummy".into()),
        })
        .await
        .unwrap();
    let list = client.list().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].octets, 320);
    let uidls = client.uidl().await.unwrap();
    assert_eq!(uidls, vec![(1, "FAKEUID0001".to_string())]);
    let msg = client.retr(1).await.unwrap();
    assert!(String::from_utf8_lossy(&msg).contains("Subject: synthetic hello"));
    client.quit().await.unwrap();
    server.await.unwrap().unwrap();
}

/// Full STLS upgrade across the transcript's TLS boundary, real rustls.
#[tokio::test]
async fn fixture_pop3_stls() {
    let (acceptor, cert_der) = tls_acceptor(&["fake.kiwi-test.invalid"]);
    let (c, s) = duplex(1 << 16);
    let steps = load("pop3_stls.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Pop3, Some(acceptor)));

    let client = crate::pop3::Pop3Client::connect(
        Transport::from_stream(
            c,
            "fake.kiwi-test.invalid",
            110,
            SocketSecurity::StartTls,
            TlsSettings {
                accept_invalid_certs: false,
                extra_roots: vec![cert_der],
            },
        ),
        crate::pop3::Pop3Config::default(),
    )
    .await
    .unwrap();
    let obs = client.transport().observation().expect("tls observation");
    assert!(obs.upgraded_via_starttls);
    assert_eq!(obs.cert_verdict, Some(CertVerdict::Valid));
    // post-STLS CAPA no longer advertises STLS
    assert!(client.has_capa("APOP"));
    server.await.unwrap().unwrap();
}

// ---- IMAP -------------------------------------------------------------

#[tokio::test]
async fn fixture_imap_select_fetch() {
    let (c, s) = duplex(1 << 16);
    let steps = load("imap_select_fetch.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Imap, None));

    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "fake.kiwi-test.invalid", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig {
            allow_plaintext_auth: true,
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::imap::ImapAuth::Login {
            user: "test-user@kiwi-test.invalid".into(),
            password: Zeroizing::new("dummy".into()),
        })
        .await
        .unwrap();
    let sel = client.select("INBOX", false).await.unwrap();
    assert_eq!(sel.exists, 2);
    assert_eq!(sel.uid_validity, Some(12345));
    let items = client
        .uid_fetch("1:*", &["UID", "FLAGS", "ENVELOPE"])
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    let env = items[0].envelope.as_ref().unwrap();
    assert_eq!(items[0].uid, Some(101));
    assert_eq!(env.subject.as_deref(), Some("synthetic"));
    assert_eq!(env.from[0].email, "alice@kiwi-test.invalid");
    client.logout().await.unwrap();
    server.await.unwrap().unwrap();
}

/// Hostile fixture: `{999999999}` literal must be rejected by the bound
/// BEFORE any allocation or read — and fast (no 1GB wait).
#[tokio::test]
async fn fixture_imap_hostile_literal_rejected() {
    let (c, s) = duplex(1 << 16);
    let steps = load("imap_hostile_fetch.txt");
    let server = tokio::spawn(serve(s, leak(steps), Proto::Imap, None));

    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "fake.kiwi-test.invalid", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig {
            allow_plaintext_auth: true,
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::imap::ImapAuth::Login {
            user: "test-user@kiwi-test.invalid".into(),
            password: Zeroizing::new("dummy".into()),
        })
        .await
        .unwrap();
    client.select("INBOX", false).await.unwrap();
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.uid_fetch("1", &["BODY[]"]),
    )
    .await
    .expect("hostile literal must not stall")
    .unwrap_err();
    assert!(matches!(r, crate::error::MailError::Protocol { .. }));
    server.await.unwrap().unwrap();
}

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

// ---- Real-server interop (mailpit) ------------------------------------
//
// Requires the compose stack: `KIWI_MAILPIT=1 cargo test -p kiwi-mail`.
// Skipped by default — keeps `cargo test` hermetic.

fn mailpit() -> bool {
    std::env::var("KIWI_MAILPIT").is_ok()
}

/// SMTP :1025 (plaintext, mailpit accepts any AUTH) → POP3 :1100
/// (demo/demo) — full send→receive round-trip against a real server.
#[tokio::test]
async fn mailpit_smtp_pop3_roundtrip() {
    if !mailpit() {
        eprintln!("skipped: set KIWI_MAILPIT=1 to run against mailpit");
        return;
    }
    let body_text = "kiwi interop round-trip marker";
    let message = format!(
        "From: interop@kiwi-test.invalid\r\nTo: demo@localhost\r\nSubject: kiwi interop\r\n\r\n{body_text}\r\n"
    );

    // --- SMTP leg ---
    let t = Transport::connect(
        "127.0.0.1",
        1025,
        SocketSecurity::Plaintext,
        TlsSettings::default(),
    )
    .await
    .expect("smtp connect");
    let mut smtp = crate::smtp::SmtpClient::connect(
        t,
        crate::smtp::SmtpConfig {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .expect("smtp handshake");
    // mailpit accepts AUTH PLAIN with any creds (or none at all)
    let _ = smtp
        .authenticate(&crate::smtp::SmtpAuth::Plain {
            user: "demo".into(),
            password: Zeroizing::new("demo".into()),
        })
        .await;
    let out = smtp
        .send_mail(&crate::smtp::SendRequest {
            from: "interop@kiwi-test.invalid".into(),
            to: vec!["demo@localhost".into()],
            message: message.clone().into_bytes(),
        })
        .await
        .expect("send");
    assert_eq!(out.accepted, vec!["demo@localhost".to_string()]);
    assert!(out.rejected.is_empty());
    smtp.quit().await.ok();

    // --- POP3 leg ---
    let t = Transport::connect(
        "127.0.0.1",
        1100,
        SocketSecurity::Plaintext,
        TlsSettings::default(),
    )
    .await
    .expect("pop3 connect");
    let mut pop3 = crate::pop3::Pop3Client::connect(
        t,
        crate::pop3::Pop3Config {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .expect("pop3 handshake");
    pop3.authenticate(&crate::pop3::Pop3Auth::UserPass {
        user: "demo".into(),
        password: Zeroizing::new("demo".into()),
    })
    .await
    .expect("pop3 auth");

    // poll LIST until our message lands (mailpit delivery is fast but async)
    let mut found = None;
    for _ in 0..20 {
        let uidls = pop3.uidl().await.expect("uidl");
        if let Some(last) = uidls.last() {
            let msg = pop3.retr(last.0).await.expect("retr");
            if String::from_utf8_lossy(&msg).contains(body_text) {
                found = Some(msg);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let msg = found.expect("message never arrived over POP3");
    let text = String::from_utf8_lossy(&msg);
    assert!(text.contains("Subject: kiwi interop"));
    pop3.quit().await.ok();
}

/// GreenMail IMAP :1143 (compose `greenmail` service, auth disabled):
/// LOGIN → SELECT INBOX → APPEND (LITERAL+ path) → UID SEARCH →
/// UID FETCH ENVELOPE round-trip, then delete+expunge cleanup.
#[tokio::test]
async fn greenmail_imap_append_fetch_roundtrip() {
    if !mailpit() {
        eprintln!("skipped: set KIWI_MAILPIT=1 to run against greenmail");
        return;
    }
    let t = Transport::connect(
        "127.0.0.1",
        1143,
        SocketSecurity::Plaintext,
        TlsSettings::default(),
    )
    .await
    .expect("imap connect");
    let mut imap = crate::imap::ImapClient::connect_with(
        t,
        crate::imap::ImapConfig {
            allow_plaintext_auth: true,
        },
    )
    .await
    .expect("imap handshake");
    imap.authenticate(&crate::imap::ImapAuth::Login {
        user: "demo".into(),
        password: Zeroizing::new("demo".into()),
    })
    .await
    .expect("imap login");

    let sel = imap.select("INBOX", false).await.expect("select");
    assert!(sel.uid_validity.is_some());

    let marker = format!("kiwi imap interop {}", std::process::id());
    let message = format!(
        "From: interop@kiwi-test.invalid\r\nTo: demo@localhost\r\nSubject: {marker}\r\n\r\nbody\r\n"
    );
    imap.append("INBOX", &["\\Seen"], message.as_bytes())
        .await
        .expect("append");

    // Poll until the appended UID appears (GreenMail delivery is fast).
    let mut found_uid = None;
    for _ in 0..20 {
        let uids = imap.uid_search("ALL").await.expect("search");
        if let Some(&last) = uids.iter().max() {
            let items = imap
                .uid_fetch(&last.to_string(), &["UID", "ENVELOPE"])
                .await
                .expect("fetch");
            if let Some(item) = items.first()
                && item.envelope.as_ref().and_then(|e| e.subject.as_deref())
                    == Some(marker.as_str())
            {
                found_uid = Some(last);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let uid = found_uid.expect("appended message never appeared");

    // Cleanup so reruns stay deterministic.
    imap.uid_store(&uid.to_string(), "+FLAGS.SILENT", &["\\Deleted"])
        .await
        .expect("flag deleted");
    imap.expunge().await.expect("expunge");
    imap.logout().await.ok();
}

// ---- Cross-module engine tests (T-105/T-106 via scripted servers) ------

/// `sync_folder` full lifecycle: initial import → flag refresh + local
/// expunge → UIDVALIDITY reset wipe+repopulate.
#[tokio::test]
async fn sync_folder_end_to_end() {
    const ENV: &str = "(\"01-Jan-2024 00:00:00 +0000\" \"s\" ((\"A\" NIL \"a\" \"x\")) NIL NIL NIL NIL NIL NIL \"m\")";
    let (c, s) = duplex(1 << 16);
    let script = format!(
        "S: * OK ready\n\
             C: x LOGIN u p\n\
             S: a OK LOGIN completed\n\
             C: x SELECT INBOX\n\
             S: * 2 EXISTS\n\
             S: * 0 RECENT\n\
             S: * OK [UIDVALIDITY 999] ok\n\
             S: * OK [UIDNEXT 3] ok\n\
             S: a OK [READ-WRITE] SELECT completed\n\
             C: x UID SEARCH ALL\n\
             S: * SEARCH 1 2\n\
             S: a OK SEARCH completed\n\
             C: x UID FETCH 1,2 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE BODYSTRUCTURE)\n\
             S: * 1 FETCH (UID 1 FLAGS () ENVELOPE {ENV} RFC822.SIZE 50 INTERNALDATE \"01-Jan-2024 00:00:00 +0000\")\n\
             S: * 2 FETCH (UID 2 FLAGS (\\Seen) ENVELOPE {ENV} RFC822.SIZE 60 INTERNALDATE \"01-Jan-2024 00:00:00 +0000\")\n\
             S: a OK FETCH completed\n\
             C: x SELECT INBOX\n\
             S: * 1 EXISTS\n\
             S: * OK [UIDVALIDITY 999] ok\n\
             S: * OK [UIDNEXT 3] ok\n\
             S: a OK [READ-WRITE] SELECT completed\n\
             C: x UID SEARCH ALL\n\
             S: * SEARCH 1\n\
             S: a OK SEARCH completed\n\
             C: x UID FETCH 1 (UID FLAGS)\n\
             S: * 1 FETCH (UID 1 FLAGS (\\Deleted))\n\
             S: a OK FETCH completed\n\
             C: x SELECT INBOX\n\
             S: * 1 EXISTS\n\
             S: * OK [UIDVALIDITY 1000] ok\n\
             S: * OK [UIDNEXT 10] ok\n\
             S: a OK [READ-WRITE] SELECT completed\n\
             C: x UID SEARCH ALL\n\
             S: * SEARCH 9\n\
             S: a OK SEARCH completed\n\
             C: x UID FETCH 9 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE BODYSTRUCTURE)\n\
             S: * 9 FETCH (UID 9 FLAGS () ENVELOPE {ENV} RFC822.SIZE 40 INTERNALDATE \"01-Jan-2024 00:00:00 +0000\")\n\
             S: a OK FETCH completed\n"
    );
    let server = spawn_script(s, Proto::Imap, &script, None);

    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "h", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig {
            allow_plaintext_auth: true,
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::imap::ImapAuth::Login {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        })
        .await
        .unwrap();

    let store = crate::store::MailStore::open_memory().unwrap();
    store
        .conn_for_test()
        .execute(
            "INSERT INTO accounts (account_id, display_name, email, config_json) \
                 VALUES ('a1','d','e','{}')",
            [],
        )
        .unwrap();

    // Pass 1: two new messages.
    let r1 = crate::sync::sync_folder(&mut client, &store, "a1", "INBOX", 1000)
        .await
        .unwrap();
    assert_eq!(r1.new_messages, 2);
    assert_eq!(r1.remote_exists, 2);

    // Pass 2: uid 2 gone remotely, uid 1 flags changed.
    let r2 = crate::sync::sync_folder(&mut client, &store, "a1", "INBOX", 1001)
        .await
        .unwrap();
    assert_eq!(r2.new_messages, 0);
    assert_eq!(r2.expunged, 1);
    assert_eq!(r2.flag_updates, 1);

    // Pass 3: UIDVALIDITY changed → wipe + repopulate with uid 9.
    let r3 = crate::sync::sync_folder(&mut client, &store, "a1", "INBOX", 1002)
        .await
        .unwrap();
    assert!(r3.uid_validity_reset);
    assert_eq!(r3.new_messages, 1);
    let folder_id = store.ensure_folder("a1", "INBOX").unwrap();
    assert_eq!(store.folder_uids(folder_id).unwrap(), vec![9]);

    server.await.unwrap().unwrap();
}

/// `sync_pop3`: UIDL diff → RETR unseen → second pass dedups via
/// pop3_seen (no RETR re-fetch).
#[tokio::test]
async fn sync_pop3_end_to_end() {
    let (c, s) = duplex(1 << 16);
    let server = spawn_script(
        s,
        Proto::Pop3,
        "S: +OK ready\n\
             C: USER demo\n\
             S: +OK send PASS\n\
             C: PASS demo\n\
             S: +OK ok\n\
             C: UIDL\n\
             S: +OK\n\
             S: 1 UIDAAA\n\
             S: .\n\
             C: RETR 1\n\
             S: +OK 120 octets\n\
             S: From: a@x\n\
             S: To: b@x\n\
             S: Subject: pop3 sync msg\n\
             S: \n\
             S: body line\n\
             S: .\n\
             C: UIDL\n\
             S: +OK\n\
             S: 1 UIDAAA\n\
             S: .\n",
        None,
    );

    let mut client = crate::pop3::Pop3Client::connect(
        transport_for(c, "h", 110, SocketSecurity::Plaintext),
        crate::pop3::Pop3Config {
            allow_plaintext_auth: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    client
        .authenticate(&crate::pop3::Pop3Auth::UserPass {
            user: "demo".into(),
            password: Zeroizing::new("demo".into()),
        })
        .await
        .unwrap();

    let store = crate::store::MailStore::open_memory().unwrap();
    store
        .conn_for_test()
        .execute(
            "INSERT INTO accounts (account_id, display_name, email, config_json) \
                 VALUES ('a1','d','e','{}')",
            [],
        )
        .unwrap();

    let r1 = crate::sync::sync_pop3(&mut client, &store, "a1", "INBOX", false, 1000)
        .await
        .unwrap();
    assert_eq!(r1.downloaded, 1);
    assert_eq!(r1.remote_drops, 1);
    let r2 = crate::sync::sync_pop3(&mut client, &store, "a1", "INBOX", false, 1001)
        .await
        .unwrap();
    assert_eq!(r2.downloaded, 0, "seen UIDL must not re-download");
    server.await.unwrap().unwrap();
}

/// APPEND over LITERAL+ (non-sync `{n+}` path — no `+` wait).
#[tokio::test]
async fn imap_append_literal_plus() {
    let (c, s) = duplex(1 << 16);
    let server = spawn_script(
        s,
        Proto::Imap,
        "S: * OK ready\n\
             C: x APPEND \"Sent\" (\\Seen) {8+}\n\
             C: hi there\n\
             S: a OK APPEND completed\n",
        None,
    );
    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "h", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig::default(),
    )
    .await
    .unwrap();
    client
        .append("Sent", &["\\Seen"], b"hi there")
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

/// APPEND sync-literal path (`{n}`, server without LITERAL+): the client
/// must wait for `+`, send exactly the literal + CRLF, and nothing else —
/// a stray extra CRLF would surface as an empty command line and make the
/// trailing LOGOUT expectation diverge.
#[tokio::test]
async fn imap_append_sync_literal() {
    let (c, s) = duplex(1 << 16);
    let server = spawn_script(
        s,
        Proto::Imap,
        "S: * OK ready\n\
             C: x CAPABILITY\n\
             S: * CAPABILITY IMAP4rev1\n\
             S: a OK done\n\
             C: x APPEND \"Sent\" (\\Seen) {8}\n\
             S: + go ahead\n\
             C: hi there\n\
             S: a OK APPEND completed\n\
             C: x LOGOUT\n\
             S: a OK bye\n",
        None,
    );
    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "h", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig::default(),
    )
    .await
    .unwrap();
    client
        .append("Sent", &["\\Seen"], b"hi there")
        .await
        .unwrap();
    client.logout().await.unwrap();
    server.await.unwrap().unwrap();
}

/// IDLE: continuation → untagged events collected → DONE → tagged OK.
#[tokio::test]
async fn imap_idle_collects_events() {
    let (c, s) = duplex(1 << 16);
    let server = spawn_script(
        s,
        Proto::Imap,
        "S: * OK ready\n\
             C: x IDLE\n\
             S: + idling\n\
             S: * 5 EXISTS\n\
             S: * 1 RECENT\n\
             C: DONE\n\
             S: a OK IDLE terminated\n",
        None,
    );
    let mut client = crate::imap::ImapClient::connect_with(
        transport_for(c, "h", 143, SocketSecurity::Plaintext),
        crate::imap::ImapConfig::default(),
    )
    .await
    .unwrap();
    let events = client
        .idle_collect(std::time::Duration::from_millis(150))
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|e| e.starts_with(b"5 EXISTS")));
    server.await.unwrap().unwrap();
}
