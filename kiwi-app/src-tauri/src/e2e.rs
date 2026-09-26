//! T-257 — account-add → first-sync E2E verification (offline, scripted).
//!
//! Proves the wizard path end-to-end against the same fixture seams the
//! protocol crates use: `MockNet` replays the autoconfig HTTPS document,
//! a `tokio` loopback listener replays a scripted IMAP transcript
//! (`kiwi_mail::testutil` — the transcript format Agent 6's GreenMail/
//! Mailpit captures use, generalized to real streams for exactly this).
//!
//! The transport path is real: `sync_account_impl` → `connect_imap` →
//! `Transport::connect(127.0.0.1, port, StartTls)` → genuine TCP + TLS
//! handshake (self-signed acceptor + the account's `accept_invalid_certs`
//! consent flag — the same flag the wizard's "accept once" sets) → LOGIN
//! → LIST → SELECT → UID SEARCH/FETCH → envelopes land in the real
//! `MailStore` → `list_folders`/`list_messages` read them back.
//!
//! Failure branches are first-class: unreachable host must surface a
//! connect error (not panic/hang), a server `NO` on LOGIN must surface
//! as `server-reject`, and a domain with no fixtures must fall through
//! discovery to a flagged pattern guess — never crash, never fabricate.

use std::sync::Arc;

use kiwi_autoconfig::net::MockNet;
use kiwi_mail::testutil::{self, Proto, TlsAcceptor};
use tokio::net::TcpListener;

use crate::commands::accounts::{add_account_impl, list_accounts_impl};
use crate::commands::autoconfig::discover_account_impl;
use crate::commands::mail::{
    get_message_impl, list_folders_impl, list_messages_impl, message_source_impl, sync_account_impl,
};
use crate::commands::message::attachment::download_attachment_impl;
use crate::commands::send::{Delivered, cancel_impl, deliver, drop_outbox, send_impl};
use crate::state::{AppState, now_unix};
use crate::types::{AddAccountInput, AuthInput, ComposeInput, SendOptions, ServerInput};

fn test_state(tag: &str, net: MockNet) -> Arc<AppState> {
    let dir = std::env::temp_dir().join(format!(
        "kiwi-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    Arc::new(
        AppState::open_test_with_net(dir, crate::state::rejecting_transport(), Arc::new(net))
            .unwrap(),
    )
}

/// Bind a loopback listener and spawn the transcript server on accept.
/// Returns the port to point the account at plus the server task handle
/// (join it after the sync — `Err` means a wire divergence).
async fn serve_imap(
    script: &str,
    tls: Option<TlsAcceptor>,
) -> (u16, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let steps = testutil::parse(script);
    let h = tokio::spawn(async move {
        let (stream, _) =
            tokio::time::timeout(testutil::TRANSCRIPT_STEP_TIMEOUT, listener.accept())
                .await
                .map_err(|_| "timed out waiting for IMAP connection".to_string())?
                .map_err(|e| e.to_string())?;
        testutil::serve(stream, &steps, Proto::Imap, tls).await
    });
    (port, h)
}

/// Autoconfig document for `e2e.test` pointing at the loopback listener.
fn autoconfig_xml(port: u16) -> String {
    format!(
        r#"<clientConfig version="1.1"><emailProvider id="e2e.test">
  <domain>e2e.test</domain>
  <displayName>E2E Fixture Provider</displayName>
  <incomingServer type="imap">
    <hostname>127.0.0.1</hostname><port>{port}</port>
    <socketType>STARTTLS</socketType>
    <username>%EMAILADDRESS%</username>
    <authentication>password-cleartext</authentication>
  </incomingServer>
  <outgoingServer type="smtp">
    <hostname>127.0.0.1</hostname><port>2525</port>
    <socketType>STARTTLS</socketType>
    <username>%EMAILADDRESS%</username>
    <authentication>password-cleartext</authentication>
  </outgoingServer>
</emailProvider></clientConfig>"#
    )
}

/// Discovery net answering only the autoconfig-host fetch for e2e.test.
fn fixture_net(port: u16) -> MockNet {
    MockNet::new().with_https(
        "https://autoconfig.e2e.test/mail/config-v1.1.xml",
        &autoconfig_xml(port),
    )
}

/// Build the `kiwi_add_account` input exactly as the wizard does from a
/// discovery suggestion (password auth, STARTTLS, self-signed consent).
fn add_input_from(s: &crate::types::SuggestionView, accept_invalid: bool) -> AddAccountInput {
    AddAccountInput {
        display_name: "E2E User".into(),
        email: s.email.clone(),
        incoming_protocol: s.incoming.kind.clone(),
        incoming: ServerInput {
            host: s.incoming.host.clone(),
            port: s.incoming.port,
            security: s.incoming.security.clone(),
        },
        outgoing: ServerInput {
            host: s.outgoing.host.clone(),
            port: s.outgoing.port,
            security: s.outgoing.security.clone(),
        },
        username: Some(s.incoming.username.clone()),
        outgoing_username: Some(s.outgoing.username.clone()),
        incoming_auth: Some(AuthInput {
            kind: s.incoming.auth.clone(),
            secret: Some("s3cret".into()),
            oauth2_ticket: None,
        }),
        outgoing_auth: Some(AuthInput {
            kind: s.outgoing.auth.clone(),
            secret: Some("s3cret".into()),
            oauth2_ticket: None,
        }),
        accept_invalid_certs: accept_invalid,
    }
}

/// Happy-path transcript: STARTTLS upgrade, LOGIN, LIST one INBOX with
/// two envelopes, flag-bearing metadata fetch, threading-header fetch,
/// clean LOGOUT. Post-STLS CAPABILITY is answered by the harness's
/// generic probe reply — not scripted.
const SCRIPT_OK: &str = r#"
S: * OK e2e.test IMAP4rev2 TestServer ready
C: a1 CAPABILITY
S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS IDLE LITERAL+ SASL-IR
S: a1 OK CAPABILITY completed
C: a2 STARTTLS
S: a2 OK Begin TLS negotiation now
# TLS handshake
C: a3 LOGIN u@e2e.test REDACTED-DUMMY
S: a3 OK LOGIN completed
C: a4 LIST "" "*"
S: * LIST (\HasNoChildren) "/" "INBOX"
S: a4 OK LIST completed
C: a5 SELECT INBOX
S: * FLAGS (\Seen \Answered \Flagged \Deleted \Draft)
S: * 2 EXISTS
S: * 1 RECENT
S: * OK [UIDVALIDITY 4242] UIDs valid
S: * OK [UIDNEXT 103] Predicted next UID
S: a5 OK [READ-WRITE] SELECT completed
C: a6 UID SEARCH ALL
S: * SEARCH 101 102
S: a6 OK SEARCH completed
C: a7 UID FETCH 101,102 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE BODYSTRUCTURE)
S: * 1 FETCH (UID 101 FLAGS (\Seen) ENVELOPE ("Wed, 01 Jan 2025 12:00:00 +0000" "Hello from E2E" (("Alice" NIL "alice" "e2e.test")) (("Alice" NIL "alice" "e2e.test")) (("Alice" NIL "alice" "e2e.test")) (("User" NIL "u" "e2e.test")) NIL NIL NIL "<m1@e2e.test>") RFC822.SIZE 4321 INTERNALDATE "01-Jan-2025 12:00:00 +0000")
S: * 2 FETCH (UID 102 FLAGS () ENVELOPE ("Wed, 01 Jan 2025 13:00:00 +0000" "Second message" (("Bob" NIL "bob" "e2e.test")) (("Bob" NIL "bob" "e2e.test")) (("Bob" NIL "bob" "e2e.test")) (("User" NIL "u" "e2e.test")) NIL NIL NIL "<m2@e2e.test>") RFC822.SIZE 555 INTERNALDATE "02-Jan-2025 13:00:00 +0000")
S: a7 OK FETCH completed
C: a8 UID FETCH 101,102 (UID BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)])
S: * 1 FETCH (UID 101)
S: * 2 FETCH (UID 102)
S: a8 OK FETCH completed
C: a9 LOGOUT
S: * BYE TestServer logging out
S: a9 OK LOGOUT completed
"#;

/// Same greeting/upgrade but the server refuses LOGIN — the auth-failure
/// branch (server `NO` → `server-reject`, not a crash).
const SCRIPT_AUTH_FAIL: &str = r#"
S: * OK e2e.test IMAP4rev2 TestServer ready
C: a1 CAPABILITY
S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS IDLE LITERAL+
S: a1 OK CAPABILITY completed
C: a2 STARTTLS
S: a2 OK Begin TLS negotiation now
# TLS handshake
C: a3 LOGIN u@e2e.test REDACTED-DUMMY
S: a3 NO [AUTHENTICATIONFAILED] Credentials rejected
"#;

#[tokio::test(flavor = "current_thread")]
async fn e2e_discover_add_sync_list_green_path() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (port, server) = serve_imap(SCRIPT_OK, Some(acceptor)).await;
    let state = test_state("green", fixture_net(port));

    // ── Stage 1: discover ──────────────────────────────────────────
    let disc = discover_account_impl(&state, "u@e2e.test")
        .await
        .expect("discover e2e.test");
    assert_eq!(disc.domain, "e2e.test");
    assert_eq!(disc.source, "autoconfig_host");
    assert!(!disc.needs_manual_review);
    let s = &disc.suggestion;
    assert_eq!(s.incoming.kind, "imap");
    assert_eq!(s.incoming.host, "127.0.0.1");
    assert_eq!(s.incoming.port, port);
    assert_eq!(s.incoming.security, "starttls");
    assert_eq!(s.incoming.auth, "password");
    assert_eq!(s.incoming.username, "u@e2e.test");
    assert!(
        disc.attempts
            .iter()
            .any(|a| a.source == "autoconfig_host" && a.outcome == "hit"),
        "autoconfig_host stage must record the hit: {:?}",
        disc.attempts
    );

    // ── Stage 2: add account (wizard → add_account) ────────────────
    let view = add_account_impl(&state, add_input_from(s, true))
        .await
        .expect("add account");
    let listed = list_accounts_impl(&state).await.expect("list accounts");
    assert!(
        listed
            .iter()
            .any(|a| a.id == view.id && a.email == "u@e2e.test"),
        "account must persist: {listed:?}"
    );

    // ── Stage 3: sync (real TCP + TLS + scripted transcript) ────────
    let reports = sync_account_impl(state.clone(), view.id.clone(), None)
        .await
        .expect("sync account");
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.protocol, "imap");
    assert_eq!(r.folder, "INBOX");
    assert_eq!(r.new_messages, 2);
    assert_eq!(r.remote_exists, 2);
    assert!(!r.uid_validity_reset);

    // ── Stage 4: folders + messages readable back ──────────────────
    let folders = list_folders_impl(&state, &view.id)
        .await
        .expect("list folders");
    let inbox = folders
        .iter()
        .find(|f| f.name == "INBOX")
        .expect("INBOX registered");
    let msgs = list_messages_impl(&state, view.id.clone(), inbox.id, None)
        .await
        .expect("list messages");
    assert_eq!(msgs.len(), 2);
    // Newest-first ordering.
    assert_eq!(msgs[0].uid, 102);
    assert_eq!(msgs[0].subject.as_deref(), Some("Second message"));
    assert_eq!(msgs[0].from.as_deref(), Some("bob@e2e.test"));
    assert!(msgs[0].unread, "no \\Seen flag on 102 → unread");
    assert_eq!(msgs[1].uid, 101);
    assert_eq!(msgs[1].subject.as_deref(), Some("Hello from E2E"));
    assert!(!msgs[1].unread, "\\Seen flag on 101 → read");
    assert_eq!(msgs[1].message_id.as_deref(), Some("<m1@e2e.test>"));

    // The whole transcript must have replayed — a wire divergence would
    // surface here, not as a protocol error the client swallowed.
    server.await.unwrap().expect("transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_unreachable_host_surfaces_connect_error() {
    // A port that was bound then dropped: connect gets refused fast.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let state = test_state("dead", fixture_net(port));

    // Discovery still succeeds (the document is reachable) — the
    // unreachable *server* must fail at sync, cleanly.
    let disc = discover_account_impl(&state, "u@e2e.test").await.unwrap();
    let view = add_account_impl(&state, add_input_from(&disc.suggestion, true))
        .await
        .unwrap();
    let err = sync_account_impl(state, view.id, None)
        .await
        .expect_err("dead port must fail");
    assert_eq!(err.code, "connect-failed");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_auth_rejection_surfaces_server_reject() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (port, server) = serve_imap(SCRIPT_AUTH_FAIL, Some(acceptor)).await;
    let state = test_state("auth", fixture_net(port));

    let disc = discover_account_impl(&state, "u@e2e.test").await.unwrap();
    let view = add_account_impl(&state, add_input_from(&disc.suggestion, true))
        .await
        .unwrap();
    let err = sync_account_impl(state, view.id, None)
        .await
        .expect_err("auth rejection must fail");
    assert_eq!(err.code, "server-reject");
    assert!(
        err.message.contains("AUTHENTICATIONFAILED") || err.message.contains("rejected"),
        "server reply must surface: {}",
        err.message
    );
    server.await.unwrap().expect("transcript replayed fully");
}

// ---------------------------------------------------------------------------
// T-339 — lazy attachment fetch: BODYSTRUCTURE persists part descriptors at
// sync without pulling payloads; the reader fetch is a skeleton (HEADER +
// per-leaf .MIME + eager text leaf); a save issues `BODY.PEEK[<section>]` on
// a fresh connection, decodes, and marks the row fetched; view-source forces
// the complete `BODY[]` and clears the deferred marker.
// ---------------------------------------------------------------------------

/// Serve `scripts` as sequential connections on one loopback listener —
/// every client command opens a fresh session, so a multi-command scenario
/// needs one script per connection.
async fn serve_imap_seq(
    scripts: Vec<String>,
    tls: Option<TlsAcceptor>,
) -> (u16, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let parsed: Vec<Vec<testutil::Step>> = scripts.iter().map(|s| testutil::parse(s)).collect();
    let h = tokio::spawn(async move {
        for steps in &parsed {
            let (stream, _) =
                tokio::time::timeout(testutil::TRANSCRIPT_STEP_TIMEOUT, listener.accept())
                    .await
                    .map_err(|_| "timed out waiting for IMAP connection".to_string())?
                    .map_err(|e| e.to_string())?;
            testutil::serve(stream, steps, Proto::Imap, tls.clone()).await?;
        }
        Ok(())
    });
    (port, h)
}

/// The handshake+select prelude every fresh connection replays.
const LAZY_PRELUDE: &str = "S: * OK e2e.test IMAP4rev2 TestServer ready\n\
     C: a1 CAPABILITY\n\
     S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS IDLE LITERAL+\n\
     S: a1 OK CAPABILITY completed\n\
     C: a2 STARTTLS\n\
     S: a2 OK Begin TLS negotiation now\n\
     # TLS handshake\n\
     C: a3 LOGIN u@e2e.test REDACTED-DUMMY\n\
     S: a3 OK LOGIN completed\n\
     C: a4 SELECT INBOX\n\
     S: * 1 EXISTS\n\
     S: * OK [UIDVALIDITY 4242] UIDs valid\n\
     S: a4 OK [READ-WRITE] SELECT completed\n";

const LAZY_LOGOUT: &str = "C: a7 LOGOUT\n\
     S: * BYE TestServer logging out\n\
     S: a7 OK LOGOUT completed\n";

#[tokio::test(flavor = "current_thread")]
async fn e2e_lazy_attachment_body_peek() {
    // multipart/mixed: eager text/plain leaf (section 1) + deferred
    // application/pdf attachment (section 2, base64, 16 wire octets).
    const BS: &str = "((\"text\" \"plain\" NIL NIL NIL \"7bit\" 10 1)\
        (\"application\" \"pdf\" (\"name\" \"note.pdf\") NIL NIL \"base64\" 16 NIL\
        (\"attachment\" (\"filename\" \"note.pdf\")) NIL) \"mixed\"\
        (\"boundary\" \"outer\"))";
    let env = "(\"Wed, 01 Jan 2025 12:00:00 +0000\" \"Lazy attach\"\
        ((\"Alice\" NIL \"alice\" \"e2e.test\"))\
        ((\"Alice\" NIL \"alice\" \"e2e.test\"))\
        ((\"Alice\" NIL \"alice\" \"e2e.test\"))\
        ((\"User\" NIL \"u\" \"e2e.test\")) NIL NIL NIL \"<lazy@e2e.test>\")";

    // Conn 1: sync — metadata FETCH carries BODYSTRUCTURE; the only body
    // fetch allowed is the threading-headers probe. No BODY[] anywhere.
    let c1 = format!(
        "S: * OK e2e.test IMAP4rev2 TestServer ready\n\
         C: a1 CAPABILITY\n\
         S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS IDLE LITERAL+\n\
         S: a1 OK CAPABILITY completed\n\
         C: a2 STARTTLS\n\
         S: a2 OK Begin TLS negotiation now\n\
         # TLS handshake\n\
         C: a3 LOGIN u@e2e.test REDACTED-DUMMY\n\
         S: a3 OK LOGIN completed\n\
         C: a4 LIST \"\" \"*\"\n\
         S: * LIST (\\HasNoChildren) \"/\" \"INBOX\"\n\
         S: a4 OK LIST completed\n\
         C: a5 SELECT INBOX\n\
         S: * FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\n\
         S: * 1 EXISTS\n\
         S: * 1 RECENT\n\
         S: * OK [UIDVALIDITY 4242] UIDs valid\n\
         S: * OK [UIDNEXT 302] Predicted next UID\n\
         S: a5 OK [READ-WRITE] SELECT completed\n\
         C: a6 UID SEARCH ALL\n\
         S: * SEARCH 301\n\
         S: a6 OK SEARCH completed\n\
         C: a7 UID FETCH 301 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE BODYSTRUCTURE)\n\
         S: * 1 FETCH (UID 301 FLAGS () ENVELOPE {env} RFC822.SIZE 200 INTERNALDATE \"01-Jan-2025 12:00:00 +0000\" BODYSTRUCTURE {BS})\n\
         S: a7 OK FETCH completed\n\
         C: a8 UID FETCH 301 (UID BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)])\n\
         S: * 1 FETCH (UID 301)\n\
         S: a8 OK FETCH completed\n\
         C: a9 LOGOUT\n\
         S: * BYE TestServer logging out\n\
         S: a9 OK LOGOUT completed\n"
    );

    // Conn 2: get_message → fresh BODYSTRUCTURE + skeleton fetch (HEADER +
    // per-leaf .MIME + the text leaf) — the attachment body is NOT fetched.
    // Literal payloads ride the following S: steps (each step's bytes are
    // the literal, then the response continuation on the same line).
    let c2 = format!(
        "{LAZY_PRELUDE}\
         C: a5 UID FETCH 301 (UID BODYSTRUCTURE)\n\
         S: * 1 FETCH (UID 301 BODYSTRUCTURE {BS})\n\
         S: a5 OK FETCH completed\n\
         C: a6 UID FETCH 301 (UID BODY.PEEK[HEADER] BODY.PEEK[1.MIME] BODY.PEEK[1] BODY.PEEK[2.MIME])\n\
         S: * 1 FETCH (UID 301 BODY[HEADER] {{47}}\n\
         S: Content-Type: multipart/mixed; boundary=\"outer\" BODY[1.MIME] {{24}}\n\
         S: Content-Type: text/plain BODY[1] {{10}}\n\
         S: hello body BODY[2.MIME] {{29}}\n\
         S: Content-Type: application/pdf)\n\
         S: a6 OK FETCH completed\n\
         {LAZY_LOGOUT}"
    );

    // Conn 3: download → re-verify BODYSTRUCTURE then pull only section 2.
    let c3 = format!(
        "{LAZY_PRELUDE}\
         C: a5 UID FETCH 301 (UID BODYSTRUCTURE)\n\
         S: * 1 FETCH (UID 301 BODYSTRUCTURE {BS})\n\
         S: a5 OK FETCH completed\n\
         C: a6 UID FETCH 301 (UID BODY.PEEK[2])\n\
         S: * 1 FETCH (UID 301 BODY[2] {{16}}\n\
         S: aGVsbG8gZmlsZQ==)\n\
         S: a6 OK FETCH completed\n\
         {LAZY_LOGOUT}"
    );

    // Conn 4: view-source forces the complete BODY[] even though a
    // skeleton is on disk, and the deferred marker clears.
    let raw_body = "From: alice@e2e.test; FULL-BODY-WIRE-MARKER";
    let c4 = format!(
        "{LAZY_PRELUDE}\
         C: a5 UID FETCH 301 (UID BODY[])\n\
         S: * 1 FETCH (UID 301 BODY[] {{{}}}\n\
         S: {raw_body})\n\
         S: a5 OK FETCH completed\n\
         {LAZY_LOGOUT}",
        raw_body.len()
    );

    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (port, server) = serve_imap_seq(vec![c1, c2, c3, c4], Some(acceptor)).await;
    let state = test_state("lazy", fixture_net(port));

    let disc = discover_account_impl(&state, "u@e2e.test").await.unwrap();
    let view = add_account_impl(&state, add_input_from(&disc.suggestion, true))
        .await
        .unwrap();

    // ── Sync: descriptors persist, no payload pulled ─────────────────
    let reports = sync_account_impl(state.clone(), view.id.clone(), None)
        .await
        .expect("sync account");
    assert_eq!(reports[0].new_messages, 1);
    let folder_id = reports[0].folder_id;
    {
        let store = state.store.lock().await;
        assert!(
            store.has_message_parts(folder_id, 301).unwrap(),
            "BODYSTRUCTURE must persist deferred-part rows"
        );
        let rows = store.message_parts(folder_id, 301).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].part_index, 0);
        assert_eq!(rows[0].section, "2");
        assert_eq!(rows[0].name.as_deref(), Some("note.pdf"));
        assert_eq!(rows[0].mime, "application/pdf");
        assert_eq!(rows[0].size_bytes, Some(16));
        assert_eq!(rows[0].encoding, "base64");
        assert!(!rows[0].fetched);
        // Ordinary sync never wrote a body — payloads stay server-side.
        assert!(store.body_file(folder_id, 301).unwrap().is_none());
    }

    // ── Read: skeleton lands, attachment list is metadata-only ────────
    let body = get_message_impl(state.clone(), view.id.clone(), folder_id, 301)
        .await
        .expect("get message");
    assert!(body.body_present);
    assert!(
        body.text_body
            .as_deref()
            .is_some_and(|t| t.contains("hello body")),
        "eager text leaf must render: {:?}",
        body.text_body
    );
    assert_eq!(body.attachments.len(), 1);
    let att = &body.attachments[0];
    assert_eq!(att.index, 0);
    assert_eq!(att.filename.as_deref(), Some("note.pdf"));
    assert_eq!(att.content_type, "application/pdf");
    assert_eq!(att.size, 16, "wire octets, honestly labeled");
    assert!(!att.fetched, "payload still deferred");
    {
        let store = state.store.lock().await;
        let raw = std::fs::read(store.body_file(folder_id, 301).unwrap().unwrap()).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.contains("hello body"),
            "skeleton carries the text leaf"
        );
        assert!(
            text.contains("application/pdf"),
            "skeleton carries the part's MIME headers"
        );
        assert!(
            !text.contains("aGVsbG8"),
            "attachment payload must not be in the skeleton"
        );
    }

    // ── Save: BODY.PEEK[2] lands, decoded + durably stored ────────────
    let dest = state
        .data_dir
        .parent()
        .unwrap()
        .join(format!("kiwi-e2e-lazy-save-{}", std::process::id()));
    let dest_str = dest.to_string_lossy().to_string();
    let saved = download_attachment_impl(
        state.clone(),
        view.id.clone(),
        folder_id,
        301,
        0,
        dest_str.clone(),
    )
    .await
    .expect("deferred attachment download");
    assert_eq!(saved.filename, "note.pdf");
    assert_eq!(saved.content_type, "application/pdf");
    assert_eq!(saved.size, 10, "decoded size — base64 expanded honestly");
    assert_eq!(std::fs::read(&saved.path).unwrap(), b"hello file");
    {
        let store = state.store.lock().await;
        assert!(
            store
                .message_part(folder_id, 301, 0)
                .unwrap()
                .unwrap()
                .fetched,
            "row marked fetched only after bytes are durable"
        );
        assert!(store.attachment_payload_path(folder_id, 301, 0).is_file());
    }

    // ── Repeat save is local — the listener only serves 4 connections ─
    download_attachment_impl(state.clone(), view.id.clone(), folder_id, 301, 0, dest_str)
        .await
        .expect("repeat save must not dial");

    // ── View-source: skeleton is not verbatim — BODY[] forced ─────────
    let src = message_source_impl(state.clone(), view.id.clone(), folder_id, 301)
        .await
        .expect("message source");
    assert!(
        src.source.contains("FULL-BODY-WIRE-MARKER"),
        "source must be the complete body, not the skeleton"
    );
    {
        let store = state.store.lock().await;
        assert!(
            !store.has_message_parts(folder_id, 301).unwrap(),
            "complete body clears the deferred marker"
        );
    }
    // And a second source read is local (listener is gone after conn 4).
    message_source_impl(state.clone(), view.id.clone(), folder_id, 301)
        .await
        .expect("source replay must not dial");

    let _ = std::fs::remove_file(&dest);
    server.await.unwrap().expect("transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_undiscoverable_domain_flagged_not_crash() {
    // No fixtures at all: discovery must fall through to a flagged
    // pattern guess — the failure branch is data, not an exception.
    let state = test_state("miss", MockNet::new());
    let disc = discover_account_impl(&state, "u@nohost.invalid")
        .await
        .expect("discover never crashes on a dead domain");
    assert!(disc.needs_manual_review);
    assert_eq!(disc.source, "mx_heuristic");
    assert!(disc.suggestion.oauth2.is_none());
}

// ---------------------------------------------------------------------------
// T-262 — send-path E2E: compose → enqueue → outbox due → scripted loopback
// SMTP (real TCP + STARTTLS, same testutil seam as T-257) → MAIL/RCPT/DATA +
// message bytes on the wire → outbox drained + Sent-folder copy + audit rows.
// Failure branches: 5xx at DATA retains + surfaces, undo-cancel never sends,
// STARTTLS refusal fails closed.
// ---------------------------------------------------------------------------

/// Bind a loopback listener; returns it plus its port. Scripts are
/// generated later (they embed the built MIME bytes), so bind/serve are
/// split — the account must exist before `send_impl` can build the MIME.
async fn bind_listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Hard cap per scripted session — a parked transcript must fail fast,
/// not hang the test binary past its own timeout.
const SERVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve one scripted session per accepted connection, in order — the
/// send path's APPEND session and the follow-up sync each take one.
fn spawn_sessions(
    listener: TcpListener,
    scripts: Vec<String>,
    proto: Proto,
    tls: Option<TlsAcceptor>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        for raw in &scripts {
            let (stream, _) = tokio::time::timeout(SERVE_TIMEOUT, listener.accept())
                .await
                .map_err(|_| format!("timed out waiting for {proto:?} session"))?
                .map_err(|e| e.to_string())?;
            let steps = testutil::parse(raw);
            // Hard cap per session — a parked transcript must fail fast,
            // not hang the test binary past its own timeout.
            tokio::time::timeout(
                SERVE_TIMEOUT,
                testutil::serve(stream, &steps, proto, tls.clone()),
            )
            .await
            .map_err(|_| format!("{proto:?} transcript session exceeded {SERVE_TIMEOUT:?}"))?
            .map_err(|e| {
                eprintln!("[e2e serve {proto:?}] divergence: {e}");
                e
            })?;
        }
        Ok(())
    })
}

/// Wizard-shaped account input for the send tests: IMAP + SMTP both
/// loopback STARTTLS, password auth, self-signed consent.
fn send_input(smtp_port: u16, imap_port: u16) -> AddAccountInput {
    let server = |port: u16| ServerInput {
        host: "127.0.0.1".into(),
        port,
        security: "starttls".into(),
    };
    let auth = || {
        Some(AuthInput {
            kind: "password".into(),
            secret: Some("s3cret".into()),
            oauth2_ticket: None,
        })
    };
    AddAccountInput {
        display_name: "E2E Sender".into(),
        email: "u@e2e.test".into(),
        incoming_protocol: "imap".into(),
        incoming: server(imap_port),
        outgoing: server(smtp_port),
        username: Some("u@e2e.test".into()),
        outgoing_username: Some("u@e2e.test".into()),
        incoming_auth: auth(),
        outgoing_auth: auth(),
        accept_invalid_certs: true,
    }
}

fn compose() -> ComposeInput {
    ComposeInput {
        to: vec!["bob@e2e.test".into()],
        cc: vec![],
        bcc: vec![],
        subject: "E2E sent subject".into(),
        text: "Hello from the send-path E2E.".into(),
        html: None,
        in_reply_to: None,
        references: vec![],
        attachments: vec![],
    }
}

/// SMTP wire lines for the DATA payload — every byte the client sends,
/// verbatim. The terminator `.` is scripted by the caller. A leading `.`
/// would be dot-stuffed on the wire, so reflect that in the expectation.
fn smtp_data_steps(mime: &str) -> String {
    let mut s = String::new();
    let body = mime.strip_suffix("\r\n").unwrap_or(mime);
    for line in body.split("\r\n") {
        if line.starts_with('.') {
            s.push_str("C: .");
        } else {
            s.push_str("C: ");
        }
        s.push_str(line);
        s.push('\n');
    }
    s
}

/// Session preamble every scripted SMTP conversation shares: greeting,
/// EHLO with STARTTLS, upgrade, post-TLS EHLO with AUTH+SIZE, auth,
/// envelope, DATA invitation. `tail` supplies everything after the DATA
/// body (the reply that decides success vs rejection).
fn smtp_session(tail: &str, mime: &str) -> String {
    let mut s = String::from(
        "S: 220 e2e.test ESMTP TestServer\n\
         C: EHLO kiwi.local\n\
         S: 250-e2e.test greets you\n\
         S: 250-STARTTLS\n\
         S: 250 SIZE 10485760\n\
         C: STARTTLS\n\
         S: 220 2.0.0 Ready to start TLS\n\
         # TLS handshake\n\
         C: EHLO kiwi.local\n\
         S: 250-e2e.test greets you\n\
         S: 250-AUTH PLAIN LOGIN\n\
         S: 250 SIZE 10485760\n\
         C: AUTH PLAIN\n\
         S: 235 2.7.0 Authentication successful\n\
         C: MAIL FROM:<u@e2e.test>\n\
         S: 250 2.1.0 Ok\n\
         C: RCPT TO:<bob@e2e.test>\n\
         S: 250 2.1.5 Ok\n\
         C: DATA\n\
         S: 354 End data with <CR><LF>.<CR><LF>\n",
    );
    s.push_str(&smtp_data_steps(mime));
    s.push_str(tail);
    s
}

/// The sent-copy session: `file_sent_copy` connects, lists for `\Sent`,
/// APPENDs the built MIME, logs out. The post-TLS CAPABILITY is scripted
/// explicitly WITHOUT LITERAL+ so the client takes the deterministic
/// `{n}` + `+` continuation flow — the harness's generic probe reply
/// would advertise LITERAL+ and make the flow depend on whether the
/// client re-probes after upgrade.
fn imap_append_script(mime: &str) -> String {
    let n = mime.len();
    let mut s = String::from(
        "S: * OK e2e.test IMAP4rev2 TestServer ready\n\
         C: a1 CAPABILITY\n\
         S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS\n\
         S: a1 OK CAPABILITY completed\n\
         C: a2 STARTTLS\n\
         S: a2 OK Begin TLS negotiation now\n\
         # TLS handshake\n\
         C: a3 CAPABILITY\n\
         S: * CAPABILITY IMAP4rev2 UIDPLUS\n\
         S: a3 OK CAPABILITY completed\n\
         C: a4 LOGIN u@e2e.test REDACTED-DUMMY\n\
         S: a4 OK LOGIN completed\n\
         C: a5 LIST \"\" \"*\"\n\
         S: * LIST (\\HasNoChildren) \"/\" \"INBOX\"\n\
         S: * LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\n\
         S: a5 OK LIST completed\n",
    );
    s.push_str(&format!("C: a6 APPEND \"Sent\" (\\Seen) {{{n}}}\n"));
    s.push_str("S: + go ahead\n");
    // Every literal line plus the command-terminating CRLF (trailing
    // empty element of the split).
    for line in mime.split("\r\n") {
        s.push_str("C: ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str(
        "S: a6 OK APPEND completed\n\
         C: a7 LOGOUT\n\
         S: * BYE TestServer logging out\n\
         S: a7 OK LOGOUT completed\n",
    );
    s
}

/// Follow-up sync session proving the Sent copy is real: LIST exposes
/// INBOX + Sent, Sent SELECTs one message (uid 201 — what the scripted
/// APPEND "stored"), the envelope fetch lands it locally.
const SCRIPT_SENT_SYNC: &str = r#"
S: * OK e2e.test IMAP4rev2 TestServer ready
C: a1 CAPABILITY
S: * CAPABILITY IMAP4rev2 STARTTLS UIDPLUS
S: a1 OK CAPABILITY completed
C: a2 STARTTLS
S: a2 OK Begin TLS negotiation now
# TLS handshake
C: a3 LOGIN u@e2e.test REDACTED-DUMMY
S: a3 OK LOGIN completed
C: a4 LIST "" "*"
S: * LIST (\HasNoChildren) "/" "INBOX"
S: * LIST (\HasNoChildren \Sent) "/" "Sent"
S: a4 OK LIST completed
C: a5 SELECT INBOX
S: * FLAGS (\Seen \Answered \Flagged \Deleted \Draft)
S: * 0 EXISTS
S: * 0 RECENT
S: * OK [UIDVALIDITY 4242] UIDs valid
S: * OK [UIDNEXT 1] Predicted next UID
S: a5 OK [READ-WRITE] SELECT completed
C: a6 UID SEARCH ALL
S: * SEARCH
S: a6 OK SEARCH completed
C: a7 SELECT Sent
S: * FLAGS (\Seen \Answered \Flagged \Deleted \Draft)
S: * 1 EXISTS
S: * 1 RECENT
S: * OK [UIDVALIDITY 4243] UIDs valid
S: * OK [UIDNEXT 202] Predicted next UID
S: a7 OK [READ-WRITE] SELECT completed
C: a8 UID SEARCH ALL
S: * SEARCH 201
S: a8 OK SEARCH completed
C: a9 UID FETCH 201 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE BODYSTRUCTURE)
S: * 1 FETCH (UID 201 FLAGS (\Seen) ENVELOPE ("Thu, 02 Jan 2025 12:00:00 +0000" "E2E sent subject" (("E2E Sender" NIL "u" "e2e.test")) (("E2E Sender" NIL "u" "e2e.test")) (("E2E Sender" NIL "u" "e2e.test")) (("Bob" NIL "bob" "e2e.test")) NIL NIL NIL "<sent@e2e.test>") RFC822.SIZE 999 INTERNALDATE "02-Jan-2025 12:00:00 +0000")
S: a9 OK FETCH completed
C: a10 UID FETCH 201 (UID BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)])
S: * 1 FETCH (UID 201)
S: a10 OK FETCH completed
C: a11 LOGOUT
S: * BYE TestServer logging out
S: a11 OK LOGOUT completed
"#;

/// Actions recorded in the hash-chained audit log (read raw — the chain
/// itself is verified on open by `AuditLog`).
fn audit_actions(state: &AppState) -> String {
    std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap_or_default()
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_send_delivers_files_sent_copy() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (smtp_l, smtp_port) = bind_listener().await;
    let (imap_l, imap_port) = bind_listener().await;
    let state = test_state("send", MockNet::new());
    let view = add_account_impl(&state, send_input(smtp_port, imap_port))
        .await
        .expect("add account");

    // ── Stage 1: compose-shaped input → enqueue → outbox row ────────
    let receipt = send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(0),
        }),
    )
    .await
    .expect("enqueue");
    assert_eq!(state.send_queue.lock().await.pending_count(), 1);
    assert_eq!(state.store.lock().await.outbox_list(10).unwrap().len(), 1);

    // ── Stage 2: due → drain (the flush drain's shape) ──────────────
    let item = state.send_queue.lock().await.due(i64::MAX).remove(0);
    let meta = state
        .outbox_meta
        .lock()
        .await
        .get(&receipt.queue_id)
        .cloned();
    let mime = String::from_utf8_lossy(&item.request.message).into_owned();
    assert!(
        mime.contains("Subject: E2E sent subject")
            && mime.contains("Hello from the send-path E2E."),
        "compose-shaped MIME built: {mime}"
    );

    // Scripts are generated now — they embed the exact MIME bytes.
    let smtp = spawn_sessions(
        smtp_l,
        vec![smtp_session(
            "C: .\nS: 250 2.0.0 Ok: queued as E2E0001\nC: QUIT\nS: 221 2.0.0 Bye\n",
            &mime,
        )],
        Proto::Smtp,
        Some(acceptor.clone()),
    );
    let imap = spawn_sessions(
        imap_l,
        vec![imap_append_script(&mime), SCRIPT_SENT_SYNC.into()],
        Proto::Imap,
        Some(acceptor),
    );

    // ── Stage 3: dispatch — real TCP+TLS SMTP session ───────────────
    let outcome = deliver(state.clone(), item, meta).await;
    assert_eq!(outcome, Delivered::Sent, "send must be accepted");
    drop_outbox(&state, &receipt.queue_id).await;
    assert_eq!(state.send_queue.lock().await.pending_count(), 0);
    assert!(state.outbox_meta.lock().await.is_empty());
    assert!(state.store.lock().await.outbox_list(10).unwrap().is_empty());

    // ── Stage 4: audit rows — enqueue + committed send ──────────────
    let audit = audit_actions(&state);
    for action in ["\"send-queued\"", "\"send-sent\""] {
        assert!(
            audit.contains(action),
            "audit must record {action}: {audit}"
        );
    }
    assert!(
        !audit.contains("send-sent-copy-failed") && !audit.contains("send-attempt-failed"),
        "nothing may fail on the green path: {audit}"
    );

    // ── Stage 5: the Sent copy round-trips — sync lists it back ─────
    let reports = sync_account_impl(state.clone(), view.id.clone(), None)
        .await
        .expect("sync after send");
    assert_eq!(reports.len(), 2, "INBOX + Sent sync: {reports:?}");
    let folders = list_folders_impl(&state, &view.id).await.unwrap();
    let sent = folders
        .iter()
        .find(|f| f.name == "Sent")
        .expect("Sent folder");
    let msgs = list_messages_impl(&state, view.id.clone(), sent.id, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].subject.as_deref(), Some("E2E sent subject"));
    assert_eq!(msgs[0].from.as_deref(), Some("u@e2e.test"));
    assert!(!msgs[0].unread, "sent copy appended with \\Seen → read");

    smtp.await.unwrap().expect("smtp transcript replayed fully");
    imap.await.unwrap().expect("imap sessions replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_send_smtp_reject_retains_outbox() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (smtp_l, smtp_port) = bind_listener().await;
    let state = test_state("send-5xx", MockNet::new());
    // Incoming never contacted — a dead port is honest about that.
    let view = add_account_impl(&state, send_input(smtp_port, 9))
        .await
        .unwrap();
    send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(0),
        }),
    )
    .await
    .unwrap();
    let item = state.send_queue.lock().await.due(i64::MAX).remove(0);
    let meta = state.outbox_meta.lock().await.get(&item.queue_id).cloned();
    let queue_id = item.queue_id.clone();
    let mime = String::from_utf8_lossy(&item.request.message).into_owned();

    let smtp = spawn_sessions(
        smtp_l,
        vec![smtp_session(
            "C: .\nS: 554 5.7.1 Rejected: content policy\n",
            &mime,
        )],
        Proto::Smtp,
        Some(acceptor),
    );

    // 5xx at DATA → server-reject → Held (retryable): re-enqueued with
    // backoff, persisted row kept, the failure visible in the outbox.
    let outcome = deliver(state.clone(), item, meta).await;
    assert_eq!(outcome, Delivered::Held, "5xx DATA must not be Sent");
    assert_eq!(state.send_queue.lock().await.pending_count(), 1);
    let m = state
        .outbox_meta
        .lock()
        .await
        .get(&queue_id)
        .cloned()
        .expect("outbox meta retained");
    assert_eq!(m.attempts, 1);
    assert!(m.not_before_unix > now_unix(), "linear backoff applied");
    let rows = state.store.lock().await.outbox_list(10).unwrap();
    assert!(
        rows.iter().any(|r| r.queue_id == queue_id),
        "persisted outbox row retained: {rows:?}"
    );
    let audit = audit_actions(&state);
    assert!(
        audit.contains("send-attempt-failed") && audit.contains("server-reject"),
        "the 5xx must surface tamper-evidently: {audit}"
    );

    smtp.await.unwrap().expect("smtp transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_send_cancel_inside_undo_window_never_transmits() {
    // Ports point at the discard service — irrelevant: a cancelled send
    // leaves the queue before any dispatcher could drain it, so nothing
    // ever connects. The assertions are the queue/outbox/audit state.
    let state = test_state("send-cancel", MockNet::new());
    let view = add_account_impl(&state, send_input(9, 9)).await.unwrap();
    let receipt = send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(30),
        }),
    )
    .await
    .unwrap();
    assert!(
        cancel_impl(&state, &receipt.queue_id).await.unwrap(),
        "inside the grace window cancel must succeed"
    );
    // Nothing is left to dispatch — queue, meta, persisted row all gone.
    assert!(state.send_queue.lock().await.due(i64::MAX).is_empty());
    assert!(state.outbox_meta.lock().await.is_empty());
    assert!(state.store.lock().await.outbox_list(10).unwrap().is_empty());
    let audit = audit_actions(&state);
    assert!(
        audit.contains("\"send-cancelled\""),
        "cancel must be audited"
    );
    assert!(
        !audit.contains("send-attempt-failed") && !audit.contains("send-sent"),
        "a cancelled send must never reach the wire: {audit}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_send_starttls_refusal_fails_closed() {
    let (_acceptor_unused, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (smtp_l, smtp_port) = bind_listener().await;
    let state = test_state("send-nostls", MockNet::new());
    let view = add_account_impl(&state, send_input(smtp_port, 9))
        .await
        .unwrap();
    send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(0),
        }),
    )
    .await
    .unwrap();
    let item = state.send_queue.lock().await.due(i64::MAX).remove(0);
    let meta = state.outbox_meta.lock().await.get(&item.queue_id).cloned();
    let queue_id = item.queue_id.clone();

    // EHLO reply with no STARTTLS capability — the client must abort
    // before AUTH/MAIL. The `# EOF` step proves fail-closed *on the
    // wire*: any byte past EHLO (e.g. a plaintext AUTH) fails the join.
    let smtp = spawn_sessions(
        smtp_l,
        vec![
            "S: 220 e2e.test ESMTP TestServer\n\
             C: EHLO kiwi.local\n\
             S: 250 e2e.test\n\
             # EOF\n"
                .into(),
        ],
        Proto::Smtp,
        Some(_acceptor_unused),
    );

    let outcome = deliver(state.clone(), item, meta).await;
    assert_eq!(outcome, Delivered::Held, "STARTTLS refusal must not send");
    assert_eq!(state.send_queue.lock().await.pending_count(), 1);
    assert!(
        state.outbox_meta.lock().await.get(&queue_id).is_some(),
        "retained for retry — fail closed, not dropped"
    );
    assert!(
        audit_actions(&state).contains("send-attempt-failed"),
        "refusal must be audited, not silent"
    );
    smtp.await
        .unwrap()
        .expect("server consumed greeting+EHLO only");
}

/// Transcript for a session whose only recipient is rejected: the DATA
/// phase never runs, and the client resets + quits.
fn smtp_session_all_rejected() -> String {
    String::from(
        "S: 220 e2e.test ESMTP TestServer\n\
         C: EHLO kiwi.local\n\
         S: 250-e2e.test greets you\n\
         S: 250-STARTTLS\n\
         S: 250 SIZE 10485760\n\
         C: STARTTLS\n\
         S: 220 2.0.0 Ready to start TLS\n\
         # TLS handshake\n\
         C: EHLO kiwi.local\n\
         S: 250-e2e.test greets you\n\
         S: 250-AUTH PLAIN LOGIN\n\
         S: 250 SIZE 10485760\n\
         C: AUTH PLAIN\n\
         S: 235 2.7.0 Authentication successful\n\
         C: MAIL FROM:<u@e2e.test>\n\
         S: 250 2.1.0 Ok\n\
         C: RCPT TO:<bob@e2e.test>\n\
         S: 550 5.1.1 No such user here\n\
         C: RSET\n\
         S: 250 2.0.0 Ok\n\
         C: QUIT\n\
         S: 221 2.0.0 Bye\n",
    )
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_send_no_recipient_accepted_is_never_journaled_as_sent() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (smtp_l, smtp_port) = bind_listener().await;
    let state = test_state("send-allrejected", MockNet::new());
    let view = add_account_impl(&state, send_input(smtp_port, 9))
        .await
        .unwrap();
    send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(0),
        }),
    )
    .await
    .unwrap();
    let item = state.send_queue.lock().await.due(i64::MAX).remove(0);
    let meta = state.outbox_meta.lock().await.get(&item.queue_id).cloned();

    let smtp = spawn_sessions(
        smtp_l,
        vec![smtp_session_all_rejected()],
        Proto::Smtp,
        Some(acceptor),
    );

    // An SMTP transaction that accepted nobody is not a delivery: it is a
    // server rejection, retryable for an ordinary send.
    let outcome = deliver(state.clone(), item, meta).await;
    assert_eq!(outcome, Delivered::Held);
    let audit = audit_actions(&state);
    assert!(audit.contains("send-attempt-failed"));
    assert!(!audit.contains("send-sent"), "{audit}");
    assert!(!audit.contains("send-partially-rejected"), "{audit}");
    smtp.await.unwrap().expect("smtp transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_single_attempt_send_is_never_retried() {
    let (acceptor, _der) = testutil::tls_acceptor(&["e2e.test"]);
    let (smtp_l, smtp_port) = bind_listener().await;
    let state = test_state("send-single", MockNet::new());
    let view = add_account_impl(&state, send_input(smtp_port, 9))
        .await
        .unwrap();
    let receipt = send_impl(
        &state,
        &view.id,
        compose(),
        Some(SendOptions {
            send_at_unix: None,
            undo_grace_secs: Some(0),
        }),
    )
    .await
    .unwrap();
    // Promote the queued send to the deliverability class: one attempt,
    // never re-enqueued, whatever the relay says.
    {
        let mut metas = state.outbox_meta.lock().await;
        metas.get_mut(&receipt.queue_id).unwrap().class = crate::state::OutboxClass::SingleAttempt;
    }
    let item = state.send_queue.lock().await.due(i64::MAX).remove(0);
    let meta = state.outbox_meta.lock().await.get(&item.queue_id).cloned();

    let smtp = spawn_sessions(
        smtp_l,
        vec![smtp_session_all_rejected()],
        Proto::Smtp,
        Some(acceptor),
    );

    let outcome = deliver(state.clone(), item, meta).await;
    assert_eq!(
        outcome,
        Delivered::Failed,
        "a single-use sink is not retried"
    );
    assert_eq!(state.send_queue.lock().await.pending_count(), 0);
    let audit = audit_actions(&state);
    assert!(audit.contains("send-single-attempt-abandoned"), "{audit}");
    assert!(!audit.contains("send-sent"), "{audit}");
    smtp.await.unwrap().expect("smtp transcript replayed fully");
}

// ---------------------------------------------------------------------------
// T-285 — POP3 E2E (mirror of T-257 IMAP / T-262 SMTP): account-add →
// sync → scripted loopback POP3 (real TCP + implicit TLS, same testutil
// transcript seam) → USER/PASS → UIDL-diff → RETR → envelopes + bodies in
// the real MailStore. Failure branches: auth `-ERR` → server-reject, dead
// port → connect-failed, malformed RETR status → server-reject. Policy
// branch: IPC pins keep-on-server (delete_after_download=false — no DELE
// on the wire, second sync dedups on UIDL); the delete policy is driven
// at engine level (`sync_pop3(_, true)`) against the same real transport.
// ---------------------------------------------------------------------------

/// Account input for the POP3 legs: implicit-TLS loopback, password auth.
/// The outgoing leg is inert (never dialed in these tests).
fn pop3_input(port: u16) -> AddAccountInput {
    AddAccountInput {
        display_name: "E2E POP3".into(),
        email: "u@e2e.test".into(),
        incoming_protocol: "pop3".into(),
        incoming: ServerInput {
            host: "127.0.0.1".into(),
            port,
            security: "tls".into(),
        },
        outgoing: ServerInput {
            host: "127.0.0.1".into(),
            port: 2525,
            security: "tls".into(),
        },
        username: Some("u@e2e.test".into()),
        outgoing_username: Some("u@e2e.test".into()),
        incoming_auth: Some(AuthInput {
            kind: "password".into(),
            secret: Some("s3cret".into()),
            oauth2_ticket: None,
        }),
        outgoing_auth: None,
        accept_invalid_certs: true,
    }
}

/// RFC 5322 bytes for a RETR response. Message 2 carries a leading-dot
/// body line — the wire form must dot-stuff it, and the stored body must
/// show it unstuffed (proves `read_dot_block` ran, not a raw splice).
const POP3_MSG1: &str = "Subject: POP3 hello\r\n\
From: Alice <alice@e2e.test>\r\n\
To: u@e2e.test\r\n\
Date: Wed, 01 Jan 2025 12:00:00 +0000\r\n\
Message-ID: <pop1@e2e.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
First POP3 body.\r\n";

const POP3_MSG2: &str = "Subject: POP3 second\r\n\
From: Bob <bob@e2e.test>\r\n\
To: u@e2e.test\r\n\
Date: Wed, 01 Jan 2025 13:00:00 +0000\r\n\
Message-ID: <pop2@e2e.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
Second POP3 body.\r\n\
.stuffed line survives\r\n";

/// `S:` wire lines for a RETR dot-block — leading dots doubled per RFC.
fn pop3_msg_lines(msg: &str) -> String {
    let mut s = String::new();
    for line in msg.strip_suffix("\r\n").unwrap_or(msg).split("\r\n") {
        if line.starts_with('.') {
            s.push_str("S: .");
        }
        s.push_str("S: ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str("S: .\n");
    s
}

/// Shared session head: implicit-TLS handshake, greeting, USER/PASS.
/// CAPA is not scripted — the harness auto-answers `-ERR unsupported`,
/// matching a real legacy server.
const POP3_HEAD: &str = "# TLS handshake\n\
S: +OK e2e.test POP3 TestServer ready\n\
C: USER u@e2e.test\n\
S: +OK user accepted, send PASS\n\
C: PASS\n\
S: +OK maildrop has mail\n";

#[tokio::test(flavor = "current_thread")]
async fn e2e_pop3_sync_ingests_keeps_and_dedups() {
    let (acceptor, _der) = testutil::tls_acceptor(&["127.0.0.1"]);
    let (listener, port) = bind_listener().await;
    let state = test_state("pop3-green", MockNet::new());
    let view = add_account_impl(&state, pop3_input(port))
        .await
        .expect("add pop3 account");

    // Session 1: UIDL 2 drops → RETR both → QUIT. Keep-on-server: NO DELE
    // may appear — a stray DELE diverges the transcript at join.
    let s1 = format!(
        "{POP3_HEAD}\
         C: UIDL\n\
         S: +OK\n\
         S: 1 uidl-m1@e2e.test\n\
         S: 2 uidl-m2@e2e.test\n\
         S: .\n\
         C: RETR 1\n\
         S: +OK 200 octets\n\
         {}\
         C: RETR 2\n\
         S: +OK 220 octets\n\
         {}\
         C: QUIT\n\
         S: +OK bye\n",
        pop3_msg_lines(POP3_MSG1),
        pop3_msg_lines(POP3_MSG2)
    );
    // Session 2 (re-sync): same UIDLs, all seen → zero RETR expected.
    let s2 = format!(
        "{POP3_HEAD}\
         C: UIDL\n\
         S: +OK\n\
         S: 1 uidl-m1@e2e.test\n\
         S: 2 uidl-m2@e2e.test\n\
         S: .\n\
         C: QUIT\n\
         S: +OK bye\n"
    );
    let server = spawn_sessions(listener, vec![s1, s2], Proto::Pop3, Some(acceptor));

    // ── sync 1: ingest ────────────────────────────────────────────
    let reports = sync_account_impl(state.clone(), view.id.clone(), None)
        .await
        .expect("pop3 sync");
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.protocol, "pop3");
    assert_eq!(r.folder, "INBOX");
    assert_eq!(r.downloaded, 2);
    assert_eq!(r.remote_exists, 2);
    assert_eq!(
        r.deleted_remote, 0,
        "IPC pins keep-on-server — DELE must not run"
    );

    // ── envelopes + folder landing ────────────────────────────────
    let folders = list_folders_impl(&state, &view.id).await.unwrap();
    let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
    let msgs = list_messages_impl(&state, view.id.clone(), inbox.id, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);
    // POP3 uid = message number; both land unread (no \Seen concept).
    let m2 = msgs.iter().find(|m| m.uid == 2).expect("msg 2");
    assert_eq!(m2.subject.as_deref(), Some("POP3 second"));
    assert_eq!(m2.from.as_deref(), Some("bob@e2e.test"));
    assert_eq!(m2.message_id.as_deref(), Some("pop2@e2e.test"));
    assert!(m2.unread);
    let m1 = msgs.iter().find(|m| m.uid == 1).expect("msg 1");
    assert_eq!(m1.subject.as_deref(), Some("POP3 hello"));
    assert_eq!(m1.from.as_deref(), Some("alice@e2e.test"));

    // ── body landing: stored at ingest, dot-unstuffed ─────────────
    let raw = crate::commands::mail::load_body_raw(&state, &view.id, inbox.id, 2)
        .await
        .unwrap()
        .expect("body stored at ingest");
    let body = String::from_utf8_lossy(&raw);
    assert!(body.contains("Second POP3 body."));
    assert!(
        body.contains(".stuffed line survives"),
        "dot-stuffing must be undone: {body:?}"
    );
    assert!(
        !body.contains("..stuffed"),
        "stuffed wire form must not reach the store"
    );

    // ── sync 2: UIDL dedup — keep-on-server means the drops are still
    // there, but pop3_seen makes them no-ops (no RETR in session 2). ──
    let reports2 = sync_account_impl(state.clone(), view.id.clone(), None)
        .await
        .expect("second sync");
    assert_eq!(reports2[0].downloaded, 0);
    assert_eq!(reports2[0].remote_exists, 2);
    assert_eq!(reports2[0].deleted_remote, 0);

    server.await.unwrap().expect("transcripts replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_pop3_auth_err_surfaces_server_reject() {
    let (acceptor, _der) = testutil::tls_acceptor(&["127.0.0.1"]);
    let (listener, port) = bind_listener().await;
    let state = test_state("pop3-auth", MockNet::new());
    let view = add_account_impl(&state, pop3_input(port)).await.unwrap();

    let script = "# TLS handshake\n\
S: +OK e2e.test POP3 TestServer ready\n\
C: USER u@e2e.test\n\
S: +OK user accepted, send PASS\n\
C: PASS\n\
S: -ERR authentication failed\n";
    let server = spawn_sessions(listener, vec![script.into()], Proto::Pop3, Some(acceptor));

    let err = sync_account_impl(state, view.id, None)
        .await
        .expect_err("auth -ERR must fail");
    assert_eq!(err.code, "server-reject");
    server.await.unwrap().expect("transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_pop3_dead_port_surfaces_connect_error() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let state = test_state("pop3-dead", MockNet::new());
    let view = add_account_impl(&state, pop3_input(port)).await.unwrap();
    let err = sync_account_impl(state, view.id, None)
        .await
        .expect_err("dead port must fail");
    assert_eq!(err.code, "connect-failed");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_pop3_malformed_retr_surfaces_server_reject() {
    let (acceptor, _der) = testutil::tls_acceptor(&["127.0.0.1"]);
    let (listener, port) = bind_listener().await;
    let state = test_state("pop3-badretr", MockNet::new());
    let view = add_account_impl(&state, pop3_input(port)).await.unwrap();

    // RETR answered with a garbage status line (not +OK/-ERR) — the
    // client must surface the malformed reply, not panic or fabricate.
    let script = format!(
        "{POP3_HEAD}\
         C: UIDL\n\
         S: +OK\n\
         S: 1 uidl-m1@e2e.test\n\
         S: .\n\
         C: RETR 1\n\
         S: XYZZY garbage status line\n"
    );
    let server = spawn_sessions(listener, vec![script], Proto::Pop3, Some(acceptor));

    let err = sync_account_impl(state, view.id, None)
        .await
        .expect_err("malformed RETR must fail");
    assert_eq!(err.code, "server-reject");
    server.await.unwrap().expect("transcript replayed fully");
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_pop3_delete_after_download_sends_dele() {
    // The IPC path pins keep-on-server; the delete policy is a kiwi-mail
    // `sync_pop3` option — exercised here over the same real TCP+TLS
    // loopback so the DELE commands are witnessed on the wire.
    let (acceptor, _der) = testutil::tls_acceptor(&["127.0.0.1"]);
    let (listener, port) = bind_listener().await;
    let state = test_state("pop3-dele", MockNet::new());
    let view = add_account_impl(&state, pop3_input(port)).await.unwrap();

    let script = format!(
        "{POP3_HEAD}\
         C: UIDL\n\
         S: +OK\n\
         S: 1 uidl-m1@e2e.test\n\
         S: 2 uidl-m2@e2e.test\n\
         S: .\n\
         C: RETR 1\n\
         S: +OK 200 octets\n\
         {}\
         C: DELE 1\n\
         S: +OK deleted\n\
         C: RETR 2\n\
         S: +OK 220 octets\n\
         {}\
         C: DELE 2\n\
         S: +OK deleted\n",
        pop3_msg_lines(POP3_MSG1),
        pop3_msg_lines(POP3_MSG2)
    );
    let server = spawn_sessions(listener, vec![script], Proto::Pop3, Some(acceptor));

    let t = kiwi_mail::transport::Transport::connect(
        "127.0.0.1",
        port,
        kiwi_mail::transport::SocketSecurity::ImplicitTls,
        kiwi_mail::transport::TlsSettings {
            accept_invalid_certs: true,
            extra_roots: Vec::new(),
        },
    )
    .await
    .expect("connect");
    let mut client =
        kiwi_mail::pop3::Pop3Client::connect(t, kiwi_mail::pop3::Pop3Config::default())
            .await
            .expect("pop3 handshake");
    client
        .authenticate(&kiwi_mail::pop3::Pop3Auth::UserPass {
            user: "u@e2e.test".into(),
            password: zeroize::Zeroizing::new("s3cret".into()),
        })
        .await
        .expect("auth");
    let (report, folder_id) = {
        let store = state.store.lock().await;
        let report =
            kiwi_mail::sync::sync_pop3(&mut client, &store, &view.id, "INBOX", true, now_unix())
                .await
                .expect("deleting sync");
        let folder_id = store.ensure_folder(&view.id, "INBOX").unwrap();
        (report, folder_id)
    };
    // Mirror pop3_sync's lock ordering: index update happens only after
    // the store guard is dropped — engine sync touches the store, folder
    // registration is the app layer's job.
    {
        let mut index = state.index.lock().await;
        index.remember_folder(&view.id, folder_id, "INBOX");
        index.save(&state.data_dir).unwrap();
    }
    assert_eq!(report.downloaded, 2);
    assert_eq!(report.deleted_remote, 2);
    assert_eq!(report.remote_drops, 2);

    // Envelopes + bodies still landed locally — DELE removes the server
    // copy, never the ingested one.
    let folders = list_folders_impl(&state, &view.id).await.unwrap();
    let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
    let msgs = list_messages_impl(&state, view.id.clone(), inbox.id, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);

    server.await.unwrap().expect("transcript replayed fully");
}
