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
use crate::commands::mail::{list_folders_impl, list_messages_impl, sync_account_impl};
use crate::state::AppState;
use crate::types::{AddAccountInput, AuthInput, ServerInput};

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
        AppState::open_test_with_net(
            dir,
            crate::state::integrations_transport().unwrap(),
            Arc::new(net),
        )
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
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
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
C: a7 UID FETCH 101,102 (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE)
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
