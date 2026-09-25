//! Sync-to-finding vertical e2e (T-171): live GreenMail IMAP →
//! `sync_folder` → store rows → live adapter → deterministic findings.
//!
//! Requires the compose stack: `docker compose up -d mailpit greenmail`,
//! then `KIWI_E2E=1 cargo test -p kiwi-forensics --test vertical_mail_flow`
//! (ports via `GREENMAIL_IMAP_PORT`, default 1143). Without `KIWI_E2E=1`
//! the test prints a skip note and returns green, so `cargo test
//! --workspace` stays hermetic.
//!
//! GreenMail serves plaintext IMAP with no STARTTLS (see
//! `infra/e2e/test_mail_flow.py`, which asserts that capability), so the
//! expected adapter verdicts are `KIWI-TRANSPORT-001` + `KIWI-AUTH-001` —
//! a real plaintext observation producing real findings, not a mock.

use kiwi_forensics::live::{LiveAuthObservation, LiveSessionInput, SocketMode, event_from_live};
use kiwi_forensics::model::{AuthMechanism, Protocol};
use kiwi_forensics::rules::{RuleEngine, SecurityPolicy};
use kiwi_mail::account::{
    AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
};
use kiwi_mail::imap::{ImapAuth, ImapClient, ImapConfig};
use kiwi_mail::store::MailStore;
use kiwi_mail::sync::sync_folder;
use kiwi_mail::transport::{SocketSecurity, TlsSettings, Transport};
use zeroize::Zeroizing;

const STARTED_AT_UNIX_MS: i64 = 1_700_000_000_000;
const ACCOUNT_ID: &str = "e2e-vertical";

fn e2e_enabled() -> bool {
    std::env::var("KIWI_E2E").is_ok()
}

fn imap_port() -> u16 {
    std::env::var("GREENMAIL_IMAP_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(1143)
}

fn account(port: u16) -> MailAccount {
    let server = ServerConfig {
        host: "127.0.0.1".to_string(),
        port,
        security: SocketSecurity::Plaintext,
    };
    MailAccount {
        account_id: ACCOUNT_ID.to_string(),
        display_name: "e2e vertical".to_string(),
        email: "demo@localhost".to_string(),
        incoming: IncomingAccount {
            protocol: IncomingProtocol::Imap,
            server: server.clone(),
            auth: AuthRef::None,
            username: "demo".to_string(),
        },
        outgoing: OutgoingAccount {
            server,
            auth: AuthRef::None,
            username: "demo".to_string(),
        },
    }
}

#[tokio::test]
async fn greenmail_sync_reaches_store_and_adapter() {
    if !e2e_enabled() {
        eprintln!("skipped: set KIWI_E2E=1 with compose mailpit+greenmail up");
        return;
    }
    let port = imap_port();

    // 1. Live connect + auth (GreenMail: auth disabled, demo/demo accepted).
    let transport = Transport::connect(
        "127.0.0.1",
        port,
        SocketSecurity::Plaintext,
        TlsSettings::default(),
    )
    .await
    .expect("imap connect");
    let mut imap = ImapClient::connect_with(
        transport,
        ImapConfig {
            allow_plaintext_auth: true,
        },
    )
    .await
    .expect("imap handshake");
    imap.authenticate(&ImapAuth::Login {
        user: "demo".into(),
        password: Zeroizing::new("demo".into()),
    })
    .await
    .expect("imap login");

    // 2. Seed one message whose subject is unique to this run.
    let marker = format!("kiwi vertical e2e {}", std::process::id());
    let seed = format!(
        "From: interop@kiwi-test.invalid\r\nTo: demo@localhost\r\nSubject: {marker}\r\n\r\nvertical body\r\n"
    );
    imap.append("INBOX", &["\\Seen"], seed.as_bytes())
        .await
        .expect("seed append");

    // 3. The real sync path into a real (memory-backed) store.
    let store = MailStore::open_memory().expect("open store");
    store
        .upsert_account(&account(port))
        .expect("upsert account");
    let report = sync_folder(&mut imap, &store, ACCOUNT_ID, "INBOX", STARTED_AT_UNIX_MS)
        .await
        .expect("sync_folder");
    assert!(report.new_messages >= 1, "seed synced: {report:?}");

    // 4. Message rows exist with the seeded subject.
    let folder_id = store.ensure_folder(ACCOUNT_ID, "INBOX").expect("folder id");
    let rows = store.list_messages(folder_id, 100).expect("list rows");
    assert!(
        rows.iter()
            .any(|row| row.subject.as_deref() == Some(marker.as_str())),
        "seeded subject present in store rows"
    );

    // 5. The observed transport reaches the forensics adapter and emits
    // deterministic findings (plaintext IMAP + successful LOGIN).
    let observed_plaintext = imap.transport().observation().is_none();
    assert!(observed_plaintext, "no TLS ran on this socket");
    let auth = LiveAuthObservation {
        mechanism: Some(AuthMechanism::Login),
        succeeded: Some(true),
        attempts: 1,
        failures: 0,
    };
    let input = LiveSessionInput {
        source_tag: "e2e-greenmail",
        protocol: Protocol::Imap,
        server_host: "127.0.0.1",
        server_port: imap.transport().port(),
        client_port: 0,
        index: 0,
        mode: SocketMode::Plaintext,
        observation: None,
        auth: Some(&auth),
        started_at_unix_ms: STARTED_AT_UNIX_MS,
    };
    let engine = RuleEngine::new(SecurityPolicy::default());
    let first = engine.evaluate_session(&event_from_live(&input));
    let ids: Vec<&str> = first
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(ids.contains(&"KIWI-TRANSPORT-001"), "got {ids:?}");
    assert!(ids.contains(&"KIWI-AUTH-001"), "got {ids:?}");
    let second = engine.evaluate_session(&event_from_live(&input));
    assert_eq!(
        serde_json::to_string(&first).expect("json"),
        serde_json::to_string(&second).expect("json"),
        "findings deterministic"
    );

    // 6. Cleanup so reruns stay deterministic: flag + expunge the seed.
    let uids = imap.uid_search("ALL").await.expect("search");
    for uid in &uids {
        let items = imap
            .uid_fetch(&uid.to_string(), &["UID", "ENVELOPE"])
            .await
            .expect("fetch");
        let ours = items.iter().any(|item| {
            item.envelope
                .as_ref()
                .and_then(|envelope| envelope.subject.as_deref())
                == Some(marker.as_str())
        });
        if ours {
            imap.uid_store(&uid.to_string(), "+FLAGS.SILENT", &["\\Deleted"])
                .await
                .expect("flag deleted");
        }
    }
    imap.expunge().await.expect("expunge");
    imap.logout().await.ok();
}
