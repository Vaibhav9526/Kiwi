//! `kiwi_import_mbox` (T-309): Berkeley-mbox import — the migration path for
//! mail from Thunderbird/Mailspring-era clients.
//!
//! Deliberate semantics:
//!
//! - **Local landing.** The default folder is `Import` — a folder no sync
//!   pass ever writes to. Importing into a *synced* folder is allowed but
//!   documented: IMAP reconciliation treats the server as authoritative and
//!   expunges local uids it doesn't know, so a synced target can lose the
//!   imported rows on the next pass.
//! - **Honest counts.** Every `From ` member is accounted for: imported,
//!   skipped-duplicates (same `Message-ID` already on the account),
//!   skipped-expunged (Thunderbird `Expunged` bit — importing it would
//!   resurrect deleted mail), or failed with a bounded per-member reason.
//! - **Same ingest evidence as sync.** Imported rows run the full ingest
//!   pipeline (ingest rules, attachment/link risk classification,
//!   Authentication-Results stamping with no SMTP receipt — `spf=none`,
//!   never a fabricated verdict) so imported mail carries the same evidence
//!   shape as synced mail. Rule failures count separately and never fail
//!   the member.

use std::path::Path;
use std::sync::Arc;

use tauri::State;

use kiwi_mail::mbox;
use kiwi_mail::mime::parse_message;
use kiwi_mail::store::NewMessageMeta;

use super::mail::{auth_sealer, remember_threading};
use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{MboxImportIssueView, MboxImportView};

/// Whole-file cap. Real mbox folders run to GBs; 512 MiB is the honest bound
/// for the first surface — split larger archives before import.
const MAX_MBOX_BYTES: u64 = 512 * 1024 * 1024;
/// Members processed per import; the remainder is reported via `truncated`.
const MAX_MBOX_MESSAGES: usize = 50_000;
/// Bounded failure list — past this, counts still accumulate.
const MAX_IMPORT_ISSUES: usize = 200;
/// Per-issue detail bound (never a filename or a body fragment).
const MAX_ISSUE_DETAIL: usize = 160;
/// Landing folder when the caller doesn't name one — local-only, never a
/// sync target.
pub(crate) const DEFAULT_IMPORT_FOLDER: &str = "Import";

/// `kiwi_import_mbox { accountId, path, folder? }` → `MboxImportView`.
/// Lock-gated. `path` must name an existing regular file; size and member
/// counts are bounded (`MAX_MBOX_BYTES`, `MAX_MBOX_MESSAGES`).
#[tauri::command]
pub async fn kiwi_import_mbox(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    path: String,
    folder: Option<String>,
) -> CmdResult<MboxImportView> {
    gate(state.inner()).await?;
    import_mbox_impl(
        state.inner(),
        &account_id,
        &path,
        folder.as_deref(),
    )
    .await
}

pub(crate) async fn import_mbox_impl(
    state: &AppState,
    account_id: &str,
    path: &str,
    folder: Option<&str>,
) -> CmdResult<MboxImportView> {
    bounded("accountId", account_id, 128)?;
    bounded("path", path, 4096)?;
    let folder_name = folder.unwrap_or(DEFAULT_IMPORT_FOLDER);
    bounded("folder", folder_name, 200)?;
    if folder_name.trim().is_empty() {
        return Err(IpcError::invalid("folder is empty"));
    }

    if !state
        .index
        .lock()
        .await
        .account_ids
        .iter()
        .any(|id| id == account_id)
    {
        return Err(IpcError::not_found("unknown account"));
    }

    // File checks before reading — a path that isn't a plain file is an
    // input error, not an io detail leak.
    let meta = std::fs::metadata(Path::new(path))
        .map_err(|_| IpcError::not_found("mbox file not found"))?;
    if !meta.is_file() {
        return Err(IpcError::invalid("path is not a regular file"));
    }
    if meta.len() > MAX_MBOX_BYTES {
        return Err(IpcError::invalid(format!(
            "mbox exceeds {} MiB cap",
            MAX_MBOX_BYTES / (1024 * 1024)
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| IpcError::invalid(format!("read failed: {e}")))?;
    if bytes.len() as u64 > MAX_MBOX_BYTES {
        return Err(IpcError::invalid(format!(
            "mbox exceeds {} MiB cap",
            MAX_MBOX_BYTES / (1024 * 1024)
        )));
    }

    let split = mbox::split_mbox(&bytes)
        .ok_or_else(|| IpcError::invalid("not an mbox file: no 'From ' separator found"))?;
    let now = now_unix();

    let mut view = MboxImportView {
        account_id: account_id.to_string(),
        folder: folder_name.to_string(),
        folder_id: 0,
        messages_found: split.messages.len() as u64,
        imported: 0,
        skipped_duplicates: 0,
        skipped_expunged: 0,
        failed: 0,
        truncated: split.messages.len() > MAX_MBOX_MESSAGES,
        rule_failures: 0,
        issues: Vec::new(),
    };
    if split.leading_junk {
        push_issue(
            &mut view,
            0,
            "bytes before first 'From ' separator ignored",
        );
    }

    let mut imported_uids: Vec<u64> = Vec::new();
    let mut imported_raw: Vec<Vec<u8>> = Vec::new();
    {
        let store = state.store.lock().await;
        let folder_id = store
            .ensure_folder(account_id, folder_name)
            .map_err(IpcError::from)?;
        view.folder_id = folder_id;
        // Locally-minted uids continue from the current max (same rule as
        // move_messages). Imported rows carry no server identity.
        let mut next_uid: i64 = store.max_uid(folder_id).map_err(IpcError::from)? + 1;

        for msg in split.messages.iter().take(MAX_MBOX_MESSAGES) {
            if msg.raw.is_empty() {
                view.failed += 1;
                push_issue(&mut view, msg.index as u64, "empty member");
                continue;
            }
            let mz = mbox::mozilla_status(&msg.raw);
            if mz.expunged {
                view.skipped_expunged += 1;
                continue;
            }
            let parsed = match parse_message(&msg.raw) {
                Ok(p) => p,
                Err(e) => {
                    view.failed += 1;
                    push_issue(
                        &mut view,
                        msg.index as u64,
                        &format!("unparseable: {}", bounded_detail(e.to_string())),
                    );
                    continue;
                }
            };
            // mail-parser is tolerant — a member that yields zero headers is
            // mbox padding/binary junk, not a message: skip it as a failure,
            // never store a blank row.
            if parsed.headers.is_empty() {
                view.failed += 1;
                push_issue(&mut view, msg.index as u64, "no parseable headers");
                continue;
            }
            if let Some(mid) = parsed.message_id.as_deref() {
                match store.account_has_message_id(account_id, mid) {
                    Ok(true) => {
                        view.skipped_duplicates += 1;
                        continue;
                    }
                    Ok(false) => {}
                    // A dedup read error must not lose a valid member —
                    // degrade to import like contacts-import does.
                    Err(_) => {}
                }
            }
            let uid = next_uid as u64;
            next_uid += 1;
            let meta = NewMessageMeta {
                uid,
                message_id: parsed.message_id.clone(),
                subject: parsed.subject.clone(),
                from_addr: parsed
                    .from
                    .first()
                    .map(|a| a.email.clone())
                    .or_else(|| msg.envelope_from.clone()),
                to_addrs: (!parsed.to.is_empty()).then(|| {
                    parsed
                        .to
                        .iter()
                        .map(|a| a.email.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
                date_unix: parsed.date_unix,
                size: Some(msg.raw.len() as u64),
                flags: mz.flags.iter().map(|f| f.to_string()).collect(),
                has_attachments: !parsed.attachments.is_empty(),
                snippet: Some(parsed.snippet.clone()),
                category: kiwi_mail::category::categorize(&parsed).category,
                unsub_http: parsed.unsubscribe.as_ref().and_then(|u| u.http_url.clone()),
                unsub_mailto: parsed.unsubscribe.as_ref().and_then(|u| u.mailto.clone()),
                unsub_oneclick: parsed.unsubscribe.as_ref().is_some_and(|u| u.one_click),
            };
            if let Err(e) = store
                .upsert_message(folder_id, &meta, now)
                .and_then(|_| store.store_body(folder_id, uid, &msg.raw).map(|_| ()))
            {
                view.failed += 1;
                push_issue(
                    &mut view,
                    msg.index as u64,
                    &format!("store: {}", bounded_detail(e.to_string())),
                );
                continue;
            }
            let _ = store.set_attachment_risk(folder_id, uid, &parsed.attach_risk);
            let _ = store.set_link_risk(folder_id, uid, &parsed.link_risk);
            // Same ingest evidence as the POP3 drop folder: rules + an
            // Authentication-Results stamp with no SMTP receipt (spf=none,
            // never a fabricated verdict).
            if kiwi_mail::rules::apply_on_ingest(
                &store,
                account_id,
                folder_id,
                uid,
                &parsed,
                kiwi_mail::rules::EvalStage::Full,
                now,
            )
            .is_err()
            {
                view.rule_failures += 1;
            }
            let stamp = auth_sealer().evaluate_and_stamp(&parsed, &msg.raw, now, None);
            let _ = store.set_auth(folder_id, uid, &stamp);
            view.imported += 1;
            imported_uids.push(uid);
            imported_raw.push(msg.raw.clone());
        }
    }

    // Folder registration + threading cache need the index — never while
    // holding the store lock (store → index ordering only).
    {
        let mut index = state.index.lock().await;
        index.remember_folder(account_id, view.folder_id, folder_name);
        index.save(&state.data_dir)?;
    }
    for (uid, raw) in imported_uids.iter().zip(imported_raw.iter()) {
        remember_threading(state, view.folder_id, *uid, raw).await;
    }

    state.audit.lock().await.record(
        "mbox-imported",
        &format!(
            "{account_id} → {folder_name}: found {} imported {} dup {} expunged {} failed {}{}",
            view.messages_found,
            view.imported,
            view.skipped_duplicates,
            view.skipped_expunged,
            view.failed,
            if view.truncated { " truncated" } else { "" },
        ),
        now,
    )?;
    Ok(view)
}

fn push_issue(view: &mut MboxImportView, index: u64, detail: &str) {
    if view.issues.len() < MAX_IMPORT_ISSUES {
        view.issues.push(MboxImportIssueView {
            index,
            detail: bounded_detail(detail.to_string()),
        });
    }
}

fn bounded_detail(mut s: String) -> String {
    s.truncate(MAX_ISSUE_DETAIL);
    while !s.is_char_boundary(s.len()) {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::types::{AddAccountInput, AuthInput, ServerInput};

    fn test_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kiwi-import-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn acct_input() -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming_protocol: "imap".into(),
            incoming: ServerInput {
                host: "imap.x.test".into(),
                port: 993,
                security: "tls".into(),
            },
            outgoing: ServerInput {
                host: "smtp.x.test".into(),
                port: 465,
                security: "tls".into(),
            },
            username: None,
            outgoing_username: None,
            incoming_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
                oauth2_ticket: None,
            }),
            outgoing_auth: None,
            accept_invalid_certs: false,
        }
    }

    fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> String {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().into_owned()
    }

    const GOOD_1: &[u8] = b"From sender1@x.test Sat Jan  4 10:00:00 2025\n\
        X-Mozilla-Status: 0005\n\
        From: Sender One <sender1@x.test>\nTo: a@x.test\n\
        Subject: imported one\nMessage-ID: <imp1@x.test>\nDate: Sat, 04 Jan 2025 10:00:00 +0000\n\
        \nbody one\n";
    const GOOD_2: &[u8] = b"From sender2@y.test Sat Jan  4 10:01:00 2025\n\
        From: Sender Two <sender2@y.test>\nTo: a@x.test\n\
        Subject: imported two\nMessage-ID: <imp2@x.test>\n\
        \nbody has an escaped\n>From realmail@z.test line\n";
    /// Member with no parseable headers — `parse_message` refuses it.
    const BAD: &[u8] = b"From ghost@x.test Sat Jan  4 10:02:00 2025\n\
        \xFF\xFE\x00garbage not a message\n";
    /// Thunderbird-deleted member (Expunged bit set).
    const EXPUNGED: &[u8] = b"From gone@x.test Sat Jan  4 10:03:00 2025\n\
        X-Mozilla-Status: 0009\n\
        From: Gone <gone@x.test>\nSubject: deleted\nMessage-ID: <gone@x.test>\n\nwas here\n";

    fn fixture_mbox() -> Vec<u8> {
        [GOOD_1, GOOD_2, BAD, EXPUNGED].concat()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn import_multi_member_with_unescape_expunge_and_bad_skip() {
        let dir = test_dir("multi");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let view = crate::commands::accounts::add_account_impl(&state, acct_input())
            .await
            .unwrap();
        let path = write_fixture(&dir, "in.mbox", &fixture_mbox());

        let r = import_mbox_impl(&state, &view.id, &path, None)
            .await
            .expect("import");
        assert_eq!(r.folder, "Import");
        assert_eq!(r.messages_found, 4);
        assert_eq!(r.imported, 2, "{:?}", r.issues);
        assert_eq!(r.skipped_expunged, 1);
        assert_eq!(r.failed, 1); // BAD member skipped, not fatal
        assert!(!r.truncated);
        assert_eq!(r.issues.len(), 1);
        assert_eq!(r.issues[0].index, 3);

        // Rows land as real store rows in the target folder (stored
        // message_ids are normalized without <>).
        {
            let store = state.store.lock().await;
            assert!(
                store
                    .account_has_message_id(&view.id, "imp1@x.test")
                    .unwrap()
            );
            assert!(
                store
                    .account_has_message_id(&view.id, "imp2@x.test")
                    .unwrap()
            );
            assert!(
                !store
                    .account_has_message_id(&view.id, "gone@x.test")
                    .unwrap()
            );
        }

        // X-Mozilla-Status mapped — read them back through the same
        // projection the UI does.
        let msgs =
            crate::commands::mail::list_messages_impl(&state, view.id.clone(), r.folder_id, Some(10))
                .await
                .unwrap();
        let m1 = msgs
            .iter()
            .find(|m| m.subject.as_deref() == Some("imported one"))
            .unwrap();
        assert!(!m1.unread, "X-Mozilla-Status 0005 → \\Seen");
        assert!(m1.starred, "X-Mozilla-Status 0005 → \\Flagged");
        let m2 = msgs.iter().find(|m| m.subject.as_deref() == Some("imported two")).unwrap();
        assert!(m2.unread, "no status header → unread");

        // >From unescape landed in the stored body verbatim.
        let src = crate::commands::mail::message_source_impl(
            state.clone(),
            view.id.clone(),
            r.folder_id,
            m2.uid,
        )
        .await
        .unwrap();
        assert!(src.source.contains("\nFrom realmail@z.test"), "{}", src.source);
        assert!(!src.source.contains(">From realmail"));

        // Envelope preserved: Date header parsed through the MIME pipeline.
        assert_eq!(m1.date_unix, Some(1735984800));

        // Audit row.
        let log = std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("mbox-imported"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn import_dedups_on_message_id_and_rejects_bad_inputs() {
        let dir = test_dir("dedup");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let view = crate::commands::accounts::add_account_impl(&state, acct_input())
            .await
            .unwrap();
        let path = write_fixture(&dir, "in.mbox", &fixture_mbox());

        import_mbox_impl(&state, &view.id, &path, Some("Archive"))
            .await
            .unwrap();
        let second = import_mbox_impl(&state, &view.id, &path, Some("Archive"))
            .await
            .unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicates, 2);
        assert_eq!(second.skipped_expunged, 1);
        assert_eq!(second.failed, 1);

        // Unknown account → not-found; missing file → not-found; a folder
        // path → invalid; garbage file → invalid ("not an mbox").
        assert_eq!(
            import_mbox_impl(&state, "ghost", &path, None)
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        assert_eq!(
            import_mbox_impl(&state, &view.id, &dir.join("nope.mbox").to_string_lossy(), None)
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        assert_eq!(
            import_mbox_impl(&state, &view.id, &dir.to_string_lossy(), None)
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        let junk = write_fixture(&dir, "junk.mbox", b"definitely not mbox\n");
        assert_eq!(
            import_mbox_impl(&state, &view.id, &junk, None)
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn import_is_lock_gated() {
        let dir = test_dir("locked");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        crate::commands::accounts::add_account_impl(&state, acct_input())
            .await
            .unwrap();
        state.trust.lock().await.force_lock();
        // The gate lives at the IPC wrapper — prove the same check the
        // command runs refuses while locked.
        let err = gate(&state).await.unwrap_err();
        assert_eq!(err.code, "locked");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
