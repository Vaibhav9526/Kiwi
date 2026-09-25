//! `kiwi_mailbox_export_mbox` (T-316): Berkeley-mbox export — the mirror
//! of `kiwi_import_mbox` (T-309). Wire format is mboxrd per
//! `kiwi_mail::mbox` — the same CRLF/`>From` escaping conventions the
//! importer reads (`From ` separators, `^>*From ` lines gain one `>`,
//! X-Mozilla-Status stamped from stored flags so flags round-trip).
//!
//! Deliberate semantics:
//!
//! - **Honest `partial`.** Every store row is accounted for: a row whose
//!   RFC822 body can't be obtained (envelope-only, or the on-demand IMAP
//!   fetch failed) is omitted from the file and counted in `skipped`;
//!   `partial` flips true whenever the file doesn't carry every row.
//! - **Body loading is honest, not synthesized.** Bodies come from
//!   `load_body_raw` — stored bytes verbatim, else one bounded on-demand
//!   IMAP `BODY[]` fetch. Nothing is reconstructed from envelope fields.
//!   A run of consecutive load failures trips a breaker so a dead server
//!   turns into `skipped` rows, not thousands of connection attempts.
//! - **Atomic write.** The file is built at `<dest>.kiwi-part` and renamed
//!   over the destination — a crash never leaves a truncated mbox at the
//!   chosen path.
//! - **Bounded.** `MAX_EXPORT_MESSAGES` caps processed rows (overflow is
//!   `truncated`); destination must be a writable path inside an existing
//!   directory (fail-closed on dir errors); audit is ids + counts only —
//!   never the path, never subjects.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::State;

use kiwi_mail::mbox;

use super::mail::load_body_raw;
use super::{bounded, gate, run_mail_io};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::MboxExportView;

/// Rows processed per export; the remainder is reported via `truncated`.
/// Matches the import-side member cap — the round trip is symmetric.
const MAX_EXPORT_MESSAGES: usize = 50_000;
/// Consecutive body-load failures before the on-demand fetch is abandoned
/// for the rest of the run — a dead/unreachable server costs one short
/// burst of connection attempts, not one per row.
const MAX_CONSECUTIVE_LOAD_FAILURES: u32 = 8;

/// `kiwi_mailbox_export_mbox { folderId, destPath }` → `MboxExportView`.
/// Lock-gated. `folderId` must name a real folder on a registered account;
/// `destPath` must be a writable path inside an existing directory.
#[tauri::command]
pub async fn kiwi_mailbox_export_mbox(
    state: State<'_, Arc<AppState>>,
    folder_id: i64,
    dest_path: String,
) -> CmdResult<MboxExportView> {
    gate(state.inner()).await?;
    let st = Arc::clone(state.inner());
    run_mail_io(st, move |s| async move {
        export_mbox_impl(s, folder_id, &dest_path).await
    })
    .await
}

/// `load_body_raw`'s on-demand IMAP fetch makes the future `!Send` — the
/// impl therefore runs on `run_mail_io`'s blocking thread like every other
/// command that touches a protocol client.
pub(crate) async fn export_mbox_impl(
    state: Arc<AppState>,
    folder_id: i64,
    dest_path: &str,
) -> CmdResult<MboxExportView> {
    bounded("destPath", dest_path, 4096)?;
    if dest_path.trim().is_empty() {
        return Err(IpcError::invalid("destPath is empty"));
    }
    let state = &state;

    // Folder must exist and belong to a registered account. folder_id is a
    // global key, so ownership is inherent — the account lookup doubles as
    // the "folder not on a real account" check.
    let (account_id, folder_name, metas) = {
        let store = state.store.lock().await;
        let meta = store
            .folder_meta(folder_id)?
            .ok_or_else(|| IpcError::not_found("unknown folder"))?;
        if !state
            .index
            .lock()
            .await
            .account_ids
            .iter()
            .any(|id| id == &meta.account_id)
        {
            return Err(IpcError::not_found("folder not on account"));
        }
        let rows = store.list_messages(folder_id, MAX_EXPORT_MESSAGES as u32 + 1)?;
        (meta.account_id, meta.name, rows)
    };
    let truncated = metas.len() > MAX_EXPORT_MESSAGES;
    let metas = &metas[..metas.len().min(MAX_EXPORT_MESSAGES)];

    // Destination checks before opening — a directory, a missing parent, or
    // an empty leaf are input errors, not io detail leaks. Mirrors the
    // dest-validation block in `security::write_export_atomically` (T-320) —
    // including the canonicalized app-data-dir refusal (an export must never
    // overwrite mail.db, the audit log, or a stored body). Kept local because
    // this writer streams instead of taking a byte slice.
    let dest = Path::new(dest_path);
    if dest.is_dir() {
        return Err(IpcError::invalid("destPath is a directory"));
    }
    match dest.parent() {
        Some(p) if p.as_os_str().is_empty() => {}
        Some(p) if p.is_dir() => {}
        Some(_) => return Err(IpcError::not_found("destination directory not found")),
        None => return Err(IpcError::invalid("destPath has no parent directory")),
    }
    if dest.file_name().is_none() {
        return Err(IpcError::invalid("destPath names no file"));
    }
    let canon_data = state
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| state.data_dir.clone());
    let parent = dest.parent().unwrap_or(dest);
    let resolved_parent = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    if resolved_parent.starts_with(&canon_data) {
        return Err(IpcError::invalid(
            "destPath inside the app data dir is refused",
        ));
    }

    let tmp: PathBuf = PathBuf::from(format!("{dest_path}.kiwi-part"));
    let mut out = BufWriter::new(
        std::fs::File::create(&tmp).map_err(|e| IpcError::invalid(format!("create: {e}")))?,
    );

    let mut view = MboxExportView {
        account_id: account_id.clone(),
        folder: folder_name,
        folder_id,
        exported: 0,
        skipped: 0,
        bytes: 0,
        partial: false,
        truncated,
    };
    let mut consecutive_failures = 0u32;

    let result: CmdResult<()> = async {
        for m in metas {
            // Breaker: once loads keep failing, stop spending round-trips —
            // remaining rows count as skipped without a fetch attempt.
            let raw = if consecutive_failures < MAX_CONSECUTIVE_LOAD_FAILURES {
                match load_body_raw(state, &account_id, folder_id, m.uid).await {
                    Ok(raw) => {
                        consecutive_failures = 0;
                        raw
                    }
                    Err(_) => {
                        consecutive_failures += 1;
                        None
                    }
                }
            } else {
                None
            };
            let Some(raw) = raw else {
                view.skipped += 1;
                continue;
            };
            write_member(
                &mut out,
                &raw,
                m.from_addr.as_deref(),
                m.date_unix,
                &m.flags,
            )?;
            view.exported += 1;
        }
        out.flush()
            .map_err(|e| IpcError::invalid(format!("write: {e}")))?;
        Ok(())
    }
    .await;

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    view.bytes = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
    view.partial = view.skipped > 0 || view.truncated;

    // Temp → destination. On Windows rename refuses an existing target;
    // the user chose this path, so a prior export is replaced — remove and
    // retry once (the only portable overwrite path).
    if let Err(e) = std::fs::rename(&tmp, dest) {
        if dest.exists() {
            let _ = std::fs::remove_file(dest);
            std::fs::rename(&tmp, dest).map_err(|e2| IpcError::invalid(format!("rename: {e2}")))?;
        } else {
            let _ = std::fs::remove_file(&tmp);
            return Err(IpcError::invalid(format!("rename: {e}")));
        }
    }

    state.audit.lock().await.record(
        "mbox-exported",
        &format!(
            "{account_id} folder {folder_id}: exported {} skipped {} bytes {}{}",
            view.exported,
            view.skipped,
            view.bytes,
            if view.truncated { " truncated" } else { "" },
        ),
        now_unix(),
    )?;
    Ok(view)
}

/// One mbox member: separator → optional Mozilla status stamp → escaped
/// payload → guaranteed trailing newline (a payload not ending in `\n`
/// would fuse with the next separator).
fn write_member<W: Write>(
    out: &mut W,
    raw: &[u8],
    from_addr: Option<&str>,
    date_unix: Option<i64>,
    flags: &[String],
) -> Result<(), IpcError> {
    out.write_all(&mbox::separator(from_addr, date_unix))
        .map_err(|e| IpcError::invalid(format!("write: {e}")))?;
    if !mbox::has_mozilla_status(raw)
        && let Some(stamp) = mbox::mozilla_status_lines(flags)
    {
        out.write_all(&stamp)
            .map_err(|e| IpcError::invalid(format!("write: {e}")))?;
    }
    let escaped = mbox::escape_for_mbox(raw);
    out.write_all(&escaped)
        .map_err(|e| IpcError::invalid(format!("write: {e}")))?;
    if !escaped.ends_with(b"\n") {
        out.write_all(b"\n")
            .map_err(|e| IpcError::invalid(format!("write: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AddAccountInput, AuthInput, ServerInput};

    fn test_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kiwi-export-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    /// Destinations must live OUTSIDE `state.data_dir` (the guard refuses
    /// anything under it), so tests export to a sibling temp dir.
    fn out_dir(tag: &str) -> PathBuf {
        let d = test_dir(&format!("{tag}-out"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn acct_input(email: &str) -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: email.into(),
            incoming_protocol: "pop3".into(),
            incoming: ServerInput {
                host: "pop.x.test".into(),
                port: 995,
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

    async fn seed(
        state: &Arc<AppState>,
        account_id: &str,
        folder: &str,
        bodies: &[(&[u8], Vec<&str>)],
    ) -> i64 {
        let store = state.store.lock().await;
        let fid = store.ensure_folder(account_id, folder).unwrap();
        for (i, (raw, flags)) in bodies.iter().enumerate() {
            let parsed = kiwi_mail::mime::parse_message(raw).unwrap();
            let meta = kiwi_mail::store::NewMessageMeta {
                uid: (i + 1) as u64,
                message_id: parsed.message_id.clone(),
                subject: parsed.subject.clone(),
                from_addr: parsed.from.first().map(|a| a.email.clone()),
                to_addrs: None,
                date_unix: parsed.date_unix,
                size: Some(raw.len() as u64),
                flags: flags.iter().map(|f| f.to_string()).collect(),
                has_attachments: false,
                snippet: None,
                category: kiwi_mail::category::Category::Primary,
                unsub_http: None,
                unsub_mailto: None,
                unsub_oneclick: false,
            };
            store.upsert_message(fid, &meta, 0).unwrap();
            store.store_body(fid, meta.uid, raw).unwrap();
        }
        fid
    }

    const MSG_SEEN: &[u8] = b"From: Alice <a@x.test>\r\nTo: b@y.test\r\nSubject: one\r\nMessage-ID: <e1@x>\r\nDate: Sat, 04 Jan 2025 10:00:00 +0000\r\n\r\nbody one\r\n";
    const MSG_FROM_LINE: &[u8] = b"From: Bob <b@y.test>\r\nSubject: two\r\nMessage-ID: <e2@x>\r\n\r\nplain\r\nFrom sneaky@z.test\r\n>From already\r\n";
    const MSG_UNREAD: &[u8] =
        b"From: c@z.test\r\nSubject: three\r\nMessage-ID: <e3@x>\r\n\r\nbody three\r\n";

    #[tokio::test(flavor = "current_thread")]
    async fn export_roundtrips_through_the_import_parser() {
        let dir = test_dir("roundtrip");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let view = crate::commands::accounts::add_account_impl(&state, acct_input("a@x.test"))
            .await
            .unwrap();
        let fid = seed(
            &state,
            &view.id,
            "INBOX",
            &[
                (MSG_SEEN, vec!["\\Seen", "\\Flagged"]),
                (MSG_FROM_LINE, vec![]),
                (MSG_UNREAD, vec!["\\Seen", "\\Junk"]),
            ],
        )
        .await;
        let od = out_dir("roundtrip");
        let dest = od.join("out.mbox").to_string_lossy().into_owned();

        let r = export_mbox_impl(state.clone(), fid, &dest).await.unwrap();
        assert_eq!(r.exported, 3);
        assert_eq!(r.skipped, 0);
        assert!(!r.partial && !r.truncated);
        assert!(r.bytes > 0);

        // The written file parses under A19's own splitter — the real
        // format-agreement proof.
        let bytes = std::fs::read(&dest).unwrap();
        let split = mbox::split_mbox(&bytes).unwrap();
        assert_eq!(split.messages.len(), 3);
        // Bare `From ` and `>From ` body lines escape then unescape back to
        // the byte-identical payload — the write/read round trip is exact.
        let second = &split.messages[1].raw;
        assert_eq!(
            std::str::from_utf8(second).unwrap(),
            std::str::from_utf8(MSG_FROM_LINE).unwrap()
        );
        // Status stamps round-trip: \Seen+\Flagged → status 0005;
        // \Seen+\Junk → status 0001 + status2 00080000.
        let s0 = mbox::mozilla_status(&split.messages[0].raw);
        assert!(s0.flags.contains(&"\\Seen") && s0.flags.contains(&"\\Flagged"));
        let s2 = mbox::mozilla_status(&split.messages[2].raw);
        assert!(s2.flags.contains(&"\\Seen") && s2.flags.contains(&"\\Junk"));
        // Audit row — ids + counts, never the path.
        let log = std::fs::read_to_string(state.data_dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("mbox-exported"), "{log}");
        assert!(!log.contains("out.mbox"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&od);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_marks_envelope_only_rows_partial() {
        let dir = test_dir("partial");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let view = crate::commands::accounts::add_account_impl(&state, acct_input("b@x.test"))
            .await
            .unwrap();
        let fid = seed(&state, &view.id, "INBOX", &[(MSG_SEEN, vec![])]).await;
        // A second row with a meta but no stored body → envelope-only.
        {
            let store = state.store.lock().await;
            let meta = kiwi_mail::store::NewMessageMeta {
                uid: 9,
                message_id: Some("nobody@x".into()),
                subject: Some("no body".into()),
                from_addr: None,
                to_addrs: None,
                date_unix: None,
                size: None,
                flags: vec![],
                has_attachments: false,
                snippet: None,
                category: kiwi_mail::category::Category::Primary,
                unsub_http: None,
                unsub_mailto: None,
                unsub_oneclick: false,
            };
            store.upsert_message(fid, &meta, 0).unwrap();
        }
        let od = out_dir("partial");
        let dest = od.join("out.mbox").to_string_lossy().into_owned();
        let r = export_mbox_impl(state.clone(), fid, &dest).await.unwrap();
        assert_eq!(r.exported, 1);
        assert_eq!(r.skipped, 1);
        assert!(r.partial);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&od);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_rejects_bad_destinations_and_unknown_folders() {
        let dir = test_dir("dests");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        let view = crate::commands::accounts::add_account_impl(&state, acct_input("c@x.test"))
            .await
            .unwrap();
        let fid = seed(&state, &view.id, "INBOX", &[(MSG_SEEN, vec![])]).await;

        // Directory dest, missing parent, empty path → input errors.
        assert_eq!(
            export_mbox_impl(state.clone(), fid, &dir.to_string_lossy())
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        assert_eq!(
            export_mbox_impl(
                state.clone(),
                fid,
                &dir.join("nope").join("x.mbox").to_string_lossy()
            )
            .await
            .unwrap_err()
            .code,
            "not-found"
        );
        assert_eq!(
            export_mbox_impl(state.clone(), fid, "")
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        // Unknown folder id.
        let od = out_dir("dests");
        assert_eq!(
            export_mbox_impl(state.clone(), 999999, &od.join("x.mbox").to_string_lossy())
                .await
                .unwrap_err()
                .code,
            "not-found"
        );
        // Inside the app data dir — must never overwrite mail.db/audit log.
        let inside = state.data_dir.join("pwned.mbox");
        assert_eq!(
            export_mbox_impl(state.clone(), fid, &inside.to_string_lossy())
                .await
                .unwrap_err()
                .code,
            "invalid-input"
        );
        assert!(!inside.exists());
        // No partial files linger after failures.
        assert!(!od.join("x.mbox.kiwi-part").exists());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&od);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_is_lock_gated() {
        let dir = test_dir("locked");
        let state = Arc::new(AppState::open_test(dir.clone()).unwrap());
        crate::commands::accounts::add_account_impl(&state, acct_input("d@x.test"))
            .await
            .unwrap();
        state.trust.lock().await.force_lock();
        let err = gate(&state).await.unwrap_err();
        assert_eq!(err.code, "locked");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
