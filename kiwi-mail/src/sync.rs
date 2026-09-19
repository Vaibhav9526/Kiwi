//! Folder sync engine: incremental IMAP sync via UIDVALIDITY/UIDs, and a
//! POP3 download-and-dedup pass.
//!
//! IMAP strategy (RFC 3501 + UIDPLUS):
//! 1. SELECT the folder → UIDVALIDITY/UIDNEXT/EXISTS.
//! 2. UIDVALIDITY changed (or unknown locally) → wipe local messages for the
//!    folder; UIDs are meaningless across a validity change.
//! 3. `UID SEARCH ALL` for the remote UID set (bounded by folder size; the
//!    chunking below also bounds per-command work).
//! 4. New UIDs → `UID FETCH (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE)`
//!    in chunks; known UIDs → `UID FETCH (UID FLAGS)` flag refresh.
//! 5. Local UIDs absent remotely → expunged.
//!
//! POP3 has no server-side flags/folders: `UIDL` gives stable identities,
//! `RETR` downloads unseen drops; DELE happens only when the caller's
//! policy says so (we never delete by default).

use std::collections::BTreeSet;

use crate::error::Result;
use crate::imap::{FetchItem, ImapClient};
use crate::pop3::Pop3Client;
use crate::store::{MailStore, NewMessageMeta};

/// Chunk size for UID FETCH commands — bounds command length and response
/// memory independently of folder size.
const FETCH_CHUNK: usize = 200;

#[derive(Debug, Clone, Default)]
pub struct FolderSyncReport {
    pub folder: String,
    pub uid_validity_reset: bool,
    pub new_messages: u64,
    pub flag_updates: u64,
    pub expunged: u64,
    pub remote_exists: u64,
}

/// One incremental sync pass for a single IMAP folder.
pub async fn sync_folder(
    client: &mut ImapClient,
    store: &MailStore,
    account_id: &str,
    folder: &str,
    now: i64,
) -> Result<FolderSyncReport> {
    let sel = client.select(folder, false).await?;
    let folder_id = store.ensure_folder(account_id, folder)?;

    let mut report = FolderSyncReport {
        folder: folder.into(),
        remote_exists: sel.exists,
        ..Default::default()
    };

    // 2. UIDVALIDITY reset detection.
    let prior = store.folder_meta(folder_id)?.and_then(|f| f.uid_validity);
    if prior.is_some() && prior != sel.uid_validity {
        report.uid_validity_reset = true;
        store.clear_folder_messages(folder_id)?;
    }
    let highest = sel.uid_next.unwrap_or(0).saturating_sub(1);
    store.set_folder_sync_state(folder_id, sel.uid_validity, sel.uid_next, highest)?;

    // 3. Remote UID set.
    let remote: BTreeSet<u64> = client.uid_search("ALL").await?.into_iter().collect();
    let local: BTreeSet<u64> = store.folder_uids(folder_id)?.into_iter().collect();

    // 4a. New messages: metadata fetch in bounded chunks.
    let new_uids: Vec<u64> = remote.difference(&local).copied().collect();
    for chunk in new_uids.chunks(FETCH_CHUNK) {
        let set = uid_set(chunk);
        let items = client
            .uid_fetch(&set, &["UID", "FLAGS", "ENVELOPE", "RFC822.SIZE", "INTERNALDATE"])
            .await?;
        for item in &items {
            store.upsert_message(folder_id, &to_meta(item), now)?;
            report.new_messages += 1;
        }
    }

    // 4b. Flag refresh for UIDs present on both sides.
    let shared: Vec<u64> = remote.intersection(&local).copied().collect();
    for chunk in shared.chunks(FETCH_CHUNK) {
        let set = uid_set(chunk);
        let items = client.uid_fetch(&set, &["UID", "FLAGS"]).await?;
        for item in &items {
            if let Some(uid) = item.uid
                && store.update_flags(folder_id, uid, &item.flags)?
            {
                report.flag_updates += 1;
            }
        }
    }

    // 5. Expunged locally.
    let gone: Vec<u64> = local.difference(&remote).copied().collect();
    report.expunged = store.delete_messages(folder_id, &gone)?;

    Ok(report)
}

/// Fetch full bodies for messages that only have metadata so far
/// (`BODY[]` per message; callers may throttle/queue this).
pub async fn fetch_missing_bodies(
    client: &mut ImapClient,
    store: &MailStore,
    folder_id: i64,
    limit: usize,
) -> Result<u64> {
    let missing = store.uids_without_body(folder_id)?;
    let mut done = 0u64;
    for uid in missing.into_iter().take(limit) {
        let items = client
            .uid_fetch(&uid.to_string(), &["UID", "BODY[]"])
            .await?;
        if let Some(item) = items.first()
            && let Some((_, bytes)) = item.bodies.first()
        {
            store.store_body(folder_id, uid, bytes)?;
            done += 1;
        }
    }
    Ok(done)
}

#[derive(Debug, Clone, Default)]
pub struct Pop3SyncReport {
    pub remote_drops: u64,
    pub downloaded: u64,
    pub deleted_remote: u64,
}

/// POP3 ingest: UIDL-diff → RETR unseen → optional DELE (leave-on-server is
/// the default; deleting is an explicit caller choice).
pub async fn sync_pop3(
    client: &mut Pop3Client,
    store: &MailStore,
    account_id: &str,
    folder_name: &str,
    delete_after_download: bool,
    now: i64,
) -> Result<Pop3SyncReport> {
    let folder_id = store.ensure_folder(account_id, folder_name)?;
    let uidls = client.uidl().await?;
    let mut report = Pop3SyncReport {
        remote_drops: uidls.len() as u64,
        ..Default::default()
    };
    for (number, uidl) in uidls {
        if store.pop3_seen_contains(account_id, &uidl)? {
            continue;
        }
        let bytes = client.retr(number).await?;
        let parsed = crate::mime::parse_message(&bytes).unwrap_or_default();
        let meta = NewMessageMeta {
            // POP3 has no UIDs; use the message number — dedup is via UIDL.
            uid: number as u64,
            message_id: parsed.message_id.clone(),
            subject: parsed.subject.clone(),
            from_addr: parsed.from.first().map(|a| a.email.clone()),
            to_addrs: Some(
                parsed
                    .to
                    .iter()
                    .map(|a| a.email.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            date_unix: parsed.date_unix,
            size: Some(bytes.len() as u64),
            flags: vec![],
            has_attachments: !parsed.attachments.is_empty(),
            snippet: Some(parsed.snippet.clone()),
        };
        store.upsert_message(folder_id, &meta, now)?;
        store.store_body(folder_id, number as u64, &bytes)?;
        store.pop3_mark_seen(account_id, &uidl, now)?;
        report.downloaded += 1;
        if delete_after_download {
            client.dele(number).await?;
            report.deleted_remote += 1;
        }
    }
    Ok(report)
}

/// Compact UID set notation ("1,2,3" or collapsed "a:b" runs).
fn uid_set(uids: &[u64]) -> String {
    uids.iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn to_meta(item: &FetchItem) -> NewMessageMeta {
    let env = item.envelope.clone().unwrap_or_default();
    let join = |list: &[crate::imap::Mailbox]| {
        let s = list
            .iter()
            .map(|m| m.email.clone())
            .collect::<Vec<_>>()
            .join(", ");
        (!s.is_empty()).then_some(s)
    };
    NewMessageMeta {
        uid: item.uid.unwrap_or(0),
        message_id: env.message_id,
        subject: env.subject,
        from_addr: join(&env.from),
        to_addrs: join(&env.to),
        date_unix: None, // INTERNALDATE is a display string; parsed by mime later
        size: item.size,
        flags: item.flags.clone(),
        has_attachments: item
            .bodystructure
            .as_ref()
            .map(has_attachment_parts)
            .unwrap_or(false),
        snippet: None,
    }
}

fn has_attachment_parts(bs: &crate::imap::BodyStructure) -> bool {
    use crate::imap::BodyStructure::*;
    match bs {
        Multi { parts, .. } => parts.iter().any(has_attachment_parts),
        Single {
            media_type,
            params,
            ..
        } => {
            // Heuristic: non-text leaf with a filename param, or any
            // application/* / image/* leaf not inline text.
            let has_filename = params
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("name"));
            let non_text = !media_type.eq_ignore_ascii_case("text");
            has_filename || non_text
        }
        Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_set_format() {
        assert_eq!(uid_set(&[1, 2, 5]), "1,2,5");
        assert_eq!(uid_set(&[]), "");
    }

    #[test]
    fn attachment_detection() {
        use crate::imap::BodyStructure::*;
        let att = Single {
            media_type: "application".into(),
            subtype: "pdf".into(),
            params: vec![("name".into(), "d.pdf".into())],
            encoding: "base64".into(),
            octets: 100,
        };
        assert!(has_attachment_parts(&att));
        let plain = Single {
            media_type: "text".into(),
            subtype: "plain".into(),
            params: vec![],
            encoding: "7bit".into(),
            octets: 10,
        };
        assert!(!has_attachment_parts(&plain));
        let multi = Multi {
            subtype: "mixed".into(),
            parts: vec![plain.clone(), att.clone()],
            params: vec![],
        };
        assert!(has_attachment_parts(&multi));
    }
}
