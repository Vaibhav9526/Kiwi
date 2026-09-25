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

/// Deferred-eval cap per sync pass (T-244): at most this many stored-body
/// messages get their full-parse eval per `sync_folder` call. Leftovers
/// keep their watermark slot and run on subsequent passes — a bulk
/// body-arrival (first upgrade, batch fetch) never stalls one sync.
const DEFERRED_EVAL_LIMIT: u32 = 200;

#[derive(Debug, Clone, Default)]
pub struct FolderSyncReport {
    pub folder: String,
    pub uid_validity_reset: bool,
    pub new_messages: u64,
    pub flag_updates: u64,
    pub expunged: u64,
    pub remote_exists: u64,
    /// Rule-apply errors this pass swallowed (T-244) — surfacing the count
    /// keeps a misbehaving rule visible without failing the sync.
    pub rule_failures: u64,
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
    // T-233: rules decide placement at ingest. Gated to INBOX — syncing
    // Sent/Archive/etc. must not re-fire rules on already-filed mail;
    // an explicit re-run is `rules::apply_now`. Envelope facts only at
    // this stage (sender/recipient/subject) — header/body predicates
    // refine when the body lands (`fetch_missing_bodies`). A block-list
    // verdict trashes the message before its body is ever fetched.
    let rules_at_ingest = folder.eq_ignore_ascii_case("INBOX");
    for chunk in new_uids.chunks(FETCH_CHUNK) {
        let set = uid_set(chunk);
        let items = client
            .uid_fetch(
                &set,
                &["UID", "FLAGS", "ENVELOPE", "RFC822.SIZE", "INTERNALDATE"],
            )
            .await?;
        for item in &items {
            store.upsert_message(folder_id, &to_meta(item), now)?;
            report.new_messages += 1;
            if rules_at_ingest && let Some(uid) = item.uid {
                // Envelope-stage eval: sender/recipient/subject only.
                // Errors are counted, never fatal — the message is stored
                // either way. A failed apply writes no watermark, so the
                // full eval still runs once the body lands (pending queue,
                // step 6).
                if crate::rules::apply_on_ingest(
                    store,
                    account_id,
                    folder_id,
                    uid,
                    &envelope_pseudo(item),
                    crate::rules::EvalStage::Envelope,
                    now,
                )
                .is_err()
                {
                    report.rule_failures += 1;
                }
            }
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

    // 6. Deferred full-parse eval (T-244): INBOX messages whose bodies
    // arrived — by *any* path — since their envelope-stage eval get the
    // complete predicate set now. This is the "re-evaluated at next sync"
    // contract: the on-view loader stays unhooked so a rule never moves a
    // message while it is open, and the watermark is written only on a
    // successful apply (failures count and retry). Bounded per pass;
    // leftovers stay pending for the next sync.
    if rules_at_ingest {
        for uid in store.uids_pending_body_eval(folder_id, DEFERRED_EVAL_LIMIT)? {
            let Some(path) = store.body_file(folder_id, uid)? else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(parsed) = crate::mime::parse_message(&bytes) else {
                continue;
            };
            if crate::rules::apply_on_ingest(
                store,
                account_id,
                folder_id,
                uid,
                &parsed,
                crate::rules::EvalStage::Full,
                now,
            )
            .is_err()
            {
                report.rule_failures += 1;
            }
        }
    }

    Ok(report)
}

/// Fetch full bodies for messages that only have metadata so far
/// (`BODY[]` per message; callers may throttle/queue this).
///
/// Body fetch only — no Authentication-Results stamp is written. Kept as the
/// default entry point so existing callers (and the transcript-replay test
/// harness) are unaffected; use [`fetch_missing_bodies_with_auth`] to stamp.
pub async fn fetch_missing_bodies(
    client: &mut ImapClient,
    store: &MailStore,
    folder_id: i64,
    limit: usize,
    now: i64,
) -> Result<u64> {
    fetch_missing_bodies_inner(client, store, folder_id, limit, now, None, None).await
}

/// [`fetch_missing_bodies`] plus the T-232 Authentication-Results stamp.
///
/// `sealer` supplies the DNS seam; `receipt` is the optional SMTP receipt
/// context SPF needs (absent on IMAP, where the client IP and envelope
/// sender are not knowable — SPF then records `none` with an explicit
/// comment rather than a fabricated verdict).
pub async fn fetch_missing_bodies_with_auth(
    client: &mut ImapClient,
    store: &MailStore,
    folder_id: i64,
    limit: usize,
    now: i64,
    sealer: &dyn crate::authstamp::AuthSealer,
    receipt: Option<&crate::authstamp::SmtpReceipt>,
) -> Result<u64> {
    fetch_missing_bodies_inner(client, store, folder_id, limit, now, Some(sealer), receipt).await
}

async fn fetch_missing_bodies_inner(
    client: &mut ImapClient,
    store: &MailStore,
    folder_id: i64,
    limit: usize,
    now: i64,
    sealer: Option<&dyn crate::authstamp::AuthSealer>,
    receipt: Option<&crate::authstamp::SmtpReceipt>,
) -> Result<u64> {
    let missing = store.uids_without_body(folder_id)?;
    // T-233: rules refine on the full parse — the INBOX-only gate matches
    // `sync_folder`'s (other folders are already-filed mail).
    let (inbox_scope, account_id) = match store.folder_meta(folder_id)? {
        Some(m) => (m.name.eq_ignore_ascii_case("INBOX"), m.account_id),
        None => (false, String::new()),
    };
    let mut done = 0u64;
    for uid in missing.into_iter().take(limit) {
        let items = client
            .uid_fetch(&uid.to_string(), &["UID", "BODY[]"])
            .await?;
        if let Some(item) = items.first()
            && let Some((_, bytes)) = item.bodies.first()
        {
            store.store_body(folder_id, uid, bytes)?;
            // Headers just arrived: refine the envelope-only category and
            // fill the unsubscribe offer. Parse failures keep the existing
            // values (absent fact, no guess).
            if let Ok(parsed) = crate::mime::parse_message(bytes) {
                let category = crate::category::categorize(&parsed).category;
                let _ = store.set_category(folder_id, uid, category);
                if let Some(info) = &parsed.unsubscribe {
                    let _ = store.set_unsubscribe(folder_id, uid, info);
                }
                // Full predicates now — body/header/attachment matchers
                // only become decidable here. Flag merges and
                // already-moved no-ops make re-eval idempotent. Errors are
                // swallowed here, not lost: a failed apply writes no
                // watermark, so the next `sync_folder` deferred pass
                // retries it (and counts it against `rule_failures`).
                if inbox_scope {
                    let _ = crate::rules::apply_on_ingest(
                        store,
                        &account_id,
                        folder_id,
                        uid,
                        &parsed,
                        crate::rules::EvalStage::Full,
                        now,
                    );
                }
                // T-232: Authentication-Results. Runs only when the caller
                // supplied a resolver; `None` writes no stamp (see
                // `authstamp::AuthSealer`). Failures are swallowed — a
                // security-stamp problem must not fail the body fetch.
                if let Some(sealer) = sealer {
                    let stamp = sealer.evaluate_and_stamp(&parsed, bytes, now, receipt);
                    let _ = store.set_auth(folder_id, uid, &stamp);
                }
            }
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
    /// Rule-apply errors swallowed this pass (T-244) — same contract as
    /// `FolderSyncReport::rule_failures`.
    pub rule_failures: u64,
}

/// POP3 ingest: UIDL-diff → RETR unseen → optional DELE (leave-on-server is
/// the default; deleting is an explicit caller choice).
///
/// Body ingest only — no Authentication-Results stamp. Use
/// [`sync_pop3_with_auth`] to stamp.
pub async fn sync_pop3(
    client: &mut Pop3Client,
    store: &MailStore,
    account_id: &str,
    folder_name: &str,
    delete_after_download: bool,
    now: i64,
) -> Result<Pop3SyncReport> {
    sync_pop3_inner(
        client,
        store,
        account_id,
        folder_name,
        delete_after_download,
        now,
        None,
        None,
    )
    .await
}

/// [`sync_pop3`] plus the T-232 Authentication-Results stamp. POP3 carries no
/// SMTP receipt, so SPF is always recorded as `none` with an explicit comment
/// (the client IP and envelope sender are simply not knowable here).
/// ([`sync_pop3`] shape plus the sealer and optional receipt.)
#[allow(clippy::too_many_arguments)]
pub async fn sync_pop3_with_auth(
    client: &mut Pop3Client,
    store: &MailStore,
    account_id: &str,
    folder_name: &str,
    delete_after_download: bool,
    now: i64,
    sealer: &dyn crate::authstamp::AuthSealer,
    receipt: Option<&crate::authstamp::SmtpReceipt>,
) -> Result<Pop3SyncReport> {
    sync_pop3_inner(
        client,
        store,
        account_id,
        folder_name,
        delete_after_download,
        now,
        Some(sealer),
        receipt,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sync_pop3_inner(
    client: &mut Pop3Client,
    store: &MailStore,
    account_id: &str,
    folder_name: &str,
    delete_after_download: bool,
    now: i64,
    sealer: Option<&dyn crate::authstamp::AuthSealer>,
    receipt: Option<&crate::authstamp::SmtpReceipt>,
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
            // Full headers are in hand — classify with the complete ruleset.
            category: crate::category::categorize(&parsed).category,
            // …and record any unsubscribe offer (F3).
            unsub_http: parsed.unsubscribe.as_ref().and_then(|u| u.http_url.clone()),
            unsub_mailto: parsed.unsubscribe.as_ref().and_then(|u| u.mailto.clone()),
            unsub_oneclick: parsed.unsubscribe.as_ref().is_some_and(|u| u.one_click),
        };
        store.upsert_message(folder_id, &meta, now)?;
        store.store_body(folder_id, number as u64, &bytes)?;
        // T-233: the POP3 drop folder *is* the inbox — rules run on the
        // full parse at ingest (POP3 has no envelope-only stage). Errors
        // count, never abort the download; an unmarked eval is retried by
        // the deferred pass on a later IMAP sync or by `apply_now`.
        if crate::rules::apply_on_ingest(
            store,
            account_id,
            folder_id,
            number as u64,
            &parsed,
            crate::rules::EvalStage::Full,
            now,
        )
        .is_err()
        {
            report.rule_failures += 1;
        }
        // T-232: Authentication-Results. `receipt` is always `None` on POP3 —
        // there is no SMTP client IP or envelope sender to evaluate SPF
        // against, so it records `none` with an explicit comment instead of a
        // fabricated verdict. Failures never abort the download.
        if let Some(sealer) = sealer {
            let stamp = sealer.evaluate_and_stamp(&parsed, &bytes, now, receipt);
            let _ = store.set_auth(folder_id, number as u64, &stamp);
        }
        store.pop3_mark_seen(account_id, &uidl, now)?;
        report.downloaded += 1;
        if delete_after_download {
            client.dele(number).await?;
            report.deleted_remote += 1;
        }
    }
    Ok(report)
}

/// UID set notation ("1,2,3"); runs are not collapsed — chunking bounds
/// command length, so collapsing buys nothing here.
fn uid_set(uids: &[u64]) -> String {
    uids.iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// IMAP INTERNALDATE ("17-Sep-2025 10:00:00 +0000", day may be space-padded)
/// → Unix seconds. Returns None on unparseable input — absent fact, no guess.
fn parse_internal_date(s: &str) -> Option<i64> {
    const FMT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[day padding:none]-[month repr:short]-[year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
    );
    time::OffsetDateTime::parse(s.trim(), FMT)
        .ok()
        .map(|d| d.unix_timestamp())
}

/// Envelope-only pseudo-message for the deterministic passes that run
/// before bodies arrive (`category`, `rules::apply_on_ingest`). Header,
/// body, and attachment predicates simply don't fire on it — absent
/// fact, no guess.
fn envelope_pseudo(item: &FetchItem) -> crate::mime::ParsedMessage {
    let env = item.envelope.clone().unwrap_or_default();
    let map = |list: &[crate::imap::Mailbox]| {
        list.iter()
            .map(|m| crate::mime::Addr {
                name: None,
                email: m.email.clone(),
            })
            .collect()
    };
    crate::mime::ParsedMessage {
        message_id: env.message_id,
        subject: env.subject,
        from: map(&env.from),
        to: map(&env.to),
        cc: map(&env.cc),
        ..Default::default()
    }
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
    // Metadata fetch carries no headers — classify from the envelope From
    // address only (social / no-reply domain rules still fire). The body
    // path (`fetch_missing_bodies`) refines this once headers arrive.
    let pseudo = envelope_pseudo(item);
    NewMessageMeta {
        uid: item.uid.unwrap_or(0),
        message_id: env.message_id,
        subject: env.subject,
        from_addr: join(&env.from),
        to_addrs: join(&env.to),
        date_unix: item.internal_date.as_deref().and_then(parse_internal_date),
        size: item.size,
        flags: item.flags.clone(),
        has_attachments: item
            .bodystructure
            .as_ref()
            .map(has_attachment_parts)
            .unwrap_or(false),
        snippet: None,
        category: crate::category::categorize(&pseudo).category,
        // No headers at metadata time → no unsubscribe offer yet; the body
        // path refines this via `set_unsubscribe` once headers arrive.
        unsub_http: None,
        unsub_mailto: None,
        unsub_oneclick: false,
    }
}

fn has_attachment_parts(bs: &crate::imap::BodyStructure) -> bool {
    use crate::imap::BodyStructure::*;
    match bs {
        Multi { parts, .. } => parts.iter().any(has_attachment_parts),
        Single {
            media_type, params, ..
        } => {
            // Heuristic: non-text leaf with a filename param, or any
            // application/* / image/* leaf not inline text.
            let has_filename = params.iter().any(|(k, _)| k.eq_ignore_ascii_case("name"));
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
    fn internal_date_parses() {
        assert_eq!(
            parse_internal_date("17-Sep-2025 10:00:00 +0000"),
            Some(1_758_103_200)
        );
        // space-padded day-of-month is legal (RFC 3501 date-day-fixed)
        assert_eq!(
            parse_internal_date(" 1-Jan-2024 00:00:00 +0100"),
            Some(1_704_063_600)
        );
        assert_eq!(parse_internal_date("garbage"), None);
        assert_eq!(parse_internal_date(""), None);
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

    fn envelope_item(from: &str) -> FetchItem {
        use crate::imap::{Envelope, FetchItem, Mailbox};
        FetchItem {
            uid: Some(1),
            flags: vec![],
            envelope: Some(Envelope {
                from: vec![Mailbox {
                    name: None,
                    email: from.into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn to_meta_classifies_from_envelope() {
        use crate::category::Category;
        // Domain rules fire on ENVELOPE-only metadata…
        assert_eq!(
            to_meta(&envelope_item("jobs@linkedin.com")).category,
            Category::Social
        );
        assert_eq!(
            to_meta(&envelope_item("noreply@bank.example")).category,
            Category::Notifications
        );
        // …list rules degrade to Primary until the body arrives.
        assert_eq!(
            to_meta(&envelope_item("deals@shop.example")).category,
            Category::Primary
        );
        assert_eq!(to_meta(&FetchItem::default()).category, Category::Primary);
    }
}
