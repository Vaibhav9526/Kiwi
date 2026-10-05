//! Conversation mute (T-341, Thunderbird "Ignore Thread").
//!
//! A mute is a statement about a **conversation**, not about rows: while it
//! holds, no message in that conversation contributes to an unseen count and
//! none of them raises a new-mail notification. It is stored per account, so
//! the same subject muted on one account never suppresses another account's
//! mail (accounts are independent identities, not one shared inbox).
//!
//! **Why the key is the subject fold.** The store has no `In-Reply-To` /
//! `References` column, so it cannot compute RFC 5322 thread roots. The list
//! view groups by `threading::normalize_subject(subject)` within an account,
//! so the store uses that same function and stores its output on every row at
//! ingest (`messages.conversation_key`). Mute therefore suppresses exactly the
//! set the user sees as one conversation. See `crate::threading` for the
//! honest limits of that approximation.

use std::collections::BTreeSet;

use rusqlite::params;

use super::MailStore;
use crate::error::{MailError, Result};

/// Upper bound on a conversation key. The normalizer collapses whitespace and
/// strips prefixes, so a key is a folded subject; the bound keeps a hostile or
/// corrupt subject from becoming an unbounded primary-key value.
pub const MAX_CONVERSATION_KEY_LEN: usize = 512;

impl MailStore {
    /// Mute or unmute a conversation. Returns the resulting state, so a caller
    /// never has to guess whether a redundant call changed anything.
    ///
    /// Idempotent in both directions: muting an already-muted conversation
    /// refreshes `muted_at_unix` and reports `true`; unmuting a conversation
    /// with no row reports `false` and writes nothing. A conversation with no
    /// stored messages is still a legal mute (the user may mute a thread whose
    /// mail has since been deleted, and future arrivals must stay suppressed).
    pub fn set_conversation_muted(
        &self,
        account_id: &str,
        conversation_key: &str,
        muted: bool,
        now: i64,
    ) -> Result<bool> {
        if conversation_key.is_empty() {
            return Err(MailError::InvalidInput("empty conversation key".into()));
        }
        if conversation_key.len() > MAX_CONVERSATION_KEY_LEN {
            return Err(MailError::InvalidInput(
                "conversation key exceeds 512 bytes".into(),
            ));
        }
        if muted {
            self.conn.execute(
                "INSERT INTO muted_conversations (account_id, conversation_key, muted_at_unix)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(account_id, conversation_key)
                 DO UPDATE SET muted_at_unix = excluded.muted_at_unix",
                params![account_id, conversation_key, now],
            )?;
        } else {
            self.conn.execute(
                "DELETE FROM muted_conversations
                  WHERE account_id = ?1 AND conversation_key = ?2",
                params![account_id, conversation_key],
            )?;
        }
        Ok(muted)
    }

    /// Whether this conversation is currently muted on this account.
    pub fn is_conversation_muted(&self, account_id: &str, conversation_key: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM muted_conversations
              WHERE account_id = ?1 AND conversation_key = ?2",
            params![account_id, conversation_key],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Muted conversation keys for one account (the account's "ignore thread"
    /// list). Sorted for a stable IPC/UI order.
    pub fn muted_conversation_keys(&self, account_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT conversation_key FROM muted_conversations
              WHERE account_id = ?1 ORDER BY conversation_key",
        )?;
        let rows = stmt.query_map(params![account_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Which of `uids` (in `folder_id`) belong to a muted conversation.
    ///
    /// This is the new-mail notification seam (T-329): arrivals in a muted
    /// conversation must not raise a ding. It is a real set-membership query
    /// against the stored mute rows and the stored conversation keys - the
    /// decision is derived from data, never from a caller-supplied flag.
    pub fn muted_uids_in(&self, folder_id: i64, uids: &[u64]) -> Result<BTreeSet<u64>> {
        let mut muted = BTreeSet::new();
        if uids.is_empty() {
            return Ok(muted);
        }
        // Chunked so a large arrival set cannot build an unbounded IN list.
        for chunk in uids.chunks(400) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT m.uid FROM messages m
                   JOIN folders f ON f.id = m.folder_id
                  WHERE m.folder_id = ?1
                    AND m.uid IN ({placeholders})
                    AND m.conversation_key IS NOT NULL
                    AND EXISTS (SELECT 1 FROM muted_conversations mc
                                 WHERE mc.account_id = f.account_id
                                   AND mc.conversation_key = m.conversation_key)"
            );
            // One flat i64 list: folder_id first, then the chunk's uids. The
            // placeholders are generated from the chunk length, never from
            // caller text, so this stays fully parameterized.
            let mut args: Vec<i64> = Vec::with_capacity(chunk.len() + 1);
            args.push(folder_id);
            args.extend(chunk.iter().map(|u| *u as i64));
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| r.get::<_, i64>(0))?;
            for r in rows {
                muted.insert(r? as u64);
            }
        }
        Ok(muted)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{
        AuthRef, IncomingAccount, IncomingProtocol, MailAccount, OutgoingAccount, ServerConfig,
    };
    use crate::category::Category;
    use crate::store::NewMessageMeta;
    use crate::transport::SocketSecurity;

    fn account(id: &str) -> MailAccount {
        MailAccount {
            account_id: id.into(),
            display_name: id.into(),
            email: format!("{id}@x.test"),
            incoming: IncomingAccount {
                protocol: IncomingProtocol::Imap,
                server: ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: format!("{id}@x.test"),
            },
            outgoing: OutgoingAccount {
                server: ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 465,
                    security: SocketSecurity::ImplicitTls,
                },
                auth: AuthRef::None,
                username: format!("{id}@x.test"),
            },
        }
    }

    fn meta(uid: u64, subject: Option<&str>, seen: bool) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: subject.map(str::to_string),
            from_addr: Some("a@x".into()),
            to_addrs: Some("b@y".into()),
            date_unix: Some(1_758_000_000),
            size: Some(10),
            flags: if seen { vec!["\\Seen".into()] } else { vec![] },
            has_attachments: false,
            snippet: None,
            category: Category::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    /// Account a1 / INBOX with two unseen "Deploy" mails (one is a `Re:`),
    /// one unseen "Invoice", and one read "Deploy". The Deploy conversation
    /// therefore holds 2 unseen + 1 seen.
    fn seeded() -> MailStore {
        let s = MailStore::open_memory().unwrap();
        s.upsert_account(&account("a1")).unwrap();
        s.upsert_account(&account("a2")).unwrap();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        s.upsert_message(inbox, &meta(1, Some("Deploy"), false), 1)
            .unwrap();
        s.upsert_message(inbox, &meta(2, Some("Re: Deploy"), false), 1)
            .unwrap();
        s.upsert_message(inbox, &meta(3, Some("Invoice"), false), 1)
            .unwrap();
        s.upsert_message(inbox, &meta(4, Some("Deploy"), true), 1)
            .unwrap();
        s
    }

    #[test]
    fn conversation_key_is_materialized_at_ingest() {
        let s = seeded();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        let key = |uid: i64| -> Option<String> {
            s.conn_for_test()
                .query_row(
                    "SELECT conversation_key FROM messages WHERE uid = ?1",
                    [uid],
                    |r| r.get::<_, Option<String>>(0),
                )
                .unwrap()
        };
        // "Deploy" and "Re: Deploy" fold to the same conversation.
        assert_eq!(key(1).as_deref(), Some("deploy"));
        assert_eq!(key(2).as_deref(), Some("deploy"));
        assert_eq!(key(3).as_deref(), Some("invoice"));
        assert!(s.folder_stats(inbox).is_ok());
    }

    #[test]
    fn mute_drops_unseen_counts_and_unmute_restores_them() {
        let s = seeded();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        assert_eq!(s.folder_stats(inbox).unwrap().unseen, 3, "3 unseen at rest");

        assert!(s.set_conversation_muted("a1", "deploy", true, 100).unwrap());
        assert!(s.is_conversation_muted("a1", "deploy").unwrap());
        // The whole Deploy conversation (2 unseen) leaves the count; the
        // Invoice conversation is untouched.
        let after = s.folder_stats(inbox).unwrap();
        assert_eq!(after.unseen, 1, "muted conversation is excluded");
        // `exists` is the honest row total and is deliberately NOT suppressed.
        assert_eq!(after.exists, 4);

        // Unmute restores exactly the prior count.
        assert!(
            !s.set_conversation_muted("a1", "deploy", false, 200)
                .unwrap()
        );
        assert!(!s.is_conversation_muted("a1", "deploy").unwrap());
        assert_eq!(
            s.folder_stats(inbox).unwrap().unseen,
            3,
            "roundtrip restored"
        );
    }

    #[test]
    fn mute_is_scoped_per_account() {
        let s = seeded();
        let b_inbox = s.ensure_folder("a2", "INBOX").unwrap();
        for uid in 1..=2 {
            s.upsert_message(b_inbox, &meta(uid, Some("Deploy"), false), 1)
                .unwrap();
        }
        assert_eq!(s.folder_stats(b_inbox).unwrap().unseen, 2);

        // Muting the same subject on a1 must not touch a2: accounts are
        // independent identities, not one shared inbox.
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        assert_eq!(s.folder_stats(b_inbox).unwrap().unseen, 2, "a2 unaffected");
        assert!(!s.is_conversation_muted("a2", "deploy").unwrap());

        // Muting on a2 does suppress a2.
        s.set_conversation_muted("a2", "deploy", true, 100).unwrap();
        assert_eq!(s.folder_stats(b_inbox).unwrap().unseen, 0);
    }

    #[test]
    fn a_subjectless_message_is_never_suppressed() {
        let s = MailStore::open_memory().unwrap();
        s.upsert_account(&account("a1")).unwrap();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        // No subject -> no conversation -> nothing to mute, so it keeps
        // counting. Suppressing it would require inventing a conversation.
        s.upsert_message(inbox, &meta(1, None, false), 1).unwrap();
        s.upsert_message(inbox, &meta(2, Some("Re:"), false), 1)
            .unwrap();
        assert_eq!(s.folder_stats(inbox).unwrap().unseen, 2);
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        assert_eq!(
            s.folder_stats(inbox).unwrap().unseen,
            2,
            "no-signal subjects stay countable"
        );
    }

    #[test]
    fn a_mute_survives_its_messages_being_deleted() {
        // A mute is a statement about the conversation, not the rows: it must
        // keep suppressing future arrivals even when every current member is
        // gone (deleted, moved off, expunged).
        let s = seeded();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        let deploy_uids: Vec<u64> = s
            .folder_uids(inbox)
            .unwrap()
            .into_iter()
            .filter(|u| matches!(u, 1 | 2 | 4))
            .collect();
        s.delete_messages(inbox, &deploy_uids).unwrap();
        assert_eq!(
            s.folder_stats(inbox).unwrap().unseen,
            1,
            "only Invoice left"
        );
        assert!(
            s.is_conversation_muted("a1", "deploy").unwrap(),
            "mute kept"
        );

        // A new arrival in the muted conversation stays suppressed.
        s.upsert_message(inbox, &meta(9, Some("Re: Deploy"), false), 1)
            .unwrap();
        assert_eq!(
            s.folder_stats(inbox).unwrap().unseen,
            1,
            "new mail suppressed"
        );
    }

    #[test]
    fn a_mute_survives_its_messages_being_moved() {
        // The mute is keyed by account+conversation, not by folder or uid:
        // a move re-inserts the row with its stored conversation_key, so
        // suppression follows the mail into the destination folder.
        let s = seeded();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        let work = s.ensure_folder("a1", "Work").unwrap();
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        s.move_messages(inbox, work, &[1, 2]).unwrap();
        assert_eq!(
            s.folder_stats(work).unwrap().unseen,
            0,
            "moved Deploy mail stayed suppressed in Work"
        );
        assert_eq!(s.folder_stats(inbox).unwrap().unseen, 1);
        // A same-account copy of a muted message is part of the same muted
        // conversation — it does not resurrect a countable copy. Work's
        // fresh uids are 1,2 (empty destination); the copy back to INBOX
        // lands at INBOX's max+1.
        s.copy_messages(work, inbox, &[1]).unwrap();
        let deploy_rows: i64 = s
            .conn_for_test()
            .query_row(
                "SELECT COUNT(*) FROM messages
                  WHERE folder_id = ?1 AND conversation_key = 'deploy'",
                [inbox],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(deploy_rows, 2, "seen uid 4 + the copy, key carried");
        assert_eq!(
            s.folder_stats(inbox).unwrap().unseen,
            1,
            "the copy stayed muted too"
        );
    }

    #[test]
    fn set_mute_rejects_an_empty_or_oversized_key() {
        let s = seeded();
        assert!(s.set_conversation_muted("a1", "", true, 1).is_err());
        let huge = "x".repeat(MAX_CONVERSATION_KEY_LEN + 1);
        assert!(s.set_conversation_muted("a1", &huge, true, 1).is_err());
    }

    #[test]
    fn muting_is_idempotent_and_unmuting_an_unmuted_row_writes_nothing() {
        let s = seeded();
        // Twice muted -> still muted, one row.
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        s.set_conversation_muted("a1", "deploy", true, 200).unwrap();
        assert_eq!(s.muted_conversation_keys("a1").unwrap(), vec!["deploy"]);
        // Unmute twice is fine and stays unmuted.
        s.set_conversation_muted("a1", "deploy", false, 300)
            .unwrap();
        s.set_conversation_muted("a1", "deploy", false, 400)
            .unwrap();
        assert!(s.muted_conversation_keys("a1").unwrap().is_empty());
    }

    #[test]
    fn muted_uids_in_reports_exactly_the_suppressed_arrivals() {
        let s = seeded();
        let inbox = s.ensure_folder("a1", "INBOX").unwrap();
        // Before any mute: nothing is suppressed.
        assert!(s.muted_uids_in(inbox, &[1, 2, 3]).unwrap().is_empty());
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        // uids 1 and 2 are the Deploy conversation; 3 (Invoice) is not; 99 is
        // not a stored row at all.
        let muted = s.muted_uids_in(inbox, &[1, 2, 3, 99]).unwrap();
        assert_eq!(muted.into_iter().collect::<Vec<_>>(), vec![1, 2]);
        // Chunking must not change the answer.
        let many: Vec<u64> = (1..=4).collect();
        assert_eq!(s.muted_uids_in(inbox, &many).unwrap().len(), 3);
        assert!(s.muted_uids_in(inbox, &[]).unwrap().is_empty());
    }

    #[test]
    fn removing_the_account_removes_its_conversation_mutes() {
        let s = seeded();
        s.set_conversation_muted("a1", "deploy", true, 100).unwrap();
        s.delete_account("a1").unwrap();
        assert!(
            s.muted_conversation_keys("a1").unwrap().is_empty(),
            "cascade removed the mute"
        );
    }
}
