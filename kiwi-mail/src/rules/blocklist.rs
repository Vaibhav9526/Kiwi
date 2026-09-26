//! Sender block list (F4, T-203) - per-account, deterministic, store-only.
//!
//! The trash-before-rules *precedence* is not defined here: it is the
//! `is_block` rule class landed with F1 (T-228). `rules::eval` partitions
//! enabled rules into block and regular sets, evaluates block first in
//! `position` order, and returns the first match as terminal; `rules::apply`
//! then forces a `Trash` disposition for any block verdict even when the
//! block rule carried only flag actions. This module is the user-facing half
//! that the engine was designed around: a deterministic way to say "block
//! this sender for this account", list what is blocked, and lift a block.
//!
//! It deliberately reuses the existing public rule API
//! (`upsert_rule` / `list_rules` / `delete_rule`) and adds **no schema** and
//! **no migration** - a blocked sender *is* an `is_block` rule row, which is
//! exactly how `rules::mod` describes the block list's storage form.
//!
//! ## Two deliberate correctness decisions
//!
//! 1. **Exact address, not domain.** A blocked sender rule uses
//!    [`MatchOp::Is`] on the full normalized addr-spec. [`MatchOp::Domain`]
//!    is the engine's block-list op for *domain* patterns and compares the
//!    text after the last `@`, so a value of `a@evil.com` would also match
//!    `b@evil.com` and silently trash another sender's mail. A sender
//!    block list must not do that. Domain-wide blocking is a separate,
//!    explicit operation and is NOT implied by this module.
//! 2. **Display names are never consulted.** `"Bob" <bob@x.test>` and
//!    `bob@x.test` are the same sender; the display name is attacker-painted
//!    text (same rule the `Sender` predicate doc already states).
//!
//! Rule ids are derived from the normalized address, so blocking the same
//! sender twice updates one row instead of accumulating duplicates, and
//! `unblock_sender` removes exactly the rule this module owns - it never
//! deletes a hand-written rule it did not create.

use std::collections::BTreeSet;

use crate::error::{MailError, Result};
use crate::store::MailStore;

use super::model::{MAX_MATCH_VALUE_LEN, MatchOp, Predicate, Rule, RuleAction};

/// RFC 5321 forward-path limit; a longer input is rejected rather than
/// silently truncated (truncating an address would block the wrong sender).
pub const MAX_BLOCK_SENDER_LEN: usize = 254;

/// One block-list entry as seen by a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedSender {
    /// Deterministic rule id owned by this module.
    pub rule_id: String,
    /// Human label shown in settings.
    pub name: String,
    /// `None` when the row is a block rule that is not a plain sender match
    /// (for example one a user hand-authored). Such a rule is still listed -
    /// it is still blocking mail - but the module does not claim to own it.
    pub sender: Option<String>,
    /// Disabled rows are listed so the user can see and lift them.
    pub enabled: bool,
}

fn invalid(reason: &str) -> MailError {
    MailError::InvalidInput(format!("block list rejected: {reason}"))
}

/// Normalize a user-supplied sender into a bare lowercase addr-spec.
///
/// Accepts `a@b.test`, `A@B.TEST`, `<a@b.test>` and `"Name" <a@b.test>`.
/// Surrounding quotes, angle brackets and whitespace are stripped; the
/// display name is dropped without being matched. Rejects empty input, a
/// missing or repeated `@`, empty local or domain parts, control characters,
/// and anything over [`MAX_BLOCK_SENDER_LEN`].
pub fn normalize_sender(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid("sender is empty"));
    }
    // Take the addr-spec out of `Display Name <addr>` when present. The
    // *last* `<`/`>` pair is the address per RFC 5322; anything outside it
    // is display text and is discarded, never matched.
    let candidate = match (trimmed.rfind('<'), trimmed.rfind('>')) {
        (Some(open), Some(close)) if close > open => &trimmed[open + 1..close],
        _ => trimmed,
    };
    let addr = candidate
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim();
    let addr = addr.strip_prefix("mailto:").unwrap_or(addr).trim();
    if addr.is_empty() {
        return Err(invalid("sender has no address"));
    }
    if addr.len() > MAX_BLOCK_SENDER_LEN {
        return Err(invalid("sender is too long"));
    }
    if addr.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid("sender contains whitespace or control characters"));
    }
    let mut parts = addr.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = match (parts.next(), parts.next()) {
        (Some(d), None) => d,
        _ => {
            return Err(invalid(
                "sender must be exactly one addr-spec with a single @",
            ));
        }
    };
    if local.is_empty() || domain.is_empty() {
        return Err(invalid("sender local part and domain must both be present"));
    }
    // A domain must have at least one label and no empty label, so
    // `a@`, `@b` and `a@b..c` cannot become block-list rows.
    if !domain.contains('.') || domain.split('.').any(str::is_empty) {
        return Err(invalid("sender domain is not a dotted host"));
    }
    let folded = addr.to_ascii_lowercase();
    if folded.len() > MAX_MATCH_VALUE_LEN {
        return Err(invalid("sender exceeds the rule value bound"));
    }
    Ok(folded)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Deterministic rule id for one account's block of one sender.
///
/// The id is **account-scoped on purpose**: `rules.rule_id` is the table's
/// global primary key, not a composite with `account_id`. An id derived from
/// the address alone would therefore make a later `block_sender` on a
/// *different* account overwrite the `account_id` column of the existing row,
/// silently lifting the first account's block. Hashing the account together
/// with the address keeps each account's list independent while staying
/// deterministic, so re-blocking the same sender is still an update of one
/// row rather than an accumulating duplicate.
///
/// Readable prefix plus a short MD5. MD5 is used purely as a stable
/// key-derivation function to keep distinct inputs from colliding after
/// sanitization - it is **not** a security control, and nothing here depends
/// on its collision resistance.
fn block_rule_id(account_id: &str, normalized: &str) -> String {
    let label: String = normalized
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let label: String = label.trim_matches('-').chars().take(32).collect();
    let key = format!("{account_id}\u{0}{normalized}");
    let digest = md5::compute(key.as_bytes());
    let suffix = hex(digest.as_ref())[..8].to_string();
    if label.is_empty() {
        format!("block-{suffix}")
    } else {
        format!("block-{label}-{suffix}")
    }
}

fn sender_of(rule: &Rule) -> Option<String> {
    match &rule.when {
        Predicate::Sender {
            op: MatchOp::Is,
            value,
        } => Some(value.clone()),
        _ => None,
    }
}

/// Block one sender for one account. Idempotent: the rule id is derived
/// from the normalized address, so a second call updates the same row.
///
/// The created rule is `is_block` with a terminal `Delete` action, which the
/// F1 engine evaluates before every regular rule and applies as a move to
/// `Trash`.
pub fn block_sender(store: &MailStore, account_id: &str, sender: &str) -> Result<Rule> {
    let normalized = normalize_sender(sender)?;
    // `rules.account_id` references `accounts(account_id) ON DELETE CASCADE`,
    // so a block row cannot outlive its account. Check up front to fail with
    // a clear message instead of a raw foreign-key violation, and to keep the
    // per-account contract explicit.
    if account_id.trim().is_empty() {
        return Err(invalid("account id is empty"));
    }
    if store.get_account(account_id)?.is_none() {
        return Err(invalid(&format!("unknown account {account_id}")));
    }
    let rule_id = block_rule_id(account_id, &normalized);
    let name = format!("Blocked sender: {normalized}");
    let name: String = name.chars().take(super::model::MAX_RULE_NAME_LEN).collect();
    let rule = Rule {
        id: rule_id,
        account_id: Some(account_id.to_string()),
        name,
        enabled: true,
        position: 0,
        is_block: true,
        when: Predicate::Sender {
            op: MatchOp::Is,
            value: normalized,
        },
        then: vec![RuleAction::Delete],
    };
    store.upsert_rule(&rule)?;
    Ok(rule)
}

/// Lift the block this module owns for one sender on one account.
///
/// Returns `false` when that sender was not blocked by this module. It never
/// removes a hand-written block rule, because the id it deletes is derived
/// from the normalized address rather than discovered by scanning.
pub fn unblock_sender(store: &MailStore, account_id: &str, sender: &str) -> Result<bool> {
    let normalized = normalize_sender(sender)?;
    let id = block_rule_id(account_id, &normalized);
    match store.get_rule(&id)? {
        // Only delete a row that is still ours: same account, still a block
        // rule, still the same sender. A user may have edited it since.
        Some(rule) if rule.is_block && rule.account_id.as_deref() == Some(account_id) => {
            store.delete_rule(&id)
        }
        _ => Ok(false),
    }
}

/// Is this exact sender blocked on this account?
pub fn is_blocked(store: &MailStore, account_id: &str, sender: &str) -> Result<bool> {
    let normalized = normalize_sender(sender)?;
    let id = block_rule_id(account_id, &normalized);
    Ok(matches!(store.get_rule(&id)?,
        Some(rule) if rule.enabled && rule.is_block && rule.account_id.as_deref() == Some(account_id)))
}

/// Every block rule on this account, ordered deterministically by rule id.
///
/// Hand-authored block rules are included with `sender: None` so the settings
/// list never hides a rule that is currently trashing mail.
pub fn list_blocked_senders(store: &MailStore, account_id: &str) -> Result<Vec<BlockedSender>> {
    let mut out: Vec<BlockedSender> = store
        .list_rules(Some(account_id))?
        .into_iter()
        .filter(|r| r.is_block)
        .map(|r| BlockedSender {
            sender: sender_of(&r),
            rule_id: r.id,
            name: r.name,
            enabled: r.enabled,
        })
        .collect();
    out.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(out)
}

/// Distinct sender addresses currently blocked on this account, sorted.
///
/// Derived from the same rows as [`list_blocked_senders`], so a UI that only
/// needs the address set does not have to interpret rule shapes.
pub fn blocked_addresses(store: &MailStore, account_id: &str) -> Result<Vec<String>> {
    let set: BTreeSet<String> = list_blocked_senders(store, account_id)?
        .into_iter()
        .filter_map(|b| b.sender)
        .collect();
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AuthRef, IncomingAccount, IncomingProtocol, OutgoingAccount};
    use crate::mime::ParsedMessage;
    use crate::rules::{EvalStage, TRASH_FOLDER, apply_on_ingest};
    use crate::store::NewMessageMeta;
    use crate::transport::SocketSecurity;

    /// In-memory store with one real account, because `rules.account_id`
    /// references `accounts`. Mirrors the `seed()` shape in `rules::apply`.
    fn store(account_id: &str) -> MailStore {
        let store = MailStore::open_memory().expect("store opens");
        let server = |port, security| crate::account::ServerConfig {
            host: "h".into(),
            port,
            security,
        };
        store
            .upsert_account(&crate::account::MailAccount {
                account_id: account_id.into(),
                display_name: "T".into(),
                email: "t@x.test".into(),
                incoming: IncomingAccount {
                    protocol: IncomingProtocol::Imap,
                    server: server(993, SocketSecurity::ImplicitTls),
                    auth: AuthRef::None,
                    username: "t@x.test".into(),
                },
                outgoing: OutgoingAccount {
                    server: server(587, SocketSecurity::StartTls),
                    auth: AuthRef::None,
                    username: "t@x.test".into(),
                },
            })
            .expect("account upserts");
        store
    }

    /// Two accounts so per-account isolation is actually exercised.
    fn two_accounts() -> (MailStore, &'static str, &'static str) {
        let store = store("acct-1");
        let server = |port, security| crate::account::ServerConfig {
            host: "h".into(),
            port,
            security,
        };
        store
            .upsert_account(&crate::account::MailAccount {
                account_id: "acct-2".into(),
                display_name: "T2".into(),
                email: "t2@x.test".into(),
                incoming: IncomingAccount {
                    protocol: IncomingProtocol::Imap,
                    server: server(993, SocketSecurity::ImplicitTls),
                    auth: AuthRef::None,
                    username: "t2@x.test".into(),
                },
                outgoing: OutgoingAccount {
                    server: server(587, SocketSecurity::StartTls),
                    auth: AuthRef::None,
                    username: "t2@x.test".into(),
                },
            })
            .expect("account upserts");
        (store, "acct-1", "acct-2")
    }

    #[test]
    fn normalizes_display_name_and_case() {
        assert_eq!(normalize_sender("Bob <BOB@X.Test>").unwrap(), "bob@x.test");
        assert_eq!(normalize_sender("  a@b.test  ").unwrap(), "a@b.test");
        assert_eq!(normalize_sender("<a@b.test>").unwrap(), "a@b.test");
        assert_eq!(normalize_sender("\"A\" <a@b.test>").unwrap(), "a@b.test");
        assert_eq!(normalize_sender("mailto:a@b.test").unwrap(), "a@b.test");
    }

    #[test]
    fn rejects_malformed_senders() {
        for bad in [
            "",
            "   ",
            "a@",
            "@b.test",
            "a@b..test",
            "a.b.test",
            "two@at@signs.test",
            "has space@b.test",
            "a@x.test\nc@y.test",
            "a\tb@x.test",
            "a@localhost",
        ] {
            assert!(normalize_sender(bad).is_err(), "{bad:?} must be rejected");
        }
        let long = format!("{}@b.test", "a".repeat(MAX_BLOCK_SENDER_LEN));
        assert!(normalize_sender(&long).is_err());
    }

    #[test]
    fn trims_surrounding_whitespace() {
        // A pasted address often carries a trailing newline; trimming it is
        // intended. Only *embedded* control characters are a rejection, so
        // the stored value can never disagree with a parsed From address.
        assert_eq!(normalize_sender("ctrl@x.test\n").unwrap(), "ctrl@x.test");
        assert_eq!(normalize_sender("\r\n a@b.test \t").unwrap(), "a@b.test");
    }

    #[test]
    fn block_is_idempotent_and_per_account() {
        let (s, a1, a2) = two_accounts();
        let a = block_sender(&s, a1, "Spam <spam@bad.test>").unwrap();
        assert!(a.is_block);
        assert_eq!(a.account_id.as_deref(), Some(a1));
        let b = block_sender(&s, a1, "spam@bad.test").unwrap();
        assert_eq!(a.id, b.id, "same account + sender must reuse one row");
        // `rule_id` is a global primary key, so ids MUST be account-scoped:
        // otherwise this call would rewrite the row's account_id and silently
        // lift account one.
        let c = block_sender(&s, a2, "spam@bad.test").unwrap();
        assert_ne!(a.id, c.id, "ids must be account-scoped, not address-only");
        // ...and each account keeps its own independent block.
        assert_eq!(list_blocked_senders(&s, a1).unwrap().len(), 1);
        assert_eq!(list_blocked_senders(&s, a2).unwrap().len(), 1);
        assert!(is_blocked(&s, a1, "SPAM@BAD.TEST").unwrap());
        assert!(is_blocked(&s, a2, "spam@bad.test").unwrap());
        assert!(!is_blocked(&s, "acct-3", "spam@bad.test").unwrap());
        // Lifting one account's block must leave the other's intact.
        assert!(unblock_sender(&s, a2, "spam@bad.test").unwrap());
        assert!(!is_blocked(&s, a2, "spam@bad.test").unwrap());
        assert!(is_blocked(&s, a1, "spam@bad.test").unwrap());
    }

    #[test]
    fn block_rejects_unknown_account() {
        let s = store("acct-1");
        let err = block_sender(&s, "nope", "spam@bad.test").unwrap_err();
        assert!(
            matches!(&err, MailError::InvalidInput(m) if m.contains("unknown account")),
            "got {err:?}"
        );
        assert!(block_sender(&s, "  ", "spam@bad.test").is_err());
    }

    #[test]
    fn unblock_only_touches_our_own_row() {
        let (s, a1, a2) = two_accounts();
        block_sender(&s, a1, "spam@bad.test").unwrap();
        assert!(unblock_sender(&s, a1, "SPAM@BAD.TEST").unwrap());
        assert!(!is_blocked(&s, a1, "spam@bad.test").unwrap());
        assert!(!unblock_sender(&s, a1, "spam@bad.test").unwrap());
        // Wrong account must not lift another account's block.
        block_sender(&s, a1, "spam@bad.test").unwrap();
        assert!(!unblock_sender(&s, a2, "spam@bad.test").unwrap());
        assert!(is_blocked(&s, a1, "spam@bad.test").unwrap());
    }

    #[test]
    fn unblock_leaves_hand_written_block_rules_alone() {
        let s = store("acct-1");
        let hand = Rule {
            id: "block-hand-written".into(),
            account_id: Some("acct-1".into()),
            name: "Block everything from the corp domain".into(),
            enabled: true,
            position: 0,
            is_block: true,
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: "corp.example".into(),
            },
            then: vec![RuleAction::Delete],
        };
        s.upsert_rule(&hand).unwrap();
        assert!(!unblock_sender(&s, "acct-1", "someone@corp.example").unwrap());
        assert!(s.get_rule("block-hand-written").unwrap().is_some());
        let listed = list_blocked_senders(&s, "acct-1").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].sender, None,
            "a domain rule is listed but not claimed"
        );
        assert!(listed[0].rule_id.starts_with("block-hand-written"));
    }

    #[test]
    fn distinct_senders_do_not_collide() {
        let a = block_rule_id("acct-1", "a_b@x.test");
        let b = block_rule_id("acct-1", "a-b@x.test");
        assert_ne!(a, b, "sanitization must not merge distinct senders");
        assert!(a.starts_with("block-") && a.len() <= 64);
    }

    #[test]
    fn list_is_deterministic_and_sorted() {
        let s = store("acct-1");
        block_sender(&s, "acct-1", "z@bad.test").unwrap();
        block_sender(&s, "acct-1", "a@bad.test").unwrap();
        let listed = list_blocked_senders(&s, "acct-1").unwrap();
        assert_eq!(listed.len(), 2);
        let mut ids: Vec<&str> = listed.iter().map(|b| b.rule_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            listed
                .iter()
                .map(|b| b.rule_id.as_str())
                .collect::<Vec<_>>(),
            "list order must be stable"
        );
        assert_eq!(
            blocked_addresses(&s, "acct-1").unwrap(),
            vec!["a@bad.test".to_string(), "z@bad.test".to_string()]
        );
    }

    fn meta(uid: u64, from: &str) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some("s".into()),
            from_addr: Some(from.into()),
            to_addrs: None,
            date_unix: None,
            size: None,
            flags: vec![],
            has_attachments: false,
            snippet: None,
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    fn parsed(from: &str) -> ParsedMessage {
        ParsedMessage {
            message_id: Some("<m@x>".into()),
            from: vec![crate::mime::Addr {
                name: Some("Display Name".into()),
                email: from.into(),
            }],
            subject: Some("s".into()),
            ..Default::default()
        }
    }

    fn folder_named(store: &MailStore, fid: Option<i64>) -> Option<String> {
        fid.map(|id| store.folder_meta(id).unwrap().unwrap().name)
    }

    /// The F4 headline, proven through the real engine: a blocked sender is
    /// trashed, that verdict is terminal, and it does **not** generalize to
    /// the rest of the sender's domain.
    #[test]
    fn blocked_sender_is_trashed_before_regular_rules_without_domain_overreach() {
        let s = store("acct-1");
        let fid = s.ensure_folder("acct-1", "INBOX").unwrap();
        let block = block_sender(&s, "acct-1", "Spam <SPAM@bad.test>").unwrap();
        // A broad, ordinary rule that would otherwise star and file mail from
        // the whole domain. If block-first precedence or the exact-address
        // match were wrong, this rule would win for the blocked sender.
        s.upsert_rule(&Rule {
            id: "keep-bad-test".into(),
            account_id: Some("acct-1".into()),
            name: "File the domain".into(),
            enabled: true,
            position: 0,
            is_block: false,
            when: Predicate::Sender {
                op: MatchOp::Domain,
                value: "bad.test".into(),
            },
            then: vec![RuleAction::Move {
                folder: "Work".into(),
            }],
        })
        .unwrap();

        let cases = [
            (1u64, "spam@bad.test"),
            (2, "other@bad.test"),
            (3, "nice@good.test"),
        ];
        for (uid, from) in cases {
            s.upsert_message(fid, &meta(uid, from), 100).unwrap();
        }
        let mut applied = Vec::new();
        for (uid, from) in cases {
            let m = parsed(from);
            applied.push((
                from,
                apply_on_ingest(&s, "acct-1", fid, uid, &m, EvalStage::Full, 200).unwrap(),
            ));
        }

        // 1. The blocked sender is trashed and the block rule is the record.
        let (from, out) = &applied[0];
        assert_eq!(*from, "spam@bad.test");
        assert_eq!(out.blocked_by.as_deref(), Some(block.id.as_str()));
        assert_eq!(out.matched, vec![block.id.clone()]);
        assert_eq!(
            folder_named(&s, out.moved_to_folder).as_deref(),
            Some(TRASH_FOLDER),
            "a blocked sender must land in Trash"
        );
        // ...and the broad rule never ran for it: exactly one hit recorded.
        let hits = s.list_rule_hits("acct-1", 50).unwrap();
        assert_eq!(
            hits.iter()
                .filter(|h| h.uid == 1)
                .map(|h| h.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec![block.id.as_str()],
            "block must be terminal - no regular rule may also fire"
        );

        // 2. A *different* sender at the same domain is untouched by the
        //    block. This is the over-blocking regression: a sender block is
        //    exact-address, never a silent domain ban.
        let (from, out) = &applied[1];
        assert_eq!(*from, "other@bad.test");
        assert!(
            out.blocked_by.is_none(),
            "a sibling sender must not be blocked"
        );
        assert_eq!(
            folder_named(&s, out.moved_to_folder).as_deref(),
            Some("Work"),
            "the ordinary domain rule must still apply to the sibling sender"
        );

        // 3. Unrelated mail is a no-op.
        let (_, out) = &applied[2];
        assert!(out.blocked_by.is_none());
        assert!(out.moved_to_folder.is_none());
        assert!(out.matched.is_empty());
    }

    /// A disabled block row must not trash mail, but must still be listed so
    /// the settings surface can show and lift it.
    #[test]
    fn disabled_block_does_not_trash_but_stays_listed() {
        let s = store("acct-1");
        let fid = s.ensure_folder("acct-1", "INBOX").unwrap();
        let block = block_sender(&s, "acct-1", "spam@bad.test").unwrap();
        let off = Rule {
            enabled: false,
            ..block.clone()
        };
        s.upsert_rule(&off).unwrap();
        assert!(!is_blocked(&s, "acct-1", "spam@bad.test").unwrap());

        s.upsert_message(fid, &meta(9, "spam@bad.test"), 100)
            .unwrap();
        let m = parsed("spam@bad.test");
        let out = apply_on_ingest(&s, "acct-1", fid, 9, &m, EvalStage::Full, 200).unwrap();
        assert!(out.blocked_by.is_none());
        assert!(
            out.moved_to_folder.is_none(),
            "a disabled block must not trash"
        );

        let listed = list_blocked_senders(&s, "acct-1").unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled, "the paused block is still listed");
        assert_eq!(listed[0].sender.as_deref(), Some("spam@bad.test"));
    }
}
