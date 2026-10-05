//! Conversation (thread) key derivation (T-341).
//!
//! **Why this lives in the engine.** Conversation grouping is currently a
//! *client-side* concern: `kiwi-app/src/threading.ts::buildThreads` groups the
//! flat list by `key = "<accountId>\\n<normalizedSubject>"` and its own header
//! comment says so plainly — `In-Reply-To`/`References` are not exposed by the
//! IPC, so header-chain threading is deferred. The store, meanwhile, has no
//! `conversation_id` column at all.
//!
//! T-341 needs a **store-owned** conversation identity so a mute can suppress
//! *counts* (a SQL concern) and not just a client-side filter. If the store
//! invented a different grouping, muting the thread the user clicked would
//! suppress a different set of messages. So this module ports the UI's
//! normalizer verbatim and both sides use it: the UI groups what it shows, the
//! store suppresses what it counts, and they agree by construction.
//!
//! **Honest limitation, deliberately not hidden.** Subject-folding is *not*
//! real conversation threading. Two unrelated mail that share a stripped
//! subject collapse into one key, and a reply whose subject deviates starts a
//! new one. That is precisely the grouping the list view already displays, so
//! muting is consistent with what the user sees — but it is weaker than
//! RFC 5322 `References` threading, and when the IPC exposes those headers the
//! key must move to the root `Message-ID`. See `docs/contracts/ipc.md` (T-341).
//!
//! Keep in lockstep with `kiwi-app/src/threading.ts`; the test vectors below
//! are the same cases that file's grouping depends on.

/// Reply/forward prefixes stripped iteratively (conservative set). Order
/// matters and mirrors the TS alternation: a bare `fw` must not eat the `d` of
/// `fwd:` — the `:` check rejects it and the next alternative is tried.
const PREFIXES: [&str; 5] = ["re", "fw", "fwd", "aw", "sv"];

/// Iterations of prefix stripping. The TS side uses 8; same bound, same order.
const MAX_STRIP_PASSES: usize = 8;

/// Longest mailing-list tag body accepted (`[dev] `, `[list-name] `, ...).
const MAX_TAG_LEN: usize = 40;

/// Normalized conversation key for a subject, or `None` when the subject
/// carries no signal.
///
/// `None` means "this message is not part of a foldable conversation" — the UI
/// threads such a message alone under a synthetic key, so there is nothing for
/// a user to mute and nothing for the store to suppress.
pub fn normalize_subject(raw: &str) -> Option<String> {
    let folded = strip_prefixes(raw).to_lowercase();
    let collapsed: String = folded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

/// Strip reply/forward prefixes (iteratively), then one leading list tag.
fn strip_prefixes(s: &str) -> String {
    let mut out = s.trim().to_string();
    for _ in 0..MAX_STRIP_PASSES {
        let next = strip_one_prefix(&out).trim().to_string();
        if next == out {
            break;
        }
        out = next;
    }
    strip_tag(&out).trim().to_string()
}

/// One leading `re:`/`fwd:`/`aw:`/`sv:` prefix, case-insensitive, with
/// optional whitespace around the colon.
fn strip_one_prefix(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    for p in PREFIXES {
        if let Some(rest) = lower.strip_prefix(p) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix(':') {
                // Re-slice the ORIGINAL string so the returned value keeps the
                // caller's casing; only the length consumed is borrowed.
                let consumed = s.len() - rest.len();
                return s[consumed..].trim_start().to_string();
            }
        }
    }
    s.to_string()
}

/// One leading mailing-list tag: `[` + 1..=40 non-bracket chars + `]` + space.
///
/// The tag regex is `^\[[^\][]]{1,40}\]\s*`, so: skip `[`, measure the body up
/// to the closing `]` (rejecting a nested `[` or a `]` before it), then drop
/// the `]` and any whitespace after it.
fn strip_tag(s: &str) -> String {
    let Some(rest) = s.strip_prefix('[') else {
        return s.to_string();
    };
    // Body must be 1..=MAX_TAG_LEN chars, none of them `[` or `]`.
    let body_end = rest
        .char_indices()
        .take(MAX_TAG_LEN + 1)
        .find(|(_, ch)| *ch == ']' || *ch == '[');
    let Some((close_idx, ']')) = body_end else {
        // No closing bracket within the length bound -> not a tag.
        return s.to_string();
    };
    if close_idx == 0 {
        // `[]` - empty body, and the regex needs at least one char.
        return s.to_string();
    }
    let after = close_idx + 1; // byte index just past the ']'
    s[1 + after..].trim_start().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_reply_and_forward_prefixes() {
        assert_eq!(normalize_subject("Re: Budget").as_deref(), Some("budget"));
        assert_eq!(normalize_subject("RE: Budget").as_deref(), Some("budget"));
        assert_eq!(normalize_subject("Fw: Budget").as_deref(), Some("budget"));
        assert_eq!(normalize_subject("FWD: Budget").as_deref(), Some("budget"));
        assert_eq!(normalize_subject("Aw: Budget").as_deref(), Some("budget"));
        assert_eq!(normalize_subject("Sv: Budget").as_deref(), Some("budget"));
    }

    #[test]
    fn strips_nested_prefixes_like_the_ui_does() {
        // The TS stripper loops, so a doubly-prefixed reply folds to the root.
        assert_eq!(
            normalize_subject("Re: Fwd: Re: Budget").as_deref(),
            Some("budget")
        );
    }

    #[test]
    fn a_bare_fw_prefix_does_not_eat_fwd() {
        // "fw" matches, but the rest is "d: x" with no colon, so the shorter
        // alternative must be rejected and "fwd" tried instead.
        assert_eq!(normalize_subject("Fwd: x").as_deref(), Some("x"));
        // And a subject that merely starts with those letters survives.
        assert_eq!(
            normalize_subject("reward points").as_deref(),
            Some("reward points")
        );
        assert_eq!(
            normalize_subject("sveta report").as_deref(),
            Some("sveta report")
        );
    }

    #[test]
    fn strips_list_tags_then_folds_case_and_space() {
        assert_eq!(normalize_subject("[dev] Deploy").as_deref(), Some("deploy"));
        assert_eq!(
            normalize_subject("Re: [dev] Deploy").as_deref(),
            Some("deploy")
        );
        assert_eq!(
            normalize_subject("  Hello   World ").as_deref(),
            Some("hello world")
        );
    }

    #[test]
    fn empty_and_punctuation_only_subjects_have_no_key() {
        // No signal -> None: the UI threads it alone, so there is nothing to
        // mute and nothing to suppress.
        assert_eq!(normalize_subject(""), None);
        assert_eq!(normalize_subject("   "), None);
        assert_eq!(normalize_subject("Re:"), None);
        assert_eq!(normalize_subject("[dev]"), None);
    }

    #[test]
    fn tag_length_bound_matches_the_ui() {
        // 40 chars of tag body is accepted, 41 is not a tag (and so stays).
        let ok = format!("[{}] Deploy", "a".repeat(MAX_TAG_LEN));
        assert_eq!(normalize_subject(&ok).as_deref(), Some("deploy"));
        let too_long = format!("[{}] Deploy", "a".repeat(MAX_TAG_LEN + 1));
        assert!(normalize_subject(&too_long).is_some_and(|k| k.starts_with('[')));
    }
}
