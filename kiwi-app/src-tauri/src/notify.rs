//! New-mail OS notifications (T-329) — the desktop-client feature drag/
//! ctx-menu parity never covered: when a sync pass lands *new unseen*
//! messages, show ONE OS notification per folder per pass ("3 new
//! messages in INBOX" with the newest sender+subject as preview; a single
//! arrival shows the message itself).
//!
//! Honest bounds:
//! - **Suppression beats noise.** `kiwi.notify = "off"` (global pref,
//!   settings toggle) mutes everything; a per-account `kiwi.muted` entry
//!   mutes that account (muting already hides unread — dinging for it
//!   would contradict the mute). Junk/spam/trash-name folders never
//!   notify: arrivals there are filtered mail or remote deletes, not
//!   "new mail".
//! - **Rate limit.** One notification per (account, folder) per
//!   [`NOTIFY_MIN_INTERVAL_SECS`] — back-to-back syncs (IDLE bursts,
//!   manual sync right after a live pass) coalesce into one ding.
//! - **Fail soft.** A notification failure is logged and swallowed —
//!   it never fails the sync. Nothing is audited per notification
//!   (noise); the *pref change* is audited in `kiwi_prefs_set`.
//! - The `Notifier` seam keeps the OS call mockable — tests record
//!   instead of touching the desktop.

use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::Arc;

use crate::state::{AppState, now_unix, pref_key};

/// One ding per (account, folder) per minute at most.
pub(crate) const NOTIFY_MIN_INTERVAL_SECS: i64 = 60;
/// Scan bound for the unseen preview — newest-first listing.
const NOTIFY_SCAN: u32 = 256;
/// Title/body field cap — notifications are glanceable.
const FIELD_CAP: usize = 120;

/// Folder names that never produce a notification — junk/spam per spec,
/// plus trash names (an arrival there is a remote delete, not new mail).
/// Normalized lowercase exact match.
const EXCLUDED_FOLDERS: &[&str] = &[
    "junk",
    "spam",
    "bulk",
    "bulk mail",
    "junk mail",
    "junk e-mail",
    "junk email",
    "spam mail",
    "trash",
    "deleted items",
    "deleted messages",
    "deleted",
    "bin",
    "papierkorb",
];

/// The OS notification sink. Production wraps tauri-plugin-notification;
/// tests record calls. Errors are strings — the caller only logs them.
///
/// Click-to-focus is NOT claimed: the plugin's Rust `show()` is
/// fire-and-forget with no activation callback (the guest-side `onAction`
/// API is the only click path, and wiring it for one affordance isn't
/// honest plumbing). Documented in ipc.md.
pub trait Notifier: Send + Sync {
    fn notify(&self, title: &str, body: &str) -> Result<(), String>;
}

/// Production sink: the notification plugin on the app handle.
pub struct TauriNotifier(pub tauri::AppHandle);

impl Notifier for TauriNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<(), String> {
        use tauri_plugin_notification::NotificationExt;
        self.0
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show()
            .map_err(|e| format!("{e}"))
    }
}

/// Strip controls + bound a preview field — subjects/senders are
/// untrusted bytes that render inside an OS surface.
fn clean_field(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    for ch in trimmed.chars() {
        if out.len() + ch.len_utf8() > FIELD_CAP {
            break;
        }
        out.push(ch);
    }
    out
}

/// The pure decision — every gate in one place so the unit test proves
/// the whole suppression matrix without a store or a desktop.
///
/// Returns `Some((title, body))` to show, or `None` when any rule
/// suppresses. `first` is `(sender, subject)` of the newest unseen
/// arrival; both may be absent → fallbacks, never an empty notification.
pub(crate) fn decide(
    folder_name: &str,
    unseen: u64,
    first: Option<(&str, &str)>,
    pref_off: bool,
    account_muted: bool,
    last_sent: Option<i64>,
    now: i64,
) -> Option<(String, String)> {
    if unseen == 0 || pref_off || account_muted {
        return None;
    }
    if EXCLUDED_FOLDERS.contains(&folder_name.to_ascii_lowercase().as_str()) {
        return None;
    }
    if let Some(t) = last_sent
        && now - t < NOTIFY_MIN_INTERVAL_SECS
    {
        return None;
    }
    let folder = clean_field(folder_name);
    let (sender, subject) = first.unwrap_or(("Unknown sender", "(no subject)"));
    let sender = clean_field(sender);
    let subject = clean_field(subject);
    let title = if unseen == 1 {
        format!("New message in {folder}")
    } else {
        format!("{unseen} new messages in {folder}")
    };
    let body = format!("{sender} — {subject}");
    Some((title, body))
}

/// Whether account `id` is listed in the `kiwi.muted` pref array.
fn account_muted(index: &crate::state::AppIndex, account_id: &str) -> bool {
    index
        .prefs
        .get(&pref_key(None, "kiwi.muted"))
        .and_then(|v| v.as_array())
        .is_some_and(|a| {
            a.iter()
                .any(|v| v.as_str().is_some_and(|s| s == account_id))
        })
}

/// Whether `kiwi.notify` is explicitly `"off"` (the settings toggle).
/// Absent/other values notify — the feature defaults on, mute is opt-out.
fn notify_pref_off(index: &crate::state::AppIndex) -> bool {
    index
        .prefs
        .get(&pref_key(None, "kiwi.notify"))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "off")
}

/// Post a notification if this sync pass landed new **unseen** messages
/// in `folder_id`. `before` is the folder's UID set snapshot taken before
/// the sync — the diff is the arrival set. Never returns an error.
pub(crate) async fn maybe_notify(
    state: &AppState,
    account_id: &str,
    folder_name: &str,
    folder_id: i64,
    before: &BTreeSet<u64>,
) {
    // Cheap first: no notifier (tests/headless) or empty diff → done.
    if state.notifier.lock().unwrap().is_none() {
        return;
    }
    let arrivals: Vec<u64> = {
        let store = state.store.lock().await;
        match store.folder_uids(folder_id) {
            Ok(uids) => uids
                .into_iter()
                .filter(|u| !before.contains(u))
                .take(512)
                .collect(),
            Err(_) => return,
        }
    };
    if arrivals.is_empty() {
        return;
    }
    // Unseen arrivals with envelope, newest-first — notification previews
    // the freshest, counts all unseen.
    let (unseen, first): (u64, Option<(String, String)>) = {
        let store = state.store.lock().await;
        let metas = match store.list_messages(folder_id, NOTIFY_SCAN) {
            Ok(m) => m,
            Err(_) => return,
        };
        let mut count = 0u64;
        let mut first = None;
        for m in &metas {
            if !arrivals.contains(&m.uid) {
                continue;
            }
            if m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\seen")) {
                continue;
            }
            count += 1;
            if first.is_none() {
                first = Some((
                    m.from_addr
                        .clone()
                        .unwrap_or_else(|| "Unknown sender".into()),
                    m.subject.clone().unwrap_or_else(|| "(no subject)".into()),
                ));
            }
        }
        (count, first)
    };
    if unseen == 0 {
        return;
    }
    let (pref_off, muted) = {
        let index = state.index.lock().await;
        (notify_pref_off(&index), account_muted(&index, account_id))
    };
    let key = (account_id.to_string(), folder_name.to_string());
    let last = state.notify_marks.lock().await.get(&key).copied();
    let Some((title, body)) = decide(
        folder_name,
        unseen,
        first.as_ref().map(|(s, j)| (s.as_str(), j.as_str())),
        pref_off,
        muted,
        last,
        now_unix(),
    ) else {
        return;
    };
    // Mark BEFORE the OS call — a desktop that refuses notifications is
    // rate-limited too, so a broken notifier can't fail every pass.
    state
        .notify_marks
        .lock()
        .await
        .insert(key.clone(), now_unix());
    let notifier = state.notifier.lock().unwrap().clone();
    if let Some(n) = notifier
        && let Err(e) = n.notify(&title, &body)
    {
        // Fail soft — a desktop that refuses notifications must not
        // turn into a failed sync. Logged for diagnosis only.
        eprintln!("[kiwi-app] notify {key:?}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(last: Option<i64>) -> (i64, Option<i64>) {
        (1_000_000, last)
    }

    #[test]
    fn decide_suppression_matrix() {
        let (now, _) = at(None);
        let show = |folder: &str, unseen: u64, pref: bool, muted: bool, last: Option<i64>| {
            decide(folder, unseen, Some(("a@x", "hi")), pref, muted, last, now)
        };
        // Base case notifies.
        assert!(show("INBOX", 1, false, false, None).is_some());
        // Nothing new / pref off / muted account → silent.
        assert!(show("INBOX", 0, false, false, None).is_none());
        assert!(show("INBOX", 1, true, false, None).is_none());
        assert!(show("INBOX", 1, false, true, None).is_none());
        // Junk + trash families never ding.
        for f in ["Junk", "SPAM", "Bulk Mail", "Trash", "Deleted Items"] {
            assert!(show(f, 3, false, false, None).is_none(), "{f} excluded");
        }
        // Custom folders do notify.
        assert!(show("Newsletters", 1, false, false, None).is_some());
        // Rate limit: inside the window → quiet; past it → ding.
        assert!(show("INBOX", 1, false, false, Some(now - 30)).is_none());
        assert!(show("INBOX", 1, false, false, Some(now - 61)).is_some());
    }

    #[test]
    fn decide_shape_single_vs_multi() {
        let (now, _) = at(None);
        let one = decide(
            "INBOX",
            1,
            Some(("Ann <a@x>", "Report")),
            false,
            false,
            None,
            now,
        )
        .unwrap();
        assert_eq!(one.0, "New message in INBOX");
        assert_eq!(one.1, "Ann <a@x> — Report");
        let many = decide("INBOX", 4, Some(("a@x", "s")), false, false, None, now).unwrap();
        assert_eq!(many.0, "4 new messages in INBOX");
        assert_eq!(many.1, "a@x — s");
        // Missing sender/subject get honest fallbacks.
        let bare = decide("INBOX", 1, None, false, false, None, now).unwrap();
        assert!(bare.1.contains("Unknown sender") && bare.1.contains("(no subject)"));
    }

    #[test]
    fn decide_sanitizes_untrusted_fields() {
        let (now, _) = at(None);
        let hostile = decide(
            "INBOX",
            1,
            Some(("a@x\r\nFAKE", &"x".repeat(300))),
            false,
            false,
            None,
            now,
        )
        .unwrap();
        assert!(!hostile.1.contains('\r') && !hostile.1.contains('\n'));
        assert!(hostile.1.len() <= FIELD_CAP + 32);
    }

    #[test]
    fn clean_field_bounds_and_strips() {
        assert_eq!(clean_field("a\nb\rc"), "a b c");
        assert!(clean_field(&"é".repeat(200)).len() <= FIELD_CAP);
        assert_eq!(clean_field(""), "");
    }

    // -- seam test: RecordingNotifier proves maybe_notify end-to-end ------

    struct Recorder(std::sync::Mutex<Vec<(String, String)>>);
    impl Notifier for Recorder {
        fn notify(&self, title: &str, body: &str) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((title.to_string(), body.to_string()));
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn maybe_notify_fires_once_suppresses_and_mutes() {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-notify-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = crate::state::AppState::open_test(dir.clone()).unwrap();
        let rec: Arc<Recorder> = Arc::new(Recorder(std::sync::Mutex::new(Vec::new())));
        *state.notifier.lock().unwrap() = Some(rec.clone());
        let fid = {
            let store = state.store.lock().await;
            store
                .upsert_account(&kiwi_mail::account::MailAccount {
                    account_id: "a1".into(),
                    display_name: "A".into(),
                    email: "a@x.test".into(),
                    incoming: kiwi_mail::account::IncomingAccount {
                        protocol: kiwi_mail::account::IncomingProtocol::Pop3,
                        server: kiwi_mail::account::ServerConfig {
                            host: "pop.x.test".into(),
                            port: 995,
                            security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                        },
                        username: "a".into(),
                        auth: kiwi_mail::account::AuthRef::None,
                    },
                    outgoing: kiwi_mail::account::OutgoingAccount {
                        server: kiwi_mail::account::ServerConfig {
                            host: "smtp.x.test".into(),
                            port: 465,
                            security: kiwi_mail::transport::SocketSecurity::ImplicitTls,
                        },
                        username: "a".into(),
                        auth: kiwi_mail::account::AuthRef::None,
                    },
                })
                .unwrap();
            let fid = store.ensure_folder("a1", "INBOX").unwrap();
            for (uid, seen) in [(1u64, false), (2, false), (3, true)] {
                store
                    .upsert_message(
                        fid,
                        &kiwi_mail::store::NewMessageMeta {
                            uid,
                            message_id: None,
                            subject: Some(format!("s{uid}")),
                            from_addr: Some("a@x".into()),
                            to_addrs: None,
                            date_unix: None,
                            size: None,
                            flags: if seen { vec!["\\Seen".into()] } else { vec![] },
                            has_attachments: false,
                            snippet: None,
                            category: Default::default(),
                            unsub_http: None,
                            unsub_mailto: None,
                            unsub_oneclick: false,
                        },
                        now_unix(),
                    )
                    .unwrap();
            }
            fid
        };
        let empty = BTreeSet::new();
        // First pass: 2 unseen arrivals → one ding, newest-first preview.
        maybe_notify(&state, "a1", "INBOX", fid, &empty).await;
        {
            let sent = rec.0.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, "2 new messages in INBOX");
        }
        // Immediate second pass: rate limiter swallows it.
        maybe_notify(&state, "a1", "INBOX", fid, &empty).await;
        assert_eq!(rec.0.lock().unwrap().len(), 1, "rate limit bites");
        // Global mute pref → silent even for a fresh folder.
        {
            let mut index = state.index.lock().await;
            index
                .prefs
                .insert(pref_key(None, "kiwi.notify"), serde_json::json!("off"));
        }
        let news = {
            let store = state.store.lock().await;
            let f = store.ensure_folder("a1", "News").unwrap();
            store
                .upsert_message(
                    f,
                    &kiwi_mail::store::NewMessageMeta {
                        uid: 7,
                        message_id: None,
                        subject: Some("n".into()),
                        from_addr: Some("b@y".into()),
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
                    },
                    now_unix(),
                )
                .unwrap();
            f
        };
        maybe_notify(&state, "a1", "News", news, &empty).await;
        assert_eq!(rec.0.lock().unwrap().len(), 1, "pref off mutes");
        // Unmute + muted-account list → account still silent.
        {
            let mut index = state.index.lock().await;
            index
                .prefs
                .insert(pref_key(None, "kiwi.notify"), serde_json::json!("on"));
            index
                .prefs
                .insert(pref_key(None, "kiwi.muted"), serde_json::json!(["a1"]));
        }
        maybe_notify(&state, "a1", "News", news, &empty).await;
        assert_eq!(rec.0.lock().unwrap().len(), 1, "muted account mutes");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
