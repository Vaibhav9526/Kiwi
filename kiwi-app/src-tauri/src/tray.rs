//! System tray (T-345) — the desktop-client keep-alive surface: without a
//! tray, closing the window kills sync + notifications, so the window's X
//! can park the app in the tray while mail keeps flowing.
//!
//! Shape (mirrors `notify.rs`): pure decision fns for every choice, a
//! `TooltipSink` seam so the OS call stays mockable, and the Tauri handles
//! looked up on demand (`tray_by_id`, `get_webview_window`) rather than
//! cached — a removed tray can't leave a dangling handle.
//!
//! Honest bounds:
//! - **Close-to-tray is a pref, not a trap.** `kiwi.trayOnClose` defaults
//!   ON (the feature exists because closing killed sync — opt-out, not
//!   opt-in); `"off"` restores plain close-quits. The mirror lives in
//!   `state.tray_on_close` (AtomicBool) because `on_window_event` is a
//!   sync main-thread callback that cannot await the tokio-guarded index.
//!   `kiwi_prefs_set` keeps the mirror in sync and audits the change.
//! - **No tray → no hide.** If `TrayIconBuilder::build` failed (platforms
//!   without a tray, missing icon) `tray_live` stays false and X just
//!   quits — parking a windowless app with no way back would be a bug,
//!   not a feature. `trayAvailable` on `kiwi_app_info` reports the truth.
//! - **Quit means quit.** The menu Quit exits for real — but not over a
//!   non-empty outbox: pending sends first surface a renderer confirm
//!   (`kiwi://confirm-quit` → `kiwi_confirm_quit`), because silently
//!   dropping queued mail is the one thing worse than a modal. An
//!   unreadable outbox count takes the confirm path, never the silent
//!   exit — the guard fails toward honesty.
//! - **Left click restores, right click menus** (`menu_on_left_click`
//!   off) — the tooltip count reads at a glance without opening anything.
//! - **Tooltip is event-driven, never polled.** `refresh_tooltip` runs
//!   where mail state actually changes: the four post-sync sites that
//!   also drive `maybe_notify`, plus the message-mutation commands
//!   (update/delete/copy/junk/import). The count is `total_unseen` — the
//!   same mute-aware predicate as `folder_stats`, so the tray number
//!   equals the summed badges rather than a second definition of unread.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

use crate::state::{AppIndex, AppState, pref_key};

/// Tray icon id — `tray_by_id` lookups resolve the live handle.
pub(crate) const TRAY_ID: &str = "main";
/// Renderer event: tray Compose → show the window on the compose route.
pub const TRAY_COMPOSE_EVENT: &str = "kiwi://tray-compose";
/// Renderer event: Quit was picked with sends still queued — the webview
/// owns the confirm dialog; `kiwi_confirm_quit` performs the exit.
pub const QUIT_REQUESTED_EVENT: &str = "kiwi://confirm-quit";

const MENU_TOGGLE: &str = "tray.toggle";
const MENU_COMPOSE: &str = "tray.compose";
const MENU_QUIT: &str = "tray.quit";

// ---- pure decisions (no OS calls — fully testable) ---------------------

/// What the main window's X does. Hiding is only honest while a tray
/// exists to come back from — `tray_live` false makes X a real quit even
/// when the pref is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseOutcome {
    HideToTray,
    Quit,
}

pub(crate) fn decide_close(pref_on: bool, tray_live: bool) -> CloseOutcome {
    if pref_on && tray_live {
        CloseOutcome::HideToTray
    } else {
        CloseOutcome::Quit
    }
}

/// What the tray Quit item does. Any queued send blocks the silent exit —
/// the renderer must confirm first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuitOutcome {
    ExitNow,
    NeedsConfirm { pending: u64 },
}

pub(crate) fn decide_quit(pending: u64) -> QuitOutcome {
    if pending == 0 {
        QuitOutcome::ExitNow
    } else {
        QuitOutcome::NeedsConfirm { pending }
    }
}

/// The tooltip text. `0` unread shows the bare product name — a
/// "KIWI — 0 unread" badge would be noise, and the absence of a number
/// is itself the honest signal.
pub(crate) fn tooltip(unseen: u64) -> String {
    if unseen == 0 {
        "KIWI".to_string()
    } else {
        format!("KIWI — {unseen} unread")
    }
}

/// `kiwi.trayOnClose` — absent, or anything other than the literal string
/// `"off"`, means ON. Default-on is the honest choice for a mail client:
/// the ticket exists because users expected closing the window not to
/// stop mail. The settings toggle + Quit item keep opt-out one click away.
pub(crate) fn tray_on_close_pref(index: &AppIndex) -> bool {
    index
        .prefs
        .get(&pref_key(None, "kiwi.trayOnClose"))
        .and_then(|v| v.as_str())
        != Some("off")
}

// ---- tooltip sink seam --------------------------------------------------

/// The tooltip write — production targets the built tray icon; tests
/// record. Same `Notifier`-style seam as notify.rs.
pub trait TooltipSink: Send + Sync {
    fn set_tooltip(&self, text: &str) -> Result<(), String>;
}

/// Production sink: the live tray icon resolved per call — if the icon is
/// gone there is nothing to update, which is a no-op, not an error.
pub struct TrayTooltip(pub AppHandle);

impl TooltipSink for TrayTooltip {
    fn set_tooltip(&self, text: &str) -> Result<(), String> {
        match self.0.tray_by_id(TRAY_ID) {
            Some(tray) => tray.set_tooltip(Some(text)).map_err(|e| format!("{e}")),
            None => Ok(()),
        }
    }
}

/// Recompute "KIWI — N unread" and push it. Called from sync passes and
/// message mutations; a no-op without a live tray. A store read failure
/// leaves the last tooltip standing — a stale count beats claiming 0.
pub(crate) async fn refresh_tooltip(state: &AppState) {
    if !state.tray_live.load(Ordering::Relaxed) {
        return;
    }
    let sink = state.tray_tip.lock().unwrap().clone();
    let Some(sink) = sink else { return };
    let unseen = {
        let store = state.store.lock().await;
        match store.total_unseen() {
            Ok(n) => n,
            Err(_) => return,
        }
    };
    if let Err(e) = sink.set_tooltip(&tooltip(unseen)) {
        eprintln!("[kiwi-app] tray tooltip: {e}");
    }
}

// ---- window + menu plumbing ---------------------------------------------

/// Show + focus the main window (restore from tray / compose / confirm).
fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn toggle_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        match w.is_visible() {
            Ok(true) => {
                let _ = w.hide();
            }
            _ => show_main(app),
        }
    }
}

/// Tray Quit: count pending sends first — a non-empty outbox routes to a
/// renderer confirm instead of silently discarding queued mail. The store
/// read runs on the async runtime (menu callbacks are sync).
async fn quit_flow(app: &AppHandle) {
    let pending = {
        let state = app.state::<Arc<AppState>>();
        let store = state.store.lock().await;
        // Unreadable outbox → assume pending: the confirm path is the
        // honest answer to "we cannot prove nothing is queued".
        store.outbox_count().unwrap_or(1)
    };
    match decide_quit(pending) {
        QuitOutcome::ExitNow => app.exit(0),
        QuitOutcome::NeedsConfirm { pending } => {
            show_main(app);
            let _ = app.emit(
                QUIT_REQUESTED_EVENT,
                serde_json::json!({ "pending": pending }),
            );
        }
    }
}

fn on_menu(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        MENU_TOGGLE => toggle_main(app),
        MENU_COMPOSE => {
            show_main(app);
            let _ = app.emit(TRAY_COMPOSE_EVENT, ());
        }
        MENU_QUIT => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { quit_flow(&app).await });
        }
        _ => {}
    }
}

fn on_icon_event(tray: &TrayIcon, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        show_main(tray.app_handle());
    }
}

/// Window close handler for `Builder::on_window_event` — the main
/// window's X becomes hide-to-tray only while the pref is on AND a tray
/// icon actually exists; everything else keeps default close semantics
/// (window drops → app exits).
pub(crate) fn on_window_close(window: &tauri::Window, api: &tauri::CloseRequestApi) {
    if window.label() != "main" {
        return;
    }
    let state = window.state::<Arc<AppState>>();
    let outcome = decide_close(
        state.tray_on_close.load(Ordering::Relaxed),
        state.tray_live.load(Ordering::Relaxed),
    );
    if outcome == CloseOutcome::HideToTray {
        api.prevent_close();
        let _ = window.hide();
    }
}

/// Build the tray icon. Returns `Ok(false)` when the platform offers no
/// tray (`build` failed) — the caller leaves `tray_live` false and X
/// stays a real quit. An error propagates: a build-time failure at setup
/// is loud, not silent.
pub(crate) fn install(app: &tauri::App) -> Result<bool, tauri::Error> {
    let toggle = MenuItem::with_id(app, MENU_TOGGLE, "Show / Hide KIWI", true, None::<&str>)?;
    let compose = MenuItem::with_id(app, MENU_COMPOSE, "Compose", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "Quit KIWI", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&toggle, &compose, &quit])?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("KIWI")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(on_menu)
        .on_tray_icon_event(on_icon_event);
    // The verified bundle icon (icons/icon.png via default_window_icon) —
    // the real KIWI mark, not a placeholder.
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    match builder.build(app) {
        Ok(_) => Ok(true),
        // Any build failure is a platform-tray failure: log it and degrade —
        // propagating would refuse to launch on a trayless desktop, which is
        // a regression, not degradation. `trayAvailable` still reports false.
        Err(e) => {
            eprintln!("[kiwi-app] tray unavailable: {e}");
            Ok(false)
        }
    }
}

/// `kiwi_confirm_quit` — the renderer's half of the Quit flow: emitted
/// after the user confirms over a non-empty outbox (or presses the
/// confirm button). Exempt from the lock gate on purpose: quitting a
/// locked app leaks nothing, and locking must never trap the process.
#[tauri::command]
pub async fn kiwi_confirm_quit(app: AppHandle) {
    app.exit(0)
}

/// Re-export for `lib.rs`'s `on_window_event` adapter — keeps the match
/// on `WindowEvent` beside the builder call.
pub(crate) fn handle_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        on_window_close(window, api);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::pref_key as pk;
    use std::sync::Mutex as StdMutex;

    // -- pure decision fns -------------------------------------------------

    #[test]
    fn close_decision_matrix() {
        // pref on + live tray → park; every other combination quits.
        assert_eq!(decide_close(true, true), CloseOutcome::HideToTray);
        assert_eq!(decide_close(false, true), CloseOutcome::Quit);
        assert_eq!(decide_close(true, false), CloseOutcome::Quit);
        assert_eq!(decide_close(false, false), CloseOutcome::Quit);
    }

    #[test]
    fn quit_guard_blocks_on_pending_sends() {
        assert_eq!(decide_quit(0), QuitOutcome::ExitNow);
        assert_eq!(
            decide_quit(3),
            QuitOutcome::NeedsConfirm { pending: 3 },
            "queued sends must surface a confirm, never a silent exit"
        );
    }

    #[test]
    fn tooltip_shows_real_count_or_bare_name() {
        assert_eq!(tooltip(0), "KIWI");
        assert_eq!(tooltip(1), "KIWI — 1 unread");
        assert_eq!(tooltip(1_000_000), "KIWI — 1000000 unread");
    }

    #[test]
    fn tray_pref_defaults_on_and_only_off_string_disables() {
        let mut index = AppIndex::default();
        assert!(tray_on_close_pref(&index), "absent → on");
        index
            .prefs
            .insert(pk(None, "kiwi.trayOnClose"), serde_json::json!("off"));
        assert!(!tray_on_close_pref(&index));
        index
            .prefs
            .insert(pk(None, "kiwi.trayOnClose"), serde_json::json!("on"));
        assert!(tray_on_close_pref(&index));
        // Hostile/non-string values → on (fail toward the feature, not
        // toward silently quitting the keep-alive).
        index
            .prefs
            .insert(pk(None, "kiwi.trayOnClose"), serde_json::json!(42));
        assert!(tray_on_close_pref(&index));
    }

    // -- store-level integration --------------------------------------------

    struct RecordingTip {
        calls: StdMutex<Vec<String>>,
        fail: bool,
    }
    impl TooltipSink for RecordingTip {
        fn set_tooltip(&self, text: &str) -> Result<(), String> {
            if self.fail {
                return Err("desktop refused".into());
            }
            self.calls.lock().unwrap().push(text.to_string());
            Ok(())
        }
    }

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-tray-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    fn account() -> kiwi_mail::account::MailAccount {
        kiwi_mail::account::MailAccount {
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
        }
    }

    fn meta(uid: u64, flags: &[&str]) -> kiwi_mail::store::NewMessageMeta {
        kiwi_mail::store::NewMessageMeta {
            uid,
            message_id: None,
            subject: Some(format!("subj {uid}")),
            from_addr: Some("s@y.test".into()),
            to_addrs: None,
            date_unix: None,
            size: None,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            has_attachments: false,
            snippet: None,
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
        }
    }

    /// The sink records the real count, a dead tray never writes, and a
    /// failing desktop only logs — nothing propagates.
    #[tokio::test(flavor = "current_thread")]
    async fn refresh_tooltip_counts_unseen_and_degrades() {
        let state = test_state("tip");
        {
            let store = state.store.lock().await;
            store.upsert_account(&account()).unwrap();
            let inbox = store.ensure_folder("a1", "INBOX").unwrap();
            store
                .upsert_message(inbox, &meta(1, &[]), 1_758_000_000)
                .unwrap(); // unseen
            store
                .upsert_message(inbox, &meta(2, &["\\Seen"]), 1_758_000_000)
                .unwrap(); // read
            store
                .upsert_message(inbox, &meta(3, &[]), 1_758_000_000)
                .unwrap(); // unseen
        }
        let tip = Arc::new(RecordingTip {
            calls: StdMutex::new(vec![]),
            fail: false,
        });
        *state.tray_tip.lock().unwrap() = Some(tip.clone());

        // Dead tray: no write happens at all.
        refresh_tooltip(&state).await;
        assert!(tip.calls.lock().unwrap().is_empty());

        // Live tray: the real unseen count (2 of 3) rides the tooltip.
        state.tray_live.store(true, Ordering::Relaxed);
        refresh_tooltip(&state).await;
        assert_eq!(tip.calls.lock().unwrap().as_slice(), &["KIWI — 2 unread"]);

        // A failing desktop is swallowed, never propagated.
        *state.tray_tip.lock().unwrap() = Some(Arc::new(RecordingTip {
            calls: StdMutex::new(vec![]),
            fail: true,
        }));
        refresh_tooltip(&state).await; // must not panic/return early
    }
}
