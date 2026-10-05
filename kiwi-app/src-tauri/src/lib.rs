//! KIWI app backend — the Tauri 2 IPC layer for the standalone
//! security-first mail client (T-120, T-121).
//!
//! Architecture (docs/ARCHITECTURE.md, post-pivot): the webview is
//! untrusted (SECURITY.md boundary B2); every `kiwi_*` command validates
//! input, runs the lock gate, and delegates to kiwi-mail / kiwi-core /
//! kiwi-forensics. Secrets never enter the mail store or IPC responses —
//! `AuthRef` carries credential-store keys only (credstore.rs).
//!
//! Command catalog: `docs/contracts/ipc.md`.

mod audit;
mod bridge;
mod commands;
mod credstore;
mod discovery_net;
#[cfg(test)]
mod e2e;
mod error;
mod notify;
mod observe;
mod pairing_listen;
mod send_consent;
mod signals;
mod state;
mod syncer;
mod tray;
mod types;

use tauri::Manager;

use commands::accounts::*;
use commands::autoconfig::*;
use commands::contacts::*;
use commands::devices::*;
use commands::endpoint::*;
use commands::export::*;
use commands::folders::*;
use commands::import::*;
use commands::integrations::*;
use commands::link::kiwi_link_click;
use commands::mail::*;
use commands::message::*;
use commands::oauth2::*;
use commands::pair::*;
use commands::prefs::*;
use commands::rules::*;
use commands::sandbox::*;
use commands::security::*;
use commands::send::*;
use commands::storage::*;
use commands::system::*;
use commands::templates::*;
use commands::thread::*;

/// IPC contract version — bump on breaking changes (ipc.md §1).
pub const IPC_CONTRACT_VERSION: &str = "kiwi.ipc/1";

// NOTE: no DWMWA_WINDOW_CORNER_PREFERENCE hack — the crate forbids unsafe,
/// and a decorated window (titleBarStyle Overlay) keeps Win11's native
/// rounded corners + frame shadow from DWM anyway. Only relevant if
/// decorations ever go off.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Data dir: app_data_dir when resolvable, else a temp dir (dev).
            let dir = match app.path().app_data_dir() {
                Ok(d) => d,
                Err(_) => std::env::temp_dir().join("kiwi-app-data"),
            };
            let state = state::AppState::open(dir)
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            // T-329: the OS-notification sink for sync-time new-mail dings.
            *state.notifier.lock().unwrap() = Some(std::sync::Arc::new(notify::TauriNotifier(
                app.handle().clone(),
            )));
            // T-345: the system tray — icon + menu (Show/Hide, Compose,
            // Quit) + the tooltip sink. `install` returning false means the
            // platform has no tray surface: `tray_live` stays false, X keeps
            // quit semantics, and `kiwi_app_info.trayAvailable` reports it.
            if tray::install(app)? {
                state
                    .tray_live
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                *state.tray_tip.lock().unwrap() =
                    Some(std::sync::Arc::new(tray::TrayTooltip(app.handle().clone())));
            }
            app.manage(std::sync::Arc::new(state));
            // Background outbox dispatcher (undo-send grace + send-later).
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(commands::send::outbox_loop(handle));
            // Live-sync supervisor (T-157): one worker per account,
            // IDLE-driven updates → kiwi://mail-changed.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(syncer::sync_supervisor(handle));
            // T-304: LAN pair-claim listener — present only when
            // KIWI_PAIR_LISTEN enabled a bind at open (plaintext dev seam;
            // wss/TLS ruling still pending, authenticator.md §3.2).
            let app_state = app.state::<std::sync::Arc<state::AppState>>();
            if let Some(sock) = app_state.inner().pair_listen_socket.lock().unwrap().take() {
                tauri::async_runtime::spawn(pairing_listen::serve(app_state.inner().clone(), sock));
            }
            Ok(())
        })
        // T-345: the main window's X routes through the tray decision —
        // hide-to-tray only while `kiwi.trayOnClose` is on AND a tray
        // icon actually exists; everything else keeps plain close=quit.
        .on_window_event(tray::handle_window_event)
        .invoke_handler(tauri::generate_handler![
            // system / lock path (exempt)
            kiwi_ping,
            kiwi_app_info,
            kiwi_security_status,
            kiwi_lock,
            kiwi_dev_unlock,
            tray::kiwi_confirm_quit,
            kiwi_request_challenge,
            kiwi_submit_challenge,
            // pairing engine (§9d — canonical names; kiwi_* above are aliases)
            pair_begin,
            pair_status,
            unlock_challenge,
            device_list,
            device_revoke,
            // accounts (gated)
            kiwi_list_accounts,
            kiwi_add_account,
            kiwi_remove_account,
            kiwi_test_account,
            kiwi_verify_server,
            kiwi_discover_account,
            kiwi_lookup_autoconfig,
            // oauth2 acquisition (gated)
            kiwi_oauth2_begin,
            kiwi_oauth2_poll,
            kiwi_oauth2_cancel,
            kiwi_open_external,
            kiwi_oauth2_status,
            // mail read (gated)
            kiwi_list_folders,
            kiwi_folder_create,
            kiwi_folder_rename,
            kiwi_folder_delete,
            kiwi_list_messages,
            kiwi_search_messages,
            kiwi_get_message,
            kiwi_message_source,
            kiwi_sync_account,
            kiwi_sync_status,
            kiwi_set_pop3_policy,
            kiwi_import_mbox,
            kiwi_mailbox_export_mbox,
            // message actions (gated)
            kiwi_update_message,
            kiwi_delete_messages,
            kiwi_move_messages,
            kiwi_copy_messages,
            kiwi_download_attachment,
            kiwi_render_body,
            kiwi_set_remote_content,
            kiwi_message_unsubscribe,
            // sandbox-open (gated, fail closed)
            kiwi_sandbox_open_link,
            kiwi_sandbox_open_attachment,
            kiwi_sandbox_sessions,
            kiwi_link_click,
            // snooze (gated — T-255, F-feature)
            kiwi_message_snooze,
            kiwi_message_unsnooze,
            kiwi_list_snoozed,
            // junk (gated — T-263, completes T-212)
            kiwi_message_set_junk,
            // send (gated)
            kiwi_send_message,
            kiwi_cancel_send,
            kiwi_schedule_send,
            kiwi_list_outbox,
            kiwi_flush_outbox,
            // storage diagnostics (gated — T-330: measured db size/health + VACUUM)
            kiwi_storage_stats,
            kiwi_storage_compact,
            // conversation mute (gated — T-341, Thunderbird "Ignore Thread")
            kiwi_thread_set_muted,
            kiwi_thread_list_muted,
            // security data (gated)
            kiwi_security_findings,
            kiwi_security_events,
            kiwi_audit_events,
            // audit integrity (ungated — see commands/security.rs)
            kiwi_audit_integrity,
            kiwi_finding_detail,
            kiwi_session_detail,
            kiwi_security_report,
            // forensic report file export (gated — T-320, self-verifying)
            kiwi_forensics_export,
            // devices + org binding (gated)
            kiwi_register_device,
            kiwi_list_devices,
            kiwi_revoke_device,
            kiwi_set_org_binding,
            // contacts (gated)
            kiwi_list_contacts,
            kiwi_search_contacts,
            kiwi_get_contact,
            kiwi_create_contact,
            kiwi_update_contact,
            kiwi_delete_contact,
            kiwi_contacts_by_email,
            kiwi_contacts_by_tag,
            kiwi_contact_tags,
            kiwi_import_vcards,
            kiwi_export_vcards,
            // prefs (gated)
            kiwi_prefs_get,
            kiwi_prefs_set,
            kiwi_prefs_list,
            // external integrations (gated — opt-in per action)
            kiwi_integrations_tempmail_create,
            kiwi_integrations_tempmail_poll,
            kiwi_integrations_tempmail_fetch,
            kiwi_integrations_tempmail_discard,
            kiwi_integrations_tempmail_extend,
            kiwi_integrations_deliverability_begin,
            kiwi_integrations_deliverability_send,
            kiwi_integrations_deliverability_status,
            kiwi_integrations_deliverability_report,
            // inbox rules (gated — F1/T-233)
            kiwi_rules_list,
            kiwi_rules_upsert,
            kiwi_rules_delete,
            kiwi_rules_apply_now,
            kiwi_rules_hits,
            kiwi_rules_preview,
            kiwi_blocklist_list,
            kiwi_blocklist_block,
            kiwi_blocklist_unblock,
            // message templates (gated — T-288)
            kiwi_templates_list,
            kiwi_templates_create,
            kiwi_templates_update,
            kiwi_templates_delete,
            kiwi_templates_render,
            // endpoint signals (exempt — feeds trust)
            kiwi_collect_endpoint_signals,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kiwi application");
}
