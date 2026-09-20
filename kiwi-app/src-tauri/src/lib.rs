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
mod error;
mod observe;
mod signals;
mod state;
mod syncer;
mod types;
mod verifier;

use tauri::Manager;

use commands::accounts::*;
use commands::devices::*;
use commands::endpoint::*;
use commands::mail::*;
use commands::message::*;
use commands::security::*;
use commands::send::*;
use commands::system::*;

/// IPC contract version — bump on breaking changes (ipc.md §1).
pub const IPC_CONTRACT_VERSION: &str = "kiwi.ipc/1";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Data dir: app_data_dir when resolvable, else a temp dir (dev).
            let dir = match app.path().app_data_dir() {
                Ok(d) => d,
                Err(_) => std::env::temp_dir().join("kiwi-app-data"),
            };
            let state = state::AppState::open(dir)
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            app.manage(std::sync::Arc::new(state));
            // Background outbox dispatcher (undo-send grace + send-later).
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(commands::send::outbox_loop(handle));
            // Live-sync supervisor (T-157): one worker per account,
            // IDLE-driven updates → kiwi://mail-changed.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(syncer::sync_supervisor(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // system / lock path (exempt)
            kiwi_ping,
            kiwi_app_info,
            kiwi_security_status,
            kiwi_lock,
            kiwi_request_challenge,
            kiwi_submit_challenge,
            // accounts (gated)
            kiwi_list_accounts,
            kiwi_add_account,
            kiwi_remove_account,
            kiwi_test_account,
            kiwi_verify_server,
            // mail read (gated)
            kiwi_list_folders,
            kiwi_list_messages,
            kiwi_get_message,
            kiwi_sync_account,
            kiwi_sync_status,
            // message actions (gated)
            kiwi_update_message,
            kiwi_delete_messages,
            kiwi_move_messages,
            kiwi_download_attachment,
            kiwi_render_body,
            kiwi_set_remote_content,
            // send (gated)
            kiwi_send_message,
            kiwi_cancel_send,
            kiwi_schedule_send,
            kiwi_list_outbox,
            kiwi_flush_outbox,
            // security data (gated)
            kiwi_security_findings,
            kiwi_security_events,
            kiwi_finding_detail,
            kiwi_session_detail,
            kiwi_security_report,
            // devices + org binding (gated)
            kiwi_register_device,
            kiwi_list_devices,
            kiwi_revoke_device,
            kiwi_set_org_binding,
            // endpoint signals (exempt — feeds trust)
            kiwi_collect_endpoint_signals,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kiwi application");
}
