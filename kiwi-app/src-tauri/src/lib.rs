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
mod error;
mod observe;
mod signals;
mod state;
mod syncer;
mod types;
mod verifier;

use tauri::Manager;

use commands::accounts::*;
use commands::autoconfig::*;
use commands::contacts::*;
use commands::devices::*;
use commands::endpoint::*;
use commands::integrations::*;
use commands::mail::*;
use commands::message::*;
use commands::oauth2::*;
use commands::prefs::*;
use commands::rules::*;
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
            kiwi_list_messages,
            kiwi_search_messages,
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
            kiwi_message_unsubscribe,
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
            // endpoint signals (exempt — feeds trust)
            kiwi_collect_endpoint_signals,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kiwi application");
}
