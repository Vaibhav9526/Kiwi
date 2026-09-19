//! kiwi-app backend — Tauri IPC surface.
//!
//! Thin command layer: every command validates input then delegates to
//! kiwi-mail / kiwi-core / kiwi-forensics / kiwi-admin. No business logic here.
//! Command names are the contract with the frontend — see
//! docs/contracts/ui-surfaces.md.

/// Health check so the frontend can verify the backend is live.
#[tauri::command]
fn kiwi_ping() -> String {
    "kiwi backend ok".to_string()
}

/// Placeholder: list configured mail accounts.
#[tauri::command]
async fn kiwi_list_accounts() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!([]))
}

/// Placeholder: current endpoint trust/lock state from kiwi-core.
#[tauri::command]
async fn kiwi_security_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "trust": "unknown", "locked": false }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            kiwi_ping,
            kiwi_list_accounts,
            kiwi_security_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kiwi application");
}
