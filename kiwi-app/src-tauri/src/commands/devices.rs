//! Device lifecycle + org-binding commands.
//!
//! The `kiwi_*` device names here are THIN COMPAT ALIASES over the canonical
//! §9d handlers in `commands/pair.rs` — `PairEngine` (persisted `pair.db`)
//! is the only device authority; there is no second implementation.

use std::sync::Arc;

use tauri::State;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{DeviceView, OrgBindingView, RegisterDeviceInput, SecurityStatusView};

/// Compat alias for §9d's registration seam — renderer-supplied label +
/// public key, `pending` until a `device-pairing` challenge completes.
/// Delegates to `PairEngine::register_device` (Ed25519-only, exactly 32
/// key bytes, normalized-label conflict — the ticket-claim path enforces
/// the same rules).
#[tauri::command]
pub async fn kiwi_register_device(
    state: State<'_, Arc<AppState>>,
    input: RegisterDeviceInput,
) -> CmdResult<DeviceView> {
    gate(state.inner()).await?;
    super::pair::register_device_impl(state.inner(), input).await
}

/// Compat alias for canonical `device_list` (§9d.5).
#[tauri::command]
pub async fn kiwi_list_devices(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<DeviceView>> {
    super::pair::device_list_impl(state.inner()).await
}

/// Compat alias for canonical `device_revoke` (§9d.6) — terminal,
/// persisted, idempotent.
#[tauri::command]
pub async fn kiwi_revoke_device(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> CmdResult<SecurityStatusView> {
    super::pair::device_revoke_impl(state.inner(), &device_id).await
}

/// Bind this client to an org's local admin service (send-path policy
/// bridge, admin-api §10). Loopback-only is enforced by the bridge itself.
#[tauri::command]
pub async fn kiwi_set_org_binding(
    state: State<'_, Arc<AppState>>,
    org_id: Option<String>,
    base_url: Option<String>,
) -> CmdResult<Option<OrgBindingView>> {
    gate(state.inner()).await?;
    set_org_binding_impl(state.inner(), org_id, base_url).await
}

pub(crate) async fn set_org_binding_impl(
    state: &AppState,
    org_id: Option<String>,
    base_url: Option<String>,
) -> CmdResult<Option<OrgBindingView>> {
    let binding = match (org_id, base_url) {
        (Some(org_id), Some(base_url)) => {
            bounded("orgId", &org_id, 128)?;
            bounded("baseUrl", &base_url, 256)?;
            // Validate loopback now so a bad URL fails at config time.
            crate::bridge::check_loopback(&base_url)?;
            Some(crate::state::OrgBinding { org_id, base_url })
        }
        (None, None) => None,
        _ => {
            return Err(IpcError::invalid(
                "orgId and baseUrl must be provided together (or neither, to clear)",
            ));
        }
    };
    let view = binding.as_ref().map(|b| OrgBindingView {
        org_id: b.org_id.clone(),
        base_url: b.base_url.clone(),
    });
    {
        let mut index = state.index.lock().await;
        index.org = binding;
        index.save(&state.data_dir)?;
    }
    state.audit.lock().await.record(
        "org-binding",
        &match &view {
            Some(v) => format!("bound to {} via {}", v.org_id, v.base_url),
            None => "cleared".to_string(),
        },
        now_unix(),
    )?;
    Ok(view)
}
