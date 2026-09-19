//! Device lifecycle + org-binding commands.

use std::sync::Arc;

use base64::Engine;
use tauri::State;

use kiwi_core::device::{Device, DevicePublicKey};

use super::{bounded, gate, status_view};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, new_id, now_unix};
use crate::types::{DeviceView, OrgBindingView, RegisterDeviceInput, SecurityStatusView};

/// Register an authenticator device (Phase 3/4 seam): stores the public key,
/// status `pending` until a `device-pairing` challenge completes. The
/// private key never leaves the device — we only ever see the public half.
#[tauri::command]
pub async fn kiwi_register_device(
    state: State<'_, Arc<AppState>>,
    input: RegisterDeviceInput,
) -> CmdResult<DeviceView> {
    gate(state.inner()).await?;
    register_device_impl(state.inner(), input).await
}

pub(crate) async fn register_device_impl(
    state: &AppState,
    input: RegisterDeviceInput,
) -> CmdResult<DeviceView> {
    bounded("label", &input.label, 128)?;
    let algorithm = crate::types::parse_key_algorithm(&input.algorithm)
        .ok_or_else(|| IpcError::invalid("algorithm must be ed25519|ecdsa-p256|rsa3072"))?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(input.public_key_b64.as_bytes())
        .map_err(|_| IpcError::invalid("publicKeyB64 is not valid base64"))?;
    // Algorithm-specific sanity bounds on key size.
    let ok_len = match algorithm {
        kiwi_core::device::KeyAlgorithm::Ed25519 => key.len() == 32,
        kiwi_core::device::KeyAlgorithm::EcdsaP256 => (33..=65).contains(&key.len()),
        kiwi_core::device::KeyAlgorithm::Rsa3072 => (256..=1024).contains(&key.len()),
    };
    if !ok_len {
        return Err(IpcError::invalid("public key length wrong for algorithm"));
    }

    let device = Device {
        device_id: new_id("dev"),
        label: input.label.clone(),
        public_key: DevicePublicKey {
            algorithm,
            key,
            keystore_ref: input.keystore_ref.clone(),
        },
        status: kiwi_core::device::DeviceStatus::Pending,
        registered_unix: now_unix(),
        last_seen_unix: now_unix(),
        endpoint_signals: Vec::new(),
    };
    let view = DeviceView::from(&device);
    state
        .devices
        .lock()
        .await
        .register(device)
        .map_err(|e| IpcError::new("device-error", format!("register: {e:?}")))?;
    {
        let mut index = state.index.lock().await;
        if !index.device_ids.contains(&view.device_id) {
            index.device_ids.push(view.device_id.clone());
        }
        index.save(&state.data_dir)?;
    }
    state.audit.lock().await.record(
        "device-registered",
        &format!("{} ({})", view.label, view.device_id),
        now_unix(),
    )?;
    Ok(view)
}

#[tauri::command]
pub async fn kiwi_list_devices(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<DeviceView>> {
    gate(state.inner()).await?;
    list_devices_impl(state.inner()).await
}

pub(crate) async fn list_devices_impl(state: &AppState) -> CmdResult<Vec<DeviceView>> {
    let ids = state.index.lock().await.device_ids.clone();
    let devices = state.devices.lock().await;
    Ok(ids
        .iter()
        .filter_map(|id| devices.get(id).map(DeviceView::from))
        .collect())
}

/// Terminal revocation — audited. Revoking this endpoint's own device id
/// feeds `device-revoked` into the next trust evaluation (hard-lock kind).
#[tauri::command]
pub async fn kiwi_revoke_device(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> CmdResult<SecurityStatusView> {
    gate(state.inner()).await?;
    revoke_device_impl(state.inner(), &device_id).await
}

pub(crate) async fn revoke_device_impl(
    state: &AppState,
    device_id: &str,
) -> CmdResult<SecurityStatusView> {
    bounded("deviceId", device_id, 128)?;
    state
        .devices
        .lock()
        .await
        .revoke(device_id)
        .map_err(|e| match e {
            kiwi_core::device::RegistryError::NotFound => IpcError::not_found("unknown device"),
            other => IpcError::new("device-error", format!("revoke: {other:?}")),
        })?;
    state
        .audit
        .lock()
        .await
        .record("device-revoked", device_id, now_unix())?;
    state.refresh_trust().await;
    Ok(status_view(state).await)
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
