//! User preferences (T-175) — small key/value store in the sidecar
//! index for the settings UI. Two scopes: global (`accountId` absent)
//! and per-account (`accountId` present, must name a known account —
//! a typo'd id must not silently write into the void). Values are
//! arbitrary JSON, bounded at 64 KiB serialized; keys are bounded and
//! `:` is reserved as the scope separator. Nothing here is a secret —
//! credentials live in the OS store, never in prefs.

use std::sync::Arc;

use tauri::State;

use super::{bounded, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, MAX_PREFS, pref_key};
use crate::types::PrefEntryView;

const MAX_PREF_KEY: usize = 128;
const MAX_PREF_VALUE_BYTES: usize = 64 * 1024;

/// Validate the caller's key + scope, returning the storage key.
fn scope_key(
    state_index: &crate::state::AppIndex,
    account_id: Option<&str>,
    key: &str,
) -> CmdResult<String> {
    if key.is_empty() {
        return Err(IpcError::invalid("pref key must not be empty"));
    }
    bounded("key", key, MAX_PREF_KEY)?;
    if key.contains(':') {
        return Err(IpcError::invalid(
            "pref key must not contain ':' (scope separator)",
        ));
    }
    if let Some(id) = account_id {
        bounded("accountId", id, 128)?;
        if !state_index.account_ids.iter().any(|a| a == id) {
            return Err(IpcError::not_found("unknown account"));
        }
    }
    Ok(pref_key(account_id, key))
}

/// `kiwi_prefs_get(key, accountId?)` → the stored JSON value, or `null`
/// when the key was never set in that scope.
#[tauri::command]
pub async fn kiwi_prefs_get(
    state: State<'_, Arc<AppState>>,
    key: String,
    account_id: Option<String>,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    let index = state.index.lock().await;
    let k = scope_key(&index, account_id.as_deref(), &key)?;
    Ok(index
        .prefs
        .get(&k)
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

/// `kiwi_prefs_set(key, accountId?, value)` → `{key, value}` — the
/// stored entry echo. Overwrites an existing key in the same scope.
#[tauri::command]
pub async fn kiwi_prefs_set(
    state: State<'_, Arc<AppState>>,
    key: String,
    account_id: Option<String>,
    value: serde_json::Value,
) -> CmdResult<PrefEntryView> {
    gate(state.inner()).await?;
    // Serialized-size bound — the index is a JSON file; an unbounded
    // value would make it a blob store.
    let size = serde_json::to_vec(&value)
        .map_err(|e| IpcError::invalid(format!("pref value not serializable: {e}")))?
        .len();
    if size > MAX_PREF_VALUE_BYTES {
        return Err(IpcError::invalid(format!(
            "pref value exceeds {MAX_PREF_VALUE_BYTES} bytes serialized"
        )));
    }
    let mut index = state.index.lock().await;
    let k = scope_key(&index, account_id.as_deref(), &key)?;
    if !index.prefs.contains_key(&k) && index.prefs.len() >= MAX_PREFS {
        return Err(IpcError::invalid(format!(
            "prefs full ({MAX_PREFS} entries)"
        )));
    }
    index.prefs.insert(k, value.clone());
    index.save(&state.data_dir)?;
    drop(index);
    Ok(PrefEntryView { key, value })
}

/// `kiwi_prefs_list(accountId?)` → every `{key, value}` in the scope,
/// ordered by key (settings pages enumerate rather than guess keys).
#[tauri::command]
pub async fn kiwi_prefs_list(
    state: State<'_, Arc<AppState>>,
    account_id: Option<String>,
) -> CmdResult<Vec<PrefEntryView>> {
    gate(state.inner()).await?;
    let index = state.index.lock().await;
    // A sentinel key validates the scope (account existence) without
    // touching storage.
    let prefix = scope_key(&index, account_id.as_deref(), "-")?;
    let prefix = prefix.trim_end_matches('-').to_string();
    Ok(index
        .prefs
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix(&prefix).map(|key| PrefEntryView {
                key: key.to_string(),
                value: v.clone(),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::accounts::add_account_impl;
    use crate::types::{AddAccountInput, AuthInput, ServerInput};

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-prefs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    fn acct_input() -> AddAccountInput {
        AddAccountInput {
            display_name: "A".into(),
            email: "a@x.test".into(),
            incoming_protocol: "imap".into(),
            incoming: ServerInput {
                host: "127.0.0.1".into(),
                port: 1,
                security: "tls".into(),
            },
            outgoing: ServerInput {
                host: "127.0.0.1".into(),
                port: 1,
                security: "tls".into(),
            },
            username: None,
            outgoing_username: None,
            incoming_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
            }),
            outgoing_auth: Some(AuthInput {
                kind: "password".into(),
                secret: Some("s".into()),
            }),
            accept_invalid_certs: false,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prefs_scopes_are_independent_and_persisted() {
        let state = test_state("scopes");
        let acct = add_account_impl(&state, acct_input()).await.unwrap();
        {
            let mut index = state.index.lock().await;
            index
                .prefs
                .insert(pref_key(None, "theme"), serde_json::json!("dark"));
            index.prefs.insert(
                pref_key(Some(&acct.id), "signature"),
                serde_json::json!("-- A"),
            );
            index.save(&state.data_dir).unwrap();
        }
        let index = state.index.lock().await;
        assert_eq!(
            index.prefs.get("global:theme"),
            Some(&serde_json::json!("dark"))
        );
        assert_eq!(
            index.prefs.get(&format!("acct:{}:signature", acct.id)),
            Some(&serde_json::json!("-- A"))
        );
        // Scopes don't leak into each other.
        assert!(!index.prefs.contains_key("global:signature"));
        // Persists across reopen (index.json on disk).
        drop(index);
        let idx2 = crate::state::AppIndex::load(&state.data_dir).unwrap();
        assert_eq!(
            idx2.prefs.get("global:theme"),
            Some(&serde_json::json!("dark"))
        );
    }

    #[test]
    fn pref_key_rejects_separator_and_unknown_account() {
        let index = crate::state::AppIndex::default();
        assert!(scope_key(&index, None, "ok.key-1").is_ok());
        assert!(scope_key(&index, None, "bad:key").is_err());
        assert!(scope_key(&index, None, "").is_err());
        assert!(scope_key(&index, Some("ghost"), "k").is_err()); // unknown account
    }
}
