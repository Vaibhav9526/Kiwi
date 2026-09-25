//! Preferences wire view (T-175) — the settings-UI key/value store.

use serde::Serialize;

/// `kiwi_prefs_list` row — `{key, value}` within one scope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefEntryView {
    pub key: String,
    pub value: serde_json::Value,
}
