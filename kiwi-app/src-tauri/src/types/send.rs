//! Send-path wire views — compose inputs, receipts, outbox rows/events.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInput {
    pub filename: String,
    pub content_type: String,
    /// Base64 payload — decoded server-side with a size bound.
    pub data_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeInput {
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    /// Plain-text body (required; may be empty string).
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOptions {
    /// Send-later: earliest dispatch (unix seconds).
    #[serde(default)]
    pub send_at_unix: Option<i64>,
    /// Undo-send grace window in seconds (default 10, capped at 120).
    #[serde(default)]
    pub undo_grace_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendReceipt {
    pub queue_id: String,
    /// Earliest dispatch time (unix seconds).
    pub not_before_unix: i64,
    /// Undo-send cancel deadline (unix seconds).
    pub undo_window_until_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxItem {
    pub queue_id: String,
    pub account_id: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub not_before_unix: i64,
    pub undo_window_until_unix: i64,
    pub attempts: u32,
    /// Whether `kiwi_cancel_send` can still undo it.
    pub cancelable: bool,
}

/// `kiwi://outbox` event payload — emitted by the dispatcher.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxEvent {
    pub queue_id: String,
    pub account_id: String,
    /// "sent" | "failed" | "held" | "blocked".
    pub status: String,
    pub detail: String,
    pub at_unix: i64,
}
