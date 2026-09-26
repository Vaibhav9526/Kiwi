//! Conversation-mute wire views (T-341, Thunderbird "Ignore Thread").
//!
//! The conversation identity is the list view's own thread key, so the UI
//! passes back exactly what it displays and no new client-side grouping is
//! needed. See `kiwi-mail/src/threading.rs` for the honest limits of that
//! grouping.

use serde::Serialize;

/// `kiwi_thread_set_muted` receipt — the resulting state, echoed so a caller
/// never has to re-read to learn whether its request took effect.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadMuteView {
    /// Echo of the `conversationId` argument, verbatim.
    pub conversation_id: String,
    /// The account the conversation was muted on. A mute is per account, so
    /// the same subject on another account is a different conversation.
    pub account_id: String,
    /// The state now in effect (echoes the `muted` argument; both directions
    /// are idempotent).
    pub muted: bool,
    /// `true` when this call changed the stored state. A redundant repeat
    /// returns `false` rather than pretending to have done work.
    pub changed: bool,
}
