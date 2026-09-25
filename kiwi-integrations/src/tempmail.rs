//! `TempMailProvider` — disposable inbox behind a clean boundary.
//!
//! # PUBLIC-INBOX WARNING (binding)
//!
//! Disposable inboxes are **public**: any message sent to a temp address is
//! readable by anyone who knows or guesses the address, and the content passes
//! through a third-party server KIWI does not control. Callers must surface
//! this in UI (`PUBLIC_INBOX_NOTICE`) and must never point real, personal, or
//! confidential mail at a temp address. Conversely, a temp inbox is a safe
//! sink for *outbound* tests (e.g. "does my message look right to a receiver")
//! and for receiving throwaway sign-up mail.
//!
//! # Shape
//!
//! One provider instance owns one mailbox session (GuerrillaMail sessions are
//! exactly this shape). Session state lives in memory only — nothing here
//! persists anything to disk or keystore, and `forget_me`/`Drop` leave no
//! residue. All methods are `&self` with interior locking so the provider can
//! sit behind IPC.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::IntegrationError;

pub mod guerrilla;
pub use guerrilla::GuerrillaMail;

/// Longest accepted local part (also GuerrillaMail's practical ceiling).
pub const MAX_LOCAL_PART: usize = 64;
/// Cap on `mail_body` text inside a fetched message (provider-filtered HTML).
pub const MAX_MAIL_BODY: usize = 4 * 1024 * 1024;
/// Cap on synthesized RFC822 output.
pub const MAX_RFC822: usize = MAX_MAIL_BODY + 16 * 1024;
/// Cap on a single summary field (subject/excerpt/etc.).
pub const MAX_FIELD: usize = 8 * 1024;

/// Mandatory disclosure text — UI must show this before enabling a temp
/// inbox. Kept here so copy cannot drift across surfaces.
pub const PUBLIC_INBOX_NOTICE: &str = "Temporary inboxes are PUBLIC: anyone who knows the address can read its mail, and \
     messages pass through a third-party server. Never receive personal or sensitive mail here.";

/// A disposable address as the provider reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempAddress {
    /// The full address (e.g. `abc123@guerrillamailblock.com`).
    pub address: String,
    /// Unix timestamp when the address was created server-side. GM addresses
    /// expire 60 min after creation (extendable to 2h via `extend`).
    pub created_unix: Option<u64>,
    /// Provider-assigned rotating session token when the API exposes one
    /// (GuerrillaMail `sid_token`). Opaque; never logged.
    #[serde(skip_serializing)]
    pub sid_token: Option<String>,
}

/// One inbox row from a poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempMessageSummary {
    /// Provider message id (GuerrillaMail ids are numeric strings).
    pub mail_id: String,
    /// Sender as the provider reports it (`mail_from`).
    pub from: String,
    /// Subject, provider HTML-entity escapes decoded.
    pub subject: String,
    /// Snippet, provider HTML-entity escapes decoded.
    pub excerpt: String,
    /// Unix timestamp of receipt, when present.
    pub timestamp_unix: Option<u64>,
    /// Provider display date (`mail_date`), verbatim.
    pub date: String,
    /// Whether the provider marks it read.
    pub read: bool,
}

/// Result of one `check_email` poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InboxPoll {
    /// Newest-first messages, capped at the provider's page size (GM: 20).
    pub messages: Vec<TempMessageSummary>,
    /// Total unseen count on the server — may exceed `messages.len()`.
    pub total_new: u64,
    /// Address the server answered for, when echoed (session resync signal).
    pub address: Option<String>,
}

/// A fetched message. `raw_rfc822` is **synthesized** (see `GuerrillaMail`
/// docs): the provider exposes structured fields + a pre-filtered body, not
/// the literal SMTP payload. Treat the bytes as hostile — render only via
/// KIWI's sanitized message path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempMessage {
    pub summary: TempMessageSummary,
    /// `Content-Type` as reported (e.g. `text/html`), when present.
    pub content_type: Option<String>,
    /// Synthesized RFC822: known headers + `\r\n` + verbatim body.
    pub raw_rfc822: Vec<u8>,
}

/// Result of `extend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendOutcome {
    /// Server says the address already expired (extension impossible).
    pub expired: bool,
    /// `affected == 1`: the address got its additional hour.
    pub extended: bool,
    /// Address creation timestamp as echoed by the server (can be in the
    /// future — the server is the clock authority).
    pub address_created_unix: Option<u64>,
}

/// Disposable-mailbox provider contract. Implementations: `GuerrillaMail`.
///
/// Implementors must: (1) speak HTTPS only, (2) keep all session state in
/// memory, (3) never log session tokens, cookies, or addresses into error
/// strings, (4) decode provider escaping before handing text out.
#[async_trait]
pub trait TempMailProvider: Send + Sync {
    /// Stable provider id, e.g. `"guerrillamail"`.
    fn name(&self) -> &'static str;

    /// Current address, if the session has one. In-memory only.
    fn address(&self) -> Option<String>;

    /// Initialize the session and return its address (`f=get_email_address`).
    /// On an existing session the provider returns the current address.
    async fn get_email_address(&self) -> Result<TempAddress, IntegrationError>;

    /// Set the address's local part (`f=set_email_user`). `local_part`
    /// charset is restricted per provider; invalid input is a `Malformed`.
    async fn set_email_user(&self, local_part: &str) -> Result<TempAddress, IntegrationError>;

    /// Poll for messages newer than the last poll (`f=check_email&seq=`).
    /// [`IntegrationError::NoSession`] when no session exists.
    async fn check_email(&self) -> Result<InboxPoll, IntegrationError>;

    /// Fetch one message (`f=fetch_email`). Provider can only fetch mail
    /// belonging to the current session.
    async fn fetch_email(&self, mail_id: &str) -> Result<TempMessage, IntegrationError>;

    /// Forget the current address (`f=forget_me`). Server keeps the session;
    /// local address state is cleared regardless of outcome.
    async fn forget_me(&self) -> Result<(), IntegrationError>;

    /// Extend address lifetime by one hour (`f=extend`, max one extension).
    async fn extend(&self) -> Result<ExtendOutcome, IntegrationError>;
}
