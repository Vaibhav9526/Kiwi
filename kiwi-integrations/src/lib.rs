//! kiwi-integrations — KIWI's external-service integration boundary.
//!
//! Two provider traits, both deliberately narrow and both gated behind the
//! network seam in [`http`]. Nothing in this crate touches the network unless
//! a caller constructs [`http::ReqwestClient`] and hands it to a provider;
//! tests inject [`http::ScriptedHttp`] and replay recorded fixtures.
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`http`] | Async `HttpClient` seam + `ReqwestClient` (HTTPS-only, no redirects, bounded) + `ScriptedHttp` test transport |
//! | [`tempmail`] | `TempMailProvider` trait + disposable-inbox types + [`tempmail::GuerrillaMail`] |
//! | [`deliverability`] | `DeliverabilityTester` trait + report model + [`deliverability::EmailSpamTester`] |
//!
//! # Standing rules (docs/contracts/integrations.md is authoritative)
//!
//! - **HTTPS only.** `http://` requests are refused before any socket opens.
//! - **No credential persistence.** Session state (PHPSESSID, slugs) lives in
//!   memory only; nothing here writes to disk, OS keystore, or the mail store.
//! - **Secrets never logged.** Capability secrets (test slugs, session ids)
//!   are wrapped in redacting newtypes and excluded from error strings.
//! - **Disposable inboxes are PUBLIC.** Any mail sent to a temp address is
//!   readable by anyone who knows the address and passes through a third-party
//!   server. Never receive real/personal/confidential mail on them.
//! - **Untrusted input everywhere.** Provider JSON is length-capped before
//!   parse, strictly typed where possible, unknown fields ignored.

#![forbid(unsafe_code)]

pub mod deliverability;
mod error;
pub mod http;
pub mod tempmail;

pub use error::IntegrationError;
