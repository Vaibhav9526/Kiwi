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
//! | [`http`] | Async `HttpClient` seam + `ReqwestClient` (HTTPS-only, no redirects, bounded) + the live-path opt-in gate + `ScriptedHttp` test transport |
//! | [`tempmail`] | `TempMailProvider` trait + disposable-inbox types + [`tempmail::GuerrillaMail`] |
//! | [`deliverability`] | `DeliverabilityTester` trait + report model + fail-closed auth gate + [`deliverability::EmailSpamTester`] |
//!
//! # Standing rules (docs/contracts/integrations.md is authoritative)
//!
//! - **HTTPS only.** `http://` requests are refused before any socket opens.
//! - **No credential persistence.** Session state (PHPSESSID, slugs) lives in
//!   memory only; nothing here writes to disk, OS keystore, or the mail store.
//! - **Secrets never logged.** Capability secrets (test slugs, session ids)
//!   are wrapped in redacting newtypes, are not serializable, are zeroized on
//!   drop, and are excluded from error strings and `Debug` output.
//! - **No live calls by accident.** The convenience `live()` constructors
//!   refuse unless [`http::LIVE_ENV`] is `1`, and refuse unconditionally when a
//!   CI marker is present. [`http::ReqwestClient`] and provider `new()` stay
//!   available for trusted production wiring and offline `ScriptedHttp` tests.
//! - **No bearer capability in a URL we hand out.** Provider report and
//!   citation URLs are validated (HTTPS, no userinfo, no fragment, bounded)
//!   and dropped when they carry the reservation slug.
//! - **In-band provider errors are never success.** Every success parse runs
//!   the provider error-envelope rejection first, and the authentication gate
//!   is fail-closed: unknown statuses, unknown categories, absent auth
//!   evidence, and client-side truncation all block.
//! - **Disposable inboxes are PUBLIC.** Any mail sent to a temp address is
//!   readable by anyone who knows the address and passes through a third-party
//!   server. Never receive real/personal/confidential mail on them.
//! - **Untrusted input everywhere.** Provider JSON is length-capped before
//!   parse, strictly typed where possible, unknown fields ignored.
//! - **No clock, no sleep, no retry.** Timing and retry policy belong to the
//!   caller so the crate stays deterministic.

#![forbid(unsafe_code)]

pub mod deliverability;
mod error;
pub mod http;
mod secret;
pub mod tempmail;

pub use error::{IntegrationError, TransportKind};
