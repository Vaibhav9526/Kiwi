//! kiwi-mail — KIWI's native mail engine.
//!
//! Owns the SMTP/IMAP/POP3 client implementations and, critically, the
//! transport layer where every security observation originates
//! (`transport::TlsObservation` → `kiwi_core::SecuritySession`).
//!
//! Module map (see docs/ARCHITECTURE.md §3):
//! - [`transport`] — TCP + rustls; captures negotiated TLS params/cert chain
//! - [`smtp`] — send client (EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA)
//! - [`imap`] — receive client (capabilities, SELECT/FETCH/IDLE, folder ops)
//! - [`pop3`] — receive client (USER/PASS/APOP, LIST/UIDL/RETR/DELE, STLS)
//! - [`account`] — account/server/credential model
//! - [`store`] — local mail storage (SQLite metadata + on-disk bodies)
//! - [`sync`] — folder sync engine
//! - [`mime`] — MIME parse/build boundary

pub mod account;
pub mod error;
pub mod imap;
pub mod lines;
pub mod mime;
pub mod pop3;
pub mod search;
pub mod smtp;
pub mod store;
pub mod sync;
#[cfg(test)]
pub mod testutil;
pub mod transport;
