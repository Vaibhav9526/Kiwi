//! kiwi-mail — KIWI's native mail engine.
//!
//! Owns the SMTP/IMAP/POP3 client implementations and, critically, the
//! transport layer where every security observation originates
//! (`transport::TlsObservation` → `kiwi_core::SecuritySession`).
//!
//! Module map (see docs/ARCHITECTURE.md §3):
//! - [`transport`] — TCP + rustls; captures negotiated TLS params/cert chain
//! - [`authstamp`] — SPF/DKIM/DMARC verdicts + RFC 8601 stamping (T-232)
//! - [`smtp`] — send client (`smtp/`: client.rs flow, commands.rs helpers+queue)
//! - [`imap`] — receive client (`imap/`: parser.rs S-expr+reply types,
//!   commands.rs command set)
//! - [`pop3`] — receive client (USER/PASS/APOP, LIST/UIDL/RETR/DELE, STLS)
//! - [`account`] — account/server/credential model
//! - [`category`] — deterministic inbox-tab classifier (headers-only)
//! - [`rules`] — deterministic inbox rules engine (F1/T-228; `rules/`:
//!   model.rs types+bounds, eval.rs pure evaluator)
//! - [`store`] — local mail storage (`store/`: schema.rs DDL, queries.rs
//!   CRUD, outbox.rs send queue)
//! - [`sync`] — folder sync engine
//! - [`mime`] — MIME parse/build boundary
//! - [`unsub`] — RFC 2369/8058 unsubscribe parsing (no fetching/sending)
//! - `testutil` — transcript-replay harness (`testutil/`: script.rs,
//!   server.rs, tests.rs)

pub mod account;
pub mod attachrisk;
pub mod authrisk;
pub mod authstamp;
pub mod category;
pub mod error;
pub mod imap;
pub mod lines;
pub mod mime;
pub mod pop3;
pub mod rules;
pub mod search;
pub mod smtp;
pub mod store;
pub mod sync;
#[cfg(test)]
pub mod testutil;
pub mod transport;
pub mod unsub;
