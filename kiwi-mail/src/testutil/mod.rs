//! Transcript-replay test harness for Agent 6's T-114 fixtures
//! (`tests/fixtures/transcripts/*.txt`).
//!
//! Format: `S: <line>` = server writes the line (CRLF appended);
//! `C: <line>` = the client must emit this line; `#` = comment;
//! a comment containing "TLS handshake" marks the upgrade boundary
//! (pop3_stls.txt). Client-side probes the transcript doesn't script
//! (CAPA / CAPABILITY) are answered generically so replays stay faithful.

mod script;
mod server;

pub use script::{Proto, Step, load, parse};
pub use server::{serve, spawn_script, tls_acceptor};

#[cfg(test)]
mod tests;
