//! Shared error type for the mail engine.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("protocol error in {protocol}: {detail}")]
    Protocol { protocol: &'static str, detail: String },
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("server rejected command {command}: {reply}")]
    ServerReject { command: String, reply: String },
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("policy rejected: {0}")]
    PolicyRejected(String),
    #[error("endpoint locked: unlock required before {0}")]
    Locked(String),
}

pub type Result<T> = std::result::Result<T, MailError>;
