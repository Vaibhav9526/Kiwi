//! Shared error type for the address book.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContactsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("invalid contact: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("vcard error: {0}")]
    VCard(#[from] crate::vcard::VCardError),
}

pub type Result<T> = std::result::Result<T, ContactsError>;
