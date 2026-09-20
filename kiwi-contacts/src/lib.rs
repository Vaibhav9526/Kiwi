//! kiwi-contacts — KIWI's local address book.
//!
//! Owns the contact model, its SQLite store, and vCard (RFC 6350) interchange.
//! It is deliberately narrow: no network, no AI, no clock reads. Times arrive
//! as parameters so that every operation is reproducible from its inputs
//! (docs/TESTING.md determinism rule).
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`contact`] | [`contact::Contact`] model, field bounds, normalization |
//! | [`store`] | SQLite persistence, migrations, search, tag queries |
//! | [`vcard`] | Bounded vCard 4.0 import/export |
//! | [`error`] | Shared error type |
//!
//! # Boundaries
//!
//! Everything in this crate treats its input as untrusted, because all three
//! entry points are: user typing, vCard files off disk or the network, and IPC
//! from the webview. Field caps live in [`contact`], stream caps in
//! [`vcard::VCardLimits`], and every SQL statement is parameterized
//! (docs/SECURITY.md). Nothing here reads a secret; a contact is never a
//! credential, and no credential belongs in a contact.
//!
//! ```
//! use kiwi_contacts::{Contact, ContactStore, vcard};
//!
//! let store = ContactStore::open_memory(0)?;
//! let stored = store.insert(&Contact::new("Ada Lovelace", 0).with_email("ada@x.test", Some("work")), 0)?;
//! assert_eq!(store.search("ada", 10)?.len(), 1);
//!
//! let text = vcard::export_vcard(&stored)?;
//! let back = vcard::import_vcards(&text, &vcard::VCardLimits::default(), 0)?;
//! assert_eq!(back.contacts[0].display_name, "Ada Lovelace");
//! # Ok::<(), kiwi_contacts::ContactsError>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod contact;
pub mod error;
pub mod store;
pub mod vcard;

pub use contact::{Contact, ContactEmail, ContactPhone};
pub use error::{ContactsError, Result};
pub use store::{ContactStore, SCHEMA_VERSION};
pub use vcard::{ImportIssue, VCardImport, VCardLimits};
