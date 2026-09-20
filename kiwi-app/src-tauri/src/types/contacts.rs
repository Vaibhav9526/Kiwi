//! Contacts wire views (T-175) — camelCase projections of the
//! `kiwi-contacts` model (kiwi.contacts/1 §2; the mapping is mechanical
//! and one-to-one).

use serde::{Deserialize, Serialize};

/// `Contact` on the wire — camelCase per kiwi.contacts/1 §2; the mapping
/// is mechanical and one-to-one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    pub id: String,
    pub display_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub name_prefix: Option<String>,
    pub name_suffix: Option<String>,
    pub org: Option<String>,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    /// `{address, label?}` — the crate's snake_case is already
    /// camelCase-compatible for these single-word fields.
    pub emails: Vec<kiwi_contacts::ContactEmail>,
    pub phones: Vec<kiwi_contacts::ContactPhone>,
    pub source_uid: Option<String>,
    pub rev_unix: Option<i64>,
    pub created_unix: i64,
    pub updated_unix: i64,
}

/// `ContactInput` — `Contact` minus the store-owned fields (`id`,
/// `createdUnix`, `updatedUnix`; kiwi.contacts/1 §3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInput {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub name_prefix: Option<String>,
    #[serde(default)]
    pub name_suffix: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub emails: Vec<kiwi_contacts::ContactEmail>,
    #[serde(default)]
    pub phones: Vec<kiwi_contacts::ContactPhone>,
    #[serde(default)]
    pub source_uid: Option<String>,
    #[serde(default)]
    pub rev_unix: Option<i64>,
}

impl ContactInput {
    /// Crate `Contact` — store-owned fields get placeholder values;
    /// `insert`/`update` overwrite `created`/`updated`, and `id` comes
    /// from the caller's `contactId` (or is store-assigned when empty).
    pub fn into_contact(self, id: String) -> kiwi_contacts::Contact {
        kiwi_contacts::Contact {
            id,
            display_name: self.display_name,
            given_name: self.given_name,
            family_name: self.family_name,
            middle_name: self.middle_name,
            name_prefix: self.name_prefix,
            name_suffix: self.name_suffix,
            org: self.org,
            title: self.title,
            notes: self.notes,
            tags: self.tags,
            emails: self.emails,
            phones: self.phones,
            source_uid: self.source_uid,
            rev_unix: self.rev_unix,
            created_unix: 0,
            updated_unix: 0,
        }
    }
}

impl From<kiwi_contacts::Contact> for ContactView {
    fn from(c: kiwi_contacts::Contact) -> Self {
        ContactView {
            id: c.id,
            display_name: c.display_name,
            given_name: c.given_name,
            family_name: c.family_name,
            middle_name: c.middle_name,
            name_prefix: c.name_prefix,
            name_suffix: c.name_suffix,
            org: c.org,
            title: c.title,
            notes: c.notes,
            tags: c.tags,
            emails: c.emails,
            phones: c.phones,
            source_uid: c.source_uid,
            rev_unix: c.rev_unix,
            created_unix: c.created_unix,
            updated_unix: c.updated_unix,
        }
    }
}

/// `kiwi_import_vcards` result (contacts.md §5.2): the contacts that
/// imported, plus one issue row per card that did not.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VCardImportView {
    pub contacts: Vec<ContactView>,
    pub issues: Vec<ImportIssueView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportIssueView {
    pub card_index: usize,
    pub detail: String,
}

/// `kiwi_contact_tags` row — `{tag, count}`, most-used first.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagCountView {
    pub tag: String,
    pub count: u64,
}
