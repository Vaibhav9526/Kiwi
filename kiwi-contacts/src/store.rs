//! Local address book storage (SQLite, per-profile `contacts.db`).
//!
//! Schema evolution uses an explicit migrations table: [`MIGRATIONS`] is an
//! ordered, append-only list, and `schema_migrations` records what has been
//! applied. New work appends an entry — existing entries are never edited,
//! because a shipped build has already run them. (kiwi-mail's store tracks the
//! same idea with `PRAGMA user_version`; the address book carries an explicit
//! table because vCard import/merge is expected to keep reshaping the schema.)
//!
//! All SQL is parameterized. No method reads the clock: every write takes
//! `now_unix` from the caller.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params, params_from_iter};

use crate::contact::{Contact, ContactEmail, ContactPhone};
use crate::error::{ContactsError, Result};

/// Current schema version — equals `MIGRATIONS.len()`.
pub const SCHEMA_VERSION: u32 = 1;

/// Ordered, append-only. Index `i` holds the statements taking the schema from
/// version `i` to `i + 1`. Never edit an entry that has shipped.
const MIGRATIONS: &[&str] = &[
    // v1 — contacts, emails, phones, tags, and the id counter.
    r#"
CREATE TABLE contacts (
    id            TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    given_name    TEXT,
    family_name   TEXT,
    middle_name   TEXT,
    name_prefix   TEXT,
    name_suffix   TEXT,
    org           TEXT,
    title         TEXT,
    notes         TEXT,
    source_uid    TEXT,
    rev_unix      INTEGER,
    created_unix  INTEGER NOT NULL,
    updated_unix  INTEGER NOT NULL
);
CREATE INDEX idx_contacts_name ON contacts(display_name COLLATE NOCASE);
CREATE INDEX idx_contacts_source_uid ON contacts(source_uid);
CREATE TABLE contact_emails (
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    address    TEXT NOT NULL COLLATE NOCASE,
    label      TEXT,
    PRIMARY KEY (contact_id, position)
);
CREATE INDEX idx_contact_emails_address ON contact_emails(address);
CREATE TABLE contact_phones (
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    number     TEXT NOT NULL,
    label      TEXT,
    PRIMARY KEY (contact_id, position)
);
CREATE TABLE contact_tags (
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (contact_id, tag)
);
CREATE INDEX idx_contact_tags_tag ON contact_tags(tag);
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"#,
];

/// Prefix owned by the store; callers may not supply ids in this namespace.
const LOCAL_ID_PREFIX: &str = "local-";

/// Upper bound on a single `list`/`search` page. Keeps an IPC caller from
/// asking the backend to materialize an entire large address book at once.
pub const MAX_PAGE: u32 = 500;

pub struct ContactStore {
    conn: Connection,
}

impl ContactStore {
    /// Open (or create) `contacts.db` inside `root`.
    pub fn open(root: impl AsRef<Path>, now_unix: i64) -> Result<Self> {
        let root: PathBuf = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let conn = Connection::open(root.join("contacts.db"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn };
        store.migrate(now_unix)?;
        Ok(store)
    }

    /// In-memory store, for tests and ephemeral profiles.
    pub fn open_memory(now_unix: i64) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn };
        store.migrate(now_unix)?;
        Ok(store)
    }

    fn migrate(&self, now_unix: i64) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             );",
        )?;
        let applied: u32 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?;
        if applied > SCHEMA_VERSION {
            return Err(ContactsError::Invalid(format!(
                "database schema v{applied} is newer than this build (v{SCHEMA_VERSION})"
            )));
        }
        for (idx, statements) in MIGRATIONS.iter().enumerate() {
            let version = idx as u32 + 1;
            if version <= applied {
                continue;
            }
            let tx = self.conn.unchecked_transaction()?;
            tx.execute_batch(statements)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![version, now_unix],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Highest applied migration version.
    pub fn schema_version(&self) -> Result<u32> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?)
    }

    /// Number of stored contacts.
    pub fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    // -- writes -------------------------------------------------------------

    /// Insert a new contact. A caller-supplied `id` is honored (import keeps
    /// vCard-derived keys); an empty one gets a store-assigned `local-N`.
    /// Returns the stored contact with `id`/timestamps filled in.
    pub fn insert(&self, contact: &Contact, now_unix: i64) -> Result<Contact> {
        let mut c = contact.clone().prepare()?;
        if c.id.is_empty() {
            c.id = self.next_local_id()?;
        } else if c.id.starts_with(LOCAL_ID_PREFIX) {
            return Err(ContactsError::Invalid(format!(
                "id `{}` uses the reserved `{LOCAL_ID_PREFIX}` prefix",
                c.id
            )));
        }
        c.created_unix = now_unix;
        c.updated_unix = now_unix;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO contacts
               (id, display_name, given_name, family_name, middle_name, name_prefix,
                name_suffix, org, title, notes, source_uid, rev_unix,
                created_unix, updated_unix)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                c.id,
                c.display_name,
                c.given_name,
                c.family_name,
                c.middle_name,
                c.name_prefix,
                c.name_suffix,
                c.org,
                c.title,
                c.notes,
                c.source_uid,
                c.rev_unix,
                c.created_unix,
                c.updated_unix,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                ContactsError::Invalid(format!("contact id `{}` already exists", c.id))
            }
            other => ContactsError::Store(other),
        })?;
        write_children(&tx, &c)?;
        tx.commit()?;
        Ok(c)
    }

    /// Replace an existing contact in place. `created_unix` is preserved.
    pub fn update(&self, contact: &Contact, now_unix: i64) -> Result<Contact> {
        let c = contact.clone().prepare()?;
        if c.id.is_empty() {
            return Err(ContactsError::Invalid("update requires an id".into()));
        }
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE contacts SET
               display_name = ?2, given_name = ?3, family_name = ?4, middle_name = ?5,
               name_prefix = ?6, name_suffix = ?7, org = ?8, title = ?9, notes = ?10,
               source_uid = ?11, rev_unix = ?12, updated_unix = ?13
             WHERE id = ?1",
            params![
                c.id,
                c.display_name,
                c.given_name,
                c.family_name,
                c.middle_name,
                c.name_prefix,
                c.name_suffix,
                c.org,
                c.title,
                c.notes,
                c.source_uid,
                c.rev_unix,
                now_unix,
            ],
        )?;
        if n == 0 {
            return Err(ContactsError::NotFound(c.id));
        }
        for table in ["contact_emails", "contact_phones", "contact_tags"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE contact_id = ?1"),
                params![c.id],
            )?;
        }
        write_children(&tx, &c)?;
        tx.commit()?;
        let mut stored = c;
        stored.updated_unix = now_unix;
        Ok(stored)
    }

    /// Delete by id. Returns false when there was nothing to delete.
    pub fn delete(&self, id: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM contacts WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    // -- reads --------------------------------------------------------------

    pub fn get(&self, id: &str) -> Result<Option<Contact>> {
        let mut rows = self.query_contacts(
            "SELECT id, display_name, given_name, family_name, middle_name, name_prefix,
                    name_suffix, org, title, notes, source_uid, rev_unix,
                    created_unix, updated_unix
             FROM contacts WHERE id = ?1",
            params![id],
        )?;
        rows.drain(..)
            .next()
            .map(|c| self.hydrate_one(c))
            .transpose()
    }

    /// Page of contacts, ordered by display name then id (deterministic).
    pub fn list(&self, limit: u32, offset: u32) -> Result<Vec<Contact>> {
        let rows = self.query_contacts(
            "SELECT id, display_name, given_name, family_name, middle_name, name_prefix,
                    name_suffix, org, title, notes, source_uid, rev_unix,
                    created_unix, updated_unix
             FROM contacts
             ORDER BY display_name COLLATE NOCASE, id
             LIMIT ?1 OFFSET ?2",
            params![clamp_page(limit), offset as i64],
        )?;
        self.hydrate(rows)
    }

    /// Substring search over display name, org, notes, tags and email
    /// addresses. ASCII case-insensitive (SQLite `LIKE`); non-ASCII matches are
    /// case-sensitive. `%` and `_` in the query are matched literally.
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<Contact>> {
        let term = query.trim();
        if term.is_empty() {
            return self.list(limit, 0);
        }
        let pattern = format!("%{}%", escape_like(term));
        let rows = self.query_contacts(
            "SELECT c.id, c.display_name, c.given_name, c.family_name, c.middle_name,
                    c.name_prefix, c.name_suffix, c.org, c.title, c.notes, c.source_uid,
                    c.rev_unix, c.created_unix, c.updated_unix
             FROM contacts c
             WHERE c.display_name LIKE ?1 ESCAPE '\\'
                OR COALESCE(c.org, '') LIKE ?1 ESCAPE '\\'
                OR COALESCE(c.notes, '') LIKE ?1 ESCAPE '\\'
                OR EXISTS (SELECT 1 FROM contact_emails e
                            WHERE e.contact_id = c.id AND e.address LIKE ?1 ESCAPE '\\')
                OR EXISTS (SELECT 1 FROM contact_tags t
                            WHERE t.contact_id = c.id AND t.tag LIKE ?1 ESCAPE '\\')
             ORDER BY c.display_name COLLATE NOCASE, c.id
             LIMIT ?2",
            params![pattern, clamp_page(limit)],
        )?;
        self.hydrate(rows)
    }

    /// Contacts carrying `tag` (case-insensitive).
    pub fn by_tag(&self, tag: &str, limit: u32) -> Result<Vec<Contact>> {
        let rows = self.query_contacts(
            "SELECT c.id, c.display_name, c.given_name, c.family_name, c.middle_name,
                    c.name_prefix, c.name_suffix, c.org, c.title, c.notes, c.source_uid,
                    c.rev_unix, c.created_unix, c.updated_unix
             FROM contacts c
             JOIN contact_tags t ON t.contact_id = c.id
             WHERE t.tag = ?1
             ORDER BY c.display_name COLLATE NOCASE, c.id
             LIMIT ?2",
            params![tag, clamp_page(limit)],
        )?;
        self.hydrate(rows)
    }

    /// First contact holding `address` (case-insensitive), if any.
    pub fn by_email(&self, address: &str) -> Result<Option<Contact>> {
        let mut rows = self.query_contacts(
            "SELECT c.id, c.display_name, c.given_name, c.family_name, c.middle_name,
                    c.name_prefix, c.name_suffix, c.org, c.title, c.notes, c.source_uid,
                    c.rev_unix, c.created_unix, c.updated_unix
             FROM contacts c
             JOIN contact_emails e ON e.contact_id = c.id
             WHERE e.address = ?1
             ORDER BY e.position, c.id
             LIMIT 1",
            params![address],
        )?;
        rows.drain(..)
            .next()
            .map(|c| self.hydrate_one(c))
            .transpose()
    }

    /// Contact imported from this vCard `UID`, if any (re-import dedup).
    pub fn by_source_uid(&self, uid: &str) -> Result<Option<Contact>> {
        let mut rows = self.query_contacts(
            "SELECT id, display_name, given_name, family_name, middle_name, name_prefix,
                    name_suffix, org, title, notes, source_uid, rev_unix,
                    created_unix, updated_unix
             FROM contacts WHERE source_uid = ?1 ORDER BY id LIMIT 1",
            params![uid],
        )?;
        rows.drain(..)
            .next()
            .map(|c| self.hydrate_one(c))
            .transpose()
    }

    /// Distinct tags with usage counts, most-used first then alphabetical.
    pub fn tags(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tag, COUNT(*) FROM contact_tags
             GROUP BY tag ORDER BY COUNT(*) DESC, tag COLLATE NOCASE",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -- internals ----------------------------------------------------------

    fn next_local_id(&self) -> Result<String> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO counters (name, value) VALUES ('contact_id', 0)
             ON CONFLICT(name) DO NOTHING",
            [],
        )?;
        tx.execute(
            "UPDATE counters SET value = value + 1 WHERE name = 'contact_id'",
            [],
        )?;
        let n: i64 = tx.query_row(
            "SELECT value FROM counters WHERE name = 'contact_id'",
            [],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(format!("{LOCAL_ID_PREFIX}{n}"))
    }

    fn query_contacts(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, read_contact)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn hydrate_one(&self, contact: Contact) -> Result<Contact> {
        let mut many = self.hydrate(vec![contact])?;
        many.pop()
            .ok_or_else(|| ContactsError::Invalid("contact vanished during read".into()))
    }

    /// Attach emails/phones/tags to already-read rows using three batched
    /// queries rather than three per contact.
    fn hydrate(&self, mut contacts: Vec<Contact>) -> Result<Vec<Contact>> {
        if contacts.is_empty() {
            return Ok(contacts);
        }
        let ids: Vec<String> = contacts.iter().map(|c| c.id.clone()).collect();
        let holes = vec!["?"; ids.len()].join(",");

        let mut emails: HashMap<String, Vec<ContactEmail>> = HashMap::new();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT contact_id, address, label FROM contact_emails
             WHERE contact_id IN ({holes}) ORDER BY contact_id, position"
        ))?;
        let rows = stmt.query_map(params_from_iter(ids.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                ContactEmail {
                    address: r.get(1)?,
                    label: r.get(2)?,
                },
            ))
        })?;
        for r in rows {
            let (id, e) = r?;
            emails.entry(id).or_default().push(e);
        }

        let mut phones: HashMap<String, Vec<ContactPhone>> = HashMap::new();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT contact_id, number, label FROM contact_phones
             WHERE contact_id IN ({holes}) ORDER BY contact_id, position"
        ))?;
        let rows = stmt.query_map(params_from_iter(ids.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                ContactPhone {
                    number: r.get(1)?,
                    label: r.get(2)?,
                },
            ))
        })?;
        for r in rows {
            let (id, p) = r?;
            phones.entry(id).or_default().push(p);
        }

        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT contact_id, tag FROM contact_tags
             WHERE contact_id IN ({holes}) ORDER BY contact_id, tag COLLATE NOCASE"
        ))?;
        let rows = stmt.query_map(params_from_iter(ids.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for r in rows {
            let (id, t) = r?;
            tags.entry(id).or_default().push(t);
        }

        for c in &mut contacts {
            c.emails = emails.remove(&c.id).unwrap_or_default();
            c.phones = phones.remove(&c.id).unwrap_or_default();
            c.tags = tags.remove(&c.id).unwrap_or_default();
        }
        Ok(contacts)
    }
}

fn read_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Contact> {
    Ok(Contact {
        id: row.get(0)?,
        display_name: row.get(1)?,
        given_name: row.get(2)?,
        family_name: row.get(3)?,
        middle_name: row.get(4)?,
        name_prefix: row.get(5)?,
        name_suffix: row.get(6)?,
        org: row.get(7)?,
        title: row.get(8)?,
        notes: row.get(9)?,
        source_uid: row.get(10)?,
        rev_unix: row.get(11)?,
        created_unix: row.get(12)?,
        updated_unix: row.get(13)?,
        tags: Vec::new(),
        emails: Vec::new(),
        phones: Vec::new(),
    })
}

fn write_children(tx: &rusqlite::Transaction<'_>, c: &Contact) -> Result<()> {
    for (i, e) in c.emails.iter().enumerate() {
        tx.execute(
            "INSERT INTO contact_emails (contact_id, position, address, label)
             VALUES (?1, ?2, ?3, ?4)",
            params![c.id, i as i64, e.address, e.label],
        )?;
    }
    for (i, p) in c.phones.iter().enumerate() {
        tx.execute(
            "INSERT INTO contact_phones (contact_id, position, number, label)
             VALUES (?1, ?2, ?3, ?4)",
            params![c.id, i as i64, p.number, p.label],
        )?;
    }
    for tag in &c.tags {
        tx.execute(
            "INSERT OR IGNORE INTO contact_tags (contact_id, tag) VALUES (?1, ?2)",
            params![c.id, tag],
        )?;
    }
    Ok(())
}

fn clamp_page(limit: u32) -> i64 {
    limit.clamp(1, MAX_PAGE) as i64
}

/// Neutralize SQL `LIKE` wildcards so a user searching for `%` finds a literal
/// percent sign instead of matching every contact.
fn escape_like(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    for ch in term.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ContactStore {
        ContactStore::open_memory(1000).expect("open")
    }

    fn ada() -> Contact {
        let mut c = Contact::new("Ada Lovelace", 0)
            .with_email("ada@kiwi-test.invalid", Some("work"))
            .with_org("Analytical Engines")
            .with_tags(vec!["friend", "math"]);
        c.notes = Some("met at the difference engine demo".into());
        c
    }

    #[test]
    fn migration_records_version_and_is_idempotent() {
        let s = store();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            SCHEMA_VERSION as usize,
            MIGRATIONS.len(),
            "SCHEMA_VERSION must track the migration list"
        );
        // Re-running migrate on the same connection must not re-apply.
        s.migrate(2000).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        let applied_at: i64 = s
            .conn
            .query_row(
                "SELECT applied_at FROM schema_migrations WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(applied_at, 1000, "first open stamps the migration");
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        let dir = std::env::temp_dir().join(format!("kiwi-contacts-newer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = ContactStore::open(&dir, 1).unwrap();
            s.conn
                .execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (99, 1)",
                    [],
                )
                .unwrap();
        }
        let err = match ContactStore::open(&dir, 2) {
            Ok(_) => panic!("a future schema must not open"),
            Err(e) => e,
        };
        assert!(matches!(err, ContactsError::Invalid(_)), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn insert_assigns_local_id_and_full_roundtrip() {
        let s = store();
        let stored = s.insert(&ada(), 500).unwrap();
        assert_eq!(stored.id, "local-1");
        assert_eq!(stored.created_unix, 500);
        assert_eq!(stored.updated_unix, 500);

        let got = s.get("local-1").unwrap().unwrap();
        assert_eq!(got, stored, "read-back must equal the write result");

        let second = s.insert(&ada(), 501).unwrap();
        assert_eq!(
            second.id, "local-2",
            "ids are monotonic, not content-derived"
        );
        assert_eq!(s.count().unwrap(), 2);
    }

    #[test]
    fn insert_rejects_duplicate_and_reserved_ids() {
        let s = store();
        let mut c = ada();
        c.id = "imported-1".into();
        s.insert(&c, 1).unwrap();
        assert!(matches!(s.insert(&c, 1), Err(ContactsError::Invalid(_))));

        let mut reserved = ada();
        reserved.id = "local-99".into();
        assert!(matches!(
            s.insert(&reserved, 1),
            Err(ContactsError::Invalid(_))
        ));
    }

    #[test]
    fn update_replaces_children_and_preserves_created_at() {
        let s = store();
        let stored = s.insert(&ada(), 500).unwrap();
        let mut edited = stored.clone();
        edited.display_name = "Ada L.".into();
        edited.emails = vec![ContactEmail {
            address: "ada@new.invalid".into(),
            label: None,
        }];
        edited.tags = vec!["colleague".into()];
        edited.phones = vec![ContactPhone {
            number: "555-0100".into(),
            label: Some("mobile".into()),
        }];

        let after = s.update(&edited, 900).unwrap();
        assert_eq!(after.updated_unix, 900);
        let got = s.get(&stored.id).unwrap().unwrap();
        assert_eq!(got.display_name, "Ada L.");
        assert_eq!(got.created_unix, 500, "created_unix is store-owned");
        assert_eq!(got.updated_unix, 900);
        assert_eq!(got.emails.len(), 1, "old emails are replaced, not merged");
        assert_eq!(got.primary_email(), Some("ada@new.invalid"));
        assert_eq!(got.tags, vec!["colleague"]);
        assert_eq!(got.phones.len(), 1);

        assert!(matches!(
            s.update(&Contact::new("nobody", 0), 901),
            Err(ContactsError::Invalid(_))
        ));
        let mut ghost = Contact::new("ghost", 0);
        ghost.id = "nope".into();
        assert!(matches!(
            s.update(&ghost, 901),
            Err(ContactsError::NotFound(_))
        ));
    }

    #[test]
    fn delete_cascades_to_children() {
        let s = store();
        let stored = s.insert(&ada(), 1).unwrap();
        s.insert(
            &Contact::new("Grace Hopper", 0).with_email("grace@kiwi-test.invalid", None),
            2,
        )
        .unwrap();
        assert!(s.delete(&stored.id).unwrap());
        assert!(!s.delete(&stored.id).unwrap(), "second delete is a no-op");
        assert_eq!(s.count().unwrap(), 1);

        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM contact_emails)
                      + (SELECT COUNT(*) FROM contact_tags)
                      + (SELECT COUNT(*) FROM contact_phones)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 1, "only the surviving contact's email remains");
    }

    #[test]
    fn search_covers_name_org_notes_tag_and_email() {
        let s = store();
        s.insert(&ada(), 1).unwrap();
        s.insert(
            &Contact::new("Grace Hopper", 0)
                .with_email("grace@kiwi-test.invalid", None)
                .with_org("US Navy")
                .with_tags(vec!["compiler"]),
            2,
        )
        .unwrap();

        let by_name = s.search("ada", 10).unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].display_name, "Ada Lovelace");

        assert_eq!(
            s.search("navy", 10).unwrap()[0].display_name,
            "Grace Hopper"
        );
        assert_eq!(s.search("compiler", 10).unwrap().len(), 1);
        assert_eq!(s.search("difference engine", 10).unwrap().len(), 1);
        assert_eq!(s.search("grace@kiwi-test", 10).unwrap().len(), 1);
        assert!(s.search("nobody", 10).unwrap().is_empty());

        // Deterministic ordering: name then id.
        assert_eq!(s.search("", 10).unwrap()[0].display_name, "Ada Lovelace");
        // Non-ASCII case folding is a documented limitation, not a crash.
        assert!(s.search("ADA LOVELACE", 10).unwrap().len() == 1);
    }

    #[test]
    fn search_wildcards_are_literal() {
        let s = store();
        s.insert(&Contact::new("Ada Lovelace", 0), 1).unwrap();
        assert!(
            s.search("%", 10).unwrap().is_empty(),
            "`%` must not match everything"
        );
        assert!(s.search("_", 10).unwrap().is_empty());
        assert!(s.search("\\", 10).unwrap().is_empty());
        assert_eq!(s.search("ada", 10).unwrap().len(), 1);
    }

    #[test]
    fn by_email_tag_and_source_uid_lookups() {
        let s = store();
        let mut c = ada();
        c.source_uid = Some("vcard-uid-1".into());
        s.insert(&c, 1).unwrap();

        assert_eq!(
            s.by_email("ADA@KIWI-TEST.INVALID")
                .unwrap()
                .unwrap()
                .display_name,
            "Ada Lovelace",
            "email lookup is case-insensitive"
        );
        assert!(s.by_email("nobody@x.invalid").unwrap().is_none());

        assert_eq!(s.by_tag("MATH", 10).unwrap().len(), 1);
        assert!(s.by_tag("nope", 10).unwrap().is_empty());

        assert_eq!(
            s.by_source_uid("vcard-uid-1").unwrap().unwrap().id,
            "local-1"
        );
        assert!(s.by_source_uid("other").unwrap().is_none());

        let tags = s.tags().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].1, 1, "each tag used once");
    }

    #[test]
    fn list_pages_and_clamps() {
        let s = store();
        for i in 0..5 {
            s.insert(&Contact::new(format!("Person {i}"), 0), i as i64)
                .unwrap();
        }
        let page = s.list(2, 0).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].display_name, "Person 0");
        let page2 = s.list(2, 2).unwrap();
        assert_eq!(page2[0].display_name, "Person 2");
        assert_eq!(s.list(0, 0).unwrap().len(), 1, "limit 0 clamps to 1");
        assert!(s.list(MAX_PAGE + 1000, 0).unwrap().len() == 5);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("kiwi-contacts-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = ContactStore::open(&dir, 10).unwrap();
            s.insert(&ada(), 10).unwrap();
        }
        {
            let s = ContactStore::open(&dir, 20).unwrap();
            assert_eq!(s.count().unwrap(), 1);
            assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
            let got = s.get("local-1").unwrap().unwrap();
            assert_eq!(got.tags, vec!["friend", "math"]);
            // The counter survives reopen, so ids stay unique.
            assert_eq!(s.insert(&ada(), 21).unwrap().id, "local-2");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
