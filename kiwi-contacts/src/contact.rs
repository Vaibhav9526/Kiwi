//! Contact model and the bounds every externally-supplied field is held to.
//!
//! Contacts arrive from three untrusted-ish directions: user typing, vCard
//! import, and IPC (webview). All three funnel through [`Contact::normalize`]
//! and [`Contact::validate`], so the caps below are the single place a limit is
//! defined. Over-limit input is rejected, never silently truncated — a dropped
//! contact is recoverable, a silently mangled one is not.

use serde::{Deserialize, Serialize};

use crate::error::{ContactsError, Result};

/// Max length of any human-name field (display/given/family/…), in bytes.
pub const MAX_NAME_LEN: usize = 256;
/// Max length of an email address; RFC 5321 forward-path ceiling.
pub const MAX_EMAIL_LEN: usize = 320;
pub const MAX_ORG_LEN: usize = 256;
pub const MAX_TITLE_LEN: usize = 256;
pub const MAX_NOTE_LEN: usize = 4096;
pub const MAX_TAG_LEN: usize = 64;
pub const MAX_LABEL_LEN: usize = 64;
/// Max length of a phone number as typed (formatting + extension included).
pub const MAX_PHONE_LEN: usize = 64;

pub const MAX_EMAILS: usize = 16;
pub const MAX_PHONES: usize = 16;
pub const MAX_TAGS: usize = 32;

/// A contact as stored and as exchanged over IPC.
///
/// `id`, `created_unix` and `updated_unix` are store-owned: callers pass an
/// empty `id` to have one assigned, and always pass time in explicitly — the
/// crate never reads the system clock (determinism rule, docs/TESTING.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Stable identifier. Empty on input means "assign one".
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
    pub emails: Vec<ContactEmail>,
    pub phones: Vec<ContactPhone>,
    /// Original `UID` of the vCard this contact came from, if any (provenance
    /// for re-import; never used as the store key).
    pub source_uid: Option<String>,
    /// vCard `REV` as unix seconds, if the source supplied one.
    pub rev_unix: Option<i64>,
    pub created_unix: i64,
    pub updated_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactEmail {
    pub address: String,
    /// vCard `TYPE` token, lowercased (`work`, `home`, `other`, …).
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactPhone {
    pub number: String,
    pub label: Option<String>,
}

impl Contact {
    /// A minimal contact with no id assigned yet.
    pub fn new(display_name: impl Into<String>, now_unix: i64) -> Self {
        Self {
            id: String::new(),
            display_name: display_name.into(),
            given_name: None,
            family_name: None,
            middle_name: None,
            name_prefix: None,
            name_suffix: None,
            org: None,
            title: None,
            notes: None,
            tags: Vec::new(),
            emails: Vec::new(),
            phones: Vec::new(),
            source_uid: None,
            rev_unix: None,
            created_unix: now_unix,
            updated_unix: now_unix,
        }
    }

    pub fn with_email(mut self, address: impl Into<String>, label: Option<&str>) -> Self {
        self.emails.push(ContactEmail {
            address: address.into(),
            label: label.map(str::to_string),
        });
        self
    }

    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.org = Some(org.into());
        self
    }

    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// First email address, if any — the value the composer prefills from.
    pub fn primary_email(&self) -> Option<&str> {
        self.emails.first().map(|e| e.address.as_str())
    }

    /// Display name, falling back to the first email, then to an empty string.
    /// Used where a row must render something.
    pub fn label(&self) -> &str {
        if !self.display_name.is_empty() {
            &self.display_name
        } else {
            self.primary_email().unwrap_or("")
        }
    }

    /// Trim, drop blanks, and de-duplicate. Order-preserving and idempotent:
    /// running it twice yields the same contact.
    pub fn normalize(&mut self) {
        fn clean(v: &mut Option<String>) {
            if let Some(s) = v.take() {
                let t = s.trim();
                if !t.is_empty() {
                    *v = Some(t.to_string());
                }
            }
        }
        self.id = self.id.trim().to_string();
        self.display_name = self.display_name.trim().to_string();
        clean(&mut self.given_name);
        clean(&mut self.family_name);
        clean(&mut self.middle_name);
        clean(&mut self.name_prefix);
        clean(&mut self.name_suffix);
        clean(&mut self.org);
        clean(&mut self.title);
        clean(&mut self.source_uid);
        if let Some(n) = self.notes.take() {
            let t = n.trim_end();
            if !t.is_empty() {
                self.notes = Some(t.to_string());
            }
        }

        let mut seen_tags: Vec<String> = Vec::with_capacity(self.tags.len());
        for tag in self.tags.drain(..) {
            let t = tag.trim();
            if t.is_empty() || seen_tags.iter().any(|s| s.eq_ignore_ascii_case(t)) {
                continue;
            }
            seen_tags.push(t.to_string());
        }
        // Tags are a set, so they get a canonical order: it makes the stored
        // rows, the exported CATEGORIES list and the JSON all stable.
        seen_tags.sort_by_key(|t| t.to_ascii_lowercase());
        self.tags = seen_tags;

        let mut seen_mail: Vec<String> = Vec::with_capacity(self.emails.len());
        let mut emails = Vec::with_capacity(self.emails.len());
        for mut e in self.emails.drain(..) {
            e.address = e.address.trim().to_string();
            e.label = e
                .label
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty());
            if e.address.is_empty() || seen_mail.iter().any(|s| s.eq_ignore_ascii_case(&e.address))
            {
                continue;
            }
            seen_mail.push(e.address.clone());
            emails.push(e);
        }
        self.emails = emails;

        let mut seen_phones: Vec<String> = Vec::with_capacity(self.phones.len());
        let mut phones = Vec::with_capacity(self.phones.len());
        for mut p in self.phones.drain(..) {
            p.number = p.number.trim().to_string();
            p.label = p
                .label
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty());
            if p.number.is_empty() || seen_phones.contains(&p.number) {
                continue;
            }
            seen_phones.push(p.number.clone());
            phones.push(p);
        }
        self.phones = phones;
    }

    /// Bounds check. Every rejection names the offending field so callers can
    /// report which card/record was refused and why.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(ContactsError::Invalid(m));

        if self.display_name.is_empty() && self.primary_email().is_none() {
            return bad("contact has neither a display name nor an email address".into());
        }
        for (field, value) in [
            ("display_name", Some(self.display_name.as_str())),
            ("given_name", self.given_name.as_deref()),
            ("family_name", self.family_name.as_deref()),
            ("middle_name", self.middle_name.as_deref()),
            ("name_prefix", self.name_prefix.as_deref()),
            ("name_suffix", self.name_suffix.as_deref()),
        ] {
            if let Some(v) = value
                && v.len() > MAX_NAME_LEN
            {
                return bad(format!("{field} exceeds {MAX_NAME_LEN} bytes"));
            }
        }
        if let Some(o) = &self.org
            && o.len() > MAX_ORG_LEN
        {
            return bad(format!("org exceeds {MAX_ORG_LEN} bytes"));
        }
        if let Some(t) = &self.title
            && t.len() > MAX_TITLE_LEN
        {
            return bad(format!("title exceeds {MAX_TITLE_LEN} bytes"));
        }
        if let Some(n) = &self.notes
            && n.len() > MAX_NOTE_LEN
        {
            return bad(format!("notes exceeds {MAX_NOTE_LEN} bytes"));
        }
        if let Some(u) = &self.source_uid
            && u.len() > MAX_NAME_LEN
        {
            return bad(format!("source_uid exceeds {MAX_NAME_LEN} bytes"));
        }
        if self.tags.len() > MAX_TAGS {
            return bad(format!("more than {MAX_TAGS} tags"));
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LEN {
                return bad(format!("tag exceeds {MAX_TAG_LEN} bytes"));
            }
        }
        if self.emails.len() > MAX_EMAILS {
            return bad(format!("more than {MAX_EMAILS} email addresses"));
        }
        for e in &self.emails {
            if e.address.len() > MAX_EMAIL_LEN {
                return bad(format!("email exceeds {MAX_EMAIL_LEN} bytes"));
            }
            if !is_plausible_email(&e.address) {
                return bad(format!("not a usable email address: {}", e.address));
            }
            if let Some(l) = &e.label {
                if l.len() > MAX_LABEL_LEN {
                    return bad(format!("email label exceeds {MAX_LABEL_LEN} bytes"));
                }
                if l.chars().any(char::is_control) {
                    return bad("email label contains control characters".into());
                }
            }
        }
        if self.phones.len() > MAX_PHONES {
            return bad(format!("more than {MAX_PHONES} phone numbers"));
        }
        for p in &self.phones {
            if p.number.len() > MAX_PHONE_LEN {
                return bad(format!("phone exceeds {MAX_PHONE_LEN} bytes"));
            }
            // Control characters would let a crafted vCard inject structure on
            // export; the value must stay single-line printable text.
            if p.number.chars().any(char::is_control) {
                return bad("phone contains control characters".into());
            }
            if let Some(l) = &p.label {
                if l.len() > MAX_LABEL_LEN {
                    return bad(format!("phone label exceeds {MAX_LABEL_LEN} bytes"));
                }
                if l.chars().any(char::is_control) {
                    return bad("phone label contains control characters".into());
                }
            }
        }
        // Every text field except `notes` is single-line: a control character
        // in a name, org or title would render as structure in a list row, a
        // header or a composer chip, and no legitimate source produces one.
        for (field, value) in [
            ("display_name", Some(self.display_name.as_str())),
            ("given_name", self.given_name.as_deref()),
            ("family_name", self.family_name.as_deref()),
            ("middle_name", self.middle_name.as_deref()),
            ("name_prefix", self.name_prefix.as_deref()),
            ("name_suffix", self.name_suffix.as_deref()),
            ("org", self.org.as_deref()),
            ("title", self.title.as_deref()),
            ("source_uid", self.source_uid.as_deref()),
        ] {
            if let Some(v) = value
                && v.chars().any(char::is_control)
            {
                return bad(format!("{field} contains control characters"));
            }
        }
        // `notes` is the one multi-line field; other control characters are
        // still refused.
        if let Some(n) = &self.notes
            && n.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return bad("notes contains control characters".into());
        }
        Ok(())
    }

    /// Normalize then validate — the boundary every write path uses.
    pub fn prepare(mut self) -> Result<Self> {
        self.normalize();
        self.validate()?;
        Ok(self)
    }
}

/// Structural check only: exactly one `@`, non-empty local part, and a domain
/// with a dot-free-only-if-single-label rule kept loose on purpose. This crate
/// must not pretend to do deliverability validation.
fn is_plausible_email(addr: &str) -> bool {
    if addr.chars().any(char::is_whitespace) || addr.chars().any(char::is_control) {
        return false;
    }
    let mut parts = addr.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_dedups_and_is_idempotent() {
        let mut c = Contact::new("  Ada Lovelace  ", 100);
        c.org = Some("  ".into());
        c.tags = vec![" Friend ".into(), "friend".into(), "".into(), "Work".into()];
        c.emails = vec![
            ContactEmail {
                address: " ada@x.test ".into(),
                label: Some(" WORK ".into()),
            },
            ContactEmail {
                address: "ADA@X.TEST".into(),
                label: Some("home".into()),
            },
            ContactEmail {
                address: "  ".into(),
                label: None,
            },
        ];
        c.phones = vec![
            ContactPhone {
                number: " 555 ".into(),
                label: None,
            },
            ContactPhone {
                number: "555".into(),
                label: None,
            },
        ];
        c.normalize();
        let once = c.clone();
        c.normalize();
        assert_eq!(once, c, "normalize must be idempotent");

        assert_eq!(c.display_name, "Ada Lovelace");
        assert_eq!(c.org, None);
        assert_eq!(c.tags, vec!["Friend", "Work"]);
        assert_eq!(c.emails.len(), 1);
        assert_eq!(c.emails[0].address, "ada@x.test");
        assert_eq!(c.emails[0].label.as_deref(), Some("work"));
        assert_eq!(c.phones.len(), 1);
        assert_eq!(c.primary_email(), Some("ada@x.test"));
    }

    #[test]
    fn validate_rejects_bad_emails_and_oversized_fields() {
        let mut c = Contact::new("A", 0);
        c.emails = vec![ContactEmail {
            address: "no-at-sign".into(),
            label: None,
        }];
        assert!(matches!(c.validate(), Err(ContactsError::Invalid(_))));

        c.emails = vec![ContactEmail {
            address: "a@b@c".into(),
            label: None,
        }];
        assert!(c.validate().is_err());

        c.emails = vec![ContactEmail {
            address: "a@b".into(),
            label: None,
        }];
        assert!(
            c.validate().is_ok(),
            "single-label domain is still accepted"
        );

        let mut c = Contact::new("A", 0);
        c.notes = Some("x".repeat(MAX_NOTE_LEN + 1));
        assert!(c.validate().is_err());

        let mut c = Contact::new("A", 0);
        c.tags = (0..=MAX_TAGS).map(|i| format!("t{i}")).collect();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_control_characters() {
        let mut c = Contact::new("A", 0);
        c.display_name = "A\r\nB".into();
        assert!(
            c.validate().is_err(),
            "CR/LF in a name must never reach export"
        );

        let mut c = Contact::new("A", 0);
        c.notes = Some("line one\nline two".into());
        assert!(
            c.validate().is_ok(),
            "newlines in notes are legitimate text"
        );

        let mut c = Contact::new("A", 0);
        c.phones = vec![ContactPhone {
            number: "1\r\n2".into(),
            label: None,
        }];
        assert!(c.validate().is_err());
    }

    #[test]
    fn contact_without_name_or_email_is_rejected() {
        let c = Contact::new("   ", 0);
        assert!(c.prepare().is_err());
        let c = Contact::new("", 0).with_email("a@b.test", None);
        assert!(c.prepare().is_ok());
    }

    #[test]
    fn label_falls_back_to_email() {
        let c = Contact::new("", 0).with_email("a@b.test", None);
        assert_eq!(c.label(), "a@b.test");
        let c = Contact::new("Ada", 0);
        assert_eq!(c.label(), "Ada");
    }
}
