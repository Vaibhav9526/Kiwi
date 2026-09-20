//! End-to-end address book behaviour: the store and the vCard codec exercised
//! together the way a caller (IPC layer, import wizard) actually drives them.

use kiwi_contacts::contact::{Contact, ContactPhone};
use kiwi_contacts::vcard::{self, VCardLimits};
use kiwi_contacts::{ContactsError, ContactStore};

const BOOK: &str = "BEGIN:VCARD\r\n\
VERSION:4.0\r\n\
UID:urn:uuid:ada\r\n\
FN:Ada Lovelace\r\n\
N:Lovelace;Ada;;;\r\n\
ORG:Analytical Engines\r\n\
EMAIL;TYPE=work;PREF=1:ada@work.invalid\r\n\
TEL;TYPE=mobile:555-0100\r\n\
CATEGORIES:friend\r\n\
NOTE:first programmer\r\n\
END:VCARD\r\n\
BEGIN:VCARD\r\n\
VERSION:4.0\r\n\
UID:urn:uuid:grace\r\n\
FN:Grace Hopper\r\n\
N:Hopper;Grace;;;\r\n\
ORG:US Navy\r\n\
EMAIL;TYPE=work:grace@navy.invalid\r\n\
CATEGORIES:friend,compiler\r\n\
END:VCARD\r\n\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
UID:urn:uuid:alan\r\n\
FN:Alan Turing\r\n\
EMAIL;TYPE=INTERNET;PREF:alan@bletchley.invalid\r\n\
END:VCARD\r\n";

fn temp_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("kiwi-contacts-it-{}-{tag}", std::process::id()))
}

#[test]
fn imports_a_book_exports_it_and_reimports_identically() {
    let import = vcard::import_vcards(BOOK, &VCardLimits::default(), 1_700_000_000).unwrap();
    assert!(import.is_complete(), "issues: {:?}", import.issues);
    assert_eq!(import.contacts.len(), 3);

    let root = temp_root("roundtrip");
    let _ = std::fs::remove_dir_all(&root);
    let store = ContactStore::open(&root, 1_700_000_000).unwrap();
    for c in &import.contacts {
        store.insert(c, 1_700_000_000).unwrap();
    }
    assert_eq!(store.count().unwrap(), 3);

    let stored = store.list(100, 0).unwrap();
    assert_eq!(stored[0].display_name, "Ada Lovelace", "ordered by display name");
    assert_eq!(stored[2].display_name, "Grace Hopper");
    // The v3 card's bare PREF still promotes its only address.
    let alan = store.by_email("alan@bletchley.invalid").unwrap().unwrap();
    assert_eq!(alan.primary_email(), Some("alan@bletchley.invalid"));

    // Export the whole book, import into a fresh store, compare field for field.
    let text = vcard::export_vcards(&stored).unwrap();
    assert_eq!(text.matches("BEGIN:VCARD").count(), 3);
    let reimported = vcard::import_vcards(&text, &VCardLimits::default(), 1_700_000_000)
        .unwrap()
        .contacts;
    assert_eq!(reimported.len(), 3);
    for (before, after) in stored.iter().zip(reimported.iter()) {
        assert_eq!(before.display_name, after.display_name);
        assert_eq!(before.emails, after.emails);
        assert_eq!(before.phones, after.phones);
        assert_eq!(before.tags, after.tags);
        assert_eq!(before.org, after.org);
        assert_eq!(before.notes, after.notes);
        assert_eq!(before.source_uid, after.source_uid);
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reimporting_the_same_book_updates_rather_than_duplicates() {
    let root = temp_root("dedupe");
    let _ = std::fs::remove_dir_all(&root);
    let store = ContactStore::open(&root, 0).unwrap();

    let first = vcard::import_vcards(BOOK, &VCardLimits::default(), 1_700_000_000)
        .unwrap()
        .contacts;
    for c in &first {
        store.insert(c, 1_700_000_000).unwrap();
    }
    assert_eq!(store.count().unwrap(), 3);

    // Re-import a book where one card changed, matching on the vCard UID the
    // way an address-book sync would.
    let updated = BOOK.replace("ORG:Analytical Engines", "ORG:Analytical Engines Ltd");
    let incoming = vcard::import_vcards(&updated, &VCardLimits::default(), 1_700_100_000)
        .unwrap()
        .contacts;
    for c in &incoming {
        let uid = c.source_uid.as_deref().expect("every card carries a UID");
        match store.by_source_uid(uid).unwrap() {
            Some(existing) => {
                let mut merged = c.clone();
                merged.id = existing.id;
                store.update(&merged, 1_700_100_000).unwrap();
            }
            None => {
                store.insert(c, 1_700_100_000).unwrap();
            }
        }
    }

    assert_eq!(store.count().unwrap(), 3, "re-import must not duplicate");
    let ada = store.by_source_uid("urn:uuid:ada").unwrap().unwrap();
    assert_eq!(ada.org.as_deref(), Some("Analytical Engines Ltd"));
    assert_eq!(ada.created_unix, 1_700_000_000, "creation time is preserved");
    assert_eq!(ada.updated_unix, 1_700_100_000);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hostile_streams_are_refused_or_bounded_but_never_panic() {
    let limits = VCardLimits::default();
    let cases: Vec<String> = vec![
        "".into(),
        "\0\0\0".into(),
        "BEGIN:VCARD".into(),
        "END:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nFN:x\r\nEND:VCARD\r\n".into(),
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:\u{feff}zero width\r\nEND:VCARD\r\n".into(),
        format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:{}:\r\nEND:VCARD\r\n",
            "A".repeat(10_000)
        ),
        // Deeply repeated parameters and empty names.
        "BEGIN:VCARD\r\nVERSION:4.0\r\n;;;;\r\nFN:x\r\nEND:VCARD\r\n".into(),
        // Escapes that terminate the value string.
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:trailing\\\\\\\\\r\nEND:VCARD\r\n".into(),
        // Email that is not an address at all.
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:x\r\nEMAIL;TYPE=work:not an address\r\nEND:VCARD\r\n".into(),
    ];

    for (i, case) in cases.iter().enumerate() {
        match vcard::import_vcards(case, &limits, 0) {
            Ok(import) => {
                for c in &import.contacts {
                    // Anything that survives the parser must also survive a
                    // store write and a re-export — the layering agrees.
                    assert!(c.validate().is_ok(), "case {i} produced an invalid contact");
                    vcard::export_vcard(c).unwrap_or_else(|e| panic!("case {i} cannot export: {e}"));
                }
            }
            Err(_) => { /* refuse loudly, never silently mangle */ }
        }
    }
}

#[test]
fn a_huge_stream_is_refused_before_it_is_parsed() {
    let huge = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:x\r\nEND:VCARD\r\n".repeat(60_000);
    let err = vcard::parse_vcards(&huge, &VCardLimits::default()).unwrap_err();
    assert!(
        matches!(err, vcard::VCardError::InputTooLarge { .. }),
        "unexpected: {err}"
    );
}

#[test]
fn store_rejects_invalid_contacts_at_the_boundary() {
    let store = ContactStore::open_memory(0).unwrap();

    let mut empty = Contact::new("   ", 0);
    empty.id = "x".into();
    assert!(matches!(
        store.insert(&empty, 0),
        Err(ContactsError::Invalid(_))
    ));

    let mut bad_email = Contact::new("Bad", 0);
    bad_email.emails = vec![kiwi_contacts::ContactEmail {
        address: "not-an-address".into(),
        label: None,
    }];
    assert!(matches!(
        store.insert(&bad_email, 0),
        Err(ContactsError::Invalid(_))
    ));

    // Nothing was written by the refused calls.
    assert_eq!(store.count().unwrap(), 0);
}

#[test]
fn stored_contact_serializes_to_the_contract_json_shape() {
    let store = ContactStore::open_memory(0).unwrap();
    let mut c = Contact::new("Ada Lovelace", 0)
        .with_email("ada@work.invalid", Some("work"))
        .with_org("Analytical Engines")
        .with_tags(vec!["friend"]);
    c.phones = vec![ContactPhone {
        number: "555-0100".into(),
        label: Some("mobile".into()),
    }];
    let stored = store.insert(&c, 7).unwrap();

    let json = serde_json::to_value(&stored).unwrap();
    let object = json.as_object().expect("contact is a JSON object");
    for key in [
        "id",
        "display_name",
        "given_name",
        "family_name",
        "middle_name",
        "name_prefix",
        "name_suffix",
        "org",
        "title",
        "notes",
        "tags",
        "emails",
        "phones",
        "source_uid",
        "rev_unix",
        "created_unix",
        "updated_unix",
    ] {
        assert!(object.contains_key(key), "contract field {key} missing");
    }
    assert_eq!(json["id"], "local-1");
    assert_eq!(json["emails"][0]["address"], "ada@work.invalid");
    assert_eq!(json["emails"][0]["label"], "work");
    assert!(json["phones"].is_array());

    // And it round-trips back through serde unchanged.
    let back: Contact = serde_json::from_value(json).unwrap();
    assert_eq!(back, stored);
}
