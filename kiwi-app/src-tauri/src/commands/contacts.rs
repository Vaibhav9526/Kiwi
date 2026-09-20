//! Address-book commands (T-175) — thin, gated wrappers over the
//! `kiwi-contacts` store (`contacts.db`, kiwi.contacts/1). The crate owns
//! all field bounds (`Contact::prepare` runs inside every `insert`/
//! `update`); this layer adds the lock gate, IPC-level input bounds,
//! error-code mapping (contacts.md §7), and audit records for writes.

use std::sync::Arc;

use tauri::State;

use kiwi_contacts::error::ContactsError;
use kiwi_contacts::vcard::{self, VCardLimits};

use super::{bounded, clamp_u32, gate};
use crate::error::{CmdResult, IpcError};
use crate::state::{AppState, now_unix};
use crate::types::{ContactInput, ContactView, ImportIssueView, TagCountView, VCardImportView};

fn contacts_err(e: ContactsError) -> IpcError {
    match e {
        ContactsError::Invalid(m) => IpcError::invalid(m),
        ContactsError::NotFound(m) => IpcError::not_found(m),
        ContactsError::VCard(e) => IpcError::invalid(e.to_string()),
        other => IpcError::new("internal", format!("contacts store: {other}")),
    }
}

fn bounded_id(name: &str, id: &str) -> CmdResult<()> {
    bounded(name, id, 256)
}

async fn audit(state: &AppState, event: &'static str, detail: &str) -> CmdResult<()> {
    state.audit.lock().await.record(event, detail, now_unix())
}

/// `kiwi_list_contacts(limit?, offset?)` → `ContactView[]`, ordered
/// `display_name` then `id`. `limit` clamps to 500 (crate MAX_PAGE).
#[tauri::command]
pub async fn kiwi_list_contacts(
    state: State<'_, Arc<AppState>>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> CmdResult<Vec<ContactView>> {
    gate(state.inner()).await?;
    let limit = clamp_u32(limit, 100, kiwi_contacts::store::MAX_PAGE);
    let contacts = state.contacts.lock().await;
    Ok(contacts
        .list(limit, offset.unwrap_or(0))
        .map_err(contacts_err)?
        .into_iter()
        .map(ContactView::from)
        .collect())
}

/// `kiwi_search_contacts(query, limit?)` → `ContactView[]`. Case-
/// insensitive substring across name/org/notes/tags/emails; `%`/`_`/`\\`
/// match literally; empty query degenerates to list (contacts.md §3.2).
#[tauri::command]
pub async fn kiwi_search_contacts(
    state: State<'_, Arc<AppState>>,
    query: String,
    limit: Option<u32>,
) -> CmdResult<Vec<ContactView>> {
    gate(state.inner()).await?;
    bounded("query", &query, 256)?;
    let limit = clamp_u32(limit, 100, kiwi_contacts::store::MAX_PAGE);
    let contacts = state.contacts.lock().await;
    Ok(contacts
        .search(&query, limit)
        .map_err(contacts_err)?
        .into_iter()
        .map(ContactView::from)
        .collect())
}

/// `kiwi_get_contact(contactId)` → `ContactView` (`not-found` absent).
#[tauri::command]
pub async fn kiwi_get_contact(
    state: State<'_, Arc<AppState>>,
    contact_id: String,
) -> CmdResult<ContactView> {
    gate(state.inner()).await?;
    bounded_id("contactId", &contact_id)?;
    let contacts = state.contacts.lock().await;
    contacts
        .get(&contact_id)
        .map_err(contacts_err)?
        .map(ContactView::from)
        .ok_or_else(|| IpcError::not_found("unknown contact"))
}

/// `kiwi_create_contact(contact)` → `ContactView` — store assigns a
/// `local-N` id (the `local-` prefix is reserved for it).
#[tauri::command]
pub async fn kiwi_create_contact(
    state: State<'_, Arc<AppState>>,
    contact: ContactInput,
) -> CmdResult<ContactView> {
    gate(state.inner()).await?;
    let contact = contact.into_contact(String::new());
    let stored = state
        .contacts
        .lock()
        .await
        .insert(&contact, now_unix())
        .map_err(contacts_err)?;
    audit(state.inner(), "contact-created", &stored.id).await?;
    Ok(ContactView::from(stored))
}

/// `kiwi_update_contact(contactId, contact)` → `ContactView` — full
/// replace, not a merge; `createdUnix` is preserved.
#[tauri::command]
pub async fn kiwi_update_contact(
    state: State<'_, Arc<AppState>>,
    contact_id: String,
    contact: ContactInput,
) -> CmdResult<ContactView> {
    gate(state.inner()).await?;
    bounded_id("contactId", &contact_id)?;
    let contact = contact.into_contact(contact_id.clone());
    let stored = state
        .contacts
        .lock()
        .await
        .update(&contact, now_unix())
        .map_err(contacts_err)?;
    audit(state.inner(), "contact-updated", &contact_id).await?;
    Ok(ContactView::from(stored))
}

/// `kiwi_delete_contact(contactId)` → `{removed}`.
#[tauri::command]
pub async fn kiwi_delete_contact(
    state: State<'_, Arc<AppState>>,
    contact_id: String,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    bounded_id("contactId", &contact_id)?;
    let removed = state
        .contacts
        .lock()
        .await
        .delete(&contact_id)
        .map_err(contacts_err)?;
    if removed {
        audit(state.inner(), "contact-deleted", &contact_id).await?;
    }
    Ok(serde_json::json!({ "removed": removed }))
}

/// `kiwi_contacts_by_email(address)` → `ContactView | null` — the
/// recipient→name lookup the reader/composer use.
#[tauri::command]
pub async fn kiwi_contacts_by_email(
    state: State<'_, Arc<AppState>>,
    address: String,
) -> CmdResult<Option<ContactView>> {
    gate(state.inner()).await?;
    bounded("address", &address, 320)?;
    let contacts = state.contacts.lock().await;
    Ok(contacts
        .by_email(&address)
        .map_err(contacts_err)?
        .map(ContactView::from))
}

/// `kiwi_contacts_by_tag(tag, limit?)` → `ContactView[]`.
#[tauri::command]
pub async fn kiwi_contacts_by_tag(
    state: State<'_, Arc<AppState>>,
    tag: String,
    limit: Option<u32>,
) -> CmdResult<Vec<ContactView>> {
    gate(state.inner()).await?;
    bounded("tag", &tag, 64)?;
    let limit = clamp_u32(limit, 100, kiwi_contacts::store::MAX_PAGE);
    let contacts = state.contacts.lock().await;
    Ok(contacts
        .by_tag(&tag, limit)
        .map_err(contacts_err)?
        .into_iter()
        .map(ContactView::from)
        .collect())
}

/// `kiwi_contact_tags()` → `{tag, count}[]`, most-used first.
#[tauri::command]
pub async fn kiwi_contact_tags(state: State<'_, Arc<AppState>>) -> CmdResult<Vec<TagCountView>> {
    gate(state.inner()).await?;
    let contacts = state.contacts.lock().await;
    Ok(contacts
        .tags()
        .map_err(contacts_err)?
        .into_iter()
        .map(|(tag, count)| TagCountView { tag, count })
        .collect())
}

/// `kiwi_import_vcards(vcard)` → `VCardImportView`. Hard parse errors
/// abort as `invalid-input`; per-card issues never discard the rest
/// (contacts.md §5.2). Re-import dedupes on `source_uid` (§5.4): an
/// already-known `UID` updates in place, preserving `id`/`createdUnix`.
#[tauri::command]
pub async fn kiwi_import_vcards(
    state: State<'_, Arc<AppState>>,
    vcard_text: String,
) -> CmdResult<VCardImportView> {
    gate(state.inner()).await?;
    // The crate's hard cap is the binding bound; reject early so the
    // oversized string never reaches the parser.
    bounded("vcard", &vcard_text, VCardLimits::default().max_input_bytes)?;
    let now = now_unix();
    let cards = vcard::parse_vcards(&vcard_text, &VCardLimits::default())
        .map_err(|e| IpcError::invalid(e.to_string()))?;
    let mut out = VCardImportView {
        contacts: Vec::new(),
        issues: Vec::new(),
    };
    let contacts = state.contacts.lock().await;
    for card in &cards {
        match card.to_contact(now) {
            Ok(c) => {
                // §5.4: source_uid match → wholesale update, else insert.
                // A lookup failure degrades to insert — a dedup read error
                // must not discard an otherwise-valid card.
                let existing = c
                    .source_uid
                    .as_deref()
                    .map(|uid| contacts.by_source_uid(uid))
                    .and_then(|r| r.ok())
                    .flatten();
                let result = match existing {
                    Some(prev) => {
                        let mut merged = c.clone();
                        merged.id = prev.id.clone();
                        merged.created_unix = prev.created_unix;
                        contacts.update(&merged, now)
                    }
                    None => contacts.insert(&c, now),
                };
                match result {
                    Ok(stored) => out.contacts.push(ContactView::from(stored)),
                    Err(e) => out.issues.push(ImportIssueView {
                        card_index: card.index,
                        detail: format!("store: {e}"),
                    }),
                }
            }
            Err(e) => out.issues.push(ImportIssueView {
                card_index: card.index,
                detail: e.to_string(),
            }),
        }
    }
    drop(contacts);
    if !out.contacts.is_empty() {
        audit(
            state.inner(),
            "contacts-imported",
            &format!("{} cards, {} issues", out.contacts.len(), out.issues.len()),
        )
        .await?;
    }
    Ok(out)
}

/// `kiwi_export_vcards(contactIds?)` → `{vcard}` — vCard 4.0, CRLF
/// folded; all contacts when `contactIds` is omitted. An unknown
/// explicit id is `not-found` (the caller asked for something that
/// does not exist — silently omitting it would lie).
#[tauri::command]
pub async fn kiwi_export_vcards(
    state: State<'_, Arc<AppState>>,
    contact_ids: Option<Vec<String>>,
) -> CmdResult<serde_json::Value> {
    gate(state.inner()).await?;
    let contacts = state.contacts.lock().await;
    let all = match contact_ids {
        Some(ids) => {
            if ids.len() > kiwi_contacts::store::MAX_PAGE as usize {
                return Err(IpcError::invalid("too many contactIds (max 500)"));
            }
            let mut found = Vec::with_capacity(ids.len());
            for id in &ids {
                bounded_id("contactId", id)?;
                found.push(
                    contacts
                        .get(id)
                        .map_err(contacts_err)?
                        .ok_or_else(|| IpcError::not_found("unknown contact"))?,
                );
            }
            found
        }
        // Page the whole book — `list` clamps at MAX_PAGE per call.
        None => {
            let mut out = Vec::new();
            let mut offset = 0u32;
            loop {
                let page = contacts
                    .list(kiwi_contacts::store::MAX_PAGE, offset)
                    .map_err(contacts_err)?;
                let n = page.len() as u32;
                out.extend(page);
                if n < kiwi_contacts::store::MAX_PAGE {
                    break;
                }
                offset += n;
            }
            out
        }
    };
    let vcard = vcard::export_vcards(&all)
        .map_err(|e| IpcError::new("internal", format!("export: {e}")))?;
    Ok(serde_json::json!({ "vcard": vcard }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::types::ContactInput;

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "kiwi-contacts-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        AppState::open_test(dir).unwrap()
    }

    fn input(name: &str, email: &str) -> ContactInput {
        ContactInput {
            display_name: name.into(),
            emails: vec![kiwi_contacts::ContactEmail {
                address: email.into(),
                label: None,
            }],
            ..Default::default()
        }
    }

    async fn create(state: &AppState, input: ContactInput) -> ContactView {
        let contact = input.into_contact(String::new());
        ContactView::from(
            state
                .contacts
                .lock()
                .await
                .insert(&contact, now_unix())
                .unwrap(),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn contacts_crud_and_lookup_roundtrip() {
        let state = test_state("crud");
        let ada = create(&state, input("Ada Lovelace", "ada@x.test")).await;
        assert!(ada.id.starts_with("local-"));

        let store = state.contacts.lock().await;
        // by_email matches the stored (normalized) spelling exactly.
        assert_eq!(store.by_email("ada@x.test").unwrap().unwrap().id, ada.id);
        assert_eq!(
            store.get(&ada.id).unwrap().unwrap().display_name,
            "Ada Lovelace"
        );
        assert_eq!(store.search("lovelace", 50).unwrap().len(), 1);
        assert!(store.delete(&ada.id).unwrap());
        assert!(store.get(&ada.id).unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn vcard_import_dedupes_on_source_uid() {
        let state = test_state("vcard");
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:aaa\r\nFN:Ada L\r\nEMAIL:ada@x.test\r\nEND:VCARD\r\n";
        let cards = vcard::parse_vcards(card, &VCardLimits::default()).unwrap();
        assert_eq!(cards.len(), 1);
        let c = cards[0].to_contact(now_unix()).unwrap();
        let store = state.contacts.lock().await;
        let first = store.insert(&c, now_unix()).unwrap();
        // Re-import: same UID → update, same local id, new name.
        let mut c2 = cards[0].to_contact(now_unix()).unwrap();
        c2.display_name = "Ada Lovelace".into();
        let existing = store.by_source_uid("urn:uuid:aaa").unwrap().unwrap();
        c2.id = existing.id;
        let second = store.update(&c2, now_unix()).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(second.display_name, "Ada Lovelace");
        assert_eq!(store.count().unwrap(), 1);
        // Export round-trips through the codec.
        let out = vcard::export_vcards(&[second]).unwrap();
        assert!(out.contains("UID:urn:uuid:aaa"));
        assert!(out.contains("FN:Ada Lovelace"));
    }
}
