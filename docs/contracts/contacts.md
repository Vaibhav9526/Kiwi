# Contract — Local Address Book (`kiwi.contacts/1`)

> Owner: Agent 9 (T-150) · **Contract version: `kiwi.contacts/1`** · Status: draft
> — awaiting Lead review · Implemented by `kiwi-contacts/` (Rust). The crate's
> public API is authoritative for semantics; this document is authoritative for
> the JSON surface and the IPC command shapes. Changes require Lead review
> (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: `kiwi-contacts` (model + store + vCard codec) → `kiwi-app/src-tauri`
(IPC command layer, trusted; maps crate types to wire views, enforces the lock
gate and input validation) → **kiwi-app webview** (React, untrusted —
SECURITY.md B2). Also consumed by the compose path (recipient autocomplete) and,
read-only, by any future org/policy surface that needs to resolve an address to
a name.

## 1. Invariants (binding)

- **No ambient state.** Every write takes `now_unix` (epoch seconds) from the
  caller. The crate never reads the system clock and never uses RNG, so
  identical inputs produce identical outputs — including the ids it assigns.
- **Contact data is untrusted input.** Every path in (typing, vCard import, IPC)
  is bounded; the caps in §4 and §6 are enforced before storage.
- **Rejection over truncation.** An over-limit value fails that record with a
  named reason. Nothing is silently shortened or dropped.
- **No credentials.** A contact is never a credential store. No password, token,
  OAuth secret, or key material may appear in any field, and none is ever logged.
- **No network.** Import and export are pure functions over caller-supplied text.
  There is no directory lookup, no gravatar fetch, no photo download.
- **Deterministic ordering.** Every list query is fully ordered (`display_name`
  then `id`); no query result depends on rowid order.
- **`contract_version` is `"kiwi.contacts/1"`.**

## 2. `Contact` (crate type ↔ wire view)

The crate serializes `Contact` with **snake_case** field names (Rust default).
`kiwi.ipc/1` §1 requires **camelCase** on the wire, so the Tauri layer maps to a
`ContactView` with `#[serde(rename_all = "camelCase")]`. The mapping is
mechanical and one-to-one; the table below gives both spellings.

| crate field | wire field | type | notes |
|-------------|-----------|------|-------|
| `id` | `id` | string | `local-N` when store-assigned (§3.1) |
| `display_name` | `displayName` | string | vCard `FN`; falls back to `N`, then to the first email |
| `given_name` | `givenName` | string\|null | vCard `N` component 2 |
| `family_name` | `familyName` | string\|null | `N` component 1 |
| `middle_name` | `middleName` | string\|null | first non-empty `N` additional component |
| `name_prefix` | `namePrefix` | string\|null | `N` component 4 |
| `name_suffix` | `nameSuffix` | string\|null | `N` component 5 |
| `org` | `org` | string\|null | vCard `ORG` first component |
| `title` | `title` | string\|null | vCard `TITLE` |
| `notes` | `notes` | string\|null | vCard `NOTE`; may contain `\n` |
| `tags` | `tags` | string[] | vCard `CATEGORIES`; de-duplicated, case-insensitively |
| `emails` | `emails` | object[] | `{ address, label }`; `label` is `string\|null` |
| `phones` | `phones` | object[] | `{ number, label }` |
| `source_uid` | `sourceUid` | string\|null | vCard `UID` of the imported card (§5.4) |
| `rev_unix` | `revUnix` | number\|null | vCard `REV` as epoch seconds |
| `created_unix` | `createdUnix` | number | store-owned |
| `updated_unix` | `updatedUnix` | number | store-owned |

`id`, `created_unix` and `updated_unix` are store-owned: values sent by a caller
are ignored on create and preserved on update.

Helper semantics the UI relies on:

- **Primary email** = `emails[0]` after normalization. Import puts `PREF`
  entries first (§5.3); everything else keeps file order.
- **Row label** = `display_name` if non-empty, else the primary email.

## 3. Commands (proposed IPC surface)

All commands are **gated** per `kiwi.ipc/1` §2: while the endpoint is locked they
fail with `code: "locked"`. Contacts are mailbox data; the lock must cover them.

| command | returns | notes |
|---------|---------|-------|
| `kiwi_list_contacts(limit?, offset?)` | `ContactView[]` | `limit` clamps to 500 |
| `kiwi_search_contacts(query, limit?)` | `ContactView[]` | §3.2 |
| `kiwi_get_contact(contactId)` | `ContactView` | `not-found` when absent |
| `kiwi_create_contact(contact: ContactInput)` | `ContactView` | store assigns `id` when empty |
| `kiwi_update_contact(contactId, contact: ContactInput)` | `ContactView` | full replace, not a merge |
| `kiwi_delete_contact(contactId)` | `{ removed: boolean }` | |
| `kiwi_contacts_by_email(address)` | `ContactView \| null` | recipient → name, for the reader/composer |
| `kiwi_contacts_by_tag(tag, limit?)` | `ContactView[]` | |
| `kiwi_contact_tags()` | `{ tag: string, count: number }[]` | most-used first, then alphabetical |
| `kiwi_import_vcards(vcardText: string)` | `VCardImportView` | §5.2 — wire arg is `vcardText` (Rust `vcard_text` → Tauri camelCase) |
| `kiwi_export_vcards(contactIds?)` | `{ vcard: string }` | all contacts when ids are omitted |

`ContactInput` is `Contact` minus the store-owned fields.

### 3.1 Identifier assignment

A contact created without an `id` is assigned `local-<n>`, where `n` is a
persisted counter (not a rowid, not a timestamp, not a UUID). Ids therefore
stay unique across restarts and are reproducible in tests. The `local-` prefix
is **reserved**: a caller-supplied id starting with it is rejected with
`invalid-input`. Imports keep their own key space (`urn:uuid:…` or whatever the
source used) by never supplying an `id` — the vCard `UID` goes to `source_uid`.

### 3.2 Search semantics

`kiwi_search_contacts` matches a **case-insensitive substring** across
`display_name`, `org`, `notes`, `tags` and email addresses.

- ASCII case folding only (SQLite `LIKE`). A query that differs from stored
  non-ASCII text only by case will not match — a documented limitation, not a
  bug to work around at the UI layer.
- `%`, `_` and `\` are matched **literally** (the term is escaped before it
  reaches `LIKE`), so a user searching for `%` gets contacts containing a
  percent sign, not the whole address book.
- An empty or whitespace-only query degenerates to `list`.
- Results are ordered by `display_name` (case-insensitive) then `id`.

## 4. Field bounds

Enforced by `Contact::validate` on every write. Over-limit input is rejected
with a named reason (`invalid-input` on the wire).

| field | limit |
|-------|-------|
| name fields (`display_name`, `given_name`, `family_name`, `middle_name`, `name_prefix`, `name_suffix`) | 256 bytes each |
| email address | 320 bytes, must be `local@domain` shaped |
| email/phone `label` | 64 bytes |
| `org` | 256 bytes · `title` 256 bytes · `notes` 4096 bytes |
| tag | 64 bytes, max 32 tags |
| email addresses | max 16 · phone numbers max 16, 64 bytes each |
| `source_uid` | 256 bytes |

A contact must have **either** a `display_name` or at least one email address.

Email address validation is structural only (one `@`, non-empty local part and
domain, no whitespace or control characters). This crate does not and must not
claim deliverability validation.

**Control characters.** `notes` is the **only** multi-line field: it may contain
`\n` and `\t`, and every other control character is refused. Every other text
field — display name, all `N` components, org, title, `source_uid`, email
addresses, and phone numbers and their labels — is single-line and refuses all
control characters, newline included. A control character in a name or org would
render as structure in a list row, a header or a composer chip, and no genuine
address book produces one; a card that carries one (via `\n` escaping in a vCard)
is refused **per card** with the offending field named, not silently reinterpreted.
This is the injection guard for §5.5, applied at the model rather than only at
export.

## 5. vCard interchange (RFC 6350)

### 5.1 Limits (`VCardLimits`)

| limit | default |
|-------|---------|
| `max_input_bytes` | 1 MiB |
| `max_line_bytes` | 1 MiB (defaults to the input cap; tighten to reject blob-carrying cards) |
| `max_cards` | 1000 |
| `max_properties_per_card` | 256 |
| `max_value_bytes` | 4096 per stored value |

`PHOTO`, `LOGO`, `SOUND` and `KEY` values are exempt from `max_value_bytes`
(they are never stored) so that a card carrying an embedded photo imports as a
contact instead of failing; they remain bounded by the line and input caps.

### 5.2 Error model

Two classes, deliberately different:

- **Hard errors** abort the whole stream: oversized input, a line over the line
  cap, an unterminated card, a malformed content line, content outside any card,
  too many cards, too many properties on a card. Past that point the bounds the
  caller asked for can no longer be guaranteed. Wire code: `invalid-input`.
- **Per-card issues** never discard the rest of the file: a card missing
  `VERSION`, declaring an unsupported version, exceeding a per-field cap, or
  producing an invalid contact is skipped and reported.

`VCardImportView` is `{ contacts: ContactView[], issues: { cardIndex: number,
detail: string }[] }`. `issues` empty is the happy path. The import wizard shows
one row per issue; it never shows a count without the reasons.

### 5.3 Properties

| property | import | export |
|----------|--------|--------|
| `VERSION` | required (`4.0`, `3.0`, `2.1`; others are an issue) | `4.0` |
| `FN`, `N` | yes | yes |
| `ORG` (first component only), `TITLE`, `NOTE` | yes | yes |
| `UID` | yes → `source_uid` | from `source_uid`, else `id` (omitted when both are empty) |
| `REV` | yes (see below) | from `rev_unix` |
| `EMAIL`, `TEL` with `TYPE` | yes | yes, when the label survives §5.5 |
| `CATEGORIES` | yes | yes |
| `PHOTO`, `LOGO`, `SOUND`, `KEY`, `URL`, `ADR`, `BDAY`, `X-*`, unknown | ignored | never written |

Ignored properties are **not** errors — a newer producer must stay importable.

`PREF` is recognized in all three forms real exporters use (`PREF=1`, bare
`PREF`, `TYPE=pref`) and promotes the entry to the front of the list. `TYPE`
values `internet` and `pref` are transport hints, not labels, and are not stored
as one.

`REV` is parsed from `19961022T140000Z`, `1996-10-22T14:00:00Z`, `19961022` and
the `±HHMM` offset forms; anything else yields `rev_unix: null` rather than an
error. The date arithmetic is integer-only (no floating point, no date crate).

### 5.4 Re-import

An address book re-imported (mail client switch, sync, manual reload) must not
duplicate. The caller matches on `source_uid` — `by_source_uid(uid)` → `update`
when found, `insert` otherwise — which preserves `created_unix` and the local
`id`. This crate does not merge field-by-field: the imported card wins wholesale.
Merging policy belongs to the import wizard, not to storage.

### 5.5 Export safety

Export is the one place stored data becomes a structured document, so:

- Every text value is escaped per RFC 6350 §3.4 (`\\`, `\,`, `\;`, newline →
  `\n`). A raw CR is dropped.
- **Parameters are sanitized, not escaped** — RFC 6350 has no parameter escaping
  mechanism, so a `TYPE` label is reduced to `[a-z0-9-]` and omitted entirely if
  nothing survives. Stored data therefore cannot introduce a `;` or `:` into the
  parameter section.
- The contact is re-validated before rendering; a stored value carrying a raw
  CRLF is not exportable at all (§4 control-character rule).
- Lines are folded at 75 octets on UTF-8 character boundaries, CRLF-terminated.
- Export never stamps the current time. `REV` is written only when `rev_unix` is
  set, so two exports of an unchanged contact are byte-identical.

## 6. Storage

- Per-profile SQLite file `contacts.db` under the app data root, alongside
  `kiwi-mail`'s `mail.db` — never the same file, never shared tables.
- Schema evolution uses an explicit `schema_migrations` table over an ordered,
  append-only migration list. (kiwi-mail's store uses `PRAGMA user_version` for
  the same purpose; the address book carries its own table because vCard
  import/merge is expected to keep reshaping the schema.) A database whose
  schema is *newer* than the running build is refused rather than opened.
- All SQL is parameterized. Child rows (`contact_emails`, `contact_phones`,
  `contact_tags`) are foreign-keyed with `ON DELETE CASCADE` and `foreign_keys`
  is enabled on every connection.
- Tabs: `contacts` · `contact_emails` (position-ordered) · `contact_phones` ·
  `contact_tags` (case-insensitive PK) · `counters` (id sequence) ·
  `schema_migrations`.

## 7. Error codes (mapping to `kiwi.ipc/1` §11)

| crate error | wire code | when |
|-------------|-----------|------|
| `ContactsError::Invalid` / `VCardError::*` (input-class) | `invalid-input` | bounds, malformed stream, bad version |
| `ContactsError::NotFound` | `not-found` | update/delete/get of an unknown id |
| `ContactsError::Store` | `internal` | SQLite failure |
| `ContactsError::Io` | `internal` | profile directory not writable |

## 8. Not in this contract (deliberate)

- **No contact groups / mailing lists.** Tags cover the grouping use case; a
  distribution-list model needs its own send-path semantics (and policy
  interaction) before it earns a schema.
- **No photo storage.** `PHOTO` is skipped on import. Storing images means an
  on-disk blob store, a render path, and an image-parsing boundary that this
  crate should not own implicitly.
- **No CardDAV / remote sync.** Local-first; a remote address book is a separate
  task with its own auth and conflict story.
- **No merge/conflict resolution.** See §5.4.
- **No encryption at rest for this file.** Contacts are not secrets; if the
  threat model changes, that is a `kiwi-core` policy decision, not a local one.
