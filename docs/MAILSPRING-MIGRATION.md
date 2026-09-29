# Mailspring → KIWI UI migration contract

Branch: `ui-migration`. Vendored source: `vendor/mailspring/` (full `app/src`,
`app/internal_packages`, `app/static/style`, `LICENSE.md` — GPL-3.0 attribution
stays in-tree; see vendor/CLAUDE.md for the source project's rules).

Goal: KIWI's mail UI adopts Mailspring's component layer verbatim where
possible, adapted at documented seams, wired to the KIWI IPC backend
(`src/ipc.ts` / `src/kiwi.ts`) — never to Mailspring's Flux/DatabaseStore.

## Rules

1. **Port verbatim, adapt only at seams.** Copy Mailspring code into
   `kiwi-app/src/ms/` preserving class/logic; replace only imports that reach
   Mailspring runtime services. Header comment in every ported file:
   `Ported from Mailspring <path>` + list of adapted seams.
2. **Forbidden in kiwi-app:** `electron`, `@electron/remote`, `AppEnv`,
   `mailspring-exports`, `DatabaseStore`, `ContactStore` (theirs), `Actions`,
   `TaskQueue`, Flux stores, `ipcRenderer`, `Rx`, `mailspring-component-kit`.
   Each becomes an adapter in `src/ms/` (see seam map).
3. **Backend truth:** all data via `api.*` in `ipc.ts` / `ContactView` shapes in
   `kiwi.ts`. No fabricated live state; browser preview stays honest-demo.
4. **React 18 OK:** ported class components use `findDOMNode`/string refs —
   still supported. No forwardRef-ification unless broken.
5. **Styling:** port the `.less` for each component into `ms-components.css`,
   mapping `@tokens` to `--kiwi-*`/`--em-*` vars already in shell.css. No
   gradients, no hardcoded brand colors — use our tokens.
6. **Honesty gates unchanged:** tsc clean, vite build clean, `ui-smoke` 27/27,
   `ui-stress` 19/19. Each port adds at least one smoke assertion.
7. **Surgical commits:** stage only owned hunks; index carries foreign work.

## Seam map (Mailspring → KIWI adapter in src/ms/)

| Mailspring dep | Adapter | Notes |
|---|---|---|
| `Utils` (flux/models/utils) | `ms-utils.ts` DONE — verbatim subset (isEqual*, localized-safe fns) |
| `DOMUtils` | `ms-dom-utils.ts` DONE — verbatim subset |
| `RegExpUtils` | `ms-regexp-utils.ts` DONE — verbatim UnicodeEmailChars+emailRegex |
| `localized()` (intl.ts) | `ms-i18n.ts` — pass-through stub w/ TODO for real l10n |
| `Menu`/`MenuItem`/`remote.Menu` | `ms-electron.ts` — builds DOM ctx menu reusing `.em-ctx` patterns |
| `clipboard` | `ms-electron.ts` — `navigator.clipboard` w/ execCommand fallback |
| `Contact`/`ContactGroup` models | `ms-contact.ts` — thin class over `ContactView` fields (name,email,id) |
| `ContactStore` (parseContactsInString, searchContacts, findContactWithEmail) | `ms-contact.ts` — async provider calling `api.searchContacts` + local `contactBook`; parse via RegExpUtils |
| `DatabaseStore` | `ms-contact.ts` — only used by ContactStore; adapt, don't port |
| `Actions`/`TaskQueue`/`DraftStore` | per-task: map to existing compose state callbacks |
| `keymap`/`AppEnv.commands` | `ms-keymap.ts` — register dispose shim over existing keydown wiring |
| `Rx.Disposable`/`Disposable` | `ms-keymap.ts` — trivial `{dispose()}` shape |
| `mailspring-component-kit` re-exports | `ms-exports.ts` — barrel re-exporting all ms/* + our icons |
| `classnames`, `underscore`, `prop-types` | real npm deps — installed; import directly |

## Port order (tasks T-355+)

1. **Kit completion (T-355, A25):** ms-electron, ms-contact, ms-i18n,
   ms-keymap, ms-exports barrel. Kit must compile standalone before ports.
2. **Composer chain (T-356, A25):** `menu.tsx`, `key-commands-region.tsx`,
   `tokenizing-text-field.tsx`, `participants-text-field.tsx` +
   `tokenizing-text-field.less` styles. Tests: spec files at
   `vendor/mailspring/app/spec/components/` are reference — port the token
   behavior asserts into a vitest or smoke check.
3. **Wire composer (T-357, A24):** `compose.tsx` To/Cc rows →
   `MsParticipantsTextField`. participants `{to,cc}` ↔ recipients state;
   suggestions via kit ContactStore; keep send/dock/reply-prefill; smoke
   `composer-chips-commit` + `reply-prefill` must stay green.
4. **Folder rail (T-358, A24):** `outline-view.tsx`, `outline-view-item.tsx`,
   `disclosure-triangle.tsx`, `drop-zone.tsx` → `nav.em-folders` account
   sections as `IOutlineViewItem[]`. Preserve drop targets, ctx menus
   (T-322 folder-mgmt), smart folders, counts.
5. **Thread list (T-359, A24):** `list-tabular.tsx` + thread-list row cells →
   mailbox rows surface. Keep security pill, tri-state marks, pick-mode,
   virtualization behavior (only if theirs is better — else keep ours and
   port skin only). Record decision in doc.
6. **Composer view full (T-361, A24):** `composer-header-actions`,
   `send-action-button` (split pill already ours — adopt theirs only if
   stricter), `attachment-area` with real `api.*` upload paths.
7. **Themes (T-360, A25):** map `ui-variables.less` + theme packages
   (dark/oled/sepia families) into stock theme packages — runs anytime.
8. **Preferences (T-362, A25):** settings rail → Mailspring preferences
   section components, keeping our settings schema.

## Non-goals

- No Flux, no sync engine port, no plugin loader.
- Backend untouched — "wire with the mail backend" = consume existing IPC;
  if a port truly needs a new command, file a task for A20, don't fake it.

## Ledger

| File/component | Source | Status | Owner |
|---|---|---|---|
| ms-utils.ts | flux/models/utils.ts | done | Lead (kit) |
| ms-dom-utils.ts | components/utils/* | done | Lead (kit) |
| ms-regexp-utils.ts | regexp-utils.ts | done | Lead (kit) |
