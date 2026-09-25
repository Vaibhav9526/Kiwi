# Agent 24 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-267: Pixel-faithful eM Client 4-pane rebuild

**Status:** done (`tsc && vite build` green; clean-room layout imitation of
`docs/ui/reference-layout.png` — no closed-source code involved).

### Files changed

- `kiwi-app/src/components/chrome.tsx` — rewritten as the eM-idiom chrome:
  `TopBar` (titlebar with hamburger menu, centered search pill
  `Search (type ? for help)`, demo pill, theme select, palette/shortcuts
  buttons, security TrustChip) + toolbar row (`+New` orange primary with
  chevron, Refresh, Reply, Reply All, Forward, Mark, Archive, Snooze,
  Quick Actions, Delete — icon + label + chevron menus); `FolderPane`
  ("Mail" header, Favorites section, smart folders with right-aligned
  counts — All Inboxes/Outbox/Sent/Trash/Drafts/Junk Email/Unread/Flagged/
  Unreplied/Snoozed, per-account expandable sections); `AgendaRail`
  (collapsible right rail — "Add new task" input, date-grouped checkbox
  items with flag icons, GTD surface, persisted via prefs, collapse state
  persisted, `kiwi-rail-toggle` window event seam); `StatusStrip` (bottom
  icon strip + status text + pending-approvals hook); `AppShell` 4-pane
  grid (sidebar | content | rail | status).
- `kiwi-app/src/views/mailbox.tsx` — eM-style message list: Primary/Other
  tabs with `+N` count (Primary = category `primary`, Other aggregates the
  rest), Today/Older date groups, circular tinted avatars, bold unread
  sender line, colored category pills (News=blue / Personal=orange /
  Logs=green hooks), gray snippet, unread dot, paperclip indicator, thread
  count badge, light-blue selection; reader = thread title + stacked
  message cards (avatar, blue sender name, right-aligned timestamp,
  collapse-to-snippet chevron). Selection, bulk ops, keyboard nav,
  remote-content controls, attachments, outbox queue preserved.
- `kiwi-app/src/App.tsx` — light theme default; `answered` populated from
  the IMAP `\Answered` flag in `toEnvelope`; smart-folder message loading
  (all-inboxes/unread/flagged/unreplied aggregate account inboxes;
  sent/trash/drafts/junk aggregate matching folders; snoozed via
  `api.listSnoozed`; outbox via queue); toolbar handlers wired to existing
  bulk ops (`bulkPatch`, `bulkDelete`, `setJunk`, `snoozeMessages`,
  `unsnoozeMessages`); `AppShell` composition with `FolderPane`,
  `AgendaRail`, `StatusStrip`.
- `kiwi-app/src/state/accounts.ts` — `useAccountModel` now returns
  `smartFolders`, `accountSections`, `smartUnread` with real unread counts
  alongside the existing folder models.
- `kiwi-app/src/prefs.ts` — `kiwi.theme` default `light`; `data-theme`
  attribute passthrough left as the A25 theme-package seam; agenda tasks +
  rail collapse persisted under `kiwi.agenda` / `kiwi.rail`.
- `kiwi-app/src/components/shell-icons.tsx` — new adapter delegating shell
  icon exports to the real T-268 registry (`components/icons/`); temporary
  local stubs retained for printer / panel-collapse / unreplied pending
  registry coverage.
- `kiwi-app/src/components/icons.tsx` — deleted (earlier stub; filename
  collided with A25's `components/icons/` directory under `./icons`
  resolution).
- `kiwi-app/src/shell.css` — eM light-idiom layer appended (`--em-*` token
  set: pane border `#e1e5ea`, selection `#d7ebfb`, primary `#f5a623`;
  `[data-theme="dark"][data-shell="mailspring"]` remap keeps dark opt-in);
  styles for titlebar/toolbar/dropdowns/folder pane/agenda rail/status
  strip/message rows/reader cards.
- Emoji/glyph sweep in owned views — `contacts.tsx`, `filters.tsx`,
  `search.tsx`, `compose.tsx`, `settings.tsx`, `setup.tsx`,
  `integrations.tsx`, `mailbox.tsx`, `App.tsx` now render `Icon`
  components (check/close/search/paperclip/list/arrows/etc.) instead of
  emoji or text glyphs. `severityGlyph()` in `kiwi.ts` retained — it is the
  deliberate non-color severity encoding, not decoration.

### Commands run

- `npm run build` (`tsc && vite build`) — **green**; 74 modules,
  dist bundle ~378 kB JS / 63 kB CSS.
- Emoji scan (`grep -P` over `views/`, `components/`, `App.tsx`) — 0 hits.

### Assumptions / risks

- Toolbar Reply/Reply All/Forward navigate to the compose route without
  prefill — identical to the pre-rebuild behavior (keyboard `r` and reader
  reply buttons did the same); reply-context prefill was never wired.
- `severityGlyph` text marks kept inside `kiwi-pill` security chips as the
  non-color severity encoding; `security.tsx` itself was icon-swept in
  parallel (its diff stays with A25's commit scope).
- Smart-folder counts use unread data where available; `Unreplied` counts
  envelopes where `answered === false`; `Snoozed` uses `listSnoozed`.
- Uncommitted-neighbor files (`ipc.ts`, `kiwi.ts` pair/link types, other
  agents' src-tauri work) were left untouched and unstaged.

### Verification

- `npm run build` green (tsc strict incl. `noUnusedLocals`).
- Light default verified through `applyUiPrefs` (`kiwi.theme` fallback
  `"light"`, `data-theme` + `data-shell="mailspring"` attributes); dark
  theme selectable via the titlebar select and settings.
- All IPC wiring, lock veil, security pill, and policy strip preserved;
  no backend mail/security behavior changed.
- Required Orca T-267 completion report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`.

## 2026-09-25 — T-231: live-data UI wiring

**Status:** done (`tsc && vite build` green).

### Files changed

- `kiwi-app/src/App.tsx` — debounced (300 ms) `kiwi_search_messages` effect
  gated on `!demo && !trust.locked && route === "mail" && query.trim()`;
  `searchHits`/`searchBusy`/`searchNote` state; `visibleMessages`
  client-side substring filter now runs in demo mode only (live delegates
  to FTS). Landed via A25's T-275 commit `dc66778` (same-file sweep of
  in-flight work — content verified identical in HEAD).
- `kiwi-app/src/views/mailbox.tsx` — `searchResults`/`searchBusy`/
  `searchNote`/`searchQuery` props; when hits are non-null the list pane
  swaps to a "Search results" view (skeletons while busy, error banner on
  IPC failure, zero-hit empty state); tabs, select-all, and bulk bar hide
  during search. New `SearchHitRow` renders only backend-returned fields
  (sender/subject/snippet/date/paperclip — no fabricated unread/star/
  category state) and navigates to `mail` route `accountId:folderId` +
  `accountId:folderId:uid`; hits without `accountId` render inert.
- `kiwi-app/src/views/contacts.tsx` — live import now calls
  `kiwi_import_vcards` with the original file payload (server-side dedupe
  + contract issue report) instead of per-card `kiwi_create_contact`;
  live export calls `kiwi_export_vcards`. Client-side parse retained only
  for the preview table. Stale "no import IPC exists yet" comment fixed.
  Bulk of the file landed via `dc66778`; this commit adds the
  file-level-issue `cardIndex` guard.
- `docs/TASKS.md` — T-231 row → done.
- `docs/agents/agent-24-status.md` — this entry.

### Verification per requirement

1. **Category tabs on real envelopes** — already satisfied by T-267:
   `toEnvelope` maps `MessageView.category` (backend emits the store row's
   category, `kiwi-mail/src/store/queries.rs`) through `normalizeCategory`;
   tabs filter `m.category` and `+N` counts non-primary envelopes in the
   loaded list. No fabricated values.
2. **Search pill → real FTS** — `api.searchMessages` → registered command
   `kiwi_search_messages` (src-tauri/src/lib.rs:101, commands/mail.rs:162;
   grammar in `kiwi_mail::search`, `accountId` resolved server-side per
   hit). Debounced 300 ms, capped at 50 hits, Enter still opens the full
   Search view.
3. **Contacts IPC** — surface exists and is registered (`kiwi_list_contacts`,
   `kiwi_search_contacts`, `kiwi_get_contact`, `kiwi_create_contact`,
   `kiwi_update_contact`, `kiwi_delete_contact`, `kiwi_contact_tags`,
   `kiwi_import_vcards`, `kiwi_export_vcards` — src-tauri/src/lib.rs:141-151).
   The view was already IPC-wired for list/CRUD; import/export are now on
   the contract commands too. Contacts search filters the 500-row loaded
   list client-side — `kiwi_search_contacts` left for larger books
   (documented in-file, not a gap).

### Commands run

- `npm run build` (`tsc && vite build`) — green, 74 modules.
- Contract-gap sweep: `grep` over `src-tauri/src/lib.rs` registry — every
  command the UI calls is registered; **no contract gaps found**.

### Assumptions / risks

- Nothing was mocked: every live-mode surface calls a registered IPC
  command; demo mode keeps its existing labeled localStorage fixture.
- Stale comments in `ipc.ts` ("pending backend" on contacts/search
  wrappers) are wrong now — left alone, that file carries other agents'
  uncommitted work.
- `visibleMessages` no longer narrows in live mode while a query is set —
  `onEmptyTrash` consequently uses the full loaded trash list, which is
  the correct semantics.
- Required Orca T-231 completion report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`.
