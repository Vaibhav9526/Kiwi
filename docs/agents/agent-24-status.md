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
