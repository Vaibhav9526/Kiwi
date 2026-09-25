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

## 2026-09-25 — T-281: rules management UI (kiwi_rules_* surface)

**Status:** done (`tsc && vite build` green).

### Files changed

- `kiwi-app/src/views/rules.tsx` — NEW `RulesView`: the authoring surface
  for the backend rules DSL (ipc.md §6d). List shows name / enabled
  checkbox / scope pill / block-list badge / position + humanized
  `describePredicate` → `describeAction` summary; enable/disable and
  up/down reorder are `kiwi_rules_upsert` calls on the stored row (reorder
  = position swap with the neighbor); delete uses an inline confirm.
  Create/edit form: name + account scope + enabled + `isBlock`, recursive
  `PredicateEditor` covering every AST node kind (sender/recipient/
  subject/header/body_contains/attachment_name leaves with
  contains/is/ends_with/domain ops + header-name field; all/any/not/
  always combinators, node-count and depth caps mirroring model.rs),
  action rows (move/archive/delete/mark_read/star — move gets a real
  `folderLists` picker grouped per account, disposition kinds limited to
  one per rule since evaluation is first-wins). "Test rule" dry-runs
  `kiwi_rules_preview` (exists — landed with T-244 surface) and renders
  matched count + first hits; "Run rules now" loops `kiwi_rules_apply_now`
  over all accounts and reports aggregate counts. Renderer inputs are
  `maxLength`-bounded to the model.rs caps; validation stays server-side
  (`invalid-input` errors surface verbatim in a banner).
- `kiwi-app/src/views/settings.tsx` — `RulesView` mounted at the top of
  the existing "Mail Rules" section; the prefs-backed `FiltersView`
  (T-186 local engine) remains below as "Draft filters", clearly labeled.
  New optional `folderLists` prop.
- `kiwi-app/src/App.tsx` — passes `folderLists` to `SettingsView`.
- `docs/TASKS.md` — T-281 row → done.
- `docs/agents/agent-24-status.md` — this entry.

### Contract findings

- `kiwi_rules_list` with no `accountId` returns **global rules only** —
  per-account calls are merged + deduped by id so scoped rules are
  visible. Documented in-file.
- `kiwi_rules_preview` IS registered (`lib.rs:172`) — the preview seam
  the brief asked for exists and is wired; no contract gap.
- `kiwi_rules_hits` (audit trail) exists but is not yet surfaced — noted
  as a natural follow-up for the security/forensic side, not required by
  the brief.

### Assumptions / risks

- Demo mode shows a labeled empty state — no fabricated ruleset.
- All edits ride `kiwi_rules_upsert` (create-or-replace by caller-assigned
  id); reorder swaps `position` values, matching backend evaluation order
  (ascending position, id tie-break).
- Committed code was swept into A25's T-280 commit `8b4aabb` mid-flight
  (same working tree) — HEAD verified to contain the final file.

### Verification

- `npm run build` (`tsc && vite build`) — green, 81 modules.
- Registry sweep: all six `kiwi_rules_*` commands present in
  `src-tauri/src/lib.rs:167-172`.
- Required Orca T-281 completion report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`.

## T-284 — security-surface regression pass (rebuilt layout)

### Audited surfaces

| Surface | Verdict |
|---|---|
| Unlock flow (T-269 canonical) | PASS — `api.unlockChallenge(active.deviceId)` at `App.tsx:1108`, polls `kiwi_security_status` every 3s while `AuthenticatorDialog` is open; `LockOverlay` shows trust lines + challenge id. No `requestChallenge(deviceId,"unlock")` callers remain (the generic wrapper stays in `ipc.ts` for pairing/recovery/elevated-action events). |
| Security pill | FIXED — previously showed only account trust and opened `findings[0]` (unrelated session finding). Now: envelope carries `auth`/`attachRisk`/`linkRisk` (T-232/T-254/T-261), `messageEvidenceLevel()` maps failed→danger / noted→warning / all-clean→secure; absent evidence falls back to account trust with an honest "not evaluated" summary. Pill expands a per-message `MessageEvidence` panel (SPF/DKIM/DMARC verdicts + dkim_domain + dmarc_policy + discrepancy/untrusted-relay flags, link + attachment reason codes). Findings feed stays reachable via the separate "Security details (N)" button (disabled at 0 — was a dead click when the pill hit `openFinding(0)` with zero findings). |
| Link policy (T-273) | FIXED — `kiwi_link_click` / `kiwi_sandbox_open_link` / `kiwi_sandbox_open_attachment` were registered backend commands with ZERO UI callers; rendered anchors in `dangerouslySetInnerHTML` were unguarded. `BodyPane` now intercepts anchor clicks: `linkClick` verdict → `allow` = `kiwi_open_external`; `requireConfirm` = warn banner w/ reasons + Open anyway/Cancel; `requireSandbox` = warn banner w/ reasons + Open in sandbox (→ `sandboxOpenLink`, session id + sanitized target + evidence shown); `deny` = blocked banner, nothing opens; IPC failure = fail-closed error banner. Displayed URL is query/fragment-stripped like the backend's `sanitized_link_target`. Demo mode shows a labeled "needs the backend" note — no fabricated verdicts. |
| Attachment sandbox | FIXED — `AttachmentList` gains an "Open in sandbox" affordance per attachment (live only, `kiwi_sandbox_open_attachment`), plus a risk banner when `attachRisk` is noted/failed listing the bounded reason codes. |
| Unsubscribe chip | PASS (unchanged) — `UnsubscribeChip` still calls `kiwi_message_unsubscribe` with real `UnsubscribeInfo` endpoints; dormant without them. |
| useMailbox dead code | RESOLVED BY DELETION — `src/state/mailbox.ts` deleted. It was a 628-line duplicate of the mailbox logic `App.tsx` owns inline (mail-changed listener + loaders); zero imports anywhere (verified by grep across `src/` and `src-tauri/`). Adopting it would mean re-plumbing App.tsx's integrated loaders for no behavioral gain and churning a file other agents are actively editing. `normalizeCategory`/`parseUnsubscribe` live in `kiwi.ts`, unaffected. |

### Contract notes (not gaps)

- `auth`/`attachRisk`/`linkRisk` are absent until the message body is fetched+evaluated — the pill reads "not evaluated" rather than clean for those rows; deliberate and preserved.
- `kiwi_open_external` without `sourceUrl` requires `https://`; message links are pre-gated by `linkClick` so this is the executor path, consistent with backend design.

### Verification

- `npm run build` (`tsc && vite build`) — green, 81 modules.

## T-289 — account-add + OAuth2 flow in the new shell

### Audit result: surface was live, not stubbed — gaps fixed, rest verified

| Requirement | Verdict |
|---|---|
| Wizard end-to-end (Address→Servers→Credentials→Verify & add) | PASS — `setup.tsx` 4-step wizard inside AppShell route `setup`; autoconfig via `kiwi_discover_account` (registered `lib.rs:90`) with a labeled `local-guess` fallback on failure/absence; verify probes both servers via `kiwi_verify_server` with per-step detail; add via `kiwi_add_account` carrying `oauth2Ticket` for xoauth2. Plaintext requires explicit ack; secrets cleared post-add, never stored. |
| Device-code display + polling | PASS, tightened — `components/oauth2.tsx` renders `userCode` large w/ copy button + `verificationUriComplete ?? verificationUri` link via `kiwi_open_external` (never in-webview), per §9f. Poll loop honored `retryAfterSecs` internally already; FIXED the status line to display the live cadence (`pollSecs` state) instead of the stale begin value, added explicit **Pending** status word (approved→"Signed in as …", expired→"session expired" + "Start over"), and a missing-`userCode` guard. |
| needsRefresh badge + re-auth | PASS — Settings → Accounts polls `kiwi_oauth2_status` per account; `!credentialPresent || needsRefresh` → "OAuth2 · provider — re-auth needed" pill → inline `OAuth2SignIn` re-auth (completing the grant rewrites the same credential-store key — no re-add), posture re-fetched on done. |
| Error paths | PASS — discovery failure/absence → labeled guess-or-manual notes; §9f vocabulary mapped (`oauth2-denied/expired/not-configured/reauth/incomplete/endpoint`, `backend-unavailable`, `locked`); transient poll IPC errors keep the grant alive; verify/add failures → `${code}: ${message}` banner + Retry; demo → explicit "needs the backend" banners, nothing fabricated. |
| First-run CTA | FIXED — StatusStrip "Add account" and the +New menu entry already routed; ADDED a list-pane first-run empty state (`hasAccounts` prop = real `accountsRaw.length`): live + zero accounts → "No accounts yet / Add account…" instead of a misleading "no messages". FolderPane's empty-state CTA is A25's in-flight T-283/287 edit — left untouched. |

### Fix-forward (broken in-flight tree, not mine)

- `RuleView` gained `failureCount`/`lastError`/`lastFailureUnix` (paired backend apply-failure telemetry, in-flight kiwi.ts + src-tauri change). `rules.tsx` draft-constructor broke the build — added the fields (`0/null/null`) and rendered the intended "failing ×N" pill with `lastError`/timestamp in the tooltip. kiwi.ts staged alongside since the commit must typecheck standalone.

### Verification

- `npm run build` (`tsc && vite build`) — green, 83 modules.

## T-291 — keyboard navigation depth

### Reconciliation (overlay ⇄ reality, both directions)

| Binding | State |
|---|---|
| Ctrl+K palette · Ctrl+N compose · F5 sync · `/` focus search · `?` overlay · Enter-in-search → results · Ctrl+Enter send · Esc close dialogs | already real — verified handlers exist (App.tsx:973, chrome.tsx:293, compose.tsx:347); left as advertised. |
| j/k · ↑/↓ · n/p — next/prev message | already real — `em-rows` keydown → `stepSelection` → real `navigate` to `messageId` route. |
| s / e / u | already real — `toggleStar`/`onArchive`/`toggleRead` → `patchMessage`/`moveMessages` IPC (local-only in demo, labeled). |
| **Enter (list)** | ADDED — focus moves into `.em-reader` (`readerRef.focus()`); previously row-Enter only re-selected. |
| **Delete (list)** | ADDED — `onBulkDelete([selected.id], isTrash)` → `kiwi_delete_messages` (permanent when already in Trash). |
| **Esc / r / a / f (reader)** | ADDED — `.em-reader` gained a keydown map: Esc returns focus to the list; r/a/f open the composer (reply-all/forward share the compose route — no prefill contract exists; documented, not stubbed). |

### Focus management

- `.em-rows` gained `tabIndex={0}` so the pane itself holds nav focus (rows already focusable); reader section already had `tabIndex={0}`.
- Typing guard on both pane maps (`INPUT/TEXTAREA/SELECT/contenteditable`) — attachment "Save to" inputs live inside the reader and must not trigger s/e/u; Esc inside a field blurs it instead of bouncing panes.
- Modifier keys excluded from reader single-letter map; global handler already guards `isTyping`.
- Focus ring: `theme.css ::focus-visible` outline + T-287 button ring — new focus targets covered automatically.

### Overlay truth table

- Added rows: Enter-in-list, Delete, r/a/f reader composer keys, Esc-in-reader.
- No working-but-unlisted bindings remain (palette arrows, agenda Enter/Esc, compose address-picker are dialog-internal).
- No advertised-but-dead bindings remain.

### Verification

- `npm run build` (`tsc && vite build`) — green, 83 modules.
- No UI test driver exists in-repo (no playwright/vitest) — bindings verified by static trace to real handlers/IPC; demo mode exercises the same map with local-only mutations.

## T-292 — print + message-source views

### Print stylesheet (shell.css, `@media print`)

- Reader-only output: hides `.em-chrome` (titlebar+toolbar), `.em-folders`,
  `.em-list-col`, `.em-rail`, `.em-statusbar`, plus every interactive
  affordance inside the reader (`.em-reader-tools`, `.em-reader-meta`,
  `.em-card-tools`, `.em-card-actions`, attachment inputs/buttons/banners,
  banners' buttons, skeletons, dialogs, lock overlay).
- `.em-main/.em-center/.em-mailbox` flatten to static block flow; `.em-reader`
  un-scrolls (overflow:visible, height:auto) so multi-page bodies paginate.
- Typography: 10.5pt/1.5 body, 14pt thread title, black-on-white regardless
  of theme; card headers keep sender/recipients/date with a hairline rule;
  attachment filenames retained (only the save inputs/buttons hide);
  `page-break-inside: avoid` on cards. Selector-verified against real markup.
- Print affordance already existed (reader-tools print icon → `window.print()`).

### View source — real data, honest gap

- `SourceDialog` (mailbox.tsx) on a new reader-tools icon button (disabled
  while no body is loaded / demo — tooltip explains). Shows the real
  `kiwi_message_body` payload: parsed header table (Subject/From/To/Cc/Date/
  Message-ID/In-Reply-To/References/store coords) + a monospace scrollable
  HTML-part / plaintext-part source toggle (whichever exist).
- **CONTRACT GAP**: no IPC exposes raw RFC822 wire source (verbatim MIME
  headers + all parts). `kiwi_message_body` returns the parsed view only.
  The dialog states this explicitly; needs a backend `kiwi_message_source`
  (or a `raw` field on `MessageBodyView`) to complete — recommended for the
  backend queue, not stubbed UI-side.

### Verification

- `npm run build` (`tsc && vite build`) — green, 84 modules.

## T-294 — drag-drop + paste attachments in composer

**Mechanism (real, not mocked):** attachments ride inside the `kiwi_send_enqueue`
payload as `dataB64` (`commands/send/enqueue.rs` — `OutboundAttachment`,
`MAX_ATTACH_TOTAL = 25 MiB` total). No separate attach IPC exists and no
read-file IPC exists, so the Tauri path-drop event (`tauri://drag-drop`,
paths only) could not produce bytes. Set `dragDropEnabled: false` on the
window so OS drops reach the DOM as real `File` objects — `dataTransfer.files`
→ existing `addFiles` path → chips → send payload. Nothing else used the
Tauri drag events (verified: zero `tauri://drag` listeners in src/).

**Landed (views/compose.tsx, shell.css, tauri.conf.json):**
- Dropzone over the whole compose surface: `dragenter/over/leave/drop` with a
  depth counter (no flicker over children), gated on `types.includes("Files")`
  so text drags don't trigger. Veil: `.em-drop-veil` dashed-accent overlay,
  `Icon name="file"` + "Drop files to attach", `pointer-events:none` so the
  drop lands on the section.
- Chips render immediately as pending entries (object-identity updates);
  per-file progress is real — `FileReader.onprogress` fraction → "reading N%"
  until `dataB64` resolves. Read failure removes the chip + names the file.
  Size shown KB/MB, Remove unchanged, key now includes index (same name+size
  collision edge).
- 25 MiB cap enforced in `addFiles` before anything reaches the send IPC —
  matches backend `MAX_ATTACH_TOTAL` exactly; oversized files are named in
  the error ("…exceeds the 25 MiB per-message attachment cap — not attached").
- Paste: `onPaste` on the compose section → `clipboardData.files` → same
  path; real File objects, no fabricated paths. Text paste untouched
  (`files.length === 0` → no preventDefault).
- Send guard: pending attachments block `send()` with a clear error so an
  empty `dataB64` can never reach the IPC.

**Verification:** `tsc && vite build` green (84 modules). Static trace:
drop/paste/input all funnel to `addFiles` → `attachments` state → chip render
→ `send()` maps `{filename, contentType, dataB64}` into `kiwi_send_enqueue`.
No UI driver exists in-repo (no playwright/vitest); FileReader/DOM-drop path
is browser-verifiable in the vite dev server but was verified here by static
trace per house convention. Interim build break during this session was A25's
in-flight T-296 (`onScheduleSend` seam) — settled on their next save, final
build green.

## T-299 — right-click context menus (message list + folder tree)

**New `components/contextmenu.tsx`** — shared native-look menu: fixed at
cursor, viewport-clamped (layout-effect measure+flip), Esc / outside
pointerdown / window-blur dismiss, full keyboard nav (↑↓ cycle enabled
items, Enter select, → opens submenu, ← collapses, Home/End), one submenu
level anchored per-row (`aria-haspopup`/`aria-expanded` on parents),
`role=menu`/`menuitem`/`separator`, disabled items grayed with title
explaining why.

**Message-list menu (mailbox.tsx):** `RowShell` gained `onContextMenu`
(suppressed on buttons/inputs so native behavior survives there);
`openRowMenu` follows the eM idiom — right-clicking an unpicked row selects
it; a picked row keeps the whole selection as targets; thread rows pass
every member id. Entries vs real state:
- Reply / Reply All / Forward → compose route (same as reader r/a/f keys);
  disabled "Select a single message" on multi-select.
- Mark read/unread + star flip by envelope state on single; multi shows
  both directions with counts → `onToggleRead`/`onToggleStar`/`onBulkPatch`.
- Snooze ▸ Later today/Tomorrow/Next week → new `onSnooze(ids,preset)`
  (App `snoozeIds` groups refs per account → `kiwi_message_snooze`).
- Archive → `onArchive`/`onBulkPatch`. Move to ▸ — submenu from the real
  `props.folderLists[accountId]` (new prop), source folder excluded for
  single targets, disabled when mixed-account or no folders → new
  `onMoveToFolder` (App `moveToFolder` → `kiwi_move_messages` per
  source-folder group, 400-uid chunks, same-as-destination skipped).
- Mark as junk → `onBulkSpam` (kiwi_message_set_junk). Delete /
  Delete permanently → `onBulkDelete` (permanent in Trash, same as Del key).
- Demo: read/star/archive/delete/junk-disabled→honest titles; snooze/move
  disabled "Needs the Tauri backend".

**Folder-tree menu (chrome.tsx):** `FolderRow` + `FolderPane` gained
`onMarkAllRead` — account-section folders only (smart rows have no scope
key). Single item "Mark all as read (N)" — disabled when `unread===0` or
demo. No folder-scope command exists; App `markFolderRead` loops
`kiwi_update_message {seen:true}` over `listMessages` unread rows (500
bound, per-row failure tally, honest summary + reload).

**Verification:** `npm run build` (typecheck + vite) green, 86 modules.
Static trace to registered commands: update/snooze/move/delete/set_junk/
list_messages all in lib.rs. No UI driver in-repo — verified by trace +
build per convention. A25's T-296 (onScheduleSend) was already in HEAD
(3c29e3a) — no conflicts; one transient os-error-1224 file lock retried.

## T-301 — templates UI over the T-288 backend (ipc.md §6i)

**New `views/templates.tsx` — `TemplatesManager`** mounted at Settings →
Appearance → "Message templates" (replaced the localStorage `kiwi.templates`
name-only stub — it was placeholder cruft, removed cleanly with its
`savePref`/`schedulePush` deps):

- List: real `kiwi_templates_list` rows — name, subject, body preview,
  updated date; detected `{{name}}` placeholders rendered as code chips
  (display regex mirrors the §6i grammar — server stays authority).
- Editor: name ≤128B / subject ≤998B / bodyText ≤64KiB fields bounded to the
  contract caps; optional bodyHtml behind `<details>` (plaintext composer
  ignores it — stated inline).
- Preview: per-saved-row — detected placeholders get test-value inputs,
  "Render preview" → real `kiwi_templates_render(id, vars)` → rendered
  subject + body shown; `missingVars` chips surfaced verbatim ("stay
  verbatim + flagged on insert"). Preview only offered on saved rows — the
  contract renders by id.
- Create ("New template…" → `kiwi_templates_create`), Edit (full-replace
  `kiwi_templates_update`), Delete (inline confirm → `kiwi_templates_delete`).
- Empty state ("No templates yet — save one from the composer or create
  here"), loading note, error banner + Retry, demo → labeled note.

**Composer (views/compose.tsx):** the old `TEMPLATES` const + marker-insert
select replaced —
- Real picker `<select>`: lazy `kiwi_templates_list` on first focus, real
  names, "No saved templates" empty state; disabled+demo tooltip.
- Pick → `kiwi_templates_render(id, vars)` with honest caller vars
  (`from_name`, `from_email` from the selected account, `to` = first
  recipient, `date` = today ISO) → rendered subject applied when non-empty,
  rendered bodyText appended after a blank-line gap. `missingVars` →
  status note naming the unfilled `{{var}}`s (left verbatim per contract).
- "Save as template…" → inline name field → `kiwi_templates_create` with
  the current subject+body (empty fields omitted per §6i optionality);
  picker reloads lazily. "Manage…" → settings route.
- Errors → `kiwi-banner error`; insert/save notes → `em-note` status.

**Verification:** `npm run build` (typecheck + vite) green, 87 modules.
All five §6i commands registered in lib.rs:177-181; wrappers used verbatim.
No UI driver — static trace per convention. `kiwi.templates` localStorage
key no longer read/written (stub removed).

## T-303 — real pairing QR (§9d) over the T-269 canonical backend

**Discovery:** `pair_begin`/`pair_status` had zero callers — no pairing UI
existed; the only QR was a dead "QR placeholder" box in the LockOverlay.
Backend contract (`commands/pair.rs`): `pair_begin(deviceLabel)` returns
`{ticket, expiresUnix, qrPayload}` where `qrPayload` is the complete
`{"type":"kiwi-pairing",endpoint,desktopKey,ticket,…}` JSON the phone scans —
the renderer renders it verbatim, never constructs it. Lock matrix §9d.7:
unlocked ⇒ ordinary gate; locked ⇒ only while a backend-owned `pair_flow`
is live, else `IpcError("locked")`. `pair_status` never echoes the payload
(§9d.2 bearer-secret rule — nothing here logs/persists it).

**New `components/pair.tsx`:**
- `QrCanvas` — renders the payload via `encodeQrMatrix` imported from
  `mobile/src/qr/qrcode.ts` (the segno-verified T-194 encoder — single
  source of truth, not a copy; vite bundles it cross-package cleanly).
  Byte-mode EC-M, integer module scale, 4-module quiet zone, white canvas
  bg (theme-independent contrast), `role="img"` + honest aria-label;
  QrEncodeError surfaces verbatim.
- `PairQrFlow` — `pairBegin` on mount → QR + live expiry countdown +
  `pairStatus` poll (2.5s, read-only) → `claimed` (device label shown,
  onClaimed fires) / `expired` (real "New code" re-begin) / `unavailable`
  (`locked`→"can't pair while locked…", `pair-unavailable`→`code: msg`).
  Poll treats locked/unknown-ticket replies as expiry (flow died).

**Surfaces:**
- Settings → Identity → Devices: "Pair new device…" (disabled+demo title)
  → inline PairQrFlow; `claimed` → real `listDevices` refresh. Empty-state
  copy no longer claims "Phase 4 flow" vaporware.
- LockOverlay: placeholder box replaced — when `live && !deviceLabel`
  (paired devices approve over the channel; a QR adds nothing) PairQrFlow
  attempts begin and degrades honestly on the §9d.7 gate. New `live` prop
  wired in App.tsx (`!demo`).

**Verification:** `tsc && vite build` green (90 modules). Encoder evidence:
mobile's segno-vector suite — 11/14 pass incl. module-for-module JSON
vectors at EC-M (the pairing payload's exact shape); the 3 failures are
documented scope limits (payloads needing v>25 rejected by design per the
file header; one fixture where the encoder picks a tighter valid version
than the reference). Plus a byte-assert I ran against a §9d-shaped payload
(realistic ticket/key/endpoint JSON): deterministic matrix, correct
geometry/finder patterns, ~30% dark density. Throwaway test not retained.

## T-305 — repeatable UI smoke gate (scripts/ui-smoke.mjs, `npm run test:ui`)

**Harness** — `kiwi-app/scripts/ui-smoke.mjs`, zero new dependencies:
Node 25 built-in `fetch`/`WebSocket` speak raw CDP; spawns vite via the
local bin (`node node_modules/vite/bin/vite.js`, pinned `--host 127.0.0.1`
— plain `localhost` binds ::1 on Windows and the 127.0.0.1 probe missed it),
launches headless Edge/Chrome (`--remote-debugging-port=0`, port read from
`DevToolsActivePort`), attaches `Target.createTarget`+flatten, and asserts
against the real rendered DOM — no jsdom, no mocks. The app's own demo
mode supplies data (a plain browser is not a Tauri webview).

**Checks (10):** boot (.em-chrome+root), folders (nav.em-folders rows +
.em-tree-count chips), list (.em-rows/.em-row), select→reader card,
context menu (real contextmenu MouseEvent → .em-ctx[role=menu] 10 items,
Esc-on-element dismiss — the menu's React onKeyDown lives on the menu
root), compose (hash-route, recipients/body/account fields), settings
(all 8 tabs clicked, tabpanel h1 verified per section), theme (radiogroup
labels carry display names, not ids — clicked "…Dark", asserted
`data-theme=dark`, restored via the "· default" chip), ? overlay
(keydown ? on body bubbles to the window handler; Esc dispatched on the
dialog for its own onKeyDown), lock (overlay contract — absent when
unlocked; real locked-state assertion is live-backend-only and reported
honestly).

**Output:** PASS/FAIL/SKIP per check + `SMOKE_JSON{…}` line for CI;
exit 1 on any failure. `--url` attaches to an already-running server,
`--browser` picks edge|chrome|path, `--keep` leaves processes alive.

**Result:** 10/10 PASS on real Edge headless (~40s). Verified
`npm run build` still green (90 modules). package.json staged with ONLY
the `test:ui` script line — A25's in-flight vitest/testing-library dep
edits deliberately left unstaged (blob-staged via hash-object +
update-index since the diff shared a hunk).

## T-308 — device-management surface vs canonical §9d commands

**Contract audit result: the wire was already complete.** The flagged
"drift" was a stale file — `types.rs` had been split (T-181) and my first
read hit a dead flat file; `types/devices.rs` projects the full §9d.5
`PairDeviceView` (`fingerprint` dash-grouped, `keystoreRef`,
`revokedUnix`, `registeredUnix`, `lastSeenUnix`, `keyFingerprintTail`)
from `DeviceRow`. `kiwi.ts` `DeviceView` matches the wire exactly.
`api.listDevices` calls canonical `device_list`; `api.revokeDevice` calls
`device_revoke` (terminal + idempotent, audits on transition AND retry,
refreshes trust — commands/pair.rs:263).

**Surface fixes (settings.tsx Identity → Devices):**
- Rows now render EVERY real field: label + status pill (revoked styled
  differently w/ "terminal, cannot satisfy challenges" title), deviceId,
  algorithm, paired (registeredUnix) + last-seen + revoked dates,
  keystoreRef alias or "none", and the full dash-grouped `fingerprint`
  in <code> with a display-only title (§9d.5: never a trust input).
  `keyFingerprintTail` retained inside the row for the short form.
- **"this device"**: `loadDevices` now also fetches `securityStatus()` —
  its `deviceId` is THIS desktop's own device record id
  (`state.index.device_id`, state.rs:960). Matching row gets a
  "this device" badge.
- Empty state: "No paired devices." + the T-303 `PairQrFlow` entry
  (Pair new device… → claimed → real listDevices refresh).
- Revoke: inline Confirm/Keep → real `device_revoke` → `loadDevices()`
  + `onStatusChanged()` (trust refresh); revoked rows show the timestamp
  and the button disables with "Already revoked".

**Verification (live, real commands):** `cargo test -p kiwi-app pair::`
7/7 green — `device_list_ordering_fields_and_label_conflict`,
`revocation_survives_engine_reopen`, `pair_status_lifecycle`,
`pair_begin_fails_closed…`, `unlock_challenge_canonical_wire_while_locked`,
plus the §9d.7 locked-gate assertions for device_list/device_revoke.
These exercise the exact impls the UI calls (register→list→revoke→reopen
persistence). Renderer-side: the T-305 suite gained a `devices` check —
Identity tab mounts, "Pair new device…" present, demo-disabled, honest
empty state → 11/11 PASS on real Edge. `tsc && vite build` green (91
modules). Nothing fabricated: every rendered field is on the wire view.

Mid-session the settings.tsx edits were swept into commit 43b528a
("A24 → T-308") — final content verified in HEAD; this commit carries
the smoke-suite addition + this log.

## T-310 — reader quoted-text collapse + thread polish (presentation-only)

**Quote collapse (BodyPane, mailbox.tsx):**
- HTML path: post-mount DOM pass tags `data-kiwi-quote` on top-level quote
  containers (`blockquote`, `.gmail_quote`, `.moz-cite-prefix`,
  `[type="cite"]`) plus a preceding "On … wrote:" preamble element —
  `.em-quotes-collapsed` on the body hides them. The sanitize pipeline is
  untouched: this is an effect over `rendered.html` AFTER it mounts, with
  zero re-parsing authority. Conservative guards: nested quotes ride their
  ancestor; nothing collapses when the quote IS the whole body (no real
  content would remain).
- Text path: `splitQuotedText` collapses only when the marker is
  unambiguous — "On … wrote:" preamble followed by quote lines, or a `>`
  run (≥2 lines) that extends to EOM tolerating blanks + a trailing sig
  block. Interleaved quoting, quote-only bodies, single stray `>` lines,
  and bare preambles all stay fully visible.
- Toggle: "Show quoted text (N)" / "Hide" — per-message-open state
  (`useState` + reset on uid change), collapsed by default, no pref.

**In-reply-to jump:** `MessageEnvelope` now carries `messageId` /
`inReplyTo` / `references` (real `MessageView` fields mapped in
`toEnvelope`). Each card resolves `inReplyTo` (or last `references`) —
normalized, case-folded, `<>`-stripped — against loaded thread members and
renders "← In reply to {sender}" navigating to the parent's real route.
Nothing renders when unresolved — honest dormancy in demo (fixtures carry
no chain ids).

**Signature de-emphasis:** RFC 3676 `-- ` delimiter in the HEAD region only
renders inside a muted `.em-sig` span (text bodies). HTML sig heuristics
skipped — not cheap/reliable; noted, not faked.

**Fix-forward:** `ipc.ts` imported `SandboxSessionView` unused (A21's
T-300 seam) — removed the name from the import list only; the type still
backs `parseSandboxSessions` in kiwi.ts.

**Verification:** `tsc && vite build` green (91 modules); smoke suite
11/11 PASS on real Edge headless. `splitQuotedText` logic verified
directly on 8 cases (collapse: preamble+quotes, run-to-EOM, sig+quote;
refuse: interleaved, quote-only, stray `>`, bare preamble, plain).
Swept into `6ee4daf` mid-session — final content verified in HEAD.

## T-313 — quick-filter chips on the message list

**Chip bar** (`.em-filterbar`, mailbox.tsx) — client-side view filtering
over the already-fetched rows; zero new IPC:

- **Unread / Starred / Attachments** chips AND-combine, each with a live
  count scoped to the current tab's loaded set. **From sender** captures
  the selected row's From address when toggled (disabled with honest
  tooltip when no selection exists; title names the captured address).
- `filtered` memo sits between the category-tab filter and thread
  grouping — threading, range-select, select-all, keyboard nav, and
  "selected" fallback all operate on the narrowed set consistently.
- **Reset on folder switch** (chips + sender address cleared together);
  chips compose with search honestly by disappearing while `searching`
  (search drives its own result list — stacking the two would lie about
  scope).
- **Counts**: header reads "N of M filtered" while chips are active;
  a `role=status` span announces "N of M shown" for AT; chips are
  `aria-pressed` buttons inside a labelled `role=group`.
- **No-matches state** is distinct from empty-folder: "No matches —
  nothing passes the active filter chips" + a Clear filters button.

**Shortcut:** none added — chips are ordinary focusable buttons and `/`
already focuses search; inventing one would collide with the T-291 map.
Documented, not faked.

**Verification:** `tsc && vite build` green; the T-305 suite gained a
`quickfilter` check — flattens to list mode, asserts `.em-row` count
equals the Unread chip's declared count AND the status line reads
"N of M shown", sender chip narrows 1..total, Clear restores full rows +
empty status. **12/12 PASS** on real Edge headless.

## T-314 — smoke suite deepened to FLOW checks (+ real reply prefill landed)

**Feature discovery (filed-and-fixed, not faked):** the flow audit exposed
that "Reply" anywhere in the app — ctx menu, reader card, r/a/f keys,
toolbar — opened a BLANK composer; the old comment even admitted "compose
route owns prefill when it exists". Real implementation landed rather
than a faked test:

- `seedCompose(mode, m, body)` (exported from mailbox.tsx) writes a
  one-shot `kiwi.replySeed` to sessionStorage then navigates — same
  pattern as T-312's `kiwi.composeTo` handoff. Reply seeds `Re:` subject
  (no double-Re) + To=original sender; Reply-All adds cc = body's
  to/cc minus self minus sender (needs the loaded body — honest); Forward
  seeds `Fwd:` + quote with empty recipients.
- **Quote only when provable:** `> `-prefixed lines + "On … wrote:" attach
  ONLY when `body` belongs to that message (`m.id === selectedId` /
  card-gated `isSelected`) — a right-click on an unselected row seeds
  without a quote rather than fabricate one. Storage denied → composer
  opens blank.
- ComposeView consumes the seed post-draft-restore: recipients merge
  dedup'd, subject fills only if empty, quote appends below existing
  draft text — restored drafts never clobbered.
- Wired: ctx-menu ×3, card header + actions Reply, r/a/f keys, App
  toolbar Reply/ReplyAll/Forward.

**Suite:** `check()` gained a `kind` ("smoke"|"flow"); results + a
`flows` array both land in SMOKE_JSON. New flow checks (state-change
assertions, restore afterwards so the suite is order-independent):

- `rail` — agenda rail collapse→expand roundtrip via the real toggle.
- `ctxmark` — ctx-menu Mark read/unread flips `.em-row.is-unread`, then
  restores via the same menu.
- `reply-prefill` — row→Reply→compose: `Re:` subject + To chip asserted;
  quote honestly gated in demo (no message-body IPC) and said so in the
  detail string.
- `demo-send` — recipient commit via #compose-to+Add → Send → "Demo:
  sending" toast → Undo action → "back to draft" status. Honest demo
  path, no fake IPC.
- `pref-roundtrip` — dark theme → real `Page.reload` → still dark →
  restore light (localStorage roundtrip proven on real browser).
- `quickfilter` re-tagged as the flow it already was.
- `lock` stays a smoke check — demo cannot reach the locked overlay
  (documented honestly; positive render is live-only).

**Result:** 18/18 PASS (12 smoke + 6 flow) on real Edge headless, ~15s.
`tsc && vite build` green.

## T-317 — drag messages → folder tree (last un-wired mailbox interaction)

**Drag side** (mailbox.tsx): `RowShell` gains `dragIds`/`dragSubject` —
draggable rows write `application/x-kiwi-messages` JSON + `text/plain`
summary + `effectAllowed=move`. Pick-aware: a dragged row inside the
picked set drags the whole selection (threads resolve to member ids, or
the picked set when a member is picked).

**Drop side** (chrome.tsx): `FolderRow` accepts a `dropTarget` only on
real account folders — Favorites/smart rows (incl. Outbox) get NO handler,
so dropping there is impossible by construction (honest, not a fake deny).
`getData` is unreadable during dragover, so the source folder rides as a
`application/x-kiwi-src-*` TYPE token (lowercased — setData normalizes).
Same-folder hover → `dropEffect=none` + `em-drop-denied` +
`aria-dropeffect="none"`; valid target → `em-drop-target` + `move`.
Drop filters same-folder members (multi-source drags keep the movable
subset); all-local drops no-op silently.

**Drop → same move path:** `onDropMessages` resolves the composite
`accountId:folderId` → `moveToFolder` → the existing chunked
`kiwi_move_messages` loop (shared with ctx-menu Move-to, which stays the
keyboard fallback). Demo → honest "needs the Tauri backend" toast. Toast
now names the destination ("Moved N to X."). **No undo** — no real undo
IPC exists; not faked.

**Smoke `dragdrop` flow:** synthetic `DragEvent`+`DataTransfer` on real
DOM (Chromium resets `dropEffect` post-dispatch for synthetic events —
proven via probe; so assertions use the React-state affordance:
`em-drop-denied`/`em-drop-target` + `aria-dropeffect`). Verifies:
dragstart carries the payload+source token → same-folder hover denied →
different folder paints the move affordance → drop reaches the handler →
demo answers the honest toast. **20/20 PASS.**

**Mid-flight collisions:** A25's T-318 was landing in settings.tsx +
ui-smoke.mjs concurrently (transient tsc errors + a `mbox-io` check
appeared mid-run + one theme-check flake during their save). My staging
was hunk-scoped: `git apply --cached` of ONLY the dragdrop hunk —
mbox-io stays in the worktree for their own commit.
