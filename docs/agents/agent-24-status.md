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
