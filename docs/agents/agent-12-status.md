# Agent 12 — Status Log (Muse Spark, frontend owner kiwi-app/src)

> Append dated entries. Owns kiwi-app/src exclusively.

## 2026-09-25 — T-190b Mailspring archaeology done; build green

- **Status:** T-190b done. Delivered `docs/ui-mailspring-map.md` (tokens,
  component inventory, animation catalog A1–A24, layout maps for shell/
  sidebar/thread-rows/reader/composer/prefs, interaction states, T-191
  worklist) + `kiwi-app/src/mailspring-tokens.css` (clean-room
  `--kiwi-ms-*` tokens: colors light+dark, type, spacing, radii, shadows,
  motion ladder, reduced-motion kill-switch). `npm run build` green
  (tsc strict + vite, 55 modules). `src-tauri/` untouched. No commits made.
- **Legal:** reference/mailspring is GPL-3.0 — STUDY ONLY. Surveyed via 3
  read-only subagents + lead pass; all values paraphrased observations with
  file:line provenance; zero Mailspring code copied into our tree.
- **Key findings for T-191:** (1) Wide thread rows = c1–c5 icon/star/
  participants-200px/subject-flex/date/hover-actions @36px, narrow stacked
  @85px under ~540px — our stacked cards must become this grid. (2) Motion
  ladder 30ms→10s (nav 125ms, hover 150ms, popover 240ms overshoot, modal
  100ms veil + 360ms rise/untilt, toast 150ms lift, undo ring 10s linear).
  (3) Mailspring has NO prefers-reduced-motion handling — our kill-switch
  must cover all new tokens. (4) Keep flagship deep-black dark default;
  adopt light direction + sidebar/list/reader tonal structure. (5) Composer
  = modal + popout + plugin slot (send-later/undo hook); prefs = 6 tabs
  (General/Accounts/Identity/Appearance/Shortcuts/Mail Rules).
- **Files changed (created, mine only):**
  - `docs/ui-mailspring-map.md` — new (map + catalog + worklist).
  - `kiwi-app/src/mailspring-tokens.css` — new (opt-in; not yet imported —
    T-191 wires it, flagship untouched).
- **Commands run:** `npm run build` in kiwi-app (green, 55 modules, no new
  deps); `orca terminal --help` probe (send next).
- **Assumptions/limits:** token file intentionally unimported until T-191
  rebuild (zero visual change this task); dark `ui-dark` green accent noted
  but NOT adopted (flagship brand wins); tracking/open-receipt colors mapped
  as deferred per owner privacy gate.
- **Needs:** Lead to queue T-191 rebuild (owns kiwi-app/src, ready).
- **Next:** T-191 Mailspring-faithful rebuild per the map (sidebar, thread
  rows w/ hover actions, reading pane, modal composer, tabbed prefs,
  animations; preserve all IPC) → T-192 security re-integration.

## 2026-09-25 — T-191 Mailspring-idiom rebuild done; build green, smoke-verified

- **Status:** T-191 done. `kiwi-app/src` rebuilt to the Mailspring idiom
  per `docs/ui-mailspring-map.md`. Reskin/layout only — zero backend/IPC
  changes (`src-tauri/` untouched; every `api.*` call site, prop, route,
  and handler preserved; verified via two read-only inventory subagents
  before editing). `npm run build` green (tsc strict + vite, 58 modules,
  no new deps, no warnings). Headless Edge smoke shots (mail / compose
  modal / settings tabs / security) all render correctly, no console-bare
  failures. No secrets; no remote fonts/assets (rg-verified).
- **Layout (req 1):** desktop MenuBar (File/Go/Help, all wired to existing
  routes/actions) + unified toolbar (Get/Write/search/palette/theme/
  TrustChip) in `chrome.tsx`; sidebar with Mailboxes tree, alt-filled inbox
  badges, collapsible Accounts with color bars; single-line thread rows
  (checkbox · star · participants · subject+snippet · short date · hover
  quick-actions Archive + two-step Delete) with 540px ResizeObserver narrow
  switch; reader with top action bar + SecurityPill retained; composer as a
  modal dialog (backdrop-click/Esc close, draft autosave makes Esc safe);
  prefs as 6 tabs (General/Accounts/Identity/Appearance/Shortcuts/Mail
  Rules with embedded live FiltersView) + arrow/Home/End tablist keys.
- **Animations (req 2):** `motion.css` implements the catalog on exact
  token timings — A1 sheet slide+fade 125ms, A2/A3 fades, A4 120–150ms
  button tints, A5 row 120ms, A6 actionbar drop 200ms, A8 reader ready
  100ms + thread-expand reveal, A9 hover reveals, A12 menu pop 240ms
  overshoot, A13 veil 100ms + dialog rise/untilt 360ms, A14 toast lift
  150ms, A16 disclosure 90ms, A17 switch 150ms, A18 spinner 1.1s, A19
  auto-hide scrollbars, A24 micro 50ms. Deferred honestly (no DOM hook):
  A7 swipe spring (phase 2), A11 composer wipe, A15 ring element (undo
  uses ttlMs timing), A20–A23 package loops. Reduced-motion kills all.
- **Preserved (req 3):** all `kiwi.ipc/1` bindings, selection/bulk/threading
  semantics, policy banner, SecurityPill/FindingDialog/LockOverlay/
  AuthenticatorDialog, Security Center, toasts, palette, contacts, filters,
  search, prefs sync wrappers, demo fallbacks.
- **Desktop feel (req 4):** Ctrl+N compose (typing-guarded), Ctrl+Enter send
  (pre-existing), F5 sync, `/` `?` Ctrl+K retained; menus instead of
  web-chrome. Native Tauri menus are `src-tauri/` (Agent 7's) — untouched.
- **Theme/CSP (req 5–6):** `mailspring-tokens.css` imported in `main.tsx`
  (+`shell.css`, `motion.css`); ms-dark re-anchored to flagship depth so
  the dark default stays flagship deep-black; strict CSP meta in
  `index.html` (self-only, no remote fonts/assets) present in dist.
- **Tests:** kiwi-app has no test runner (pre-existing — package.json has
  no `test` script); tsc-strict + vite build is the gate and is green.
- **Commits (reviewable stages):** `b344ba0` stage 1 (tokens/shell/motion/
  chrome/CSP/data-shell) + `f1b9073` stage 2 (App/mailbox/settings/
  shortcuts) by me; stage-3 polish (narrow RO, star reveal, expand anim)
  swept into Lead's `859a347` with my exact diff intact (verified).
- **Files changed (mine):** `main.tsx`, `index.html`, `prefs.ts`,
  `mailspring-tokens.css`, `shell.css` (new), `motion.css` (new),
  `components/chrome.tsx`, `App.tsx`, `views/mailbox.tsx`,
  `views/settings.tsx`, `components/shortcuts.tsx`. Compose untouched
  (modal is a wrapper in App).
- **Deviations/risks:** (1) Thread expand = fade+rise 100ms, not a
  measured-height tween (multi-row threads have no single wrapper —
  documented in motion.css). (2) Esc in composer inputs does NOT close the
  modal (autocomplete/textarea own it). (3) Row delete = direct backend
  call with inline two-step confirm (same honesty as BulkBar). (4) Light
  theme needs owner click-through (verified dark only headlessly).
- **Next:** T-192 security-surface re-integration in this idiom; owner
  visual review of the 4 smoke shots.

## 2026-09-25 — T-192 security surfaces in Mailspring idiom done; green

- **Status:** T-192 done. All five surfaces delivered as reskin-only
  changes (zero logic/IPC changes; `src-tauri/` untouched).
  `npm run build` green (tsc strict + vite, 58 modules, warning-free).
  Headless Edge smoke shots (mail, security) render clean. Committed as
  `6368739` (6 files, +232/−45, kiwi-app/src only).
- **(1) Header badge + popover:** `SecurityPill` gains the tighter
  `ms-secbadge` treatment (glyph + label kept, never color-only) in the
  reader header row; click now opens the finding detail as a light-dismiss
  right-side **popover** (`ms-finding-popover` + `ms-pop` 240ms overshoot,
  transparent veil) instead of a centered modal — full record, session
  line, signals, siblings, prev/next, Esc/focus all preserved.
- **(2) Composer strip:** `PolicyBanner` is now the slim `ms-policy-strip`
  above the subject (block/warn variants, offenders + Remove kept, A6 drop
  entry). Position above subject pre-existed; refusal still blocks send
  (`disabled when blocked`, fail-closed live banner) — compose logic
  untouched.
- **(3) Lock overlay:** full-app veil kept; approve panel is now
  `ms-approve-box` with **fingerprint badge** (`····tail`, new optional
  `fpTail` prop wired from App: demo `9F3A`, live device-id tail, hidden
  when unknown) + **"Approve on device"** copy including the honest
  cannot-approve-here line; Verify primary button.
- **(4) Security Center:** prefs-style window surface — findings as bordered
  rows with Details, `ms-filterbar`, caps-header `ms-table`, posture
  pointer note (devices/signals/org live in Settings → Identity, no data
  invented). Session drill-in stays modal (A13).
- **(5) Sidebar approvals:** `Sidebar` takes optional `pendingApprovals`;
  App passes 1 while a challenge dialog is `waiting` — Security nav shows
  a filled alt badge + pending-aware aria-label. Zero when idle (verified
  in shots).
- **Files:** `components/security.tsx`, `components/chrome.tsx`,
  `views/security-center.tsx`, `App.tsx` (2 prop wires), `shell.css`,
  `motion.css`.
- **Risks/notes:** popover verified statically (same content, new shell;
  no click-driver in this env — needs Tauri click-through); light theme
  still needs owner review (dark verified headlessly).
- **Next:** idle until review feedback / Lead queue.
