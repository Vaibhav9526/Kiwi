# Agent 25 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-268: Icon set + theme packages + plugin scaffold (Item B)

**Status:** implementation complete; verification below.

### Delivered

- `src/components/icons/` — `icons.tsx` (registry: 53 glyphs, 16×16 grid,
  `currentColor` stroke, `fill` flag for solid glyphs), `Icon.tsx`
  (`<Icon name size label strokeWidth>`; decorative by default, `label`
  exposes `role="img"`), `icons.css`, `index.ts` barrel, `README.md`
  emoji→icon map. `SEVERITY_ICON` mirrors `severityGlyph`.
- `src/themes/` — `types.ts` (manifest `{id,name,version,vars}` +
  validation + `varsToCss`), `registry.ts` (stock + sideloaded packages,
  `localStorage["kiwi.themes.installed"]`, `<style data-kiwi-theme-pkg>`
  injection, stock-id collision refused), `useTheme.ts` (`useTheme()`,
  `DEFAULT_THEME="light"`, `data-theme` apply, legacy `kiwi-theme` event
  kept, `prefers-color-scheme` follow for `system`), `ThemePicker.tsx`
  (Appearance picker for Preferences), `stock/light|dark/{manifest.json,
  theme.css}` — light = eM-style neutral (white content, gray-blue panes,
  blue selection, orange primary) **now the default**; dark = flagship.
- `src/plugins/` — `manifest.ts` (`{id,version,permissions[]}` + 4
  capabilities: message-list-read, composer-action, settings-page,
  notify), `bridge.ts` (`plugin/1` postMessage envelope: req/res/evt,
  capability-gated methods, lock gate, 10s timeout, `PluginBridgeError`),
  `registry.ts` (sideload install/enable/disable/remove,
  `kiwi.plugins.v1`), `GETTING-STARTED.md`, `examples/hello/`.
- `motion.css` — theme-switch color/border cross-fade on chrome surfaces
  (panel cadence; in the reduced-motion kill list).
- `docs/THREAT-MODEL.md` — T-PLG attacker, B10 boundary, RR-11 accepted
  risk (trusted-code alpha, post-alpha hardening listed).

### Files changed (mine)

- New: `components/icons/{icons.tsx,Icon.tsx,icons.css,index.ts,README.md}`,
  `themes/{types,registry,useTheme}.ts`, `themes/ThemePicker.tsx`,
  `themes/index.ts`, `themes/stock/{light,dark}/{manifest.json,theme.css}`,
  `plugins/{manifest,bridge,registry,index}.ts`, `plugins/GETTING-STARTED.md`,
  `plugins/examples/hello/{manifest.json,plugin.js}`.
- Edited (shared/unclaimed, minimal): `main.tsx` (+`import "./themes"`),
  `motion.css` (theme transition block), `components/toasts.tsx`,
  `components/security.tsx`, `components/oauth2.tsx` (emoji→Icon),
  `components/icons.tsx` (A24's adapter: `./icons`→`./icons/index` fix —
  icons.tsx shadows icons/ in module resolution — plus `print`,
  `collapse-right`, `unreplied` registry entries so their stubs became
  `named()` delegates), `docs/TASKS.md`, `docs/THREAT-MODEL.md`,
  this file.
- NOT touched (A24/T-267): `App.tsx`, `views/*`, `chrome.tsx` content,
  `shell.css`, `prefs.ts` (A24 already flipped the fallback to light and
  left the custom-id passthrough seam).

### Seam notes for A24 (also sent in DONE report)

- `<Icon name>` / `IconXxx` adapters both live: `from "../components/icons"`
  = adapter (icons.tsx), `from ".../icons/index"` = registry — the file
  shadows the directory for bare `./icons` specifiers; use explicit
  `./icons/index` for the registry.
- Mount `<ThemePicker/>` (from `../themes`) in Settings → Appearance, or
  drive the section with `useTheme()`. settings.tsx:54/139 `loadPref(
  "kiwi.theme","dark")` fallbacks still say dark — should become `light`
  (or just consume `useTheme().theme`).
- App.tsx:169 `kiwi-theme` listener filters to light|dark|system —
  custom installed theme ids won't pass the filter (harmless for stock;
  `useTheme` accepts any registered id).
- Emoji still live in `views/*` — map per `components/icons/README.md`.

### Commands run

- `npx tsc` — **0 errors in T-268 files**; residual errors at report time
  are inside A24's in-flight T-267 files (`chrome.tsx:293` `onSubmitSearch`,
  `mailbox.tsx:709/714` `onPick` — undefined names mid-destructure; their
  `IconChevronRight` import landed during this pass).
- `npx vite build` — green (74 modules, 977ms).
- esbuild+node smoke (`artifacts/t268-smoke/`): manifest validation,
  capability gating, bridge envelope checks — **20/20 pass**.

### Assumptions / risks

- Light-default directive fully lands only once A24's `useTheme` adoption
  (or equivalent fallback edits) ships; prefs.ts fallback already light.
- Plugin registry/bridge are scaffold-only by design — no execution host
  until post-alpha (documented in RR-11, not a silent skip).
- Sideloaded `theme.css` is injected verbatim after the generated vars
  block — trusted-package alpha model (same posture as plugins).

### Scope (per planner ITEM B + Lead dispatch)

- `kiwi-app/src/components/icons/` — monochrome stroke SVG icon set (~16px,
  `currentColor`, inline React components, no icon-library dep, no remote
  assets) replacing every emoji/unicode glyph used as UI chrome. Emoji
  inventory + mapping documented in `components/icons/README.md`.
- `kiwi-app/src/themes/` — theme package format (`manifest.json`
  `{id,name,version,vars}` + `theme.css` overriding `mailspring-tokens.css`
  vars), stock `light` (**default** per owner directive, eM Client ref) +
  `dark` (flagship palette), `useTheme()` hook + `ThemePicker` for A24's
  Preferences, `data-theme` on root.
- `kiwi-app/src/plugins/` — sideload-only v1: manifest
  `{id,version,permissions[]}` parsing/validation, capability declaration
  registry, postMessage bridge contract stub. ALPHA MODEL: plugins run as
  trusted code; isolation enforcement deferred (owner amendment) — accepted
  risk recorded in `docs/THREAT-MODEL.md` (B10 / T-PLG / RR-11).
- `motion.css` — theme-switch transition only (scoped, reduced-motion-safe).

### Boundaries honored

- Owns: `src/components/icons/*`, `src/themes/*`, `src/plugins/*`,
  additive `--kiwi-ms-*`/`--kiwi-*` vars in `mailspring-tokens.css`,
  `motion.css` theme-transition block.
- A24 (T-267) owns `App.tsx`, `views/*`, `chrome.tsx`, `shell.css` —
  untouched. Integration seam delivered: `<Icon name/>`, `useTheme()`,
  `<ThemePicker/>`; emoji→icon map in `components/icons/README.md` for the
  view rebuild.
- Minimal shared-file edits: `prefs.ts` (default `dark`→`light` per
  directive), `main.tsx` (one `import "./themes"` line so stock theme
  packages + sideloaded-theme restore are live), emoji→`<Icon>` swaps in
  unclaimed `components/{toasts,security,oauth2}.tsx`.

### Emoji inventory (grep-verified, `kiwi-app/src`)

Visual glyph sites (emoji/dingbat/arrow-as-icon) found in: `App.tsx`,
`chrome.tsx`, `toasts.tsx`, `security.tsx`, `oauth2.tsx`, `palette.tsx`,
`mailbox.tsx`, `search.tsx`, `contacts.tsx`, `filters.tsx`,
`integrations.tsx`, `settings.tsx`, `setup.tsx`, `compose.tsx`,
`security-center.tsx`, `kiwi.ts` (`severityGlyph`). Glyphs used as literal
keyboard-hint text (`↑↓`, `→` in prose/strings) stay text — not icons.
Full per-site mapping in `src/components/icons/README.md`.

## 2026-09-25 — T-274: Reference plugin + capability-gate proof (bridge e2e)

**Status:** complete — gate proven executable, not just documented.

### Delivered

- `src/plugins/examples/notify-on-mail/` — working reference plugin:
  `manifest.json` declares `notify`; `plugin.js` listens for host
  `mail-changed` events via the injected `PluginClient` and calls
  `notify.show` with the event payload.
- `src/plugins/e2e/run.mjs` — scripted harness (`node src/plugins/e2e/run.mjs`
  from `kiwi-app/`). Bundles the real `src/plugins` modules in-memory via
  esbuild → data-URL import (no reimplementation, no temp files), stubs
  `window` as the host-side postMessage bus + in-memory `localStorage`, and
  drives the full path: disk manifest → `validatePluginManifest` →
  `installPlugin` → `getPlugin` → exec `plugin.js` via `new Function`
  (the documented trusted-code alpha loader) → `host.emit("mail-changed")`
  → plugin's `notify.show` request → capability gate → host handler.
- `GETTING-STARTED.md` — new "Alpha trust boundary" table (enforced vs.
  deferred controls), harness instructions, and an exact 9-item
  post-alpha hardening checklist (isolated context, origin pinning,
  MessageChannel binding, boundary re-check, CSP/assets, no ambient
  authority incl. `__TAURI__`, trust gate, lifecycle enforcement,
  audit logging).

### Assertions (21/21 pass)

- Manifest validates; declares exactly `notify`; install persists package.
- `mail-changed` event reached the plugin; `notify.show` arrived at the
  host handler carrying event data (`added=3, folder=Inbox`).
- `added=0` correctly ignored by the plugin.
- Rogue plugin (declared `message-list-read` only): `notify.show` →
  `capability-denied` and the handler was never invoked; its declared
  `messages.list` resolved through the same gate — selective grant proven
  both directions; `settings.registerPane` also denied;
  `messages.getEnvelope` (declared cap, no host handler) →
  `not-implemented`; `bogus.nope` → `unknown-method`.
- Lock gate: every request rejects `locked` while `isLocked()`.
- Foreign-plugin + malformed + non-object frames dropped silently (no
  response emitted); `isBridgeMessage` accepts/rejects correctly.
- Unanswered request rejects `timeout` (60ms test window).
- Manifest rejection cases: bad id, bad version, non-array permissions,
  unknown capability, `..` entry traversal, missing entry file, non-JSON
  text.

### Files changed (T-274)

- New: `plugins/examples/notify-on-mail/{manifest.json,plugin.js}`,
  `plugins/e2e/run.mjs`.
- Edited: `plugins/GETTING-STARTED.md`, this file.
- Zero production-code changes — the harness exercises the shipped modules
  as-is (stubbed DOM surface only).

### Notes

- Repo state on pickup: `tsc` fully green (A24's T-267 in-flight errors
  resolved); `components/icons.tsx` adapter was renamed to
  `shell-icons.tsx` — `./icons/index` specifiers still correct; the NOTE
  comment inside `shell-icons.tsx` references the old shadowing but is
  A24's file, left untouched.
- `notify.show` host handler in the harness is a recording stub — the
  production mapping to toasts is a host-side wiring task (UI owner).

## 2026-09-25 — T-275: T-268 seam landing (A24 files transferred)

**Status:** complete — seams landed + live-verified via CDP screenshots.

### Delivered

- `views/settings.tsx` — Appearance tab mounts `<ThemePicker/>` (replaces the
  hardcoded light/dark/system `<select>`); `themeDefault` state removed →
  `useTheme().theme` (hook persists the pref + applies `data-theme`); backend
  pull no longer re-reads the pref manually — `applyPrefsBag` now emits
  `kiwi-theme` so bag-carried theme ids (incl. custom) apply live.
- `App.tsx` — local `useState` theme + `kiwi-theme` listener + `light|dark|
  system` filter removed → `useTheme()`; `cycleTheme` uses `setTheme(next)`;
  TopBar's `theme`/`onTheme` props dropped.
- `components/chrome.tsx` — TopBar self-serves `useTheme()`; theme select now
  lists every registered package (System + stock + sideloaded) with resolved
  name, not a hardcoded trio.
- `prefs.ts` — `applyUiPrefs` no longer writes `data-theme` (themes module is
  the sole writer → uninstalled-id fallback can't be overwritten); keeps
  accent/density/shell attrs. `applyPrefsBag` dispatches `kiwi-theme` when the
  bag carries `kiwi.theme`.
- `views/integrations.tsx` — last rendered glyph (`▾`/`▸` disclosure) →
  `Icon chevron-down/chevron-right`. Residual inventory: all remaining emoji/
  arrows are comments, keyboard-hint text (`↑↓`, `→` in prose), or the
  documented `severityGlyph` text fallback — intentional, not chrome.

### Live verification (CDP, artifacts/t275/)

- Boot: `data-theme=light` (default landed) — `01-mail-light.png`.
- `kiwi-theme(dark)` event → `data-theme=dark` — `02-mail-dark.png`
  (flagship palette: deep black, amber accents, orange primary).
- Settings→Appearance: picker renders 3 radios (System + KIWI Light +
  KIWI Flagship Dark w/ swatches) — `03-settings-appearance.png`.
- Clicking "KIWI Dark" radio → `data-theme=dark` live —
  `04-settings-dark-picked.png`.
- Ghost theme id (`ghost-theme`) → resolves to `light` via registry
  fallback — installed-package ids verified end-to-end.
- Visual pass vs `docs/ui/reference-layout.png`: 4-pane boundaries
  (folders | list | reader | agenda), toolbar order (+New orange primary →
  Refresh → Reply/ReplyAll/Forward/Mark/Archive/Snooze/QuickActions/Delete
  w/ carets), list rows (avatar, sender, category pill, preview, date,
  badge), reader card (subject + security pills + To-line + body +
  actions), agenda rail (Add new task + date groups + checks/flags),
  bottom nav strip + status icons — all land. Deviations are spec-level
  (KIWI trust chip/demo pill/theme select in topbar; F2 Primary/Other
  tabs), not fidelity bugs.

### Commands run

- `npx tsc` — 0 errors repo-wide.
- `npx vite build` — green (381 kB bundle).
- `node src/plugins/e2e/run.mjs` — 21/21.
- headless-shell CDP drive (`artifacts/t275/shot.mjs`) — 4 screenshots +
  4 live attribute assertions, all pass.

### Notes

- A vite dev server was already live on :1420 (stale agent process) —
  reused for the visual pass; did not kill it.
- `shell-icons.tsx`'s stale "icons.tsx shadows icons/" NOTE comment left
  as-is in T-274; file is now transferred — comment corrected in T-275.

## 2026-09-25 — T-280: Host-side plugin surfaces (notify + settings-page)

**Status:** complete — capabilities now land on real app surfaces.

### Delivered

- `src/plugins/runtime.ts` — session supervisor (React-free, harness-
  exercisable): `startPluginSession` builds the capability-gated host +
  in-context client + runs the entry via `new Function` (documented
  trusted-code alpha loader); sessions self-register/dispose; `reconcile
  Plugins`, `stopAllPlugins`, `emitToPlugin`, `broadcastPluginEvent`;
  module pane store (`listPluginPanes`/`subscribePluginPanes`).
- Host sinks: `notify.show` → app toasts with `[plugin-id]` scope (kind
  validated against ToastKind set); `settings.registerPane` →
  `{paneId,title,icon?,html?}` record; `settings.renderPane` → pane body
  update; `settings.unregisterPane` → removal. Lock gate unchanged —
  rejects before handlers run.
- `src/plugins/hooks.ts` — `usePluginRuntime(notify, locked)` (mount-time
  reconcile + `kiwi-plugins-changed` re-reconcile + unmount teardown),
  `usePluginPanes` (useSyncExternalStore), `useInstalledPlugins`.
- `bridge.ts` — `settings.renderPane` added to the `settings-page`
  capability method set.
- `views/settings.tsx` — new **Plugins** tab: installed plugins with
  capabilities list, enable/disable, remove; registered panes render via
  `PluginPaneCard` (emits `pane.mount`/`pane.unmount`; body markup
  verbatim — documented trusted-code posture).
- `App.tsx` — `usePluginRuntime(notify, trust.locked)`; the T-271
  mail-changed debounce now also `broadcastPluginEvent("mail-changed",
  {added})`.
- `plugins/examples/settings-pane/` — second reference plugin:
  registers pane on `host.ready`, renders markup on `pane.mount`, fires
  a scoped `notify.show`.

### Verification

- `node src/plugins/e2e/run.mjs` — **30/30 pass** (9 new: pane install →
  session → registerPane lands store record → pane.mount → renderPane
  markup → scoped toast; denial without the cap; locked no-crash; dispose
  removes panes).
- `npx vite build` — green (409 kB).
- `npx tsc` — 0 errors in T-280 files; 2 residual errors in
  `src/views/rules.tsx` — an untracked file a concurrent agent is actively
  writing (union-narrowing on `RulePredicate` group nodes; foreign
  in-flight work, not T-280 scope — same posture as A24's earlier
  transient errors).

### Notes

- `message-list-read`/`composer-action` methods remain honestly
  `not-implemented` — host sinks for those mount points are future work.
- Plugin pane markup is rendered verbatim by design (alpha); CSP blocks
  inline script, markup/style unsanitized — recorded in GETTING-STARTED's
  trust-boundary list.
- A concurrent agent touched `App.tsx` (T-231 FTS wiring) during this
  task — my edits were additive only, no overlap.

## T-283 — Agenda rail real content (GTD + security summary)

### Files
- `src/components/chrome.tsx` — new `AgendaSecurity` prop type +
  `SecuritySummaryCard` mounted at the T-267 rail seam (above task groups,
  below Add-task); `AgendaRail` now takes `security?: AgendaSecurity`.
- `src/App.tsx` — rail prop wired: `trust`, `lockReason` (locked only),
  `findings.length`, `smartUnread["unread"]`, `flagged`/`unreplied` (demo
  only), `activeDevices` (live only), `demo`.
- `src/prefs.ts` — `kiwi.agenda` added to `PREF_KEYS` (backend sync push).
- `src/shell.css` — `.em-security-*` block (card, head, score, demo tag,
  lock reason, count rows, Security Center link).

### Data provenance (real only — no mocks)
- Verdict: `useSession()` trust → `severityLabel(trust.trust)` /
  "Locked" + `score/100` when non-null; lock reason shown while locked.
- Open findings = real `findings.length` (kiwi_security_findings live;
  DEMO_FINDINGS in demo — `demo` chip tags fixture-derived numbers).
- Unread = `smartUnread["unread"]` — real `unseen` sum from folder list.
- Flagged/Unreplied = shown **only in demo** (computed from DEMO_MESSAGES);
  live has no store-wide aggregate in `accounts.ts` (hardcoded 0) → row
  omitted, never presented as real.
- Active devices = `devices.filter(status==="active").length`, live only.
- **Noted gap:** pending sandbox-open sessions have no list IPC — row
  intentionally absent until a real source exists (commented at the seam).

### Tasks persistence (existing mechanism kept — documented choice)
- No tasks backend exists (`kiwi_tasks`/tasks IPC: not found). Tasks were
  already persisted via `loadPref/savePref` under `kiwi.agenda` —
  add/checkbox/flag/delete all flow through `setTasks` → `savePref` →
  localStorage source-of-truth offline; added to `PREF_KEYS` so the bag
  also backend-syncs. Date groups (No Date/Today/Tomorrow) preserved;
  `kiwi.rail` collapse pref unchanged; A24 layout contract intact.

### Verification
- `npx tsc` — 0 errors repo-wide (prior `rules.tsx` residuals resolved by
  their owner — T-281 landed concurrently; `RulesView` + `folderLists`
  settings changes preserved untouched).
- `npm run build` — green.
- `node src/plugins/e2e/run.mjs` — 30/30 (one transient 28/2 on a cold
  esbuild run; clean on re-runs).
- CDP screenshot pass (`artifacts/t283/`): card renders with severity
  icon + "Unknown/demo" verdict + 4 real rows; collapse hides rail;
  live DOM add-task → `kiwi.agenda` localStorage persistence proven
  end-to-end.

## T-287 — UI hardening sweep (error/empty/offline/keyboard/a11y)

### Audit result (what was already real)
- **Errors:** mailbox `messagesError`/`foldersError`/`bodyError`/`renderError`
  banners + plaintext fallback; quick-search `searchNote` banner; full search
  view error banner; compose `sendError`/`attachError` + toasts; sync fail →
  toast + status note; settings per-action `actionError` + `prefsSync` badge;
  security-center `role=alert`; contacts error banner; integrations banners.
- **Empty:** folder "Nothing here", search "No matches" (quick + full),
  contacts "No contacts", outbox "Outbox is empty", palette "No matching
  commands", reader "Select a message", rules/demo honest text.
- **Keyboard:** `?` overlay already real (T-153 `ShortcutsHelp`, keydown
  guard skips text fields, Esc closes) — verified live, not a lying hint.
- **Offline:** `isTauri()` gate → labeled demo mode; session catches IPC
  failures to defaults (accounts/devices empty, trust DEMO fallback) —
  no crash paths found.

### Landed fixes (the actual gaps)
- `components/chrome.tsx` `FolderPane` — new `foldersError` + `demo` props;
  in-pane recoverable error row (`role=alert`, was status-strip-only) and
  "No accounts yet → Add account" empty state. Rows kept OUTSIDE
  `role="tree"` (valid ARIA tree).
- `App.tsx` — wires `foldersError`/`demo` into `FolderPane`.
- `views/rules.tsx` — "No rules yet" upgraded to `kiwi-empty` idiom
  (filters icon + guidance text; create form is the action).
- `shell.css` — global `button/[role=button]/a/summary:focus-visible` 2px
  accent ring (UA default was intact; now on-theme in both themes);
  `.em-folders-error`/`.em-folders-empty` styles.

### Verification (CDP, `artifacts/t287/`)
- `?` key → overlay opens (15 rows), Esc closes; screenshot.
- Keyboard Tab → `.em-iconbtn` gets `outline: solid 2px rgb(47,111,214)`
  accent ring (`:focus-visible` rule live in stylesheet).
- `tsc` 0 errors repo-wide; `vite build` green (417 kB); plugin e2e 30/30
  (one 28/2 on a cold esbuild run — known timing flake, clean on re-run).
- Icon-button name audit: all icon-only buttons carry `aria-label` or
  `title` (accessible name verified, none added).
- Contrast: both stock themes re-verified rendering (T-275 CDP shots);
  new text uses existing `--kiwi-ms-*` tokens only.

## T-290 — KIWI High Contrast stock theme (third package; format dogfood)

### Files
- `src/themes/stock/high-contrast/manifest.json` + `theme.css` — new package.
- `src/themes/registry.ts` — 3-line stock registration (manifest + css +
  STOCK_THEMES entry). Picker/topbar/select pick it up automatically.
- `src/plugins/runtime.ts` — bugfix found by this task's live pass:
  `listPluginPanes()` returned a fresh array per call →
  `useSyncExternalStore` never saw a stable snapshot → SettingsView
  crashed with "Maximum update depth exceeded". Now `panesChanged()`
  rebuilds a cached `paneSnapshot`; `listPluginPanes` returns the stable
  ref (all mutations already funnel through `panesChanged`).

### Palette (WCAG-AA+, single hc-light variant — verified computationally)
- Text `#000`/white = 21:1; secondary 12.6:1; muted 8.45:1.
- Accent/link `#0b4db3` = 7.7:1; primary `#b34700` + white label = 5.5:1
  (keeps the orange identity, darkened to pass).
- Selection: tint `#c2d9f9` w/ black text 14.6:1 + accent border 7.7:1;
  solid selection = accent-active + white 10.1:1.
- Borders `#595959` = 7.0:1; divider `#6e6e6e` = 4.16:1 (fixed after an
  initial 2.82:1 fail on `#8a8a8a`).
- Status colors darkened to ≥5.5:1 on white and their tint bgs; focus
  glow 50% accent + the T-287 2px focus-visible ring both ≥3:1.
- 22 key pairs scripted-verified, all PASS (WCAG rel-luminance, min 4.5
  text / 3.0 UI).
- Legacy `--kiwi-*` tokens overridden too (pre-token surfaces theme along).

### Verification (CDP, `artifacts/t290/`)
- Picker lists "KIWI High Contrast v1.0.0" (registry auto-pickup proven —
  the format genuinely supports a third theme).
- Label click → `data-theme=high-contrast` + `kiwi.theme` pref set;
  computed vars confirmed applied in-page; **persisted across reload**.
- Screenshots: picker row + mail view in HC.
- `tsc` 0 errors; `vite build` green; plugin e2e 30/30.

### Regression note
- The Settings crash found here was a T-280 latent defect (uncached
  external-store snapshot), not a T-290 regression — fixed in runtime.ts,
  Settings renders 8 tabs again.

## T-293 — Resizable panes (eM-style splitters)

### Files
- `src/state/panes.ts` — `usePaneWidth(prefKey, fallback, min, max)`:
  clamped state, `kiwi.pane.*` pref persistence (save on change, load on
  mount), `reset()`.
- `src/components/chrome.tsx` — `PaneSplitter` (role=separator,
  aria-orientation=vertical, valuemin/max/now, tabIndex, pointer-capture
  drag, ±10/±25 arrow keys, Home/End, Enter/dbl-click reset, `invert` for
  the right-edge rail) + AppShell wires folders + rail splitters.
- `src/views/mailbox.tsx` — list-column splitter between list/reader.
- `src/shell.css` — `.em-main`/`.em-mailbox` grids gain 5px splitter
  columns; widths via `clamp(min, var(--kiwi-pane-*), max)`;
  `.em-splitter` hairline→accent-on-hover/drag/focus; `.em-rail-wrap`;
  splitter hidden while rail collapsed (`:has(.em-rail-collapsed)`).
- `src/prefs.ts` — `kiwi.pane.folders|list|rail` in PREF_KEYS.

### Constraints
- Folders 180–400 (def 216), list 280–600 (def 320; unset = 26% fluid as
  before), rail 180–480 (def 232). Double clamp: JS on set/load + CSS
  `clamp()` so a bad stored value can't break the grid.
- Reader flexes (`minmax(0,1fr)`) — it never gets a splitter; it reflows.

### CDP verification (artifacts/t293/) — real pointer drags
- 3 separators present; folders +80 → 296 (pref `296`); list −60 → 280
  (min-clamped from 260); rail left-drag −60 → 292 (invert correct).
- Keyboard: → +10, Shift+→ +25 (331 total); End→400 max, Home→180 min,
  Enter→216 reset; double-click→216.
- Reload → stored widths applied (216/280/292 after resets).
- Screenshots show no layout breakage; list stays usable at 280px floor.
- `tsc` 0 errors; `vite build` green; plugin e2e 30/30.

## T-296 — Real outbox / scheduled-send view

### Files
- `src/views/mailbox.tsx` — `OutboxList` rebuilt: per-item state chip
  derived from real `OutboxItem` fields (Undo-window / Scheduled /
  Sending now / Retry-attempt-N / Sending-attempt-N), relative send time
  ("in 12m", absolute in title), undo countdown, and actions:
  Undo send (cancelSend), Send now (scheduleSend → now), Reschedule…
  (inline datetime-local picker → scheduleSend). Empty state reworded to
  "No scheduled sends". Helpers `relSendIn` + `outboxState`.
- `src/App.tsx` — `refreshOutbox` hoisted above the mail-changed effect
  and added to the existing 300ms debounce (queue transitions refresh the
  badge + view live); new `doScheduleSend` handler (toast + refresh);
  `onScheduleSend` prop wired into MailboxView.
- `src/shell.css` — `.em-outbox-head`/`em-outbox-state` state chips
  (accent for undo/scheduled, warning for sending/retry), actions row,
  inline picker styling.

### Contract gap (filed honestly)
`OutboxItem` has NO state enum / `lastError` / hold reason — a held queue
row is only inferable as `attempts>0 && notBefore` pushed forward. The UI
labels that "Retry — attempt N" without claiming a failure cause. Needs a
backend `state`+`lastError` pair to show real held/failed rows.

### Verify
- `tsc` 0 errors repo-wide; `vite build` green.
- CDP (`artifacts/t296/`): `#/mail/outbox` → "Outbox (0)" header,
  "Send all now" (aria-labeled), "No scheduled sends" empty state,
  state-chip CSS resolves (accent border, pill), 4-col grid intact.
- Live queue cards need the Tauri backend (demo mode has no queue); the
  card path compiles and mounts via the same props as the verified list.

## T-297 — No-mock UI audit → docs/audits/ui-honesty-1.md

### Method
Scripted CDP click-census (`artifacts/t297/audit.mjs`, `audit2.mjs`):
21 route passes + all 8 Settings tabs, ~1,100 control clicks. Effect =
nav | toast | DOM mutation | checked/aria flip | input focus.
Destructive/dialog-confirm controls verified by handler binding instead.
v1 census had mass false positives (React re-renders detach
earlier-enumerated nodes) — v2 re-queries each control by CSS path.
Console errors across the whole sweep: 0.

### Findings
- **1 dead control (fixed):** Quick Actions main button was
  `onClick={() => undefined}` — `ToolBtn` gained `menuOnMain` (main click
  toggles menu, `aria-haspopup/expanded`). CDP-verified.
- **0 unlabeled mocks.** Demo data is globally chip-labeled + per-action
  "Demo mode — needs the Tauri backend" toasts; agenda demo rows tagged.
- **4 labeled gaps filed:** raw-RFC822 source IPC (T-295/A19), pairing QR
  placeholder, OutboxItem state/lastError (T-298/A20), plugin
  message-list-read/composer-action (documented not-implemented).
- Context menu landed mid-audit (A24): right-click → 10 real items,
  demo-gated items honestly titled; transient tsc errors resolved when
  their App.tsx callsite landed. Verified post-settle.

### Gotcha worth noting for future audits
`#/rules`, `#/integrations`, `#/security-center` are NOT routes — the
router falls back to mail. Real routes: mail/compose/setup/settings/
security/search/contacts/filters; rules+integrations+plugins are
Settings tabs.

### Verify
`tsc` 0 errors repo-wide (post-A24 settle); `vite build` green;
plugin e2e not rerun (no plugin-surface changes).

## T-302 — plugin capability hosts (message-list-read + composer-action) — done
- runtime.ts: `messages.list`/`messages.getEnvelope` sinks behind `message-list-read`,
  projecting ONLY whitelisted envelope fields (id/from/subject/date/unread/starred/
  hasAttachments/category/trust/answered) — new envelope fields can't leak by default;
  no body, snippet, recipients, or evidence hints. Lock gate + cap gate enforced
  host-side before the sink runs.
- runtime.ts: composer-action store (`register/unregister/list/subscribe`,
  cached snapshot à la panes) + `fireComposerAction` evt; dispose cleans the
  plugin's actions. ComposeView renders the registered buttons (icon validated
  via isIconName → fallback puzzle) and posts `{actionId, subject, to[], cc[]}` —
  no body bytes.
- App.tsx feeds `listSnapshot` = the live `visibleMessages` (post-filter/override)
  via a ref, so plugin reads see exactly what the user sees.
- e2e run.mjs: +17 assertions → 47/47 — grant path (snapshot rows, whitelist,
  getEnvelope hit/miss, register→fire→plugin-acted, unregister, dispose cleanup)
  AND denial path (both caps absent → capability-denied, no action record).
- GETTING-STARTED cap→sink table updated; '30 assertions' → 47.
- FINDING (honest): live in-app plugin exec is CSP-blocked — index.html has
  `script-src 'self'` (no unsafe-eval) so `new Function` is refused; plugin
  sessions run only in the harness today. Documented in GETTING-STARTED
  'Post-alpha hardening' — deliberately NOT relaxed (B2 CSP backstop);
  live exec arrives with the sandboxed-context task (RR-11).
- tsc 0 errors repo-wide, vite green, e2e 47/47.
## T-306 — CSP-safe worker plugin loader — done
- NEW `src/plugins/worker.ts`: `buildPluginWorkerScript` = prelude + entry
  source concatenated into one blob-Worker script (no eval anywhere — the
  plugin source IS the worker script). Prelude = env-agnostic port shim
  (browser `self` ↔ node `parentPort`) + a self-contained `kiwi` client for
  the `plugin/1` envelope (req/res/evt, id match, 10s timeout, dispose).
  `spawnBlobWorker` default factory (blob URL + revoke-on-alive + terminate).
- `runtime.ts`: `startPluginSession` spawns the worker FIRST (spawn failure =
  honest "plugin failed to load" toast, no zombie), host rides a dedicated
  per-session port (`listenOn` = worker, `target` = worker postMessage
  adapter — plugin traffic off the broadcast window bus). Worker `error` →
  notify + dispose; `messageerror` → notify. `spawnWorker` sink seam lets
  the harness inject node:worker_threads. `PluginSession.client` → `worker`.
- `bridge.ts`: `PluginHostOptions.listenOn` (default window) + postMessage
  calls dropped `"*"` → 1-arg (Window defaults targetOrigin "/" — tighter).
- CSP delta (minimal, documented): `worker-src 'self' blob:` added to
  index.html meta + src-tauri/tauri.conf.json. `script-src` still 'self'
  only — NO unsafe-eval. Blob workers inherit document CSP → plugin fetch
  is clamped by connect-src (free exfil mitigation).
- e2e: harness runs sessions in real node worker_threads via spawnWorker —
  same prelude+entry artifact. +1 assertion: plugin-side globalThis write
  does not leak to host. 48/48 ×2 stable. Unregister test now routes the
  request from inside the worker via a test evt (client lives in-worker).
- LIVE PROOF (the point of the task): `vite build` → `vite preview` :4173 →
  CDP: installed shipped examples/hello → reload → `[hello] Hello plugin
  loaded.` toast rendered under production CSP; `__kiwiLiveLeak` undefined
  on page globalThis; 0 exceptions. artifacts/t306/{live.mjs,live.png}.
- Docs: GETTING-STARTED trust-boundary table rewritten (worker context +
  dedicated channel now ENFORCED; ambient-authority list corrected — DOM/
  localStorage/cookies/__TAURI__ genuinely gone, fetch CSP-clamped);
  hardening items 1+3 marked done; THREAT-MODEL B10/RR-11 updated with the
  CSP delta + residual risks (shared process, no origin pinning, unsigned).
- tsc 0 errors repo-wide; vite build green; plugin e2e 48/48.


## T-307 — plugin install UX (done)

- **Settings → Plugins "Install plugin…"** button → hidden `webkitdirectory`
  input; `installPluginFiles` reads every picked file as text, strips the
  top-level dir via `webkitRelativePath`, caps at 64 files / 512KB each, then
  calls registry `installPlugin(manifestText, files)` (settings.tsx).
- **Honest errors** — `.kiwi-banner.error` surfaces: missing root
  `manifest.json`, invalid JSON, unknown capabilities (with the known list),
  oversize/overflow files, read failures. Verified live for all three classes.
- **Live FileList bug caught + fixed**: `input.value=""` ran BEFORE reading
  the (live) FileList → installs silently no-op'd for real users too. Now
  `Array.from(files)` snapshots before clearing — found via the CDP demo,
  would have shipped broken otherwise.
- **List refresh** rides the existing `kiwi-plugins-changed` → installed rows
  re-render with declared-capability badges (`.ms-badge` per permission,
  "no capabilities declared" when empty).
- **Live install demo** (`artifacts/t307/install.mjs` + plugins-tab.png):
  `vite preview` :4173 + CDP. CDP can't populate `webkitdirectory` inputs
  headless, so files were injected via `DataTransfer` carrying the REAL
  on-disk bytes — the production handler path ran unmodified:
  notify-on-mail installed → row + `notify` badge → worker target spawned
  (running under prod CSP) → hello installed → `[hello] Hello plugin
  loaded.` toast → disable killed its worker (2→1) → re-enable respawned
  (1→2) → Remove deleted the row.
- e2e flake hardened: notify.show assertion now polls the toast itself
  (plugin awaits renderPane THEN notify — trails one round-trip). 48/48 ×4.
- tsc 0 errors repo-wide (foreign mid-flight errors settled); vite green.
- Docs: GETTING-STARTED lifecycle section now documents the install UX.

## T-312 — contacts depth + agenda sandbox row (done)

- **Audit of existing surface**: detail/edit already real (T-173 view +
  T-231 IPC): click → detail card (org/title, labeled emails+phones, tag
  pills, notes) → Edit form → api.updateContact; Delete → confirm →
  api.deleteContact. Full IPC CRUD exists — NO gap to file.
- **Added depth (live-verified):**
  - Server-side search in live mode — debounced `kiwi_search_contacts`
    (250ms); the loaded list caps at 500 so a real book needs it. Failure
    → error banner + client-filter fallback (stated, not silent). Demo
    keeps the client filter only. Selection resolves across serverHits so
    a hit outside the first-500 still opens its detail card.
  - "Write" → compose handoff: per-email `Write` button + action-row
    primary (disabled w/ reason when no address). sessionStorage
    `kiwi.composeTo` one-shot → ComposeView seeds the recipient chip AFTER
    draft restore (merge, never clobber). Live-proven: click → #/compose →
    `To: alice@example.test` chip, key consumed.
- **T-300 landed → wired the stub**: `api.sandboxSessions()` joins
  loadSecurity's Promise.all → `sandboxOpens` count → Agenda security card
  "Sandbox opens" row (shield icon). Honest semantics: T-300 sessions are
  always `completed` (no live guest exists), so the row is opens-count,
  not "pending". null/absent in demo — verified absent.
- Verify: tsc 0 errors; vite green; ui-smoke 12/12; e2e untouched 48/48.
  Live exercise of the sandbox row needs the Tauri backend (no demo
  fixture by design) — same posture as findings/devices rows.
- artifacts/t312/{verify.mjs,contacts-detail.png,mail-rail.png}

## T-315 — About settings tab (done)

- New SECTIONS entry "About" → `{section === "About"}` panel:
  - **Version**: `src/version.ts` reads tauri.conf.json `version` (fallback
    package.json) — build-manifest source, never a literal that drifts.
  - **Diagnostics `dl`** — real sources only: app version, accounts
    (live IPC count; demo counts DEMO_ACCOUNTS — the fixture source the
    sidebar actually renders, caught a "0 (demo fixtures)" lie in review),
    plugins installed (real registry), then live-only appInfo rows:
    backend version + IPC contract, sessions observed, deviceId, org.
    Profile-dir/store-size honestly omitted (no IPC exposes them) — the
    panel SAYS so rather than estimate.
  - **Keymap panel**: renders the shared `SHORTCUT_ROWS` (same const the
    `?` overlay + Shortcuts tab use — one source, no drift).
  - **License**: MPL-2.0 per repo LICENSE + contributors line.
- `dl` semantics (dt/dd grid) per the a11y ask; tab rides the existing
  roving-tabindex tablist.
- Smoke: new `about` check (version regex, dl, shortcut table, license,
  backend-row absence asserted in demo); settings-tabs now counts 9.
  ui-smoke 13/13; tsc clean; vite green.
- artifacts/t315/about.png — verified live in built app.

## T-318 — mbox import/export UI seam (done)

- Contracts: both rows landed in `docs/contracts/ipc.md` §6j —
  `kiwi_import_mbox(accountId, path, folder?)` → `MboxImportView` (T-309)
  and `kiwi_mailbox_export_mbox(folderId, destPath)` → `MboxExportView`
  (T-316). Wired verbatim; nothing stubbed.
- `src/kiwi.ts` `MboxExportView` + `src/ipc.ts` `api.mailboxExportMbox`
  added (import wrapper pre-existed). Tauri arg convention matches the
  other folderId commands.
- **Import** — Settings→Accounts, per-account "Import .mbox…" expands an
  inline form: path input (typed-path idiom — no dialog plugin in this
  shell; same as attachment download), optional target folder (empty =
  local `Import`), busy "Importing…", result card renders counts VERBATIM
  (imported/messagesFound, duplicates, expunged, failed, ruleFailures,
  truncated, first-5 issues + "+N more"). Client rejects non-.mbox
  extension + empty path before the IPC; backend errors land in the
  section action-error banner.
- **Export** — two entry points, both call `api.mailboxExportMbox`:
  (a) Settings→Accounts "Export folder" card: folder select built from
      real `folderLists` (per-account optgroup-style labels, `(empty)`/
      `(N)` exists-count in the label), dest-path input (.mbox auto-
      appended AND echoed back in the result so the shown path is the
      real one), busy state, result banner shows exported/skipped/bytes/
      truncated/partial + "folder was empty" when 0/0.
  (b) Folder ctx-menu "Export to mbox…" (download icon) on account rows
      only — smart rows never open the menu — → modal (ms-composer-modal
      reuse): dest input + error banner + busy; success → notify toast
      with verbatim counts. Composite `accountId:folderId` key parsed to
      the numeric folderId; non-real ids toast an error.
- **Honest states**: demo → import buttons disabled (title explains),
  export card + ctx item disabled with "needs the backend" reason; live
  no-accounts → explicit "add one first" note; empty folder list → "sync
  first" hint; `exists===0` folders labeled `(empty)` in the select.
- **Audit view**: none exists — `securityEvents` is transport sessions,
  `audit.jsonl` has no renderer IPC. Both actions ARE audited backend-side
  (`mbox-imported`/`mbox-exported`, ids+counts only) per §6j; nothing to
  surface them in yet — documented, not faked.
- Smoke: new `mbox-io` check (export card renders, demo gate text, ctx
  item present + disabled-with-reason in demo). ui-smoke **20/20**;
  tsc 0 errors; vite green.
- artifacts/t318/{shot.mjs,settings-accounts.png,folder-ctx.png}

## T-323 — app-audit log view surface (done)

- Contract: filed `kiwi_audit_events(before_unix?, limit)` in ipc.md §8 as a
  PROPOSED/backend-pending row (T-324, A15). Shape consumed by the UI:
  newest-first `{event, atUnix, actor, subjectId?, detailJson?}` — ids and
  counts only (paths/subjects/bodies never enter the audit channel).
- `kiwi.ts` `AuditEventView` + `ipc.ts` `api.auditEvents(beforeUnix?, limit)`.
- Home: Security Center → new "App audit log" section below the transport
  events table, with an explicit "this is what the app DID, not what the
  wire showed" distinction. No tabs existed; a section is the honest fit.
- States: `pending` (BackendUnavailableError / unknown-command → banner
  saying the read IPC is queued and recording already happens), `error`
  (real failure + Retry), `ready` (table), loading, and a true "No audit
  events recorded yet" empty state. Demo → pending banner, NEVER fixtures.
- Table: Time (locale) · event `code` · actor · subjectId · Detail toggle →
  detailJson pretty-printed in `kiwi-evidence` pre (parse fallback = raw).
  200-row pages, "Load older" keyset-paginates on last atUnix, Refresh
  replaces + resets the done flag.
- Copy: "Copy JSON" / "Copy CSV" write the LOADED rows to the clipboard via
  navigator.clipboard (real rows only — no "download full log" fake; the
  toolbar states that explicitly).
- Auto-lights: nothing is mocked — when T-324 registers the command the same
  code path renders real rows (the pending state only triggers on
  unavailable/unknown-command errors).
- Verify: tsc 0 errors; vite green; ui-smoke **22/22** — new `audit-log`
  check asserts heading + pending banner + zero fabricated rows.
- artifacts/t323/probe.mjs

## T-333 — storage stats/compact + notification pref (done)

- **Storage (T-330 landed: both commands registered).** ipc.md §8 had no
  rows yet — filed them as-built: `kiwi_storage_stats() → StorageStatsView`
  ({dbBytes|null, messageCount, folderCount, attachmentBytes|null,
  auditCount, schemaVersion, integrityCheck}) and `kiwi_storage_compact() →
  StorageCompactView` ({beforeDbBytes|null, afterDbBytes|null}; refuses
  `sync-in-flight` w/ retry hint; audited `-requested` BEFORE VACUUM then
  `-compacted`). `kiwi.ts` types + `ipc.ts` wrappers added.
- **About → new "Storage" section** (below Diagnostics): dl of real
  measurements — db size humanized (fmtBytes, binary units) + raw bytes,
  messages, folders, attachment payload bytes (annotated: persisted tree
  only), audit records, schema version. `null` renders "unmeasurable" —
  never an estimate. `integrityCheck` shows SQLite's own verdict; non-"ok"
  renders a danger pill with the verbatim text.
- **Compact flow:** "Compact database…" → warn-banner confirm (explains the
  write pause + sync-in-flight refusal + audit tags) → `api.storageCompact()`
  → honest `before → after` note + stats re-fetch; `sync-in-flight`/other
  errors land verbatim in an error banner. Demo → the whole section shows
  "need the backend", no fabricated numbers.
- The stale Diagnostics omit-note was updated — it claimed "store size
  omitted, no IPC exposes it"; now only profile-dir remains omitted.
- **Notifications (T-329 landed):** pref is `kiwi.notify` ("on"/"off",
  global scope, audited `pref-notify-set` — ipc.md prefs table). The
  Settings→General "OS notifications" select was already bound to it and
  already round-trips via `collectPrefs`/`applyPrefsBag` → `kiwi_prefs_set`.
  Added the honest demo note: no OS-notification channel in this build, but
  the pref saves and the desktop app honors it. Suppression semantics
  (muted accounts, junk/spam/trash folders, 60s rate limit) are backend —
  the footnote already states them.
- Verify: tsc 0 errors; vite green; ui-smoke **23/23** — `about` extended
  (storage heading + demo no-backend gate + no fabricated integrity), new
  `notify-pref` check (select present + demo no-channel note).

## T-338 — audit-integrity strip indicator + corrupt surface (done)

- **T-331 landed ahead of me:** `kiwi_audit_integrity() → {state, auditOk}`
  probe (ipc.md §8, contract row committed), `auditOk` on
  `SecurityStatusView`, `toTrustState` normalizes non-boolean → null,
  `ipc.ts` wrapper degrades malformed payloads honestly, security-center
  corrupt banner + row-withholding + `audit-corrupt` IpcError path, plus a
  6-test vitest file. My job was the strip polish + closing the "unchecked"
  honesty hole.
- **Strip indicator is now a real tri-state** (`TrustChip`): `false` →
  danger pill "Audit: unverified" (persistent, → Security view, title =
  AUDIT_CORRUPT_MESSAGE); `true` → quiet `secure` pill "Audit: verified"
  (a real backend claim, not assumed); `null`/absent → neutral `unknown`
  pill "Audit: unchecked" (title "Audit log integrity not yet verified").
  Previously null/true rendered NOTHING — silence was indistinguishable
  from verified. Value is backend-owned only: `kiwi_security_status.auditOk`
  via `toTrustState`; no localStorage, no renderer guess.
- **Demo note (corrects the brief's assumption):** demo has NO backend and
  no audit.jsonl — "verified ok" would be a fabricated claim. The strip
  therefore reads **unchecked** in demo; `verified` can only appear on a
  real `kiwi_security_status` verdict. Smoke asserts exactly this.
- **Security Center audit section:** corrupt banner unchanged (persistent,
  role=alert, rows withheld) — plus a "Re-check" button that re-runs the
  probe and reloads rows if the chain now verifies (real re-verification,
  not a dismiss). Added verdict line for the readable states: "verified"
  when ok, "could not be verified — rows shown are unverified" when the
  probe reports unknown while rows rendered.
- Updated `audit-integrity.test.tsx` — the two tests that pinned silence
  now pin the neutral/green pills (unchecked = never `secure`/`danger`
  class; verified = `secure`, `data-audit-integrity="ok"`).
- Verify: tsc 0 errors; vitest audit-integrity 6/6; vite green;
  ui-smoke **25/25** — new `audit-strip` check asserts demo chip is
  `unchecked`, carries no verdict class, honest title.

## T-342 — UI pass#2: disposable-inbox sidebar promo + density + radius tokens (in progress)

**Status:** in-progress — resumed 2026-09-26 after overnight Orca restart.
Prior session already landed (uncommitted): `src/state/tempmail.ts`
(shared `useTempMail` — one hook instance drilled to sidebar/view/
management card), `src/views/disposable.tsx` (inbox-style list+reader
view), `src/router.ts` (`disposable` route), `chrome.tsx`
`FolderRow.onOpen` seam.

**Plan (planner pass#2 spec):**
- Sidebar promo: "Disposable Inbox" section under the mailboxes (icon +
  unread badge → `#/disposable`; "+ New disposable" quick-action;
  demo-gated honestly). Integrations keeps the management card only.
- Radius: global `--kiwi-radius-*` scale (sm 6 / md 8 / card 12 /
  large 16 / pill / circle) in `theme.css`; `--kiwi-ms-radius-*`
  re-based onto it (owner directive supersedes the sharper observed
  Mailspring values); literal sweep in theme/shell css.
  A24's `.em-dock` already awaits `var(--kiwi-radius-large, 16px)` —
  resolves 16px with `lg` deliberately undefined.
- Density: sidebar gains a populated section; remaining bare-text empty
  state (palette) upgraded to the kiwi-empty idiom; agenda/richer rows
  verified already shipped (T-283/T-287).

**Files (mine):** `state/tempmail.ts`, `views/disposable.tsx`,
`router.ts`, `theme.css`, `mailspring-tokens.css`, `views/integrations.tsx`,
`views/integrations.test.tsx`, `components/palette.tsx`, this file.
**Shared, additive hunks only:** `chrome.tsx` (my section + onOpen;
A24's requestCompose hunks foreign), `App.tsx` (useTempMail + route +
prop drill; A24 dock + A20 quit-modal foreign), `shell.css` (my
dispo/radius styles; A24 `.em-dock-*` foreign), `settings.tsx` (one
temp-prop hunk; A20 trayClose foreign), `scripts/ui-smoke.mjs` (one
additive check; A26 browser-gate foreign).

**DONE 2026-09-26 — T-342 complete.** Evidence:

- **Sidebar promo:** `.em-dispo` section under the mailbox tree — clock-icon
  "Disposable Inbox" `FolderRow` (new `onOpen` seam overrides the default
  folder navigation) with real `temp.unread` badge, plus a `+ New`
  quick-action that mints an address via the shared hook then lands on
  `#/disposable`. Demo-gated: disabled with an honest title, never
  fabricates a session or count.
- **First-class view:** `views/disposable.tsx` (`#/disposable`) — notice
  verbatim BEFORE controls, demo explanation, honest no-mailbox empty
  state, address card + lifecycle buttons, 45s-polled list | reader
  split, sanitized-inert html, `≈`-labeled provider age-out ESTIMATE.
- **Shared state:** App owns the single `useTempMail(!demo && !locked)`
  instance → FolderPane prop + DisposableInboxView + SettingsView →
  TempMailPanel. Panel is management-only now (lifecycle + "Open
  Disposable Inbox" + unread count; message list deleted).
- **Radius tokens:** `theme.css` `--kiwi-radius-{sm,md,card,large,lg,pill,
  circle}` scale (lg kept as alias for A24's committed dock var refs);
  `--kiwi-ms-radius-*` re-based onto it in `mailspring-tokens.css`;
  literal-radius sweep across theme.css + shell.css (incl. the committed
  `.em-dock-chip` 8px literal → `--kiwi-radius-md`).
- **Density:** last bare-text empty state (palette "No matching
  commands.") → `.kiwi-palette-empty` icon+muted idiom; all other empty
  states already `kiwi-empty`-illustrated (verified in audit).
- **Smoke:** new `disposable` check — sidebar section+row, route lands,
  notice verbatim, demo `+New`/create disabled, zero fabricated rows.
- **Verify:** `npx tsc --noEmit` 0 errors; `npm run build` green;
  `vitest run integrations.test.tsx` 15/15 (3 T-342 tests incl.
  real-hook notice round-trip + click-inert reader + management-only
  contract); `ui-smoke.mjs` **27/27 pass, 0 fail, 0 skip** (Edge).
- **Foreign gates noted:** `cargo fmt --check` diff = foreign UNTRACKED
  `kiwi-mail/src/parts.rs` (untouched); `cargo clippy --workspace
  --all-targets` finished with ONE warning, `too_many_arguments` at
  foreign in-flight `kiwi-mail/src/sync.rs:362` (+165-line foreign hunk,
  not mine — left for its owner).
- **Commit hygiene:** whole-file adds only for files whose diff is 100%
  mine; `git apply --cached` filtered patches for mixed files — App.tsx
  (kept 5 T-342 hunks, dropped A20's quit-modal/tray-listener hunks),
  settings.tsx (kept temp prop/import/call, dropped A20 trayClose),
  ui-smoke.mjs (kept only the `disposable` check; A26's browser-gate +
  other agents' checks foreign), TASKS.md (only the T-342 row flip).
- **Assumption:** `.em-dispo-*`/`.kiwi-dispo-*` styles + `kiwi-toolbar-gap`
  landed inside A24's committed T-343 sweep (ee543ef) — they stay, no
  rework needed; my remaining shell.css delta is token swaps + the
  palette-empty block.
- **Risk:** live-mode `+ New`/lifecycle exercised only via unit tests
  (demo smoke asserts gating); provider flows need a live backend run.

## UI-sweep — global bug sweep (in progress, Planner dispatch 2026-09-26d)

**Status:** in-progress — claimed before editing. Lead saturated; dispatched by Planner.

**Scope:** click through EVERY view — mail, compose dock, contacts,
settings (all tabs), disposable inbox, security center, integrations,
rules, filters, templates — capture alignment/overflow/dead-controls/
missing-labels-or-icons/contrast/broken-empty-states, write findings
here FIRST, then fix top-severity. Frontend CSS/TSX only — no backend.
Gate: kiwi-app tsc clean.

**Method:** CDP sweep script (`kiwi-app/scripts/ui-sweep.mjs`, sibling of
ui-smoke.mjs) drives Edge over every route + every settings tab +
palette/shortcuts/dock overlays; per view collects console errors,
horizontal-overflow offenders, unnamed interactive controls, zero-size
widgets, computed-style contrast misses, and a screenshot into
artifacts/ui-sweep/. Screenshots eyeballed before fixing.

**File claims:** TBD after findings land — will list each file before
editing. Likely candidates: shell.css / theme.css / offending views.
Foreign in-flight noted: A24 T-357/358/359 (compose/nav/mailbox ports),
A20 T-348 blocklist UI, Lead T-350-352 dev-unlock/tray seams — my fixes
must not sweep those hunks.

**Findings:** (populated after the sweep run)

**Findings (sweep run, Edge 1440×900, artifacts/ui-sweep/ 25 shots + sweep-report.json):**

VERIFIED defects (screenshot or DOM-evidenced):
- **S1. setup.tsx — missing spaces in hero copy** (visible: "Get startedwith us", "security.Complete these steps") — JSX text-collapse bugs on the first-run screen. HIGH (user-facing copy).
- **S2. Compose `section` overflows 14px horizontally** (scrollWidth>clientWidth, no scroll allowed) — inner row pokes past the modal. MED.
- **S3. Enabled toolbar labels at 3.07:1** (`.em-tool-label` rgb(138,145,156) — Reply/Forward/etc. confirmed NOT inside disabled buttons after the disabled-aware audit) — fails WCAG AA on the main action bar. HIGH.
- **S4. `--em-text-faint` (≈2.6:1) used on content text** — "(4 of 5)" count, agenda times, menu hints/section heads, demo microcopy. Decorative-use token on informative text. HIGH.
- **S5. `.em-row-acct` account badge orange ≈1.94:1** — worst measured contrast in the app. HIGH.
- **S6. Link/action blue ≈3.3–4.1:1** (`.em-linkbtn`, `.em-add-task`, `.em-fmt` on light) — under AA. MED.
- **S7. `--em-text-dim` ≈4.08:1 on snippets/dates** — marginal fail. MED.
- **S8. Warn text ≈4.48:1** (`9a6206` on warn bg: security Warning pill, disposable PUBLIC notice, backend-unavailable banner) — marginal. LOW-MED.
- **S9. Settings h2/h3 group labels ≈4.48:1** (`6a7280`) — marginal. LOW.
- **S10. Contacts detail pane empty state is bare text** ("Select a contact — or create one.") — inconsistent with the kiwi-empty idiom. LOW.
- **S11. Bare-text empties** — settings-general "No accounts yet." + settings-plugins "No plugins installed." — LOW.

FALSE POSITIVES (audit artifact, verified via screenshot):
- setup hero white-on-white: hero is a gradient/photo panel — background-image not visible to computed-background walks. Text is legible.
- settings-appearance "14 unnamed inputs": label-wrapped radios — named correctly.
- ctx "Snooze" 3.18:1 — disabled item (demo); exempt.
- compose `#compose-body` unnamed: resolved — label-wrapped.

NOT EXERCISED: compose dock (nav-away doesn't dock — needs the minimize control; dock smoke path is T-343's check), live mode (demo only in browser).

**Fix plan (top severity):** S1 setup copy; S3 toolbar label token; S4 text-faint usages that carry information → --em-text-dim; S5 account badge → darker ink or tinted-pill treatment; S6 link blue → existing darker --em-link; S7 dim token nudge; S8/S9 marginal nudges; S10 contacts empty state; S2 compose overflow if the offender is identifiable.

**Correction (evidence-first):** S1 setup "missing spaces" = FALSE POSITIVE — `<br/>` renders correctly (verified in setup.png); textContent concatenation artifact. S3 toolbar labels = FALSE POSITIVE — live probe confirms labels sit inside `button[disabled]` (disabled styling via `--kiwi-text-disabled`, WCAG-exempt). S10 contacts empty pane = FALSE POSITIVE — already a `.kiwi-empty` w/ icon (contacts.tsx:691). S2 compose overflow = benign negative-margin bleed by design (`em-compose-fields` edge-bleed inside padded modal; no visual clip) — will harden with `overflow-x: clip` to prevent horizontal scrollbar.

**File claims (A25 sweep fixes — staged surgically, foreign hunks excluded):**
- `kiwi-app/src/shell.css` — token bumps at `[data-shell=mailspring]` light+dark blocks (~1132/1170); warning-text swaps at `.ms-policy-strip.warn`, `.em-outbox-*`, `.em-security-demo`; `.ms-composer-modal` overflow-x.
- `kiwi-app/src/views/mailbox.tsx` — `.em-row-acct` inline style (acct hue kept on border, text darkened toward theme text via color-mix).
- `kiwi-app/src/themes/stock/light/theme.css` + `light-orange/theme.css` — `--kiwi-warning` → darker (4.47→~5.4).
- `kiwi-app/scripts/ui-sweep.mjs` — audit hardening (`.is-disabled`, `[aria-disabled]`, label-wrapped controls, gradient-bg awareness).
- `kiwi-app/scripts/ui-probe.mjs` — NEW tiny CDP probe helper (kept: fleet can reuse for DOM forensics).

NOT fixing (recorded for Planner): settings bare `<small>` empties (honest inline hints inside cards — idiom would be overkill); dark-theme cat-pill/link palette (audit ran light only — separate dark sweep warranted); compose dock interaction untested via nav-away (dock needs minimize control — covered by T-343 smoke).

**FIXES LANDED (worktree):**
- `shell.css` `[data-shell=mailspring]` light: `--em-text-dim` #69707c→#5a616e, `--em-text-faint` #98a0ab→#667080, `--em-group-head` #6a7280→#5a6470, `--em-link` #3b82c4→#3370b8, `--em-cat-news`→#2e68a8, `--em-cat-personal`→#9a5b00, `--em-cat-logs`→#27712b; dark: `--em-text-faint` #5e5c72→#84829a (was ~2.9:1 on dark pane).
- `shell.css`: `--kiwi-ms-warning` (fill/status orange) no longer used as TEXT — `.ms-policy-strip.warn`, `.em-outbox-sending/.em-outbox-retry`, `.em-security-demo` now use `--kiwi-warning` ink (border keeps the status hue). `.em-iconbtn.is-active` blends link 78% toward ink (clears AA on select tint). `.ms-composer-modal` gets `overflow-x: clip` (negative-margin field bleed can't summon h-scrollbar).
- `mailbox.tsx` `.em-row-acct`: avatar tint stays on border; label text = `color-mix(tint 55%, --kiwi-ms-text)` — theme-adaptive AA.
- `light/theme.css` + `light/manifest.json`: `--kiwi-ms-text-muted` #7d8794→#6b7480, `--kiwi-warning` #9a6206→#8a5605; `light-orange/theme.css`: same warning fix; `mailspring-tokens.css`: base muted #8a94a0→#6b7480, dark muted #5e5c72→#84829a.
- `compose.tsx`: `overflowX: "clip"` on compose section.
- `ui-sweep.mjs` hardened: disabled-context skip (`[disabled]`/`aria-disabled`/`.is-disabled`/`:disabled` ancestors), gradient-bg skip (counted, not flagged), `overflow-x:clip` exempt in overflow audit. NEW `ui-probe.mjs` — minimal CDP eval helper.

**RE-SWEEP (post-fix):** 25 stops — all clean EXCEPT: settings-general/plugins bare `<small>` "No accounts yet."/"No plugins installed." (ACCEPTED — inline card hints, kiwi-empty idiom would be overkill) and `section.ms-pref-section` 18px x-overflow on Shortcuts/About (FOREIGN — `src/ms/ms-preferences.css` in-flight, unstyled child ~18px; cosmetic, overflow:hidden clips; owner=A24's port).

**FOREIGN RESOLVED MID-SWEEP:** search view giant-ellipse/squeeze = `section.em-search` colliding with header `.em-search` pill styles — fixed in worktree by foreign rename to `em-search-view` (search.tsx + shell.css:3796); verified clean in re-run.

**GATES:** `npx vite build` ✓ · `ui-smoke.mjs` 27/27 PASS ✓ · `npx tsc --noEmit`: **0 errors in all touched/shipped files**; workspace-wide tsc RED on foreign in-flight `src/ms/{drop-zone,outline-view,outline-view-item}.tsx` — comment blocks contain literal `data-*/` sequences that early-terminate `/* */` comments (72 parse errors). NOT mine — owner is the Mailspring-port author (A24 T-35x); flagged for Lead.

**SURGICAL STAGE — FINAL STATE:** committed hunks = shell.css (7 sweep hunks only — composer's `overflow-x:clip`, 3× `--kiwi-warning` text swaps, light-token bumps, cat-pill fg tuning, `.em-iconbtn.is-active` blend, dark faint bump), compose.tsx (`overflowX:"clip"` only), mailspring-tokens.css (2 muted bumps), light/light-orange theme warning+dark-muted, light manifest muted bump, `ui-sweep.mjs` + `ui-probe.mjs` (new tooling), this status file.
- `mailbox.tsx` NOT committed: mid-sweep T-335 refactor relocated `.em-row-acct` into untracked `src/ms/ms-thread-row.tsx` — my color-mix badge fix was carried into that file intact (comment `A25 UI-sweep` preserved @117-125); owner lands it.
- Foreign preserved in worktree: mailbox.tsx T-335 rewrite, A24 `src/ms/*` port (still churning — untracked), ms-pref-section overflow, all `src-tauri/*`.

**GATES (final):** `ui-smoke` 27/27 PASS · `vite build` ✓ · `tsc --noEmit`: **0 errors outside foreign `src/ms/`** — red remainder = ms-mail-important-icon, ms-thread-list-columns, ms-thread-list-participants, tokenizing-text-field (active port churn; signature shifted from earlier parse errors → owner still mid-landing). Gate satisfied for A25 scope: my files typecheck clean.
