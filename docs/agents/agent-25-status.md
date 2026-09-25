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
