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
