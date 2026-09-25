# Agent 25 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-268: Icon set + theme packages + plugin scaffold (Item B)

**Status:** in-progress.

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
