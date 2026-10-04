# Liquid Glass window-transparency system (KIWI)

How the frosted-glass window works: a transparent Tauri window with DWM
materials, plus a theme that gets out of the way so the OS backdrop shows
through. Reference doc — see files cited inline.

Evidence: `kiwi-app/src-tauri/tauri.conf.json`,
`kiwi-app/src/components/window-controls.tsx`,
`kiwi-app/src/themes/stock/liquid-glass/theme.css`,
`kiwi-app/src/themes/stock/liquid-glass/manifest.json`,
`kiwi-app/src-tauri/capabilities/default.json`,
`kiwi-app/src-tauri/src/lib.rs:59-62`. Commits `9a6e442`, `564e7a1`,
`a5fd763`, `dadcf77`.

### Files involved

| File | Role |
|---|---|
| `kiwi-app/src-tauri/tauri.conf.json` | Window recipe: transparency + DWM material preference order. |
| `kiwi-app/src/components/window-controls.tsx` | Custom min / max-restore / close cluster (`dadcf77`); renders only under Tauri (`isTauri()` gate). |
| `kiwi-app/src/themes/stock/liquid-glass/theme.css` | Scoped glass paint: root transparency, alpha grading, blur, veils. |
| `kiwi-app/src/themes/stock/liquid-glass/manifest.json` | Token mirror of `theme.css` for the theme registry. |
| `kiwi-app/src-tauri/capabilities/default.json` | Grants `allow-minimize / allow-toggle-maximize / allow-is-maximized / allow-close` so the cluster's window commands pass the ACL. |
| `kiwi-app/src-tauri/src/lib.rs:59-62` | Documents why no `DWMWA_WINDOW_CORNER_PREFERENCE` unsafe hack is used. |

### Commit history

| Commit | Change |
|---|---|
| `9a6e442` | Adds the Liquid Glass stock theme (translucent fills, blur/saturate, specular edges, iOS blue accent). |
| `564e7a1` | Makes translucency real: `transparent:true` + `windowEffects`, root transparency, alpha cuts, titlebar merge, manifest regen. |
| `a5fd763` | `state: active` → `followsWindowActiveState` so unfocused windows keep MicaAlt instead of raw transparency. |
| `dadcf77` | `decorations:false` + custom caption controls; preserves drag / dbl-click / resize / tray-close. |

## 1. Window layer (`tauri.conf.json`)

`app.windows[0]` (`label: "main"`) is the only glass surface. Current config:

| Field | Value | What it does on Windows |
|---|---|---|
| `transparent: true` | `true` | Webview starts with an alpha channel; without it DWM materials are painted over by an opaque client area and CSS `backdrop-filter` has nothing to sample (root cause fixed in `564e7a1`). |
| `decorations: false` | `false` (added `dadcf77`) | OS draws no native caption strip above the client area. The app's own `.em-titlebar` (with `data-tauri-drag-region`) **is** the titlebar, so glass runs unbroken from the top edge down. Requires the custom caption cluster in `src/components/window-controls.tsx`. |
| `titleBarStyle: "Overlay"` | `"Overlay"` | Keeps overlay titlebar semantics (content flows under the caption area) alongside the hidden title. Pre-dates glass; retained. |
| `hiddenTitle: true` | `true` | Hides the native title text — the DOM titlebar supplies its own labels/controls. |
| `windowEffects.effects` | `["mica", "acrylic", "blur"]` | Ordered preference list, **fallback-ordered** (per `564e7a1` message): Tauri tries mica first, then acrylic, then plain blur. First available material wins. |
| `windowEffects.state` | `"followsWindowActiveState"` (fixed `a5fd763`) | Applies Mica while focused and MicaAlt while unfocused, so the frosted blur survives de-focus. The prior `state: "active"` dropped to raw transparency when unfocused. |

Why `transparent + decorations: false` is the working recipe: `transparent`
hands DWM a composited alpha surface to tint/blur, and `decorations: false`
removes the opaque native frame that would otherwise cap that surface with a
dark bar above the theme's own chrome (`dadcf77`). Either half alone fails —
opaque window = milky flat fills; decorated window = glass body under a
non-glass strip.

Custom caption cluster (`window-controls.tsx`, `dadcf77`): three Win11-styled
buttons (46px wide, full row height, square corners) with neutral
`color-mix` hover wash and danger-red close. The cluster opts out of dragging
via `data-tauri-drag-region="false"`, syncs the maximize glyph through
`onResized` (covers Win+Up, snap, taskbar), no-ops outside Tauri (vite dev),
and never calls `exit()` — `close()` emits `CloseRequested` so tray logic
still decides hide-vs-quit. Required ACL grants live in
`capabilities/default.json` (see files table).

## 2. Theme layer (`src/themes/stock/liquid-glass/`)

Added in `9a6e442`, made truly translucent in `564e7a1`. Everything is scoped
to `[data-theme="liquid-glass"]` — other themes paint their own opaque
`--kiwi-ms-bg` and are pixel-identical.

| Concern | Mechanism (`theme.css`) |
|---|---|
| Root transparency | `html`, `body`, `#root` → `background: transparent`. `#root` adds one ~0.10–0.16 pastel mesh tint (radial/linear gradients, `fixed` attachment) so the OS backdrop tints without double-compositing. |
| Surface alpha grading | Structural panes (sidebar, list, reader, rail, toolbars) `rgba(255,255,255,0.26–0.42)`; center well `.em-main` only `0.06`; floating overlays/menus/modals up to `0.52`. Low alphas let mica/acrylic read through; the old 0.62–0.75 fills read as milky lavender. |
| Frosting | Structural surfaces `backdrop-filter: blur(36px) saturate(200%)`; overlays/menus/modals `blur(40px) saturate(200%)`; veils/backdrops `blur(8–30px)`. The deep blur + saturation is what turns low-alpha fills into glass. |
| Specular edges | `inset 0 1px 0 rgba(255,255,255,0.55–0.6)` top highlight on panes, cards, controls; white hairline borders `rgba(255,255,255,0.42–0.55)`; soft blue-tinted shadows `rgba(31,38,135,0.07–0.2)`. |
| Readability veils | `0.35` white floor in two places: titlebar chips (`.em-iconbtn`, `.em-theme-label`, `.em-demo-pill`) and `::before` pseudo-layers under pure-text regions (`.kiwi-rendered-body`, `.em-card-body`) — `pointer-events: none`, content kept at `z-index: 1`. Preserves `#1d1d1f` ink over arbitrary wallpapers. |
| Titlebar merge | `.em-titlebar`/`.em-toolbar` drop plate fill, `border-bottom`, and shadow under this scope only — titlebar → toolbar → body is one continuous sheet. Drag region and caption buttons are DOM attributes, untouched. |
| `manifest.json` | Mirrors all CSS tokens (126 vars: `--accent`, `--kiwi-ms-*`, `--kiwi-*`, `--em-*`) so the theme registry resolves identical values in opaque contexts. Regenerated 1:1 in `564e7a1` (117/117 at the time, zero drift). |

## 3. Platform behavior + fallbacks

| Platform / condition | Rendered result |
|---|---|
| Windows 11, DWM composition on | Mica (or MicaAlt when unfocused) sampled through the transparent window, then CSS `backdrop-filter` + low-alpha fills refract it. Full Liquid Glass look. |
| Windows 11, mica unavailable | Next entry in `effects` wins: acrylic, else window `blur`. Still frosted, different noise/tint characteristics. |
| Windows 10 / no mica-acrylic | Falls through to `blur`, then plain transparency: CSS glass over whatever is behind the window, no DWM material tint. Usable, flatter. |
| Other OSes (Linux/macOS builds) | `windowEffects` DWM materials are Windows-only; the window stays transparent and CSS blur/alpha still applies. No crash — just less depth than Win11 mica. |
| Windows Settings → Transparency effects OFF | OS-level kill switch: DWM drops backdrop materials to opaque. App has no override (no app-side setting found); CSS translucency then composites over an opaque window, so glass degrades to pale fills until the user re-enables it. |

Mica vs acrylic (documented distinction): mica samples the **desktop
wallpaper only** (static, cheap, theme-aware); acrylic samples **live windows
behind** the client area (dynamic blur, costlier). Ordering mica first keeps
the common case cheap and stable; acrylic covers machines where mica is
absent but live blur still works.

## 4. Adding a new glass-capable theme

1. Scaffold `src/themes/stock/<id>/theme.css` + `manifest.json`; register in `src/themes/registry.ts` (pattern from `9a6e442`).
2. Root transparency: `[data-theme="<id>"] html/body/#root { background: transparent; }` plus at most a faint tint on `#root` — never an opaque `body`.
3. Alpha surfaces: keep structural fills `0.10–0.45` white (or dark equivalent), overlays slightly higher; add `backdrop-filter: blur(32–40px) saturate(180–200%)` on panes/cards/overlays.
4. Specular + legibility: white inset top highlight + hairline borders; add `0.30–0.35` veils/chips under body copy and titlebar controls.
5. `manifest.json`: mirror every token value 1:1 (no drift); keep accent/focus/severity tokens opaque so buttons, rings, and banners survive translucency.
6. Verify: opaque themes unchanged, unfocused window still frosted, text legible over light and dark wallpapers.

## 5. Known limitations

- **No programmatic DWM corner control.** `lib.rs:59-62` notes the crate forbids `unsafe`, so no `DWMWA_WINDOW_CORNER_PREFERENCE` hack. Rounded corners + frame shadow come free from DWM while decorated/overlay-styled; an undecorated window takes whatever the compositor gives.
- **Mica ≠ live blur.** Mica reflects wallpaper only — moving windows behind KIWI will not shimmer through on mica; only acrylic (fallback) does that.
- **`radius` is macOS-only.** No effect on Windows; corner geometry on Win11 is DWM-owned (see above).
- **Transparency toggle lives with the OS.** Disabling Windows transparency effects flattens glass app-wide; KIWI cannot force materials back on.
- **Titlebar behaviors preserved by construction (`dadcf77`).** Drag stays on `.em-titlebar` (cluster opts out via `data-tauri-drag-region="false"`); double-click maximize is tao's `drag.js` mapping (no duplicate handler); edge/corner resize is tao's `WM_NCHITTEST` path (`resizable` stays on); close-to-tray still emits `CloseRequested` → `tray::handle_window_event` → `kiwi.trayOnClose` (never `exit()`). Capabilities `allow-minimize / allow-toggle-maximize / allow-is-maximized / allow-close` are required because `core:window:default` omits mutating commands.
- **Opaque themes share the transparent window.** The window-level recipe is global, so a non-glass theme must keep painting opaque fills to look unchanged. Glass opt-in is purely the theme's choice to go transparent — nothing in `tauri.conf.json` is per-theme.
- **Dev-browser preview differs.** Outside Tauri there is no DWM backdrop and `WindowControls` renders nothing; expect flat pale fills in `vite dev`, full glass only in the desktop build.
