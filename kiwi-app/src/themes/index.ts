/**
 * KIWI themes (T-268). Consumers:
 *   - `useTheme()` — read/apply theme; the seam A24 wires into App.tsx
 *     (replaces the `loadPref("kiwi.theme","dark")` state + `kiwi-theme`
 *     event pair; keep dispatching the event for legacy listeners — done
 *     internally).
 *   - `<ThemePicker />` — Appearance section content for Preferences.
 *   - `installThemePackage(manifest, css)` — sideload a theme package.
 * Importing this module registers stock theme CSS and re-injects any
 * sideloaded packages (`initThemes` runs on import, DOM-guarded).
 */
export { DEFAULT_THEME, SYSTEM_THEME, THEME_EVENT, THEME_PREF_KEY, applyThemeToRoot, initThemes, resolveThemeSetting, useTheme } from "./useTheme";
export type { UseTheme } from "./useTheme";
export { getTheme, installThemePackage, isStockTheme, listThemes, removeTheme, restoreInstalledThemes, INSTALLED_THEMES_KEY, THEMES_CHANGED_EVENT } from "./registry";
export { validateThemeManifest, varsToCss } from "./types";
export type { ThemeManifest, ThemeValidation } from "./types";
export { ThemePicker } from "./ThemePicker";

import { initThemes } from "./useTheme";
initThemes();
