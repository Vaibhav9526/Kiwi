/**
 * `useTheme()` (T-268) — the theme seam A24's views/App consume.
 *
 *   const { theme, resolvedTheme, themes, setTheme } = useTheme();
 *
 * - `theme`: the stored setting — a theme id or `"system"`.
 * - `resolvedTheme`: concrete theme id actually applied (`system` resolves
 *   via prefers-color-scheme; unknown ids fall back to the default).
 * - `setTheme(id|"system")`: persists `kiwi.theme`, applies `data-theme`
 *   on `<html>`, and dispatches the legacy `kiwi-theme` CustomEvent so
 *   existing listeners (App.tsx, settings selects) stay in sync.
 *
 * DEFAULT IS LIGHT (owner directive, eM Client reference — supersedes the
 * flagship-dark default).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { loadPref, savePref } from "../prefs";
import { THEMES_CHANGED_EVENT, getTheme, installThemePackage, listThemes, removeTheme, restoreInstalledThemes } from "./registry";
import type { ThemeManifest, ThemeValidation } from "./types";

export const DEFAULT_THEME = "light";
export const SYSTEM_THEME = "system";
export const THEME_PREF_KEY = "kiwi.theme";
/** Back-compat event contract already used by App.tsx/views/settings.tsx. */
export const THEME_EVENT = "kiwi-theme";

export function resolveThemeSetting(setting: string): string {
  if (setting !== SYSTEM_THEME) return setting;
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return DEFAULT_THEME;
  }
}

/** Apply a concrete theme id to the root element (theme + shell attrs). */
export function applyThemeToRoot(themeId: string): void {
  try {
    const root = document.documentElement;
    root.setAttribute("data-theme", themeId);
    root.setAttribute("data-shell", "mailspring");
  } catch {
    // No DOM (tests).
  }
}

export interface UseTheme {
  /** Stored setting: theme id or "system". */
  theme: string;
  /** Concrete theme id applied to the document. */
  resolvedTheme: string;
  /** Stock + sideloaded theme manifests. */
  themes: ThemeManifest[];
  setTheme: (setting: string) => void;
  installTheme: (manifestJson: unknown, cssText?: string) => ThemeValidation;
  uninstallTheme: (id: string) => boolean;
}

export function useTheme(): UseTheme {
  const [theme, setThemeState] = useState<string>(() => loadPref<string>(THEME_PREF_KEY, DEFAULT_THEME));
  const [themes, setThemes] = useState<ThemeManifest[]>(() => listThemes());
  // Bumps when the OS scheme flips while `theme === "system"`.
  const [schemeRev, setSchemeRev] = useState(0);

  const resolvedTheme = useMemo(() => {
    void schemeRev;
    const resolved = resolveThemeSetting(theme);
    return getTheme(resolved) ? resolved : DEFAULT_THEME;
  }, [theme, schemeRev, themes]);

  // Back-compat: Settings/App dispatch `kiwi-theme` with the new setting.
  useEffect(() => {
    const onTheme = (e: Event) => {
      const v = (e as CustomEvent).detail;
      if (typeof v === "string") setThemeState(v);
    };
    const onCatalog = () => setThemes(listThemes());
    let mql: MediaQueryList | null = null;
    const onScheme = () => setSchemeRev((n) => n + 1);
    try {
      window.addEventListener(THEME_EVENT, onTheme);
      window.addEventListener(THEMES_CHANGED_EVENT, onCatalog);
      mql = window.matchMedia("(prefers-color-scheme: dark)");
      mql.addEventListener("change", onScheme);
    } catch {
      // No DOM.
    }
    return () => {
      try {
        window.removeEventListener(THEME_EVENT, onTheme);
        window.removeEventListener(THEMES_CHANGED_EVENT, onCatalog);
        mql?.removeEventListener("change", onScheme);
      } catch {
        // ignore
      }
    };
  }, []);

  // Apply + persist on change.
  useEffect(() => {
    applyThemeToRoot(resolvedTheme);
    savePref(THEME_PREF_KEY, theme);
  }, [theme, resolvedTheme]);

  const setTheme = useCallback((setting: string) => {
    setThemeState(setting);
    try {
      window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: setting }));
    } catch {
      // ignore
    }
  }, []);

  const installTheme = useCallback((manifestJson: unknown, cssText?: string) => {
    const r = installThemePackage(manifestJson, cssText);
    return r;
  }, []);

  const uninstallTheme = useCallback((id: string) => {
    const removed = removeTheme(id);
    return removed;
  }, []);

  return { theme, resolvedTheme, themes, setTheme, installTheme, uninstallTheme };
}

/** Module-load init: re-inject sideloaded theme styles + apply current. */
export function initThemes(): void {
  restoreInstalledThemes();
  applyThemeToRoot(resolveThemeSetting(loadPref<string>(THEME_PREF_KEY, DEFAULT_THEME)));
}
