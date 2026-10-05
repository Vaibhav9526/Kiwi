/**
 * Theme registry (T-268): stock packages are bundled (manifest + theme.css
 * under `stock/<id>/`); sideloaded packages are validated, persisted to
 * localStorage (`kiwi.themes.installed`), and injected as a scoped
 * `<style data-kiwi-theme-pkg>` block. No remote fetching — sideload only.
 */
import type { ThemeManifest, ThemeValidation } from "./types";
import { validateThemeManifest, varsToCss } from "./types";
import lightManifestJson from "./stock/light/manifest.json";
import darkManifestJson from "./stock/dark/manifest.json";
import highContrastManifestJson from "./stock/high-contrast/manifest.json";
import lightBlueManifestJson from "./stock/light-blue/manifest.json";
import lightOrangeManifestJson from "./stock/light-orange/manifest.json";
import darkBlueManifestJson from "./stock/dark-blue/manifest.json";
import darkOledManifestJson from "./stock/dark-oled/manifest.json";
import sepiaManifestJson from "./stock/sepia/manifest.json";
import liquidGlassManifestJson from "./stock/liquid-glass/manifest.json";
import mailspringTaigaManifestJson from "./stock/mailspring-taiga/manifest.json";
import mailspringUbuntuManifestJson from "./stock/mailspring-ubuntu/manifest.json";
import mailspringLessIsMoreManifestJson from "./stock/mailspring-less-is-more/manifest.json";
import mailspringDarkManifestJson from "./stock/mailspring-dark/manifest.json";
import mailspringDarksideManifestJson from "./stock/mailspring-darkside/manifest.json";
import "./stock/light/theme.css";
import "./stock/dark/theme.css";
import "./stock/high-contrast/theme.css";
import "./stock/light-blue/theme.css";
import "./stock/light-orange/theme.css";
import "./stock/dark-blue/theme.css";
import "./stock/dark-oled/theme.css";
import "./stock/sepia/theme.css";
import "./stock/liquid-glass/theme.css";
import "./stock/mailspring-taiga/theme.css";
import "./stock/mailspring-ubuntu/theme.css";
import "./stock/mailspring-less-is-more/theme.css";
import "./stock/mailspring-dark/theme.css";
import "./stock/mailspring-darkside/theme.css";

export const INSTALLED_THEMES_KEY = "kiwi.themes.installed";
/** Fired on `window` after install/remove so pickers refresh. */
export const THEMES_CHANGED_EVENT = "kiwi-themes-changed";

interface InstalledTheme {
  manifest: ThemeManifest;
  /** Raw theme.css text (already `[data-theme]`-scoped by convention). */
  css: string;
}

const STOCK_THEMES: ThemeManifest[] = [
  lightManifestJson,
  lightBlueManifestJson,
  lightOrangeManifestJson,
  sepiaManifestJson,
  liquidGlassManifestJson,
  mailspringTaigaManifestJson,
  mailspringUbuntuManifestJson,
  mailspringLessIsMoreManifestJson,
  darkManifestJson,
  darkBlueManifestJson,
  darkOledManifestJson,
  mailspringDarkManifestJson,
  mailspringDarksideManifestJson,
  highContrastManifestJson,
]
  .map((j) => validateThemeManifest(j))
  .filter((r): r is { ok: true; manifest: ThemeManifest } => r.ok)
  .map((r) => r.manifest);

function readInstalled(): InstalledTheme[] {
  try {
    const raw = window.localStorage.getItem(INSTALLED_THEMES_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return [];
    return arr.filter((x): x is InstalledTheme => {
      const o = x as InstalledTheme;
      return !!o && typeof o === "object" && validateThemeManifest(o.manifest).ok && typeof o.css === "string";
    });
  } catch {
    return [];
  }
}

function writeInstalled(list: InstalledTheme[]): void {
  try {
    window.localStorage.setItem(INSTALLED_THEMES_KEY, JSON.stringify(list));
  } catch {
    // Quota/private mode — theme applies for this session only.
  }
}

function styleNode(id: string): HTMLStyleElement | null {
  try {
    return document.querySelector(`style[data-kiwi-theme-pkg="${id}"]`);
  } catch {
    return null;
  }
}

function injectThemeStyle(entry: InstalledTheme): void {
  try {
    let node = styleNode(entry.manifest.id);
    if (!node) {
      node = document.createElement("style");
      node.setAttribute("data-kiwi-theme-pkg", entry.manifest.id);
      document.head.appendChild(node);
    }
    // Manifest vars always produce the canonical scoped block; raw theme.css
    // (author-scoped by convention) is appended verbatim — alpha trusted model.
    node.textContent = `${varsToCss(entry.manifest)}\n${entry.css}`;
  } catch {
    // No DOM (tests) — registry data still updates.
  }
}

function removeThemeStyle(id: string): void {
  try {
    styleNode(id)?.remove();
  } catch {
    // ignore
  }
}

function notifyChanged(): void {
  try {
    window.dispatchEvent(new CustomEvent(THEMES_CHANGED_EVENT));
  } catch {
    // ignore
  }
}

/** Stock + sideloaded themes, stock first. */
export function listThemes(): ThemeManifest[] {
  return [...STOCK_THEMES, ...readInstalled().map((t) => t.manifest)];
}

export function getTheme(id: string): ThemeManifest | undefined {
  return listThemes().find((t) => t.id === id);
}

export function isStockTheme(id: string): boolean {
  return STOCK_THEMES.some((t) => t.id === id);
}

/**
 * Install a sideloaded theme package. `manifestJson` = parsed or raw JSON
 * string; `cssText` = theme.css content (optional — manifest vars alone
 * produce a working theme). Stock ids cannot be replaced.
 */
export function installThemePackage(
  manifestJson: unknown,
  cssText = "",
): ThemeValidation {
  const raw = typeof manifestJson === "string" ? safeParse(manifestJson) : manifestJson;
  if (raw === undefined) return { ok: false, errors: ["manifest is not valid JSON"] };
  const v = validateThemeManifest(raw);
  if (!v.ok) return v;
  if (isStockTheme(v.manifest.id)) {
    return { ok: false, errors: [`"${v.manifest.id}" is a stock theme id — choose another`] };
  }
  const list = readInstalled().filter((t) => t.manifest.id !== v.manifest.id);
  const entry: InstalledTheme = { manifest: v.manifest, css: cssText };
  list.push(entry);
  writeInstalled(list);
  injectThemeStyle(entry);
  notifyChanged();
  return v;
}

export function removeTheme(id: string): boolean {
  if (isStockTheme(id)) return false;
  const list = readInstalled();
  const next = list.filter((t) => t.manifest.id !== id);
  if (next.length === list.length) return false;
  writeInstalled(next);
  removeThemeStyle(id);
  notifyChanged();
  return true;
}

/** Re-inject every sideloaded theme's style block (call once at startup). */
export function restoreInstalledThemes(): void {
  for (const t of readInstalled()) injectThemeStyle(t);
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
