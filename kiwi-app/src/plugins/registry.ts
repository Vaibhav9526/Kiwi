/**
 * Plugin registry (T-268) — sideload-only v1. No store, no remote fetches:
 * a plugin package is installed from a local folder/zip the user picks
 * (manifest.json + entry file + assets as text records). Installed state
 * persists in localStorage under `kiwi.plugins.v1`; enable/disable/remove
 * are the v1 lifecycle. Execution host (iframe/worker) is post-alpha —
 * the alpha runs trusted code (THREAT-MODEL RR-11).
 */
import type { PluginManifest, PluginValidation } from "./manifest";
import { validatePluginManifest } from "./manifest";

export const PLUGINS_KEY = "kiwi.plugins.v1";
/** Fired on `window` after install/enable/disable/remove. */
export const PLUGINS_CHANGED_EVENT = "kiwi-plugins-changed";

export interface InstalledPlugin {
  manifest: PluginManifest;
  enabled: boolean;
  source: "sideload";
  installedAt: string; // ISO
  /** Package files as text records (entry js, css, assets ≤ v1 sizes). */
  files: Record<string, string>;
}

function read(): InstalledPlugin[] {
  try {
    const raw = window.localStorage.getItem(PLUGINS_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return [];
    return arr.filter((x): x is InstalledPlugin => {
      const o = x as InstalledPlugin;
      return (
        !!o &&
        typeof o === "object" &&
        o.source === "sideload" &&
        typeof o.enabled === "boolean" &&
        typeof o.installedAt === "string" &&
        typeof o.files === "object" &&
        o.files !== null &&
        validatePluginManifest(o.manifest).ok
      );
    });
  } catch {
    return [];
  }
}

function write(list: InstalledPlugin[]): void {
  try {
    window.localStorage.setItem(PLUGINS_KEY, JSON.stringify(list));
  } catch {
    // Quota/private mode — in-memory state only.
  }
}

function notifyChanged(): void {
  try {
    window.dispatchEvent(new CustomEvent(PLUGINS_CHANGED_EVENT));
  } catch {
    // ignore
  }
}

export function listPlugins(): InstalledPlugin[] {
  return read();
}

export function getPlugin(id: string): InstalledPlugin | undefined {
  return read().find((p) => p.manifest.id === id);
}

/**
 * Sideload install: validate the manifest, then persist package files.
 * `manifestJson` accepts an object or raw JSON text. `files` maps package-
 * relative paths to file text (entry js/css loaded by the host later).
 */
export function installPlugin(
  manifestJson: unknown,
  files: Record<string, string> = {},
): PluginValidation {
  const raw = typeof manifestJson === "string" ? safeParse(manifestJson) : manifestJson;
  if (raw === undefined) return { ok: false, errors: ["manifest is not valid JSON"] };
  const v = validatePluginManifest(raw);
  if (!v.ok) return v;
  const entry = v.manifest.entry;
  if (entry && !(entry in files)) {
    return { ok: false, errors: [`entry "${entry}" missing from package files`] };
  }
  for (const path of Object.keys(files)) {
    if (path.includes("..") || path.startsWith("/")) {
      return { ok: false, errors: [`package file "${path}" is not a safe relative path`] };
    }
  }
  const list = read().filter((p) => p.manifest.id !== v.manifest.id);
  list.push({
    manifest: v.manifest,
    enabled: true,
    source: "sideload",
    installedAt: new Date().toISOString(),
    files,
  });
  write(list);
  notifyChanged();
  return v;
}

export function setPluginEnabled(id: string, enabled: boolean): boolean {
  const list = read();
  const p = list.find((x) => x.manifest.id === id);
  if (!p) return false;
  p.enabled = enabled;
  write(list);
  notifyChanged();
  return true;
}

export function removePlugin(id: string): boolean {
  const list = read();
  const next = list.filter((p) => p.manifest.id !== id);
  if (next.length === list.length) return false;
  write(next);
  notifyChanged();
  return true;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
