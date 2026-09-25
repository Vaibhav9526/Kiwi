/**
 * KIWI plugin manifest (T-268, sideload-only v1).
 *
 * manifest.json:
 *   { "id": "hello", "version": "0.1.0", "permissions": ["notify"],
 *     "name": "Hello", "entry": "plugin.js" }
 *
 * ALPHA MODEL (owner amendment 2026-09-25): plugins execute as TRUSTED
 * renderer code — declarations below are the contract surface; capability
 * *enforcement* is deferred post-alpha. Accepted risk: THREAT-MODEL RR-11.
 */

/** Declared capability surface. A plugin may only call bridge methods whose
 * capability it declares (enforced by the host bridge even in alpha — the
 * gap is DOM/IPC isolation, not the capability check). */
export const PLUGIN_CAPABILITIES = [
  /** Read message-list metadata (envelopes, flags) — never bodies. */
  "message-list-read",
  /** Contribute an action to the composer surface. */
  "composer-action",
  /** Contribute a pane to Preferences. */
  "settings-page",
  /** Raise toast notifications. */
  "notify",
] as const;

export type PluginCapability = (typeof PLUGIN_CAPABILITIES)[number];

export interface PluginManifest {
  /** Unique slug — `^[a-z0-9][a-z0-9.-]{1,63}$`. */
  id: string;
  /** Semver `x.y.z`. */
  version: string;
  /** Declared capabilities (subset of PLUGIN_CAPABILITIES). */
  permissions: PluginCapability[];
  name?: string;
  description?: string;
  author?: string;
  /** Entry file inside the plugin package (e.g. "plugin.js"). */
  entry?: string;
  /** Minimum app version the plugin targets. */
  minAppVersion?: string;
}

export const PLUGIN_ID_RE = /^[a-z0-9][a-z0-9.-]{1,63}$/;
export const PLUGIN_VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
export const PLUGIN_ENTRY_RE = /^[a-zA-Z0-9_.\-/]{1,200}$/;

export type PluginValidation =
  | { ok: true; manifest: PluginManifest }
  | { ok: false; errors: string[] };

/** Validate + normalize a parsed manifest payload. Never throws. */
export function validatePluginManifest(raw: unknown): PluginValidation {
  const errors: string[] = [];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, errors: ["manifest must be a JSON object"] };
  }
  const m = raw as Record<string, unknown>;

  if (typeof m.id !== "string" || !PLUGIN_ID_RE.test(m.id)) {
    errors.push(`id must match ${PLUGIN_ID_RE}`);
  }
  if (typeof m.version !== "string" || !PLUGIN_VERSION_RE.test(m.version)) {
    errors.push(`version must match ${PLUGIN_VERSION_RE} (semver x.y.z)`);
  }
  if (m.name !== undefined && typeof m.name !== "string") errors.push("name must be a string");
  if (m.description !== undefined && typeof m.description !== "string") errors.push("description must be a string");
  if (m.author !== undefined && typeof m.author !== "string") errors.push("author must be a string");
  if (m.entry !== undefined && (typeof m.entry !== "string" || !PLUGIN_ENTRY_RE.test(m.entry) || m.entry.includes(".."))) {
    errors.push(`entry must match ${PLUGIN_ENTRY_RE} and not traverse ("..")`);
  }
  if (m.minAppVersion !== undefined && (typeof m.minAppVersion !== "string" || !PLUGIN_VERSION_RE.test(m.minAppVersion))) {
    errors.push("minAppVersion must be semver x.y.z");
  }

  const permissions: PluginCapability[] = [];
  if (!Array.isArray(m.permissions)) {
    errors.push("permissions must be an array of capability strings");
  } else {
    for (const p of m.permissions) {
      if (typeof p !== "string") {
        errors.push("permissions entries must be strings");
      } else if (!(PLUGIN_CAPABILITIES as readonly string[]).includes(p)) {
        errors.push(`unknown capability "${p}" (known: ${PLUGIN_CAPABILITIES.join(", ")})`);
      } else if (!permissions.includes(p as PluginCapability)) {
        permissions.push(p as PluginCapability);
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  const out: PluginManifest = {
    id: m.id as string,
    version: m.version as string,
    permissions,
  };
  if (typeof m.name === "string") out.name = m.name;
  if (typeof m.description === "string") out.description = m.description;
  if (typeof m.author === "string") out.author = m.author;
  if (typeof m.entry === "string") out.entry = m.entry;
  if (typeof m.minAppVersion === "string") out.minAppVersion = m.minAppVersion;
  return { ok: true, manifest: out };
}

export function isPluginCapability(v: unknown): v is PluginCapability {
  return typeof v === "string" && (PLUGIN_CAPABILITIES as readonly string[]).includes(v);
}
