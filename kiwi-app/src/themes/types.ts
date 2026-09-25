/**
 * KIWI theme package format (T-268): a theme = `manifest.json` + `theme.css`.
 *
 * manifest.json:
 *   { "id": "light", "name": "KIWI Light", "version": "1.0.0",
 *     "author": "KIWI", "description": "…", "vars": { "--kiwi-ms-bg": "#fff" } }
 *
 * - `id` becomes the `data-theme` attribute value on the document root.
 * - `vars` is the canonical token map (overrides mailspring-tokens.css);
 *   also used for picker swatches and to generate the theme's style block
 *   when a sideloaded package ships no/insufficient CSS.
 * - `theme.css` carries the full override rules, scoped to
 *   `[data-theme="<id>"]`.
 */

export const THEME_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const THEME_VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
export const CSS_VAR_RE = /^--[a-zA-Z0-9-]+$/;

export interface ThemeManifest {
  id: string;
  name: string;
  version: string;
  author?: string;
  description?: string;
  vars: Record<string, string>;
}

export type ThemeValidation =
  | { ok: true; manifest: ThemeManifest }
  | { ok: false; errors: string[] };

/** Validate + normalize a parsed manifest JSON payload. Never throws. */
export function validateThemeManifest(raw: unknown): ThemeValidation {
  const errors: string[] = [];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, errors: ["manifest must be a JSON object"] };
  }
  const m = raw as Record<string, unknown>;

  if (typeof m.id !== "string" || !THEME_ID_RE.test(m.id)) {
    errors.push(`id must match ${THEME_ID_RE} (lowercase slug; becomes data-theme)`);
  }
  if (typeof m.name !== "string" || m.name.trim().length === 0) {
    errors.push("name must be a non-empty string");
  }
  if (typeof m.version !== "string" || !THEME_VERSION_RE.test(m.version)) {
    errors.push(`version must match ${THEME_VERSION_RE} (semver x.y.z)`);
  }
  if (m.author !== undefined && typeof m.author !== "string") {
    errors.push("author must be a string when present");
  }
  if (m.description !== undefined && typeof m.description !== "string") {
    errors.push("description must be a string when present");
  }

  let vars: Record<string, string> = {};
  if (m.vars === undefined) {
    errors.push("vars is required (object of CSS custom property overrides)");
  } else if (typeof m.vars !== "object" || m.vars === null || Array.isArray(m.vars)) {
    errors.push("vars must be an object of --var: value pairs");
  } else {
    for (const [k, v] of Object.entries(m.vars)) {
      if (!CSS_VAR_RE.test(k)) {
        errors.push(`vars key "${k}" is not a CSS custom property name (--…)`);
      } else if (typeof v !== "string") {
        errors.push(`vars["${k}"] must be a string`);
      } else {
        vars[k] = v;
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  const out: ThemeManifest = {
    id: m.id as string,
    name: (m.name as string).trim(),
    version: m.version as string,
    vars,
  };
  if (typeof m.author === "string") out.author = m.author;
  if (typeof m.description === "string") out.description = m.description;
  return { ok: true, manifest: out };
}

/** Generate a scoped override block from manifest vars (sideload fallback). */
export function varsToCss(manifest: ThemeManifest): string {
  const lines = Object.entries(manifest.vars).map(([k, v]) => `  ${k}: ${v};`);
  return `:root[data-theme="${manifest.id}"],\n[data-theme="${manifest.id}"] {\n${lines.join("\n")}\n}`;
}
