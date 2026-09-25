/**
 * Local UI preferences (T-112, T-167). Frontend-owned persistence for
 * display and behavior settings. Never stores credentials, tokens, or
 * message content (signatures/drafts are user-authored UI text).
 *
 * Backend prefs sync rides the ipc.md §9c key/value store (`kiwi_prefs_*`,
 * wired T-175/T-237 via `api.getPrefs/setPrefs`). The sync policy is:
 * localStorage is the source of truth offline; on load the backend bag (if
 * any) overwrites local keys; every local change is pushed best-effort.
 * All keys are namespaced `kiwi.*`.
 */

export function loadPref<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function savePref(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Private mode / quota — preferences simply don't persist.
  }
}

/** Every `kiwi.*` pref the UI owns (for backend push + load-merge). */
export const PREF_KEYS = [
  "kiwi.theme",
  "kiwi.accent",
  "kiwi.density",
  "kiwi.grace",
  "kiwi.minTls",
  "kiwi.templates",
  "kiwi.notify",
  "kiwi.poll",
  "kiwi.toasts",
  "kiwi.sound",
  "kiwi.muted",
  "kiwi.defaultAccount",
  "kiwi.filterRules",
] as const;

/** Per-account prefs live under suffixed keys (never secrets). */
export const accountPref = (base: string, accountId: string) => `${base}.${accountId}`;

export function collectPrefs(): Record<string, unknown> {
  const bag: Record<string, unknown> = {};
  for (const k of PREF_KEYS) {
    try {
      const raw = window.localStorage.getItem(k);
      if (raw !== null) bag[k] = JSON.parse(raw);
    } catch {
      // Skip unreadable keys — local truth stands.
    }
  }
  try {
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      if (
        k &&
        (k.startsWith("kiwi.signature.") || k.startsWith("kiwi.syncFreq.")) &&
        !(k in bag)
      ) {
        bag[k] = JSON.parse(window.localStorage.getItem(k) ?? "null");
      }
    }
  } catch {
    // Best-effort enumeration only.
  }
  return bag;
}

/** Merge a backend bag over local keys (backend wins where present). */
export function applyPrefsBag(bag: Record<string, unknown>): void {
  for (const [k, v] of Object.entries(bag)) {
    if (typeof k === "string" && k.startsWith("kiwi.") && v !== undefined) savePref(k, v);
  }
  applyUiPrefs();
}

/** Muted account ids (`kiwi.muted`, string array). */
export function loadMuted(): string[] {
  const v = loadPref<unknown>("kiwi.muted", []);
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Apply theme + accent + density attributes to the document root. */
export function applyUiPrefs(): void {
  try {
    const root = document.documentElement;
    const theme = loadPref<string>("kiwi.theme", "dark");
    if (theme === "system") {
      const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.setAttribute("data-theme", dark ? "dark" : "light");
    } else {
      root.setAttribute("data-theme", theme);
    }
    root.setAttribute("data-accent", loadPref<string>("kiwi.accent", "standard"));
    root.setAttribute("data-density", loadPref<string>("kiwi.density", "comfortable"));
    // T-191: the Mailspring-idiom shell is the active theme foundation.
    root.setAttribute("data-shell", "mailspring");
  } catch {
    // DOM unavailable (tests) — nothing to apply.
  }
}
