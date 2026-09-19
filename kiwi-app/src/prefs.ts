/**
 * Local UI preferences (T-112). Frontend-only persistence for display settings
 * (theme, grace window, min-TLS display default, templates). Never stores
 * credentials, tokens, or message content. Backend prefs arrive with the
 * settings IPC — this is the offline-capable UI layer only.
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
