/** Font-size control (Settings → Appearance): `kiwi.fontScale` must persist
 * through the same localStorage + backend-bag plumbing as `kiwi.density` and
 * land on the document root as `--kiwi-font-scale`, which theme.css
 * (root font-size, `rem` sizes) and mailspring-tokens.css (the
 * --kiwi-ms-text-* tokens) both multiply by. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FONT_SCALES, applyPrefsBag, applyUiPrefs, collectPrefs, fontScaleFor, loadPref, savePref } from "./prefs";

/** jsdom's localStorage is shadowed by Node's experimental `--localstorage-file`
 * shim under this runner, so stand up an in-memory Storage for the pref
 * plumbing (savePref swallows write errors, which would hide a broken test). */
const real: Storage | undefined = Object.getOwnPropertyDescriptor(window, "localStorage")?.value;
const store = new Map<string, string>();
const stub: Storage = {
  get length() {
    return store.size;
  },
  key: (i: number) => [...store.keys()][i] ?? null,
  getItem: (k: string) => (store.has(k) ? (store.get(k) as string) : null),
  setItem: (k: string, v: string) => void store.set(k, String(v)),
  removeItem: (k: string) => void store.delete(k),
  clear: () => store.clear(),
};

beforeAll(() => {
  Object.defineProperty(window, "localStorage", { value: stub, configurable: true, writable: true });
});
afterAll(() => {
  if (real) Object.defineProperty(window, "localStorage", { value: real, configurable: true, writable: true });
});

function rootScale(): string {
  return document.documentElement.style.getPropertyValue("--kiwi-font-scale");
}

describe("font-size scale (kiwi.fontScale)", () => {
  it("defaults to 1 (no scaling) when unset", () => {
    window.localStorage.removeItem("kiwi.fontScale");
    applyUiPrefs();
    expect(fontScaleFor(loadPref("kiwi.fontScale", "default"))).toBe(1);
    expect(rootScale()).toBe("1");
  });

  it("writes the multiplier onto the document root for each option", () => {
    for (const [id, scale] of Object.entries(FONT_SCALES)) {
      savePref("kiwi.fontScale", id);
      applyUiPrefs();
      expect(rootScale()).toBe(String(scale));
    }
  });

  it("falls back to 1 for an unknown/stale stored id", () => {
    savePref("kiwi.fontScale", "enormous");
    applyUiPrefs();
    expect(rootScale()).toBe("1");
  });

  it("is collected for the backend push and applied from a pulled bag", () => {
    savePref("kiwi.fontScale", "xl");
    expect(collectPrefs()["kiwi.fontScale"]).toBe("xl");
    window.localStorage.removeItem("kiwi.fontScale");
    applyPrefsBag({ "kiwi.fontScale": "large" });
    expect(loadPref("kiwi.fontScale", "default")).toBe("large");
    expect(rootScale()).toBe(String(FONT_SCALES.large));
  });
});
