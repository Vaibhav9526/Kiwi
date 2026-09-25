/**
 * Resizable pane widths (T-293). Widths persist via the pref store
 * (`kiwi.pane.*` keys, in PREF_KEYS → backend-synced), are clamped to
 * their usable min/max on both write and load, and default to the
 * eM-idiom proportions when unset. CSS consumes them via
 * `--kiwi-pane-*` custom properties on `.em-main` / `.em-mailbox`.
 */
import { useCallback, useEffect, useState } from "react";
import { loadPref, savePref } from "../prefs";

export interface PaneWidth {
  px: number;
  set: (px: number) => void;
  reset: () => void;
}

const clampPx = (v: number, min: number, max: number) => Math.min(max, Math.max(min, Math.round(v)));

export function usePaneWidth(prefKey: string, fallback: number, min: number, max: number): PaneWidth {
  const [px, setPx] = useState(() => {
    const v = loadPref<number>(prefKey, fallback);
    return typeof v === "number" && Number.isFinite(v) ? clampPx(v, min, max) : fallback;
  });
  const set = useCallback((v: number) => setPx(clampPx(v, min, max)), [min, max]);
  const reset = useCallback(() => setPx(fallback), [fallback]);
  useEffect(() => {
    savePref(prefKey, px);
  }, [prefKey, px]);
  return { px, set, reset };
}
