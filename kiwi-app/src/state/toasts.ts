/**
 * Toast state (T-182, extracted from App.tsx verbatim): ephemeral
 * send/sync/policy notices, max 5, 6 s auto-dismiss, `kiwi.toasts`
 * kill-switch, best-effort WebAudio blip. Zero functional change — this is
 * the exact notify/dismiss logic, only relocated.
 */

import { useCallback, useRef, useState } from "react";
import { loadPref } from "../prefs";
import type { Toast, ToastKind } from "../components/toasts";

export type NotifyFn = (
  kind: ToastKind,
  text: string,
  opts?: { action?: { label: string; run: () => void }; ttlMs?: number },
) => void;

export function useToasts(): { toasts: Toast[]; notify: NotifyFn; dismissToast: (id: number) => void } {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const dismissToast = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);

  const notify = useCallback(
    (kind: ToastKind, text: string, opts?: { action?: { label: string; run: () => void }; ttlMs?: number }) => {
      // Toast kill-switch (T-167): in-view status lines still update, so
      // nothing is lost — the popup is just skipped.
      try {
        if (loadPref<string>("kiwi.toasts", "on") === "off") return;
      } catch {
        // Prefs unreadable — notify anyway.
      }
      toastId.current += 1;
      const id = toastId.current;
      setToasts((ts) => [...ts.slice(-4), { id, kind, text, action: opts?.action }]);
      window.setTimeout(() => dismissToast(id), opts?.ttlMs ?? 6000);
      // Optional UI sound (T-167): tiny WebAudio blip, best-effort only —
      // never throws, never blocks, no assets.
      try {
        if (loadPref<string>("kiwi.sound", "off") === "on") {
          const Ctx = (window as unknown as { AudioContext?: new () => AudioContext }).AudioContext;
          if (Ctx) {
            const ctx = new Ctx();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.frequency.value = kind === "error" ? 220 : 660;
            gain.gain.value = 0.04;
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.12);
            window.setTimeout(() => void ctx.close().catch(() => undefined), 300);
          }
        }
      } catch {
        // Audio unavailable — the toast itself already rendered.
      }
    },
    [dismissToast],
  );

  return { toasts, notify, dismissToast };
}
