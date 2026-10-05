/**
 * Custom window caption controls (min / max-restore / close) for the
 * undecorated main window — `decorations: false` in tauri.conf.json, so the
 * app's own `.em-titlebar` IS the titlebar and Windows draws no caption strip
 * above it. One glass sheet from the top edge down, in every theme.
 *
 * Behavior preserved (requirement 3/4 of the brief):
 * - **Dragging** stays on the `.em-titlebar` `data-tauri-drag-region`; this
 *   cluster opts OUT with `data-tauri-drag-region="false"` so a mousedown here
 *   is never swallowed as a drag (tao's drag.js treats the value `false` as
 *   "drag blocked here and for ancestors", and `<button>` already blocks it —
 *   the attribute makes that intent explicit rather than incidental).
 * - **Double-click to maximize** is handled by tao itself: drag.js maps a
 *   double-click on a drag region to `internal_toggle_maximize` on
 *   Windows/Linux. No duplicate handler here, which would double-toggle.
 * - **Edge/corner resize** needs nothing from us: tao's WM_NCHITTEST handler
 *   resizes undecorated + RESIZABLE windows (verified in tao 0.35.3
 *   event_loop.rs) and `resizable` stays on.
 * - **Close-to-tray** is NOT bypassed: `close()` emits `CloseRequested`, which
 *   is exactly what the native X used to emit, so
 *   `tray::handle_window_event` → `on_window_close` still runs and the
 *   `kiwi.trayOnClose` pref decides hide-vs-quit. We never call `exit()`.
 *
 * Outside the Tauri webview (vite dev / the demo build) there is no window to
 * control, so the cluster renders nothing rather than dead buttons.
 */
import { useCallback, useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isTauri } from "../ipc";
import { IconMaximize, IconMinimize, IconRestore, IconWindowClose } from "./shell-icons";

/** A rejected window command must not break the shell or the other two
 * buttons — log it and move on (same posture as ms-electron.ts). */
function reportFailure(what: string, err: unknown): void {
  console.warn(`window.${what} failed`, err);
}

export function WindowControls() {
  const [maximized, setMaximized] = useState(false);

  const syncMaximized = useCallback(async () => {
    try {
      setMaximized(await getCurrentWindow().isMaximized());
    } catch (err) {
      reportFailure("isMaximized", err);
    }
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    void syncMaximized();
    // The window can also maximize from outside the cluster (Win+Up, taskbar,
    // drag-to-top, snap layouts), so the glyph follows the real state rather
    // than only what our own button did.
    let dispose: (() => void) | undefined;
    let cancelled = false;
    void (async () => {
      try {
        const win = getCurrentWindow();
        const unlisten = await win.onResized(() => void syncMaximized());
        if (cancelled) unlisten();
        else dispose = unlisten;
      } catch (err) {
        reportFailure("onResized", err);
      }
    })();
    return () => {
      cancelled = true;
      dispose?.();
    };
  }, [syncMaximized]);

  if (!isTauri()) return null;

  const minimize = () => void getCurrentWindow().minimize().catch((e: unknown) => reportFailure("minimize", e));
  const toggleMaximize = () => void getCurrentWindow().toggleMaximize().catch((e: unknown) => reportFailure("toggleMaximize", e));
  const close = () => void getCurrentWindow().close().catch((e: unknown) => reportFailure("close", e));

  return (
    <div className="em-wincontrols" data-tauri-drag-region={false} role="group" aria-label="Window controls">
      <button type="button" className="em-winbtn" onClick={minimize} aria-label="Minimize" title="Minimize">
        <IconMinimize />
      </button>
      <button
        type="button"
        className="em-winbtn"
        onClick={toggleMaximize}
        aria-label={maximized ? "Restore" : "Maximize"}
        title={maximized ? "Restore" : "Maximize"}
      >
        {maximized ? <IconRestore /> : <IconMaximize />}
      </button>
      <button type="button" className="em-winbtn em-winbtn-close" onClick={close} aria-label="Close" title="Close">
        <IconWindowClose />
      </button>
    </div>
  );
}
