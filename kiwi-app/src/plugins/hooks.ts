/**
 * React bindings for the plugin runtime (T-280). Pure logic lives in
 * runtime.ts so the e2e harness can exercise it without React.
 */
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { ToastKind } from "../components/toasts";
import { PLUGINS_CHANGED_EVENT, listPlugins } from "./registry";
import type { InstalledPlugin } from "./registry";
import {
  listComposerActions,
  listPluginPanes,
  reconcilePlugins,
  stopAllPlugins,
  subscribeComposerActions,
  subscribePluginPanes,
} from "./runtime";
import type { ComposerAction, PluginPane } from "./runtime";

export type NotifySink = (kind: ToastKind, text: string) => void;

/**
 * Host the enabled plugins for the app's lifetime: reconciles sessions on
 * mount and whenever the registry broadcasts `kiwi-plugins-changed`.
 * `notify` routes plugin `notify.show` calls into the toast system;
 * `locked` feeds the bridge lock gate (all calls reject while locked);
 * `listSnapshot` (T-302) feeds `messages.list`/`messages.getEnvelope` —
 * the envelopes the user currently sees (display state, overrides applied).
 * When omitted those methods resolve `not-implemented`.
 */
export function usePluginRuntime(notify: NotifySink, locked: boolean, listSnapshot?: () => unknown[]): void {
  const lockedRef = useRef(locked);
  lockedRef.current = locked;
  const notifyRef = useRef<NotifySink>(notify);
  notifyRef.current = notify;
  const snapshotRef = useRef<(() => unknown[]) | undefined>(listSnapshot);
  snapshotRef.current = listSnapshot;

  useEffect(() => {
    const sinks = {
      notify: (kind: string, text: string) => notifyRef.current(kind as ToastKind, text),
      isLocked: () => lockedRef.current,
      ...(listSnapshot ? { listSnapshot: () => snapshotRef.current?.() ?? [] } : {}),
    };
    const reconcile = () => reconcilePlugins(sinks);
    reconcile();
    let un: (() => void) | undefined;
    try {
      window.addEventListener(PLUGINS_CHANGED_EVENT, reconcile);
      un = () => window.removeEventListener(PLUGINS_CHANGED_EVENT, reconcile);
    } catch {
      // No DOM.
    }
    return () => {
      un?.();
      stopAllPlugins();
    };
  }, []);
}

/** Live list of plugin-registered Settings panes. */
export function usePluginPanes(): PluginPane[] {
  return useSyncExternalStore(subscribePluginPanes, listPluginPanes);
}

/** Live list of plugin-registered composer actions (T-302). */
export function useComposerActions(): ComposerAction[] {
  return useSyncExternalStore(subscribeComposerActions, listComposerActions);
}

/** Installed plugin records — re-reads on `kiwi-plugins-changed`. */
export function useInstalledPlugins(): InstalledPlugin[] {
  const [list, setList] = useState<InstalledPlugin[]>(() => listPlugins());
  useEffect(() => {
    const refresh = () => setList(listPlugins());
    try {
      window.addEventListener(PLUGINS_CHANGED_EVENT, refresh);
      return () => window.removeEventListener(PLUGINS_CHANGED_EVENT, refresh);
    } catch {
      return undefined;
    }
  }, []);
  return list;
}
