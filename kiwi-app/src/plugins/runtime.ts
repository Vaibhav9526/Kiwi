/**
 * Plugin runtime (T-280) — host-side sinks that make bridge capabilities
 * visible, plus the session supervisor that starts/stops enabled plugins.
 *
 * ALPHA TRUSTED-CODE MODEL (unchanged, THREAT-MODEL RR-11): plugin entry
 * files execute in the app context via `new Function` with an injected
 * PluginClient — these are host sinks, NOT isolation. Origin checks and
 * context isolation remain deferred (see GETTING-STARTED "Alpha trust
 * boundary").
 *
 * Host sinks wired here:
 *   notify.show              → app toast system, text scoped "[plugin-id] …"
 *   settings.registerPane    → pane record {paneId,title,icon?} in the store
 *   settings.renderPane      → pane body markup (plugin-supplied; rendered
 *                              verbatim in Settings→Plugins — trusted alpha)
 *   settings.unregisterPane  → pane removed
 *
 * Bridge events the host emits: "host.ready" after each session starts and
 * "pane.mount"/"pane.unmount" as panes open/close; "mail-changed" is
 * broadcast from App's kiwi://mail-changed debounce.
 *
 * React bindings live in hooks.ts; this module is DOM-free enough to run in
 * the node e2e harness (window access is stubbed there).
 */
import type { PluginManifest } from "./manifest";
import { createPluginClient, createPluginHost } from "./bridge";
import type { PluginClient, PluginHost } from "./bridge";
import { listPlugins } from "./registry";
import type { InstalledPlugin } from "./registry";

/* ---------- pane store (plugin-registered Settings panes) ---------- */

export interface PluginPane {
  pluginId: string;
  pluginName: string;
  paneId: string;
  title: string;
  /** Registry icon name — arbitrary strings rejected, falls back to "puzzle". */
  icon?: string;
  /** Plugin-supplied markup (trusted alpha — rendered verbatim). */
  body?: string;
}

const panes = new Map<string, PluginPane>(); // key `${pluginId}/${paneId}`
const paneListeners = new Set<() => void>();
// Cached snapshot — useSyncExternalStore needs a STABLE reference between
// notifications; a fresh array per call loops React into max-update-depth.
let paneSnapshot: PluginPane[] = [];

function paneKey(pluginId: string, paneId: string) {
  return `${pluginId}/${paneId}`;
}

function panesChanged() {
  paneSnapshot = [...panes.values()];
  for (const fn of paneListeners) {
    try {
      fn();
    } catch {
      // listener bug must not break the store
    }
  }
}

export function listPluginPanes(): PluginPane[] {
  return paneSnapshot;
}

export function subscribePluginPanes(fn: () => void): () => void {
  paneListeners.add(fn);
  return () => paneListeners.delete(fn);
}

/* ---------- session supervisor ---------- */

export interface PluginSinks {
  /** App toast sink — plugin text is scoped with its id. */
  notify: (kind: string, text: string) => void;
  /** App lock check — the bridge rejects every call while locked. */
  isLocked: () => boolean;
}

export interface PluginSession {
  manifest: PluginManifest;
  host: PluginHost;
  client: PluginClient;
  dispose: () => void;
}

const sessions = new Map<string, PluginSession>();

const TOAST_KINDS = new Set(["info", "ok", "warn", "error"]);

function asStr(v: unknown, max = 2000): string | undefined {
  return typeof v === "string" && v.length > 0 && v.length <= max ? v : undefined;
}

/**
 * Start one installed plugin: build the host (capability-gated sinks),
 * the in-context client, then run the entry source with `kiwi` injected.
 * Returns the session; throws are caught and reported via notify.
 */
export function startPluginSession(installed: InstalledPlugin, sinks: PluginSinks): PluginSession | null {
  const { manifest } = installed;
  const win = typeof window !== "undefined" ? window : undefined;
  if (!win) return null;

  const host = createPluginHost({
    manifest,
    target: win,
    isLocked: sinks.isLocked,
    handlers: {
      "notify.show": (params, plugin) => {
        const p = (params ?? {}) as Record<string, unknown>;
        const text = asStr(p.text);
        if (!text) return { shown: false, reason: "missing text" };
        const kind = TOAST_KINDS.has(p.kind as string) ? (p.kind as string) : "info";
        sinks.notify(kind, `[${plugin.id}] ${text}`);
        return { shown: true };
      },
      "settings.registerPane": (params, plugin) => {
        const p = (params ?? {}) as Record<string, unknown>;
        const paneId = asStr(p.paneId ?? p.id, 80);
        const title = asStr(p.title, 120);
        if (!paneId || !title) return { registered: false, reason: "paneId + title required" };
        panes.set(paneKey(plugin.id, paneId), {
          pluginId: plugin.id,
          pluginName: plugin.name ?? plugin.id,
          paneId,
          title,
          icon: asStr(p.icon, 60),
          body: asStr(p.html, 200_000),
        });
        panesChanged();
        return { registered: true };
      },
      "settings.renderPane": (params, plugin) => {
        const p = (params ?? {}) as Record<string, unknown>;
        const paneId = asStr(p.paneId ?? p.id, 80);
        const key = paneId ? paneKey(plugin.id, paneId) : undefined;
        const pane = key ? panes.get(key) : undefined;
        if (!pane) return { rendered: false, reason: "pane not registered" };
        pane.body = asStr(p.html, 200_000) ?? "";
        panesChanged();
        return { rendered: true };
      },
      "settings.unregisterPane": (params, plugin) => {
        const p = (params ?? {}) as Record<string, unknown>;
        const paneId = asStr(p.paneId ?? p.id, 80);
        const removed = paneId ? panes.delete(paneKey(plugin.id, paneId)) : false;
        if (removed) panesChanged();
        return { removed };
      },
    },
  });

  const client = createPluginClient({ pluginId: manifest.id, host: win, listenOn: win });
  const session: PluginSession = {
    manifest,
    host,
    client,
    dispose: () => {
      host.detach();
      client.dispose();
      // Only remove ourselves — a newer session may already hold the slot.
      if (sessions.get(manifest.id) === session) sessions.delete(manifest.id);
      let touched = false;
      for (const [k, pane] of panes) {
        if (pane.pluginId === manifest.id) {
          panes.delete(k);
          touched = true;
        }
      }
      if (touched) panesChanged();
    },
  };

  const entry = manifest.entry ?? "plugin.js";
  const src = installed.files[entry];
  try {
    // Trusted-code alpha loader (documented): in-context execution.
    new Function("kiwi", src ?? "")(client);
  } catch (err) {
    sinks.notify("error", `[${manifest.id}] plugin failed to load: ${err instanceof Error ? err.message : String(err)}`);
  }
  host.emit("host.ready", { plugin: manifest.id, version: manifest.version });
  sessions.set(manifest.id, session);
  return session;
}

/**
 * Reconcile live sessions with the registry: start enabled+missing, stop
 * removed/disabled. Returns the live session ids after the pass.
 */
export function reconcilePlugins(sinks: PluginSinks): string[] {
  const want = new Map(listPlugins().filter((p) => p.enabled).map((p) => [p.manifest.id, p]));
  for (const [id, s] of sessions) {
    if (!want.has(id)) s.dispose(); // dispose() removes itself from sessions
  }
  for (const [id, inst] of want) {
    const cur = sessions.get(id);
    if (cur && cur.manifest.version === inst.manifest.version) continue;
    cur?.dispose();
    startPluginSession(inst, sinks); // self-registers on success
  }
  return [...sessions.keys()];
}

export function stopAllPlugins(): void {
  for (const s of sessions.values()) s.dispose();
  sessions.clear();
}

/** Host→plugin event to one plugin (no-op if not running). */
export function emitToPlugin(pluginId: string, event: string, data?: unknown): void {
  sessions.get(pluginId)?.host.emit(event, data);
}

/** Host→all-plugins event (e.g. mail-changed from the IPC debounce). */
export function broadcastPluginEvent(event: string, data?: unknown): void {
  for (const s of sessions.values()) s.host.emit(event, data);
}
