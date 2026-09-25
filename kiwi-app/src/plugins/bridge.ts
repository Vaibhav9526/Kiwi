/**
 * Plugin bridge (T-268) — the postMessage contract between the KIWI host
 * and a plugin context (iframe/worker in the hardened model; same-context
 * module in the trusted-code alpha).
 *
 * Envelope: every message carries `$kiwi: "plugin/1"` + `dir`
 * ("req" plugin→host, "res" host→plugin, "evt" either direction).
 *
 *   plugin → host  { $kiwi:"plugin/1", dir:"req", id, plugin, method, params }
 *   host → plugin  { $kiwi:"plugin/1", dir:"res", id, plugin, ok, result|error }
 *   either         { $kiwi:"plugin/1", dir:"evt", plugin, event, data }
 *
 * Methods are gated by declared capabilities (CAPABILITY_METHODS). Alpha
 * trust note (owner amendment): plugins run as trusted code — `origin`
 * checks and context isolation are deferred (THREAT-MODEL RR-11); the
 * capability gate + lock gate still apply, and every request rejects while
 * the app is locked.
 */
import type { PluginCapability, PluginManifest } from "./manifest";

export const BRIDGE_PROTOCOL = "plugin/1" as const;
export const BRIDGE_TIMEOUT_MS = 10_000;

export interface BridgeRequest {
  $kiwi: typeof BRIDGE_PROTOCOL;
  dir: "req";
  id: string;
  plugin: string;
  method: string;
  params?: unknown;
}

export interface BridgeResponse {
  $kiwi: typeof BRIDGE_PROTOCOL;
  dir: "res";
  id: string;
  plugin: string;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
}

export interface BridgeEvent {
  $kiwi: typeof BRIDGE_PROTOCOL;
  dir: "evt";
  plugin: string;
  event: string;
  data?: unknown;
}

export type BridgeMessage = BridgeRequest | BridgeResponse | BridgeEvent;

export function isBridgeMessage(v: unknown): v is BridgeMessage {
  const o = v as BridgeMessage;
  return (
    typeof o === "object" &&
    o !== null &&
    o.$kiwi === BRIDGE_PROTOCOL &&
    typeof o.plugin === "string" &&
    (o.dir === "req" || o.dir === "res" || o.dir === "evt")
  );
}

/** Bridge method → required capability. Extend per capability only. */
export const CAPABILITY_METHODS: Record<PluginCapability, readonly string[]> = {
  "message-list-read": ["messages.list", "messages.getEnvelope"],
  "composer-action": ["composer.registerAction", "composer.unregisterAction"],
  "settings-page": ["settings.registerPane", "settings.unregisterPane"],
  notify: ["notify.show"],
};

/** Reverse lookup: method → capability it requires (undefined = unknown). */
export function methodCapability(method: string): PluginCapability | undefined {
  for (const [cap, methods] of Object.entries(CAPABILITY_METHODS)) {
    if (methods.includes(method)) return cap as PluginCapability;
  }
  return undefined;
}

export type BridgeHandler = (params: unknown, plugin: PluginManifest) => unknown | Promise<unknown>;

export interface PluginHostOptions {
  manifest: PluginManifest;
  /** Message target the plugin posts/listens on (iframe.contentWindow etc). */
  target: Pick<Window, "postMessage">;
  /** App lock check — every request rejects while locked. */
  isLocked: () => boolean;
  /** Method handlers; a method absent here rejects even if permitted. */
  handlers: Record<string, BridgeHandler>;
}

export interface PluginHost {
  /** postMessage listener — detach() on unload. */
  detach: () => void;
  /** Push a host→plugin event. */
  emit: (event: string, data?: unknown) => void;
}

/**
 * Host end of the bridge. ALPHA: `isTrustedSource` intentionally accepts all
 * origins — plugins are trusted code until post-alpha isolation lands
 * (RR-11). Everything else is enforced now: envelope shape, declared
 * capabilities, handler presence, lock gate.
 */
export function createPluginHost({ manifest, target, isLocked, handlers }: PluginHostOptions): PluginHost {
  const post = (msg: BridgeResponse | BridgeEvent) => {
    try {
      target.postMessage(msg, "*");
    } catch {
      // Plugin context gone — drop silently.
    }
  };

  const onMessage = async (e: MessageEvent) => {
    const data = e.data as unknown;
    if (!isBridgeMessage(data) || data.dir !== "req" || data.plugin !== manifest.id) return;
    const reply = (ok: boolean, result?: unknown, error?: { code: string; message: string }) =>
      post({ $kiwi: BRIDGE_PROTOCOL, dir: "res", id: data.id, plugin: manifest.id, ok, result, error });
    // Alpha trusted-code model: no origin enforcement yet (RR-11).
    void e.origin;
    if (isLocked()) return reply(false, undefined, { code: "locked", message: "App is locked — plugin calls disabled." });
    const cap = methodCapability(data.method);
    if (!cap) return reply(false, undefined, { code: "unknown-method", message: `No such bridge method "${data.method}".` });
    if (!manifest.permissions.includes(cap)) {
      return reply(false, undefined, { code: "capability-denied", message: `Plugin "${manifest.id}" did not declare "${cap}".` });
    }
    const handler = handlers[data.method];
    if (!handler) return reply(false, undefined, { code: "not-implemented", message: `Host does not implement "${data.method}" yet.` });
    try {
      reply(true, await handler(data.params, manifest));
    } catch (err) {
      reply(false, undefined, { code: "handler-error", message: err instanceof Error ? err.message : String(err) });
    }
  };

  try {
    window.addEventListener("message", onMessage);
  } catch {
    // No DOM.
  }
  return {
    detach: () => {
      try {
        window.removeEventListener("message", onMessage);
      } catch {
        // ignore
      }
    },
    emit: (event, data) => post({ $kiwi: BRIDGE_PROTOCOL, dir: "evt", plugin: manifest.id, event, data }),
  };
}

export interface PluginClientOptions {
  pluginId: string;
  /** Where requests go — window.parent inside an iframe, or the host global. */
  host?: Pick<Window, "postMessage">;
  /** Source of incoming messages — defaults to window. */
  listenOn?: Pick<Window, "addEventListener" | "removeEventListener">;
  timeoutMs?: number;
}

export interface PluginClient {
  request: <T = unknown>(method: string, params?: unknown) => Promise<T>;
  onEvent: (event: string, cb: (data: unknown) => void) => () => void;
  dispose: () => void;
}

/** Plugin-side bridge client — used inside the plugin's context. */
export function createPluginClient({ pluginId, host, listenOn, timeoutMs = BRIDGE_TIMEOUT_MS }: PluginClientOptions): PluginClient {
  const target = host ?? (typeof window !== "undefined" ? window.parent : undefined);
  const source = listenOn ?? (typeof window !== "undefined" ? window : undefined);
  let seq = 0;
  const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  const listeners = new Map<string, Set<(data: unknown) => void>>();

  const onMessage = (e: MessageEvent) => {
    const data = e.data as unknown;
    if (!isBridgeMessage(data) || data.plugin !== pluginId) return;
    if (data.dir === "res") {
      const p = pending.get(data.id);
      if (!p) return;
      pending.delete(data.id);
      clearTimeout(p.timer);
      if (data.ok) p.resolve(data.result);
      else p.reject(new PluginBridgeError(data.error?.code ?? "error", data.error?.message ?? "bridge error"));
    } else if (data.dir === "evt") {
      for (const cb of listeners.get(data.event) ?? []) {
        try {
          cb(data.data);
        } catch {
          // Plugin listener bugs must not break the bridge.
        }
      }
    }
  };

  source?.addEventListener("message", onMessage as EventListener);

  return {
    request(method, params) {
      if (!target) return Promise.reject(new PluginBridgeError("no-host", "No host window to post to."));
      const id = `${pluginId}:${++seq}`;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new PluginBridgeError("timeout", `Bridge call "${method}" timed out.`));
        }, timeoutMs);
        pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
        target.postMessage({ $kiwi: BRIDGE_PROTOCOL, dir: "req", id, plugin: pluginId, method, params } satisfies BridgeRequest, "*");
      });
    },
    onEvent(event, cb) {
      let set = listeners.get(event);
      if (!set) listeners.set(event, (set = new Set()));
      set.add(cb);
      return () => set.delete(cb);
    },
    dispose() {
      source?.removeEventListener("message", onMessage as EventListener);
      for (const [, p] of pending) {
        clearTimeout(p.timer);
        p.reject(new PluginBridgeError("disposed", "Bridge disposed."));
      }
      pending.clear();
      listeners.clear();
    },
  };
}

export class PluginBridgeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PluginBridgeError";
    this.code = code;
  }
}
