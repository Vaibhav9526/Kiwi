/**
 * Plugin worker script builder (T-306) — the alpha loader executes plugin
 * entry files inside a dedicated `Worker` built from a `blob:` URL instead
 * of `new Function` in the app context. Reasons:
 *
 *   - CSP: `new Function` requires `script-src 'unsafe-eval'` (rejected —
 *     it would weaken the mail-content backstop for every script). A blob
 *     worker only needs `worker-src 'self' blob:` — far narrower.
 *   - Isolation (partial, free): worker code has no DOM, no `window`, no
 *     `localStorage`/cookies, no `__TAURI__` IPC bridge; and as a blob
 *     worker it INHERITS the document CSP, so `fetch` inside plugin code is
 *     clamped by the app's `connect-src`. Trusted-code alpha posture stands
 *     (RR-11): CPU/memory are still shared and capabilities remain a
 *     declared contract enforced at the bridge — but ambient authority is
 *     genuinely reduced.
 *
 * The worker script is `PRELUDE + plugin source`: the prelude installs a
 * `kiwi` bridge client speaking the `plugin/1` envelope over the worker's
 * postMessage port — identical contract to `createPluginClient` in
 * bridge.ts (the prelude is self-contained because blob workers can't
 * import modules; the e2e harness exercises this exact prelude in a real
 * worker thread). The port shim resolves `self` in a browser worker and
 * falls back to `node:worker_threads` `parentPort` so the SAME script runs
 * in the harness — no divergent test path.
 */
export interface PluginWorkerLike {
  postMessage(msg: unknown): void;
  addEventListener(type: string, fn: (e: { data?: unknown; message?: string }) => void): void;
  removeEventListener?(type: string, fn: (e: { data?: unknown; message?: string }) => void): void;
  terminate(): void | Promise<unknown>;
}

/** Injected by the host/embedder; default = blob Worker (browser). */
export type PluginWorkerFactory = (script: string, pluginId: string) => PluginWorkerLike;

/**
 * Prelude source — `var` + sloppy mode on purpose: plugin sources are plain
 * scripts (same semantics the `new Function` loader gave them) and sloppy
 * concat keeps `var` redeclaration legal if a plugin picks an unlucky name.
 * `kiwi` lands as a script-scope binding the appended source sees directly.
 */
const WORKER_PRELUDE = `
/* ---- KIWI plugin worker prelude (T-306) — host-injected, do not edit in
   generated form; source of truth: src/plugins/worker.ts ---- */
var __kiwiPort = (function () {
  var g = globalThis;
  // Browser DedicatedWorkerGlobalScope (self === globalThis there) — or any
  // context already exposing the web worker messaging globals.
  if (typeof g.self === "object" && g.self !== null && typeof g.self.postMessage === "function" && typeof g.self.addEventListener === "function") {
    return g.self;
  }
  // node:worker_threads (e2e harness) — no self/postMessage globals.
  var pp = require("node:worker_threads").parentPort;
  var ls = new Set();
  pp.on("message", function (d) { Array.from(ls).forEach(function (f) { f({ data: d }); }); });
  return {
    postMessage: function (m) { pp.postMessage(m); },
    addEventListener: function (_t, f) { ls.add(f); },
    removeEventListener: function (_t, f) { ls.delete(f); },
  };
})();

var kiwi = (function () {
  var PROTO = "plugin/1"; // BRIDGE_PROTOCOL — keep in sync with bridge.ts
  var TIMEOUT_MS = 10000; // BRIDGE_TIMEOUT_MS — keep in sync with bridge.ts
  var PLUGIN_ID = __PLUGIN_ID__;
  var seq = 0;
  var pending = new Map();
  var listeners = new Map();
  function berr(code, message) {
    var e = new Error(message);
    e.name = "PluginBridgeError";
    e.code = code;
    return e;
  }
  __kiwiPort.addEventListener("message", function (e) {
    var d = e && e.data;
    if (!d || typeof d !== "object" || d.$kiwi !== PROTO || d.plugin !== PLUGIN_ID) return;
    if (d.dir === "res") {
      var p = pending.get(d.id);
      if (!p) return;
      pending.delete(d.id);
      clearTimeout(p.timer);
      if (d.ok) p.resolve(d.result);
      else p.reject(berr((d.error && d.error.code) || "error", (d.error && d.error.message) || "bridge error"));
    } else if (d.dir === "evt") {
      var set = listeners.get(d.event);
      if (set) Array.from(set).forEach(function (cb) { try { cb(d.data); } catch (_e) { /* plugin listener bugs must not break the bridge */ } });
    }
  });
  return {
    request: function (method, params) {
      var id = PLUGIN_ID + ":" + (++seq);
      return new Promise(function (resolve, reject) {
        var timer = setTimeout(function () {
          pending.delete(id);
          reject(berr("timeout", 'Bridge call "' + method + '" timed out.'));
        }, TIMEOUT_MS);
        pending.set(id, { resolve: resolve, reject: reject, timer: timer });
        __kiwiPort.postMessage({ $kiwi: PROTO, dir: "req", id: id, plugin: PLUGIN_ID, method: method, params: params });
      });
    },
    onEvent: function (event, cb) {
      var set = listeners.get(event);
      if (!set) { set = new Set(); listeners.set(event, set); }
      set.add(cb);
      return function () { set.delete(cb); };
    },
    dispose: function () {
      pending.forEach(function (p) { clearTimeout(p.timer); p.reject(berr("disposed", "Bridge disposed.")); });
      pending.clear();
      listeners.clear();
    },
  };
})();
/* ---- end prelude; plugin entry source follows ---- */
`;

/**
 * Build the complete worker script for a plugin: prelude (port + `kiwi`
 * client) followed by the entry source verbatim. One artifact feeds both
 * the app's blob Worker and the node harness, so tests prove the real path.
 */
export function buildPluginWorkerScript(pluginId: string, entrySource: string): string {
  return WORKER_PRELUDE.replace("__PLUGIN_ID__", JSON.stringify(pluginId)) + "\n" + entrySource;
}

/**
 * Default factory (browser): blob-URL dedicated worker. Requires
 * `worker-src blob:` in the CSP — deliberately NOT `script-src
 * 'unsafe-eval'`. Throws when Worker/blob URLs are unavailable so the host
 * can surface a load failure instead of a silent no-op.
 */
export function spawnBlobWorker(script: string): PluginWorkerLike {
  if (typeof Worker === "undefined" || typeof Blob === "undefined" || typeof URL === "undefined" || typeof URL.createObjectURL !== "function") {
    throw new Error("Worker context unavailable");
  }
  const url = URL.createObjectURL(new Blob([script], { type: "text/javascript" }));
  const w = new Worker(url);
  const revoke = () => {
    try {
      URL.revokeObjectURL(url);
    } catch {
      // already revoked
    }
  };
  // Revoke once the worker is alive (first message or error) — keeping the
  // URL alive until then avoids racing the script fetch; terminate() also
  // revokes so silent workers don't pin the URL forever.
  w.addEventListener("message", revoke, { once: true });
  w.addEventListener("error", revoke, { once: true });
  return {
    postMessage: (m) => w.postMessage(m),
    addEventListener: (t, f) => w.addEventListener(t, f as EventListener),
    removeEventListener: (t, f) => w.removeEventListener(t, f as EventListener),
    terminate: () => {
      w.terminate();
      revoke();
    },
  };
}
