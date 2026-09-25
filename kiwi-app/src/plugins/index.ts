/**
 * KIWI plugins (T-268) — sideload-only v1 scaffold.
 *
 *   manifest.ts  — manifest format + capability declarations + validation
 *   bridge.ts    — postMessage contract (`kiwi plugin/1` envelope), host +
 *                  plugin ends, capability-gated methods, lock-gated calls
 *   registry.ts  — install / list / enable / disable / remove (localStorage)
 *
 * EXECUTION (T-306): plugins run in a dedicated `Worker` built from a
 * blob: URL (worker.ts) — no DOM/localStorage/`__TAURI__`, CSP-inherited
 * connect-src clamp — under the trusted-code alpha model (origin pinning,
 * signing, resource limits still deferred: docs/THREAT-MODEL.md RR-11 +
 * boundary B10). Requires `worker-src blob:` in the CSP — NO unsafe-eval.
 */
export { PLUGIN_CAPABILITIES, PLUGIN_ID_RE, PLUGIN_VERSION_RE, isPluginCapability, validatePluginManifest } from "./manifest";
export type { PluginCapability, PluginManifest, PluginValidation } from "./manifest";
export {
  BRIDGE_PROTOCOL,
  BRIDGE_TIMEOUT_MS,
  CAPABILITY_METHODS,
  PluginBridgeError,
  createPluginClient,
  createPluginHost,
  isBridgeMessage,
  methodCapability,
} from "./bridge";
export type {
  BridgeEvent,
  BridgeHandler,
  BridgeMessage,
  BridgeRequest,
  BridgeResponse,
  PluginClient,
  PluginClientOptions,
  PluginHost,
  PluginHostOptions,
} from "./bridge";
export { PLUGINS_KEY, PLUGINS_CHANGED_EVENT, getPlugin, installPlugin, listPlugins, removePlugin, setPluginEnabled } from "./registry";
export type { InstalledPlugin } from "./registry";
export {
  broadcastPluginEvent,
  emitToPlugin,
  fireComposerAction,
  listComposerActions,
  listPluginPanes,
  reconcilePlugins,
  startPluginSession,
  stopAllPlugins,
  subscribeComposerActions,
  subscribePluginPanes,
} from "./runtime";
export type { ComposerAction, PluginPane, PluginSession, PluginSinks } from "./runtime";
export { buildPluginWorkerScript, spawnBlobWorker } from "./worker";
export type { PluginWorkerFactory, PluginWorkerLike } from "./worker";
export { useComposerActions, useInstalledPlugins, usePluginPanes, usePluginRuntime } from "./hooks";
export type { NotifySink } from "./hooks";
