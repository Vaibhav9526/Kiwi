/**
 * KIWI plugins (T-268) — sideload-only v1 scaffold.
 *
 *   manifest.ts  — manifest format + capability declarations + validation
 *   bridge.ts    — postMessage contract (`kiwi plugin/1` envelope), host +
 *                  plugin ends, capability-gated methods, lock-gated calls
 *   registry.ts  — install / list / enable / disable / remove (localStorage)
 *
 * ALPHA MODEL: plugins execute as trusted renderer code — origin checks and
 * context isolation are deferred per owner amendment (2026-09-25). Accepted
 * risk: docs/THREAT-MODEL.md RR-11 + boundary B10. Post-alpha hardening:
 * sandboxed iframe/worker host, origin pinning, capability enforcement at
 * the context boundary, plugin signing/review gate before IPC-adjacent caps.
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
