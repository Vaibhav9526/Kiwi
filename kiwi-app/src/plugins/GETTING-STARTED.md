# KIWI plugins — Getting Started (v1, sideload-only)

> **Alpha model:** plugins run as *trusted code* inside the app context.
> Isolation (sandboxed iframe/worker, origin checks) is deferred post-alpha —
> see `docs/THREAT-MODEL.md` RR-11. Only install plugins you trust; the
> manifest capabilities below are the *contract*, not yet a hard boundary.

## Package format

A plugin is a folder (or flat file set) containing:

```
my-plugin/
  manifest.json    # required
  plugin.js        # entry (manifest.entry)
  style.css        # optional
```

`manifest.json`:

```json
{
  "id": "my-plugin",
  "version": "0.1.0",
  "name": "My Plugin",
  "description": "What it does",
  "author": "you",
  "entry": "plugin.js",
  "permissions": ["notify", "message-list-read"]
}
```

Rules: `id` = `^[a-z0-9][a-z0-9.-]{1,63}$`; `version` = semver `x.y.z`;
`permissions` ⊆ `PLUGIN_CAPABILITIES`; `entry` = safe relative path.

## Capabilities (v1)

| Capability | Bridge methods it unlocks |
|---|---|
| `message-list-read` | `messages.list`, `messages.getEnvelope` |
| `composer-action` | `composer.registerAction`, `composer.unregisterAction` |
| `settings-page` | `settings.registerPane`, `settings.unregisterPane` |
| `notify` | `notify.show` |

Undeclared capabilities → host replies `{ ok:false, error.code:"capability-denied" }`.
While the app is locked, **all** calls fail with `"locked"`.

## Bridge contract (`plugin/1`)

Messages are `postMessage` envelopes with `$kiwi: "plugin/1"`:

- plugin → host request: `{ dir:"req", id, plugin, method, params }`
- host → plugin response: `{ dir:"res", id, plugin, ok, result | error:{code,message} }`
- events either way: `{ dir:"evt", plugin, event, data }`

Use `createPluginClient({ pluginId })` (from `./bridge`) instead of raw
postMessage — it matches ids, times out at 10s, and rejects with
`PluginBridgeError` (`code` field).

### Minimal `plugin.js`

```js
// Runs in the plugin context. `kiwi` is the injected PluginClient.
kiwi.onEvent("host.ready", async () => {
  await kiwi.request("notify.show", { kind: "info", text: "my-plugin loaded" });
});
```

See `examples/hello/manifest.json` + `examples/hello/plugin.js`.

## Lifecycle (v1)

`installPlugin(manifest, files)` → enabled immediately;
`setPluginEnabled(id, false)` → host stops routing calls;
`removePlugin(id)` → purged from `kiwi.plugins.v1`.
The Preferences → Integrations/Plugins pane (per-plugin enable/disable +
remove UI) is wired by the layout task onto `listPlugins()` etc.

## Post-alpha hardening (planned, tracked as follow-up task)

- Sandboxed iframe/worker execution context with origin pinning.
- Capability enforcement at the context boundary (not just bridge methods).
- No IPC-adjacent capability for unsigned/unreviewed plugins.
- CSP for plugin assets; size caps; no raw DOM/net access by default.
