# KIWI plugins — Getting Started (v1, sideload-only)

> **Alpha model:** plugins run as *trusted code* inside the app context.
> Isolation (sandboxed iframe/worker, origin checks) is deferred post-alpha —
> see `docs/THREAT-MODEL.md` RR-11. Only install plugins you trust; the
> manifest capabilities below are the *contract*, not yet a hard boundary.

## Alpha trust boundary — what is enforced vs. deferred

**Enforced today** (proven by `e2e/run.mjs`, 21 assertions):

| Control | Where | Behavior |
|---|---|---|
| Manifest validation | `manifest.ts` | id/version/entry regexes, permissions ⊆ known caps, no `..` traversal |
| Install hygiene | `registry.ts` | entry file must exist in package, safe relative paths, localStorage persistence |
| Capability gate | `bridge.ts` `createPluginHost` | undeclared capability → `capability-denied` before the handler runs |
| Method registry | `bridge.ts` `CAPABILITY_METHODS` | method outside every capability → `unknown-method` |
| Lock gate | `bridge.ts` `isLocked()` | every request rejects `locked` while the app is locked |
| Envelope shape | `bridge.ts` `isBridgeMessage` | untagged/malformed/foreign-plugin frames dropped silently |
| Timeout | `bridge.ts` `createPluginClient` | unanswered requests reject `timeout` after 10s (configurable) |

**NOT enforced in alpha** (accepted risk RR-11 — plugins are trusted code):

- No origin check (`e.origin` ignored) — any context can address the host.
- No context isolation — `plugin.js` executes in the app context
  (`new Function` loader style); it shares DOM, globals, and fetch.
- No DOM/IPC hard boundary — a hostile plugin can reach anything the
  renderer can. Capabilities gate *bridge methods only*.
- No code review/signing gate — sideload is user-trust based.
- `enabled=false` stops new loads; a running plugin context is not
  preempted (no context to preempt yet).
- Plugin pane markup renders verbatim in Settings→Plugins
  (`dangerouslySetInnerHTML`) — trusted-code posture; CSP blocks inline
  script but markup/style is unsanitized.

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

| Capability | Bridge methods it unlocks | Host sink (T-280) |
|---|---|---|
| `message-list-read` | `messages.list`, `messages.getEnvelope` | *unwired — `not-implemented` until the read API lands* |
| `composer-action` | `composer.registerAction`, `composer.unregisterAction` | *unwired — composer mount point pending* |
| `settings-page` | `settings.registerPane`, `settings.unregisterPane`, `settings.renderPane` | pane in **Settings → Plugins** (title/icon live; body = plugin markup) |
| `notify` | `notify.show` | app toast system, text scoped `[plugin-id] …` |

**Host events:** `host.ready` fires after each session loads; `pane.mount`/
`pane.unmount` fire when a plugin pane opens/closes (reply with
`settings.renderPane` to fill the body); `mail-changed` is broadcast from
the app's `kiwi://mail-changed` debounce (`{added: n}`).

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

See `examples/hello/` (minimal) and `examples/notify-on-mail/` (reference:
declares `notify`, listens for host `mail-changed` events, calls
`notify.show` — exercised end-to-end by the harness below).

## Proving the bridge (`e2e/run.mjs`)

```bash
node src/plugins/e2e/run.mjs        # from kiwi-app/ — prints TAP-ish lines
```

The harness bundles the real `src/plugins` modules in-memory (esbuild), stubs
a `window` bus + localStorage, then drives the full path: manifest on disk →
validate → `installPlugin` → `getPlugin` → exec `plugin.js` with an injected
`PluginClient` → `mail-changed` event → `notify.show` request → capability
gate → host handler. It also exercises the T-280 sinks end-to-end via
`startPluginSession`: pane registration, `pane.mount` → `renderPane` markup,
scoped `notify.show` toasts, and the capability denial. 30 assertions; exits
non-zero on any failure.

## Lifecycle (v1)

`installPlugin(manifest, files)` → enabled immediately;
`setPluginEnabled(id, false)` → host stops routing calls;
`removePlugin(id)` → purged from `kiwi.plugins.v1`.
The Preferences → Integrations/Plugins pane (per-plugin enable/disable +
remove UI) is wired by the layout task onto `listPlugins()` etc.

## Post-alpha hardening checklist

Tracked as a follow-up task (THREAT-MODEL RR-11). Each item closes a gap
listed in "NOT enforced in alpha" above:

1. **Isolated context** — run `plugin.js` in a sandboxed `<iframe
   sandbox="allow-scripts">` or a `Worker`; no same-context `new Function`.
2. **Origin pinning** — enforce `e.origin` against the plugin's assigned
   origin in `createPluginHost` (the hook is already marked in `bridge.ts`).
3. **Channel binding** — replace broadcast `postMessage("*")` with a
   `MessageChannel`/port handoff per plugin instance.
4. **Boundary re-check** — re-validate capabilities inside the isolated
   context (the bridge gate alone isn't enough once contexts exist).
5. **CSP + asset policy** — restrictive CSP for plugin contexts; file size
   caps and MIME allowlist for package assets.
6. **No ambient authority** — plugin contexts get no `window`, no
   Tauri IPC (`__TAURI__`), no cookie/credential/session access.
7. **Trust gate** — signing or review requirement before any plugin gains
   IPC-adjacent capabilities; unsigned plugins stay on the v1 cap set.
8. **Lifecycle enforcement** — `disable`/`remove` tears down the context,
   not just registry state; crash isolation + auto-disable on repeated
   faults; per-plugin rate limiting on bridge calls.
9. **Audit** — log bridge denials and capability use to the existing audit
   surface so plugin activity is reviewable like other security events.
