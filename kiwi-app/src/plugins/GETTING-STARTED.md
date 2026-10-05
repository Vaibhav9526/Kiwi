# KIWI plugins — Getting Started (v1, sideload-only)

> **Alpha model:** plugins run as *trusted code*, but inside a dedicated
> `Worker` built from a `blob:` URL (T-306 — **not** `new Function`, so no
> `unsafe-eval` ever). Workers have no DOM/`window`/`localStorage`/`__TAURI__`
> and inherit the document CSP (plugin `fetch` is clamped by `connect-src`).
> Origin pinning, signing, and resource limits remain deferred post-alpha —
> see `docs/THREAT-MODEL.md` RR-11. Only install plugins you trust; the
> manifest capabilities below are the *contract*, enforced at the bridge.

## Alpha trust boundary — what is enforced vs. deferred

**Enforced today** (proven by `e2e/run.mjs`, 48 assertions):

| Control | Where | Behavior |
|---|---|---|
| Manifest validation | `manifest.ts` | id/version/entry regexes, permissions ⊆ known caps, no `..` traversal |
| Install hygiene | `registry.ts` | entry file must exist in package, safe relative paths, localStorage persistence |
| Capability gate | `bridge.ts` `createPluginHost` | undeclared capability → `capability-denied` before the handler runs |
| Method registry | `bridge.ts` `CAPABILITY_METHODS` | method outside every capability → `unknown-method` |
| Lock gate | `bridge.ts` `isLocked()` | every request rejects `locked` while the app is locked |
| Envelope shape | `bridge.ts` `isBridgeMessage` | untagged/malformed/foreign-plugin frames dropped silently |
| Timeout | worker prelude + `createPluginClient` | unanswered requests reject `timeout` after 10s (configurable) |
| Worker context | `worker.ts` blob `Worker` | plugin runs off the main thread: no DOM, `window`, `localStorage`, cookies, or `__TAURI__`; CSP inherited (connect-src clamps fetch) |
| Dedicated channel | `runtime.ts` session host | each plugin's bridge traffic rides its own worker port — no broadcast window bus |

**NOT enforced in alpha** (accepted risk RR-11 — plugins are trusted code):

- No origin pinning on the worker port — any code running *inside* the
  worker context can speak the bridge protocol for that plugin id.
- No hard resource boundary — the worker shares the process: a hostile
  plugin can burn CPU/memory; no memory caps or rate limits yet.
- No code review/signing gate — sideload is user-trust based.
- `enabled=false` stops new sessions; `removePlugin`/`disable` terminates
  the worker (real teardown now — the context exists to terminate).
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
| `message-list-read` | `messages.list`, `messages.getEnvelope` | current message-list snapshot (whitelisted envelope fields only — no body/snippet/recipients) |
| `composer-action` | `composer.registerAction`, `composer.unregisterAction` | toolbar button in **Compose**; click fires `composer.action` back to the plugin |
| `settings-page` | `settings.registerPane`, `settings.unregisterPane`, `settings.renderPane` | pane in **Settings → Plugins** (title/icon live; body = plugin markup) |
| `notify` | `notify.show` | app toast system, text scoped `[plugin-id] …` |

**Host events:** `host.ready` fires after each session loads; `pane.mount`/
`pane.unmount` fire when a plugin pane opens/closes (reply with
`settings.renderPane` to fill the body); `composer.action` fires when the
plugin's registered compose button is clicked (`{actionId, subject, to[], cc[]}` —
no body bytes); `mail-changed` is broadcast from
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
validate → `installPlugin` → `getPlugin` → build worker script → exec in a
real `node:worker_threads` Worker (the *same* prelude+entry artifact the
app's blob Worker runs — `spawnWorker` is injected) → `mail-changed` event →
`notify.show` request → capability gate → host handler. It exercises all four
capability sinks end-to-end via `startPluginSession`: pane registration,
`pane.mount` → `renderPane` markup, scoped `notify.show` toasts, whitelisted
`messages.list`/`getEnvelope` snapshots, composer-action register → fire →
unregister → dispose cleanup, capability denials in both directions, and a
worker-isolation proof (a plugin-side `globalThis` write must not reach the
host). 48 assertions; exits non-zero on any failure.

## Lifecycle (v1)

`installPlugin(manifest, files)` → enabled immediately;
`setPluginEnabled(id, false)` → host stops routing calls;
`removePlugin(id)` → purged from `kiwi.plugins.v1`.

**Install UX (T-307):** Settings → Plugins has an **Install plugin…** button
backed by a folder picker (`webkitdirectory`). The picked folder's files are
read as text (64-file / 512KB-per-file caps), the top-level dir is stripped so
`manifest.json` resolves at the package root, and `installPlugin` runs the
manifest schema + capability whitelist + safe-path checks. Failures surface
verbatim in an error banner ("manifest is not valid JSON", `unknown capability
"x" (known: …)`, "no manifest.json at the package root", …) — nothing fails
silently. Success emits `kiwi-plugins-changed` → the list refreshes, the
plugin's declared capabilities render as per-row badges, and (if enabled) the
worker session starts immediately. Per-row Enable/Remove were verified live.

## Post-alpha hardening checklist

Tracked as a follow-up task (THREAT-MODEL RR-11). Each item closes a gap
listed in "NOT enforced in alpha" above:

**Resolved T-302 blocker (T-306):** live exec now works under the strict
CSP — the loader moved into a `blob:` `Worker`. The only CSP delta is
`worker-src 'self' blob:` on `index.html` + `tauri.conf.json` (narrower than
`script-src 'unsafe-eval'`, which stays absent). Verified live in the built
app: `examples/hello` loads and toasts; a plugin-side global write does not
reach the host page. Remaining checklist items:

1. ~~Isolated context~~ — **done (T-306)**: dedicated Worker; no DOM,
   localStorage, cookies, or `__TAURI__` in plugin context.
2. **Origin pinning** — pin the worker's CSP origin / tie bridge identity
   to the spawned context, not just the manifest id field.
3. ~~Channel binding~~ — **done (T-306)**: per-session dedicated worker
   port replaced the broadcast `postMessage("*")` window bus (host posts
   with same-origin `/` now, never `*`).
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
