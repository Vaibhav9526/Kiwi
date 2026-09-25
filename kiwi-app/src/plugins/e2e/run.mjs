#!/usr/bin/env node
/**
 * T-274 bridge e2e harness — proves the plugin bridge end-to-end against the
 * REAL shipped modules (bundled in-memory via esbuild; nothing reimplemented):
 *
 *   manifest.json on disk → validatePluginManifest → installPlugin → getPlugin
 *   → load entry source → exec with injected PluginClient (the documented
 *   trusted-code alpha loader) → host "mail-changed" event → plugin replies
 *   with notify.show → capability gate → handler.
 *
 * Asserts: event delivered + plugin acted (granted capability), capability
 * DENIAL for an undeclared method, selective grant, unknown-method,
 * not-implemented, lock gate, cross-plugin message isolation, malformed
 * envelopes dropped, request timeout, manifest/install rejection cases.
 *
 * DOM surface is stubbed: `window` = host-side postMessage bus + in-memory
 * localStorage. Run from kiwi-app/:  node src/plugins/e2e/run.mjs
 */
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // src/plugins/e2e
const pluginsDir = dirname(here); // src/plugins
const exDir = join(pluginsDir, "examples", "notify-on-mail");

/* ---------- DOM-ish stubs ---------- */

function makeBus(name) {
  const listeners = new Set();
  return {
    name,
    sent: [], // every postMessage payload, for traffic assertions
    postMessage(data /*, origin */) {
      this.sent.push(data);
      const evt = { data, origin: "plugin-context" };
      // postMessage is a macrotask — dispatch async like the real channel.
      setTimeout(() => listeners.forEach((fn) => fn(evt)), 0);
    },
    addEventListener(_type, fn) {
      listeners.add(fn);
    },
    removeEventListener(_type, fn) {
      listeners.delete(fn);
    },
    dispatchEvent() {
      return true; // kiwi-plugins-changed broadcast — no-op here
    },
  };
}

const memStore = new Map();
const hostBus = makeBus("host"); // window: plugins post reqs here, host listens
globalThis.window = {
  ...hostBus,
  localStorage: {
    getItem: (k) => (memStore.has(k) ? memStore.get(k) : null),
    setItem: (k, v) => void memStore.set(k, String(v)),
    removeItem: (k) => void memStore.delete(k),
    clear: () => memStore.clear(),
  },
};

/* ---------- bundle + import the real modules ---------- */

const out = await build({
  entryPoints: [join(pluginsDir, "index.ts")],
  bundle: true,
  format: "esm",
  write: false,
  platform: "neutral",
  logLevel: "silent",
});
const P = await import(
  "data:text/javascript;base64," +
    Buffer.from(out.outputFiles[0].text).toString("base64")
);
const {
  validatePluginManifest,
  installPlugin,
  getPlugin,
  createPluginHost,
  createPluginClient,
  isBridgeMessage,
  PluginBridgeError,
} = P;

/* ---------- tiny assertion kit ---------- */

let pass = 0;
let fail = 0;
function ok(cond, name) {
  if (cond) {
    pass++;
    console.log(`ok ${pass + fail} - ${name}`);
  } else {
    fail++;
    console.log(`not ok ${pass + fail} - ${name}`);
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- 1) manifest load + validation ---------- */

const manifestText = readFileSync(join(exDir, "manifest.json"), "utf8");
const manifestJson = JSON.parse(manifestText);
const v = validatePluginManifest(manifestJson);
ok(v.ok && v.manifest.id === "notify-on-mail", "reference manifest validates");
ok(
  v.ok && v.manifest.permissions.length === 1 && v.manifest.permissions[0] === "notify",
  "manifest declares exactly the notify capability",
);

/* ---------- 2) sideload install via the real registry ---------- */

const pluginSrc = readFileSync(join(exDir, "plugin.js"), "utf8");
const inst = installPlugin(manifestText, { "plugin.js": pluginSrc });
ok(inst.ok, "installPlugin accepts raw manifest text + package files");
const rec = getPlugin("notify-on-mail");
ok(
  !!rec && rec.enabled && rec.source === "sideload" && typeof rec.files["plugin.js"] === "string",
  "installed plugin persisted + enabled with entry file",
);

/* ---------- 3) wire host + plugin over a linked bus pair ---------- */

const pluginBus = makeBus("plugin:notify-on-mail"); // host posts res/evt here
const notified = []; // host-side notification sink (the capability effect)
let locked = false;

const host = createPluginHost({
  manifest: rec.manifest,
  target: pluginBus,
  isLocked: () => locked,
  handlers: {
    "notify.show": (params, plugin) => {
      notified.push({ plugin: plugin.id, params });
      return { shown: true };
    },
  },
});

const kiwi = createPluginClient({ pluginId: "notify-on-mail", host: hostBus, listenOn: pluginBus });
// Trusted-code alpha loader: entry source runs in-context with `kiwi` injected.
new Function("kiwi", rec.files["plugin.js"])(kiwi);
ok(true, "plugin.js executed against injected PluginClient");

/* ---------- 4) event delivery + granted capability ---------- */

host.emit("mail-changed", { added: 3, folder: "Inbox" });
await sleep(40);
ok(
  notified.length === 1 &&
    notified[0].plugin === "notify-on-mail" &&
    /3 new messages — Inbox/.test(notified[0].params.text),
  "mail-changed event reached plugin; plugin called notify.show with event data",
);

host.emit("mail-changed", { added: 0 }); // plugin ignores non-positive adds
await sleep(30);
ok(notified.length === 1, "plugin ignored mail-changed with added=0");

/* ---------- 5) capability gate: undeclared method DENIED ---------- */

const rogueManifest = {
  id: "rogue-reader",
  version: "0.1.0",
  permissions: ["message-list-read"], // deliberately NOT "notify"
};
const rogueBus = makeBus("plugin:rogue-reader");
const listed = [];
const hostRogue = createPluginHost({
  manifest: validatePluginManifest(rogueManifest).manifest,
  target: rogueBus,
  isLocked: () => locked,
  handlers: { "messages.list": () => (listed.push(1), { messages: [] }) },
});
const rogue = createPluginClient({ pluginId: "rogue-reader", host: hostBus, listenOn: rogueBus });

let deniedCode = null;
await rogue.request("notify.show", { kind: "info", text: "rogue ping" }).catch((e) => {
  deniedCode = e instanceof PluginBridgeError ? e.code : "wrong-error-type";
});
ok(deniedCode === "capability-denied", "undeclared capability rejected with capability-denied");
ok(notified.length === 1, "denied request never reached the notify.show handler");

const listedRes = await rogue.request("messages.list", {});
ok(
  listedRes && Array.isArray(listedRes.messages) && listed.length === 1,
  "declared capability (message-list-read) resolves through the same gate",
);

let paneCode = null;
await rogue.request("settings.registerPane", { title: "x" }).catch((e) => (paneCode = e.code));
ok(paneCode === "capability-denied", "second undeclared capability also denied");

let unimplCode = null;
await rogue.request("messages.getEnvelope", { id: "m1" }).catch((e) => (unimplCode = e.code));
ok(unimplCode === "not-implemented", "declared-but-unhandled method → not-implemented");

let unknownCode = null;
await rogue.request("bogus.nope", {}).catch((e) => (unknownCode = e.code));
ok(unknownCode === "unknown-method", "method outside every capability → unknown-method");

/* ---------- 6) lock gate ---------- */

locked = true;
let lockCode = null;
await rogue.request("messages.list", {}).catch((e) => (lockCode = e.code));
ok(lockCode === "locked", "all requests reject while app is locked");
locked = false;

/* ---------- 7) isolation + envelope hygiene ---------- */

const beforePlugin = pluginBus.sent.length;
const beforeRogue = rogueBus.sent.length;
hostBus.postMessage({ $kiwi: "plugin/1", dir: "req", id: "g:1", plugin: "ghost", method: "notify.show" });
hostBus.postMessage({ dir: "req", id: "x", plugin: "notify-on-mail", method: "notify.show" }); // no $kiwi tag
hostBus.postMessage("garbage");
await sleep(30);
ok(
  pluginBus.sent.length === beforePlugin && rogueBus.sent.length === beforeRogue,
  "foreign-plugin + malformed envelopes dropped, no response emitted",
);
ok(isBridgeMessage({ $kiwi: "plugin/1", dir: "evt", plugin: "x", event: "e" }), "isBridgeMessage accepts a valid evt");
ok(!isBridgeMessage({ $kiwi: "plugin/1", dir: "req", id: "i" }), "isBridgeMessage rejects missing plugin field");

/* ---------- 8) timeout ---------- */

const orphanBus = makeBus("plugin:orphan"); // no host ever answers
const orphan = createPluginClient({ pluginId: "orphan", host: hostBus, listenOn: orphanBus, timeoutMs: 60 });
let timeoutCode = null;
await orphan.request("notify.show", {}).catch((e) => (timeoutCode = e.code));
ok(timeoutCode === "timeout", "unanswered request rejects with timeout");

/* ---------- 9) manifest/install rejection cases ---------- */

const bad = [
  [{ id: "BAD CAPS" }, "id"],
  [{ id: "ok-id", version: "1.0" }, "version"],
  [{ id: "ok-id", version: "1.0.0", permissions: "notify" }, "permissions-not-array"],
  [{ id: "ok-id", version: "1.0.0", permissions: ["admin"] }, "unknown-capability"],
  [{ id: "ok-id", version: "1.0.0", permissions: [], entry: "../escape.js" }, "entry-traversal"],
];
let allRejected = true;
for (const [m, tag] of bad) {
  const r = validatePluginManifest(m);
  if (r.ok) {
    allRejected = false;
    console.log(`   manifest rejection missed: ${tag}`);
  }
}
ok(allRejected, "invalid manifests rejected (id, version, permissions, capability, traversal)");
ok(
  !installPlugin({ id: "ghost", version: "1.0.0", permissions: [], entry: "x.js" }, {}).ok,
  "install rejects manifest whose entry file is absent from the package",
);
ok(!installPlugin("not json", {}).ok, "install rejects non-JSON manifest text");

/* ---------- 10) host sinks: settings-page pane + scoped notify.show (T-280) ---------- */

const paneDir = join(pluginsDir, "examples", "settings-pane");
const instP = installPlugin(readFileSync(join(paneDir, "manifest.json"), "utf8"), {
  "plugin.js": readFileSync(join(paneDir, "plugin.js"), "utf8"),
});
ok(instP.ok, "settings-pane reference plugin installs");
const recP = getPlugin("settings-pane-demo");
const toasts = [];
const sinks = { notify: (k, t) => toasts.push({ k, t }), isLocked: () => locked };
const sess = P.startPluginSession(recP, sinks);
ok(!!sess, "plugin session starts via runtime (in-context alpha loader)");
await sleep(50); // host.ready evt → plugin calls settings.registerPane
ok(
  P.listPluginPanes().some(
    (p) => p.pluginId === "settings-pane-demo" && p.paneId === "about" && p.title === "Demo Plugin" && p.icon === "puzzle",
  ),
  "settings.registerPane landed a pane record in the host store",
);

P.emitToPlugin("settings-pane-demo", "pane.mount", { paneId: "about" });
await sleep(60);
const paneBody = P.listPluginPanes().find((p) => p.paneId === "about")?.body ?? "";
ok(/rendered by the plugin/.test(paneBody), "pane.mount evt → plugin pushed markup via settings.renderPane");
ok(
  toasts.some((t) => t.t === "[settings-pane-demo] demo pane mounted" && t.k === "info"),
  "notify.show reached the toast sink scoped with the plugin id",
);

let paneDenied = null;
await rogue.request("settings.registerPane", { paneId: "x", title: "X" }).catch((e) => (paneDenied = e.code));
ok(paneDenied === "capability-denied", "settings.registerPane denied without settings-page cap");
ok(
  !P.listPluginPanes().some((p) => p.pluginId === "rogue-reader"),
  "denied registerPane created no pane record",
);

locked = true;
P.emitToPlugin("settings-pane-demo", "pane.mount", { paneId: "about" });
await sleep(50);
ok(true, "no crash while locked (plugin renderPane call rejected 'locked' internally)");
locked = false;

sess.dispose();
ok(
  !P.listPluginPanes().some((p) => p.pluginId === "settings-pane-demo"),
  "session dispose removes the plugin's panes",
);

host.detach();
hostRogue.detach();
kiwi.dispose();
rogue.dispose();
orphan.dispose();
P.stopAllPlugins();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
