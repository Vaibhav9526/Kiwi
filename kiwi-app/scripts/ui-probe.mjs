#!/usr/bin/env node
/* one-off DOM probe — boots vite+Edge headless, evals a JS expression, prints result.
   Usage: node scripts/ui-probe.mjs "<js>" [hash] */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const EXPR = process.argv[2];
const HASH = process.argv[3] ?? "#/mail";
const PRE = process.argv[4]; // optional JS to run after boot (e.g. hash nav)
const PORT = 1423;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const cwd = fileURLToPath(new URL("..", import.meta.url));
const vite = spawn(process.execPath, [join(cwd, "node_modules", "vite", "bin", "vite.js"), "--port", String(PORT), "--strictPort", "--host", "127.0.0.1"], { cwd, stdio: ["ignore", "ignore", "ignore"] });
let up = false;
for (let i = 0; i < 60 && !up; i++) {
  try { const r = await fetch(`http://127.0.0.1:${PORT}/`, { signal: AbortSignal.timeout(1500) }); up = r.ok; } catch {}
  await sleep(400);
}
if (!up) { vite.kill(); console.error("vite never came up"); process.exit(1); }

const EDGE = ["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "C:/Program Files/Microsoft/Edge/Application/msedge.exe"].find(existsSync);
const prof = mkdtempSync(join(tmpdir(), "kiwi-probe-"));
const br = spawn(EDGE, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${prof}`, "--no-first-run", "--disable-gpu", "--window-size=1440,900", "about:blank"], { stdio: ["ignore", "ignore", "ignore"] });
const pf = join(prof, "DevToolsActivePort");
let ws = null;
for (let i = 0; i < 60 && !ws; i++) {
  if (existsSync(pf)) {
    const [p] = readFileSync(pf, "utf8").split("\n");
    const v = await (await fetch(`http://127.0.0.1:${p.trim()}/json/version`)).json();
    ws = v.webSocketDebuggerUrl;
  }
  await sleep(250);
}
const sock = new WebSocket(ws);
await new Promise((r, j) => { sock.onopen = r; sock.onerror = j; });
let id = 0;
const pend = new Map();
sock.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } };
const send = (method, params, sessionId) => new Promise((res, rej) => {
  const i = ++id; pend.set(i, (m) => (m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result)));
  sock.send(JSON.stringify({ id: i, method, params, sessionId }));
});
const { targetId } = await send("Target.createTarget", { url: `http://127.0.0.1:${PORT}/${HASH}` });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
await send("Runtime.enable", {}, sessionId);
await sleep(2500); // app boot
if (PRE) {
  await send("Runtime.evaluate", { expression: PRE, awaitPromise: true }, sessionId);
  await sleep(1400);
}
const r = await send("Runtime.evaluate", { expression: EXPR, returnByValue: true, awaitPromise: true }, sessionId);
console.log(JSON.stringify(r.result?.value ?? r, null, 1));
br.kill(); vite.kill(); rmSync(prof, { recursive: true, force: true });
process.exit(0);
