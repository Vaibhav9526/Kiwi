#!/usr/bin/env node
/**
 * capture-shots.mjs — screenshot every KIWI view in demo mode via CDP.
 * Reuses the ui-smoke.mjs approach: vite + headless Edge/Chrome + raw CDP,
 * zero dependencies. Output: PNGs into --out dir.
 *
 * Usage: node scripts/capture-shots.mjs [--out ../videos/kiwi-deep-dive/assets/shots]
 *                                     [--port 1422] [--browser edge|chrome|path]
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const arg = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const OUT = resolve(arg("out", "../videos/kiwi-deep-dive/assets/shots"));
const VITE_PORT = Number(arg("port", "1422"));
const BROWSER_ARG = arg("browser", process.env.KIWI_SMOKE_BROWSER ?? "auto");
const BOOT_TIMEOUT = 30000;
const VW = 1568, VH = 1040;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let viteProc = null, browserProc = null, profileDir = null;

async function bootVite(port) {
  const cwd = fileURLToPath(new URL("..", import.meta.url));
  viteProc = spawn(process.execPath, [join(cwd, "node_modules", "vite", "bin", "vite.js"),
    "--port", String(port), "--strictPort", "--host", "127.0.0.1"], {
    cwd, stdio: ["ignore", "pipe", "pipe"],
  });
  const deadline = Date.now() + BOOT_TIMEOUT;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return `http://127.0.0.1:${port}`;
    } catch {}
    if (viteProc.exitCode !== null) throw new Error("vite exited early");
    await sleep(400);
  }
  throw new Error("vite did not answer");
}

const CANDIDATES = {
  edge: ["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
         "C:/Program Files/Microsoft/Edge/Application/msedge.exe", "msedge"],
  chrome: ["C:/Program Files/Google/Chrome/Application/chrome.exe",
           "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe", "chrome"],
};
function findBrowser() {
  if (BROWSER_ARG !== "auto") {
    const hit = (CANDIDATES[BROWSER_ARG] ?? [BROWSER_ARG]).find((p) => existsSync(p));
    if (hit) return hit;
    if (existsSync(BROWSER_ARG)) return BROWSER_ARG;
  }
  for (const kind of ["edge", "chrome"]) {
    const hit = CANDIDATES[kind].find((p) => existsSync(p));
    if (hit) return hit;
  }
  throw new Error("no browser");
}

async function launchBrowser() {
  const exe = findBrowser();
  profileDir = mkdtempSync(join(tmpdir(), "kiwi-shots-"));
  browserProc = spawn(exe, [
    "--headless=new", "--remote-debugging-port=0",
    `--user-data-dir=${profileDir}`, "--no-first-run", "--disable-gpu",
    "--disable-extensions", `--window-size=${VW},${VH}`, "about:blank",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  const portFile = join(profileDir, "DevToolsActivePort");
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (existsSync(portFile)) {
      const [port] = readFileSync(portFile, "utf8").split("\n");
      const ver = await (await fetch(`http://127.0.0.1:${port.trim()}/json/version`)).json();
      return ver.webSocketDebuggerUrl;
    }
    if (browserProc.exitCode !== null) throw new Error("browser exited early");
    await sleep(250);
  }
  throw new Error("no DevTools port");
}

class Cdp {
  #ws; #id = 0; #pending = new Map();
  static async connect(wsUrl) {
    const c = new Cdp();
    c.#ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      c.#ws.onopen = res; c.#ws.onerror = () => rej(new Error("ws failed"));
    });
    c.#ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && c.#pending.has(m.id)) {
        const { res, rej } = c.#pending.get(m.id);
        c.#pending.delete(m.id);
        m.error ? rej(new Error(m.error.message)) : res(m.result);
      }
    };
    return c;
  }
  send(method, params = {}, sessionId) {
    const id = ++this.#id;
    this.#ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((res, rej) => {
      this.#pending.set(id, { res, rej });
      setTimeout(() => { if (this.#pending.delete(id)) rej(new Error(`${method} timeout`)); }, 20000);
    });
  }
  async newPage(url) {
    const { targetId } = await this.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await this.send("Target.attachToTarget", { targetId, flatten: true });
    await this.send("Runtime.enable", {}, sessionId);
    await this.send("Page.enable", {}, sessionId);
    await this.send("Emulation.setDeviceMetricsOverride",
      { width: VW, height: VH, deviceScaleFactor: 1, mobile: false }, sessionId);
    await this.send("Page.navigate", { url }, sessionId);
    return sessionId;
  }
  async eval(sid, expression, awaitPromise = false) {
    const r = await this.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise }, sid);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? "eval failed");
    return r.result?.value;
  }
  async shot(sid, path) {
    const r = await this.send("Page.captureScreenshot", { format: "png" }, sid);
    writeFileSync(path, Buffer.from(r.data, "base64"));
  }
  close() { try { this.#ws?.close(); } catch {} }
}

async function waitFor(cdp, sid, expr, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { if (await cdp.eval(sid, expr)) return true; } catch {}
    await sleep(200);
  }
  return false;
}

const STOPS = [
  ["mail",            "#/mail/all-inboxes",              "header.em-chrome"],
  ["mail-message",    "#/mail/all-inboxes/msg-1",        null],
  ["compose",         "#/compose",                       null],
  ["security-center", "#/security",                      null],
  ["search",          "#/search",                        null],
  ["contacts",        "#/contacts",                      null],
  ["filters",         "#/filters",                       null],
  ["disposable",      "#/disposable",                    null],
  ["settings",        "#/settings",                      null],
  ["setup",           "#/setup",                         null],
];

async function main() {
  mkdirSync(OUT, { recursive: true });
  const base = await bootVite(VITE_PORT);
  console.log("vite:", base);
  const wsUrl = await launchBrowser();
  console.log("browser up");
  const cdp = await Cdp.connect(wsUrl);
  const sid = await cdp.newPage(base);

  if (!(await waitFor(cdp, sid, "!!document.querySelector('header.em-chrome')"))) {
    console.error("app shell never mounted"); process.exit(2);
  }
  await sleep(800);

  for (const [name, hash, wait] of STOPS) {
    await cdp.eval(sid, `window.location.hash = ${JSON.stringify(hash)}`);
    if (wait) await waitFor(cdp, sid, wait);
    await sleep(900);
    const p = join(OUT, `${name}.png`);
    await cdp.shot(sid, p);
    console.log("shot", name, "->", p);
  }

  cdp.close();
  console.log("done");
}

main().catch((e) => { console.error(e); process.exitCode = 1; })
  .finally(() => {
    try { browserProc?.kill(); } catch {}
    try { viteProc?.kill(); } catch {}
    try { if (profileDir) rmSync(profileDir, { recursive: true, force: true }); } catch {}
    setTimeout(() => process.exit(process.exitCode ?? 0), 300);
  });
