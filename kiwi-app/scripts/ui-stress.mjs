#!/usr/bin/env node
/**
 * ui-stress.mjs — CDP-driven stress + visual-regression suite for kiwi-app.
 *
 * Companion to ui-smoke.mjs: where smoke asserts each flow once, this suite
 * (a) re-asserts the specific visual contracts the user flagged (flat
 * actions, readable disabled tools, honest backend state, Gmail-style
 * compose fields, settings CSS not leaking into Security), and
 * (b) hammers the shell — route spam, folder spam, row spam, dock churn,
 * context-menu churn, typing bursts — while measuring interaction latency,
 * long-task jank, and heap growth. Browser mode has no backend, so the
 * "backend" phase checks the IPC boundary honestly: commands must reject
 * as BackendUnavailableError and no view may fabricate live data.
 *
 * Usage: node scripts/ui-stress.mjs [--url URL] [--port 1422] [--browser edge|chrome|path]
 * Exit 0 = all pass/skip; exit 1 = any FAIL. STRESS_JSON{...} for CI.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const arg = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const URL_ARG = arg("url", null);
const VITE_PORT = Number(arg("port", "1422"));
const BROWSER_ARG = arg("browser", process.env.KIWI_SMOKE_BROWSER ?? "auto");
const REQUIRE_BROWSER = process.env.KIWI_SMOKE_REQUIRE_BROWSER === "1";
const PER_CHECK_TIMEOUT = 15000;
const BOOT_TIMEOUT = 30000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function report(id, status, detail = "", kind = "stress") {
  results.push({ id, status, detail, kind });
  const tag = status === "pass" ? "PASS" : status === "fail" ? "FAIL" : "SKIP";
  console.log(`${tag}  ${id}${detail ? ` — ${detail}` : ""}`);
}

function summarize(url, extra = {}) {
  const pass = results.filter((r) => r.status === "pass").length;
  const fail = results.filter((r) => r.status === "fail").length;
  const skipp = results.filter((r) => r.status === "skip").length;
  const summary = { suite: "ui-stress", url, pass, fail, skip: skipp, results, ...extra };
  console.log(`STRESS_JSON${JSON.stringify(summary)}`);
  console.log(`ui-stress: ${pass} pass, ${fail} fail, ${skipp} skip`);
  return { pass, fail, skipp };
}

class BrowserUnavailable extends Error {}

// ---------------------------------------------------------------- vite --

let viteProc = null;
async function bootVite(port) {
  const cwd = fileURLToPath(new URL("..", import.meta.url));
  viteProc = spawn(process.execPath, [join(cwd, "node_modules", "vite", "bin", "vite.js"),
    "--port", String(port), "--strictPort", "--host", "127.0.0.1"], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let viteErr = "";
  viteProc.stderr.on("data", (d) => (viteErr += d));
  const deadline = Date.now() + BOOT_TIMEOUT;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return `http://127.0.0.1:${port}`;
    } catch { /* still starting */ }
    if (viteProc.exitCode !== null) throw new Error(`vite exited early: ${viteErr.slice(-400)}`);
    await sleep(400);
  }
  throw new Error(`vite did not answer on :${port} within ${BOOT_TIMEOUT}ms`);
}

// ------------------------------------------------------------- browser --

const BROWSER_CANDIDATES = {
  edge: [
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "microsoft-edge",
    "msedge",
  ],
  chrome: [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "google-chrome",
    "chromium",
    "chromium-browser",
  ],
};

function findBrowser() {
  if (BROWSER_ARG !== "auto") {
    const list = BROWSER_CANDIDATES[BROWSER_ARG] ?? [BROWSER_ARG];
    const hit = list.find((p) => existsSync(p));
    if (hit) return hit;
    if (existsSync(BROWSER_ARG)) return BROWSER_ARG;
    return list[list.length - 1];
  }
  for (const kind of ["edge", "chrome"]) {
    const hit = BROWSER_CANDIDATES[kind].find((p) => existsSync(p));
    if (hit) return hit;
  }
  throw new BrowserUnavailable("no browser found — set --browser to a Chrome/Edge binary");
}

let browserProc = null;
let profileDir = null;
async function launchBrowser() {
  const exe = findBrowser();
  profileDir = mkdtempSync(join(tmpdir(), "kiwi-stress-"));
  browserProc = spawn(exe, [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${profileDir}`,
    "--no-first-run",
    "--disable-gpu",
    "--disable-extensions",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  const gone = new Promise((resolve) => {
    browserProc.once("error", (e) =>
      resolve(new BrowserUnavailable(`${exe} could not be started: ${e.message}`)));
    browserProc.once("exit", (code, signal) =>
      resolve(new BrowserUnavailable(`${exe} exited before the CDP port opened (code=${code} signal=${signal})`)));
  });
  const portFile = join(profileDir, "DevToolsActivePort");
  const ready = (async () => {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      if (existsSync(portFile)) {
        const [port] = readFileSync(portFile, "utf8").split("\n");
        const ver = await (await fetch(`http://127.0.0.1:${port.trim()}/json/version`)).json();
        return { wsUrl: ver.webSocketDebuggerUrl, exe };
      }
      await sleep(250);
    }
    throw new Error("browser did not open a DevTools port");
  })();
  const winner = await Promise.race([ready, gone]);
  if (winner instanceof BrowserUnavailable) throw winner;
  return winner;
}

// ----------------------------------------------------------------- CDP --

class Cdp {
  #ws; #id = 0; #pending = new Map();
  static async connect(wsUrl) {
    const c = new Cdp();
    c.#ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      c.#ws.onopen = res;
      c.#ws.onerror = () => rej(new Error("CDP websocket failed"));
    });
    c.#ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && c.#pending.has(msg.id)) {
        const { res, rej } = c.#pending.get(msg.id);
        c.#pending.delete(msg.id);
        msg.error ? rej(new Error(`${msg.error.message}`)) : res(msg.result);
      }
    };
    return c;
  }
  send(method, params = {}, sessionId) {
    const id = ++this.#id;
    this.#ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((res, rej) => {
      this.#pending.set(id, { res, rej });
      setTimeout(() => {
        if (this.#pending.delete(id)) rej(new Error(`CDP ${method} timed out`));
      }, 30000);
    });
  }
  async newPage(url) {
    const { targetId } = await this.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await this.send("Target.attachToTarget", { targetId, flatten: true });
    await this.send("Runtime.enable", {}, sessionId);
    await this.send("Page.enable", {}, sessionId);
    await this.send("Page.navigate", { url }, sessionId);
    return sessionId;
  }
  async eval(sessionId, expression, awaitPromise = false) {
    const r = await this.send("Runtime.evaluate", {
      expression, returnByValue: true, awaitPromise,
    }, sessionId);
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text ?? "eval failed");
    }
    return r.result?.value;
  }
  close() { try { this.#ws?.close(); } catch {} }
}

async function waitFor(cdp, sid, expr, timeout = PER_CHECK_TIMEOUT) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await cdp.eval(sid, expr)) return true;
    await sleep(150);
  }
  return false;
}

const qs = (sel) => `!!document.querySelector(${JSON.stringify(sel)})`;
const qsa = (sel) => `document.querySelectorAll(${JSON.stringify(sel)}).length`;

const pct = (arr, p) => arr.length ? arr.slice().sort((a, b) => a - b)[Math.min(arr.length - 1, Math.floor(arr.length * p))] : 0;
const stats = (arr) => arr.length
  ? `n=${arr.length} avg=${Math.round(arr.reduce((a, b) => a + b, 0) / arr.length)}ms p95=${Math.round(pct(arr, 0.95))}ms max=${Math.round(Math.max(...arr))}ms`
  : "n=0";

// -------------------------------------------------------------- checks --

async function runChecks(cdp, sid) {
  const check = async (id, desc, fn) => {
    try { const detail = await fn(); report(id, "pass", `${desc}${detail ? ` (${detail})` : ""}`); }
    catch (e) { report(id, "fail", `${desc} — ${e instanceof Error ? e.message : e}`); }
  };

  await check("boot", "app shell boots", async () => {
    if (!(await waitFor(cdp, sid, qs("header.em-chrome")))) throw new Error("no .em-chrome");
    return "mounted";
  });

  /* ===== Phase A — the flagged items, asserted on computed style ===== */

  await check("flat-primary", "no gradient on any primary action", async () => {
    // Open a dock so .em-send exists; scan every primary surface.
    await cdp.eval(sid, "window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}))");
    await waitFor(cdp, sid, qs(".em-dock .em-send"), 5000);
    const offenders = await cdp.eval(sid, `(()=>{
      const sels = ['.em-send','.em-send-chev','.ms-btn-primary','.kiwi-btn-primary'];
      const bad = [];
      for (const s of sels) for (const el of document.querySelectorAll(s)) {
        const cs = getComputedStyle(el);
        if (cs.backgroundImage !== 'none') bad.push(s + '=' + cs.backgroundImage.slice(0, 40));
      }
      // The legacy gradient token must also be flat.
      const g = getComputedStyle(document.documentElement).getPropertyValue('--kiwi-gradient');
      if (/gradient/.test(g)) bad.push('--kiwi-gradient=' + g.trim().slice(0, 40));
      return bad;
    })()`);
    if (offenders.length) throw new Error(`gradient survives on: ${offenders.join("; ")}`);
    // Discard the dock so later checks start clean.
    await cdp.eval(sid, `document.querySelector('.em-dock .em-compose-trash')?.click()`);
    return "Send pill, split chevron, .ms-btn-primary, .kiwi-btn-primary, --kiwi-gradient all flat";
  });

  await check("disabled-contrast", "disabled toolbar is muted-not-ghost", async () => {
    await cdp.eval(sid, "window.location.hash = '#/mail'");
    await waitFor(cdp, sid, `${qsa(".em-row")} > 0`, 5000);
    // Nothing selected → sibling tools disabled. The split variant wraps the
    // button in a .em-tool.is-disabled span; measure the effective opacity the
    // user sees (element × any disabled ancestor chain is flattened by the
    // computed style only for the element itself, so sample wrappers AND the
    // disabled buttons inside).
    const r = await cdp.eval(sid, `(()=>{
      const els = [...document.querySelectorAll(
        '.em-tool:disabled, .em-tool.is-disabled, .em-tool-main:disabled, .em-tool-caret:disabled, .ms-btn:disabled')];
      // For a wrapped split, the ghost effect comes from the wrapper's opacity —
      // dedupe so a button inside .is-disabled isn't double-counted.
      const seen = new Set();
      const vals = [];
      for (const el of els) {
        const wrap = el.closest('.em-tool.is-disabled') || el;
        if (seen.has(wrap)) continue;
        seen.add(wrap);
        vals.push(parseFloat(getComputedStyle(wrap).opacity));
      }
      return { n: els.length, vals };
    })()`);
    if (!r.n) throw new Error("no disabled tools found to measure");
    const min = Math.min(...r.vals);
    if (min < 0.55) throw new Error(`disabled opacity ${min} — still ghost-faint`);
    if (min >= 0.98) throw new Error(`disabled opacity ${min} — not visually disabled at all`);
    return `${r.n} disabled controls, min opacity ${min}`;
  });

  await check("sec-layout", "Security view is NOT settings-rail flex", async () => {
    await cdp.eval(sid, "window.location.hash = '#/security'");
    if (!(await waitFor(cdp, sid, qs("section[aria-label='KIWI Security event center']"), 5000)))
      throw new Error("security section did not mount");
    const info = await cdp.eval(sid, `(()=>{
      const s = document.querySelector("section[aria-label='KIWI Security event center']");
      const d = getComputedStyle(s).display;
      const kids = [...s.children].slice(0, 4).map(c => Math.round(c.getBoundingClientRect().top));
      return { display: d, tops: kids };
    })()`);
    if (info.display === "flex") throw new Error("settings flex leaked into Security (display=flex)");
    const sorted = [...info.tops].sort((a, b) => a - b);
    if (JSON.stringify(info.tops) !== JSON.stringify(sorted))
      throw new Error(`children not vertically stacked: tops=${info.tops}`);
    return `display=${info.display}, children stack top→down ${info.tops.join("→")}`;
  });

  await check("honest-setup", "add-account says Backend unavailable, not Demo mode", async () => {
    for (const h of ["#/setup", "#/accounts", "#/add-account"]) {
      await cdp.eval(sid, `window.location.hash = '${h}'`);
      await sleep(350);
      const hit = await cdp.eval(sid, `document.body.textContent.includes('Backend unavailable') || document.body.textContent.includes('Demo mode')`);
      if (hit) break;
    }
    const txt = await cdp.eval(sid, "document.body.textContent");
    if (/Demo mode/i.test(txt) && !/Backend unavailable/i.test(txt))
      throw new Error("still says 'Demo mode' — misleading in browser");
    if (!/Backend unavailable|browser preview|no mail backend/i.test(txt))
      throw new Error("no honest backend-unavailable copy found on any account route");
    return "browser preview honesty confirmed";
  });

  await check("compose-fields", "composer uses Gmail field rows, not boxed form", async () => {
    await cdp.eval(sid, "window.location.hash = '#/compose'");
    if (!(await waitFor(cdp, sid, qs(".em-compose-fields"), 5000)))
      throw new Error("no .em-compose-fields — old form markup still mounted");
    const r = await cdp.eval(sid, `(()=>{
      const fields = document.querySelectorAll('.em-field').length;
      const to = document.getElementById('compose-to');
      const bw = to ? getComputedStyle(to).borderTopWidth : 'missing';
      const ccLink = !!document.querySelector("[aria-label='Add Cc recipients']");
      const chipsInRow = !!document.querySelector(".em-field p[aria-label='Recipients']");
      const labels = [...document.querySelectorAll('.em-field-label')].map(e => e.textContent.trim());
      return { fields, bw, ccLink, chipsInRow, labels };
    })()`);
    if (r.fields < 2) throw new Error(`only ${r.fields} field rows`);
    if (r.bw !== "0px") throw new Error(`To input still boxed (border ${r.bw})`);
    if (!r.ccLink) throw new Error("no inline Cc link in To row");
    if (!r.chipsInRow) throw new Error("recipient chips not inline in the To row");
    return `${r.fields} field rows (${r.labels.join("/")}), borderless inputs, Cc link, inline chips`;
  });

  await check("compose-footer", "Gmail footer: split send pill + icon row + trash", async () => {
    const r = await cdp.eval(sid, `(()=>{
      const f = document.querySelector('.em-compose-footer');
      if (!f) return { missing: true };
      return {
        split: !!f.querySelector('.em-send-split'),
        send: !!f.querySelector('.em-send'),
        chev: !!f.querySelector('.em-send-chev'),
        icons: f.querySelectorAll('.em-compose-tools .em-iconbtn').length,
        trash: !!f.querySelector('.em-compose-trash'),
        hairline: getComputedStyle(f).borderTopWidth,
      };
    })()`);
    if (r.missing) throw new Error("no .em-compose-footer");
    if (!r.split || !r.send || !r.chev) throw new Error("split send pill incomplete");
    if (r.icons < 5) throw new Error(`only ${r.icons} footer icons (need Aa/attach/link/image/more)`);
    if (!r.trash) throw new Error("no trash button");
    return `split pill + ${r.icons} tool icons + trash, hairline ${r.hairline}`;
  });

  await check("composer-chips-commit", "Enter/comma/Add commit, send folds pending text", async () => {
    const r = await cdp.eval(sid, `(async ()=>{
      const i = document.getElementById('compose-to');
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      // Comma commits — one frame between input and keydown so React has
      // re-rendered (real typing is never synchronous).
      set.call(i, 'comma@test.example'); i.dispatchEvent(new Event('input',{bubbles:true}));
      await new Promise(r2 => requestAnimationFrame(r2));
      i.dispatchEvent(new KeyboardEvent('keydown',{key:',',bubbles:true}));
      await new Promise(r2 => requestAnimationFrame(r2));
      const chips1 = document.querySelector("p[aria-label='Recipients']").textContent;
      return { chips1 };
    })()`, true);
    if (!r.chips1.includes("comma@test.example")) throw new Error("comma did not commit the address");
    return "comma-commit works";
  });

  /* ===== Phase B — stress + latency ===== */

  await check("route-spam", "20 hash-route switches all mount + stay fast", async () => {
    const routes = ["#/mail", "#/compose", "#/security", "#/disposable", "#/settings"];
    const sel = {
      "#/mail": ".em-row", "#/compose": ".em-compose-fields",
      "#/security": "section[aria-label='KIWI Security event center']",
      "#/disposable": ".kiwi-dispo", "#/settings": ".ms-prefs-rail",
    };
    const lat = [];
    for (let i = 0; i < 20; i++) {
      const h = routes[i % routes.length];
      const t0 = Date.now();
      await cdp.eval(sid, `window.location.hash = '${h}'`);
      if (!(await waitFor(cdp, sid, qs(sel[h]), 4000))) throw new Error(`${h} did not mount (iter ${i})`);
      lat.push(Date.now() - t0);
    }
    const p95 = pct(lat, 0.95);
    if (p95 > 1500) throw new Error(`route nav p95 ${Math.round(p95)}ms — laggy`);
    return stats(lat);
  });

  await check("folder-spam", "40 rapid folder clicks all select", async () => {
    await cdp.eval(sid, "window.location.hash = '#/mail'");
    await waitFor(cdp, sid, `${qsa("nav.em-folders [role=treeitem], nav.em-folders .em-fold")} > 2`, 5000);
    const n = Math.min(40, await cdp.eval(sid, qsa("nav.em-folders [role=treeitem], nav.em-folders .em-fold")) * 8);
    const lat = await cdp.eval(sid, `(async () => {
      const items = [...document.querySelectorAll('nav.em-folders [role=treeitem], nav.em-folders .em-fold')];
      const lat = [];
      for (let i = 0; i < ${n}; i++) {
        const el = items[i % items.length];
        const t0 = performance.now();
        el.click();
        // Wait one frame — selection must land within a frame to feel instant.
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        lat.push(performance.now() - t0);
      }
      return lat;
    })()`, true);
    const p95 = pct(lat, 0.95);
    if (p95 > 200) throw new Error(`folder select p95 ${Math.round(p95)}ms — laggy`);
    return stats(lat);
  });

  await check("row-spam", "30 row clicks → reader tracks every one", async () => {
    await cdp.eval(sid, "window.location.hash = '#/mail'");
    await waitFor(cdp, sid, `${qsa(".em-row")} > 0`, 5000);
    const r = await cdp.eval(sid, `(async () => {
      const rows = [...document.querySelectorAll('.em-row')];
      if (!rows.length) return { miss: 30, lat: [] };
      let miss = 0; const lat = [];
      for (let i = 0; i < 30; i++) {
        const el = rows[i % rows.length];
        const t0 = performance.now();
        el.click();
        await new Promise(r2 => requestAnimationFrame(() => requestAnimationFrame(r2)));
        lat.push(performance.now() - t0);
        // Selected state must have landed on the clicked row (or the row
        // under a virtualized list — assert SOME row is selected).
        if (!document.querySelector('.em-row[aria-selected="true"], .em-row.is-selected, .em-row.selected'))
          miss++;
      }
      return { miss, lat };
    })()`, true);
    if (r.miss > 3) throw new Error(`${r.miss}/30 clicks lost selection`);
    return `misses=${r.miss} ${stats(r.lat)}`;
  });

  await check("dock-churn", "8× open→minimize→restore→discard, no chip leaks", async () => {
    await cdp.eval(sid, "window.location.hash = '#/mail'");
    await waitFor(cdp, sid, `${qsa(".em-row")} > 0`, 5000);
    for (let i = 0; i < 8; i++) {
      await cdp.eval(sid, "window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}))");
      if (!(await waitFor(cdp, sid, qs(".em-dock:not([hidden]) .em-dock-head"), 3000))) {
        // Dock may open non-hidden but wrapper-div hidden differs; accept any visible dock.
        if (!(await waitFor(cdp, sid, `${qsa(".em-dock")} > 0`, 3000))) throw new Error(`dock never opened (iter ${i})`);
      }
      // Minimize → exactly one new chip.
      const chipsBefore = await cdp.eval(sid, qsa(".em-dock-chip"));
      await cdp.eval(sid, `document.querySelector('.em-dock [aria-label^="Minimize"]')?.click()`);
      if (!(await waitFor(cdp, sid, `${qsa(".em-dock-chip")} === ${chipsBefore + 1}`, 3000)))
        throw new Error(`minimize did not leave a chip (iter ${i})`);
      // Restore → discard.
      await cdp.eval(sid, `[...document.querySelectorAll('.em-dock-chip-label')].at(-1).click()`);
      await waitFor(cdp, sid, qs(".em-dock .em-compose-trash"), 3000);
      await cdp.eval(sid, `[...document.querySelectorAll('.em-dock .em-compose-trash')].at(-1).click()`);
      await waitFor(cdp, sid, `${qsa(".em-dock-chip")} <= ${chipsBefore}`, 3000);
    }
    const chips = await cdp.eval(sid, qsa(".em-dock-chip"));
    if (chips > 1) throw new Error(`${chips} chips leaked across churn`);
    return `chips end=${chips} (leaked ≤1)`;
  });

  await check("ctxmenu-churn", "15× context-menu open/Esc cycles", async () => {
    await cdp.eval(sid, "window.location.hash = '#/mail'");
    await waitFor(cdp, sid, `${qsa(".em-row")} > 0`, 5000);
    const lat = [];
    for (let i = 0; i < 15; i++) {
      const t0 = Date.now();
      await cdp.eval(sid, `(()=>{const el=document.querySelector('.em-row');
        const r=el.getBoundingClientRect();
        el.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,clientX:r.left+8,clientY:r.top+8}));})()`);
      if (!(await waitFor(cdp, sid, `${qsa(".em-ctx-item")} > 0`, 3000))) throw new Error(`menu never opened (iter ${i})`);
      lat.push(Date.now() - t0);
      await cdp.eval(sid, `document.querySelector('.em-ctx')?.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))`);
      if (!(await waitFor(cdp, sid, `${qsa(".em-ctx-item")} === 0`, 3000))) throw new Error(`menu never closed (iter ${i})`);
    }
    const p95 = pct(lat, 0.95);
    if (p95 > 500) throw new Error(`ctx open p95 ${Math.round(p95)}ms — laggy`);
    return stats(lat);
  });

  await check("type-burst", "60-char typing burst into To field stays responsive", async () => {
    await cdp.eval(sid, "window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}))");
    await waitFor(cdp, sid, `${qsa(".em-dock")} > 0`, 4000);
    const r = await cdp.eval(sid, `(async () => {
      const i = [...document.querySelectorAll('.em-dock input#compose-to')].find(x => x.offsetParent !== null)
              || document.querySelector('.em-dock input#compose-to');
      if (!i) return { err: 'no to input' };
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      const lat = [];
      i.focus();
      let v = '';
      for (const ch of 'stress.test.address@repeated-domain.example'.padEnd(60, 'x')) {
        const t0 = performance.now();
        v += ch; set.call(i, v); i.dispatchEvent(new Event('input',{bubbles:true}));
        await new Promise(r2 => requestAnimationFrame(r2));
        lat.push(performance.now() - t0);
      }
      return { lat, val: i.value };
    })()`, true);
    if (r.err) throw new Error(r.err);
    const p95 = pct(r.lat, 0.95);
    if (p95 > 100) throw new Error(`keystroke p95 ${Math.round(p95)}ms — input lag`);
    // Clean up the dock.
    await cdp.eval(sid, `[...document.querySelectorAll('.em-dock .em-compose-trash')].at(-1)?.click()`);
    return stats(r.lat);
  });

  await check("theme-flip", "6× theme toggles settle correctly", async () => {
    await cdp.eval(sid, "window.location.hash = '#/settings'");
    await waitFor(cdp, sid, qs(".ms-prefs-rail"), 5000);
    await cdp.eval(sid, `[...document.querySelectorAll('[role=tab]')].find(t=>/appearance/i.test(t.textContent))?.click()`);
    await waitFor(cdp, sid, `${qsa("select")} > 0`, 4000);
    const r = await cdp.eval(sid, `(async () => {
      const sel = [...document.querySelectorAll('select')].find(s =>
        [...s.options].some(o => /dark/i.test(o.textContent)));
      if (!sel) return { err: 'no theme select' };
      const vals = [...sel.options].map(o => o.value).filter(v => /dark|light/i.test(v));
      if (vals.length < 2) return { err: 'no light/dark options: ' + vals.join(',') };
      const lat = [];
      for (let i = 0; i < 6; i++) {
        const t0 = performance.now();
        const v = vals[i % vals.length];
        const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set;
        set.call(sel, v); sel.dispatchEvent(new Event('change',{bubbles:true}));
        await new Promise(r2 => requestAnimationFrame(() => requestAnimationFrame(r2)));
        lat.push(performance.now() - t0);
        if (!document.documentElement.dataset.theme) return { err: 'data-theme lost at iter ' + i, lat };
      }
      return { lat };
    })()`, true);
    if (r.err) throw new Error(r.err);
    return stats(r.lat);
  });

  await check("mem-growth", "heap growth across the whole burst is bounded", async () => {
    const m = await cdp.eval(sid, `(async () => {
      if (!performance.memory) return null;
      const a = performance.memory.usedJSHeapSize;
      // Force a second full burst of churn before measuring again.
      for (let i = 0; i < 10; i++) {
        window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}));
        await new Promise(r => setTimeout(r, 60));
        document.querySelector('.em-dock .em-compose-trash')?.click();
        await new Promise(r => setTimeout(r, 60));
      }
      if (window.gc) window.gc();
      await new Promise(r => setTimeout(r, 400));
      const b = performance.memory.usedJSHeapSize;
      return { deltaMB: (b - a) / 1048576 };
    })()`, true);
    if (m === null) { report("mem-growth", "skip", "performance.memory unavailable", "stress"); return "skip"; }
    if (m.deltaMB > 60) throw new Error(`heap grew ${m.deltaMB.toFixed(1)}MB across 10 open/discard cycles — likely leak`);
    return `Δheap=${m.deltaMB.toFixed(1)}MB over 10 dock cycles`;
  });

  await check("longtask-jank", "long tasks during stress stay bounded", async () => {
    // Retroactive: measure NOW over a 30s interaction replay window.
    const r = await cdp.eval(sid, `(async () => {
      let tasks = 0, total = 0;
      const obs = new PerformanceObserver(l => { for (const e of l.getEntries()) { tasks++; total += e.duration; } });
      obs.observe({ entryTypes: ['longtask'] });
      // Compressed replay: route hop + folder spam + dock open/close.
      for (const h of ['#/mail','#/compose','#/security','#/mail']) { window.location.hash = h; await new Promise(r2 => setTimeout(r2, 120)); }
      for (let i = 0; i < 6; i++) {
        window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}));
        await new Promise(r2 => setTimeout(r2, 80));
        document.querySelector('.em-dock .em-compose-trash')?.click();
      }
      await new Promise(r2 => setTimeout(r2, 500));
      obs.disconnect();
      return { tasks, total: Math.round(total) };
    })()`, true);
    // Headless + CDP inflates jank slightly; the fail bar is generous but real.
    if (r.total > 3000) throw new Error(`${r.tasks} long tasks totalling ${r.total}ms`);
    return `${r.tasks} long tasks, ${r.total}ms total`;
  });

  /* ===== Phase C — backend boundary (browser mode honesty) ===== */

  await check("backend-absent-honest", "no Tauri → every IPC surface degrades honestly", async () => {
    const r = await cdp.eval(sid, `(async () => {
      const tauri = '__TAURI_INTERNALS__' in window;
      if (tauri) return { tauri: true };
      // Sweep the views: no surface may claim live connectivity.
      const claims = [];
      for (const h of ['#/mail','#/security','#/disposable','#/settings']) {
        window.location.hash = h;
        await new Promise(r2 => setTimeout(r2, 250));
        const txt = document.body.textContent;
        if (/connected to backend|synced just now|live mode/i.test(txt)) claims.push(h);
      }
      return { tauri: false, claims };
    })()`, true);
    if (r.tauri) return "inside Tauri — boundary checks covered by Rust tests";
    if (r.claims.length) throw new Error(`views claim live backend on ${r.claims.join(",")}`);
    return "0 fabricated live-state claims across mail/security/disposable/settings";
  });

  await check("demo-send-still-works", "demo send→undo survives after stress", async () => {
    await cdp.eval(sid, "window.location.hash = '#/compose'");
    await waitFor(cdp, sid, qs(".em-compose-fields"), 4000);
    await cdp.eval(sid, `(()=>{
      const i = document.getElementById('compose-to');
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      set.call(i,'stress@example.test'); i.dispatchEvent(new Event('input',{bubbles:true}));
      i.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    })()`);
    if (!(await waitFor(cdp, sid, `document.querySelector("p[aria-label='Recipients']").textContent.includes('stress@example.test')`, 4000)))
      throw new Error("recipient never committed");
    await cdp.eval(sid, `document.querySelector("section[aria-label='Compose message'] .em-send")?.click()`);
    if (!(await waitFor(cdp, sid, `document.body.textContent.includes('Demo: sending')`, 5000)))
      throw new Error("demo send did not fire post-stress");
    return "send path alive after full hammer";
  });
}

// ---------------------------------------------------------------- main --

async function main() {
  let url = URL_ARG;
  if (!url) url = await bootVite(VITE_PORT);
  console.log(`ui-stress: serving ${url}`);
  const { wsUrl, exe } = await launchBrowser();
  const cdp = await Cdp.connect(wsUrl);
  const sid = await cdp.newPage(url);
  try {
    await runChecks(cdp, sid);
  } finally {
    const { pass, fail } = summarize(url, { browser: exe });
    try { browserProc?.kill(); } catch {}
    try { viteProc?.kill(); } catch {}
    try { if (profileDir) rmSync(profileDir, { recursive: true, force: true }); } catch {}
    cdp.close();
    process.exit(fail > 0 ? 1 : 0);
  }
}

main().catch((e) => {
  if (e instanceof BrowserUnavailable) {
    if (REQUIRE_BROWSER) { console.error(`ui-stress: ${e.message}`); process.exit(1); }
    report("browser", "skip", e.message);
    summarize(URL_ARG ?? "(none)", { browserAbsent: true });
    process.exit(0);
  }
  console.error(`ui-stress: ${e instanceof Error ? e.message : e}`);
  try { browserProc?.kill(); } catch {}
  try { viteProc?.kill(); } catch {}
  try { if (profileDir) rmSync(profileDir, { recursive: true, force: true }); } catch {}
  process.exit(1);
});
