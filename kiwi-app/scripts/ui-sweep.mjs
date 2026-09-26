#!/usr/bin/env node
/**
 * ui-sweep.mjs — CDP-driven visual/UX defect sweep for kiwi-app (A25 UI-sweep).
 *
 * Unlike ui-smoke.mjs (assertions), this WALKS every view and collects
 * evidence: per stop it screenshots the real rendered DOM into
 * artifacts/ui-sweep/ and runs an in-page audit for:
 *   - console errors / warnings captured since the last stop
 *   - horizontal overflow offenders (scrollWidth > clientWidth)
 *   - interactive controls with no accessible name
 *   - zero-size / clipped widgets
 *   - text contrast below WCAG AA (4.5:1 normal, 3:1 large)
 *   - icon-only buttons whose icon failed to render (no svg, no text)
 *   - bare-text empty states (not wrapped in .kiwi-empty)
 * Findings are evidence, not verdicts — screenshots + the JSON report get
 * eyeballed before any fix lands.
 *
 * Usage: node scripts/ui-sweep.mjs [--url ...] [--port 1422] [--keep]
 *        [--shots dir] [--stop name]
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
const KEEP = args.includes("--keep");
const ONLY = arg("stop", null);
const BOOT_TIMEOUT = 30000;
const SHOTS = arg("shots", join(fileURLToPath(new URL("..", import.meta.url)), "..", "artifacts", "ui-sweep"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  throw new Error(`vite did not answer on :${port}`);
}

// ------------------------------------------------------------- browser --

const BROWSER_CANDIDATES = {
  edge: [
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "msedge",
  ],
  chrome: [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "chrome",
    "chromium",
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
  throw new Error("no browser found — set --browser/KIWI_SMOKE_BROWSER");
}

let browserProc = null;
let profileDir = null;
async function launchBrowser() {
  const exe = findBrowser();
  profileDir = mkdtempSync(join(tmpdir(), "kiwi-sweep-"));
  browserProc = spawn(exe, [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${profileDir}`,
    "--no-first-run",
    "--disable-gpu",
    "--disable-extensions",
    "--window-size=1440,900",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  const portFile = join(profileDir, "DevToolsActivePort");
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
}

// ----------------------------------------------------------------- CDP --

class Cdp {
  #ws; #id = 0; #pending = new Map(); #events = [];
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
        msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
      } else if (msg.method) {
        c.#events.push(msg);
      }
    };
    return c;
  }
  drain() { const e = this.#events.splice(0); return e; }
  send(method, params = {}, sessionId) {
    const id = ++this.#id;
    this.#ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((res, rej) => {
      this.#pending.set(id, { res, rej });
      setTimeout(() => {
        if (this.#pending.delete(id)) rej(new Error(`CDP ${method} timed out`));
      }, 20000);
    });
  }
  async newPage(url) {
    const { targetId } = await this.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await this.send("Target.attachToTarget", { targetId, flatten: true });
    await this.send("Runtime.enable", {}, sessionId);
    await this.send("Log.enable", {}, sessionId);
    await this.send("Page.enable", {}, sessionId);
    await this.send("Emulation.setDeviceMetricsOverride",
      { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
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
  async shot(sessionId, file) {
    const r = await this.send("Page.captureScreenshot", { format: "png" }, sessionId);
    writeFileSync(file, Buffer.from(r.data, "base64"));
  }
  close() { try { this.#ws?.close(); } catch {} }
}

async function waitFor(cdp, sid, expr, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { if (await cdp.eval(sid, expr)) return true; } catch { /* transient nav */ }
    await sleep(200);
  }
  return false;
}

// ----------------------------------------------------------- page audit --

const AUDIT = `(() => {
  const out = { overflow: [], unnamed: [], zeroSize: [], contrast: [], noIcon: [], bareEmpty: [] };
  const vis = (el) => {
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden" || Number(s.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const tag = (el) => {
    const id = el.id ? "#" + el.id : "";
    const cls = (el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\\s+/).slice(0, 2).join(".") : "");
    return el.tagName.toLowerCase() + id + cls;
  };
  const accName = (el) => {
    // Native accessible-name sources for form controls: wrapping <label>,
    // label[for], aria-* — my earlier textContent check missed all three.
    const wrap = el.closest("label");
    if (wrap && (wrap.textContent || "").trim()) return "wrap-label";
    if (el.id && document.querySelector('label[for="' + el.id + '"]')) return "label-for";
    return el.getAttribute("aria-label") || el.getAttribute("aria-labelledby")
      || (el.textContent || "").trim() || el.getAttribute("title")
      || (el.getAttribute("value") ?? "") || el.getAttribute("placeholder") || "";
  };
  // horizontal overflow — only flag elements not allowed to scroll
  for (const el of document.querySelectorAll("body *")) {
    if (!vis(el)) continue;
    const s = getComputedStyle(el);
    if (/(auto|scroll|hidden|clip)/.test(s.overflowX)) continue;
    if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 40)
      out.overflow.push({ el: tag(el), over: el.scrollWidth - el.clientWidth });
  }
  // unnamed interactive controls
  for (const el of document.querySelectorAll("button, a[href], input, select, textarea, [role=button], [role=tab], [role=menuitem], [role=treeitem], [role=switch]")) {
    if (!vis(el) || el.disabled || el.closest("button[disabled],[aria-disabled=true]")) continue;
    const name = accName(el);
    if (!name) {
      const hasSvg = !!el.querySelector("svg");
      const hasImg = !!el.querySelector("img[src]");
      (hasSvg || hasImg ? out.noIcon : out.unnamed).push({ el: tag(el), icon: hasSvg });
      if (hasSvg === false && hasImg === false) out.unnamed[out.unnamed.length - 1].icon = false;
    }
  }
  // zero-size interactive
  for (const el of document.querySelectorAll("button, input, select, [role=button], [role=tab]")) {
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden") continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) out.zeroSize.push({ el: tag(el), w: +r.width.toFixed(1), h: +r.height.toFixed(1) });
  }
  // contrast — text-bearing leaf nodes
  const lum = (c) => {
    const m = c.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)(?:,\\s*([\\d.]+))?\\)/);
    if (!m) return null;
    const f = (v) => { v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return { l: 0.2126 * f(+m[1]) + 0.7152 * f(+m[2]) + 0.0722 * f(+m[3]), a: m[4] === undefined ? 1 : +m[4] };
  };
  const bgOf = (el) => {
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
      const c = lum(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0.85) return c.l;
    }
    return lum(getComputedStyle(document.body).backgroundColor)?.l ?? 1;
  };
  const disabledCtx = (el) =>
    el.disabled ||
    el.closest("[disabled], [aria-disabled=true], .is-disabled, :disabled");
  const seen = new Set();
  let gradientSkipped = 0;
  for (const el of document.querySelectorAll("body *")) {
    if (out.contrast.length >= 25) break;
    if (!vis(el) || el.closest("[aria-hidden=true]")) continue;
    const txt = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 0);
    if (!txt) continue;
    const s = getComputedStyle(el);
    if (disabledCtx(el)) continue;
    if (s.cursor === "not-allowed") continue;
    // gradient/image backdrops fool the solid-color walk — needs eyeballing
    let grad = false;
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
      const bi = getComputedStyle(n).backgroundImage;
      if (bi && bi !== "none") { grad = true; break; }
      const c = lum(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0.85) break;
    }
    if (grad) { gradientSkipped++; continue; }
    const fg = lum(s.color); if (!fg) continue;
    const bg = bgOf(el);
    const ratio = (Math.max(fg.l, bg) + 0.05) / (Math.min(fg.l, bg) + 0.05);
    const fs = parseFloat(s.fontSize);
    const large = fs >= 24 || (fs >= 18.66 && parseInt(s.fontWeight) >= 700);
    const need = large ? 3 : 4.5;
    if (ratio < need) {
      const k = tag(el) + "|" + s.color;
      if (seen.has(k)) continue;
      seen.add(k);
      out.contrast.push({ el: tag(el), ratio: +ratio.toFixed(2), need, fg: s.color, text: (el.textContent || "").trim().slice(0, 40) });
    }
  }
  if (gradientSkipped) out.gradientSkipped = gradientSkipped;
  // bare empty states — "No X"/"Nothing" text outside the kiwi-empty idiom
  for (const el of document.querySelectorAll("p, small, div, span")) {
    const t = (el.textContent || "").trim();
    if (!/^(no |nothing |none |empty )/i.test(t) || t.length > 120) continue;
    if (el.children.length > 0 && el.tagName !== "P" && el.tagName !== "DIV") continue;
    if (el.closest(".kiwi-empty, .em-empty, .kiwi-palette-empty, .em-ctx, [role=alert], [role=note], [role=status]")) continue;
    if (el.closest(".kiwi-dispo, .em-rows")) continue; // inbox lists have their own idiom
    if (vis(el)) out.bareEmpty.push({ el: tag(el), text: t.slice(0, 60) });
  }
  return out;
})()`;

// --------------------------------------------------------------- stops --

const stops = [
  { id: "mail-inbox", go: "#/mail", wait: `!!document.querySelector('.em-rows')` },
  {
    id: "mail-reader", go: "#/mail",
    pre: `document.querySelector('.em-row')?.click()`,
    wait: `!!document.querySelector('.em-reader')`,
  },
  { id: "compose", go: "#/compose", wait: `!!document.querySelector("section[aria-label='Compose message']")` },
  {
    id: "compose-filled", go: "#/compose",
    pre: `(() => {
      const i = document.querySelector('#compose-subject') || [...document.querySelectorAll('input')].find(x => (x.closest('.em-field')?.textContent||'').includes('Subject'));
      if (i) { const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; s.call(i,'Sweep subject line'); i.dispatchEvent(new Event('input',{bubbles:true})); }
    })()`,
    wait: `!!document.querySelector("section[aria-label='Compose message']")`,
  },
  {
    id: "compose-dock", go: "#/compose",
    pre: `(() => {
      const i = document.querySelector('#compose-subject') || [...document.querySelectorAll('input')].find(x => (x.closest('.em-field')?.textContent||'').includes('Subject'));
      if (i) { const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; s.call(i,'Dock sweep'); i.dispatchEvent(new Event('input',{bubbles:true})); }
      setTimeout(() => { window.location.hash = '#/mail'; }, 150);
    })()`,
    wait: `!!document.querySelector('.em-dock, .em-dock-chip')`,
    settle: 900,
  },
  { id: "contacts", go: "#/contacts", wait: `document.readyState==='complete'`, settle: 700 },
  { id: "filters", go: "#/filters", wait: `document.readyState==='complete'`, settle: 700 },
  { id: "security", go: "#/security", wait: `document.readyState==='complete'`, settle: 900 },
  { id: "disposable", go: "#/disposable", wait: `!!document.querySelector('.kiwi-dispo')`, settle: 500 },
  { id: "search", go: "#/search", wait: `document.readyState==='complete'`, settle: 700 },
  { id: "setup", go: "#/setup", wait: `document.readyState==='complete'`, settle: 700 },
  {
    id: "palette", go: "#/mail",
    pre: `document.querySelector('[aria-label="Open command palette"]')?.click()`,
    wait: `!!document.querySelector('.kiwi-palette')`,
    settle: 400,
  },
  {
    id: "palette-query", go: "#/mail",
    pre: `(() => {
      document.querySelector('[aria-label="Open command palette"]')?.click();
      setTimeout(() => {
        const i = document.querySelector('.kiwi-palette input');
        if (i) { const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; s.call(i,'zzz-no-match'); i.dispatchEvent(new Event('input',{bubbles:true})); }
      }, 250);
    })()`,
    wait: `!!document.querySelector('.kiwi-palette-empty, .kiwi-palette')`,
    settle: 700,
  },
  {
    id: "shortcuts", go: "#/mail",
    pre: `document.querySelector('[aria-label="Show keyboard shortcuts"]')?.click()`,
    wait: `!!document.querySelector('[role=dialog]')`,
    settle: 400,
  },
  {
    id: "ctxmenu", go: "#/mail",
    pre: `(() => { const el = document.querySelector('.em-row'); if (!el) return; const r = el.getBoundingClientRect();
      el.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,clientX:r.left+40,clientY:r.top+8})); })()`,
    wait: `!!document.querySelector('.em-ctx')`,
    settle: 400,
  },
  {
    id: "hamburger", go: "#/mail",
    pre: `document.querySelector('[aria-label="Application menu"]')?.click()`,
    wait: `!!document.querySelector('[role=menu], .em-menu')`,
    settle: 400,
  },
];

// Settings tabs are stops too — the tab strip is a full surface.
const SETTINGS_TABS = ["General", "Accounts", "Identity", "Appearance", "Shortcuts", "Mail Rules", "Integrations", "Plugins", "About"];
for (const t of SETTINGS_TABS) {
  stops.push({
    id: `settings-${t.toLowerCase().replace(/\s+/g, "-")}`,
    go: "#/settings",
    pre: `[...document.querySelectorAll("button[role=tab]")].find(b=>b.textContent.trim()===${JSON.stringify(t)})?.click()`,
    wait: `document.querySelector("[role=tabpanel] h1")?.textContent?.trim()===${JSON.stringify(t)}`,
    settle: 600,
  });
}

// ---------------------------------------------------------------- main --

async function main() {
  mkdirSync(SHOTS, { recursive: true });
  let url = URL_ARG;
  if (!url) url = await bootVite(VITE_PORT);
  console.log(`ui-sweep: serving ${url}`);
  const { wsUrl, exe } = await launchBrowser();
  console.log(`ui-sweep: browser ${exe}`);
  const cdp = await Cdp.connect(wsUrl);
  const sid = await cdp.newPage(url);
  const report = {};
  try {
    if (!(await waitFor(cdp, sid, "document.readyState === 'complete' && document.getElementById('root')?.children.length > 0", BOOT_TIMEOUT)))
      throw new Error("app did not mount");
    await sleep(800);
    cdp.drain();
    for (const stop of stops) {
      if (ONLY && stop.id !== ONLY) continue;
      try {
        // Reset UI state between stops: Escape open dialogs/menus (palette,
        // shortcuts overlay, ctx menus, hamburger) then land on the route.
        await cdp.eval(sid, `(() => {
          // React onKeyDown lives on elements inside #root — dispatch Escape
          // on each open overlay AND on body (for native doc/window handlers),
          // then a document mousedown for useDismissable-style menus.
          for (const el of document.querySelectorAll('[role=dialog], .kiwi-palette, .em-ctx, [role=menu], .kiwi-dialog-backdrop'))
            el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
          document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
          document.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
          document.querySelector('.kiwi-dialog-backdrop')?.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
        })()`);
        await sleep(250);
        await cdp.eval(sid, `window.location.hash = ${JSON.stringify(stop.go)}`);
        if (stop.pre) { await sleep(300); await cdp.eval(sid, stop.pre); }
        if (stop.wait) await waitFor(cdp, sid, stop.wait, 8000);
        await sleep(stop.settle ?? 350);
        const audit = await cdp.eval(sid, AUDIT);
        const consoleErrs = cdp.drain()
          .filter((m) => (m.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(m.params?.type))
            || (m.method === "Log.entryAdded" && ["error", "warning"].includes(m.params?.entry?.level)))
          .map((m) => m.params?.entry?.text ?? (m.params?.args || []).map((a) => a.value ?? a.description ?? "").join(" "))
          .filter((t) => t && !/favicon|DevTools|Autofill|vite.*hmr|\[vite\]/i.test(t));
        if (consoleErrs.length) audit.consoleErrors = [...new Set(consoleErrs)].slice(0, 8);
        const shot = join(SHOTS, `${stop.id}.png`);
        await cdp.shot(sid, shot);
        report[stop.id] = audit;
        const n = Object.values(audit).reduce((a, v) => a + (Array.isArray(v) ? v.length : 0), 0);
        console.log(`${String(stop.id).padEnd(20)} ${n} finding(s)`);
      } catch (e) {
        report[stop.id] = { error: e instanceof Error ? e.message : String(e) };
        console.log(`${String(stop.id).padEnd(20)} STOP-ERROR: ${report[stop.id].error}`);
      }
    }
  } finally {
    cdp.close();
  }
  writeFileSync(join(SHOTS, "sweep-report.json"), JSON.stringify(report, null, 2));
  console.log(`ui-sweep: report + ${Object.keys(report).length} screenshots → ${SHOTS}`);
}

main().catch((e) => {
  console.error(`ui-sweep fatal: ${e instanceof Error ? e.message : e}`);
  process.exitCode = 1;
}).finally(() => {
  if (!KEEP) {
    try { viteProc?.kill(); } catch {}
    try { browserProc?.kill(); } catch {}
    if (profileDir) { try { rmSync(profileDir, { recursive: true, force: true }); } catch {} }
  }
});
