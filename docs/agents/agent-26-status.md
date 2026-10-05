# Agent 26 — status log

Scope: read-mostly audit and CI hardening. Current assignment: **T-194**
(claimed 2026-09-26; previous assignments T-336/T-344/T-346 below).

## 2026-09-26 — T-194: mobile authenticator screens (mock transport)

**Status:** DONE — evidence below. Brief: pairing QR, approvals, devices,
history screens in `mobile/` over a mock transport; orphaned by A17's exit
(fleet-state-2026-09-25). Contract: `docs/contracts/authenticator.md`
(v1, Owner A4). Constraints held: no contract normative edits (ADR-013
R1-R8 still PROPOSED — gated rulings such as wss-only QR endpoints are NOT
applied); desktop-side findings stay with their owners; production posture
stays fail-closed.

### Delivered

- **Protocol/transport layer** (`mobile/src/protocol/`, `mobile/src/transport/`):
  QR generator + strict §3.1 parser (`qr.ts`), canonical challenge bytes and
  bounded parse (`canonical.ts`), approval gate transaction (`approval.ts`),
  replay ledger with auto-prune (`replay.ts`), best-effort queue with deny
  TTL (`queue.ts`), decision history (`history.ts`), dependency-free byte
  primitives (`bytes.ts`, replaces Node `Buffer` — Hermes has none),
  transport seams (`transport/link.ts`).
- **Environment seam** (`mobile/src/environment.ts`): `Environment` +
  `createFailClosedEnvironment` (wss-only rejecting link, fail-closed
  keystore) + `ApprovalBundle`; nothing in protocol/screens constructs an
  environment — `src/App.tsx` injects it (mock by default, bannered, toggle
  to FAIL-CLOSED).
- **Mock desktop** (`mobile/src/mock/`): in-process `MockDesktop` pairing/
  challenge plumbing (ticket lifecycle, single-use, plain-b64 32-byte device
  key check, ticket-label authoritative, shape-only `postResponse` — mock
  NEVER verifies signatures), `SoftHsmKeystore.createTestOnly` wiring,
  demo issue/offline switches. Reachable only from `src/mock` and tests —
  enforced by `tests/isolation/mock-isolation.test.ts`.
- **Screens** (`mobile/src/screens/`): `PairingScreen` (full §3.2 flow:
  parse -> keystore -> hello -> activation challenge -> review/decide ->
  flush -> active -> `onPaired`), `PendingApprovalsScreen` (pull + paste
  review, live countdown, tap-time re-gate, queue drain, demo/offline
  toggles, identity required), `DevicesScreen` (public facts + forget with
  confirm), `HistoryScreen`, shared `format.ts`. `App.tsx` = 4-tab shell.
- **Tests**: 11 files / 88 tests — protocol suites (qr, canonical, approval,
  replay, queue, history, bytes, keystore), mock flow suite, mock isolation
  suite, plus the fixed `qrcode.test.ts` vectors.

### Key decisions (evidence-first)

- **Mock mode is the default but bannered + toggleable** to FAIL-CLOSED;
  UI never lets mock output masquerade as a real approval (SECURITY.md
  rules 1, 4, 7).
- **`device_public_key_b64` is plain std Base64, exactly 32 bytes, no
  `ed25519:` prefix** (ipc.md §9d / pair.rs:306); the prefix belongs to the
  QR's desktop key only.
- **Mock desktop ignores claimant-supplied `device_label`** — the ticket's
  bound label is authoritative (ipc.md §9d).
- **Gate order runs twice** (review + tap) per §6.1: bounded parse -> live
  clock -> mandatory binding -> replay ledger. Keystore refusal leaves the
  challenge re-approvable (rule 10). Expired at review/tap is recorded as
  `expired`, never `deny`.
- **Pairing identity is provisional internally; real identity only after
  activation** (T270-08). `postResponse` returns `delivered` = accepted
  only — offline responses are queued, not "delivered".

### Findings remediated (docs/audits/FINDINGS.md rows, this task's scope)

- AUTH-4 (QR key pin: exact encoding + 32-byte round-trip, `qr.ts:56-73`),
  AUTH-6 (`approval.ts:149-165` mandatory binding), AUTH-7 (`approval.ts:
  144-148` live clock at review and tap; screen tick keeps countdown honest),
  AUTH-8 (`queue.ts` deny TTL 300 s + dropped outcomes in `tick()`),
  AUTH-9 (soft-HSM gate no longer ceremonial: isolation test proves only
  `src/mock`/tests reach it; honest header; wired only in bannered mock
  mode), AUTH-10 (`qr.ts:16,87-89` 300 s max), AUTH-11 (`approval.ts:
  168-178` records `expired`), AUTH-12 (`replay.ts:30-40,50` auto-prune at
  3600 s), AUTH-14 (`canonical.ts:126-133` bounded container + fixed error
  text; `approval.ts:73-76` bounded messages), AUTH-15 (`mobile/index.js`
  registers under `displayName` "KIWI Authenticator"), AUTH-16
  (`canonical.ts:95-105` session/event grammar + fixture now
  `boot-test-0001`).
- AUTH-2 **mobile half**: `buildChallengeResponseData` always carries
  `decision` (`canonical.ts:175-194`); desktop half already landed T-282
  (`types/system.rs` `ChallengeResponseInput.decision`) — end-to-end wire
  casing remains AUTH-3 (T-188). AUTH-13 **partial**: review card now
  shows issued + expiry + session/transaction + endpoint; the desktop-label
  field does not exist in either payload (contract-data gap — contract
  owner). AUTH-5 left open on purpose (ADR-013 R3 wss-only is
  PROPOSED/gated). AUTH-1/3/I out of scope (desktop / T-188 / Phase 4).
- T270-03 (= AUTH-6/7 gates), T270-04 (= AUTH-14/16 bounds+grammar),
  T270-06 (queue integrity: one outcome per id, delivered ids cannot
  re-admit, `queue.ts`), T270-07 (no `Buffer` in `src/` — `bytes.ts`
  + test parity), T270-08 (no fabricated "paired" state; activation gate)
  addressed. T270-05 only **partially**: prune + deny TTL wired, but
  durability/persistence is Phase 4 (AUTH-I) — NOT implemented.

### Verification (final run, this entry)

- `npm run typecheck` → 0 errors (protocol/mock core, `tsconfig.core.json`
  now includes `link.ts`, `environment.ts`, `src/mock`, isolation tests).
- `npm run typecheck:app` → 0 errors (incl. RN screens).
- `npm test` → **11 files / 88 tests passed** (was 43 pass / 3 fail at
  claim time — the 3 pre-existing `qrcode.test.ts` vector failures are
  fixed at the generator level).
- `npm run lint` → 0 errors (warnings tolerated per repo policy).
- Not exercised: RN android/ios builds, native modules, live wss — by
  design (scaffold posture, no native toolchain in this task).

---

## 2026-09-25 — T-336: wire the UI smoke suite into CI

**Status:** done (CI job added, browser-absence skip made honest, one
pre-existing red check reported and left to its owner).

### Files changed

- `.github/workflows/ci.yml` — new `ui-smoke` job (plus a header-comment
  refresh that also removed a pre-existing duplicated paragraph).
- `kiwi-app/scripts/ui-smoke.mjs` — honest browser-absence handling.
- `docs/agents/agent-26-status.md` — this file.

No app source, contract, `FINDINGS.md`, or `TASKS.md` edits.

### What the job does

`ui-smoke` on `ubuntu-latest`, `timeout-minutes: 15`, working dir
`kiwi-app`: `actions/checkout@v4` → `actions/setup-node@v4` (Node 22, npm
cache) → **resolve a headless browser** → `npm ci` → `npm run build` →
`npm run test:ui` (`node scripts/ui-smoke.mjs`) → on failure, upload
`kiwi-app/smoke.log` via `actions/upload-artifact@v4`.

The smoke step runs under `set -o pipefail` so `… | tee smoke.log` still
propagates the suite's real exit code, and the log is written for the
artifact.

### Browser resolution (probe first, install only if needed)

`KIWI_SMOKE_BROWSER` is what the harness reads (an absolute path or a PATH
name). The step therefore:

1. probes `google-chrome`, `google-chrome-stable`, `chromium`,
   `chromium-browser` on `PATH` — the ubuntu-latest image ships Google
   Chrome, so the normal path is zero-install;
2. only if the probe finds nothing, runs
   `npx --yes playwright@1 install --with-deps chromium` and resolves
   `~/.cache/ms-playwright/chromium-*/chrome-linux/chrome`;
3. writes `available`/`path` step outputs and the chosen binary + version to
   `$GITHUB_STEP_SUMMARY`;
4. **fails the job** if no browser could be obtained — a green run must
   never mean "silently skipped".

Playwright Chromium is the fallback rather than a Chrome apt install
because it needs no Google apt repository/`.deb` fetch and pins its own
system deps via `--with-deps`, so the fallback does not depend on
`dl.google.com` reachability.

### Honest browser-absence handling (harness change)

The harness previously threw a bare `Error` ("no browser found"), which
landed in `main().catch` as a fatal error and **exit 1** — i.e. a machine
with no browser reported a hard failure, and there was no way to tell
"absent" from "broken". Changes:

- `class BrowserUnavailable` distinguishes *no browser here* from a browser
  that started and then misbehaved. `findBrowser()` throws it when nothing
  is found, and a `spawn` `error`/`exit` before the CDP port opens is now
  classified the same way instead of throwing an unhandled `error` event.
- Default (`KIWI_SMOKE_REQUIRE_BROWSER` unset): reports
  `SKIP browser — no usable browser — …`, prints `SMOKE_JSON` with
  `pass:0, fail:0, skip:1, browserAbsent:true`, exits **0**. A skip can
  never be mistaken for a pass: `pass` stays 0 and the summary is marked.
- `KIWI_SMOKE_REQUIRE_BROWSER=1`: the same condition reports
  `FAIL browser — required but unavailable — …` and exits **1**. The CI
  job sets this, so the gate is real.
- A browser that *does* launch but never opens its DevTools port is still a
  hard failure — that is a real defect, not an absence.
- `summarize()` is now the single source of the `SMOKE_JSON` line, so the
  absent-browser and normal paths cannot drift apart.

### Verification

- `node --check scripts/ui-smoke.mjs` — clean.
- Browser absent, no `REQUIRE`: `SKIP browser …`, `SMOKE_JSON` with
  `browserAbsent:true, pass:0, fail:0, skip:1`, **exit 0**.
- Browser absent, `KIWI_SMOKE_REQUIRE_BROWSER=1`: `FAIL browser …`,
  `fail:1`, **exit 1**.
- Real run on this machine (`npm run test:ui`, Edge via the Windows
  candidate list): browser launched, CDP attached, **23 pass, 1 fail, 0
  skip** — the launch/CDP path is intact after the refactor.
- `.github/workflows/ci.yml` parses as YAML; `jobs` = rust, node-admin,
  node-mobile, node-kiwi-app, **ui-smoke**, static-checks, infra-live;
  `ui-smoke` resolves to ubuntu-latest / timeout 15 / `kiwi-app` with the
  7 expected steps.
- `npm ci --dry-run` — exit 0, lock in sync with `package.json`.
- The two `run:` blocks were reviewed line by line for bash correctness
  (`set -euo pipefail`, `command -v` inside `if`, `ls … || true` under
  `pipefail`, `exit 1` on absence). `bash -n` could not be executed on this
  host (the `bash` on PATH is a WSL shim with no distro installed).

### Pre-existing red check — NOT fixed, needs its owner

The one failing check is **`unified`** ("All Inboxes merges demo accounts
w/ own-account badges" — got only `ava@example.test`). It is **another
agent's uncommitted in-flight check** (absent from `HEAD`, present in the
shared working tree), not a browser/harness problem and not caused by this
task. Diagnosis: `kiwi-app/src/mock.ts` does define two demo accounts
(`acc-demo-1` ava@example.test, `acc-demo-2` ava.oldmail.test), but every
`DEMO_MESSAGES` row belongs to `acc-demo-1`, so an All-Inboxes view can
only ever render one account badge. The check therefore needs either a
second-account demo message or a narrower assertion — an app/demo-data
decision, deliberately left to its owner rather than edited from here.

Consequence: **the new CI job will be red until that check is fixed.** It
is honest — the browser genuinely ran and reported a real failure.

### Update — the `unified` check is now green

Its owner fixed the demo data while T-344 was in progress: the ui-smoke run
now reports **25 pass, 0 fail, 0 skip** and the `ui-smoke` CI job is no
longer blocked by it. Nothing was changed from here.

## 2026-09-25 — T-344: local gates script (Windows + POSIX)

**Status:** done. Both scripts written, and the `.ps1` run end-to-end on
this host (13/13 gates) plus the `.sh` syntax-checked and executed per group.

### Files changed

- `scripts/gates.ps1` (new) — Windows / PowerShell 5.1+.
- `scripts/gates.sh` (new) — bash, for Linux/macOS and CI parity.
- `docs/TESTING.md` — new §2 subsection documenting the script as the local
  equivalent of CI.
- `docs/agents/agent-26-status.md` — this entry.

### Gate set (CI order, identical keys in both scripts)

`rust.fmt`, `rust.test`, `rust.clippy`, `app.typecheck`, `app.test`,
`app.build`, `app.ui`, `py.secret_scan`, `py.copy_overlap`,
`py.check_fixtures`, `py.check_csp`, `py.check_encoding`,
`py.compose_static` — the list read off `static-checks` + `node-kiwi-app` in
`ci.yml`, plus the `infra-live`-free compose static subset
(`python -m unittest tests.infra.test_compose.ComposeStaticTests`), which
CI also runs in `static-checks` and needs no daemon. Nothing from
`infra-live` is included: it needs a live Docker stack.

### Behaviour contract

- Per gate: a numbered `== [n] title ==` header, the tool's own output, then
  `PASS` / `FAIL` / `SKIP`; a trailing `gates: N run, X PASS, Y FAIL, Z SKIP`
  line; **exit 1 if any FAIL**, exit 2 if the filter matched nothing.
- A failing gate never aborts the run — the rest still execute (verified).
- **SKIP only for absent tooling:** no `cargo` / no `npm` / no `python` /
  no headless browser. A check that runs and fails is always FAIL.
- `app.ui` mirrors the T-336 CI probe (PATH names, Windows Chrome/Edge
  absolute paths, Playwright cache) and passes the found binary via
  `KIWI_SMOKE_BROWSER`, so the suite's own honest `SKIP browser` (exit 0,
  `pass: 0`) surfaces as a SKIP gate rather than a pass.
- `-Only` / `GATES_ONLY` accepts groups or a single key (prefix match) for a
  fast inner loop.

### Verification

- `bash -n scripts/gates.sh` — clean; file is ASCII and newline-terminated.
- `GATES_ONLY=py` (bash): 6 gates ran, 5 PASS + the real `check_encoding`
  FAIL, exit 1 — matches the ps1 result exactly.
- `GATES_ONLY=app.ui` (bash): no Linux browser on PATH → honest
  `SKIP app.ui`, exit 0.
- Bad filter (`GATES_ONLY=nope` / `-Only nope`): exit 2 in both.
- `-Only app` (ps1): typecheck, vitest, build and the CDP smoke all PASS —
  **ui-smoke 25 pass / 0 fail / 0 skip** against a real headless browser.
- Full `scripts/gates.ps1` run: 13/13 gates in CI order,
  `7 PASS, 6 FAIL, 0 SKIP`, exit 1.

### Bug found and fixed during verification

The first ps1 draft mis-scored passing gates as FAIL: `& $Body` returns the
scriptblock's **stdout plus** its return value, so `$rc` became an array of
log lines ending in the exit code. Gate bodies now stream with `| Out-Host`
and return only `$LASTEXITCODE` (plus a last-element guard in
`Invoke-Gate`). A regex patch that briefly duplicated `--prefix kiwi-app` in
three npm lines was also caught and corrected by inspection.

### Honest state of the repo right now — 6 FAILs, none mine

Every failing gate is pre-existing concurrent in-flight breakage in files
this task never touched:

- `rust.fmt` / `rust.test` / `rust.clippy` —
  `kiwi-app/src-tauri/src/commands/lock_matrix.rs:265` has a syntax error
  (`unexpected closing delimiter: ]`), and
  `kiwi-mail/src/store/mod.rs:590,603` has `cannot find macro 'params'`.
- `app.typecheck` / `app.build` —
  `kiwi-app/src/views/compose.tsx:488` `TS2345` (in-flight `compose.tsx`,
  `shortcuts.tsx`, `search.tsx` edits).
- `py.check_encoding` — double-encoded UTF-8 in
  `kiwi-mail/src/authstamp.rs` and `kiwi-mail/src/store/mod.rs`.

These are reported, not fixed: the files belong to other in-flight agents,
and editing them from here would collide with their work. The value of the
script is exactly this: one command surfaced all three breakages with
file:line. Re-run after those land to get a green row.

### Owner items

- Nothing required for T-344. The three breakages above need their owners.
- `gates.sh` was executed here through Git Bash on Windows, which is not the
  target platform; the syntax check is solid, but a first real Linux run is
  still worth watching.

## 2026-09-25 — T-346: regenerate docs/architecture.svg to as-built

**Status:** done. Hand-authored, self-contained, rendered and visually
verified in both colour schemes.

### Files changed

- `docs/architecture.svg` — fully rewritten (10,642 B / 1240x820 / 6 crates
  Phase-0 diagram → 25,466 B / 1400x1260 / as-built).
- `scripts/gates.ps1` — one em dash was double-encoded by the T-344 regex
  patch and was tripping the repo's own encoding gate; replaced with ASCII.
- `docs/agents/agent-26-status.md` — this entry.

### Layout (doc section order, top to bottom)

1. **Renderer** — `kiwi-app/src` (React 18 + TS + Vite): the four-pane
   `chrome.tsx` shell, the real view list, and the Worker-isolated plugins
   (T-306). Marked "untrusted render - SECURITY.md B2".
2. **IPC boundary** — the three cross-cutting rules from sec 4: lock gate
   (`lock_matrix.rs`, T-340), consent boundary (`send_consent.rs`, native
   rfd for integration-bound sends only), audit (`audit.rs` to
   `audit.jsonl`, hash-chained, re-anchored sweep, `audit-corrupt`).
3. **Command modules** — `src-tauri/src/commands/` + `state.rs AppState`,
   with the real family names (accounts, autoconfig, contacts, devices,
   endpoint, export/import, folders, integrations, link, `message/*`,
   oauth2, pair, prefs, rules, sandbox, security, `send/*`, storage,
   templates).
4. **Workspace crates** — all **10** from sec 3 with their real key modules:
   `kiwi-mail`, `kiwi-core`, `kiwi-pair`, `kiwi-forensics`, `kiwi-mailauth`,
   `kiwi-integrations`, `kiwi-autoconfig`, `kiwi-contacts`, `kiwi-sandbox`,
   `kiwi-app/src-tauri`.
5. **Storage + sidecars** — SQLite `mail.db` (outbox rows, FTS5, bodies and
   attachments on disk, `index.json` / `audit.jsonl` / `pair.db` /
   `contacts.db`), `kiwi-admin` (Node/Drizzle + PG), `kiwi-admin-ui`,
   `mobile/` (RN authenticator, fail-closed, R1-R8 pending).

Footer strips carry the sec 5 security chain, the sec 9 canonical data
flows, and sec 11 hard boundaries + the gate commands.

### Rendering + self-containment

- 1400x1260 viewBox, so 1 unit = 1 px at the 1400px target width.
- Dark+light safe by construction: every element carries a **literal light
  palette** as presentation attributes, and a self-contained
  `@media (prefers-color-scheme: dark)` block overrides fills/strokes by
  class. A renderer that ignores CSS still gets the readable light theme.
- System font stack only (`ui-sans-serif, system-ui, ... sans-serif`); no
  `@font-face`, no `<image>`, no `<script>`, no `xlink:href`, and the only
  `http://` in the file is the required SVG namespace declaration.

### Validation

- `xml.etree` parse: well-formed, 384 elements.
- Real render check via headless Chrome `--screenshot` at 1400x1260, twice:
  the shipped file (dark override active) and a copy with the `<style>`
  block stripped (light fallback). Both inspected visually: all five
  layers legible, no clipping, no overlap, labels readable.
- **0 non-ASCII characters**, so this file cannot trip the repo's
  `check_encoding.py` double-encoding gate.

### Bug caught by rendering (not by the XML check)

The first hand-authored version used `·`, `—`, `§`, `→` and curly quotes.
The XML parsed fine and the first screenshot showed the whole diagram
rendered as mojibake (`â€¢`, `Â§`) — the same double-encoded signature that
T-344's gates script was flagging in `kiwi-mail`. Rebuilt the file ASCII-only
(`-`, `/`, `sec N`, `->`), which is renderer-proof and encoding-gate-proof.
That is also how the `gates.ps1` corruption was found and fixed.

### Owner items

- Route the `unified` check/demo-data mismatch to its owner; the job goes
  green once it passes.
- Optional: add the ui-smoke gate to `docs/TESTING.md` §2 (it now exists
  only in `.github/workflows/ci.yml`); not done here to keep this task's
  doc footprint minimal while other agents are editing docs.
- The `rfd`/native-dialog work and T-321 consent docs are unrelated and
  untouched by Agent 26.
