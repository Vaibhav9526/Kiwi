# Agent 6 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-19 — T-006 delivered (all 5 sub-items)

**Status:** T-006 work complete from Agent 6 side; ready for Lead merge into
TASKS.md ledger (`claimed` → `in-review`). No handoff needed.

**Files changed (all inside Agent 6 boundaries; `source/`, crates, and other
agents' files untouched):**

- `docs/TESTING.md` — expanded: per-crate/service commands (cargo fmt/clippy/test;
  eslint/tsc/vitest contract), coverage targets (≥80% trust+rules paths, 100% rule
  positive+negative coverage), fixture-runner design (MANIFEST.json-driven), E2E
  checklist placeholder pending T-001/T-007, §13 security matrix traceability,
  verified tooling table, perf-tracking policy, evidence rules.
- `docs/SECURITY.md` — expanded: 11 binding rules, 7 trust boundaries (B1–B7, incl.
  new B6 AI + B7 PCAP-ingest), 5 explicit assumptions (A1–A5), secure-coding
  checklist, AI rules (§12: allowed payload, injection posture, offline-capable),
  verification gates + review triggers.
- `docs/THREAT-MODEL.md` — expanded: 7 assets (AS-1–AS-7), 6 in-scope attackers
  (T-NET/SRV/INP/LOC/AUTH/AI) + explicit out-of-scope, boundary→mitigation→test
  table, 8 attack scenarios each needing a regression test, 6 residual risks
  (RR-1–RR-6), review cadence.
- `docs/quality-gate.md` — new: G1–G11 checklist operationalizing prompt.md §14
  with DONE / NOT READY / BLOCKED verdicts.
- `tests/fixtures/README.md` + `tests/fixtures/MANIFEST.json` (v1, 32 entries:
  16 pcap / 11 cert / 5 message, all `planned`) + `pcap/`, `certs/`, `messages/`
  dirs — naming scheme, T-012 generation plan, size caps, synthetic-only rules.
- `tests/tools/gitleaks.toml` — secret-scan config (extends gitleaks defaults +
  KIWI synthetic-marker allowlist).
- `tests/tools/secret_scan.py` — stdlib-only fallback scanner (gitleaks absent).
- `tests/tools/check_fixtures.py` — manifest/schema/naming/secret/size checker.

**Commands run (from repo root, PowerShell):**

- `cargo --version; rustc --version; node --version; npm --version;
  python --version; gitleaks version; git --version` → cargo/rustc 1.98.1,
  node 25.8.1, npm 11.11.0, Python 3.14.3, git 2.52.0.windows.1;
  **gitleaks NOT installed** (fallback scanner is the gate until installed).
- `python tests/tools/check_fixtures.py` → initially FAIL (2 malformed-PCAP names
  violated the naming scheme); fixed names to
  `smtp_plaintext_notls_malformed-01-truncated-hello.pcapng` (+ `-02-…`);
  re-run → `OK (entries=32 present_bytes=0)`.
- `python tests/tools/secret_scan.py` → first run `scanned=0` (repo has zero
  tracked files — everything untracked); fixed scanner to include
  `git ls-files --others --exclude-standard`; final → `scanned=37 hits=0`.
- Manifest JSON validity re-confirmed via `json.load` (32 entries).

**Test results:** check_fixtures OK; secret_scan 0 hits. No crate test suites
exist yet (kiwi-core/kiwi-forensics scaffolds observed but owned by Agents 2/3 —
not executed, not touched).

**Assumptions:**

- Lead merges T-006 → `in-review`; Agent 6 keeps authority to mark NOT READY.
- T-012 (Agent 3 + Agent 6) produces actual fixture bytes per the catalog.
- T-015 builds the crate-side harness consuming MANIFEST.json (TESTING.md §4).
- E2E checklist template lands after T-001 build + T-007 source map.
- Agents 2/3/4 adopt the `npm run lint/typecheck/test` + cargo gate commands.

**Risks / notes for Lead:**

1. Nothing in the repo is git-tracked yet (`git ls-files` empty) — secret gate
   would have been vacuous without the untracked-files fix; recommend an initial
   commit soon so gitleaks/gates have a baseline.
2. gitleaks not installed on this host — recommend `choco install gitleaks`.
3. Suggest adding `__pycache__/` (and keeping `target/`, `node_modules/`) in
   `.gitignore` — left untouched as Lead-owned; test-tool runs regenerate
   `tests/tools/__pycache__` (removed after final run).
4. Observed `kiwi-core/` + `kiwi-forensics/` scaffolds and `err.txt` in root —
   not reviewed in depth (outside Agent 6 write boundary); quality-gate G1–G11
   applies when Agents 2/3 submit them.

## 2026-09-19/20 — T-113 + T-114 + T-115 delivered (standalone pivot)

**Status:** All three tasks complete from Agent 6 side; T-115 verdicts below
are binding gate decisions (NOT READY authority). All edits inside Agent 6
boundaries; other agents' code reviewed read-only.

### T-113 — docs updated for standalone architecture

- `docs/TESTING.md` — Thunderbird-build gates removed (mach/MozillaBuild,
  TB-workflow E2E). Added: workspace gate commands, `[lints] workspace`
  requirement, client-layer matrix §5a–5d (SMTP/IMAP/POP3 engine, security
  matrix, app/UI incl. remote-content block, webview↔Rust IPC fuzzing),
  T-114 summary §6, refreshed tooling table (docker 29.5.2 present,
  `cargo audit` missing).
- `docs/SECURITY.md` — B2 redefined (webview↔Rust IPC), B8 added
  (MIME/attachments), A2 rewritten (owned rustls `TlsObservation` replaces
  NSS-hook assumption), new rules 12–13 (remote-content block, attachment
  handling), rule 4/8 (rustls config, OS credential-manager for OAuth
  tokens), `md5`-only-for-APOP constraint, `zeroize`-must-be-wired rule,
  CSP + `[lints]` checklist items, Tauri/CSP review triggers.
- `docs/THREAT-MODEL.md` — client-as-attack-surface revision: assets AS-8
  (mail store), AS-9 (render isolation); attackers T-MAIL, T-WEB;
  boundaries B2/B8 rows; scenarios 9–12 (tracking pixel, spoofed
  attachment, hostile FETCH, mail-to-webview XSS); RR-3/RR-6/RR-7 new;
  NSS-blind-spot RR retired.
- `docs/quality-gate.md` — G2 (workspace-green, no mach), G9 (workspace
  clippy + mandatory `lint` script + `[lints]` inheritance), G10
  (remote-content, attachments, non-null CSP).

### T-114 — test mail server strategy + transcript fixtures

- New `tests/mail-server-strategy.md`: **in-process tokio fakes PRIMARY**
  (hermetic, adversarial modes real servers can't do), **Mailpit/Docker
  INTEROP profile** (docker 29.5.2 verified), GreenMail/MailHog/public
  accounts rejected with reasons. Fake-server contract for Agent 2
  (`kiwi-mail/tests/common/fake.rs`, ephemeral ports, scripted + hostile
  modes, `TlsObservation` assertions). Run convention:
  `cargo test -p kiwi-mail` (hermetic default) vs
  `KIWI_INTEROP=mailpit` (ignored interop tests).
- 7 synthetic transcripts in `tests/fixtures/transcripts/` (present,
  3503 bytes): smtp_send_ok / smtp_auth_fail / smtp_stripped /
  imap_select_fetch / imap_hostile_fetch / pop3_retr / pop3_stls. Dummies
  only (`REDACTED-DUMMY`, fake base64, `*.kiwi-test.invalid`).
- `MANIFEST.json` v1 now 39 entries (32 + 7); `check_fixtures.py` learns
  `suite: transcript` + naming rule; fixtures README documents the set.
- `secret_scan.py` refined after it flagged 3 lines in `kiwi-mail/smtp.rs`:
  all three were proper `Zeroizing<String>` handling (struct fields + test
  dummy), i.e. false positives. Scanner now skips `Zeroizing`/`REDACTED`
  lines and only matches quoted `:` values (struct-field ascriptions no
  longer hit; JSON/YAML secrets still do). Negative control 7/7 PASS.

### T-115 — gate verdicts (G1–G11) on the three scaffolds

Workspace state at review: `cargo test --workspace` →
kiwi-core **32 passed**, kiwi-forensics **36 passed**, kiwi-mail 2 passed,
kiwi-app 0+0, 0 failed. `cargo clippy -p kiwi-core -p kiwi-forensics
-p kiwi-mail --all-targets -- -D warnings` → clean (exit 0).
`secret_scan` → 118 files, 0 hits. `check_fixtures` → OK (39 entries).
`npm test` (kiwi-admin) → 34 passed; `npm run typecheck` → clean.
`npm audit` → **2 vulns (1 moderate, 1 critical GHSA-82fw-gwwq-j7x9,
fix available via `npm audit fix`)**.

| Scaffold | Pass | Fail → verdict |
|----------|------|----------------|
| kiwi-core (T-002) | 32 tests, clippy clean, zero deps, no unsafe/todo/panic, unwraps test-only, secrets clean, security-session.md contract present | **G9: `cargo fmt --check` DIRTY** (challenge/device/identity/policy/trust.rs) + **missing `[lints] workspace = true`** (unsafe-forbid not inherited) → **NOT READY**. Fix: `cargo fmt` + add `[lints] workspace = true`. Trivial; all else green. |
| kiwi-forensics (T-003) | 36 tests, clippy clean, fmt clean, `unsafe_code=forbid` local, no panic/todo, secrets clean, bounded-parse dep comments | **G7: `docs/contracts/forensics.md` missing** (T-003 target file); `tests/` dir empty (no integration tests — acceptable at scaffold, T-015 tracks) → **NOT READY** (single named gap: contract doc). |
| kiwi-admin (T-004) | 34 tests, typecheck clean, admin-api.md present, audit hash-chain tested, secrets clean | **G9: no `lint` script, no eslint** (violates TESTING.md package contract) + **1 critical dev-dep vuln with available fix** → **NOT READY**. Fix: add eslint + `npm audit fix`. Advisory: `createConsoleLogger` relies on caller discipline — add `redact()` wrapper before auth-adjacent paths (now in SECURITY.md §4). |

Positive security notes (recorded, not gates): Agent 2's `SmtpAuth` uses
`Zeroizing<String>` with **no `Debug` derive** on the enum (matches the
"never Debug-printed" comment); `SmtpConfig::default()` is fail-closed
(`require_starttls: true`, `allow_plaintext_auth: false`).

Out-of-scope observations (NOT verdicts — kiwi-mail T-101/T-102 and kiwi-app
T-110 are in-progress): two transient failures seen mid-review, both
consistent with concurrent editing and resolved on re-run — `kiwi-mail`
E0308 (first `cargo test` pass) and kiwi-app build-script failure
(`icons/icon.ico` missing; icon landed 23:27). No action. Early flag for
Lead/Agent 5: `kiwi-app/src-tauri/tauri.conf.json` has **`"csp": null`** —
must become non-null before any remote mail content renders (SECURITY.md
B2, quality-gate G5/G10).

**Commands run (repo root unless noted):** `cargo test --workspace` (×3, incl.
one transient E0308 pass); `cargo fmt --check`; `cargo clippy -p kiwi-core
-p kiwi-forensics -p kiwi-mail --all-targets -- -D warnings` (exit 0);
`cargo audit --version` (not installed); `npm test` + `npm run typecheck`
(kiwi-admin, both green); `npm audit --prefix kiwi-admin` (2 vulns);
`python tests/tools/check_fixtures.py` (OK); `python tests/tools/secret_scan.py`
(0 hits); negative-control script (7/7, temp file removed); `docker --version`
(29.5.2). No source files edited — read-only review outside Agent 6 dirs.

**Assumptions:** T-002/T-003/T-004 owners apply the named one-line fixes and
request re-review; kiwi-mail/kiwi-app excluded from T-115 (separate tasks);
transcript replay wiring is Agent 2's (T-101+) per the T-114 contract.

**Risks:** active concurrent editing caused transient build states during
review — re-run gates at merge time; repo still largely untracked in git
(initial commit + `__pycache__/` ignore still pending with Lead);
`cargo-audit` + `gitleaks` still uninstalled.

## 2026-09-20 — CSP fix verified; T-115 re-run; Agent 4→5 handoff noted; Agent 3 standby decision

**Status:** Continued T-113/T-114/T-115 per updated brief. No files outside
Agent 6 boundaries touched. No handoff needed from Agent 6.

### 1. CSP fix verified (closes the T-115 flag)

- Lead set `kiwi-app/src-tauri/tauri.conf.json →
  app.security.csp = "default-src 'self'; img-src 'self' data: blob:;
  style-src 'self' 'unsafe-inline'; connect-src 'self' ipc:
  http://ipc.localhost"`. Read-only verification only.
- Assessment: scripts fall back to `default-src 'self'` (no inline/eval/
  remote — good); remote mail images blocked at CSP level (`img-src` has no
  remote hosts — good, tracking-pixel block now has defense in depth);
  `style-src 'unsafe-inline'` acceptable for React (noted, not a finding).
- New gate tool `tests/tools/check_csp.py` (my `tests/` territory): asserts
  non-null CSP, default-src present, no script unsafe-inline/eval/wildcard/
  remote; warns on missing `object-src 'none'` / `frame-src` / remote
  img-src. First run: `OK (directives=4 warnings=3)` — the 3 warnings are
  hardening suggestions for Lead/Agent 5 (`object-src 'none'`, `frame-src`,
  style inline), NOT findings. Wired into TESTING.md §2 cross-cutting
  commands. `__pycache__` removed after run.

### 2. T-115 re-run (all verdicts stand; scope grew, still green)

- `cargo test --workspace` → kiwi-core 32, **kiwi-forensics 46 (+10)**,
  **kiwi-mail 30 (+28)**, kiwi-app 0+0, 0 failed. Agents 2 + 3 highly active.
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0 (clean,
  now incl. kiwi-app).
- `cargo fmt --check` → still dirty: kiwi-core (same 5 files — Agent 2 has
  not run `cargo fmt`), **new** kiwi-forensics `findings/diff.rs`,
  `findings/mod.rs`, `score.rs` (Agent 3's new code unformatted), kiwi-mail
  much larger surface (imap/mime/pop3/store/sync/smtp — T-101..T-106 in
  progress, unformatted). **Verdicts unchanged: kiwi-core NOT READY (fmt +
  `[lints]`), kiwi-forensics NOT READY (forensics.md + now fmt too),
  kiwi-admin NOT READY (lint + vuln).**
- kiwi-admin re-verified as handoff baseline for Agent 5 (untouched since
  10:03 PM, pre-handoff): `npm test` → 34 passed, `npm audit` → still
  2 vulns (1 mod + 1 critical), no eslint. Agent 5 has not logged pickup
  yet (status file last 11:23 PM, pre-reassignment) — T-004/T-108/T-109
  clock is with Agent 5; no Agent 6 action unless asked.
- `secret_scan` + `check_fixtures` not re-run (no fixture/tool changes
  since last green except check_csp.py addition — new tool run documented
  above).

### 3. Agent 3 standby decision: NO absorb (Agent 3 is LIVE)

- Evidence: `kiwi-forensics/src` writes 11:43–11:59 PM (score/diff/findings
  modules), test count 36 → 46 since T-115. Stale status file (last entry
  10:25 PM) is flaky logging, not a stall.
- Per §8 conflict rule + brief ("do NOT touch kiwi-forensics/ while Agent 3
  is active"), `docs/contracts/forensics.md` stays Agent 3's file. Agent 6
  remains on standby: if Agent 3 stalls (no tree activity + no status for a
  full cycle), absorb **the contract doc only**, never the crate, and log
  the trigger here first.
- Handoff note (Agent 4 → Agent 5, T-004/T-108/T-109) acknowledged from
  AGENT_HANDOFF.md + TASKS.md: Agent 4 on reviewer-only restriction (no
  edits until Lead re-clears) — Agent 6 will treat any kiwi-admin edit by
  Agent 4 as a §8 violation flag.

**Commands run:** `cargo test --workspace` (summary), `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings` (exit 0),
`npm test` + `npm audit` (kiwi-admin), `python tests/tools/check_csp.py`
(OK, 3 warns). All read-only except: new `tests/tools/check_csp.py`,
TESTING.md one-block edit, this log entry.

**Assumptions:** Lead merges; Agent 2 runs `cargo fmt` + adds `[lints]`;
Agent 3 formats + writes forensics.md; Agent 5 picks up kiwi-admin
(`npm test` first per handoff) + adds eslint + `npm audit fix`.

**Risks:** fmt-drift is widening while Agents 2/3 sprint (suggest Lead call
a `cargo fmt` checkpoint before next review); Agent 5 now carries
T-004+T-108+T-109+T-111+T-112 — overload risk, watch pickup latency.

## 2026-09-20 — T-003/T-107 takeover (Agent 3 quota): P1–P4 done, report/ built

**Status:** Handoff + agent-3-status read in full before touching anything.
Design constraints honored throughout (details below). All edits in
`kiwi-forensics/`, `docs/contracts/forensics.md`, this log.

### P1 — rules live: 46 → 70 tests green, fmt + clippy clean

- Uncommented `pub mod rules` (+ `live`, `report` as they landed).
- Wrote the three missing rule modules Agent 3 left on disk as stubs:
  `rules/crypto.rs` (12 rules: version floor/deprecated/unknown, handshake
  missing, resumption, cipher broken/weak/legacy/unrecognized, kex
  no-FS/unauth/unknown), `rules/certificate.rs` (12 rules via exhaustive
  `RULE_SPECS` table over `CertificateProblem`), `rules/auth.rs` (6 rules:
  exposure, deprecated, single/repeated failure with threshold split, MD5,
  not-observed). Completed `transport.rs`'s 3 referenced-but-missing fns
  (NOT_ADVERTISED / NOT_ATTEMPTED / REFUSED).
- Fixed Agent 3's latent errors (rules/ never compiled): `description`
  takes `&str` (added `&` at 15 `format!` sites), extended `model`
  re-exports (VersionComparison, CertThresholds, CertificateInfo,
  PublicKeyAlgorithm, SignatureAlgorithm, HostnameMatch), added missing
  `require_tls13: false` in `permissive()`, removed dead lookup in favor of
  a `CertRule` struct (also satisfies no-`expect` clippy deny).
- Severity/confidence rationale documented per rule in code; engine
  invariants kept (engine stamps provenance, drops evidence-less, sorts
  worst-first). No clock/RNG/floats; no unsafe; unwraps/expects test-only.
- Found + fixed one real model gap: verifier rejections were lost on empty
  chains (`problems()` early-returned before the trust match). Trust
  `Untrusted|Revoked` now surfaces `TrustRejected` even unparsed, while
  `NotEvaluated` + empty chain still reports nothing (Agent 3's
  `missing_certificate_reports_nothing` test kept green).
- Evidence: `cargo test -p kiwi-forensics` → **70 passed, 0 failed**;
  `cargo clippy -p kiwi-forensics --all-targets -- -D warnings` → exit 0;
  `cargo fmt -p kiwi-forensics -- --check` → clean (also formatted Agent 3's
  drifted files — owned crate now).

### P2 — `docs/contracts/forensics.md` created (Lead-authorized via handoff)

Versions (`kiwi.forensics/1`, catalog 1, `kiwi-score-1`), invariants,
`ConnectionSecurityEvent` JSON shape, §4 redaction rules, finding/evidence
shapes + stable keys, full 37-rule catalog table with sev/conf, scoring
formula (weights, confidence bp, repeat dimming, cap, grades), §7
determinism, §8 report spec, §9 SecuritySession mapping (both directions),
§10 fixture pointer. Matches implementation exactly.

### P3 — `src/live/` adapter (T-107)

Zero-new-dep design: `LiveTlsObservation` + `SocketMode` + `LiveCertVerdict`
mirror structs (kiwi-mail converts at its boundary; DER bytes never cross —
count only), `LiveSessionInput` bundle, pure `event_from_live`. Conservative
mapping: unknown version strings → `Unknown(0xFFFF)` sentinel (fires
TLS-003, never feeds floor rule); unparsed DER count → `chain_truncated`
(explicit limitation); resumption/KEX suppression inherited from rules;
STARTTLS observation only asserted on real upgrades. 5 adapter tests.
Refactored 9-arg fn into struct after clippy `too_many_arguments`.

### P4 — transcripts confirmed for Agent 2

Corpus ready at `tests/fixtures/transcripts/` (7 files, MANIFEST-present);
Agent 2's `smtp.rs` already references it ("pending Agent 6's T-114
corpus" — now unblocked). No further Agent 6 action; fake-harness
implementation is Agent 2's per `tests/mail-server-strategy.md`.

### P5 — report/ built; analyzers + pcap reserved for Agent 3's return

- Built `src/report/` per contract §8: `Report`, `Limitation` (+ codes),
  `AiEnrichment`, `ReportBuilder` (scores on build, sorts findings),
  JSON round-trip, and grounding enforcement (uncited AI keys dropped +
  recorded as `ai-uncited-keys` limitation). 2 tests. lib.rs doc-links to
  `report::` now resolve.
- NOT started (deliberate): `src/analyzers/` + `src/pcap/` stay commented
  in lib.rs for Agent 3 — its bounded-reader design (own readers, hard
  limits, no libpcap) is mid-flight and §8 says avoid concurrent rewrites.
  Exact next actions on its return: analyzers (SMTP/IMAP/POP3 trace →
  event builders, reusing transcript corpus) → pcap readers per its notes
  → uncomment → full green → T-003 done.
- T-115 update: **kiwi-forensics verdict flips to READY** (was: contract +
  fmt; both closed; 70 tests, clippy/fmt clean, secrets clean). kiwi-core
  still NOT READY (fmt + `[lints]`, Agent 2 active — not touched per §8).
  kiwi-admin still NOT READY (Agent 5 pickup pending).
- Workspace re-verified: core 32, forensics 70, mail 41 (Agent 2 added 11),
  all green; fixtures OK (39); secrets 0/145; CSP OK.

**Files changed:** `kiwi-forensics/src/rules/{crypto,certificate,auth}.rs`
(new), `rules/{mod,transport,policy}.rs`, `model/{mod,cert}.rs`,
`src/{lib,live/mod,report/mod}.rs`, `docs/contracts/forensics.md` (new),
this log. kiwi-mail/kiwi-core/kiwi-admin/kiwi-app untouched.

**Commands run:** `cargo test -p kiwi-forensics` (→68→70 green),
`cargo test --workspace` (all green), clippy `-D warnings` (exit 0),
`cargo fmt -p kiwi-forensics` (+check clean), fixtures/secret/CSP tools
(all green), read-only greps/reads elsewhere.

**Assumptions:** Agent 3 resumes analyzers/pcap on quota reset and reviews
my rules/live/report/contract diff; temporary ownership ends on its return
unless Lead extends.

**Risks:** my severity choices (esp. Medium vs High on deprecations) are
judgement calls — flagged for Agent 3/Lead review, all in one table
(contract §5) for easy revision; `Unknown(0xFFFF)` sentinel needs kiwi-mail
to eventually supply raw wire values if it wants exactness.

## 2026-09-20 — T-131 + T-133 (infra directive, ADR-007/008/009, ARCH §7)

**Status:** Both done and live-verified. Branch `release/v0.1.0`. T-113 doc
updates deferred per directive. All edits in T-131 target paths + `tests/`
+ `.gitignore` (one line) + this log.

### T-131 — compose infra delivered

- `docker-compose.yml` (root, project `kiwi`): `db` (postgres:17-alpine,
  `pg_isready` healthcheck, named volume `kiwi-pgdata`), `mailpit`
  (**axllent/mailpit:v1.31.2 pinned** — tag verified live on Docker Hub
  today), `admin` (builds `kiwi-admin/Dockerfile`, waits on healthy `db`,
  node-fetch `/healthz` healthcheck). `.env` required (`env_file
  required: true` — fail fast); created local `.env` from example
  (gitignored, dev defaults only).
- `.env.example`: all compose vars documented (T-133 asserts coverage).
- `kiwi-admin/Dockerfile` (multi-stage, node:22-bookworm-slim): builder
  runs `npm run typecheck` gate + emits `dist/`; runner ships deps + dist;
  node-fetch HEALTHCHECK (no curl). No secrets baked in.
- `kiwi-admin/.dockerignore`, `infra/README.md` (start/stop, service table,
  mailpit quick-check for kiwi-mail interop, pending-items + troubleshooting,
  ADR-009 justification block).
- `.gitignore` += `.env` (Lead-owned file; one line, security necessity —
  secrets must never commit. Flagging explicitly.)
- Tauri stays out: enforced by test, not convention
  (`test_tauri_not_in_compose`).

### T-133 — `tests/infra/test_compose.py` (stdlib unittest, 13 tests)

Static (no daemon): config-valid, env-coverage, Tauri-guard,
Dockerfile-type-gate. Live: PG TCP + healthy + pg_isready, mailpit SMTP
banner + API, admin /healthz (skips until T-130), migrations connectivity
(runs psql probe now that Drizzle markers exist — see below), sandbox
lifecycle (DEFERRED skip until T-132). Result: **13 tests OK (2 principled
skips: admin-health T-130, sandbox T-132)** against the live stack.

### Live verification evidence (daemon was down → launched Docker Desktop)

- `docker compose pull db mailpit` → both pins pull clean.
- `docker compose up -d db mailpit` → **both Up + healthy** (mailpit wget
  probe works — image is alpine-based as assumed).
- `docker compose build admin` → green (type gate passed inside).
- Two real findings fixed en route:
  1. **Repo lock drift:** `npm ci` fails in-image (`@types/node` peer
     resolution) though the tree installs/tests green. Dockerfile uses
     `npm install` + carries node_modules, with comments restoring `ci`
     after Agent 5 regenerates the lock under T-130. **Flag to Agent 5.**
  2. **Scanner vs `.env.example`:** dev-default password tripped
     secret_scan (correct instinct, wrong verdict). Added documented
     placeholder allowlist (`kiwi-dev-only-change-me`, `changeme`, …);
     negative control 7/7 PASS — real credentials still trip.
- `secret_scan` 193 files / 0 hits; `check_fixtures` OK (39);
  `check_csp` OK (3 advisories, unchanged).

### Handover notes

- `admin` service is **expected-red until T-130** (no `src/server.ts` /
  `/healthz` yet): image builds, container has nothing to run. Compose,
  tests and README all encode this — no changes needed when T-130 lands
  except the entrypoint itself. **T-130 appears underway** (Drizzle
  markers `drizzle.config.ts` + `drizzle/` appeared mid-task) — Agent 5
  active, no conflict (untouched per §8).
- Known pending: `cargo-audit`/`gitleaks` installs, repo initial commit,
  T-113 infra-doc pass (deferred), T-132 sandbox.

**Commands run:** `docker info` (daemon down → launched Docker Desktop),
`docker compose config/pull/up/ps/build`, `docker compose build --no-cache`
(debug), full unittest suite (13 OK), secret/fixture/CSP tools, registry
tag check via Docker Hub, read-only greps elsewhere.

**Assumptions:** dev-default PG password acceptable for local-only use
(documented, gitignored `.env`); mailpit v1.31.2 pin holds until Dependabot-
style review; T-130 provides server entrypoint + `/healthz` + migrations.

**Risks:** Docker Desktop on this host was off — CI/others must ensure the
daemon; `npm install` (vs `ci`) in-image trades pinning for robustness
until the lock regen; `.env` with stronger password is the deployer's job
(noted in README).

## 2026-09-20 — T-140 CI + T-141 mailauth fixtures + T-133 DB upgrade

**Status:** All three done, verified live where possible. T-113 deferred
per directive (not touched).

### T-140 — `.github/workflows/ci.yml` (validated YAML, 4 jobs)

`rust` (Tauri system deps via apt + fmt/test/clippy-`-D warnings`),
`node-admin` (`npm ci` + typecheck + test), `static-checks` (secret_scan,
check_fixtures, check_csp, compose-static unittest), `infra-live`
(compose up db+mailpit, build admin, full unittest, `down -v` always).
Pre-flight evidence: local `npm ci` EXIT=0 (lock healthy after T-130
regen — CI's `npm ci` is safe), admin suite now 64 passed (Agent 5
active), YAML parses with all 4 jobs. Note: better-sqlite3 warns
EBADENGINE on node 25 (wants ≤24) — pre-existing, flagged for Agent 5;
setup-node pins 22 in CI so CI is unaffected.

### T-141 — mailauth corpus (Agent 8's proposal, realized 1:1 + extras)

- 6 `.eml` + `transcripts/smtp_auth-mixed-results.txt` (named per proto
  convention; proposal's `auth-mixed-results` documented as realized) +
  `tests/fixtures/dns/mailauth.txt` (SPF/DKIM/DMARC fragments, TEST-NET
  addresses only).
- `auth-dkim-valid.eml` carries a **real RSA-2048 `simple/simple`
  signature** (Node `crypto`, fold-free headers so simple==relaxed; no
  `t=`/`x=` by design) with **generator round-trip verification**
  (sign→verify + body-hash check — `DKIM round-trip: OK`); tampered copy
  differs by exactly one body line (diff-verified). Generator script kept
  out of the repo; method in `tests/mailauth-mapping.md`, which also maps
  every fixture → `MockResolver` builders → expected verdicts per
  contract §8 (findings mapping itself lands with forensics auth work).
- MANIFEST 39 → 47 entries; checker learns `suite: dns`; fixtures README
  documents the corpus + verdict-tag convention. `check_fixtures: OK`;
  secrets clean.

### T-133 — DB test upgraded from probe to proof

`test_migrations_apply_and_guard_holds`: applies `drizzle/pg/*.sql` to the
compose DB via psql (rerun-safe: "already exists" tolerated, tables are
the gate), asserts all 9 T-130 tables present, then INSERTs a probe audit
row and proves DELETE raises the append-only guard. Live result: OK.
Suite remains 13 tests OK (2 principled skips: admin /healthz T-130,
sandbox T-132). Note: `drizzle-kit migrate` itself can't run (config has
no dbCredentials — T-130 runtime wiring still open); psql-apply is the
documented stand-in, journal-free by design for dev DBs.

**Files changed:** `.github/workflows/ci.yml`, `tests/fixtures/messages/
auth-*.eml` (6), `tests/fixtures/transcripts/smtp_auth-mixed-results.txt`,
`tests/fixtures/dns/mailauth.txt`, `tests/fixtures/MANIFEST.json`,
`tests/fixtures/README.md`, `tests/mailauth-mapping.md`,
`tests/tools/check_fixtures.py`, `tests/infra/test_compose.py`, this log.

**Commands run:** npm ci (0) + npm test (64 passed) in kiwi-admin; full
infra unittest (13 OK); checkers (47-entry fixtures OK, 251-file secrets
0 hits); DKIM generator + round trip; YAML parse; read-only greps of
Agent 8/mailauth contract/drizzle SQL.

**Assumptions:** verdict-tag (non-KIWI-ID) convention in MANIFEST is
interim until findings mapping exists; fresh DKIM keypair per generation
is fine (fixtures pin signature + p= together).

**Risks:** my hand-rolled DKIM simple-canon must agree with mailauth's
verifier on edge bytes — fixtures use minimal ASCII to stay in the safe
subset; consumption tests (Agent 8/forensics) are the final arbiter;
better-sqlite3/node-25 engine mismatch is Agent 5's; no `db:migrate`
script exists yet (T-130 follow-up).

## 2026-09-20 — T-140 confirmed + T-113 infra doc pass (ARCH §7, sandbox.md)

**Status:** T-140 re-verified step-by-step against the brief (all requested
steps present: cargo test/clippy/fmt, npm ci+test, secret_scan,
check_fixtures, check_csp, infra unittest) — no changes needed, still
unrun on runners (first push will prove it). T-113 infra pass complete.

### T-113 — TESTING.md / SECURITY.md / THREAT-MODEL.md infra layer

- **TESTING.md:** header revision note; §1 +2 layer rows (infra, sandbox);
  new §2 infra commands (compose up/build, unittest discover, migrate
  verification, CI mirror note); §5e infrastructure matrix (health,
  migrations, guard, env discipline, availability, lifecycle, monitoring);
  §6 mailpit profile updated (root compose, landed); §7 docker row
  refreshed + CI row.
- **SECURITY.md:** rules 14 (sandbox-only execution, no host fallback),
  15 (compose/image/.env discipline, Tauri never containerized), 16 (no
  secrets in DBs ever); B3b (PG/Drizzle: ORM-only, reviewed migrations,
  least-privilege role, DSN discipline, DB trigger + hash-chain); B9
  (sandbox guest boundary, all tiers + WSL2 caveat); A7 (dev-defaults
  posture), A8 (availability varies, absent ≠ degraded); checklist +2
  (infra review, sandbox provider rules).
- **THREAT-MODEL.md:** B9 + B3b boundary rows; scenarios 13 (unavailable →
  disabled, never host) + 14 (guest misbehavior → kill/discard/
  incomplete); RR-8 (WSL2 shared kernel), RR-9 (container escape accepted
  for infra), RR-10 (PG volume disposal).

### T-133 stub upgrade (sandbox now testable statically)

Sandbox stub split: contract pins no-host-fallback (asserted by regex —
caught my own cross-line regex bug, fixed), PoC scripts present
(asserted), lifecycle still DEFERRED-skip until `sandbox/` lands.
Suite: **15 tests OK (2 skips: admin-health T-130, lifecycle T-132)**.
Fixtures OK (47), secrets 0/268.

**Files changed:** `docs/{TESTING,SECURITY,THREAT-MODEL}.md`,
`tests/infra/test_compose.py`, this log.

**Commands run:** full infra unittest (15 OK), checkers (all green).

**Assumptions:** T-132 design/contract are the sandbox source of truth;
provider-crate tests (QEMU transcripts) remain future work per
sandbox.md §4.7.

**Risks:** none new; sandbox WSL2-tier caveat must reach UI copy before
the feature ships (flag for Agent 5).

## 2026-09-20 — T-147 greenmail IMAP + T-148 forensics remainder (analyzers/pcap)

**Status:** Both done. §8 conflict handled by adoption-over-rewrite (see
provenance note). Crate: 86 tests green, clippy + fmt clean.

### T-147 — live IMAP via GreenMail (mailpit proven IMAP-less)

- Evidence first: mailpit:1143 accepts TCP and sends **zero bytes**
  (vs POP3/SMTP banners fine) — IMAP truly absent, not misconfigured.
- ADR-009 evaluation (in `infra/README.md`): Dovecot needs baked Maildir +
  user config (custom image, ongoing care); GreenMail standalone is the
  purpose-built fixture server (all protocols, zero-config test users).
  Picked `greenmail/standalone:2.1.14` (tag verified live on Docker Hub),
  IMAP-only surface (`GREENMAIL_OPTS=test.imap`, auth disabled —
  synthetic-only, localhost-bound). Dovecot stays a revisit option.
- Compose: new `greenmail` service (`1143:3143`), mailpit IMAP mapping
  removed (was a dead port), `.env.example` gains `GREENMAIL_IMAP_PORT`.
  No in-image healthcheck (Zulu base ships no nc/wget/curl — verified by
  exec); external T-133 assertions are the health signal (documented).
- Verified live: greeting `* OK IMAP4rev1 GreenMail`, CAPABILITY,
  LOGIN OK, LIST INBOX. Two infra incidents fixed en route: stale mailpit
  1143 mapping blocked bind (recreated mailpit), and greenmail lost its
  network on first start (force-recreate fixed; worth watching).
- T-133 gains `test_greenmail_imap_greeting` (greeting + CAPABILITY);
  suite 16 OK. CI `infra-live` now starts greenmail too. Strategy doc +
  TESTING.md §6 updated (mailpit = SMTP/POP3, greenmail = IMAP).

### T-148 — analyzers adopted + pcap built; crate green

- **Provenance flag (Lead: please attribute):** `kiwi-forensics/src/
  analyzers/` (mod/imap/pop3/smtp) + `tests/pcap_ingest.rs` +
  `tests/pcapng_ingest.rs` appeared uncommitted at ~01:54 with no status
  entry (author unknown — Agent 3 still quota-dead per its log). Per §8 I
  did NOT rewrite: I read everything, kept the design (TraceFacts +
  finalize, tag-matched replies, credential-safe verbs-only evidence),
  and integrated.
- **Real bug found + fixed in the adopted code:** sniffed protocol was
  dropped — per-protocol analyzers called `finalize(trace, trace.protocol)`
  with the pre-sniff `Unknown`, so every sniffed session misreported
  `Unknown` downstream. Threaded `analyzed_as` through all three
  `analyze()` entry points (my end-to-end test caught it).
- **pcap/ built to satisfy the adopted tests:** streaming `PcapReader`
  (from_slice/next_packet/read_packets), `LinkType`, normalizing
  `Timestamp`, `CaptureError` taxonomy, per-packet + file-bytes + block +
  interface bounds, `if_tsresol` honored, unknown blocks skip by length.
  Two latent issues fixed: SHB byte-order magic lives at +8 (not +12 —
  caught empirically after a clean rebuild still failed), and one test
  helper declared caplen=4096 while writing caplen=0 (rewrote those bytes
  explicitly; logged here, test now tests what its comment claims).
  `max_packets` semantics follow the tests (per-batch cap on
  `read_packets`; streaming totals guarded by file-bytes bound).
- Full crate denys (`unwrap/expect/panic/indexing_slicing` non-test) now
  hold for the new code too — reader rewritten get-based; 4 collapsible-if
  + contains/is_multiple_of cleanups in adopted files.
- Evidence: lib 74 (incl. 4 new analyzer trace→rules end-to-end tests:
  SMTP strip → KIWI-STARTTLS-001 + AUTH-001; IMAP login-fail → AUTH-003;
  POP3 APOP → MD5 yes/exposure no; sniffing incl. unknown-stays-unknown),
  classic 9, pcapng 3 — **86 green**; clippy `-D warnings` exit 0; fmt
  clean; contract §8 entry points named (`PcapReader` → `analyze` →
  `RuleEngine` → `ReportBuilder`).
- Left for Agent 3's return: TCP reassembly impl (`reassembly` trait
  specified), PCAP→trace→event wiring into analyzers, `report` polish.
  Nothing of theirs was deleted (only superseded `classic.rs`/`ng.rs` of
  my own earlier pass were removed).

### Incidental findings (not mine, flagged not fixed)

- `kiwi-autoconfig` (Agent 8, T-135, files moving ~01:51) currently does
  NOT compile (`ClientConfig::parse` + `expected identifier impl` errors)
  → `cargo test --workspace` is red through no fault of reviewed crates.
  Untouched per §8; needs Agent 8 or Lead.
- secret_scan FP on a TSX label ternary (password label vs APOP-secret
  label in ternary position) fixed with a ternary-position skip;
  own-doc self-hit reworded. Negative control 7/7 PASS; full scan
  286 files / 0 hits.

**Files changed:** `docker-compose.yml`, `.env.example`, `infra/README.md`,
`tests/mail-server-strategy.md`, `docs/TESTING.md`,
`.github/workflows/ci.yml`, `kiwi-forensics/src/{pcap/*,analyzers/*}`,
`kiwi-forensics/tests/{pcap_ingest,pcapng_ingest}.rs` (3 minimal fixes),
`docs/contracts/forensics.md`, `tests/tools/secret_scan.py`, this log.

**Commands run:** IMAP/SMTP/POP3 socket probes; `docker compose
pull/up/ps/build` (greenmail verified); full unittest (16 OK); cargo
test/clippy/fmt on kiwi-forensics (86 green, clean); workspace test
(blocked by autoconfig — see above); checkers green.

**Assumptions:** GreenMail defaults (auth-disabled test users) acceptable
for fixture mail; mystery-analyzer authorship resolves to Agent 3/Lead on
return — my integration edits are reviewable diffs, not rewrites.

**Risks:** unknown-provenance code is now load-bearing in the crate —
Lead should confirm the author and have them review my 3 test fixes +
analyzed_as threading; workspace CI stays red until autoconfig compiles.

## 2026-09-20 — T-148 close-out: authorship corrected, CI parses, full gate matrix

**Status:** T-148 done from Agent 6 side. Session restarted; brief
confirmed the `analyzers/` + `pcap/` code **is Agent 3's authored code**
(per git/authorship) and my integration fixes stand — the
"unknown provenance" flag from the 09-20 T-148 entry is hereby
**retracted**. Corroboration on disk: `kiwi-forensics/src/lib.rs:1`
attributes the crate to agent 3 / T-003, and the modules follow Agent 3's
logged design (own bounded readers, TraceFacts + finalize, credential-safe
verbs-only evidence). Git history cannot distinguish further (all work
squashed into checkpoint `a982665` under one committer), so Lead's
authorship confirmation is recorded as the source of truth here.

**T-148 review pass (no new source edits — verification only):**
re-read `analyzers/mod.rs` (sniff → per-protocol analyze with threaded
`analyzed_as` → single `finalize`), `pcap/mod.rs` (limits-before-alloc,
`CaptureError` taxonomy, normalizing `Timestamp`), `pcap/reassembly.rs`
(interface-only Phase-5 stub, uncalled — no fail-open path). Design
judgement: sound, matches `docs/contracts/forensics.md` §§4/8. The 4
end-to-end analyzer tests + 12 pcap tests all green (see matrix). Left
for Agent 3: TCP reassembly impl, PCAP→trace→event wiring, report
polish. My integration diffs (analyzed_as threading, SHB magic offset,
caplen test bytes, deny-lint compliance) remain reviewable and untouched
since the last green run.

**T-140 CI verification:** `.github/workflows/ci.yml` parses
(`yaml.safe_load` OK, jobs `rust/node-admin/static-checks/infra-live`).
Step-by-step mirror check vs local gates: rust job runs fmt + test
+ clippy `-D warnings` (matches); node-admin runs `npm ci` +
typecheck + test on node 22 (matches); static-checks runs all three
checkers + `ComposeStaticTests` (class exists at
`tests/infra/test_compose.py:58`); infra-live starts
`db mailpit greenmail` (T-147 greenmail present), builds admin,
runs full unittest discover, `down -v` always. No YAML changes needed.
CI is RED on runners until the two blockers below are fixed (both
outside Agent 6 files).

### Full gate matrix (repo root, `release/v0.1.0`, working tree clean)

| Gate | Result |
|------|--------|
| `cargo test --workspace` | **RED — blocked by `kiwi-autoconfig` (Agent 8, T-135 open).** `autoconfig_xml.rs:547`: `mod tests` nested inside `impl ClientConfig` (impl opened :476 never closed before the test module) → `error: module is not supported in traits or impls`. Read-only diagnosis; **one-line fix for Agent 8: close the impl before `#[cfg(test)]`.** Also fmt-dirty (see below). |
| `cargo test --workspace --exclude kiwi-autoconfig` | **224 passed, 0 failed:** kiwi-app 26, kiwi-core 32, kiwi-forensics 86 (74 lib + 9 classic + 3 pcapng), kiwi-mail 54, kiwi-mailauth 26. |
| `cargo clippy --workspace --all-targets -- -D warnings` | **RED: 9 lints, all `kiwi-mail/src/testutil.rs` (Agent 2)** — `manual_split_once` ×1 (:110), `needless_borrow` ×8 (:270–478, `&leak(steps)` pattern). Test-only helper, trivial fixes, **Agent 2's file — flagged, not touched per §8.** |
| `cargo clippy -p kiwi-forensics --all-targets -- -D warnings` | **Clean (exit 0).** |
| `cargo fmt --all -- --check` | **DIRTY — none of it mine:** `kiwi-autoconfig` (Agent 8: autoconfig_xml/discovery/heuristics/ispdb/lib/manual/net/suggest) + `kiwi-mail` examples + `testutil.rs` (Agent 2). `cargo fmt -p kiwi-forensics -- --check` → **clean.** |
| `npm test` kiwi-admin | **64 passed, 1 skipped** (db.migrations, pre-existing skip). |
| `npm run typecheck` kiwi-admin | **Clean (exit 0).** |
| `secret_scan` | **289 files / 0 hits.** (One self-hit on my own prior log line tripped the run — reworded the line in this file, re-ran green.) |
| `check_fixtures` | **OK (entries=47 present_bytes=7819).** |
| `check_csp` | **OK (directives=4 warnings=3)** — same 3 hardening advisories, unchanged. |

**Verdicts:** kiwi-forensics (T-148 scope) is **READY** — 86 tests,
clippy/fmt clean, secrets clean, contract §§4/8 entry points named and
implemented (`PcapReader` → `analyze` → `RuleEngine` →
`ReportBuilder`). Workspace gate is RED through exactly two
other-owned defects (autoconfig compile error, kiwi-mail testutil
lints) + fmt drift in the same two crates — all flagged with file:line
for the owners. No Agent 6 files changed except this log + the one-line
self-hit reword above; `source/`, crates, and other agents' files
untouched.

**Assumptions:** Agent 8 fixes the impl-close brace + runs `cargo fmt`;
Agent 2 clears the 9 testutil lints + runs `cargo fmt`; Lead re-runs the
gate at merge (transient concurrent-edit states observed before).

**Risks:** CI (`rust` job) stays red until both fixes land — nothing
Agent 6 can clear without violating §8; T-003 final DONE still waits on
Agent 3's reassembly + wiring on its return.

## 2026-09-20 — T-003 DONE (full ownership) + T-154 baseline + TASKS.md repair

**Status:** T-003 complete and self-certified READY→done under direct
Lead instruction (Agent 3 not returning today). TASKS.md: T-003 and
T-148 marked done; duplicate T-154 row removed. All edits inside Agent 6
boundaries except the Lead-authorized ledger flip (details + incident
below). Crate: **111 tests green, clippy + fmt clean.**

### T-003 close-out — what was built (all `kiwi-forensics/` + contract)

Remaining scope was the packets→traces gap: readers yielded frames,
analyzers consumed hand-built traces, nothing connected them, and the
reassembly trait had no implementation. Closed with three pieces, zero
new dependencies (crate stays serde/serde_json-only):

- **`pcap::decode` (new):** Ethernet + IPv4 + TCP header parser →
  directed `TcpSegment`s (endpoints, seq, payload, frame index,
  timestamp). ARP/IPv6/UDP/truncated/malformed become counted
  `DecodeSkip`s — never fatal, never guessed. 7 unit tests incl.
  hostile-truncation sweep.
- **`pcap::reassembly` (implemented):** bounded `Reassembler`
  (`ReassemblyLimits`: flows/segments/bytes/frames) with first-seen-wins
  overlap, seq-wrap heuristic, gap flagging, per-direction extents
  (byte-range → frame attribution), over-limit drops counted for the
  pipeline. Agent 3's trait kept (`StreamReassembler`); its `TcpStream`
  reshaped to initiator-relative `ReassembledFlow` (documented — the old
  shape had no callers). 8 unit tests.
- **`pipeline` (new, contract §10):** `analyze_capture` composes
  reader → decode → reassemble → traces → `RuleEngine` →
  `ReportBuilder`, returning `CaptureReport { report, diagnostics }`.
  Two real design findings fixed en route: (1) client/server roles were
  flipped for greeting-first protocols — `resolve_roles` now decides by
  well-known port, then greeting content, then initiator default
  (caught by the SMTP end-to-end test asserting findings, not just
  sessions); (2) my own test asserted no credential-word in report JSON
  but rule prose legitimately discusses secrets — switched to a
  distinctive password (`s3cr3t-hunter2`, absent from output).
  Cross-direction lines merge in frame (time) order. New limitation
  codes: `stream-gap`, `capture-over-limit`,
  `rule-dropped-without-evidence` (+ existing `chain-unverified` on
  every capture report, `protocol-unknown` when sniffing abstains).
  `tests/capture_pipeline.rs`: 5 end-to-end tests from synthetic pcap
  bytes (SMTP strip → STARTTLS-001 + AUTH-001; IMAP login-fail →
  AUTH-003; real seq-gap → limitation; ARP counted as skip; garbage
  rejected).
- **Contract:** §9 stub (a literal truncation marker on disk) replaced
  with the real both-directions mapping tables (event↔session fields
  with verified `as_str()` spellings incl. ssl3.0→ssl3 and
  static→kex-group rules; findings→TrustSignal table with penalty
  ownership staying in kiwi-core; AUTH-003 explicitly signal-less);
  new §10 pipeline spec; entry-points paragraph + owner/status updated.
  `stream_offsets` deliberately left empty for pipeline traces (frames
  carry provenance; documented in §10).

**Evidence:** `cargo test -p kiwi-forensics` → 94 lib + 5 pipeline +
9 classic + 3 pcapng = **111 passed, 0 failed**; `cargo clippy -p
kiwi-forensics --all-targets -- -D warnings` → exit 0 (4 of my own
lints fixed: while-let, clone-on-copy, collapsible-if,
explicit-counter); `cargo fmt -p kiwi-forensics -- --check` → clean.

**Left explicitly undone (documented, not gaps):** IPv6/VLAN/tunnel
parsing (counted skips); TLS-decryption (encrypted captures are
findings-light by design — live adapter is the path for TLS sessions);
`SecuritySession`→event bridging specified (§9b) without an in-crate
impl (consumers bridge; kiwi-app maps findings→status today).

### T-154 — dependency audit baseline (SECURITY.md §7)

- `cargo audit` (installed cargo-audit 0.22.2, 1251 advisories):
  **1 vuln — rsa 0.9.10 RUSTSEC-2023-0071 Marvin (medium, no fix
  available)**, direct dep of `kiwi-mailauth` (Agent 8). Assessed
  **not exploitable here**: Marvin needs private-key decryption;
  prod code verifies DKIM with public keys only, sole private-key use
  is 1024-bit test keygen. Plus 7 warnings: unmaintained `unic-*`
  (via Tauri urlpattern) + `proc-macro-error`, unsound `glib`
  (Linux-only GTK path) — all transitive/conditional, ride-upstream.
- npm full audit: **kiwi-admin 6 vulns (1 critical + 5 moderate, all
  dev-only)** — critical vitest GHSA-5xrq-8626-4rwp 9.8 fixed by
  non-breaking upgrade past 3.2.6 (also clears the mocker traversal);
  esbuild dev-server issue via drizzle-kit needs `--force` (breaking)
  or dev-server isolation. **kiwi-admin-ui + kiwi-app: 0.**
  **mobile: not auditable — no lockfile** (Agent 4/Lead: generate one).
  Production-only audits are clean everywhere they run. Fixes flagged
  to owners (Agent 5: `npm audit fix` in kiwi-admin); none block T-003.

### Incident — TASKS.md encoding damage (mine, repaired, verified)

My T-154 ledger edit double-encoded the file (46 mojibake spots) and I
initially misread the cause as concurrent Lead edits — wrong: the other
sessions only *committed* (e46ac39 cycle swept my damaged working copy
into HEAD, incl. my duplicate T-154 row alongside the Lead's open one).
Repaired byte-exact in place: mojibake triples mapped back (7 arrows,
38 em-dashes, 1 en-dash, 7 section pairs — fully accounted), then
applied only the three intended changes. Verified via normalized diff
(non-ASCII blinded): **exactly 3 hunks vs HEAD** (T-003 done, T-148
done, open-T-154 dup removed) — zero content loss, 54 rows, no dup IDs.
Lesson recorded: for shared-ledger files, verify with normalized diffs
and prefer byte-exact scripts over blind rewrites; my other edited
files (forensics.md, SECURITY.md, this log) scanned clean with
deletion lists matching only intended replacements.

**Files changed:** `kiwi-forensics/src/{pcap/decode.rs (new),
pcap/reassembly.rs, pcap/mod.rs, pipeline.rs (new), report/mod.rs,
lib.rs}`, `kiwi-forensics/tests/capture_pipeline.rs (new)`,
`docs/contracts/forensics.md` (§9 + §10 + header), `docs/SECURITY.md`
(§7), `docs/TASKS.md` (3 ledger changes + encoding repair), this log.

**Assumptions:** Lead accepts the T-003 DONE flip on this evidence;
Agent 8 tracks the rsa advisory; Agent 5 runs `npm audit fix`;
Agent 4/Lead produce `mobile/package-lock.json`.

**Risks:** shared-tree concurrency is now the norm (Agents 7–10
committing around me) — my full-gate reds from this morning
(autoconfig compile error, mail testutil lints) are other agents'
in-flight states; re-verify at merge. `cargo-audit` installed to
`~/.cargo/bin` (host-local, not repo-pinned).

## 2026-09-20 — T-166 done: forensics→app seam aligned for T-164

**Status:** T-166 complete. Contract query shapes specified
(forensics.md §11), live auth threading implemented, fixture-driven
seam test green, audit-chain tamper guard verified at both layers.
TASKS.md T-166 marked done (byte-exact script edit after the T-154
encoding lesson — ledger verified mojibake-free). One 1-line compat
touch in Agent 7's `observe.rs`, loudly flagged below; everything
else inside Agent 6 boundaries.

### 1. Seam gap found + closed: auth facts died at the adapter

`observe.rs` collects `auth_mechanism`/`auth_succeeded` but its
`forensics_findings()` never passed them on — `LiveSessionInput` had
no auth fields, so the AUTH rules (001–006) could only ever fire from
capture traces, never on the live path the Security view actually
serves. Fix (my crate): new `LiveAuthObservation {mechanism,
succeeded, attempts, failures}` + `LiveSessionInput.auth`, mapped to
`AuthObservation` in `event_from_live` under the analyzers'
assertion rule (section exists only if mechanism/outcome/attempts
observed). Placement mattered: the no-handshake early return skipped
my first version — extracted `attach_auth()` called on both paths
(caught by the new test, fixed before green). `observe.rs` gets
`auth: None` + a T-164 pointer comment — workspace stays green;
threading `ctx` through is Agent 7's specified one-liner (mapping
rule in §11, no guessing: `none`→absent, `client-cert`→External,
`other:<name>`→`from_token`, attempts/failures counted from the
observed exchange).

### 2. forensics.md §11 — exact query shapes for T-164

- `list_findings({account_id?, severity?, limit?})` → full `Finding[]`
  verbatim. Severity vocabulary pinned to `Severity::as_str()`;
  unknown string → `invalid-input` (never silent). Binding total sort:
  severity desc, observed_at desc, rule_id asc, subject_key asc.
  Limit default 100 / max 1000. Flags the two T-164 changes to current
  `kiwi_security_findings` (no severity param, observed_at-only sort).
- `list_events({limit?, account_id?})` → `EventRow[]` (camelCase as
  emitted: id/tsUnix/accountId/category/severity/summary/detailRef),
  newest-first, worst-signal severity in forensics spellings (exact
  input domain of the view's `eventSeverityToSeverity` — backend UI
  tokens would be a violation). Mostly documents existing behavior;
  T-164 addition is the `account_id` filter.
- `finding_detail({key})` → `Finding` verbatim; key is the
  `finding_id()` form (`rule_id|subject_key`); empty/overlong →
  `invalid-input`, no match → `not_found`. New command (session
  context stays with `kiwi_session_detail`).
- UI derivation rules recorded for Agent 5's mapper: stable `id`
  derives as `rule_id|subject_key` (not a serialized field — the
  `finding-${index}` fallback retires once keys flow); `remediation`
  is an object, not the array the mapper assumes. Verified the
  frontend already maps backend vocabularies — no mismatch to fix.

### 3. Seam integration test (hermetic, green first clean run)

`kiwi-forensics/tests/sync_send_finding.rs` (+ documented dev-deps:
kiwi-mail/tokio/zeroize — published crate stays serde-only): a real
`SmtpClient` sends through a fixture-shaped localhost server
(dialogue scripted from `smtp_send_ok.txt` S: lines), then the
observe→adapter→engine path emits TRANSPORT-001 + AUTH-001 with
byte-identical JSON across runs and no credential leakage. Two
harness bugs fixed en route: post-DATA deadlock (server must send
the queued-reply before reading — the client is reading, not
writing) and server-read timeouts so divergence fails instead of
hanging. kiwi-mail's `testutil` is `#[cfg(test)]`-gated so the
fixture parse is intentionally minimal here (S: extraction only;
C: conformance stays kiwi-mail's own replay tests).

### 4. Audit-chain tamper guard verified e2e

`cargo test -p kiwi-app audit` → tamper test green;
`npm test -- audit` (kiwi-admin) → 9/9 green (chain + guard suites).
`e2e/` dir is still empty scaffolding (Agent 9's T-149) — noted, not
mine to fill.

### Concurrency note (shared tree)

Mid-task, `kiwi-mail/src/search.rs` (untracked, another agent's
active write — mtime seconds fresh) broke the workspace build and
took my dev-dep test build with it. Per §8 I did not touch it;
waited ~90s for writes to settle, then ran green. Same posture as
the morning's autoconfig/mail states: flag, never fix others'
in-flight files.

**Evidence:** forensics 96 lib + 5 pipeline + 9 + 3 + 1 seam = **114
green**; clippy `-D warnings` clean; fmt clean; `cargo check -p
kiwi-app` clean (observe.rs compat); secret_scan 321 files / 0 hits;
fixtures OK (47).

**Files changed:** `kiwi-forensics/src/live/mod.rs` (auth
threading + 2 tests), `kiwi-forensics/Cargo.toml` (dev-deps only),
`kiwi-forensics/tests/sync_send_finding.rs` (new),
`kiwi-app/src-tauri/src/observe.rs` (1-line `auth: None` compat —
Agent 7, flagged), `docs/contracts/forensics.md` (§11),
`docs/TASKS.md` (T-166 done), this log.

**Assumptions:** Agent 7 implements severity/limit/account_id +
`finding_detail` per §11 under T-164 and threads auth per the spec;
Agent 5 upgrades `findingToInfo` when keys flow.

**Risks:** none new; the `auth: None` compat silently keeps AUTH
rules off the live path until Agent 7 threads — tracked in §11, not
in code I own.

## 2026-09-20 — T-170 integration review: 5 contract pairs + full gate

**Status:** review complete. Read-only throughout (no source file
outside Agent 6 boundaries touched — fixes are all flagged with
owner + file:line). Two doc touch-ups inside my own files:
forensics.md §11 `finding_detail` aligned to the implemented
`findingId` shape, this log entry.

### Pair A — ipc.md vs `src-tauri/commands/*` (+ lib.rs + ipc.ts)

37 `#[tauri::command]` fns, all 37 registered (names match 1:1).
`delete/move` (§6b), `finding_detail` (§8), `sync_status`/`mail-changed`
(§6c) all present as documented; `schedule_send(queueId, sendAtUnix)`,
`sync_account`, Delete/Move/FindingDetail view shapes all match.

- **A1 (real, Agent 7 doc):** §3 `SecurityStatusView.requiredAction`
  `"none | notify-user | require-authenticator | block-access"` vs
  code `types.rs:667-675`
  `"none|warn-user|require-authenticator-unlock|require-reauth|block-access"`.
  Two invented tokens + one missing (`require-reauth`).
- **A2 (real, Agent 7 doc):** §4 `ChallengeView.nonceB64` vs code
  `types.rs:161` `nonce_hex` (hex, like fingerprints).
- **A3 (nit, Agent 7 doc):** §3 `SignalView` example kind
  `"starttls-stripped"` is not a real `SignalKind` (closest:
  `starttls-downgrade-suspected` per security-session.md §3).
- **A4 (gap, Agent 5):** no `ipc.ts` wrappers for `kiwi_delete_messages`,
  `kiwi_move_messages`, `kiwi_schedule_send`, `kiwi_sync_status`,
  `kiwi_finding_detail` — backend ready, UI unwired (T-162 bulk UI and
  the finding dialog fall back to stubs/demo until these land).
- **A5 (noted, intentional):** `kiwi_get/set_prefs` wrappers exist with
  no backend (local fallback per `prefs.ts`) — consistent, no action.
- Trivia: A7 log claims "36 total" handlers; lib.rs registers 37.

### Pair B — autoconfig.md vs `kiwi-autoconfig` (bounds/stages verified green 53/53)

Spellings, stage order, URLs, bounds (256/253/256KiB/32/16),
`needs_manual_review`, `to_mail_account` ids/keys, `default_port`,
ISPDB/MX tables all match, except:

- **B1 (minor, Agent 8):** §6 "usernames 1–256 chars" — code checks
  byte length (`suggest.rs:148-154`).
- **B2 (specified-but-absent, Agent 8/Lead):** §7 production
  `DiscoveryNet` adapter ("blocks on a private runtime") does not
  exist — only `MockNet` (`net.rs:67` is the sole impl). T-156 wizard
  has nothing live to call yet.
- **B3 (real, Agent 8):** `auth_kind` (`autoconfig_xml.rs:441-450`)
  maps empty string and anything containing "cram" to Password;
  contract §5 allows only the two `password-*` spellings + `OAuth2`
  and sends everything else to `unsupported`. Empty→Password is an
  undocumented default; `cram-*`→Password mislabels
  challenge-response as a password kind.
- **B4 (real, Agent 8 doc):** §4 lists GoDaddy in `ISPDB_FIXTURES`;
  code has 9 provider groups (`ispdb.rs:76-140`), GoDaddy only in
  `MX_HINTS` (`heuristics.rs:127-130`).
- **B5 (nit, Agent 8 doc):** §4 cites `pphosted.com` as an MX example;
  no such entry in `MX_HINTS`.

### Pair C — sandbox.md vs `kiwi-sandbox` (faithful)

Traits, errors, bounds (4096/64KiB/256KiB), tiers all match verbatim.

- **C1 (minor, Agent 10 doc):** `AnalysisReport.egress`
  (`EgressEvidence`, `lib.rs:137-149`) exists in code but not in the
  contract §Types shape. Additive + serde-defaulted, no breakage.
- Nit: `wsl2.rs:693` `GuestRun.exit_code` never read (dead_code
  warning — only warning in the workspace build).

### Pair D — contacts.md vs `kiwi-contacts` (clean)

Bounds, §4 control-char rule (incl. the fix-round tightening),
VCardLimits defaults, migrations/newer-refused/cascade/FK,
LIKE-escape + empty-query→list + NOCASE ordering, `local-N` +
reserved prefix, `MAX_PAGE` clamp, error-code table all verified
against code. The snake_case-crate vs camelCase-wire split from A9's
log is handled honestly in contract §2 (view is Agent 7's to add).
One nit: **D1** — `source_uid` bound reuses the name
`MAX_NAME_LEN` (value 256 correct).

### Pair E — forensics.md §11 vs Agent 7 reality

- **E1/E2 (open, Agent 7):** `severity`/`limit`/worst-first sort on
  findings and `account_id` on events are specified but NOT in
  `security.rs:20-100` (account-only, observed_at-desc). T-164
  delivered `finding_detail` only — these need a follow-up.
- **E3 (closed today, mine):** §11 now matches the implemented
  `kiwi_finding_detail(findingId)→FindingDetailView` wrapper shape.
- **E4 (open, Agent 7):** `observe.rs` still passes `auth: None`
  (verified current); AUTH rules stay silent live per design until
  the §11 one-liner lands.

### Status-log claim spot-checks

- A7 "36 handlers" → 37 (stale count, harmless).
- A9 "investigate if not 41 tests" → actual **48 green (42 lib + 6
  integ)**; the arithmetic in their entry is fuzzy but the crate is
  green — no action.
- A8's rebuttal of the old impl-brace flag: the flag was real at
  observation time (workspace failed there that morning; Lead's
  unblock commit repaired it); crate green since — no action.

### Full gate matrix (this run, shared tree, uncommitted changes present)

| Gate | Result |
|------|--------|
| `cargo test --workspace` | **394 passed, 2 FAILED** — both `kiwi-mail/search.rs` FTS5 (`parse_query_negation_noise_and_caps :383`, `match_sql_is_bounded_and_quoted :408`). Per-crate: app 41, autoconfig 53, contacts 48 (42+6), core 32, forensics 114 (96+5+9+3+1), mail 75+2F, mailauth 26, sandbox 5. Live mailpit+greenmail roundtrips passed (daemon up). |
| `cargo clippy --workspace --all-targets -- -D warnings` | **FAIL only in `kiwi-contacts` (17 errors**: doc-list indent, collapsible-if, needless Ok+`?`, needless borrows, char comparison). Excluding contacts: clean. |
| `cargo fmt --all -- --check` | **FAIL: 40 hunks, 100% `kiwi-contacts`** (contact/store/vcard/tests). All other crates clean. |
| kiwi-admin `npm test` | 68 passed, 1 skipped ✓. `typecheck` **FAILs (3 errors**: `repositories.pg.ts:218`, `services.ts:185`, `db.migrations.test.ts:33`) — tests green because vitest doesn't typecheck. |
| kiwi-admin-ui `npm run build` | ✓ 797ms. mobile `npm test` 32 ✓ + `typecheck` ✓ (lockfile now exists — T-154 gap closed). kiwi-app `vite build` ✓ 1.10s. |
| Checkers | secret_scan 320 files / 0 hits ✓; fixtures OK (47) ✓; CSP OK (3 advisories, unchanged) ✓; compose static 5 OK ✓. |

Reds cluster exactly where agents are mid-flight (contacts never
gated — A9 has no working toolchain; mail-search FTS5 logic gaps
already attributed; admin typecheck vs in-flight T-149 work). Nothing
in the matrix implicates `kiwi-forensics`, `kiwi-core`,
`kiwi-autoconfig`, `kiwi-mailauth`, `kiwi-sandbox`, or the Tauri
backend beyond the listed doc nits.

**Files changed (mine only):** `docs/contracts/forensics.md` (§11
`finding_detail` shape), this log.

**Assumptions:** owners take the flagged items; A9's crate needs a
first-ever clippy/fmt pass once green; admin typecheck needs a
re-run after T-149 settles.

**Risks:** workspace CI is red on three independent ownerless-until-
claimed items (contacts clippy/fmt, mail-search ×2, admin tsc ×3) —
recommend Lead serialize before any release cut.


