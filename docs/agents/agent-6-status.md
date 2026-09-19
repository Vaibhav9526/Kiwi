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

