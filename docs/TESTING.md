# KIWI — Testing Strategy

> Owner: Agent 6. Status: standalone pivot (ADR-005) — Thunderbird-build
> gates removed; client-layer matrix added. Infra layer (ADR-006/007/008,
> ARCHITECTURE.md §7): compose/PG/Drizzle/sandbox surfaces added.
> Master contract: prompt.md §13–§14 (with §1–2 superseded by ADR-005).

Every feature ships with verification. A task is DONE only when its tests
exist, run, and pass — with evidence recorded in the owning agent's
`docs/agents/agent-N-status.md`. Missing evidence → Agent 6 marks the task
**NOT READY**.

## 1. Test layers

| Layer | Scope | Runner | Where |
|-------|-------|--------|-------|
| Unit | per crate/service, per function | `cargo test` (Rust); vitest (Node/TS) | beside code (`#[cfg(test)]`, `*.test.ts`) |
| Integration | cross-module via `docs/contracts/` interfaces | `cargo test --test '*'`; vitest workspace | `kiwi-*/tests/` |
| Client E2E | send/receive/compose/folders/attachments/offline/lock vs test mail servers (T-114) | fake-server harness + mailpit profile | `kiwi-mail/tests/`, `tests/fixtures/transcripts/` |
| App smoke | Tauri shell runs, IPC commands round-trip, frontend routes render | `cargo test -p kiwi-app` + manual checklist | `kiwi-app/` |
| Security regression | every fixed weakness → permanent test | same runners, `security_*` naming | per crate + `tests/` |
| Fixture-driven | PCAP / TLS / cert / message / transcript fixtures | `tests/tools/check_fixtures.py` + crate runners | `tests/fixtures/` |
| Secret-leak | no credentials/tokens/keys in repo | gitleaks + fallback grep script | `tests/tools/` |
| Infra (compose/PG) | services healthy, migrations apply, guard holds | `docker compose` + `tests/infra/test_compose.py` | `tests/infra/`, `infra/` |
| Sandbox lifecycle | provider availability, create/revert/teardown, capability reporting | PoC scripts + transcripts (T-132) | `tests/infra/`, `docs/sandbox.md` |

## 2. Per-crate / per-service commands (run from repo root)

### Rust workspace (`kiwi-core`, `kiwi-forensics`, `kiwi-mail`, `kiwi-app/src-tauri`)

```powershell
cargo fmt --check                                    # formatting gate
cargo clippy --workspace --all-targets -- -D warnings  # lint gate
cargo test --workspace                               # unit + integration
cargo test -p kiwi-mail --features fake-server       # client tests vs in-process fakes (T-114; feature name proposal)
```

Workspace lints (`Cargo.toml [workspace.lints.rust]`, inherited via
`[lints] workspace = true` in each crate): `unsafe_code = "forbid"`.
Every crate must opt into `[lints] workspace = true` — Agent 6 checks this
in gate review (kiwi-core was missing it at T-115 review).

Minimum crate layout:

```
kiwi-<svc>/
  src/
  tests/            # integration tests against public API (empty tests/ dirs are a G3 finding)
  Cargo.toml        # pinned security-sensitive deps; publish = false for app crates
```

### Node/TypeScript (`kiwi-admin`, `kiwi-app` frontend)

```powershell
npm run lint            # eslint, zero warnings (REQUIRED — missing script is a G9 finding)
npm run typecheck       # tsc --noEmit
npm run test            # vitest run
```

`package.json` scripts contract (each Node/TS package must provide exactly
these names):

```json
{ "scripts": {
    "lint": "eslint . --max-warnings 0",
    "typecheck": "tsc --noEmit",
    "test": "vitest run" } }
```

### Tauri app

```powershell
cargo test -p kiwi-app            # IPC command round-trips,MC state transitions
cd kiwi-app; npm run build        # frontend must compile; CSP must be non-null (see SECURITY.md)
```

`tauri.conf.json` with `"csp": null` is a G5 finding — webview CSP is
mandatory before any remote content renders.

### Cross-cutting (repo root, always runnable)

```powershell
python tests/tools/check_fixtures.py     # fixture catalog integrity
python tests/tools/secret_scan.py        # fallback secret scan when gitleaks is absent
python tests/tools/check_csp.py          # Tauri CSP assertion (non-null, no script inline/eval/remote)
gitleaks detect --config tests/tools/gitleaks.toml --source . --verbose   # when installed
```

### Infrastructure (compose + PG + Drizzle + sandbox)

```powershell
cp .env.example .env                     # once (gitignored; dev defaults only)
docker compose up -d db mailpit          # postgres + mailpit (admin builds separately)
docker compose build admin               # type gate runs inside the image
python -m unittest discover -s tests/infra -v   # T-133: health, migrations, guard, stubs
docker compose down                      # stop; -v also deletes the pgdata volume
```

- DB migrations (`kiwi-admin/drizzle/pg/*.sql`) are applied to the compose
  DB by the T-133 test (psql path — `drizzle-kit migrate` has no
  dbCredentials yet, T-130 follow-up); the test also asserts all 9 tables
  and proves the audit append-only guard rejects DELETE.
- CI mirror: `.github/workflows/ci.yml` (`infra-live` job runs the same
  suite on runners with Docker; `static-checks` needs no daemon).
- Sandbox surface (T-132, `docs/sandbox.md`): host probe
  `tests/infra/check-sandbox-host.ps1`, WSL2 lifecycle PoC
  `tests/infra/sandbox-wsl-poc.ps1`, capability reporting
  (`Available|Degraded|Unavailable`); QEMU command-line + agent-protocol
  transcripts land as fixtures when the provider crate exists. Sandbox
  absent → tests assert `Unavailable`, never host execution.

## 3. Coverage expectations

- Rust: `cargo tarpaulin` (or `cargo llvm-cov`) — target **≥ 80% line**
  on `kiwi-core` trust/policy decisions, `kiwi-forensics` rule engine, and
  `kiwi-mail` transport/auth paths; **100% of deterministic security rules**
  must have at least one positive and one negative fixture test.
- Node/TS: vitest `--coverage` — target **≥ 80%** on policy evaluator,
  RBAC, audit-log paths.
- Coverage is advisory in Phase 0–1, gating from Phase 2. The hard gate is
  always: **every security finding ever reported has a permanent regression
  test** (`security_*` test name referencing the finding ID).

## 4. Fixture runner design

`tests/fixtures/` is indexed by `MANIFEST.json` (schema + naming in
`tests/fixtures/README.md`):

```
tests/fixtures/
  pcap/<proto>_<mode>_<tls>[_<suffix>].pcapng
  certs/<case>.pem
  messages/<case>.eml
  transcripts/<proto>_<scenario>.txt   # NEW (T-114): protocol session transcripts
  MANIFEST.json
```

- `tests/tools/check_fixtures.py` validates naming, index-vs-disk parity,
  secret patterns, size caps (5 MB/file, 100 MB total).
- Crate runners consume fixtures by path: forensics iterates
  `"suite": "pcap"` entries asserting expected finding IDs; kiwi-mail
  state-machine tests replay `"suite": "transcript"` sessions.
- T-012 (Agent 3 + Agent 6) generates the actual `.pcapng`/`.pem` bytes.
  Transcript fixtures land under T-114 (synthetic, hand-written).

## 5. Client-layer test matrix (standalone — replaces Thunderbird matrix)

### 5a. Mail engine (kiwi-mail, vs fake servers + mailpit — see T-114 doc)

| Area | Cases |
|------|-------|
| SMTP send | happy path; AUTH PLAIN/LOGIN/XOAUTH2; auth failure; STARTTLS upgrade; downgrade/strip indication; send queue (undo-send window, send-later); oversize message; unreachable server; timeout mid-DATA |
| IMAP receive | LOGIN/AUTHENTICATE; SELECT; FETCH envelope/bodystructure; UIDVALIDITY change (resync); IDLE; folder create/rename/delete; malformed FETCH responses (untrusted server!) |
| POP3 receive | USER/PASS + APOP; LIST/UIDL/RETR/DELE; STLS upgrade; UIDL-based dedup |
| TLS observation | every connection yields `TlsObservation` (version, suite, KEX group, chain) or explicit `unknown` + reduced trust — never a guessed value |
| Account setup | valid/invalid creds; autoconfig; OAuth2 token store boundaries; per-account isolation |
| Sync/store | incremental UID sync; interrupted sync resumes; attachment on-disk storage; store corruption → rebuild, never silent loss |
| Offline/online | queued sends flush on reconnect; no duplicate delivery (idempotency) |

### 5b. Security features (per prompt.md §13, unchanged)

valid / invalid / weak / missing config; network failure; malformed input;
downgrade/stripping indicators where reproducible; cert edge cases; auth
failure; stale+replayed authenticator challenge; unauthorized admin access.
Each row maps to ≥1 test ID (traceability table owned by implementer,
audited by Agent 6).

### 5c. App / UI (kiwi-app + frontend)

normal / error / loading / locked / unlock states; keyboard nav; a11y;
theme compat; resize/overflow; **remote-content blocked by default**
(tracking pixels); attachment open/save flows; IPC error surfacing
(Rust errors render as UI states, never panics, never raw internals).

### 5d. Webview ↔ Rust IPC boundary

- Every Tauri command validates + authorizes input service-side; frontend
  input is untrusted.
- Fuzz/property tests on command payloads (oversize strings, hostile
  filenames, malformed IDs).
- No command transports message bodies to admin/analytics paths
  (contract invariant).

## 6. Test mail servers (T-114 summary; detail in `tests/mail-server-strategy.md`)

- **Default:** in-process fakes (tokio, in `kiwi-mail` dev-harness) — scripted
  SMTP/IMAP/POP3 peers incl. adversarial modes (strip STARTTLS, weak cipher
  only, hostile FETCH). Hermetic, no Docker, CI-friendly.
- **Interop profile:** Mailpit via Docker (`docker-compose.yml` at root —
  landed T-131) — realistic E2E, attachment round-trips.
- **Live IMAP:** GreenMail standalone in compose (T-147 — mailpit serves no
  IMAP) on 1143; IMAP greeting + CAPABILITY asserted by T-133.
- Transcript fixtures (`tests/fixtures/transcripts/`) let state-machine
  tests run with zero infrastructure.

### 5e. Infrastructure (compose / PG / Drizzle / sandbox)

| Area | Cases |
|------|-------|
| Compose health | `db` pg_isready-healthy; mailpit SMTP banner + API 200; `admin` /healthz (pending T-130 entrypoint — skip, never fake) |
| Migrations | `drizzle/pg/*.sql` apply clean to compose PG; all 9 tables present; rerun-safe |
| Audit guard | probe INSERT then DELETE → guard raises append-only error (live DB proof) |
| Env discipline | `.env.example` covers every compose var; `.env` gitignored (test-enforced) |
| Sandbox availability | provider reports `Available\|Degraded\|Unavailable` per host; absent → analysis `Unavailable`, UI disabled |
| Sandbox lifecycle | create → analyze → revert → teardown; base image never mutated; per-run instances never reused |
| Sandbox monitoring | proc/FS/net events bounded; hostile-guest output cannot blow up host parser |

## 7. Tooling baseline (re-verified 2026-09-19/20 on this host)

| Tool | Found | Notes |
|------|-------|-------|
| cargo/rustc 1.98.1 | yes | fmt + clippy available; `cargo audit` NOT installed (`cargo install cargo-audit`) |
| node 25.8.1 / npm 11.11.0 | yes | vitest per package |
| python 3.14.3 | yes | `tests/tools/*`, stdlib only |
| git 2.52.0 | yes | repo still largely untracked — commit early for gate baselines |
| gitleaks | no | `choco install gitleaks`; fallback script is the gate meanwhile |
| docker 29.5.2 + compose v5.1.4 | yes | db+mailpit verified healthy; daemon must be running (Docker Desktop) |
| CI (`.github/workflows/ci.yml`) | yes | rust / node-admin / static-checks / infra-live jobs mirror this file |

Config: `tests/tools/gitleaks.toml`. Dependency policy: lockfiles committed
(`Cargo.lock`, `package-lock.json`); `cargo audit` / `npm audit` at each
milestone — T-115 found 2 vitest dev-dep vulns (1 critical, fix available).

## 8. Performance / regression tracking

- Forensics: PCAP ingest MB/s per fixture-size class; alert on >20% drop.
- Transport: `TlsObservation` capture adds ~0 measurable handshake latency
  (assert via bench, not belief); sync throughput (msgs/s) baselined by T-106.
- UI: webview IPC round-trip budgets documented in ui-surfaces contract.

## 9. Evidence rules (unchanged)

- Exact command + counts in the status file; "tests pass" alone insufficient.
- Never delete/quarantine tests to go green without a TASKS.md entry.
- T-015 (regression harness + crate fixture wiring) remains the follow-up.
