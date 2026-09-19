# KIWI — Testing Strategy

> Owner: Agent 6. Status: Phase 0 — strategy defined, harnesses land with
> Phase 1 crates (T-015). Master contract: prompt.md §13–§14.

Every feature ships with verification. A task is DONE only when its tests
exist, run, and pass — with evidence recorded in the owning agent's
`docs/agents/agent-N-status.md`. Missing evidence → Agent 6 marks the task
**NOT READY** (prompt.md §6, Agent 6 authority).

## 1. Test layers

| Layer | Scope | Runner | Where |
|-------|-------|--------|-------|
| Unit | per crate/service, per function | `cargo test` (Rust); vitest (Node/TS) | beside code (`#[cfg(test)]`, `*.test.ts`) |
| Integration | cross-module via `docs/contracts/` interfaces | `cargo test --test '*'`; vitest workspace | `kiwi-*/tests/` |
| End-to-end | Thunderbird workflows (needs T-001 build) | manual checklist + scripted where possible | §5 |
| Security regression | every fixed weakness → permanent test | same runners, `security_*` naming | per crate + `tests/` |
| Fixture-driven | PCAP / TLS / cert / message fixtures | `tests/tools/check_fixtures.py` + crate runners | `tests/fixtures/` |
| Secret-leak | no credentials/tokens/keys in repo | gitleaks + fallback grep script | `tests/tools/` |

## 2. Per-crate / per-service commands (run from repo root)

### Rust (`kiwi-core`, `kiwi-forensics`) — lands with T-002/T-003 scaffolds

```powershell
cargo fmt --check          # formatting gate (CI-equivalent locally)
cargo clippy --all-targets -- -D warnings   # lint gate
cargo test                 # unit + integration
cargo test --doc           # doc examples, where present
```

Minimum crate layout each Rust service must ship:

```
kiwi-<svc>/
  src/
  tests/            # integration tests against public API
  Cargo.toml        # pinned security-sensitive deps (see §7)
```

### Node/TypeScript (`kiwi-admin`, `kiwi-admin-ui`) — lands with T-004 scaffold

```powershell
npm run lint            # eslint, zero warnings
npm run typecheck       # tsc --noEmit
npm run test            # vitest run
```

`package.json` scripts contract (Agent 4 must provide exactly these names):

```json
{ "scripts": {
    "lint": "eslint . --max-warnings 0",
    "typecheck": "tsc --noEmit",
    "test": "vitest run" } }
```

### Thunderbird integration (blocked on T-001 build + T-007 source map)

Mach-level checks run inside `C:\mozilla-build\start-shell.bat`:

```sh
./mach eslint --fix-dry-run <touched-dirs>   # JS lint for in-tree changes
./mach build          # must stay green after hook insertion
```

No Agent 6-owned automation touches `source/` until Lead publishes the
integration-point map.

### Cross-cutting (repo root, always runnable)

```powershell
python tests/tools/check_fixtures.py     # fixture catalog integrity (names, no secrets, no real PII)
python tests/tools/secret_scan.py        # fallback secret scan when gitleaks is absent
gitleaks detect --config tests/tools/gitleaks.toml --source . --verbose   # when installed
```

## 3. Coverage expectations

- Rust: `cargo tarpaulin` (or `cargo llvm-cov`) — target **≥ 80% line**
  on `kiwi-core` trust/policy decisions and `kiwi-forensics` rule engine;
  **100% of deterministic security rules** must have at least one positive
  and one negative fixture test (prompt.md §4.5: never invent findings →
  every rule needs reproducible evidence).
- Node/TS: vitest coverage (`--coverage`) — target **≥ 80%** on policy
  evaluator, RBAC, audit-log paths.
- Coverage is advisory in Phase 0–1, gating from Phase 2. The hard gate is
  always: **every security finding ever reported has a permanent regression
  test** (`security_*` test name referencing the finding ID).

## 4. Fixture runner design

`tests/fixtures/` is content-addressed by naming convention, not by a
database (see `tests/fixtures/README.md` for the full catalog):

```
tests/fixtures/
  pcap/<proto>_<mode>_<tls>.pcapng    # e.g. smtp_starttls_tls12.pcapng
  certs/<case>.pem                    # e.g. expired.pem, hostname-mismatch.pem
  messages/<case>.eml                 # synthetic only, never real mail
  MANIFEST.json                       # machine-readable index (schema in README)
```

- `tests/tools/check_fixtures.py` validates: every file in `MANIFEST.json`
  exists, every file on disk is indexed, names match the convention,
  and no file trips the secret patterns.
- Crate runners consume fixtures by path: e.g. forensics tests iterate
  `MANIFEST.json` entries with `"suite": "pcap"` and assert expected
  finding IDs. This keeps fixture data (Agent 6) decoupled from engine
  assertions (Agent 3).
- T-012 (Agent 3 + Agent 6) generates the actual `.pcapng`/`.pem` bytes.
  Phase 0 delivers the catalog + manifest schema + empty-directory
  placeholders only — **no fabricated packet bytes checked in as real**.

## 5. E2E checklists (Thunderbird-dependent, run post-T-001)

Thunderbird workflows (prompt.md §13): account setup, login, receive, send,
folders, compose, attachments, rendering, reconnect, offline/online,
security alert → lock transitions. Each E2E run records: build revision,
`mozconfig` hash, pass/fail per row, screenshots for UI rows. Agent 5 owns
execution of UI rows; Agent 6 owns the checklist template (to be added here
once T-007 unblocks — currently tracked as T-015 dependency).

## 6. Security feature test matrix (minimum per feature)

From prompt.md §13 — every security feature must cover:

1. valid configuration 2. invalid 3. weak 4. missing 5. network failure
6. malformed input 7. downgrade/stripping indicators (where reproducible)
8. certificate edge cases 9. authentication failure 10. stale/replayed
authenticator challenge 11. unauthorized admin access.

Traceability: each row maps to ≥1 test ID. Template:

```
| Matrix row | Test ID(s) | Fixture(s) | Owner | Status |
```

Agent 2/3/4 fill their rows as they implement; Agent 6 audits completeness.

## 7. Tooling baseline (verified 2026-09-19 on this host)

| Tool | Found | Version | Notes |
|------|-------|---------|-------|
| cargo/rustc | yes | 1.98.1 | `cargo fmt`, `cargo clippy` available |
| node / npm | yes | 25.8.1 / 11.11.0 | vitest/eslint per-service on scaffold |
| python | yes | 3.14.3 | runs `tests/tools/*`, stdlib only |
| git | yes | 2.52.0.windows.1 | — |
| gitleaks | **not installed** | — | install: `choco install gitleaks` or GitHub release; until then `tests/tools/secret_scan.py` is the gate |

Config: `tests/tools/gitleaks.toml` (checked in, Agent 6-owned).
Dependency policy: security-sensitive deps pinned with lockfiles
(`Cargo.lock`, `package-lock.json` committed); `cargo audit` / `npm audit`
run at each milestone and recorded in the agent status file.

## 8. Performance / regression tracking

- Forensics: benchmark PCAP ingest throughput (MB/s) per fixture-size class;
  record in status file at each milestone; alert on >20% regression.
- Trust evaluation: `SecuritySession` decision latency budget documented in
  the security-session contract; measured via criterion-style benches later.
- No perf gate blocks Phase 1; baselines must exist by end of Phase 2.

## 9. Evidence rules

- Test output pasted or summarized with counts (`X passed, Y failed`) plus
  the exact command in the status file — "tests pass" alone is insufficient.
- Failing tests are never deleted to go green; quarantine with a
  `#[ignore]` + TASKS.md entry + AGENT_HANDOFF.md note.
- T-015 (security regression harness + fixture runner wiring into crates)
  is the follow-up; this file is its spec.
