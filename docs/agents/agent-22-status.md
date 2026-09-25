# Agent 22 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-236: inbox-rules contract

**Status:** done (draft contract written; Lead review still required).

### Files changed

- `docs/contracts/rules.md` — new `kiwi.rules/1` contract covering T-228 model/evaluation/persistence semantics and the proposed T-233 apply/audit IPC seam.
- `docs/agents/agent-22-status.md` — this entry.

No Rust, TypeScript, or Agent 18 files were changed.

### Evidence and findings

- Read `kiwi-mail/src/rules/mod.rs`, `model.rs`, `eval.rs`, and `apply.rs`.
- Read `kiwi-mail/src/store/schema.rs`, `queries.rs`, and `mod.rs`; confirmed the rules CRUD, `rule_hits` methods, `JUNK_FLAG`, bounds, scope, ordering, and error behavior.
- Read `kiwi-mail/src/sync.rs`; confirmed the T-233 apply primitives are not yet called from the metadata, body-fetch, or POP3 sync paths.
- Searched `kiwi-app/src-tauri/src/` and `kiwi-app/src/`; no rules IPC types, commands, registration, or frontend bindings are present.
- Read `docs/contracts/ipc.md` for camelCase, lock-gate, error, and timestamp conventions.
- T-233 status remains open in `docs/TASKS.md:193`; the contract labels the proposed handlers and sync/schema gates explicitly.

### Commands run

- Repository search/read inspection with `glob`, `grep`, and `read`.
- `git status --short` and targeted `git diff --stat` inspection to avoid touching concurrent worktree changes.
- `git diff --check -- docs/contracts/rules.md docs/agents/agent-22-status.md` — passed.
- `cargo test -p kiwi-mail` — **156 passed, 0 failed**.

### Assumptions / risks

- `SCHEMA_VERSION` remains 6 while `rule_hits` was appended to the version-6 DDL. Existing v6 profiles may miss the table; T-233 must add a migration/guarded creation before treating audit persistence as complete.
- T-233's apply/audit code is present in the shared worktree but sync integration and app IPC are not landed; no claim of shipped T-233 behavior is made in the contract.
- The contract reserves `kiwi_rules_hits` as the matched-ID audit command and uses the standard `invalid-input`, `not-found`, `store-error`, `policy-blocked`, and `locked` error codes.
- Concurrent agents are editing the shared worktree; unrelated modifications and untracked files were preserved.

### Verification

- Contract content was checked against the source line ranges cited in its sections.
- `git diff --check` passed for both Agent 22 Markdown files.
- `cargo test -p kiwi-mail` passed 156/156.
- Required Orca T-236 completion report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.

## 2026-09-25 — T-238: forensics serde vocabulary proposal

**Status:** done (ruling request written; Lead canonical-vocabulary decision still required).

### Files changed

- `docs/audits/for-serde-vocab-1.md` — new read-only audit and ruling-request proposal covering all 31 `kiwi-forensics` enums, current serde forms, contract promises, FSV-1, and stored-report migration.
- `docs/agents/agent-22-status.md` — this entry.

No Rust, TypeScript, schema, or contract implementation files were changed.

### Evidence and findings

- Scanned every `.rs` file under `kiwi-forensics/src/`: 31 enums total, 27 serde-derived, 24 ordinary `#[serde(rename_all = "snake_case")]` enums, one internally tagged `EvidenceValue`, and four enums without serde.
- Reproduced FOR-1/FOR-2: current report JSON uses `tls12`, `start_tls`, `x_o_auth2`, and `{"unknown":N}` while `forensics.md` promises `as_str()` forms such as `tls1.2`, `starttls`, `xoauth2`, and bare `unknown`.
- Compared enum promises against `docs/contracts/forensics.md` and `docs/contracts/ipc.md`, including `Grade`, `ChangeKind`, PCAP enums, and the separate FOR-6 unknown-variant gap.
- Recommended FSV-1: lower `snake_case` external enum tags, retain the `EvidenceValue` internal-tag exception, preserve `TlsVersion::Unknown` payloads, and keep `as_str()` semantic/evidence/stable-key text separate.
- Added versioned dual-read/single-write migration notes for existing reports and a separate forward-compatibility implementation gate.

### Commands run

- Read-only `glob`, `grep`, and `read` inspection of `contract-drift-1.md`, `forensics.md`, `ipc.md`, `API_CONTRACTS.md`, `report/mod.rs`, `lib.rs`, and all enum-bearing source files.
- `cargo test -p kiwi-forensics` — **115 passed, 0 failed** (96 unit, 5 capture-pipeline, 9 pcap-ng, 3 sync-send, 1 vertical-flow, 1 doc-test).
- No source formatting, implementation, or code-writing command was run.

### Assumptions / risks

- T-238 is a ruling request, not approval of FSV-1; no code owner may treat the proposal as ratified until the Lead records the decision.
- `TlsVersion::Unknown` migration must not fabricate a raw value when reading a legacy bare `"unknown"` string.
- FOR-6 remains open: a spelling rule alone cannot provide forward-compatible deserialization for future or data-bearing enum variants.
- `ipc.md` currently mixes core/session vocabulary (`tls1.3`, `xoauth2`, `hostname-mismatch`) with embedded forensic Serde values; the proposal keeps that boundary explicit.
- Concurrent shared-worktree changes were preserved.

### Verification

- `git diff --check` passed for the new audit file and status log.
- T-238 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.

## 2026-09-25 — T-246: autoconfig-parser drift enumeration

**Status:** done (read-only analysis and candidate rulings; no code change).

### Files changed

- `docs/audits/autoconfig-drift-1.md` — new focused ACFG-3..10 audit with contract/source evidence, severity, and code-fix versus contract-fix recommendations.
- `docs/audits/contract-drift-1.md` — appended the T-246 ACFG-3..10 reconciliation section.
- `docs/agents/agent-22-status.md` — this entry.

No Rust, TypeScript, schema, or `docs/contracts/*` files were changed by T-246.

### Evidence and findings

- Read `docs/contracts/autoconfig.md` and the existing ACFG-3..10 rows in `docs/audits/contract-drift-1.md`.
- Read `kiwi-autoconfig/src/lib.rs`, `ispdb.rs`, `heuristics.rs`, `autoconfig_xml.rs`, `discovery.rs`, `net.rs`, and `suggest.rs`; traced validation, fixture lookup, MX suffix matching, XML bounds/PI/root/domain selection, placeholder substitution, and stage error mapping.
- ACFG-3/5/6/10 are primarily contract corrections: RFC `atext` acceptance, stale `pphosted.com` example, distinct `Error::TooLong` taxonomy, and `%EMAILDOMAIN%` support.
- ACFG-4 is a product/data decision: GoDaddy is absent from nine bundled ISPdb entries but remains available through the `secureserver.net` MX hint; do not invent fixture endpoints.
- ACFG-7/8/9 are the security/selection subset: arbitrary PIs are skipped, bare `emailProvider` roots are accepted, and provider selection can fall through to the first provider; candidate resolution is fail-closed code work.
- Candidate severities are M for ACFG-4/7/8/9 and L for ACFG-3/5/6/10; no H finding was identified.
- ACFG-1/2 and ACFG-11 onward remain outside T-246 scope.

### Commands run

- Read-only `glob`, `grep`, and `read` inspection of the contract, existing audit, task/status files, and all relevant `kiwi-autoconfig/src` modules/tests.
- `cargo test -p kiwi-autoconfig` — **92 passed, 0 failed**.
- `git diff --check -- docs/audits/contract-drift-1.md docs/audits/autoconfig-drift-1.md` — passed.

### Assumptions / risks

- Line references describe the current T-246 snapshot; concurrent worktree edits may shift them.
- GoDaddy ISPdb support requires verified provider endpoint data before any code fix.
- Candidate rulings are recommendations for Lead/Agent 8 review, not implementation approvals.
- T-241 is closed and was not modified; unrelated shared-worktree changes were preserved.

### Verification

- `cargo test -p kiwi-autoconfig` — **92 passed, 0 failed**.
- `git diff --check` passed for the T-246 audit files.
- T-246 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.
