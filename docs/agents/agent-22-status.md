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

## 2026-09-25 — T-250: admin-api contract-vs-implementation enumeration

**Status:** done (read-only endpoint/audit documentation; no source or contract changes).

### Files changed

- `docs/audits/admin-drift-1.md` — new full matrix for all 16 §3 endpoints plus `/healthz`, with current route/permission/scope/wire/error/limit behavior, §13 audit-export, §14 device-inventory, and current T-193 fix status.
- `docs/agents/agent-22-status.md` — this entry.

No `kiwi-admin` source, test, migration, or `docs/contracts/*` files were changed by T-250. T-241 remained closed and untouched.

### Evidence and findings

- Read `docs/contracts/admin-api.md` §§1–3 and §§12–14, `kiwi-admin/src/server.ts`, `rbac/rbac.ts`, `types.ts`, service classes, validation/model files, repository interfaces/projections, audit export, and current HTTP/RBAC/service/export tests.
- Enumerated all 16 contract method/path rows: org create/user list/create/role, device inventory/revoke, policy create/list/evaluate/outbound, mailflow ingest/query, audit query/verify/global export/org-scoped export; also recorded extra-contract `GET /healthz`.
- Remaining primary findings: policy-list and audit-query response projections; bounded partial audit verification; unaudited read/export denials; global export incorrectly available to `org_admin` because `system-admin` is absent; missing org-scoped export and device inventory; list/pagination and wire-shape documentation gaps; mailflow enum/id semantics; unknown-org error paths; app-assigned audit sequence wording.
- §13 artifact format, raw NDJSON, full-chain cap, and signed/unsigned builder behavior are present; authorization and denial-audit gaps remain.
- §14 device inventory, scoped export, and the related unimplemented service/repository paths are explicitly code-fix gates.
- Current T-193 fixes verified: authenticated/audited policy evaluation, fail-closed null-org scoping, owner-scoped revoke, `org.create`, non-positive verify rejection, atomic/capped policy writes with error audit, typed errors/conflicts/membership, bounded/batched lists, millisecond timestamps, serialized appends, escaped LIKE filters, strict `numParam`, JSON content-type, and corrected healthz version.

### Commands run

- Read-only `glob`, `grep`, and `read` inspection of the admin contract, prior ADM audit, route/RBAC/service/repository/model/test sources.
- `npm run typecheck` — passed.
- `npm test` — **107 passed, 1 skipped, 0 failed** across 11 test files.
- No code formatting, build, migration, or implementation command was run.

### Assumptions / risks

- Line references describe the current T-250 shared-worktree snapshot; concurrent edits may shift them.
- The global audit export finding is intentionally high severity because the contract is the ratified org-control security boundary; no implementation or contract weakening was attempted.
- T-250 records recommendations only; Lead/code-owner rulings remain required.
- Unrelated shared-worktree changes and the closed T-241 audit were preserved.

### Verification

- `npm run typecheck` — passed.
- `npm test` — **107 passed, 1 skipped, 0 failed**.
- `git diff --check` for the T-250 audit/status files — passed.
- T-250 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.

## 2026-09-25 — T-252: master findings register

**Status:** done (read-only consolidation; no source or audit-input changes).

### Files changed

- `docs/audits/FINDINGS.md` — new deduplicated 161-row register with severity, summary, source location, owner-task, and fixed/in-flight/queued/open status.
- `docs/agents/agent-22-status.md` — this entry.

No `kiwi-admin`, `kiwi-autoconfig`, `kiwi-forensics`, `kiwi-app`, contract, or
source audit files were changed by T-252. The three source audits remain intact.

### Evidence and findings

- Read `contract-drift-1.md`, `autoconfig-drift-1.md`, `admin-drift-1.md`, `docs/TASKS.md`, Agent 19/20/22 status logs, recent commits, and current worktree status.
- Canonicalized overlaps: T-241 IPC findings into IPC-1/6/7/8/9 and UIS-6/PAIR-I; T-246 ACFG-3..10 into the existing ACFG IDs; T-250 ADM-T250-01/09/10/11/12/14/15 into ADM-1/8/10/11/12/7/19; retained new ADM-T250-05..08 and 13.
- Cross-referenced current queues: T-237 is in-flight because its ledger row is open/uncommitted; T-239 is fixed; T-245 is in-flight; T-247, T-251, and T-253 are queued; T-231 and T-193 remain active where applicable.
- Included the original high/medium/low/info findings from the broad audit as well as the focused ACFG/admin findings; no duplicate T-241/T-246/T-250 rows remain as separate findings.
- Added a queue/ownership summary and maintenance rule requiring current code/test/contract evidence before changing status to fixed.

### Commands run

- Read-only `glob`, `grep`, and `read` inspection of all three audits, task ledger, agent logs, commits, and worktree status.
- `git diff --check` for the T-252 files — passed.
- No code tests were run because T-252 changes documentation only; the T-250 admin checks remain recorded above.

### Assumptions / risks

- Status is based on the shared tree at consolidation time; concurrent agents may advance task state after this entry.
- T-237’s Agent 20 status says done but explicitly says changes are uncommitted while the task ledger remains open; it is conservatively marked in-flight.
- T-241/T-246/T-250 are audit provenance, not proof that their queued remediation findings are fixed.

### Verification

- `docs/audits/FINDINGS.md` contains one findings table with 161 canonical rows.
- `git diff --check` for `docs/audits/FINDINGS.md` and this status entry — passed.
- T-252 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.

## 2026-09-25 — T-256: sandbox contract-vs-implementation enumeration

**Status:** done (read-only contract/implementation audit; no source or
contract implementation changes).

### Files changed

- `docs/audits/sandbox-drift-1.md` — full coverage matrix for the sandbox
  contract, provider, guest agent, report schema, invariants, and caller
  obligations; includes SBX-1/SBX-2 and the existing SBX-3–7/SBX-I findings.
- `docs/agents/agent-22-status.md` — this entry.

No Rust, TypeScript, shell, `docs/contracts/*`, Tauri, or `FINDINGS.md` files
were changed by T-256. Unrelated shared-worktree changes were preserved.

### Evidence and findings

- Read `docs/contracts/sandbox.md` in full and mapped all ten declared types,
  both async traits, errors, report fields, seven invariants, and caller
  obligations to current source.
- Read the complete `kiwi-sandbox/src/{lib,error,null,wsl2}.rs` implementation,
  the full `kiwi-sandbox/agent/kiwi-agent.sh`, sandbox tests, design doc, and
  T-161/T-168 status history.
- Searched `kiwi-app/src-tauri` and the wider app/forensics tree: no
  `kiwi-sandbox` dependency, sandbox module, Tauri command/registration,
  provider consumer, or IPC wrapper was found.
- Revalidated canonical SBX-1 (fs merge cap 3x), SBX-2 (`ImageMissing` dead),
  SBX-3 (`limits_applied` dropped), SBX-4 (outside-workdir accounting), SBX-5
  (process args string), SBX-6 (network attempts dropped), SBX-7 (probe
  vocabulary), and SBX-I (undocumented surface).
- Recorded provisional T256-O1..O6 observations for absent caller wiring,
  management-command timeout cleanup, root-writable artifact mode, unverified
  rootfs mount policy, incomplete JSON escaping, and the unspecified link
  surface. These do not replace or alter the canonical T-252 register.

### Commands run

- Read-only `glob`, `grep`, and `read` inspection of the contract, provider,
  guest agent, tests, Tauri registry/manifests, design docs, and prior audits.
- `cargo test -p kiwi-sandbox` — **5 passed, 0 failed**.
- `cargo clippy -p kiwi-sandbox --all-targets -- -D warnings` — passed.
- `cargo fmt -p kiwi-sandbox --check` — passed.
- `git diff --check --no-index -- NUL docs/audits/sandbox-drift-1.md` — passed.
- `git diff --check --no-index -- NUL docs/agents/agent-22-status.md` — passed.

### Assumptions / risks

- The WSL2 live lifecycle test remains environment-gated; source evidence and
  the existing test implementation were used for this read-only audit.
- `wsl.conf` automount/interop policy is a prepared-image assumption, not a
  provider-validated fact; T256-O2 records the deployment risk.
- T256-O1..O6 are provisional owner-review notes and were not added to the
  canonical `FINDINGS.md`; SBX-1/SBX-2 remain the required open register rows.
- T-241, T-246, and T-250 remain closed and untouched; concurrent Agent 18/19/
  20/21 work was not modified.

### Verification

- `docs/audits/sandbox-drift-1.md` contains a contract-promise matrix and
  detailed SBX findings with file:line evidence, severity, and resolution.
- `cargo test -p kiwi-sandbox` — **5 passed, 0 failed**.
- `git diff --check` for the T-256 audit/status files — passed.
- T-256 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.

## 2026-09-25 — T-258: mailauth post-T-183 contract-vs-code verification

**Status:** done (read-only contract/source audit; no source or contract
implementation changes).

### Files changed

- `docs/audits/contract-drift-1.md` — appended the T-258 14-group
  mailauth verification matrix, §9 deviation check, MAUTH-2/3 resolution, and
  residual findings.
- `docs/agents/agent-22-status.md` — this entry.

No `kiwi-mailauth` source, test, dependency, or `docs/contracts/*` files were
changed. Unrelated shared-worktree changes were preserved.

### Evidence and findings

- Read `docs/contracts/mailauth.md`, all current `kiwi-mailauth/src/` modules,
  `Cargo.toml`, Agent 16's T-183 status/commit, and the existing MAUTH rows.
- Verified the 14 task-level T-183 behavior groups against current code and
  tests: DKIM empty-body/`l=`/header-hash/order/canonicalization/`b=`/`t=x=`;
  SPF include/redirect/void/caps/macro grammar; and DMARC From-first,
  subdomain `sp=`, and multi-record behavior.
- Confirmed the three ratified §9 deviations are documented and implemented:
  invalid/absent DMARC `p=`/`sp=` → `permerror`, strict macro-label rejection
  of percent escapes, and KIWI's 14-day `t=` window with `x=` precedence.
- MAUTH-2 and MAUTH-3 are resolved by the updated contract/code pair; retained
  residuals include MAUTH-1/4/5/6/7/8 and T258-specific org-override,
  empty-PTR-void, unknown-macro, identical-DKIM-field, and contract-status
  observations.
- No `FINDINGS.md` changes were made; this read-only task did not alter the
  canonical register.

### Commands run

- `cargo test -p kiwi-mailauth` — **63 passed, 0 failed**.
- `cargo clippy -p kiwi-mailauth --all-targets -- -D warnings` — passed.
- `cargo fmt -p kiwi-mailauth --check` — passed.
- `git diff --check -- docs/contracts/mailauth.md docs/audits/contract-drift-1.md docs/agents/agent-22-status.md` — passed after the T-258 append.

### Assumptions / risks

- Line references reflect the current shared-worktree snapshot; unrelated
  concurrent changes may shift them.
- T258-specific findings are provisional owner-review notes and are not
  silently promoted to canonical register IDs.
- The contract still says T-183/§9 review is pending in its metadata; T-258
  records that documentation-state mismatch without editing the contract.
- No live DNS/network test was run; the crate's tests use `MockResolver` and
  remain fully offline.

### Verification

- T-258 audit section contains all 14 requested groups, file:line evidence,
  the three ratified deviations, and residual recommendations.
- `cargo test -p kiwi-mailauth` — **63 passed, 0 failed**.
- Clippy, rustfmt, and targeted diff checks — passed.
- T-258 Orca DONE report sent to terminal
  `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`; receipt returned `accepted: true`.
