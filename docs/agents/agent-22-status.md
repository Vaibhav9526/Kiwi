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
