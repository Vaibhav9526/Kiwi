# Agent 4 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

---

## 2026-09-19 — T-004 (org/policy model + kiwi-admin scaffold) — COMPLETE, ready for review

**Status:** `in-review` (not self-marking `done` in TASKS.md — Agent 6/Lead
authority per TASKS.md rules). All brief deliverables implemented and
verified green.

### Files changed (all inside my boundary)

- `kiwi-admin/package.json` — pinned deps: typescript 5.7.3, vitest 3.2.4,
  @types/node 22.10.5. **Runtime dependencies: zero** (Node stdlib only).
- `kiwi-admin/tsconfig.json` — strict + `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noImplicitOverride`, NodeNext.
- `kiwi-admin/vitest.config.ts`, `kiwi-admin/README.md`.
- `kiwi-admin/src/types.ts` — roles, TLS ordering/aliases, domain helpers.
- `kiwi-admin/src/util/validate.ts`, `kiwi-admin/src/util/logger.ts` —
  untrusted-input validators; secrets-free structured logger.
- `kiwi-admin/src/db/driver.ts` — SQLite via **`node:sqlite`** (built into
  Node ≥22.5) behind a dialect-neutral `Db` facade (ADR-003 Postgres seam).
- `kiwi-admin/src/db/migrations.ts` — v1 org-model schema (9 tables + ledger).
- `kiwi-admin/src/db/interfaces.ts` — repository interfaces (Postgres-ready).
- `kiwi-admin/src/db/sqlite-org.ts`, `kiwi-admin/src/db/sqlite-mailflow.ts` —
  SQLite repository implementations.
- `kiwi-admin/src/policy/model.ts`, `kiwi-admin/src/policy/evaluator.ts` —
  deterministic policy evaluator (pure, no I/O, no AI).
- `kiwi-admin/src/policy/services.ts`, `kiwi-admin/src/mailflow/services.ts` —
  RBAC-enforced service wrappers.
- `kiwi-admin/src/audit/model.ts`, `kiwi-admin/src/audit/chain.ts` —
  hash-chained append-only audit log (SHA-256 chain from `genesis`).
- `kiwi-admin/src/rbac/rbac.ts` — permission model, `requirePermission()`,
  `AuthorizationDeniedError`.
- `kiwi-admin/src/services.ts` — `createServiceContainer()` composition root;
  every mutation/denial audited.
- Tests: `tests/policy.evaluator.test.ts` (13), `tests/rbac.test.ts` (9),
  `tests/audit.chain.test.ts` (5), `tests/services.test.ts` (7),
  `tests/helpers/db.ts`.
- `docs/contracts/admin-api.md` — contract v1 (endpoints + RBAC table,
  policy/mailflow/audit schemas, evaluator semantics, test map).

### Commands run + results

- `npm install` → ok (dev deps only).
- `npx tsc --noEmit` → **0 errors** (strict).
- `npx vitest run` → **4 files / 34 tests passed** (~0.4 s).
  Covers: domain allow/deny, external-recipient warn/block, min-TLS downgrade
  block + unverified-TLS warn, disabled policy, determinism; RBAC matrix +
  cross-org denial + negative cases + denials audited; audit chaining,
  field-tamper detection, row-deletion detection, strict parsing; service
  wiring incl. mailflow metadata-only (no body field) ingest.

### Assumptions

- `node:sqlite` accepted as the "better-sqlite3 or equivalent" from the brief
  (zero native deps = minimal pinned dep set; native-module build risk on
  Windows avoided). If Lead prefers better-sqlite3, only `src/db/driver.ts`
  changes.
- External-recipient "external" = recipient domain not covered by an allow
  rule; org-owned domains table exists but is not yet joined into evaluation
  (Phase 6 work, noted in contract §5.2).
- min-TLS applies to outbound only in v1; unknown TLS warns, never blocks
  (deterministic model acts on measured facts only).
- Timestamps are Unix seconds (INTEGER) in SQLite.

### Risks / open items for Lead

1. `audit_log` append-only is enforced **by application convention**, not yet
   by SQLite triggers — raw-SQL tampering from a same-DB process is possible.
   Hardening follow-up suggested (documented in admin-api.md §7).
2. Multi-process audit appends need a file lock before any second process
   opens `kiwi-admin.db` (single-process verified only).
3. vitest upgraded 2.1.8 → 3.2.4: vitest 2.x's bundled Vite cannot resolve
   the `node:sqlite` builtin (test-suite load failure). Any other Node/TS
   package should start at vitest ≥3.
4. Org domain → evaluator linkage ("internal vs external" definition) to be
   finalized with Lead in Phase 6 before any UI labels a domain "external".
5. No secrets in code/tests/docs: fixture actors use `*.test` example
   domains; no credentials anywhere (verified by reading all files).

