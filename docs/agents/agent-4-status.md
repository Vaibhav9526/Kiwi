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

---

## 2026-09-19 — REASSIGNED: T-004 completion, T-108, T-109 → Agent 5 (temporary)

**Status:** `paused / standby-reviewer`. Per Lead + `docs/AGENT_HANDOFF.md`
(HANDOFF T-004/T-108/T-109 — repeated inference timeouts). I make **no edits**
to `kiwi-admin/` or `docs/contracts/admin-api.md` until Lead re-clears me
(prompt.md §8 conflict rule). My only writes are this status file.

### Correction to the handoff record (for Agent 5 + Lead)

The AGENT_HANDOFF.md entry says compile/test state "unverified / tests
unknown". **That is now superseded** — before standing down I ran read-only
verification (no source edits):

- `cd kiwi-admin && npx tsc --noEmit` → **0 errors** (strict).
- `cd kiwi-admin && npx vitest run` → **4 files / 34 tests passed** (526 ms)
  — rbac 9, audit.chain 5, policy.evaluator 13, services 7.

Agent 5 inherits a **green baseline**, not an unknown one. T-004 deliverables
are complete as described in my T-004 entry above; my `in-review` status
stands (Agent 6/Lead still hold `done` authority).

### What T-108/T-109 need (design notes carried over — nothing in code yet)

Contract v1 already reserves both seams; Agent 5 should implement server-side
against `createServiceContainer()`:

- **T-108 (policy bridge, server side):** endpoint
  `POST /api/v1/policies/{policyId}/evaluate` → `PolicyService.evaluate`
  (`src/policy/services.ts`, pure `evaluatePolicy`, reason codes in
  `src/policy/model.ts`, semantics in contract §5). Open design decisions
  needing **Lead sign-off** before Agent 5 codes them:
  1. **Machine-actor model.** RBAC v1 is human-role based
     (org_admin/security_admin/viewer). The kiwi-mail send path needs an
     actor with `policy.read` (evaluate) + `mailflow.ingest`. Options:
     (a) dedicated `service` role (RBAC matrix change → contract v2), or
     (b) bind a platform-scoped actor per device from the `devices` table.
     Do NOT shoe-horn a human role for a machine principal.
  2. **Audit policy for evaluate.** v1 audits mutations + denials. Decide:
     are *allowed* evaluations audited too? (block/warn decisions are
     high-value forensic evidence; but every send would grow the chain —
     possible compromise: audit only warn/block outcomes + all denials.)
  3. **Failure semantics.** If kiwi-admin is unreachable, kiwi-mail must
     fail closed or fail open **per org policy** — that choice belongs in
     the contract, decided by Lead, not improvised client-side.
- **T-109 (mail-flow ingest):** endpoint `POST /api/v1/mailflow/events` →
  `MailflowService.ingest` (`src/mailflow/services.ts`; strict parser
  `parseMailflowIngest` already enforces metadata-only + org_id required for
  outbound + canonical TLS labels). Considered schema change for Agent 5 to
  propose: idempotency via `UNIQUE(org_id, message_id, direction)` to dedupe
  client retries (migration **v2**, sequential migrations make this safe).
  Hard rule unchanged: **no body/subject/content fields anywhere**
  (prompt.md §6; unknown fields are already dropped, not stored).

### Reviewer/backup duties while reassigned (read-only)

When Agent 5 lands changes I will review against: strict validation at every
boundary; audit on every mutation and denial; `verify()` chain still green;
no body/secret fields; evaluator still pure/deterministic; migrations remain
sequential and append-only; tests green (`tsc --noEmit` + `vitest run`).

No further entries until I resume or review.


---

## 2026-09-19 — T-136 (brief: T-137) — mobile/ authenticator scaffold + contracts/authenticator.md — COMPLETE, ready for review

**Status:** `in-review` (Agent 6/Lead hold `done` authority per TASKS.md
rules). Brief said "code only, no build run needed" — the toolchain was
available, so verification was actually run; results below.

### Scope note

kiwi-admin freeze honored: `kiwi-admin/` and `docs/contracts/admin-api.md`
untouched (git status below). Write surface: `mobile/` (new),
`docs/contracts/authenticator.md` (new), this status file.

### Files created

- `docs/contracts/authenticator.md` — contract v1: invariants; QR payload v1
  (`kiwi-pairing` JSON; single-use 8..128-char ticket; ≤5 min TTL);
  pairing-channel handshake (TLS + pinned desktop key); canonical challenge
  bytes with byte-parity to kiwi-core `Challenge::canonical_bytes`
  (u32be length prefixes, event tags 0x01–0x04, 32B nonce, i64be times);
  nonce/expiry/replay rules; keystore-only key lifecycle (Ed25519 required;
  ecdsa-p256/rsa3072 reserved + fail-closed); approve/deny semantics
  (§6.3: deny unsigned, audited, non-consuming); offline queue (§7);
  scaffold map; audit/test map; versioning (tag/canonical change ⇒ v2 +
  coordinated release); limitations; 4 open items flagged for Lead + Agent 6.
- `mobile/` (30 files): package.json (pinned deps incl. react-native
  0.76.5), tsconfig.json (strict + noUncheckedIndexedAccess +
  exactOptionalPropertyTypes), tsconfig.core.json (RN-free subset),
  vitest.config.ts, .eslintrc.js, babel/metro config, app.json, index.js,
  .gitignore, README.md; src/protocol/{event,types,validate,qr,canonical,
  replay,queue}.ts; src/keystore/{keystore,soft-hsm}.ts (fail-closed,
  test-only HSM); src/screens/{Pairing,PendingApprovals}Screen.tsx;
  src/App.tsx; tests/ 5 suites + helpers/protocol.ts.

### Commands run + results

- `npm install` (pinned set) → 791 packages; package-lock.json complete.
- `npx tsc --noEmit -p tsconfig.core.json` → **0 errors**.
- `npx tsc --noEmit` (full app incl. RN screens) → **0 errors**.
- `npx vitest run` → **5 files / 32 tests passed** (canonical 10, qr 8,
  queue 5, replay 5, soft-hsm 4).
- Not run (per brief): `npm run android/ios`, metro bundling, eslint
  (config present; lint deferred — noted in README).

### Session incident (disclosed)

One mangled edit created a stray directory `D:\Hack header\session.ts`
outside the repo; deleted immediately, verified `D:\` contains only the
real tree, and re-read confirmed the intended `canonical.ts` content was
intact (the corrupt variant never landed). No repo file corrupted; final
gates pass on clean content.

### Assumptions

- `session_id` on unlock challenges carries the desktop transaction id
  (`x-tx:<txn>`); exact source = open item §10.3 (Agent 7 / T-120 IPC).
- QR ingest is paste-based in scaffold; camera scan is Phase 4 — contract
  §3.2 unchanged by ingest mode.
- React Native 0.76.5 + RN CLI config style as current stable; final RN
  pin is Lead's call at Phase 4 kickoff.

### Risks / open items for Lead + Agent 6

1. **Crypto sign-off gate** (SECURITY.md §6): the keystore-wrapped-seed
   fallback (§5) needs explicit approval; nothing in this scaffold touches
   raw key material (soft-hsm is test-only, refuses empty-seed signing).
2. Pairing transport choice (websocket vs mDNS TCP) — §10.2.
3. Deny-vs-timeout audit wording — §10.4, align with Agent 6 when the
   challenge flow lands in kiwi-app.
4. ESLint not yet executed (config in place); Agent 6's gate should add
   `npm run lint` for mobile on first review.

