# Contract — kiwi-admin API (org / policy / mailflow / audit)

> Owner: Agent 4 · **Contract version: 1.3** (T-134 list endpoints + dev HTTP
> transport by Agent 5; **Lead-reviewed 2026-09-20 — approved**) · §13 (T-179
> audit export) is implemented but **pending Lead review**; §14 (device
> inventory, T-188) is a **proposed, not-implemented** addition · Status: active
> Implemented by `kiwi-admin/` (Node + TypeScript). Reference implementation:
> `src/services.ts` (service layer) + `src/policy/evaluator.ts` (deterministic
> evaluator). The REST transport is layered over these services; the endpoint
> table fixes RBAC so the future HTTP layer cannot drift. Changes require
> Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: kiwi-admin ↔ local admin UI (React+TS, Phase 6+); kiwi-admin ↔
Thunderbird KIWI integration layer (policy check at compose/send, mailflow
metadata ingest); kiwi-admin ↔ kiwi-core (device/session identity, Phase 3+).

## 1. Invariants (binding on all parties)

- **Deterministic only.** Policy evaluation, RBAC, and audit verification
  never require AI (SECURITY.md rule 1).
- **Localhost only.** The service binds to a local interface, never a remote
  listener. Phase 0 exposes services as an in-process TypeScript API
  (`createServiceContainer()`); the REST mapping below is the wire contract
  for the HTTP layer added later.
- No message bodies, credentials, tokens, or secrets in any payload, store,
  or log (SECURITY.md rules 5, 6). Mail-flow events are **metadata only**.
- All externally supplied input is untrusted: every request payload passes
  validation (`src/util/validate.ts`) before use (SECURITY.md rule 9).
- Unknown fields are ignored, not fatal; integer `schema_version`; producers
  emit `1`.
- Every mutating operation and every authorization denial is audited to the
  append-only hash-chained log (SECURITY.md rule 11).
- **Advisory verdicts.** Policy verdicts decide what the local client should
  do. Real organizational enforcement must happen at a mail gateway/relay; a
  UI-only block is NOT complete organizational enforcement (prompt.md §6).

## 2. Roles and permissions (v1)

| role | permissions |
|------|-------------|
| `org_admin` | all: org.read, org.create, org.update, user.read, user.invite, user.role.grant, device.read, device.revoke, policy.read, policy.write, mailflow.read, mailflow.ingest, audit.read, audit.export |
| `security_admin` | org.read, user.read, device.read, device.revoke, policy.read, policy.write, mailflow.read, audit.read |
| `viewer` | org.read, user.read, device.read, policy.read, mailflow.read, audit.read |

`audit.export` (T-179) is held ONLY by `org_admin` and is deliberately not
implied by `audit.read`: every role may read the log, but taking a signed
off-box copy of the whole chain — the evidence artifact — is an owner-level
act. See §13.

- Org scoping: an actor whose session is bound to org X cannot exercise
  org-scoped permissions against org Y (`hasPermission()` in
  `src/rbac/rbac.ts`). Fail-closed (T-193/H2): an actor with NO org binding
  holds NO org scope — a null org target denies nothing by itself, but any
  non-null org target denies a null-org actor, so omitting `x-kiwi-org`
  narrows rather than widens. Org-bound reads default to the caller's own
  org (T-193/H4, §12.3). Platform-level actors (`org_id` null) holding
  `org.create` may create new orgs but hold no org-scoped rights until granted.
- Denials surface as `403` (or `AuthorizationDeniedError` in-process) and are
  always audited with `outcome: "denied"` and `details.permission`.

## 3. Endpoints (wire mapping; service call = current in-process API)

| Method + path | Service call | Permission | Notes |
|---------------|--------------|------------|-------|
| `POST /api/v1/orgs` | `OrgService.createOrg` | `org.create` (org_admin only; T-193/H5) | |
| `GET  /api/v1/orgs/{orgId}/users` | `OrgService.listUsers` | `user.read` | T-134: users with roles, email-ordered |
| `GET  /api/v1/orgs/{orgId}/devices` | `OrgService.listDevices` | `device.read` | T-188: device inventory; see §14 — **not implemented** |
| `POST /api/v1/orgs/{orgId}/users` | `OrgService.createUser` | `user.invite` | |
| `PUT /api/v1/orgs/{orgId}/users/{userId}/role` | `OrgService.grantRole` | `user.role.grant` | |
| `POST /api/v1/devices/{deviceId}/revoke` | `OrgService.revokeDevice` | `device.revoke` | |
| `POST /api/v1/orgs/{orgId}/policies` | `PolicyService.createPolicy` | `policy.write` | body = PolicyObject minus id |
| `GET /api/v1/orgs/{orgId}/policies` | `PolicyService.listPolicies` | `policy.read` on owning org | T-134: full definitions with domain rules |
| `POST /api/v1/policies/{policyId}/evaluate` | `PolicyService.evaluate` | `policy.read` on owning org | deterministic; single-policy check |
| `POST /api/v1/orgs/{orgId}/policies/evaluate-outbound` | `PolicyService.evaluateOutbound` | `policy.read` on the org | T-108 send-path bridge; see §10 |
| `POST /api/v1/mailflow/events` | `MailflowService.ingest` | `mailflow.ingest` | MailflowEvent schema §6 |
| `GET  /api/v1/mailflow/events` | `MailflowService.query` | `mailflow.read` | filters: org, recipient domain, ts range, limit ≤ 1000; org-bound callers omitting org read their own org (T-193/H4) |
| `GET  /api/v1/audit` | `AuditService.query` | `audit.read` | filters: org, ts range, limit ≤ 1000 |
| `GET  /api/v1/audit/verify` | `AuditService.verify` | `audit.read` | replays hash chain; see §7 |
| `GET  /api/v1/audit/export` | `AuditService.export` | `audit.export` | T-179 signed NDJSON of the FULL chain; see §13 |

Error shape (uniform): `{ "error": { "code": string, "message": string, "details"?: object } }`.
Stable codes are `auth.required` (reserved for the future authenticated
transport), `auth.denied`, `validation.failed`, `not.found`, `conflict`, and
`internal`. The current header-actor scaffold reports missing/unusable
credentials as `403 auth.denied`, not `401 auth.required`. Validation failures
name the offending field; `internal` messages expose only a correlation
reference.

<!-- CONTINUED-1 -->

## 4. SQLite schema (v1 — org model)

One file per service boundary (`kiwi-admin.db`, ADR-003). Drizzle ORM
(ADR-006, T-130): PostgreSQL schema `src/db/schema.pg.ts` is primary with
Drizzle Kit migrations in `drizzle/pg/`; SQLite mirror `src/db/schema.sqlite.ts`
with migrations in `drizzle/sqlite/` for tests/local. Runtime applies pending
migrations idempotently via Drizzle's journal-tracked migrator
(`__drizzle_migrations`). The audit append-only triggers ship as custom
migration `0001` in BOTH dialects (SQLite `RAISE(ABORT)`; PG plpgsql
`RAISE EXCEPTION`).

| table | key columns | notes |
|-------|-------------|-------|
| `orgs` | `id PK`, `name`, `created_at` | |
| `domains` | `org_id+domain PK`, `verified` | FK → orgs CASCADE |
| `users` | `id PK`, `org_id FK`, `email`, `UNIQUE(org_id,email)` | |
| `user_org_roles` | `user_id+org_id PK`, `role CHECK('org_admin','security_admin','viewer')`, `granted_at` | |
| `devices` | `id PK`, `org_id FK`, `label`, `revoked`, `revoked_at` | |
| `policies` | `id PK`, `org_id FK`, `name`, `enabled`, `min_tls`, `external_recipients CHECK('allow','warn','block')` | `min_tls` nullable = no floor |
| `policy_domain_rules` | `policy_id+domain PK`, `action CHECK('allow','block')` | FK → policies CASCADE |
| `mailflow_events` | `id PK`, `org_id`, `direction CHECK('inbound','outbound')`, `sender`, `recipient`, `ts`, `message_id`, `tls_version`, `security_status`, `policy_verdict CHECK('allow','warn','block','unknown')`, `received_at` | indexed `(org_id, ts)`, `(recipient)`; **no body column by design** |
| `audit_log` | `seq PK AUTOINCREMENT`, `ts`, `actor_subject`, `actor_roles`, `org_id`, `action`, `resource`, `outcome CHECK('allowed','denied','error')`, `request_id`, `details`, `prev_hash`, `entry_hash` | append-only; see §7 |

Timestamps are Unix milliseconds (INTEGER) — every service-stamped field
(`created_at`, `granted_at`, `revoked_at`, audit `ts`, mailflow `received_at`,
export `exported_at`). Caller-supplied mailflow message-time `ts` (§6) passes
through as given in the same unit. Booleans stored as 0/1.

## 5. Policy object + evaluator semantics

### 5.1 PolicyObject

```json
{
  "id": "pol-…",
  "org_id": "org-…",
  "name": "default-outbound",
  "enabled": true,
  "min_tls": "tls1.2" | null,
  "external_recipients": "allow" | "warn" | "block",
  "domain_rules": [ { "domain": "partner.example", "action": "allow" | "block" } ]
}
```

`min_tls` uses the canonical labels `ssl3 | tls1.0 | tls1.1 | tls1.2 | tls1.3`
(case-insensitive aliases accepted on input, e.g. `TLS1_2`).

### 5.2 Evaluator (deterministic; `src/policy/evaluator.ts`)

Order for outbound mail: (1) recipient domain parseability, (2) explicit
block rule, (3) explicit allow rule, (4) external-recipient behavior
(warn/block/allow for any recipient not covered by an allow rule), (5)
min-TLS floor on the observed transport TLS of the connection. Verdict
severity `block > warn > allow`.

- Unparseable recipient → **block** (`recipient-unparseable`).
- Explicit block rule match → **block** regardless of other facts.
- Below-minimum observed TLS → **block** (`tls-below-minimum`).
- TLS unobserved/unknown → **warn** (`tls-unverified`) — never block:
  absence of evidence is not evidence of weakness (deterministic model can
  only act on measured facts).
- External recipient with `warn` → **warn** (`external-recipient`).
- min-TLS applies to outbound direction only (v1).

### 5.3 Reason codes (stable identifiers)

`recipient-unparseable`, `recipient-domain-blocked`,
`recipient-domain-allowed`, `external-recipient`, `tls-below-minimum`,
`tls-unverified`, `no-policy-enabled`.

**Limitation (honest-enforcement):** verdicts returned here are advisory
decisions. Gateway/relay enforcement is out of scope for v1; any UI must not
represent a client-side block as complete organizational enforcement.

<!-- CONTINUED-2 -->

## 6. MailflowEvent (metadata only)

```json
{
  "id": "uuid",
  "org_id": "org-… | null (required for outbound)",
  "direction": "inbound" | "outbound",
  "sender": "user@example.test",
  "recipient": "user@example.test",
  "ts": 1726000000,
  "message_id": "<…> | null",
  "tls_version": "tls1.3 | … | null (unobserved)",
  "security_status": "clean | warn | suspicious | tls-mismatch | unknown",
  "policy_verdict": "allow | warn | block | unknown"
}
```

- Ingest requires `mailflow.ingest`; queries require `mailflow.read` scoped
  to the org.
- No `body`, subject, or content field exists at any layer. Adding one is a
  contract change requiring Lead review (prompt.md §6 Agent 4: no message
  bodies by default for admin analytics).
- `ts` is caller-supplied message time in Unix milliseconds (§4);
  `received_at` (set by the service, also milliseconds) is ingest time.

## 7. Audit event + hash chain

```json
{
  "seq": 12,
  "ts": 1726000000,
  "actor": { "subject": "admin@acme.test", "roles": ["org_admin"] },
  "org_id": "org-…",
  "action": "policy.create",
  "resource": "pol-…",
  "outcome": "allowed | denied | error",
  "request_id": "… | null",
  "details": {},
  "prev_hash": "<hex64>",
  "entry_hash": "<hex64>"
}
```

- `entry_hash = SHA-256(canonical JSON of the event fields +
  prev_hash)`; canonical JSON = fixed field order, `roles` sorted as stored,
  `details` as persisted. First record's `prev_hash` = `"genesis"`.
- `verify()` replays the chain from genesis; any field mutation or row
  deletion breaks verification (`chain broken at seq N`). Implemented in
  `src/audit/chain.ts` + `AuditService.verify`.
- Append-only enforced at TWO layers: (1) DB triggers `audit_log_no_update` /
  `audit_log_no_delete` (migration v2) abort any UPDATE or DELETE from any
  connection, including raw SQL from this process; (2) `verify()` replays the
  hash chain AND requires contiguous `seq` within the verified window, so a
  gap left by row removal is flagged even if hashes were recomputed.
- Residual risks (honest, accepted): a file-write holder can `DROP TRIGGER`
  first and then tamper — triggers raise the bar, they are not a trust root.
  Tail truncation (deleting the newest rows) verifies clean without an
  external high-water mark. Mitigations: OS file ACLs on `kiwi-admin.db`,
  `verify()` on service startup, backup comparison for high-value
  deployments. A retained signed export (`GET /api/v1/audit/export`, §13) is an externally verifiable high-water mark for its point in time: tail truncation after an export breaks against it. Concurrent appends are serialized in the repository transaction (`AuditRepository.appendChained`, T-193/H6 — tail-read, `seq` assignment, hash, and insert in one driver transaction; Postgres additionally takes a transaction-scoped advisory lock), so no two appends share a `seq` even across processes, and the chain stays gapless, which is what the contiguity check above relies on.

## 8. Cross-service notes

- Device identity (`devices` table) is owned here; the trust/session model
  and authenticator binding live in kiwi-core (contract
  `contracts/security-session.md`). kiwi-admin stores device records and
  revocation state only.
- Mailflow events reference org/user/device by id, never by credential.
- Postgres path (T-130): `src/db/schema.pg.ts` + `drizzle/pg/` migrations are
  the primary DDL; `src/db/repositories.pg.ts` implements the async mirror
  (`AsyncInterface`) of the sync repository contracts, with PG booleans mapped
  to 0/1 at the boundary. Sync interfaces in `src/db/interfaces.ts` remain the
  contract for the local in-process path (SQLite/Drizzle). Unifying services on
  async is tracked follow-up work (needs Lead). Connection strings are
  caller-supplied env (`DATABASE_URL`) — never code, logs, or migrations.

## 9. Test map (evidence for T-004)

| test file | covers |
|-----------|--------|
| `tests/policy.evaluator.test.ts` | allow/deny domain rules, external-recipient warn/block, min-TLS downgrade block, unverified-TLS warn, determinism |
| `tests/rbac.test.ts` | role permission matrix, cross-org denial, negative cases, denials audited |
| `tests/audit.chain.test.ts` | chaining, tamper detection (field edit), deletion detection (replay), canonical hashing, strict input parsing |
| `tests/services.test.ts` | service-level RBAC + audit wiring, policy determinism through service, mailflow metadata-only ingest, chain verification |
| `tests/policy.bridge.test.ts` (T-108) | org worst-wins per-recipient verdicts, min-TLS block, alias normalization, no-policy allow, cross-org denial audited, input validation, core determinism |
| `tests/mailflow.emitter.test.ts` (T-109) | per-recipient expansion, metadata-only keys, unknown-defaulting, ingest round-trip, end-to-end service ingest, inbound builder |
| `tests/audit.guard.test.ts` (tamper guard) | trigger rejection of UPDATE/DELETE, trigger registration, seq-gap detection, restart-safe idempotent migrations |
| `tests/db.migrations.test.ts` (T-130) | fresh-file migration (9 tables + triggers), idempotent re-migrate, FK enforcement, PG/SQLite artifact DDL assertions, PG live round-trip (skipped without `DATABASE_URL`), compile-time PG repo conformance |

Run: `npm run typecheck && npm test` (55 tests passing + 1 PG-live skip at T-130 close).

## 10. Send-path bridge — T-108 (kiwi-mail send path ↔ kiwi-admin)

`npm run build && npm run serve` (env `KIWI_ADMIN_DB`, `KIWI_ADMIN_PORT`;
defaults `kiwi-admin.db`, `8471`). Implements the §3 + §10 wire mapping over
the services plus extra-contract `GET /healthz` (`{status, service, version,
contract}`) for process supervision (Agent 6 T-133). Binds **127.0.0.1 only**.

DEV-AUTH WARNING (scaffold only): actor identity arrives via `x-kiwi-subject`
/ `x-kiwi-roles` / `x-kiwi-org` headers — convenient, NOT secure. kiwi-core
session auth (Phase 3+) replaces header actors before this transport serves
anything beyond local development. The header scheme must never survive
contact with a non-loopback listener.

The compose-send hook (kiwi-mail, Agent 2) consults the bridge BEFORE
transmission; the frontend composer banner (KIWI-UI-007) renders the
per-recipient results. Wire shape:

```json
// POST /api/v1/orgs/{orgId}/policies/evaluate-outbound  (permission: policy.read)
{ "sender": "alice@acme.test", "recipients": ["b@partner.example"], "tlsVersion": "tls1.3" }
// → 200
{
  "orgId": "org-…",
  "overall": "allow | warn | block",
  "results": [
    { "recipient": "b@partner.example", "verdict": "allow",
      "reasons": [{ "code": "recipient-domain-allowed", "detail": "partner.example" }],
      "policyId": "pol-…" }
  ]
}
```

Rules (implemented by `PolicyService.evaluateOutbound` over the pure core
`evaluateOutboundForOrg` in `src/policy/services.ts`):

- Input validated as untrusted: org/user/address identifiers, 1–256
  recipients, TLS label via canonical aliases (unknown label → 400
  `validation.failed`, never silent allow-on-typo).
- All ENABLED policies of the org evaluate each recipient (§5.2 order);
  worst verdict wins per recipient; `overall` is worst across recipients —
  the send path must not transmit when ANY recipient is `block`.
- No enabled policies → per-recipient `allow` with reason
  `no-policy-enabled` (documented, auditable — not silent).
- Allowed AND denied checks are audited (`policy.evaluate_outbound`).
- Advisory only (§5.3 honest-enforcement): a `block` stops the local client;
  gateway/relay enforcement is out of scope for v1.
- kiwi-mail side (Agent 2): call with the OBSERVED transport TLS of the
  sending connection (`tlsVersion: null` when unobserved — warns, never
  blocks, per §5.2); on bridge unreachable, fail closed for send (hold in
  outbox, banner "Policy check unavailable").

## 11. Mail-flow emitter — T-109 (client → kiwi-admin ingest)

After the bridge verdict is known and the SMTP result is known, the client
emits send-attempt facts; after receive sync it emits received facts. Pure
builders in `src/mailflow/emitter.ts`; transport is `MailflowService.ingest`
(§3, permission `mailflow.ingest`); schema is §6 (metadata only).

- `buildSendAttemptEvents({ orgId, sender, perRecipient: [{ recipient, policyVerdict }], tlsVersion, securityStatus?, messageId?, ts })`
  → one outbound wire event per recipient. `policyVerdict` comes from the
  §10 bridge result; attempts are recorded regardless of delivery outcome
  (v1 stores advisory verdict, not delivery status).
- `buildReceivedEvent({ orgId | null, sender, recipient, tlsVersion, securityStatus?, messageId?, ts })`
  → one inbound wire event per received message (`policy_verdict: "unknown"`).
- Builder output is re-validated by `parseMailflowIngest` on ingest — the
  emitter never bypasses validation (round-trip proven in tests).
- Emission points (kiwi-mail, Agent 2): post-send-attempt (all recipients of
  the attempt) and post-receive-sync (per message). Failures to emit must not
  fail delivery; queue-and-retry locally.
- `security_status` reflects OBSERVED transport/findings only; builders
  default it to `"unknown"` — never inferred from the policy verdict.

## 12. Dev HTTP transport — T-134 scaffold (`src/server.ts`)

`npm run build && npm run serve` (env `KIWI_ADMIN_DB`, `KIWI_ADMIN_PORT`,
`DATABASE_URL`; defaults `kiwi-admin.db`, `8471`, unset). Implements the §3 +
§10 wire mapping over the services plus extra-contract `GET /healthz`
(`{status, service, version, contract}`) for process supervision (Agent 6
T-133). Binds **127.0.0.1 only**.

### 12.1 Dialect selection (`src/services.ts`)

`createServiceContainer` branches on `DATABASE_URL`:

| `DATABASE_URL` | driver | migrations applied |
|----------------|--------|--------------------|
| set | Postgres (ADR-006) | `drizzle/pg` via `migratePg` |
| unset/empty | SQLite (ADR-003) | `drizzle/sqlite` via `migrateSqlite` |

Compose sets `DATABASE_URL`, so the containerized service is Postgres-backed
and `depends_on: db: service_healthy` is load-bearing. A bare dev shell has no
`DATABASE_URL` and stays on SQLite.

ONE service layer serves both. `db/interfaces.ts` declares repository methods
as `MaybePromise<T>` and every service awaits them — `await` on a non-Promise is
a no-op, so SQLite stays synchronous end to end while Postgres resolves
normally. The pure cores (policy evaluator, audit chain, validation, RBAC) did
not gain async. `ServiceContainer.dialect` names the driver in use and is logged
at startup; `ServiceContainer.db` (the raw synchronous SQL facade) is SQLite
only and is `null` on Postgres.

The migration SQL is runtime data, not build input: the image must ship
`drizzle/` or the migrator cannot find `meta/_journal.json` and the container
exits before binding a port.

### 12.2 Dev auth — header actors

DEV-AUTH WARNING (scaffold only): actor identity arrives via `x-kiwi-subject`
/ `x-kiwi-roles` / `x-kiwi-org` headers — convenient, NOT secure. kiwi-core
session auth (Phase 3+) replaces header actors before this transport serves
anything beyond local development. The header scheme must never survive
contact with a non-loopback listener. **Header actors are a dev scaffold, not
authentication**: a caller can claim any subject and any role.

What the scaffold DOES guarantee, so that removing it later is a swap rather
than a rewrite:

- **`x-kiwi-roles` is fail-closed.** An absent header, an empty string, or a
  value whose tokens are all unrecognized yields an EMPTY role set, and every
  permission check then refuses with `403 auth.denied`. It does not fall back
  to `org_admin`. `x-kiwi-subject` falls back to the placeholder
  `local-unauthenticated` only so the denial is attributable in the audit log.
- **Every route is permission-checked, the audit reads included.**
  `GET /api/v1/audit` and `GET /api/v1/audit/verify` both require `audit.read`
  (§2, §3), enforced in `AuditService` so a denial is attributed to the actor.
  `verify` reads the FULL chain regardless of any org filter — a hash chain
  only validates over every row, so an org-scoped window would report a
  false `valid`.

### 12.3 Audit query filters

`GET /api/v1/audit` accepts `org`, `since`, `until`, `limit` (≤ 1000).

- `org` narrows to that org's rows, applied in SQL. Rows with a NULL `org_id`
  — platform-level acts such as `org.create` — belong to no org and are
  excluded from an org-scoped read. An org-bound caller (session `org_id`
  set) who omits `org` reads their OWN org, never the whole log (T-193/H4);
  only a platform (org-unbound) caller with no filter reads globally.
  Filtering must happen in the query rather than after it, so `limit` cannot
  truncate the window before the filter is applied.
- `since`/`until` are Unix-millisecond bounds on `ts`; rows come back ordered by
  `seq` ascending, which is the order `verify` requires.
- An org-scoped caller (session `org_id` bound) cannot read another org's
  slice: `hasPermission` refuses the cross-org target with `403`.

## 13. Audit export — T-179 (`GET /api/v1/audit/export`)

Signed NDJSON snapshot of the complete audit chain.

Request: `GET` with no body. There are no supported query parameters;
`org`, `since`, `until`, and `limit` are ignored by the current route, not
honored (§13.3).

Authorization requires **`audit.export`**, held only by `org_admin` (§2).
`security_admin` and `viewer` hold `audit.read` and are still refused with
`403 auth.denied`; absent or unrecognized `x-kiwi-roles` also fails closed.

The current service checks this permission with a `null` target, so the
operation is **global, not org-scoped**: even an actor carrying
`x-kiwi-org` receives the complete cross-org chain when its role is
`org_admin`. This is explicit current behavior and a security decision Lead
must ratify with §13. If global export is not intended, implementation must
first add a genuine platform-role/permission gate; documentation alone cannot
turn `audit.export` into an org-scoped permission. The `x-kiwi-*` headers
remain development scaffolding, not production authentication (§12.2).

Success is `200` with `content-type: application/x-ndjson; charset=utf-8`,
`cache-control: no-store`, and a raw `\n`-delimited body. The evidence must
not be JSON-encoded into one string or served from a cache. Failure responses
use §3's JSON error envelope:

| status | code | condition |
|--------|------|-----------|
| `400` | `validation.failed` | chain exceeds `AUDIT_EXPORT_MAX_ROWS` (10000); it is refused, never truncated |
| `403` | `auth.denied` | missing/unusable role or role without `audit.export`; `details.permission = "audit.export"` |
| `500` | `internal` | storage/audit-append failure; message contains only a correlation reference |

The current localhost transport does not emit `401 auth.required`; missing
credentials fail through the permission check as `403 auth.denied`.

### 13.1 Line layout

`\n`-terminated JSON objects, one per line, no trailing blank line:

| line | object | contents |
|------|--------|----------|
| 1 | `header` | `version` (`kiwi.audit-export/1`), `exported_at`, `rows`, `first_seq`, `last_seq` |
| 2 … rows+1 | `record` | one AuditRecord per line, `seq` ascending, chain fields included |
| rows+2 | `chain_state` | `verifyChain()` verdict for exactly those rows: `valid`, `error`, `checked`, `head_hash`, `first_seq`, `last_seq` |
| rows+3 | `signature` | `alg`, `signed`, `key_id`, `signature`, `covers_through` |

Record lines carry `seq`, `prev_hash`, and `entry_hash`, so a reader can
recompute the chain from the export alone without calling back into the
service. `chain_state` sits at index `rows + 1`.

Exact integrity scope: `entry_hash` covers canonical JSON containing
`actor.subject`, `actor.roles`, `org_id`, `action`, `resource`, `outcome`,
`request_id`, `details`, and `prev_hash`. It does **not** cover `seq` or `ts`.
`verifyChain` checks hash linkage and adjacency between returned rows; it
does not independently require a non-empty export's `first_seq` to equal 1.
"Full chain" therefore means every row returned by the repository range at
snapshot time, not a proof that no historical prefix was omitted. Tightening
either omission requires a code/format decision, not a documentation-only
claim.

### 13.2 Signature

`signature = HMAC-SHA256(key, lines 1..rows+2 joined by "\n")`, lowercase
hex, `alg: "hmac-sha256"`, `covers_through: rows + 2`.

- The signature covers the **header and the `chain_state` line**, not only
  the records. Otherwise "chain valid" and `exported_at` would be editable
  in transit without invalidating the signature.
- `key_id` is `SHA-256(key)` truncated to 16 hex chars — a stable
  fingerprint so a verifier can tell *which* key signed. The key itself
  never appears in the artifact and is never logged.
- **Unsigned exports are reported honestly**: with no key configured the
  trailer is `{ alg: "none", signed: false, key_id: null, signature: null,
  covers_through: null }` — a complete, well-formed export that does not
  claim to be signed. There is no placeholder signature.

Key source: `KIWI_AUDIT_EXPORT_KEY` (env, read once at startup; also
settable per server for tests). The effective HMAC key is the UTF-8 bytes of
the value after surrounding whitespace is removed; `key_id` is computed from
that same trimmed value. Unset/blank → unsigned. Verifiers must trim before
recomputing either value.

### 13.3 Whole chain only — no window, no `?org=`

The export is always the FULL chain. There is no caller-supplied `org`,
`since`, `until`, or `limit`; those filters are ignored, and a filtered
export is refused by omission rather than silently weakened.

The reason is that a truncated export cannot honestly carry a chain-state
claim: a prefix of a valid chain is itself valid, so a paged or org-filtered
export would be indistinguishable from a complete one while reporting
`valid: true`. Org-scoped reads belong at `GET /api/v1/audit?org=` (§12.3),
which makes no integrity claim.

If the chain exceeds `AUDIT_EXPORT_MAX_ROWS` (10000) the request fails with
`400 validation.failed` ("export is capped at 10000 rows…") rather than
truncating. Archive and prune the log before exporting.

### 13.4 The export audits itself

A successful export appends an `audit.export` row (`org_id` null,
`outcome: "allowed"`) with `details: { rows, signed, key_id }` — the
fingerprint, never the key. Taking a signed copy of the whole log off-box
must leave a trace, or the log could be exfiltrated with nothing to show
for it. The row is appended **after** the snapshot. The current service does
not hold the append gate across the range read and the subsequent append, so
a concurrent successful mutation may land between them; the artifact is a
complete chain prefix at snapshot time, not necessarily the row immediately
preceding `audit.export`. If exact adjacency is required, snapshot + audit
append must be serialized (or moved into one repository transaction).

Current implementation does **not** audit export denials, and §13.4's
former "recursion" rationale is withdrawn: `AuditService.append` writes
directly and does not re-enter the permission check, so a denial row is
technically possible. This is a known deviation from binding §1/§2. Before
§13 is approved, either implement denial-only rows for export (and decide
whether query/verify follow the same rule) or amend the global invariant
explicitly. A denial must never be recorded as `allowed`. If the required
self-audit append fails, the endpoint must return `500 internal` and send no
export body rather than deliver an unaudited successful export.

### 13.5 Line shapes (exact)

Field order is part of the signed bytes: every line is `JSON.stringify` of the
object below, in this order, with no whitespace. A producer that reorders keys
produces a valid export that no independent verifier can check — the export's
whole purpose — so these orders are normative, not illustrative.

Wire types and builder invariants (`src/audit/export.ts` +
`src/audit/model.ts`; the source interface is wider than this valid wire
union):

```ts
type AuditExportHeader = {
  type: "header";
  version: string;                    // currently "kiwi.audit-export/1"
  exported_at: number;                // safe integer, Unix milliseconds
  rows: number;                       // 0..10000
  first_seq: number | null;           // null only when rows == 0
  last_seq: number | null;            // null only when rows == 0
};

type AuditExportRecord = {
  seq: number;
  ts: number;
  actor_subject: string | null;
  actor_roles: string | null;         // JSON-encoded string, not string[]
  org_id: string | null;
  action: string;
  resource: string | null;
  outcome: "allowed" | "denied" | "error";
  request_id: string | null;
  details: string | null;             // JSON-encoded object string, or null
  prev_hash: string;
  entry_hash: string;                 // lowercase SHA-256 hex
};

type AuditExportChainState = {
  type: "chain_state";
  valid: boolean;
  error: string | null;
  checked: number;
  head_hash: string;                  // "genesis" for an empty chain
  first_seq: number | null;
  last_seq: number | null;
};

type AuditExportSignature =
  | { type: "signature"; alg: "hmac-sha256"; signed: true;
      key_id: string; signature: string; covers_through: number }
  | { type: "signature"; alg: "none"; signed: false;
      key_id: null; signature: null; covers_through: null };
```

For a signed trailer, `key_id` is exactly 16 lowercase hex characters,
`signature` exactly 64 lowercase hex characters, and `covers_through` is the
1-based line number of `chain_state` (`rows + 2`). The unsigned variant has
all three value fields `null` by construction.

```jsonc
// line 1
{"type":"header","version":"kiwi.audit-export/1","exported_at":1726000000000,
 "rows":12,"first_seq":1,"last_seq":12}

// lines 2..rows+1 — field order per src/audit/model.ts AuditRecord
{"seq":1,"ts":1726000000000,"actor_subject":"admin@acme.test",
 "actor_roles":"[\"org_admin\"]","org_id":"org-…","action":"policy.create",
 "resource":"pol-…","outcome":"allowed","request_id":null,"details":"{}",
 "prev_hash":"genesis","entry_hash":"<hex64>"}

// line rows+2
{"type":"chain_state","valid":true,"error":null,"checked":12,
 "head_hash":"<hex64>","first_seq":1,"last_seq":12}

// line rows+3 — signed
{"type":"signature","alg":"hmac-sha256","signed":true,
 "key_id":"<16 hex>","signature":"<hex64>","covers_through":14}
```

Notes that matter to an implementer:

- `actor_roles` and `details` are **JSON-encoded strings**, not nested objects —
  they are stored as text and pass through verbatim, so a reader must parse
  them once more to recompute the hash input. This is the easiest place to get
  an independent verifier subtly wrong.
- `covers_through` is `rows + 2`, i.e. one less than the total line count.
- `exported_at` is Unix **milliseconds** (§4).
- The record `ts` is what the log actually holds. See §13.6.

**Empty chain.** A chain with no rows exports as exactly three lines —
`header`, `chain_state`, `signature` — with `rows: 0`, `first_seq`/`last_seq`
`null`, `head_hash: "genesis"`, and `chain_state.valid: true`. A signed empty
export has `covers_through: 2`; an unsigned empty export has
`covers_through: null`, as required by the discriminated trailer type above.
This is honest rather than vacuous: with no rows there is nothing that could
fail to verify. It is also definitionally different from a bounded verify
against a populated log; read `chain_state.checked` against `header.rows`,
which agree by construction here.

### 13.6 Timestamp units in exported records

`header.exported_at` is Unix **milliseconds** (§4): the HTTP route supplies
its `Date.now()` value directly to `buildAuditExport`. Record `ts` values
pass through exactly as stored and are not normalized by the exporter.

Unit history (T-193/M1, settled): early revisions declared seconds in §4
while the implementation stamped milliseconds, and the route-supplied `now`
was seconds while every other service-stamped field was milliseconds. The
contract now declares milliseconds everywhere service-stamped (§4) and the
route supplies `Date.now()`, so all stored timestamps share one unit. No
stored row was rewritten to get here; rewriting `ts` would destroy historical
evidence, even though `ts` is not an `entry_hash` input (§7) and therefore does
not technically require hash recomputation. Any such migration must be explicit
and versioned. Deployments holding pre-T-193 rows may still contain
second-unit `created_at` values from the old route clock; those rows predate the
unit declaration and must be read with that in mind (local-dev only —
`docker compose down -v` plus fresh migrations resets the clock).

## 14. Device inventory — T-188 (`GET /api/v1/orgs/{orgId}/devices`)

> **PROPOSED — pending Lead review.** Agent 9 drafted this shape; Agent 18
> revalidated it against the current repository/RBAC code on 2026-09-25.
> **Not implemented:** no `OrgRepository.listDevices` or HTTP route exists
> today. The section fixes the wire shape and fail-closed org scoping;
> §14.5 lists what implementation must add.

### 14.1 Request and response

Request: `GET /api/v1/orgs/{orgId}/devices`, no body. The optional `limit`
query parameter is a decimal integer, default `50`, clamped to `1..=500`,
matching the other org-scoped list endpoints. Unknown query parameters are
ignored. There is no offset/pagination cursor in v1; the response is bounded
to the requested limit. The path identifier is trimmed and must match
`assertIdentifier`: 1..=256 characters from `[A-Za-z0-9_.:@-]`; otherwise the
response is `400 validation.failed`.

Success is `200` with `{ "items": DeviceView[] }`, matching
`GET /api/v1/orgs/{orgId}/users` (§3):

```jsonc
{
  "items": [
    { "id": "dev-…",            // PK, `dev-` + UUID
      "org_id": "org-…",
      "label": "Pixel 8",       // 1..=200 characters after trim
      "revoked": 0,             // integer 0|1, never JSON boolean
      "revoked_at": null,       // integer Unix milliseconds, or null
      "created_at": 1729000000 } // integer Unix milliseconds
  ]
}
```

Every field above is required; only `revoked_at` is nullable. A valid row has
`revoked = 0` and `revoked_at = null`, or `revoked = 1` and a non-null
`revoked_at`; inconsistent legacy rows are not silently normalized and cause a
sanitized `500 internal`. All service-stamped times are Unix milliseconds
(§4). Unknown JSON fields are not introduced by this endpoint. Items are
ordered by `created_at` ascending, then `id` ascending. The tie-breaker is
mandatory: same-millisecond registrations otherwise have no total order.

This is intentionally a superset of the current `createDevice`/`getDevice`
row shape, which omits `revoked_at`. The repository projection must add that
column rather than fabricate `null` for revoked rows. An unknown but
syntactically valid `orgId` returns `200 { "items": [] }`, consistent with
`listUsers`; changing both list endpoints to return `404` for an unknown org
is a separate contract decision.

Failure responses use §3's JSON envelope: `400 validation.failed` for the path
identifier, `403 auth.denied` for RBAC/scope failure, and a sanitized
`500 internal` for storage failure. The route must never return a device row
for a different `org_id`.

### 14.2 Permission, authentication, and scoping

Permission **`device.read`**, held by all three roles (§2). The production
contract requires an authenticated session bound to the target org. In the
current localhost scaffold, the actor comes from
`x-kiwi-subject` / `x-kiwi-roles` / `x-kiwi-org` (§12.2):

- `x-kiwi-roles` must contain a recognized role. Missing/unknown roles yield
  an empty role set and `403 auth.denied`.
- `x-kiwi-org` must equal the path `{orgId}`. Current `hasPermission` is
  fail-closed for org-scoped targets: a null-org actor is not global and is
  denied for a non-null path target.
- The service must validate the path id with `assertIdentifier`, then call
  `requirePermission(actor, "device.read", orgId)` with that **real path org
  id** before querying. It must not pass `null` as the target or silently
  default a missing `x-kiwi-org` to the path.
- A platform/bootstrap actor with no org session is not an exception to this
  endpoint. It has no legitimate device-inventory scope until an org-bound
  session exists.

A cross-org request therefore returns `403` with
`{"error":{"code":"auth.denied","message":"…","details":{"permission":"device.read"}}}`
and must not reveal whether the target org or device exists. In the future
authenticated transport, absent or invalid session credentials return
`401 auth.required`; the current header scaffold has no such state and uses
`403 auth.denied` for both missing and insufficient authority.

### 14.3 Auditing

A successful inventory read is **unaudited**, consistent with `listUsers` and
`listPolicies`; §1 audits mutations, not routine successful reads. An
authorization denial **must** be audited with `outcome: "denied"` and
`details.permission: "device.read"`, as required by §1, without including
device data in `details`.

The denial row is fixed as `action: "device.list"`, `resource: orgId`,
`org_id: orgId`, `outcome: "denied"`, `details: { permission: "device.read" }`,
`request_id: null` in the current scaffold, and a millisecond `ts`. It must be
written by a denial-only path, not `auditWrap` (which would also record a
successful read). If that required append fails, fail closed with
`500 internal` and do not return the inventory.

### 14.4 Relationship to the other device registries

There are three distinct device data models in the checkout. They are **not**
the same registry and currently have no synchronization:

| | `kiwi-admin` `devices` table | current `kiwi-app` `DeviceRegistry`/index | `kiwi-pair` `pair.db` `devices` |
|---|---|---|---|
| scope | org-scoped, multi-device per org | one local endpoint, in-memory | one endpoint, persistent profile store |
| id | `dev-<uuid>`, app-assigned | `dev-*`, app-assigned | supplied at `register_device` |
| states | `revoked` 0/1 | `pending`/`active`/`suspended`/`revoked` | `pending`/`active`/`suspended`/`revoked` (terminal) |
| holds | label, timestamps | public key, keystore ref, status | public key, keystore ref, challenge/replay state |
| current caller | proposed admin route | `kiwi_list_devices` / `kiwi_revoke_device` | library API; not yet wired into kiwi-app |
| contract | this document | `ipc.md` §§4/9 | `contracts/pair.md`, `ipc.md` §9d |

This admin endpoint does **not** answer "which authenticators are paired to
this endpoint." The current `kiwi_list_devices` reads the in-memory app
registry, not `pair.db`; only a future approved migration can make the IPC
device projection read kiwi-pair. A UI that presents these registries as the
same thing would be wrong in a way no error would surface. Cross-registry
reconciliation is unbuilt and not part of this section.

### 14.5 Implementation checklist (nothing built)

1. `OrgRepository.listDevices(orgId)` — `db/interfaces.ts` (as
   `MaybePromise<DeviceRow[]>`), plus both implementations:
   `DrizzleOrgRepository` (sync, `db/repositories.ts`) and `PgOrgRepository`
   (async, `db/repositories.pg.ts`). Return `revoked_at` in the row, enforce
   `limit` in SQL, and order by `created_at, id`; `getDevice(id)` exists, but
   neither driver has an org-scoped list method.
2. `OrgService.listDevices(actor, orgId)` — `assertIdentifier(orgId,
   "orgId")`, then `requirePermission(actor, "device.read", orgId)` with the
   validated path target; do not use a nullable/defaulted target. Preserve an
   auditable `device.read` denial without auditing successful reads.
3. A route in `src/server.ts` inside the existing `/api/v1/orgs/:org/…` block
   (`rest[2] === "devices" && rest.length === 3`, `GET`), parsing the bounded
   `limit`, answering `{ items }` like the users route, and mapping the
   uniform errors from §3.
4. The §3 row above (added).
5. Unit coverage in `tests/server.test.ts` — including a **cross-org denial
   assertion**, a null-org denial, an empty-unknown-org assertion, and the
   default/`500` limit bound.
6. e2e coverage in `infra/e2e/test_admin_e2e.py`, and the `rbac.ts` matrix
   needs no change (`device.read` already exists and is already granted).

### 14.6 Open, and deliberately not decided here

`POST` for device creation has **no route and no permission**:
`OrgService.createDevice` is gated on `"device.revoke"`
(`src/policy/services.ts:90`), which is the wrong permission for a create, and
`rbac.ts` declares no `device.create` to use instead (T-185 finding L5). This
section documents the read path only. Inventing a create contract here would
paper over a permission-model question that needs a ruling.

<!-- CONTINUED-4 -->





