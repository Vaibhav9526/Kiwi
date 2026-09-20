# Contract — kiwi-admin API (org / policy / mailflow / audit)

> Owner: Agent 4 · **Contract version: 1.3** (T-134 list endpoints + dev HTTP
> transport by Agent 5; **Lead-reviewed 2026-09-20 — approved**) · §13 (T-179
> audit export, Agent 9) and §14 (device inventory, Agent 9, T-188) are
> **additions pending Lead review** · Status: active
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
  `src/rbac/rbac.ts`). Platform-level actors (`org_id` null) may bootstrap
  new orgs but hold no org-scoped rights until granted.
- Denials surface as `403` (or `AuthorizationDeniedError` in-process) and are
  always audited with `outcome: "denied"` and `details.permission`.

## 3. Endpoints (wire mapping; service call = current in-process API)

| Method + path | Service call | Permission | Notes |
|---------------|--------------|------------|-------|
| `POST /api/v1/orgs` | `OrgService.createOrg` | platform-level (bootstrap) | |
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
| `GET  /api/v1/mailflow/events` | `MailflowService.query` | `mailflow.read` | filters: org, recipient domain, ts range, limit ≤ 1000 |
| `GET  /api/v1/audit` | `AuditService.query` | `audit.read` | filters: org, ts range, limit ≤ 1000 |
| `GET  /api/v1/audit/verify` | `AuditService.verify` | `audit.read` | replays hash chain; see §7 |
| `GET  /api/v1/audit/export` | `AuditService.export` | `audit.export` | T-179 signed NDJSON of the FULL chain; see §13 |

Error shape (uniform): `{ "error": { "code": string, "message": string, "details"?: object } }`
with codes `auth.required`, `auth.denied`, `validation.failed`, `not.found`,
`conflict`. Validation failures name the offending field.

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

Timestamps are Unix seconds (INTEGER). Booleans stored as 0/1.

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
- `ts` is message time; `received_at` (set by the service) is ingest time.

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
  deployments. A retained signed export (`GET /api/v1/audit/export`, §13) is an externally verifiable high-water mark for its point in time: tail truncation after an export breaks against it. Multi-process appends still need a file lock (queued with
  Lead) — single-process appends are serialized in-process.

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
  excluded from an org-scoped read. Omitting `org` returns the whole log.
  Filtering must happen in the query rather than after it, so `limit` cannot
  truncate the window before the filter is applied.
- `since`/`until` are Unix-second bounds on `ts`; rows come back ordered by
  `seq` ascending, which is the order `verify` requires.
- An org-scoped caller (session `org_id` bound) cannot read another org's
  slice: `hasPermission` refuses the cross-org target with `403`.

## 13. Audit export — T-179 (`GET /api/v1/audit/export`)

Signed NDJSON snapshot of the audit chain. Permission **`audit.export`**,
held only by `org_admin` (§2). `security_admin` and `viewer` hold
`audit.read` and are still refused with `403 auth.denied` — the two
permissions are deliberately independent.

Response: `200` with `content-type: application/x-ndjson; charset=utf-8`
and `cache-control: no-store`. The log is evidence; a cached or
intermediary-transformed copy is worse than none.

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
settable per server for tests). Unset/blank → unsigned.

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
for it. The row is appended **after** the snapshot, so the artifact covers
the chain exactly as it stood immediately before its own record.

Denials are NOT self-audited, matching `query`/`verify`: the audit service
is what writes the chain, so having it record its own refusals would make
every refusal of a log read recurse into the log it was refused.

### 13.5 Line shapes (exact)

Field order is part of the signed bytes: every line is `JSON.stringify` of the
object below, in this order, with no whitespace. A producer that reorders keys
produces a valid export that no independent verifier can check — the export's
whole purpose — so these orders are normative, not illustrative.

```jsonc
// line 1
{"type":"header","version":"kiwi.audit-export/1","exported_at":1726000000,
 "rows":12,"first_seq":1,"last_seq":12}

// lines 2..rows+1 — field order per src/audit/model.ts AuditRecord
{"seq":1,"ts":1726000000,"actor_subject":"admin@acme.test",
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
- `exported_at` is Unix **seconds** (§4).
- The record `ts` is what the log actually holds. See §13.6.

**Empty chain.** A chain with no rows exports as exactly three lines —
`header`, `chain_state`, `signature` — with `rows: 0`, `first_seq`/`last_seq`
`null`, `head_hash: "genesis"`, `covers_through: 2`, and `chain_state.valid`
`true`. This is honest rather than vacuous: with no rows there is nothing that
could fail to verify. It is also definitionally different from
`GET /api/v1/audit/verify?limit=0`, which reports `checked: 0` against a log
that *does* have rows — the T-185 review logged that as a false attestation
(`docs/audits/admin-review-1.md` H8). Read `checked` against `rows`: here they
agree by construction.

### 13.6 Known discrepancy — the export's own audit row is in the wrong unit

Open code defect, **not** a contract statement; recorded so a reader is not
misled by a log that mixes units. T-185 finding M2: the `audit.export` row is
appended with `opts.now` (Unix **seconds**, `src/server.ts:210`), while every
other audit row is written with `Date.now()` (**milliseconds**,
`src/services.ts:134,139`). So the one record proving an export happened is
~1000x smaller on the `ts` axis than its neighbours.

§4 and §12.3 are the authority: `ts` is Unix seconds, and the millisecond
writes are the defect, not the export. Fixing it is T-187's scope; it cannot be
done by rewriting existing rows, because `ts` is inside every `entry_hash`.
See `docs/audits/admin-review-1.md` M1/M2.

## 14. Device inventory — T-188 (`GET /api/v1/orgs/{orgId}/devices`)

> **PROPOSED — pending Lead review** (Agent 9, T-188). **Not implemented:**
> this endpoint does not exist in `src/` today. The section fixes the shape and
> the RBAC scoping requirement so the implementation cannot silently choose
> weaker ones; §14.5 lists exactly what has to be written.

### 14.1 Shape

`200` with `{ "items": DeviceView[] }`, matching `GET /orgs/{orgId}/users`
(§3). Devices are ordered by `created_at` ascending, ties broken by `id` — a
total order, because `created_at` is a millisecond value and two devices
registered in the same millisecond would otherwise come back in whatever order
the driver chose. Deterministic output is a binding invariant (§1).

```jsonc
{ "id": "dev-…",            // PK, `dev-` + UUID
  "org_id": "org-…",
  "label": "…",             // 1..=200 chars
  "revoked": 0,             // 0/1 — booleans are integers (§4)
  "revoked_at": null,       // Unix seconds, null unless revoked
  "created_at": 0 }         // Unix seconds
```

Superset of what `OrgService.createDevice` returns (§3), which omits
`revoked_at`. Either both carry it or neither should; a create that cannot
report the field its own list view reports is an asymmetry with no rationale.

An unknown `orgId` returns `200 { "items": [] }`, consistent with `listUsers`
(which does not check org existence either). A `404` for an unknown org is
arguably better and would be a change to both endpoints — a decision for the
Lead, not a divergence to introduce quietly on one of them.

### 14.2 Permission and scoping

Permission **`device.read`**, held by all three roles (§2). Two requirements
that are not optional:

- The permission check must use the **real `orgId` from the path**, never
  `null`. `hasPermission` skips org scoping when the target is null
  (`src/rbac/rbac.ts:91`), so passing null would hand every org's device
  inventory to a caller bound to one org. The T-185 review logged exactly this
  pattern as defects H3/H4 against `revokeDevice` and the unscoped read
  filters; this endpoint must not join them.
- `orgId` must pass `assertIdentifier` before use, as `listUsers` does
  (`src/policy/services.ts:113`). The path segment is attacker-controlled and
  the identifier gate is what keeps it a value rather than a shape.

### 14.3 Auditing

**Unaudited**, consistent with the other reads (`listUsers`/`listPolicies` are
RBAC-gated and unaudited by design — §1 audits *mutating* operations and
denials). Worth stating explicitly rather than leaving as an omission: a device
inventory is a map of an org's enrolled endpoints, and an operator could
reasonably expect inventory reads to be logged. If that is wanted, it is a
change to every read endpoint, not a special case here.

### 14.4 Relationship to the other device registries

There are two device stores and they are **not** the same registry:

| | `kiwi-admin` `devices` table | `kiwi-pair` `pair.db` `devices` |
|---|---|---|
| scope | org-scoped, multi-device per org | one endpoint, local profile |
| id | `dev-<uuid>`, app-assigned | supplied at `register_device` |
| states | `revoked` 0/1 | `pending`/`active`/`suspended`/`revoked` (terminal) |
| holds | label, timestamps | public key, keystore ref, challenge state |
| contract | this document | `contracts/pair.md`, `contracts/ipc.md` §9d |

Nothing synchronizes them today, so this endpoint does **not** answer "which
authenticators are paired to this endpoint" — that is `kiwi_list_devices`
(`ipc.md` §9) reading `pair.db`, and it is per-endpoint rather than per-org. A
UI that presents one as the other would be wrong in a way no error would
surface. Cross-registry reconciliation is unbuilt and not part of this section.

### 14.5 Implementation checklist (nothing built)

1. `OrgRepository.listDevices(orgId)` — `db/interfaces.ts` (as
   `MaybePromise<DeviceRow[]>`), plus both implementations:
   `DrizzleOrgRepository` (sync, `db/repositories.ts`) and `PgOrgRepository`
   (async, `db/repositories.pg.ts`). `getDevice(id)` exists; there is no
   org-scoped list method on either driver.
2. `OrgService.listDevices(actor, orgId)` — `requirePermission(actor,
   "device.read", orgId)` then `assertIdentifier(orgId, "orgId")`, mirroring
   `listUsers`.
3. A route in `src/server.ts` inside the existing `/api/v1/orgs/:org/…` block
   (`rest[2] === "devices" && rest.length === 3`, `GET`), answering
   `{ items }` like the users route.
4. The §3 row above (added).
5. Unit coverage in `tests/server.test.ts` — including a **cross-org denial
   assertion**, which is the test that would have caught H3/H4 had it existed.
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





