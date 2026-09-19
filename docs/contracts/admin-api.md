# Contract — kiwi-admin API (org / policy / mailflow / audit)

> Owner: Agent 4 · **Contract version: 1** · Status: draft (T-004)
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
| `org_admin` | all: org.read, org.create, org.update, user.read, user.invite, user.role.grant, device.read, device.revoke, policy.read, policy.write, mailflow.read, mailflow.ingest, audit.read |
| `security_admin` | org.read, user.read, device.read, device.revoke, policy.read, policy.write, mailflow.read, audit.read |
| `viewer` | org.read, user.read, device.read, policy.read, mailflow.read, audit.read |

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
| `POST /api/v1/orgs/{orgId}/users` | `OrgService.createUser` | `user.invite` | |
| `PUT /api/v1/orgs/{orgId}/users/{userId}/role` | `OrgService.grantRole` | `user.role.grant` | |
| `POST /api/v1/devices/{deviceId}/revoke` | `OrgService.revokeDevice` | `device.revoke` | |
| `POST /api/v1/orgs/{orgId}/policies` | `PolicyService.createPolicy` | `policy.write` | body = PolicyObject minus id |
| `POST /api/v1/policies/{policyId}/evaluate` | `PolicyService.evaluate` | `policy.read` on owning org | deterministic; called by compose-send hook |
| `POST /api/v1/mailflow/events` | `MailflowService.ingest` | `mailflow.ingest` | MailflowEvent schema §6 |
| `GET  /api/v1/mailflow/events` | `MailflowService.query` | `mailflow.read` | filters: org, recipient domain, ts range, limit ≤ 1000 |
| `GET  /api/v1/audit` | `AuditService.query` | `audit.read` | filters: org, ts range, limit ≤ 1000 |
| `GET  /api/v1/audit/verify` | `AuditService.verify` | `audit.read` | replays hash chain; see §7 |

Error shape (uniform): `{ "error": { "code": string, "message": string, "details"?: object } }`
with codes `auth.required`, `auth.denied`, `validation.failed`, `not.found`,
`conflict`. Validation failures name the offending field.

<!-- CONTINUED-1 -->

## 4. SQLite schema (v1 — org model)

One file per service boundary (`kiwi-admin.db`, ADR-003). Applied by
sequential migrations in `src/db/migrations.ts`; applied versions recorded in
`schema_migrations`.

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
- Append-only by convention in v1: application code never UPDATEs or DELETEs
  audit rows. **Known v1 hardening gap (reported to Lead):** no SQLite
  trigger/permission prevents raw-SQL tampering from a process holding the
  DB; a DB-level guard is planned as a follow-up.
- Concurrency: single-process appends are serialized in-process. Multi-process
  appends need a file lock (queued with Lead).

## 8. Cross-service notes

- Device identity (`devices` table) is owned here; the trust/session model
  and authenticator binding live in kiwi-core (contract
  `contracts/security-session.md`). kiwi-admin stores device records and
  revocation state only.
- Mailflow events reference org/user/device by id, never by credential.
- Postgres migration path: repositories in `src/db/interfaces.ts` are the
  seam; a Postgres implementation replaces the SQLite classes without
  touching services or evaluator.

## 9. Test map (evidence for T-004)

| test file | covers |
|-----------|--------|
| `tests/policy.evaluator.test.ts` | allow/deny domain rules, external-recipient warn/block, min-TLS downgrade block, unverified-TLS warn, determinism |
| `tests/rbac.test.ts` | role permission matrix, cross-org denial, negative cases, denials audited |
| `tests/audit.chain.test.ts` | chaining, tamper detection (field edit), deletion detection (replay), canonical hashing, strict input parsing |
| `tests/services.test.ts` | service-level RBAC + audit wiring, policy determinism through service, mailflow metadata-only ingest, chain verification |

Run: `npm run typecheck && npm test` (34 tests, all passing at T-004 close).


