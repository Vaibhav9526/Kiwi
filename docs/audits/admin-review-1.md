# kiwi-admin defect review 1 (T-185)

Systematic review of `kiwi-admin/src/**/*.ts` — all 22 source files read — looking
for input-validation gaps, injection surfaces, missing pagination bounds,
error-path leaks, RBAC coverage per route against the `docs/contracts/admin-api.md`
§2/§3 matrix, and transaction boundaries. Same method as the four defects I found
earlier (which became the T-149 regression guards).

**Reviewer:** Agent 9. **Date:** 2026-09-20. **Scope:** `release/v0.1.0` working tree.

## Verification status: verified by Agent 6 (T-187); Lead rulings applied

LEAD RULINGS (all approved, implementation = Agent 6 T-193):
- H1: require actor + `policy.evaluate`-class permission + audit row on evaluate.
- H2: fail-closed — org-bound actor with missing/invalid x-kiwi-org gets NO org scope (deny), not all-orgs.
- H3: device revocation scoped to actor's org.
- H4: org-bound actor read filters default to own org, never all.
- H5: createOrg requires org_admin/system — drop the org.read fallback.
- H6: PG audit seq — atomic nextval/serial in transaction, no client max+1.
- H7: add UNIQUE constraint migration for pg users (dialect parity).
- H8: verify?limit=0 → 400 invalid (never attest empty chain as valid).
- M1-M7: approved — ms timestamps per contract fix or contract update, atomic createPolicy,
  no raw error leaks, emit documented conflict code, validate grantRole orgId, bounded listings.
- L1-L5: approved as follow-ups (LIKE escape, strict numParam, content-type check, dead logger).


Nothing below was reproduced at runtime. Every command (`npm test`, `npm run
typecheck`, `docker compose`, `cargo`) was refused for the whole session because
the tool-safety classifier was unavailable ("deepseek-v4-flash is temporarily
unavailable, so auto mode cannot determine the safety of Bash/PowerShell right
now"). So each finding is an argument from the source, with the file:line
evidence needed to confirm or refute it. Findings are labelled with confidence
where the reasoning depends on driver behavior I could not execute.

The relevant unexecuted commands are in `docs/agents/agent-9-status.md`.

## Severity summary

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| H1 | High | `policies/{id}/evaluate` has no actor, no permission check, no audit | `server.ts:301` |
| H2 | High | Omitting `x-kiwi-org` disables all org scoping | `rbac.ts:91`, `server.ts:85` |
| H3 | High | Device revocation is unscoped — any security_admin, any org | `policy/services.ts:94` |
| H4 | High | Read filters default to "all orgs" for an org-bound actor | `mailflow/services.ts:50`, `:101` |
| H5 | High | `createOrg` defaults to `org.read` — a viewer can create orgs | `policy/services.ts:44` |
| H6 | High | Postgres audit appends collide on the `seq` primary key | `mailflow/services.ts:86` |
| H7 | High | Postgres `users` ships a NON-unique index where SQLite ships UNIQUE | `drizzle/pg/0000_mature_tiger_shark.sql:101` |
| H8 | High | `audit/verify?limit=0` attests `valid: true` while checking nothing | `mailflow/services.ts:131` |
| M1 | Medium | Audit/policy timestamps are milliseconds; contract documents seconds | `services.ts:134` |
| M2 | Medium | The T-179 export row is stamped in seconds while the log is in ms | `mailflow/services.ts:177` |
| M3 | Medium | `createPolicy` is non-atomic and unaudited on failure | `policy/services.ts:136` |
| M4 | Medium | 500 responses return raw internal error text | `server.ts:194` |
| M5 | Medium | Documented `conflict` code is never emitted | `admin-api.md:76` (§3) |
| M6 | Medium | `grantRole` neither validates `orgId` nor checks user membership | `policy/services.ts:72` |
| M7 | Medium | `listUsers`/`listPolicies` are unbounded with N+1 queries | `policy/services.ts:111`, `:174` |
| L1 | Low | `recipientDomain` LIKE metacharacters are not escaped | `repositories.pg.ts:227` |
| L2 | Low | `numParam` accepts `1e3` / `0x10` / whitespace forms | `server.ts:163` |
| L3 | Low | No `content-type` check on request bodies | `server.ts:89` |
| L4 | Low | `util/logger.ts` is dead code with an ambient clock | `util/logger.ts:25` |
| L5 | Low | RBAC-gated methods with no route (`listDomains`, `createDevice`) | `policy/services.ts:105`, `:77` |
| L6 | Low | Tail truncation is now detectable — the export publishes a head hash | `audit/export.ts:132` |
| L7 | Low | `/healthz` advertises `contract: "admin-api/1.3-pending"` | `server.ts:213` |

No SQL injection was found: every query goes through Drizzle's parameterized
builders, and no route concatenates SQL. The `like()` case (L1) is pattern
widening, not injection.

---

## High

### H1 — `POST /api/v1/policies/{policyId}/evaluate` is unauthenticated

`server.ts:301-325` reads the body and calls `container.policies.evaluate(rest[1], {...})`.
`PolicyService.evaluate` (`policy/services.ts:167-171`) takes **no actor** and
calls no `requirePermission`; the route never passes `actor` at all, so the
identity parsed at `server.ts:209` is discarded. Nothing is audited either —
`auditWrap` is not involved, so neither the evaluation nor a denial appears in
the log.

`docs/contracts/admin-api.md` §3 line 67 lists the permission as `policy.read` on
the owning org. The implementation applies none.

Failure scenario: any process that can open a socket to 127.0.0.1 sends
`POST /api/v1/policies/pol-<id>/evaluate` with **no `x-kiwi-*` headers**. No
headers means `roles: []` (`server.ts:81-84`), which every other route refuses —
this one does not. The response discloses the policy's decision and its reason
codes, and by probing a guessed policy id the caller learns whether it exists
(the missing-policy path throws `not found`, `policy/services.ts:169`, mapped to
404 at `server.ts:191`). It is also a cross-org read: the policy id is the only
scope, and no org check exists.

Proposed fix: add `actor: Actor` as the first parameter of
`PolicyService.evaluate`, resolve the policy's owning org
(`PolicyRuleRepository.getPolicy` already returns `org_id`), `requirePermission(actor,
"policy.read", row.org_id)`, and route it through `auditWrap` with
`"policy.read"` so both the allow and the denial are recorded — the shape
`evaluateOutbound` already uses (`policy/services.ts:196-238`).

### H2 — Omitting `x-kiwi-org` disables every org scope

`actorFromHeaders` sets `orgId = get("x-kiwi-org")?.trim() || null`
(`server.ts:85`). `hasPermission` skips org scoping when the target org is null
**or when the actor's org is null** (`rbac.ts:91`):

```ts
if (targetOrgId !== null && actor.orgId !== null && targetOrgId !== actor.orgId) return false;
```

So an actor with no org binding satisfies every org-scoped permission for every
org. Contract §2 lines 49-52 present scoping as enforced ("an actor whose session
is bound to org X cannot exercise org-scoped permissions against org Y"); the
scaffold-auth caveat in §3.2 covers identity, not scoping, so this is a gap
between the contract and the code rather than a documented limitation.

Failure scenario: `x-kiwi-roles: security_admin` with **no** `x-kiwi-org` header
yields `device.revoke`, `policy.write` and `mailflow.read` with no org target at
all — which is the direct enabler of H3 and H4, and turns the header-auth
scaffold from "anyone can claim a role" into "anyone can claim global reach".

Proposed fix: make the org binding mandatory for org-scoped permissions. Either
(a) `hasPermission` requires `actor.orgId !== null` for every permission except a
small platform list (`org.create`), or (b) remove the `actor.orgId !== null`
clause so a null-org actor is refused for any non-null target. (b) is the smaller
change but breaks the documented bootstrap path, so it needs a Lead ruling.

### H3 — Device revocation is not org-scoped

`OrgService.revokeDevice` (`policy/services.ts:94-103`) passes `orgId: null` to
`auditWrap`, so `requirePermission(actor, "device.revoke", null)` performs no org
check, and the repository revokes by device id alone
(`db/interfaces.ts` — `revokeDevice(deviceId, now)`, no org parameter).

Failure scenario: a `security_admin` of org A sends
`POST /api/v1/devices/dev-<org-B-device>/revoke` and revokes another org's device,
with the audit row itself recording `org_id: null` so the cross-org act is not
even attributable to an org in the log.

Note the deliberate asymmetry to confirm during the fix: `createDevice` passes
`orgId` (`policy/services.ts:84-91`) and the permission `"device.revoke"` rather
than a `device.create`, which also looks like a copy-paste artifact.

Proposed fix: resolve the device's owning org before the check (or add
`revokeDevice(deviceId, orgId, now)` to the repository with an
`AND org_id = ?` predicate) and pass that org to `auditWrap`.

### H4 — Read filters default to every org for an org-bound actor

`MailflowService.query` (`mailflow/services.ts:50`) and `AuditService.query`
(`mailflow/services.ts:101`) pass `filter.orgId ?? null` as the RBAC target. When
the caller omits `?org=`, the target is null and `hasPermission` performs no org
check, so the repository returns every org's rows.

Failure scenario: a `viewer` bound to org A calls `GET /api/v1/mailflow/events`
with `x-kiwi-org: org-A` and no `?org=` parameter, and receives org B's mail
metadata — sender, recipient, TLS version, security status — which is exactly the
metadata the org boundary is supposed to protect.

Contract §12.3 line 380 documents "omitting `org` returns the whole log" for the
audit route, so the audit half is at least documented behaviour; the mailflow
half has no such note, and for a multi-tenant model neither is the right default.

Proposed fix: when `actor.orgId !== null`, default the filter to the actor's own
org rather than to unscoped, and require an explicit cross-org grant (or an
explicitly platform-level actor) to widen it.

### H5 — `createOrg` falls back to the `org.read` default

`OrgService.createOrg` (`policy/services.ts:44-46`) passes **six** arguments to
`auditWrap`, omitting the permission, so the default `permission: Permission =
"org.read"` applies (`services.ts:128`). `org.read` is held by every role
including `viewer` (`rbac.ts:61`), so any authenticated caller can create orgs.
`"org.create"` is declared at `rbac.ts:11` and granted to `org_admin` at
`rbac.ts:37` and is **never referenced anywhere else in `src/`**.

Two readings conflict, which is why this needs a ruling rather than a silent
patch: §3 line 60 marks the route "platform-level (bootstrap)", implying no
permission is required, while §2 line 40 grants `org.create` to `org_admin` only.
Neither reading makes `viewer` sufficient.

Proposed fix: pass `"org.create"` explicitly, and settle the bootstrap case
separately — if an unauthenticated bootstrap is genuinely wanted, it needs an
explicit guard (e.g. only while the `orgs` table is empty) rather than an
accidental `org.read` default. Independently, the default parameter itself is a
hazard: a future call site that forgets the argument silently checks the weakest
permission in the system. Consider making it required.

### H6 — Postgres audit appends collide on the primary key

`AuditService.append` (`mailflow/services.ts:85-92`) is read-then-write:

```ts
const last = await this.repos.audit.last();
const prevHash = last?.entry_hash ?? "genesis";
const seq = (last?.seq ?? 0) + 1;
```

`PgAuditRepository.append` inserts that `seq` explicitly (`repositories.pg.ts:255-269`),
and `seq` is the primary key (`schema.pg.ts:145`). Node interleaves the two
requests at both `await` points, so two concurrent appends read the same `last`
and compute the same `seq`: the second insert raises a duplicate-key error, the
request fails with a 500, and its success is never recorded.

Failure scenario: two requests to any `auditWrap`-ed route at the same time —
trivially reachable since every route awaits — and one of them (typically the
denial row, which is written before the exception propagates) is lost from the
log. An audit log that drops entries under concurrency is the one failure mode
the whole hash chain exists to prevent.

Contract §7 line 213 states "single-process appends are serialized in-process",
and `audit/chain.ts:7-9` repeats the claim — but that comment describes
`InMemoryAuditLog`, whose `append` really is synchronous. The DB-backed path is
not serialized. Confidence: high on the code shape; the collision itself is the
standard read-then-insert race and was not executed (no Postgres access).

Proposed fix: compute the sequence in the database in one statement —
`INSERT INTO audit_log (seq, ...) SELECT coalesce(max(seq), 0) + 1, ... FROM audit_log` —
or take a transaction-scoped advisory lock around read-compute-insert. Either
keeps the app-assigned-seq design while making it atomic. A `SERIAL`/sequence
column would also work but changes the contiguous-seq contract that `verify`
depends on.

### H7 — Postgres `users` is missing the unique constraint in the shipped DDL

`schema.pg.ts:52` declares `index("idx_users_org_email")` where
`schema.sqlite.ts:48` declares `uniqueIndex("idx_users_org_email")` for the same
`(org_id, email)` pair. This is not only a schema-file drift — the generated
migrations ship the difference:

- `drizzle/pg/0000_mature_tiger_shark.sql:101` — `CREATE INDEX "idx_users_org_email" ...`
- `drizzle/sqlite/0000_chubby_shard.sql:101` — `CREATE UNIQUE INDEX "idx_users_org_email" ...`

Contract §4 line 96 documents `users` as `UNIQUE(org_id,email)`.

Failure scenario: on Postgres (the compose configuration, §12.1) `POST
/api/v1/orgs/{org}/users` twice with the same email creates two distinct user
rows — duplicate identities, each independently granted roles. The identical
request on SQLite fails the constraint. A security property that holds on one
dialect and not the other is worse than one that holds on neither, because the
test suite's SQLite leg passes.

Confidence: high — the generated SQL is evidence, not inference.

Proposed fix: change `schema.pg.ts:52` to `uniqueIndex(...)` and generate a
migration (`drizzle-kit generate`) that creates the unique index. A pre-existing
database with duplicates needs a data cleanup before that migration can apply,
which is a deployment note rather than a code change.

### H8 — `GET /api/v1/audit/verify?limit=0` attests a healthy chain without reading it

`AuditService.verify` bounds only from above:
`Math.min(opts.limit, AUDIT_EXPORT_MAX_ROWS)` (`mailflow/services.ts:131`) — no
lower bound, unlike `query` (`:102`) and `mailflow.query` (`:51`), which both
floor at 1. `?limit=0` therefore issues `LIMIT 0` (`repositories.ts:323`,
`repositories.pg.ts:308`), and `verifyChain([])` returns
`{valid: true, error: null, checked: 0, headHash: "genesis"}` (`chain.ts:172`).

Failure scenario: `GET /api/v1/audit/verify?limit=0` returns
`{"valid":true,"checked":0,"error":null}`. A monitoring probe or an operator
script that treats `valid: true` as "the log is intact" is told the log is intact
while nothing was verified. The same applies to `?limit=1` (attests a one-row
prefix), and `?limit=-1` additionally reaches the drivers as a negative limit:
SQLite's `LIMIT -1` means **no limit**, so the 10000-row memory valve is bypassed;
Postgres rejects it, producing a 500 that leaks the driver message (M4).

This is the same class of error the T-179 export deliberately refuses to make —
§13.3 requires the export to cover the whole chain because a prefix verifies as
valid, and `AuditService.export` raises rather than truncating
(`mailflow/services.ts:151-158`). `verify` should hold itself to the same
standard.

Proposed fix: floor the limit at 1, and make the attestation honest about
coverage — either report `checked` against the known row count and set
`valid: false` (or a distinct `complete: false`) when the window is short, or
drop the parameter and always verify the full chain the way `export` does.

---

## Medium

### M1 — Timestamps are milliseconds where the contract says seconds

Contract §4 line 104 ("Timestamps are Unix seconds (INTEGER)"), §7 line 184
(`"ts": 1726000000`) and §12.3 line 383 ("`since`/`until` are Unix-second bounds
on `ts`") all say seconds. The code writes `Date.now()` (milliseconds) for every
audit row: `services.ts:134` (denials) and `services.ts:139` (successes), and for
policy creation at `policy/services.ts:144`. `received_at` is also ms
(`repositories.ts:219`, `repositories.pg.ts:213`), which is at least self
consistent since nothing filters on it.

`server.ts:210` computes `now = Math.floor(Date.now() / 1000)` — seconds — but
only the routes that take an explicit `now` use it; `auditWrap` ignores it and
calls `Date.now()` itself.

Failure scenario: `GET /api/v1/audit?until=1758000000` (a seconds bound, as
documented) compares `ts <= 1758000000` against stored millisecond values
(~1.758e12) and returns **zero rows** — a silently empty window that looks like
"no audit activity". `?since=<seconds>` returns everything instead, including
rows older than the bound. Only the undocumented millisecond form behaves as
documented.

Not an overflow: both dialects store these columns as 64-bit
(`schema.pg.ts:50` bigint, `schema.sqlite.ts:46` integer), so millisecond values
fit. I checked this specifically because a 32-bit column would have made the
values wrap rather than merely mis-filter.

Proposed fix: standardise on seconds — replace `Date.now()` with
`Math.floor(Date.now() / 1000)` at the four call sites and thread the request's
`now` (already computed at `server.ts:210`) into `auditWrap` instead of letting
it re-read the clock, which also removes an ambient-clock dependency. Existing
millisecond rows need a one-off migration or an explicit "log starts here"
cutover note, since rewriting `ts` would break every `entry_hash` — the chain
sacrifices the timeline, not the other way round. That trade-off is the Lead's
call and should be recorded in §7 before anyone touches the rows.

### M2 — The T-179 export stamps its own audit row in seconds (self-inflicted)

Found while reviewing my own T-179 work. `server.ts:376` passes
`{ now, key: exportKey }` where `now` is seconds (`server.ts:210`), and
`AuditService.export` appends its record with `opts.now` rather than `Date.now()`
(`mailflow/services.ts:166-178`). Every other audit row is in milliseconds (M1),
so the export's own record is the only one in seconds — roughly 1.7e9 among rows
near 1.7e12.

Failure scenario: the export row sorts before every other row under a `ts`
ordering and is invisible to a documented `?since=<seconds>` filter, so the one
record that proves an export happened is the hardest one to find.

Fix: same as M1 — one unit everywhere. My own preference is that `AuditService`
stops accepting a caller-supplied `ts` for its own bookkeeping row at all and
uses the same source as every other row, with `opts.now` reserved for the
export's `exported_at` header field (which is where a caller-supplied,
deterministic timestamp actually belongs).

### M3 — `createPolicy` is non-atomic and unaudited on failure

`policy/services.ts:136-150` inserts the policy, then loops
`input.domainRules` one `await`ed insert per rule, with no transaction. If rule
*k* fails — a duplicate domain violates the `policy_domain_rules` primary key
(`schema.pg.ts:109`, `schema.sqlite.ts:109`), and the request body is never checked
for duplicates — the earlier rules stay committed, producing a policy that is
neither what was requested nor nothing.

Worse, the failure is unaudited: `auditWrap` writes a row only for a denial
(`services.ts:134`) or a completed success (`services.ts:139`); an exception from
`work()` propagates straight out (`services.ts:138`) leaving no trace. Contract §1
line 30 says "every mutating operation and every authorization denial is audited".

Related bound gap: `domainRules` has no length cap, while the comparable
recipient list is capped at `MAX_BRIDGE_RECIPIENTS = 256`
(`policy/services.ts:298`). A 1 MiB body (the `MAX_BODY_BYTES` cap,
`server.ts:26`) of minimal rules is tens of thousands of individual inserts.

Proposed fix: validate `domainRules` for duplicates and cap its length next to
`MAX_BRIDGE_RECIPIENTS`; wrap the insert loop in a transaction (a real one on
Postgres; on SQLite the whole handler is synchronous, so the practical exposure
is the Postgres path); and add an `outcome: "error"` audit row in a `catch`
around `work()` in `auditWrap`, since the `AuditOutcome` type already has that
member (`audit/model.ts`) and nothing currently writes it.

### M4 — 500 responses return raw internal error text

`server.ts:194` sends `errBody("internal", err instanceof Error ? err.message : "unexpected error")`.
Every message reaches the caller verbatim, including driver text: Postgres
constraint and relation names, error codes, and on a connection failure
potentially DSN fragments (the DSN is never logged, per `services.ts:168`, but
this path echoes whatever the driver throws). The service is localhost-only,
which bounds the exposure, but it is also the path an operator reads, and
internal identifiers in a response body is the kind of leak that becomes
meaningful the moment anything proxies this port.

Relatedly, `server.ts:191` classifies any error whose message matches `/not found/`
as a 404 — including a driver error such as `relation "audit_log" not found`,
which would be reported to the caller as a missing resource rather than a broken
deployment.

Proposed fix: keep the full error in the server-side log (once `util/logger.ts`
is wired up — see L4) and return a generic message plus a correlation id in the
response. Replace the message-regex classification with typed errors
(`AuthorizationDeniedError` and `RequestValidationError` are already typed;
add a `NotFoundError` and use it at `policy/services.ts:169`).

### M5 — The documented `conflict` error code is never emitted

§3 line 76 lists `conflict` among the uniform error codes. `src/` never produces
it: grep finds the string only in the contract. Every constraint violation
surfaces through the generic 500 path (`server.ts:194`) — a duplicate email on
SQLite, a duplicate key from H6, a duplicate domain rule in M3, an FK violation
from M6.

Failure scenario: a client cannot distinguish "that email is already taken"
(409, retry with different data) from "the service is broken" (500). The e2e
suite cannot assert the difference either.

Proposed fix: map driver constraint errors to a typed `ConflictError` at the
repository or service boundary and return `409 conflict` with the offending
field, matching §3's shape. Folding this into the M4 typed-error work is the
cheapest moment to do it.

### M6 — `grantRole` does not validate `orgId` or check user membership

`policy/services.ts:72` passes `assertIdentifier(userId, "userId")` but passes
`orgId` through **raw** to the repository — contrast `createUser`, which
validates the same value (`policy/services.ts:61`). The repository upserts on
`(user_id, org_id)` (`repositories.pg.ts:77-86`, `repositories.ts:75-85`) with no
check that the user belongs to that org; the foreign keys only require the ids to
exist.

Failure scenario: an `org_admin` of org A calls
`PUT /api/v1/orgs/org-A/users/user-<belongs-to-B>/role`. The RBAC check targets
org A (which they hold), the FK to `users(id)` is satisfied by B's user, and the
result is a role row `(user_B, org_A, org_admin)` — org A's admin role attached to
an outsider. With a nonexistent user id instead, the FK violation surfaces as a
500 leaking the constraint name (M4).

Proposed fix: validate `orgId`, and make the repository's upsert conditional on
the user's `org_id` matching — either `INSERT ... SELECT ... WHERE EXISTS (SELECT
1 FROM users WHERE id = ? AND org_id = ?)` or a service-level membership check
before the write, returning 404/409 rather than 500.

### M7 — Unbounded listings with N+1 role queries

`listUsers` (`policy/services.ts:111-120`) fetches the org's users, then issues a
separate `listRoles` query per user; `listPolicies` (`policy/services.ts:174-189`)
does the same per policy for its domain rules. Neither has a limit or pagination
parameter, and no route accepts one (`server.ts:241`, `:259`).

This is a performance and response-size issue rather than a security one — both
are RBAC-gated on the correct org — but an org with thousands of users turns one
request into thousands of queries and an unbounded response body, and M4's error
path would then leak a driver message from a query that failed under load.

Proposed fix: a bounded `limit` (defaulted, capped like `query` already does) and
a batched role lookup (`WHERE user_id IN (...)` or a join) rather than one query
per row.

---

## Low

### L1 — `recipientDomain` reaches LIKE unescaped

`repositories.pg.ts:227` and `repositories.ts:240` build
`like(recipient, \`%@${filter.recipientDomain}\`)`. The value is bound as a
parameter, so this is **not** injection, but LIKE metacharacters inside it are
not escaped and no `ESCAPE` clause is added: `?recipientDomain=%` matches every
recipient, and `_` matches any single character, widening the filter beyond what
the caller asked for. The route passes the parameter straight through with no
validation or length bound (`server.ts:354-355`), unlike every other field.

Proposed fix: validate `recipientDomain` with the domain-part rules already
available (`emailDomain`, `types.ts`), and escape `%`, `_` and the escape
character itself with an explicit `ESCAPE` clause.

### L2 — `numParam` accepts non-decimal integer spellings

`server.ts:163-169` uses `Number(raw)` and checks only `isSafeInteger`, so
`?limit=1e3`, `?limit=0x10` and `?limit=%2012` are all accepted. Harmless today
because the value is re-bounded downstream, but it means the parameter grammar is
"whatever JS coerces", which is not what a contract reader expects.

Proposed fix: `/^-?\d+$/` before `Number()`.

### L3 — No `content-type` check on request bodies

Every POST/PUT parses the body as JSON regardless of `content-type`
(`server.ts:89-116`), so a form-encoded or text body is accepted if it happens to
be valid JSON. Low impact; worth tightening because it is one line and it makes
the boundary explicit.

### L4 — `util/logger.ts` is dead code with an ambient clock

No file in `src/` imports it, so the redaction logic it presumably implements has
never been exercised — worth knowing, because the project rule against logging
secrets is only as good as the untested path that would enforce it. It also calls
`new Date().toISOString()` (`util/logger.ts:25`), an ambient clock in a codebase
whose determinism rule forbids exactly that.

Proposed fix: either wire it up at the M4 error path and give it a caller-supplied
clock, or delete it. Leaving an untested secret-redaction helper in the tree is
the worst of the three options.

### L5 — RBAC-gated methods with no route

`OrgService.listDomains` (`policy/services.ts:105-108`, gated on `org.read`) and
`OrgService.createDevice` (`policy/services.ts:77`, gated on `device.revoke`)
have no HTTP route. `device.revoke` as the permission for *creating* a device
also looks like a copy-paste artifact from `revokeDevice`, and there is no
`device.create` permission to use instead (`rbac.ts:9-30`).

Not a vulnerability — unreachable code is not an exposed surface — but the
`device.create`/`device.revoke` conflation will become one the moment a route is
added, and §2 has no `device.create` row to check it against.

### L6 — Tail truncation is now detectable, and §7 does not say so

§7 lines 209-213 records, honestly, that deleting the newest rows verifies clean
because there is no external high-water mark. The T-179 export changes that: the
`chain_state` line publishes `head_hash` (`audit/export.ts:132`), and the
signature covers it, so an operator who retains one signed export holds an
externally verifiable high-water mark for that point in time.

Nothing needs to change in the code; the improvement is that §7's residual-risk
paragraph should name the export as the available mitigation, since otherwise a
reader concludes the risk is unmitigable.

### L7 — `/healthz` advertises a contract version nothing else uses

`server.ts:213` reports `contract: "admin-api/1.3-pending"`. The string appears
nowhere else — not in the contract, not in tests — and §12 line 321 classes
`/healthz` as extra-contract. A monitor parsing it learns nothing, and the
`-pending` suffix is a claim about review state that will silently go stale.

Proposed fix: report the version the contract actually declares, or drop the
field.

---

## What held up

Recording these because a review that only lists defects is not evidence about
the parts that are sound:

- **No SQL injection.** Every query is built with Drizzle's parameterized
  operators; no route path or query parameter is ever concatenated into SQL,
  including the identifier-shaped ones (`assertIdentifier` is defence in depth,
  not the only barrier).
- **Ingest validation is complete.** `parseMailflowIngest` (`mailflow/model.ts:46-91`)
  validates every field, normalises TLS versions against an allow-list, coerces
  unknown enum values to `"unknown"`, and requires `org_id` for outbound events
  (`:75-77`) — the `as` casts at `server.ts:335-343` are therefore cosmetic.
- **`actorFromHeaders` is fail-closed on roles** (`server.ts:81-84`): an absent or
  unrecognised `x-kiwi-roles` yields no roles rather than a default admin. That
  was one of the four earlier defects and the fix is intact.
- **The export refuses rather than truncates** (`mailflow/services.ts:151-158`),
  and reports `signed: false` honestly rather than emitting a placeholder
  signature (`audit/export.ts:155-162`) — the property H8 shows `verify` lacks.
- **`sendNdjson` exists for a real reason** (`server.ts:49-56`): `send()` would
  JSON-escape the newlines and destroy the line structure, and `no-store` is
  correct for evidence.
- **Org scoping works when both orgs are non-null** (`rbac.ts:91`) — the H2/H3/H4
  cluster is entirely about the null paths, not about the comparison itself.

## Recommended order

1. H1, H3, H5 — small, local, each a permission check that is simply absent.
2. H2 — the ruling comes first (mandatory org binding breaks the bootstrap path),
   then the one-line change.
3. H8 — floor the limit; decide whether `verify` keeps a window parameter at all.
4. H6, H7 — Postgres-only and both need migrations; H7 also needs a data check
   before the unique index can be created.
5. M1/M2 — settle the unit and the existing-row policy with the Lead before
   touching timestamps, because rewriting `ts` invalidates every `entry_hash`.
6. M4/M5 — do them together; both are about the error boundary.

Findings H1-H5 and M6 are contract-vs-code gaps a reviewer can settle by reading
`admin-api.md` §2/§3 alone. Everything else needs a running service, and none of
it has had one.
