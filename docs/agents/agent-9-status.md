# Agent 9 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-20 — T-150: kiwi-contacts crate (model + SQLite store + vCard 4.0 codec)

**Status:** implementation complete; **build/test evidence PENDING** — see
"Verification" below. The tool-classifier service was unavailable for the whole
of this session, so no `cargo` command could be executed against the new crate.
Nothing here is claimed as passing until that run happens.

### Scope delivered

New workspace member `kiwi-contacts` (added to root `Cargo.toml` members list,
alphabetically after `kiwi-autoconfig`). Nothing outside the new crate, the root
`Cargo.toml` one-line edit, `docs/contracts/contacts.md` and this log was
touched.

| File | Contents |
|------|----------|
| `kiwi-contacts/Cargo.toml` | deps: `serde`, `serde_json`, `thiserror`, `rusqlite` (bundled, 0.32 — same pin as kiwi-mail). Dev-dep `serde_json` for the contract-shape test. `[lints] workspace = true`. |
| `kiwi-contacts/src/lib.rs` | Module map, crate docs (with a runnable doctest), `#![forbid(unsafe_code)]`, plus the same `deny(unwrap_used, expect_used, panic, indexing_slicing)` block kiwi-forensics uses (`cfg_attr(not(test), …)`). |
| `kiwi-contacts/src/error.rs` | `ContactsError` (`Io`/`Store`/`Invalid`/`NotFound`/`VCard`), `Result<T>`. |
| `kiwi-contacts/src/contact.rs` | `Contact`, `ContactEmail`, `ContactPhone`; every field cap as a `const`; `normalize()` (trim, drop blanks, case-insensitive de-dup, canonical tag order — idempotent) and `validate()` (names the offending field on every rejection); `prepare()` = normalize + validate. |
| `kiwi-contacts/src/store.rs` | `ContactStore` over rusqlite: `schema_migrations` table + ordered append-only `MIGRATIONS` list, CRUD, `list`/`search`/`by_tag`/`by_email`/`by_source_uid`/`tags`, deterministic `local-N` id assignment from a persisted counter. |
| `kiwi-contacts/src/vcard.rs` | RFC 6350 import/export: `VCardLimits`, `Property`, `RawCard`, `parse_vcards`, `import_vcards`/`VCardImport`/`ImportIssue`, `export_vcard`/`export_vcards`, `parse_timestamp`/`format_timestamp`. |
| `kiwi-contacts/tests/address_book.rs` | 6 integration tests (round-trip through disk + vCard, re-import dedup by UID, hostile-input sweep, oversize refusal, store boundary, IPC JSON shape). |
| `docs/contracts/contacts.md` | New contract `kiwi.contacts/1` — invariants, field table + wire mapping, proposed IPC commands, bounds, vCard error model/property table, storage, error-code mapping, explicit out-of-scope list. |

### Design decisions worth reviewing

1. **Migrations table, not `PRAGMA user_version`.** The brief said "migration-table
   pattern like kiwi-mail/src/store.rs". kiwi-mail tracks a single
   `SCHEMA_VERSION` in `user_version`; this crate keeps the same append-only
   discipline but records applied versions in a `schema_migrations` table, because
   vCard import/merge is expected to keep reshaping this schema and a table
   survives more than one migration without a bespoke branch. A database whose
   schema is **newer** than the build is refused rather than opened.
2. **Rejection over truncation.** An over-limit value fails the record with a
   named reason; nothing is silently shortened. Consistent across the model, the
   store and the vCard layer.
3. **Two-class vCard error model.** Stream-level damage (oversized input, line
   over cap, unterminated card, stray content, malformed line, too many cards /
   properties) is a hard error — past that point the caller's bounds cannot be
   guaranteed. Per-card problems (missing/unsupported `VERSION`, per-field cap
   exceeded, contact fails validation) become `ImportIssue`s so one bad card
   cannot discard an address book.
4. **Bulk properties are exempt from the value cap.** `PHOTO`/`LOGO`/`SOUND`/`KEY`
   values are never stored, so they do not trip `max_value_bytes` — a card with an
   embedded photo imports as a contact instead of failing. They stay bounded by
   the line and input caps.
5. **Parameters are sanitized, not escaped.** RFC 6350 has no parameter escaping
   mechanism, so an exported `TYPE=` label is reduced to `[a-z0-9-]` and omitted
   if nothing survives. This is the guard against stored data injecting structure
   into the parameter section; the value-side guard is control-character
   rejection in `Contact::validate`, which is what makes a stored CRLF
   *unexportable* rather than a `BEGIN:VCARD` injection.
6. **Store-owned ids are `local-N` from a persisted counter** — not a rowid, not a
   clock, not a UUID — so ids are stable across restarts and reproducible in
   tests. The `local-` prefix is reserved and rejected if a caller supplies it.
7. **Tags get a canonical (case-insensitive alphabetical) order** in `normalize`.
   Tags are a set; storing them ordered makes the DB rows, the exported
   `CATEGORIES` list and the JSON stable, and makes read-back equal to write.
8. **No clock, no RNG anywhere.** `open`/`insert`/`update`/`import` all take
   `now_unix`. Export never stamps a time, so two exports of an unchanged contact
   are byte-identical.

### Deliberately NOT built (contract §8)

Contact groups/mailing lists, photo storage, CardDAV/remote sync, merge policy.
Rationale recorded in the contract so it is a decision, not an oversight.

### Verification

- **Not run by this agent.** The command classifier was unavailable for the
  whole of this session, so `cargo test/clippy/fmt -p kiwi-contacts` could never
  be executed here.
- **Superseded by the Lead gate check** — see the fix-round entry below. The
  crate compiles and 39 tests pass; 2 failed and are fixed there. Do not read
  this entry as a green result.

### Known risks / notes for Lead

1. **Do not take this crate's green-ness on trust** — see Verification.
2. **Wire naming.** `kiwi.ipc/1` §1 requires camelCase over IPC; the crate
   serializes `Contact` in snake_case (Rust default). The contract gives the
   one-to-one mapping to a `ContactView`, but the view struct itself is Agent 7's
   to add. Flagging rather than forcing camelCase into a Rust library type.
3. **ASCII-only case folding** in both search (`LIKE`) and tag/email de-dup. Real
   limitation, documented in the contract §3.2 rather than papered over.
4. **`kiwi-autoconfig` is currently broken** (`mod tests` inside an `impl`;
   `cargo check --workspace` fails on it). Pre-existing, Agent 8's crate (T-135),
   not touched — but it means `cargo test --workspace` will stay red until Agent 8
   or Lead fixes it. Verify this crate with `-p kiwi-contacts` in the meantime.
5. **Schema v1 was still unshipped** when the `contact_emails.address` collation
   was corrected mid-task, so the v1 DDL was edited in place rather than
   versioned. Once any build ships, `MIGRATIONS` entries become immutable.
6. **Not wired into `kiwi-app`** — no IPC commands exist yet; the contract is the
   handoff for whoever implements them (T-146 territory).

**Files changed:** `Cargo.toml` (workspace members, +1 line),
`kiwi-contacts/**` (new: `Cargo.toml`, `src/lib.rs`, `src/error.rs`,
`src/contact.rs`, `src/store.rs`, `src/vcard.rs`, `tests/address_book.rs`),
`docs/contracts/contacts.md` (new), this log (new).

**Commands run:** none that build or test the crate (see Verification).
Read-only inspection of `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`kiwi-mail/src/{store,error,lib}.rs`, `kiwi-forensics/src/lib.rs`,
`docs/agents/agent-6-status.md`, `docs/contracts/{mailauth,ipc}.md`, and the root
`Cargo.toml`/`Cargo.lock`.

**Assumptions:** T-150 was assigned directly in the session brief; it is not yet
in `docs/TASKS.md` and this agent does not edit that file (ledger is Lead-owned,
prompt.md §8). Lead to add the row.

**Next exact action:** re-run the three gate commands (see the fix-round entry
below, which supersedes this one).

## 2026-09-20 — T-150 fix round (Lead gate: crate compiles, 39 pass, 2 fail)

**Status:** both failures fixed. Re-verification **still pending on this agent's
side** — the command classifier remained unavailable for the entire session, so
`cargo test` could not be re-run here. The Lead's runner produced the gate result
below; it is the authoritative evidence so far, and the exact commands to repeat
are listed at the end of this entry.

### Gate result received

`kiwi-contacts` compiles; 39 tests pass; 2 fail:

- `vcard::tests::empty_input_is_an_empty_import`
- `vcard::tests::hostile_values_cannot_break_the_stream_open`

### Failure 1 — blank line treated as malformed (real bug)

`parse_vcards` skipped lines only when `text.is_empty()`. A whitespace-only line
(a stray `"   "`, or a vCard written with trailing spaces) fell through to the
content-line parser, found no `:`, and returned `MalformedLine` — so
`import_vcards("   \r\n", …)` errored instead of importing nothing. The module
docs already promised that blank lines are tolerated, so the code was wrong, not
the test.

**Fix:** `if text.trim().is_empty() { continue; }` with a comment stating blank
and whitespace-only lines carry no content. Stray *content* is still a hard
error — `structurally_broken_streams_fail_hard` covers that and is unaffected.

### Failure 2 — the assertion was wrong, and it exposed a model/contract mismatch

The test escaped a newline into `FN` and then asserted the *exported* text
contained exactly one `BEGIN:VCARD` / `END:VCARD`. That assertion is simply
incorrect: the escaped value legitimately contains those strings as data, so
both counts were 2. Counting substrings in a serialized format is not a
structure test.

Replacing it with a real structure assertion surfaced something worth fixing:
the test's premise was that the card imports with a newline **inside**
`display_name` — and the code did allow that, because `validate`'s control-char
loop permitted `\n` and `\t` in `display_name`, `org` and `title`. **The
contract said only `notes` is multi-line.** So the code and `contacts.md` §4
disagreed, and the code was the permissive side.

**Resolution — tightened the model, not the doc.** `notes` is now the only
multi-line field. Every other text field (`display_name`, all `N` components,
`org`, `title`, `source_uid`, email addresses, phone numbers and labels) refuses
all control characters, newline included. Rationale: a newline in a display name
renders as structure in a list row, a composer chip or a header, and no genuine
address book produces one. A card carrying one is now refused **per card** with
the field named — still not a stream break, which is the property the test
exists to protect.

**Test rewritten** to assert the property that matters rather than a substring
count: the stream still parses as exactly one card with exactly one property
(the escaped newline is data, not a card break), and the card is refused with a
reason naming `display_name`. Added `notes_is_the_only_multi_line_field` to pin
the new rule in both directions (`NOTE:` with `\n` imports; `ORG:` with `\n` is
refused and names `org`).

### Files changed this round

`kiwi-contacts/src/vcard.rs` (blank-line skip; hostile test rewritten; new
multi-line test), `kiwi-contacts/src/contact.rs` (`validate`: single-line
control-character rule + `notes` exception), `docs/contracts/contacts.md` §4
(control-character rule stated explicitly), this log.

### Verification — exact commands to run

```
cargo fmt -p kiwi-contacts
cargo test -p kiwi-contacts
cargo clippy -p kiwi-contacts --all-targets -- -D warnings
cargo fmt -p kiwi-contacts -- --check
```

Expected: 41 tests (39 + `notes_is_the_only_multi_line_field` + the rewritten
`hostile_values…`), 0 failures; clippy and fmt clean. **If the count is not 41,
something else changed** — investigate rather than assume.

### Risks

1. **The fix is unverified.** Both changes are reasoned from the gate's failure
   names, not observed. Do not mark T-150 done until the run above is green.
2. The tightening is a **behaviour change** for any already-stored contact that
   carries a newline in a single-line field: `update` on such a contact now
   fails validation. No such data can exist in practice yet — nothing writes to
   this store outside tests, and schema v1 was never shipped.
3. `docs/contracts/contacts.md` §4 and the code now agree; §5.3's property table
   and §8's out-of-scope list were unaffected by this round.

## 2026-09-20 — T-149: kiwi-admin e2e suite + 4 defects found in the admin stack

**Status:** suite written (`infra/e2e/`), **not executed** — the command
classifier stayed unavailable for this entire session, so no `docker`, `npm`
or even `python` invocation was possible. Everything below marked "verified" was
verified by **reading the source**, not by running it. Four real defects fell
out of that reading; one I fixed, three need a decision.

### Delivered

| File | Contents |
|------|----------|
| `infra/e2e/test_admin_e2e.py` | stdlib-`unittest` e2e over live compose: full org/user/role/policy/evaluate/mailflow flow, RBAC denial refused **and** audited, contiguous `seq`, append-only guard rejection, and guard-bypass tamper **detection**. Dialect-parametrized via a `Backend` strategy. |
| `infra/e2e/README.md` | What it proves, the dialect table, why PG skips, safety notes. |
| `docker-compose.yml` | One-line fix, defect 1 below. |

Design points worth review:

- **Both layers are tested, not just the guard.** The trigger's own comment
  admits "a file/superuser holder can DROP TRIGGER first, so hash-chain
  verification on read remains the detection layer". So the suite (a) proves the
  guard refuses UPDATE/DELETE, and (b) drops the trigger, rewrites `seq 1`, and
  proves `GET /api/v1/audit/verify` returns `chain broken at seq 1` — then
  restores the row and trigger and re-verifies, so the run is repeatable.
- **`PostgresLeg` self-detects.** Per the Lead's "both dialects" decision I did
  not hardcode a skip. ~~It probes whether compose `db` actually holds service
  rows; it starts passing by itself when the wiring lands, no edit here.~~
  **SUPERSEDED** — the data-presence probe was wrong (a freshly migrated PG holds
  zero rows, so it would skip the leg it was meant to enable). Replaced by
  `service_dialect()`, which reads the driver from the service's startup log. See
  the defect 2/3/4 entry below, which is the current state of this suite.

### Defect 1 — compose passed the wrong env var name (FIXED)

`server.ts:341` reads `KIWI_ADMIN_PORT` (default **8471**); `docker-compose.yml`
set `PORT: "3001"`, which the service ignores. The container therefore listened
on 8471 while the published mapping, the compose healthcheck and the image
`HEALTHCHECK` all probed 3001 — the admin service was unreachable through its
published port, which is why T-133's admin-health test could never pass.
`.env.example` and `admin-api.md:240` already document `KIWI_ADMIN_PORT`, so the
code was right and compose was wrong.

**Fix:** compose now sets `KIWI_ADMIN_PORT: "3001"` (comment explains why).
`SqliteLeg.test_service_listens_on_the_published_port` is a regression guard.

### Defect 2 — the service never opens Postgres (needs decision)

Compose passes `DATABASE_URL` (PG) and declares `admin depends_on db: healthy`,
but `services.ts:61` hardcodes `openSqlite`/`migrateSqlite`, and `KIWI_ADMIN_DB`
defaults to a container-local SQLite file. `openPg`/`migratePg` are referenced
**only** from `tests/db.migrations.test.ts`. So the `db` service holds none of
the service's data, and `drizzle/pg/` migrations are never applied by the
running service.

This matters beyond cosmetics: the Lead's "apply Drizzle migrations" step is
ambiguous while both exist, and ADR-006/007 name PG as primary.

**Not a config tweak:** `repositories.pg.ts` implements `AsyncInterface<T>`
(every method returns a Promise); the service layer, `ServiceContainer.auditWrap`
(sync `work: () => T`) and all HTTP routes are synchronous. `src/db/README.md`
calls unifying them "tracked follow-up work (needs Lead)". It is a real
refactor of Agent 5's active area — I did **not** start it unverified.

### Defect 3 — `GET /api/v1/audit` ignores the actor entirely (needs decision)

`server.ts:323` calls `container.audit.query(filter)` with **no actor and no
`requirePermission`**, unlike `mailflow.query(actor, filter)` which checks
`mailflow.read`. `AuditService.query` takes only a filter. `audit.read` exists in
the RBAC matrix (`rbac.ts:22`) and is held by all three roles, so nothing
enforces it on the audit routes — including `/audit/verify`. For a product whose
audit log is a security control, an unauthenticated read of it is worth a
decision even at dev-scaffold grade.

Related, same file: `actorFromHeaders` falls back to `["org_admin"]` when the
`x-kiwi-roles` header is absent **or unparseable** (`server.ts:48`) — a
fail-open default on the RBAC input. A viewer-only deployment that typos a role
name silently becomes org_admin.

### Defect 4 — the `?org=` audit filter silently does nothing

`server.ts` reads `?org=` into `filter.orgId`, but `AuditService.query`
(`mailflow/services.ts:79`) never reads `orgId` — it only uses `since`/`until`/
`limit`. A caller asking for one org's audit history gets every org's. Worse than
an absent filter, because it looks like it worked. My suite deliberately does not
rely on it (comment at the call site).

### Verification

- **Nothing was executed.** `docker`, `npm`, `node`, `python` — all blocked by
  the classifier outage for the whole session.
- Consequently: the suite is **unrun**, the compose fix is **unconfirmed**, and
  any syntax or logic error in `test_admin_e2e.py` is still there. Treat T-149 as
  `in-progress`. Given T-150's gate result, assume the same class of defects.
- Read-only basis for the four defects: `server.ts`, `services.ts`, `rbac.ts`,
  `policy/services.ts`, `mailflow/services.ts`, `audit/chain.ts`,
  `db/{pg,sqlite,interfaces}.ts`, `db/README.md`, both `0001_*` guard migrations,
  `schema.sqlite.ts`, `Dockerfile`, `docker-compose.yml`, `.env.example`.

### Exact next actions

```bash
python -c "import ast; ast.parse(open('infra/e2e/test_admin_e2e.py').read())"   # syntax
docker compose up -d --force-recreate admin
python -m unittest discover -s infra/e2e -v
```

Expect `SqliteLeg` to run and `PostgresLeg` to skip with the defect-2 reason.
Then decide defects 2/3/4 — I did not act on them, as each changes behaviour
outside T-149's "tests" scope and 3 is a security-relevant call.

> **SUPERSEDED by the defect 2/3/4 entry below.** Defects 2/3/4 were approved and
> implemented, and a fifth blocker (the `Dockerfile` never copying `drizzle/`) was
> found and fixed. Because compose sets `DATABASE_URL`, the running container now
> opens **Postgres**, so the expectation is now the reverse: `PostgresLeg` runs,
> `SqliteLeg` skips. Use the next-actions list in the newest entry, not this one.

**Files changed:** `infra/e2e/test_admin_e2e.py` (new),
`infra/e2e/README.md` (new), `docker-compose.yml` (defect 1), this log.

## 2026-09-20 — T-149: defects 2/3/4 implemented (+ defect 5 found), suite STILL UNRUN

**Status:** all three approved defects are implemented across source, tests and
contract; a **fifth, more fundamental blocker** surfaced while implementing them
and is fixed. **Nothing was executed** — the command classifier was unavailable
for the entire session (both the Bash and PowerShell tools), so `tsc`, `vitest`,
`docker compose` and `python -m unittest` all remain un-run. Every claim below is
a *statement about the source as written*, not a test result. T-149 is
`in-progress`, not done.

### What the Lead approved, and what was built

**(2) Dialect branch — APPROVED, done.** `createServiceContainer` now chooses the
driver from `DATABASE_URL`: present -> `createPgServiceContainer` (`openPg` +
`migratePg`), absent -> SQLite. `ServiceContainer` gained `readonly dialect` and
`readonly db: Db | null` (`null` on Postgres — node-postgres has no synchronous
query path, so the raw facade genuinely cannot exist there).

**(3) `audit.read` + fail-closed actors — APPROVED, done.** `AuditService.query`
and `.verify` both take an `Actor` and call `requirePermission(actor,
"audit.read", …)`; both server routes now pass the actor. `actorFromHeaders`
maps `x-kiwi-roles` through `ALL_ORG_ROLES` and yields **no** roles when the
header is absent or unrecognized (the old `["org_admin"]` fallback is gone; the
subject keeps a `local-unauthenticated` placeholder only so the denial is
attributable). `admin-api.md` §12.2 records that header-actors remain a
dev scaffold pending real session auth.

**(4) `?org=` filter — APPROVED, done, in SQL.** `AuditRepository.range` gained a
4th `orgId` parameter and both drivers push `eq(audit_log.org_id, orgId)` into
the `WHERE`, rather than filtering after the query. Deliberate: a post-filter
would let `limit` truncate the window first and silently return the wrong rows,
and `verify()` relies on the unfiltered range for chain contiguity.

### Defect 5 — the admin image could never migrate (FIXED)

Found while implementing defect 2, and it is a **hard blocker that defect 1 and
defect 2 both sat on top of**: `Dockerfile` copied `/app/dist` but never copied
`drizzle/`. `openSqlite`/`openPg` resolve `migrationsFolder` relative to the
compiled module (`/app/dist/db/pg.js` + `../../drizzle/pg` -> `/app/drizzle/pg`),
so inside the container the migrator found no `meta/_journal.json` and the
process died **before it could bind a port**. Compose's `admin` healthcheck could
therefore never go green — for a reason independent of the wrong `PORT` name.
`src/db/README.md` already listed shipping `drizzle/` as a packaging requirement,
so this was a known requirement that was never implemented.

**Fix:** `COPY drizzle/ ./drizzle/`, with a comment stating that migration SQL is
runtime data, not build input.

Checked statically, since the build itself cannot run: `pg.ts:30` uses
`fileURLToPath(new URL("../../drizzle/pg", import.meta.url))`, which is
**module-relative** — `/app/dist/db/pg.js` -> `/app/drizzle/pg` — so the copy
destination is right regardless of the container's working directory.
`.dockerignore` does not exclude `drizzle/`, and its `*.sqlite*` line cannot match
the `drizzle/sqlite/` *directory* (Docker's patterns do not cross `/`, and no path
segment contains a literal `.sqlite`), so both dialects ship. `meta/_journal.json`
is present in both. The builder stage still does not receive `drizzle/`, which is
correct: it only runs `tsc`, and the migration tests are not executed in the image.

### Design decision: `MaybePromise<T>` — and why it is the *minimal* async surface

`repositories.pg.ts` was already an `AsyncInterface<T>` mirror; unifying the two
drivers meant the service layer had to tolerate both. Rather than duplicate every
service, the split is expressed in exactly one place:

```ts
export type MaybePromise<T> = T | Promise<T>;
```

Every repository method now returns `MaybePromise<...>`. `await` on a non-Promise
is a no-op, so **one** implementation of every service serves both drivers, and
the pure cores (policy evaluator, audit chain, validation, RBAC) stay
synchronous. `Awaited<MaybePromise<X>> = X`, so `AsyncInterface<T>` is unchanged
and `db.migrations.test.ts`'s compile-time conformance block still holds —
`PgOrgRepository extends AsyncInterface<OrgRepository>` is still `true`.

The alternative — making the whole service layer `async` and returning `Promise`
from the interfaces — was rejected as the larger change: it would have forced a
Promise into the SQLite path, which resolves synchronously, and pushed `async`
through `auditWrap`, every route and every test for no behavioural gain.

### A second compile error found by reading (fixed)

`tsconfig.json` sets **`exactOptionalPropertyTypes: true`**, under which an absent
property and one explicitly set to `undefined` are different types.
`startServer` forwards its own optional parameters straight through:

```ts
await createServiceContainer({ dbPath: opts.dbPath, databaseUrl: opts.databaseUrl })
```

`opts.dbPath` is `string | undefined`, which is **not** assignable to `dbPath?:
string` under that flag — a guaranteed `npm run typecheck` failure, and the
codebase has no precedent for it. Fixed by declaring both fields as
`dbPath?: string | undefined` / `databaseUrl?: string | null | undefined`, which
is also the honest type: "explicitly `undefined`" needs to mean "follow the
environment", and `createServiceContainer` already implements exactly that. The
`| undefined` is commented in both places so a later cleanup does not reintroduce
the error. **This was found by inspection, not by the compiler** — see
Verification.

### Interpretation recorded: "SqliteLeg run + PostgresLeg live" cannot both hold

The Lead expected both legs to run now that the wiring lands. They cannot: a
single container opens one driver, and compose sets `DATABASE_URL`, so it takes
the Postgres path. The suite therefore **self-detects** — `service_dialect()`
parses the driver out of the service's own startup line
(`… listening on http://127.0.0.1:3001 (postgres)`) and the matching leg runs
while the other skips with a reason naming the wiring. This replaced an earlier
data-presence probe, which was wrong in principle: a freshly migrated Postgres
holds zero audit rows, so a probe requiring rows would have skipped the very leg
it was meant to enable. SQLite guard coverage stays in-process via
`tests/audit.guard.test.ts`.

Test-class structure: `AdminE2E` (stack lifecycle + helpers, no tests) ->
`TransportLeg` (always: port, `/healthz`, dialect, `audit.read` guard) and
`DialectLeg` (abstract; the 5 flow/tamper/org-filter tests) ->
`SqliteLeg` / `PostgresLeg`. `DialectLeg` raises `SkipTest` on itself, because
`unittest` collects abstract `TestCase` subclasses and would otherwise fail every
inherited test on a missing `backend`.

### A guaranteed-failure bug in the e2e suite itself (found by reading, fixed)

`TLS_VERSION_ALIASES` (`types.ts:25`) is keyed `ssl3`, `tls1_0`/`tls1`/`tls1.0`,
`tls1_1`, `tls1_2`/`tls1.2`, `tls1_3`/`tls1.3` — **there is no `1.2` key**. My
`exercise_full_flow` sent `"min_tls": "1.2"` and `"tls_version": "1.2"` in three
places, and both consumers reject an unaliased label with `400`:

- `server.ts:119` (`parsePolicyBody`) -> `min_tls` -> policy create fails;
- `server.ts:246` accepts the snake_case fallback and then `:269` rejects it ->
  `evaluate-outbound` fails;
- `mailflow/model.ts:72` (`parseMailflowIngest`) -> ingest fails.

`exercise_full_flow` opens with `assertEqual(status, 201)` on the policy, so
**the suite would have failed on its first run at step 4 of 6**, in every leg
that ran. Fixed to `tls1.2` in all three places, with a comment naming the alias
table so it is not reintroduced. Also corrected the ingest fixture's
`security_status` from `"ok"` (not in `SECURITY_STATUSES`, so it silently became
`"unknown"`) to `"clean"`.

Found by reading the alias table while checking that the flow's inputs are
actually valid — not by a failing run, since there was no run. **This is the
concrete argument for running the suite before trusting it**, and it is the
reason the entry below refuses to call anything here verified.

### A dialect claim in the previous entry that needed checking

The Postgres leg's premise is that compose hands the service a `DATABASE_URL`.
Confirmed at `docker-compose.yml:78` (`DATABASE_URL: ${DATABASE_URL}` on the
`admin` service, with `depends_on: db: service_healthy`), so the container takes
the Postgres path and `PostgresLeg` is the leg that runs — `SqliteLeg` skips.

One thing that does **not** need `x-kiwi-org`: `hasPermission` (`rbac.ts:83`)
only applies org scoping when the actor itself has an org binding
(`actor.orgId !== null`). The suite's `ORG_ADMIN`/`VIEWER` headers carry no
`x-kiwi-org`, so they are platform-level actors and act on any org — which is why
the flow's `POST /orgs/{org}/users` succeeds and why `VIEWER` still gets its 403
(the denial comes from `policy.write` not being in the viewer role, not from org
scoping). Both behaviours are exercised as intended.

### Two things deliberately *not* changed

1. **`assertNonEmptyString` was not hoisted out of the `auditWrap` closures.**
   Hoisting it would make RBAC run after validation, turning a viewer's 403 into
   a 400 — a behaviour change nobody asked for.
2. **No startup probe of the audit chain.** I briefly added
   `audit.verify(...).catch(...)` to `startServer` and removed it: a denied verify
   appends a `denied` row, so it would have written a junk entry to the chain on
   every boot.

### Verification — NONE

- **Nothing ran.** `npx tsc --noEmit`, `npm run typecheck`, `node --version` and
  `python` were all refused by the classifier ("deepseek-v4-flash is temporarily
  unavailable, so auto mode cannot determine the safety of …") on both the Bash
  and PowerShell tools, across two full sessions. Read-only tools still work,
  which is how the static review below was done.
- I did **not** use `dangerouslyDisableSandbox` to get around it — that flag
  overrides the sandbox, not the permission decision, and reaching for it to
  bypass a safety gate the user's configuration put in place is not mine to do.
- **Basis for everything above is reading, not running.** The async refactor
  touches 8 source files and 5 test files and has never been compiled. Static
  review this session covered: `services.ts`, `server.ts`, `policy/services.ts`,
  `mailflow/services.ts`, `db/interfaces.ts`, both `range` implementations, both
  audit schemas (confirming `orgId` exists in each), `tsconfig.json`,
  `db.migrations.test.ts` (conformance block), and all 5 test files. That review
  found the `exactOptionalPropertyTypes` error above; it is not a substitute for
  a compiler, and there is no reason to assume it found everything.

### Exact next actions

Order matters — the typecheck is the cheapest way to find what the static review
missed, and the compose step has a real side effect.

```bash
cd kiwi-admin
npm run typecheck          # expect the exactOptionalPropertyTypes class of error
                           # to be gone; anything else it reports is genuinely new
npm test                   # vitest; expect 55+ (was ~48 before the new tests)
```

```bash
cd ..                      # repo root
docker compose up -d db admin
docker compose logs --no-log-prefix admin | tail -20   # expect "(postgres)" in the listening line
python -m unittest discover -s infra/e2e -v
```

### Risks

1. **Everything in this entry is unverified.** Treat the whole T-149 change set
   as suspect until `npm run typecheck && npm test` is green. The 5 new/rewritten
   test files have never been executed even once.
2. **`docker compose up -d admin` now applies real migrations** to the persistent
   `pgdata` volume. That is the intended new behaviour (it is the point of defect
   2), but it is a first-time side effect on shared state — not a dry run.
3. **The e2e suite runs against a persistent PG volume, so the audit log
   accumulates across runs.** Every run adds ~6 rows per flow test, and the suite
   reads with `?limit=1000` (`verify` with `10000`). The current assertions hold
   under accumulation — `seq` still starts at 1, and per-org rows stay few because
   each run mints a fresh org — but a suite whose fixture is "whatever is already
   in the database" is one long-lived deployment away from confusing failures.
   `docker compose down -v` is the clean-room reset.
4. **The e2e tamper probe drops the PG trigger.** If a run is killed between the
   DROP and the restore, `seq 1` stays rewritten and the chain stays broken, so
   every later run fails until `docker compose down -v`. Called out in the
   `assert_chain_valid` failure message and in `infra/e2e/README.md`.
5. **Fail-closed roles is a behaviour change that will look like a regression to
   any caller that was relying on the old fallback.** Any script, curl example or
   Agent 7/8 integration that omitted `x-kiwi-roles` used to get org_admin; it now
   gets 403 `auth.denied`. That is the approved intent, but it is worth a grep for
   other callers before the Lead treats a 403 as a new bug.
6. **`kiwi-autoconfig` still fails `cargo check`** (`mod tests` nested inside an
   `impl`, `autoconfig_xml.rs:547`), so `cargo test --workspace` stays red for
   reasons unrelated to this work. Agent 8's crate; untouched here.
7. **T-150 is still not green** — its fix round is also unrun (see the entry
   above). The exact commands are there; 41 tests expected.

**Files changed:** `kiwi-admin/src/db/interfaces.ts`,
`kiwi-admin/src/db/repositories.ts`, `kiwi-admin/src/db/repositories.pg.ts`,
`kiwi-admin/src/services.ts`, `kiwi-admin/src/server.ts`,
`kiwi-admin/src/policy/services.ts`, `kiwi-admin/src/mailflow/services.ts`,
`kiwi-admin/Dockerfile` (defect 5), `kiwi-admin/tests/services.test.ts`,
`kiwi-admin/tests/audit.guard.test.ts`, `kiwi-admin/tests/policy.bridge.test.ts`,
`kiwi-admin/tests/mailflow.emitter.test.ts`, `kiwi-admin/tests/server.test.ts`,
`kiwi-admin/src/db/README.md`, `docs/contracts/admin-api.md` (§12.1–12.3),
`infra/e2e/test_admin_e2e.py`, `infra/e2e/README.md`, this log.

**Commands run:** none. Read-only inspection only (the file list in Verification
above, plus `schema.{pg,sqlite}.ts`, `db.migrations.test.ts`, `tsconfig.json`).

**Assumptions:** T-149 is not in `docs/TASKS.md`; that ledger is Lead-owned
(prompt.md §8) and was not edited.
