# kiwi-admin end-to-end tests (T-149)

`test_admin_e2e.py` drives the **live compose stack** over HTTP and proves the
two properties the audit log claims. Stdlib only — no pytest, no new deps.

```bash
docker compose up -d db admin          # or let the suite start them
python -m unittest discover -s infra/e2e -v
```

The suite starts `db` and `admin` itself and waits for `/healthz`, so the
command above is optional. It **skips — never fails —** when the Docker daemon
or the stack is unavailable.

## What it proves

**Tamper rejection (the guard).** `drizzle/{pg,sqlite}/0001_*` installs a
DB-level trigger that ABORTs UPDATE and DELETE on `audit_log` from any
connection. The suite attempts both directly and asserts they are refused, then
re-checks the chain.

**Tamper detection (the layer behind the guard).** The trigger's own comment is
honest: *"a file/superuser holder can DROP TRIGGER first, so hash-chain
verification on read remains the detection layer."* The suite does exactly that
— drops the trigger, rewrites `seq 1`'s `action`, and asserts
`GET /api/v1/audit/verify` reports `chain broken at seq 1`. It then restores the
row and the trigger and asserts the chain verifies again, so the run is
repeatable and leaves the database consistent.

Plus the functional flow (orgs → users → roles → policies →
`evaluate-outbound` → mailflow ingest/query), RBAC denial being both refused and
audited, contiguous `seq` ordering, the signed audit export (T-179), and
regression guards for the three defects fixed alongside this suite (see below).

## Audit export coverage (T-179)

`GET /api/v1/audit/export` returns signed NDJSON of the whole chain
(contract `docs/contracts/admin-api.md` §13). Four tests in `TransportLeg`:

| Test | Asserts |
|------|---------|
| `test_audit_export_is_ndjson_of_the_whole_chain` | `application/x-ndjson`, line count = `rows + 3`, header window matches the rows shipped, `chain_state.valid`, `signature.covers_through` |
| `test_audit_export_signature_is_recomputable` | the HMAC recomputed in Python from the raw body matches, `key_id` is the key's SHA-256 prefix, and the key itself never appears in the artifact |
| `test_audit_export_rows_rehash_independently` | every `entry_hash` recomputed in Python from the exported row alone (canonical JSON, `admin-api.md` §7 field order, `prev_hash` chaining from `genesis`) |
| `test_audit_export_needs_more_than_audit_read` | `403` for viewer, security_admin, role-less, and unrecognized-role callers |

The third test is the one that matters: it recomputes the chain in a different
language without calling back into the service, which is the property the export
exists to provide. If a verifier outside Node cannot reproduce the hashes, the
format is not independently verifiable and the test should fail.

The signature test **skips** when `KIWI_AUDIT_EXPORT_KEY` is unset, because
unsigned exports are a supported, honestly-reported state rather than a bug —
the export says `signed: false` instead of emitting a placeholder. Note that an
`.env` predating T-179 will not carry the key; add it from `.env.example` (or
let compose fall back) to exercise the signature.

## Test classes

| Class | Runs | Covers |
|-------|------|--------|
| `TransportLeg` | always | published port, `/healthz`, dialect reporting, the audit routes' `audit.read` guard, the T-179 export |
| `SqliteLeg` | when the service opened SQLite | the shared flow + tamper tests on SQLite, `sqlite_master` table check |
| `PostgresLeg` | when the service opened Postgres | the shared flow + tamper tests on Postgres, `pg_tables` check |

`DialectLeg` holds the shared flow/tamper tests and is abstract — it declares no
backend, so it raises `SkipTest` on itself rather than failing on every test.

**Which leg runs is read from the service's own startup log.** `server.ts`
prints the driver it opened (`… listening on http://127.0.0.1:3001 (postgres)`),
and the leg that does not match skips with that reason. This replaced an earlier
data-presence probe, which was wrong: a freshly migrated Postgres holds zero
audit rows, so a probe requiring rows would have skipped the very leg it was
meant to enable.

Compose sets `DATABASE_URL`, so the containerized service takes the Postgres
path and `PostgresLeg` is the one that runs. The SQLite guard is still covered
in-process by `kiwi-admin/tests/audit.guard.test.ts`.

## Regression guards for the defects fixed with this suite

- **Compose env.** The service reads `KIWI_ADMIN_PORT`, not `PORT`; compose set
  the wrong name, so the container listened on the 8471 default while the
  published mapping and both healthchecks probed 3001.
  `TransportLeg.test_service_listens_on_the_published_port`.
- **Audit routes.** `GET /api/v1/audit` and `/audit/verify` took no actor and
  called no `requirePermission`, and `actorFromHeaders` fell back to
  `["org_admin"]` for an absent or unparseable roles header.
  `TransportLeg.test_audit_routes_require_a_role` asserts both audit routes
  refuse a role-less caller AND a caller whose role names are unrecognized.
- **`?org=` filter.** Accepted by the server, ignored by `AuditService.query`,
  so one org's request returned every org's rows.
  `DialectLeg.test_audit_org_filter_actually_narrows`.

## Safety

- Binds to the compose-published admin port on **127.0.0.1**; the service itself
  refuses any other interface.
- The tamper probe edits and restores one audit row.
- **Postgres data persists in the `pgdata` volume.** If a run is killed between
  dropping the guard and restoring it, `seq 1` stays rewritten and the chain
  stays broken — correct, but it will fail every later run until reset with
  `docker compose down -v`. The SQLite file is container-local, so
  `docker compose up -d --force-recreate admin` resets that dialect.
- Synthetic data only (`*.kiwi-test.invalid`, `*.invalid`).

# Mail-flow vertical e2e (T-171)

`test_mail_flow.py` proves the sync-to-forensics vertical for real:
compose `mailpit`+`greenmail` up → IMAP APPEND seed → the real
`sync_folder` engine → store rows → `event_from_live` →
`RuleEngine` → deterministic `KIWI-TRANSPORT-001` + `KIWI-AUTH-001`.

```bash
python -m unittest discover -s infra/e2e -p "test_mail_flow.py" -v
```

The suite starts the two mail services itself and waits for the IMAP
greeting + SMTP banner, so no manual `compose up` is needed. It
**skips — never fails —** when Docker or the stack is unavailable, and
leaves services running afterwards (`docker compose down` stays the
operator's call).

The heavy lifting is the Rust leg
(`kiwi-forensics/tests/vertical_mail_flow.rs`, env-gated `KIWI_E2E=1`
so `cargo test --workspace` stays hermetic): connect + LOGIN,
self-seeding APPEND with a per-run marker subject, `sync_folder` into
a memory-backed `MailStore`, row assertions, adapter evaluation
(double-run byte-identical JSON), then flag+expunge cleanup so reruns
are deterministic.

Scope note, asserted by the suite itself: GreenMail advertises no
STARTTLS, so plaintext verdicts are the honest expectation here — a
TLS-observation vertical needs a TLS-capable fixture server first
(future work, not this harness).
