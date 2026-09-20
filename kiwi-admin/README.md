# kiwi-admin — organization / policy / admin control plane

Node + TypeScript service owning orgs, domains, users, roles, devices,
security policies, mail-flow metadata (no message bodies) and a
tamper-evident append-only audit log. See `docs/contracts/admin-api.md`.

Design constraints (docs/SECURITY.md, docs/DECISIONS.md):
- Local-first; **Drizzle ORM** (ADR-006): PostgreSQL dialect is primary
  (`src/db/schema.pg.ts`, migrations in `drizzle/pg/`); SQLite dialect for
  tests/local (`src/db/schema.sqlite.ts`, `drizzle/sqlite/`). All persistence
  stays behind repository interfaces (`src/db/interfaces.ts`) so dialects are
  swappable behind business logic. PG connection strings come from the
  environment (`DATABASE_URL`) — never code, logs, or migrations.
- Deterministic only — no AI anywhere in this service.
- Never store or log message bodies or credentials.
- All API input is untrusted: validate type/length before use.

## Layout

```
src/db        Drizzle schemas (pg primary + sqlite mirror), repositories,
              connections, Drizzle Kit migrations (drizzle/pg, drizzle/sqlite)
src/policy    policy model + deterministic evaluator + send-path bridge
src/mailflow  mail-flow metadata ingest + queries + emitter builders
src/audit     hash-chained append-only audit log
src/rbac      roles and permission checks
tests         vitest unit tests
```

## Commands

```
npm install
npm run typecheck
npm test                          # sqlite-backed, hermetic (PG live skipped w/o DATABASE_URL)
DATABASE_URL=postgres://… npm test # also runs the PG live round-trip
npm run db:generate                # regenerate PG migrations after schema.pg.ts edits
npm run db:generate:sqlite         # regenerate SQLite migrations after schema.sqlite.ts edits
```

## Honest-enforcement note

Policy evaluation here is advisory/decision support. Real organizational
enforcement must occur at a mail gateway/relay layer; a UI-only block is NOT
complete organizational enforcement.
