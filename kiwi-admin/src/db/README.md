# kiwi-admin DB layer (Drizzle ORM, ADR-006)

- `schema.pg.ts` — PRIMARY schema (PostgreSQL): tables, CHECKs, FK cascades,
  indexes, typed relations. Mirrors `docs/contracts/admin-api.md` §4.
- `schema.sqlite.ts` — tests/local mirror (same tables/constraints/relations,
  SQLite affinities: 0/1 integers for booleans).
- `repositories.ts` — Drizzle repositories (better-sqlite3) implementing
  `interfaces.ts` exactly. Synchronous; used by `ServiceContainer` on the
  local path and by tests.
- `repositories.pg.ts` — async mirrors (`AsyncInterface`) for node-postgres.
  Same names/shapes; PG booleans mapped to 0/1 at the boundary. Used by
  `ServiceContainer` when `DATABASE_URL` is set.
- `sqlite.ts` / `pg.ts` — connections + Drizzle bindings + migrators.
  `openPg` takes a caller-supplied connection string (env only, never code).
- `interfaces.ts` — repository contracts + `Db` facade + `AsyncInterface<T>`
  mapper. Methods return `MaybePromise<T>`: better-sqlite3 resolves
  synchronously, node-postgres cannot. The service layer awaits them, so one
  implementation of every service serves both dialects (see admin-api.md
  §12.1). `AsyncInterface<T>` remains the explicit statement of intent for the
  PG repositories.
- `drizzle/pg`, `drizzle/sqlite` (repo root of kiwi-admin) — Drizzle Kit
  output: `0000_*` full schema, `0001_audit-append-only-guard` custom
  migration (audit triggers in both dialects). Regenerate with
  `npm run db:generate` / `db:generate:sqlite` after schema edits; custom
  SQL (triggers etc.) via `drizzle-kit generate --custom`.
- Packaging note: the `drizzle/` folders must ship with any deployed service
  — the migrators resolve them relative to `src/db/*.ts` at runtime.
