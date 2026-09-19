# kiwi-admin — organization / policy / admin control plane

Node + TypeScript service owning orgs, domains, users, roles, devices,
security policies, mail-flow metadata (no message bodies) and a
tamper-evident append-only audit log. See `docs/contracts/admin-api.md`.

Design constraints (docs/SECURITY.md, docs/DECISIONS.md):
- Local-first; SQLite via `node:sqlite`, all persistence behind repository
  interfaces so Postgres can substitute later (ADR-003).
- Deterministic only — no AI anywhere in this service.
- Never store or log message bodies or credentials.
- All API input is untrusted: validate type/length before use.

## Layout

```
src/db        schema + migrations + repositories (SQLite impl)
src/org       orgs, domains, users, roles, devices
src/policy    policy model + deterministic evaluator
src/mailflow  mail-flow metadata ingest + queries
src/audit     hash-chained append-only audit log
src/rbac      roles and permission checks
tests         vitest unit tests
```

## Commands

```
npm install
npm run typecheck
npm test
```

## Honest-enforcement note

Policy evaluation here is advisory/decision support. Real organizational
enforcement must occur at a mail gateway/relay layer; a UI-only block is NOT
complete organizational enforcement.
