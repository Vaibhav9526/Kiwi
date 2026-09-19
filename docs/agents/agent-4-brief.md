# Agent 4 Brief — Cline + GLM 5.3 Flash — ORGANIZATION / POLICY / ADMIN CONTROL PLANE

Read first: `prompt.md` (root), `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, this file. You are **Agent 4**.

## Mission (prompt.md §6 Agent 4)

- Org model: organizations, domains, users, roles/admin permissions,
  devices, security policies
- Mail policies: allowed/blocked recipient domains, external-recipient
  warn/block rules, minimum TLS requirements, attachment/content interfaces
- Mail-flow metadata: sender, recipient, timestamp, direction, message-ID,
  security status, audit events — NO message bodies by default
- Local admin/control service: API, policy distribution, audit logging,
  RBAC, mail-flow + security-event queries
- Real enforcement is eventually gateway/relay-level — never claim a UI-only
  block is full organizational enforcement

## Your Phase 0 task — T-004 (claimed)

Thunderbird source is still downloading; you do NOT need it. Deliver:

1. `kiwi-admin/` Node + TypeScript service scaffold (strict tsconfig,
   vitest): modules `org` (orgs/domains/users/roles/devices), `policy`
   (policy model + evaluator interface), `mailflow` (metadata ingest +
   queries), `audit` (append-only tamper-evident log — hash-chained
   entries), `db` (SQLite via better-sqlite3 or equivalent; repository
   interfaces so Postgres can replace later).
2. `docs/contracts/admin-api.md` — REST/local API contract: endpoints,
   RBAC requirements per endpoint, policy object schema, mail-flow event
   schema, audit event schema.
3. SQLite schema + migrations for the org model.
4. Tests: policy evaluator unit tests (allow/deny domain, min-TLS
   downgrade, external-recipient warn), RBAC negative tests (unauthorized
   admin op rejected + audited), audit-log chain integrity test.

## Boundaries

- Your dirs: `kiwi-admin/`, `docs/contracts/admin-api.md`,
  `docs/agents/agent-4-status.md`. Nothing else without Lead coordination.
- Tests must pass before reporting done. Keep deps minimal + pinned.

## Reporting

Append dated entries to `docs/agents/agent-4-status.md`:
status, files changed, commands run, test results, assumptions, risks.
Hit a limit → handoff entry in `docs/AGENT_HANDOFF.md`.
