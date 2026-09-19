# Agent 4 Brief v2 — Cline + GLM 5.3 Flash — ORGANIZATION / POLICY / ADMIN

**PIVOT (2026-09-19):** KIWI is a standalone email client built from scratch —
NOT a Thunderbird fork. See `docs/DECISIONS.md` ADR-005 and rewritten
`docs/ARCHITECTURE.md`. `source/` is read-only reference. Your `kiwi-admin`
work stays valid and gains a real consumer: the KIWI client itself.

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`. You are **Agent 4**.

## Mission (unchanged + now client-facing)

Org model, mail policies, mail-flow metadata, local admin/control service.
New: the KIWI client consults your policy evaluator before sending, and
emits mail-flow metadata to your service.

## Tasks (see docs/TASKS.md)

- Finish T-004: `kiwi-admin/` scaffold + `docs/contracts/admin-api.md`
  (endpoints, RBAC per endpoint, policy schema, mail-flow event schema,
  audit event schema).
- T-108: policy-enforcement bridge — design + document how `kiwi-mail`'s
  send path calls the evaluator (local IPC/localhost HTTP; request =
  sender+recipients+account; response = allow/warn/block + reason codes).
  Specify the contract in `admin-api.md`; implement the server side.
- T-109: mail-flow metadata ingest endpoint + schema (sender, recipient,
  ts, direction, message-id, security-status — never bodies).
- Keep: hash-chained audit log, RBAC negative tests, SQLite behind
  repository interfaces, vitest green.

## Boundaries

Yours: `kiwi-admin/`, `docs/contracts/admin-api.md`,
`docs/agents/agent-4-status.md`. Deps minimal+pinned. Never claim UI-only
enforcement is organizational enforcement (prompt.md §6).

## Reporting

Append dated entries to `docs/agents/agent-4-status.md`. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
