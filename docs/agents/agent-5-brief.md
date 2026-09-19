# Agent 5 Brief v2 — OpenCode Muse 1.3 #1 — CLIENT UI / UX / BRANDING

**PIVOT (2026-09-19):** KIWI is a standalone email client built from scratch —
NOT a Thunderbird fork. See `docs/DECISIONS.md` ADR-005 and rewritten
`docs/ARCHITECTURE.md`. You now own the WHOLE app UI, not integration into
someone else's client. Thunderbird = UX reference for mail workflows;
Mailspring = reference for selected productivity features.

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`. You are **Agent 5**.

## Mission (updated)

The complete KIWI client frontend: mailbox, composer, accounts, settings —
with the security surfaces from your v1 spec (indicators, lock screen,
authenticator UI, findings, re-scan/diff) integrated natively, plus
Mailspring-inspired productivity features: **unified inbox, snooze, send
later, undo send, message templates**.

## Tasks (see docs/TASKS.md)

- T-111: rewrite `docs/ui-spec.md` for the standalone app (rename old spec
  context — v1 stays as security-surface input). Cover: three-pane mailbox
  layout, unified inbox, folder tree, message list + reader, composer,
  account setup wizard, settings, security surfaces (S-01..S-07 from v1),
  lock screen, authenticator waiting UI. Per surface: states
  (normal/error/loading/locked), keyboard path, a11y, theme (dark/light).
  Update `docs/contracts/ui-surfaces.md` to match (surface IDs stable where
  possible).
- T-112 (after Lead lands T-110 Tauri shell): scaffold the React+TS
  frontend in `kiwi-app/` — Vite + React + TS, route structure, layout
  shell, theme tokens derived from `images/` palette, stub views wired to
  the IPC command stubs. `images/` stays read-only.
- Keep the v1 checklist rigor: overflow/clipping, keyboard nav, focus,
  error/locked states, theme compat — now for the whole app.

## Boundaries

Yours: `docs/ui-spec.md`, `docs/contracts/ui-surfaces.md`, `kiwi-app/`
frontend files (NOT `src-tauri/` Rust — Lead owns; coordinate via
`docs/contracts/ui-surfaces.md`), `docs/agents/agent-5-status.md`.
`images/` read-only.

## Reporting

Append dated entries to `docs/agents/agent-5-status.md`. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
