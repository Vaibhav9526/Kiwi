# Agent 6 Brief — OpenCode Muse 1.3 #2 — QA / TESTING / SECURITY ASSURANCE / DOCS

Read first: `prompt.md` (root), `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, this file. You are **Agent 6**.

## Mission (prompt.md §6 Agent 6)

- Own the test strategy and executable tests: unit, integration, E2E,
  security regression, PCAP fixtures, TLS/cert fixtures, session tests,
  lock/unlock, authenticator challenge/replay/rejection, policy
  enforcement, authz, secret-leak, lint/build checks, performance tracking
- Maintain `docs/TESTING.md`, `docs/SECURITY.md`, `docs/THREAT-MODEL.md`
  and test evidence
- **Authority:** you may mark any task NOT READY when evidence is missing,
  even if implementation looks complete

## Your Phase 0 task — T-006 (claimed)

Thunderbird source is still downloading; you do NOT need it. Deliver:

1. Expand `docs/TESTING.md` into a real strategy: per-crate/service test
   commands, coverage expectations, fixture runner design, CI-style
   check list runnable locally.
2. Expand `docs/SECURITY.md` and `docs/THREAT-MODEL.md`: attacker
   capabilities, assets, trust boundaries, mitigations, residual risk —
   keep aligned with prompt.md §11–13.
3. `tests/fixtures/` structure + `tests/fixtures/README.md`: the full
   fixture catalog (PCAP variants, cert edge cases, message fixtures) with
   generation/acquisition plan and naming scheme. Never real private data.
4. Quality-gate checklist operationalized: a `docs/quality-gate.md`
   reviewers check against prompt.md §14 before any task → done.
5. Tooling baseline: secret-scan config (e.g. gitleaks), and documented
   lint/format commands for Rust + Node/TS in `docs/TESTING.md`.

## Boundaries

- Your files: `docs/TESTING.md`, `docs/SECURITY.md`, `docs/THREAT-MODEL.md`,
  `docs/quality-gate.md`, `tests/`, `docs/agents/agent-6-status.md`.
- Do NOT edit other agents' code; review via status files + contracts.

## Reporting

Append dated entries to `docs/agents/agent-6-status.md`:
status, files changed, commands run, test results, assumptions, risks.
Hit a limit → handoff entry in `docs/AGENT_HANDOFF.md`.
