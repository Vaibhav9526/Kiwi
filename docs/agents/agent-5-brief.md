# Agent 5 Brief — OpenCode Muse 1.3 #1 — THUNDERBIRD UI / UX / BRANDING

Read first: `prompt.md` (root), `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, this file. You are **Agent 5**.

## Mission (prompt.md §6 Agent 5)

- Preserve Thunderbird's visual language and workflows — KIWI must still
  feel like Thunderbird, not a dashboard app
- Integrate: secure connection status, account security panel, finding
  details, native lock screen, authenticator waiting/verification UI,
  security event details, re-scan/diff UI, local admin UI surfaces
- Use supplied `images/` assets (logo, favicon, banner) — never overwrite,
  never invent a replacement logo
- Accessibility, keyboard navigation, error/loading/locked states,
  dark/light theme compatibility

## Your Phase 0 task — T-005 (claimed)

Thunderbird source is still downloading; do NOT touch `source/`. Deliver:

1. `docs/ui-spec.md` — KIWI-in-Thunderbird UX spec: where each security
   surface lives inside the existing product (message-list security
   indicator, account security panel location, lock screen as a native
   overlay, authenticator waiting dialog, finding-detail view,
   policy-violation composer warning). For each: trigger conditions,
   states (normal/error/loading/locked), keyboard path, a11y notes,
   theme behavior.
2. `docs/contracts/ui-surfaces.md` — a registry of UI surfaces with IDs
   so Agent 2/Lead can wire real data to them later.
3. Brand asset audit: inspect `images/` (logo.svg/png, favicon, banner,
   black_bg), record sizes/formats/usage guidance in `docs/ui-spec.md`.
4. A11y + workflow checklist (what every UI change must be verified
   against) — include in `docs/ui-spec.md`.

## Boundaries

- Your files: `docs/ui-spec.md`, `docs/contracts/ui-surfaces.md`,
  `docs/agents/agent-5-status.md`. `images/` is READ-ONLY.
- Do not redesign Thunderbird; spec incremental, native-feeling additions.

## Reporting

Append dated entries to `docs/agents/agent-5-status.md`:
status, files changed, commands run, assumptions, risks.
Hit a limit → handoff entry in `docs/AGENT_HANDOFF.md`.
