# Agent 7 Brief — Devin Pro — APP BACKEND / IPC INTEGRATION LAYER

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, `docs/API_CONTRACTS.md`, `docs/contracts/` (all three).
You are **Agent 7**.

## Mission

Make the app actually work end-to-end: turn the Tauri command stubs in
`kiwi-app/src-tauri/` into a real typed IPC layer backed by the services
other agents built.

## Tasks (see docs/TASKS.md)

- **T-120** — real command layer in `kiwi-app/src-tauri/src/lib.rs`:
  - account CRUD + connect/test → `kiwi_mail::account`
  - folder list, message list, message fetch → `kiwi_mail::{store,sync}`
  - send → `kiwi_mail::smtp` send queue (respect undo-send/send-later hooks)
  - security status/findings → `kiwi_core` trust state + `kiwi_forensics`
    findings for the session
  - **lock-state gate**: when kiwi-core trust state is `locked`, all
    commands except unlock/status return a locked error — enforce at the
    IPC boundary, not in the UI.
  - Typed serde result types; structured errors; no panics on frontend input.
- **T-121** — endpoint signal collector (Phase 3 foundation): bounded,
  measurable indicators only (process integrity, suspicious remote-session
  indicators, per `docs/SECURITY.md`) feeding `kiwi_core` trust evaluation.
  Windows-focused; read `docs/contracts/security-session.md` first. No
  EDR-scope creep.

## Boundaries

Yours: `kiwi-app/src-tauri/`, `docs/contracts/ipc.md` (create — command
catalog + payload schemas for Agent 5's frontend), `docs/agents/agent-7-status.md`.
NOT yours: `kiwi-app/src/` frontend (Agent 5), kiwi-mail internals (Agent 2 —
code to its public API; if a needed method is missing, note it in your
status + keep a typed stub, don't rewrite their crate), kiwi-core internals.

## Reporting

Append dated entries to `docs/agents/agent-7-status.md`. `cargo check -p
kiwi-app` + `cargo test --workspace` must stay green. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
