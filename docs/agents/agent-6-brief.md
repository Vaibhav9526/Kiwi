# Agent 6 Brief v2 — OpenCode Muse 1.3 #2 — QA / TESTING / SECURITY ASSURANCE

**PIVOT (2026-09-19):** KIWI is a standalone email client built from scratch —
NOT a Thunderbird fork. See `docs/DECISIONS.md` ADR-005 and rewritten
`docs/ARCHITECTURE.md`. Your NOT READY authority is unchanged.

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`. You are **Agent 6**.

## Mission (updated)

Same authority, new system-under-test: a native client (Rust workspace +
Tauri app + Node admin service).

## Tasks (see docs/TASKS.md)

- T-113: update `docs/TESTING.md`, `docs/SECURITY.md`, `docs/THREAT-MODEL.md`
  for the standalone architecture: remove Thunderbird-integration matrix,
  add client matrix — send/receive (SMTP/IMAP/POP3), compose, folders,
  attachments, account setup, offline/online, lock/unlock, authenticator,
  policy enforcement. Threat model: the client itself is now the attack
  surface (mail parsing, attachments, remote content, IPC boundary between
  webview and Rust core).
- T-114: local test mail server strategy — evaluate in-process fakes vs a
  containerized server (mailpit/mailhog/greenmail); pick one, document
  how `kiwi-mail` tests run against it; add SMTP/IMAP/POP3 transcript
  fixtures under `tests/fixtures/`.
- T-115: quality-gate review (your G1–G11) of the scaffolds:
  `kiwi-core/`, `kiwi-forensics/`, `kiwi-admin/` — check tests actually
  pass (`cargo test -p kiwi-core`, `cargo test -p kiwi-forensics`,
  `cd kiwi-admin && npm test`), no secrets, dep hygiene; record verdicts
  in your status file.
- Extend lint/secret-scan baseline to cover the Cargo workspace + kiwi-app
  (when it lands): `cargo fmt --check`, `cargo clippy --workspace`,
  `cargo audit` if available.

## Boundaries

Yours: `docs/TESTING.md`, `docs/SECURITY.md`, `docs/THREAT-MODEL.md`,
`docs/quality-gate.md`, `tests/`, `docs/agents/agent-6-status.md`.
Review other agents' code read-only; record findings in your status file.

## Reporting

Append dated entries to `docs/agents/agent-6-status.md`. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
