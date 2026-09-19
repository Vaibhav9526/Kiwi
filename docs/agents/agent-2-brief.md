# Agent 2 Brief — Devin SWE-2 — CORE SECURITY + TRUSTED SESSION ENGINE

Read first: `prompt.md` (root), `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, this file. You are **Agent 2**.

## Mission (prompt.md §6 Agent 2)

- Thunderbird security integration (narrow hooks into TLS/NSS connection data)
- Normalized internal security-session model
- Endpoint trust: device registration, identity, integrity signals, session
  trust state, lock/unlock — NO AV/EDR, measurable indicators only
- SecureMail identity: account/session model, credential/session handling,
  device registration/revocation interfaces, recovery model

## Your Phase 0 task — T-002 (claimed)

The Thunderbird source is still downloading; do NOT touch `source/`.
Until the integration map (T-007) lands, deliver:

1. `docs/contracts/security-session.md` — the normalized `SecuritySession`
   contract: fields for protocol (smtp/imap/pop3), transport state
   (plaintext/starttls/tls), negotiated TLS version, cipher suite, key
   exchange group, cert chain summary, auth mechanism, forward-secrecy flag,
   trust evaluation inputs/outputs. Typed, versioned.
2. `kiwi-core/` Rust crate scaffold (`cargo new --lib`): modules for
   `session`, `trust` (state machine: trusted → degraded → locked),
   `device` (registration/revocation), `identity` (SecureMail
   account/session), `policy`. Include unit tests for the trust state
   machine transitions and challenge-binding rules.
3. Lock-state semantics: what reduces trust, what locks, what unlocks
   (authenticator-required path) — document in the contract.

## Boundaries

- Your dirs: `kiwi-core/`, `docs/contracts/security-session.md`,
  `docs/agents/agent-2-status.md`. Nothing else without Lead coordination.
- Rust: `cargo test` must pass before you report progress.
- Subagents allowed per prompt.md §7 — they report files/commands/tests.

## Reporting

Append dated entries to `docs/agents/agent-2-status.md`:
status, files changed, commands run, test results, assumptions, risks.
Hit a limit → write a handoff entry in `docs/AGENT_HANDOFF.md` (template there).
