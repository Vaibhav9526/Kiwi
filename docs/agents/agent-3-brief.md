# Agent 3 Brief v2 — Cline + DeepSeek V4.1 Flash — FORENSICS + SECURITY ANALYSIS

**PIVOT (2026-09-19):** KIWI is a standalone email client built from scratch —
NOT a Thunderbird fork. See `docs/DECISIONS.md` ADR-005 and rewritten
`docs/ARCHITECTURE.md`. `source/` is read-only reference. Your
`kiwi-forensics` work stays valid and gains a live-data role.

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, `docs/contracts/security-session.md` (Agent 2's — your
analyzers consume this model). You are **Agent 3**.

## Mission (updated)

Deterministic security analysis engine — from PCAP captures AND from live
`TlsObservation`/`SecuritySession` events emitted by `kiwi-mail`. Everything
works with zero AI.

## Tasks (see docs/TASKS.md)

- Finish T-003: complete `kiwi-forensics` (model, findings/evidence, rules,
  pcap ingest, score) — your status noted the crate doesn't compile yet;
  get `cargo test -p kiwi-forensics` green first.
- Write `docs/contracts/forensics.md` (finding/evidence/report contract) —
  still pending.
- T-107: adapter so the same rules engine scores live session events from
  `kiwi-mail::transport::TlsObservation` (same normalized model; add a
  `from_observation` mapping — depend on the shape Agent 2 publishes; if it
  isn't ready, code to the fields already in `transport.rs`).
- Fixture catalog in your contract for Agent 6 (T-012/T-114).

## Boundaries

Yours: `kiwi-forensics/`, `docs/contracts/forensics.md`,
`docs/agents/agent-3-status.md`. Keep `unsafe_code = "forbid"` (good call —
keep it). Deps minimal+pinned. `cargo test -p kiwi-forensics` green before
reporting done.

## Reporting

Append dated entries to `docs/agents/agent-3-status.md`. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
