# Agent 3 Brief — Cline + DeepSeek V4.1 Flash — FORENSICS / PCAP / TLS RULE ENGINE

Read first: `prompt.md` (root), `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, this file. You are **Agent 3**.

## Mission (prompt.md §6 Agent 3)

- Normalized protocol/security data model
- SMTP / IMAP / POP3 analyzers, STARTTLS analysis, TLS handshake parsing
- Certificate, cipher-suite, key-exchange analysis; forward-secrecy assessment
- Cryptographic weakness rules + deterministic scoring (works with NO AI)
- PCAP forensics: `.pcap/.pcapng` ingest, TCP reassembly, session
  reconstruction, TLS metadata extraction, evidence records, timeline
- Findings model: weakness → evidence → impact → remediation; re-scan diff;
  JSON/HTML/PDF report pipeline

## Your Phase 0 task — T-003 (claimed)

Thunderbird source is still downloading; you do NOT need it. Deliver:

1. `kiwi-forensics/` Rust crate scaffold (`cargo new --lib`): modules
   `model` (normalized connection/protocol/security events), `findings`
   (finding + evidence + severity + remediation + re-scan diff types),
   `rules` (deterministic rule engine: TLS version floor, weak ciphers,
   missing forward secrecy, cert problems, plaintext auth, STARTTLS
   stripping indicators), `pcap` (ingest interface — treat all bytes as
   untrusted), `score` (deterministic scoring).
2. `docs/contracts/forensics.md` — the finding/evidence/report contract.
3. Fixture plan in `docs/contracts/forensics.md`: list of PCAP fixtures
   needed (coordinate with Agent 6 who owns `tests/fixtures/`).
4. Unit tests: at minimum, rule engine tests with synthetic sessions
   (no real packets needed yet) proving deterministic scores.

Suggested crates (evaluate, justify in status file): `pcap-file` or
`etherparse`/`pcap` for parsing. Pin versions; keep deps minimal.

## Boundaries

- Your dirs: `kiwi-forensics/`, `docs/contracts/forensics.md`,
  `docs/agents/agent-3-status.md`. Nothing else without Lead coordination.
- `cargo test` + `cargo clippy` must pass before reporting done.

## Reporting

Append dated entries to `docs/agents/agent-3-status.md`:
status, files changed, commands run, test results, assumptions, risks.
Hit a limit → handoff entry in `docs/AGENT_HANDOFF.md`.
