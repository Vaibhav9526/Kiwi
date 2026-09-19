# Agent 2 Brief v2 — Devin SWE-2 — MAIL ENGINE + CORE SECURITY

**PIVOT (2026-09-19):** KIWI is now a standalone email client built from
scratch — NOT a Thunderbird fork. Read `docs/DECISIONS.md` ADR-005 and
`docs/ARCHITECTURE.md` (rewritten). Thunderbird source at `source/` is
READ-ONLY reference. Your kiwi-core work stays valid.

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, `docs/contracts/security-session.md` (yours). You are
**Agent 2**.

## Mission (updated)

You own the heart of the client: **`kiwi-mail`** (native mail engine) plus
the existing **`kiwi-core`** (security/trust/identity).

## Tasks (see docs/TASKS.md)

- T-101 `kiwi-mail/src/transport.rs`: TCP + rustls client, `TlsObservation`
  capture (TLS version, cipher suite, key-exchange group, ALPN, peer cert
  chain DER), `SocketSecurity` modes (Plaintext/ImplicitTls/StartTls),
  STARTTLS upgrade path returning a new TlsObservation.
- T-102 `smtp.rs`: EHLO→STARTTLS→AUTH(PLAIN/LOGIN/XOAUTH2)→MAIL/RCPT/DATA;
  send-queue hooks for undo-send/send-later.
- T-103 `imap.rs`: CAPABILITY/LOGIN/AUTHENTICATE/SELECT/FETCH
  (ENVELOPE, FLAGS, BODYSTRUCTURE, RFC822.SIZE, UID), UIDVALIDITY-aware
  sync primitives, IDLE.
- T-104 `pop3.rs`: USER/PASS + APOP, LIST/UIDL/RETR/DELE, STLS.
- T-105 `account.rs` + `store.rs`: account model; SQLite mail schema
  (accounts, folders, message metadata) + bodies/attachments on disk.
- T-106 `sync.rs` + `mime.rs`: folder sync engine; mail-parser inbound,
  native outbound builder.
- Also keep kiwi-core healthy: `cargo test` stays green.

Reference (behavior only): `source/comm/mailnews/compose/src/SmtpClient.sys.mjs`,
`local/src/Pop3Client.sys.mjs`, `imap/src/`. Write idiomatic async Rust
(tokio). Stream bodies — never buffer whole messages unboundedly.
Unit-test parsers/state machines against recorded transcripts (coordinate
fixtures with Agent 6, T-114). No real credentials anywhere.

## Boundaries

Yours: `kiwi-mail/`, `kiwi-core/`, `docs/contracts/security-session.md`,
`docs/agents/agent-2-status.md`. Deps: keep minimal + pinned; justify each
new crate in your status file. `cargo test -p kiwi-mail -p kiwi-core` green
before reporting progress.

## Reporting

Append dated entries to `docs/agents/agent-2-status.md`. Hit a limit →
handoff entry in `docs/AGENT_HANDOFF.md`.
