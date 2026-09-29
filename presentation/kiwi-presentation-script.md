# KIWI — Presentation Script

**Tagline:** *Email that proves its security.*

---

## 1. Opening — the problem (30–45s)

"Every day, we click links, open attachments, and trust our inbox with
credentials, contracts, and conversations — yet almost nothing in a normal
email client can actually *prove* it did the secure thing. Your client says
'this connection was encrypted.' Says who? KIWI is built on a simple design
rule: **every security claim must be backed by evidence**, and when the
evidence isn't there, the UI says so instead of painting a fake green."

## 2. What KIWI is (30s)

"KIWI is a full-featured desktop email client **and** a security platform in
one product. It is built entirely from scratch — it is *not* a Thunderbird or
Mailspring fork. On the surface it looks and behaves like the mail clients
you already know: a four-pane mailbox, unified inbox across accounts,
compose with undo-send and send-later, search, contacts, attachments, rules,
and multiple accounts. Underneath, it quietly does the security work most
clients skip: every SMTP, IMAP, and POP3 connection is captured at the
protocol layer, scored by deterministic rules, and recorded as tamper-evident
evidence."

## 3. What KIWI serves (45s)

"KIWI serves three audiences at once:

- **The everyday user**, who gets a polished, complete mail client — four-pane
  shell, quick filters, snooze, templates, drag-to-folder, three themes —
  with honest security indicators instead of scareware.
- **The security-conscious professional**, who gets deterministic transport
  evidence for every session: TLS version, cipher suite, key exchange,
  forward secrecy, certificate chain, and STARTTLS behavior — captured, not
  inferred — plus SPF, DKIM, and DMARC verification with fail-closed DNS.
- **The organization**, which gets an admin plane: orgs, domains, users,
  roles, recipient-domain policies, and mail-flow metadata — never message
  bodies — with its own audit trail."

## 4. How KIWI is different (60s)

"Four things make KIWI different from every other mail client:

1. **Deterministic evidence, not vibes.** Every connection produces a
   `TlsObservation` — real TLS facts captured at the protocol layer. A
   rule engine (`kiwi-forensics`) turns session evidence into findings.
   No invented findings, no score without a rule behind it.

2. **The lock is real.** Suspicious session signals feed a trust engine.
   When trust drops far enough, the endpoint locks — and the Rust IPC layer
   enforces it across the *entire* command surface, not just a UI overlay.
   A compromised renderer cannot bypass it.

3. **Tamper-evident audit.** Every mutation lands in a hash-chained
   `audit.jsonl` — each record carries the hash of the previous one,
   genesis-verified on open. Corruption surfaces as `audit-corrupt` in the
   UI instead of being hidden.

4. **Fail closed over fabricate.** Absent data renders absent. A missing
   backend disables the action and says so. No placeholder signatures, no
   fabricated green checkmarks — ever.

And one more principle: **AI explains, but never asserts.** AI sits behind an
abstraction layer — it may explain a finding in plain language, but it never
decides a verdict, never asserts trust, and never authors a status. The
deterministic rule engine is the only authority."

## 5. The security chain in action (30s)

"Here's what happens when you click a link in KIWI:
**stamps → hints → click-gate → sandbox → evidence.**

Risk and authentication stamps are attached to each message at ingest. When
you click, the gate returns a verdict — allow, confirm, sandbox, or deny.
Risky links open inside a disposable WSL2 guest that is torn down before the
session is even recorded. Re-opening a link re-checks the source risk, so the
gate can't be bypassed. And every step lands in the audit chain as
reproducible evidence. Forensics reports export as canonical bytes wrapped in
a self-verifying SHA-256 envelope — you can prove the report wasn't altered
after the fact."

## 6. Tech stack & the tech behind it (60–75s)

"KIWI is a **Tauri 2** desktop app — a Rust host with a webview renderer.

**Frontend:** React 18 + TypeScript + Vite — and it's *untrusted by design*.
The webview is treated as a trust boundary: every typed `kiwi_*` IPC command
validates its input, runs the lock gate, and writes audit evidence.

**Backend:** a Rust 2024-edition workspace of ten crates:

- `kiwi-mail` — the mail engine: real SMTP, IMAP, and POP3 clients, MIME
  parsing, a SQLite local-first store with FTS5 full-text search, rules,
  mbox import/export, risk and auth stamps, and TLS transport capture.
- `kiwi-core` — security session model, trust state machine, device
  identity, policy types.
- `kiwi-pair` — canonical device-pairing authority: tickets, challenges,
  device registration and revocation, trust-on-first-use evidence.
- `kiwi-forensics` — PCAP ingest and stream reassembly, deterministic
  analyzers, scoring, and self-verifying report exports.
- `kiwi-mailauth` — SPF, DKIM, and DMARC over a bounded, fail-closed DNS
  resolver (Hickory in production, mock in tests).
- `kiwi-sandbox` — disposable WSL2 guest execution.
- `kiwi-integrations` — opt-in external services like temp-mail and
  deliverability testing, all behind a consent boundary.
- `kiwi-autoconfig` — account auto-discovery and OAuth2.
- `kiwi-contacts` — vCard contacts and address book.
- `kiwi-app/src-tauri` — the app binary owning ~25 IPC command modules, the
  audit chain, syncer, and notifications.

**Sidecars:** `kiwi-admin` — a Node/TypeScript org plane with Drizzle ORM
and PostgreSQL — a React admin UI, and a React Native authenticator app for
QR-paired device approvals.

**Secrets** never touch disk in plaintext — credentials live in the OS
credential store, and `unsafe_code` is forbidden workspace-wide.

**Dev infra:** Docker Compose runs local mail servers — mailpit for SMTP/POP3,
GreenMail for IMAP — so the whole system is testable end-to-end on one
machine. CI mirrors every gate: cargo test, clippy, fmt, TypeScript
typecheck, vitest, and a zero-dependency CDP smoke suite that drives the real
rendered DOM."

## 7. Close (15s)

"KIWI doesn't ask you to trust it — it shows you the evidence. A real mail
client for daily use, a security platform underneath, and every claim backed
by deterministic, tamper-evident proof. **Email that proves its security.**"

---

## Appendix — quick facts for Q&A

| Question | Answer |
|---|---|
| License | MPL-2.0 |
| Status | Alpha, unsigned builds (exe ~30MB, NSIS ~7.3MB, MSI ~10.7MB) |
| Desktop stack | Tauri 2 · Rust (edition 2024, unsafe forbidden) · React 18 + TS + Vite |
| Local store | SQLite (`mail.db`) with FTS5; bodies/attachments on disk |
| Protocols | Real SMTP, IMAP (IDLE/poll), POP3 (UIDL) — no mock shims |
| Auth checks | SPF / DKIM / DMARC, bounded fail-closed DNS |
| Sandbox | Disposable WSL2 guest, HTTP(S)-only, teardown-before-record |
| Audit | Hash-chained JSONL, genesis-verified, corruption → `audit-corrupt` |
| Secrets | OS credential store only; zeroized in-memory types |
| Org plane | Node + Drizzle + PostgreSQL (`kiwi-admin`), localhost admin UI |
| Mobile | React Native authenticator scaffold (fail-closed) |
| Test mail | mailpit (SMTP :1025, POP3 :1100, UI :8025), GreenMail IMAP :1143 |
| AI role | Explanation only — never decides verdicts or asserts trust |
