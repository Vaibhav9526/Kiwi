# KIWI — Architecture

> Owner: Lead Agent (Agent 1, Devin SWE-2). Status: Phase 0 — standalone pivot.
> Master prompt: `prompt.md` (repo root). **Superseded note:** prompt.md §1–2
> (modify Thunderbird) is replaced by the owner directive — KIWI is a
> **completely independent email client built from scratch** (ADR-005).
> Thunderbird = workflow/UX reference; Mailspring = productivity-feature
> reference. Everything else in prompt.md still applies.

## 1. System overview

**Product identity (owner-confirmed):** KIWI = full-featured desktop mail
client + security platform in one. Mailspring-grade UI polish, MailFlow-complete
feature set (via MPL-clean adaptation), and the security spine nobody else
ships — deterministic transport evidence, endpoint trust + native lock,
independent authenticator, PCAP forensics, org policy, tamper-evident audit.
Working tagline: *"Email that proves its security"* — every claim is
evidence-backed; AI explains but never asserts.

**Positioning guardrail (applies to every spec and surface):** feature parity
never compromises the deterministic-security rules — no remote lookups without
explicit opt-in, no plaintext secrets, `unsafe_code` stays forbidden, and every
surface honors the lock state. Copy language is evidence-first: findings cite
evidence, no fear-mongering, degradation states are described honestly.

KIWI is a security-first desktop email platform: a native mail client
(SMTP/IMAP/POP3, inbox, folders, compose, search, contacts, attachments,
account management) plus a serious security platform: deterministic transport
security analysis, endpoint trust + lock state, SecureMail identity, mobile
authenticator, PCAP forensics, org/policy control plane, tamper-evident audit.

```
+--------------------------------- kiwi-app (Tauri 2) ---------------------------------+
|  React+TS frontend (webview)  <— IPC (typed commands/events) —>  Rust core (src-tauri)|
+------------------------------------------|--------------------------------------------+
                                             |
        +----------------+-----------------+----------------+------------------+
        |                |                                   |                 |
   kiwi-mail (Rust)  kiwi-core (Rust)                  kiwi-forensics      kiwi-admin
   SMTP/IMAP/POP3    session security model            (Rust)              (Node/TS)
   account/sync/     endpoint trust + lock state       PCAP ingest/parse   org/policy/RBAC
   mail storage      SecureMail identity/sessions      TLS/cert/cipher     mail-flow metadata
   TLS observation   device registration               rules + scoring     audit log
        |                |                                   |                 |
        +----------------+--------- SQLite (local-first) ----+-----------------+
        |
  mobile authenticator (React Native) — asymmetric challenge-response pairing
        |
  kiwi-admin-ui (React + TS, localhost only) — Phase 6+
```

## 2. Repository layout (this checkout)

| Path | Contents | Owner |
|------|----------|-------|
| `prompt.md` | Original master prompt (§1–2 superseded by pivot) | Lead |
| `images/` | Supplied KIWI brand assets — do NOT overwrite | Agent 5 (read-only for all) |
| `source/` → `D:\kiwi-src` | Thunderbird/Firefox checkout — **READ-ONLY REFERENCE**, never shipped | Lead |
| `kiwi-app/` | Tauri 2 app: `src-tauri/` Rust backend + React/TS frontend | Lead + Agent 5 |
| `kiwi-mail/` | Rust: SMTP/IMAP/POP3 clients, TLS observation, account model, mail store, sync | Agent 2 |
| `kiwi-core/` | Rust: session security model, trust engine, identity, device, policy | Agent 2 |
| `kiwi-forensics/` | Rust: PCAP engine, analyzers, deterministic scoring | Agent 3 |
| `kiwi-admin/` | Node/TS: org/policy service, mail-flow metadata, audit log | Agent 4 |
| `kiwi-admin-ui/` | React+TS local admin UI (Phase 6+) | Agent 4 + Agent 5 |
| `mobile/` | React Native authenticator (Phase 4+) | TBD by Lead |
| `docs/` | Source-of-truth documentation | Lead owns; per-file owners in TASKS.md |
| `docs/contracts/` | Stable internal API/interface contracts | Lead + owning agent |
| `docs/agents/` | Per-agent briefs and status files | Each agent writes own status file only |
| `tests/` | Shared test fixtures + tools | Agent 6 |
| `artifacts/` | Logs/build artifacts (gitignored) | Lead |
| `Cargo.toml` (root) | Cargo workspace: kiwi-mail, kiwi-core, kiwi-forensics, kiwi-app/src-tauri | Lead |

**Hard boundary:** `source/` (Thunderbird) is reference-only — copy nothing
that isn't clean-room compatible (MPL: study patterns, write our own code).
Each agent works only in its directories (prompt.md §8 applies).

## 3. Module boundaries & responsibilities

- **kiwi-mail** — the mail engine. Native protocol clients:
  - `smtp` — send client: EHLO/STARTTLS upgrade, AUTH (PLAIN/LOGIN/XOAUTH2/
    CRAM-MD5), MAIL/RCPT/DATA, pipelining, size limits.
  - `imap` — receive client: capabilities, LOGIN/AUTHENTICATE, SELECT,
    FETCH (envelope/flags/body-structure/UID), IDLE, folder ops.
  - `pop3` — USER/PASS or APOP, LIST/UIDL/RETR/DELE, STLS.
  - `transport` — TCP + `rustls` TLS with **full negotiated-parameter
    capture** (TLS version, cipher suite, key-exchange group, ALPN, peer
    cert chain) — this is where every `SecuritySession` observation begins.
  - `account` — account model (SMTP+IMAP/POP3 creds, OAuth2 tokens),
    per-account folders.
  - `store` — local mail storage (SQLite: messages metadata, bodies,
    attachments on disk; per-account namespaces).
  - `sync` — folder sync engine, incremental via UIDVALIDITY/UIDs.
  - `mime` — MIME build/parse (mail-parser for inbound; own builder for
    outbound).
- **kiwi-core** — unchanged: `SecuritySession` model, trust state machine
  (trusted→degraded→locked), device registration/revocation, SecureMail
  identity/sessions/recovery, lock policy.
- **kiwi-forensics** — unchanged: PCAP ingest, TCP reassembly, protocol
  reconstruction, TLS/cert/cipher rules, deterministic scoring, reports.
  Now also consumes live `SecuritySession` events from kiwi-mail.
- **kiwi-admin** — unchanged: orgs/domains/users/roles/devices, recipient
  policies, mail-flow metadata (no bodies), hash-chained audit log, RBAC,
  SQLite behind repository interfaces.
- **kiwi-app** — Tauri shell. `src-tauri/` exposes typed IPC commands that
  delegate to kiwi-mail/kiwi-core/kiwi-forensics/kiwi-admin; frontend is
  React+TS (Vite). No business logic in the frontend beyond UI state.
- **mobile authenticator** — Phase 4: keypair in platform keystore, QR/local
  pairing, challenge-response bound to device+session+event, replay
  protection, revocation.
- **AI layer (optional)** — explanation/correlation only behind an
  abstraction; never authoritative (SECURITY.md).

## 4. Productivity features (Mailspring-inspired, native KIWI)

Selected for implementation (assigned in TASKS.md):

- Unified inbox across accounts
- Snooze / send-later scheduling
- Undo send (delayed send queue)
- Message templates/snippets
- (deferred: read receipts/tracking — privacy-sensitive, needs owner sign-off)

## 5. Thunderbird/Mailspring reference map

Study `source/comm/` (Thunderbird) and Mailspring for behavior only:

| Capability | Reference | KIWI equivalent |
|------------|-----------|-----------------|
| SMTP client state machine | `comm/mailnews/compose/src/SmtpClient.sys.mjs` | `kiwi-mail::smtp` |
| POP3 client | `comm/mailnews/local/src/Pop3Client.sys.mjs` | `kiwi-mail::pop3` |
| IMAP protocol | `comm/mailnews/imap/src/` (C++) | `kiwi-mail::imap` |
| Account/server model | `MsgIncomingServer.sys.mjs`, `nsMsgAccount*` | `kiwi-mail::account` |
| Mailbox UI patterns | `comm/mail/base/` | `kiwi-app` frontend |
| Compose UX | `comm/mail/components/compose/` | `kiwi-app` composer |
| Productivity features | Mailspring (snooze/send-later/undo/templates) | `kiwi-mail` + `kiwi-app` |

## 6. Build & toolchain (current status)

- Host: Windows, `D:\` drive. Rust 1.98, Node 25, Python 3.14 present.
- Cargo workspace at root: `kiwi-mail`, `kiwi-core`, `kiwi-forensics`,
  (later `kiwi-app/src-tauri`).
- `kiwi-admin`: npm/TypeScript; `kiwi-app` frontend: Vite + React + TS.
- Thunderbird build toolchain (MozillaBuild) no longer needed — kept
  installed harmlessly; `D:\kiwi-src` retained as reference only.

## 7. Infrastructure layer (ADR-006/007/008 — owner directive 2026-09-20)

Added before further feature development:

- **Databases** — Drizzle ORM (TypeScript layer). PostgreSQL for
  service/organization data (kiwi-admin); SQLite for local desktop state,
  cache, prefs, temporary forensic data. All access behind repository
  interfaces; migrations via Drizzle Kit; no plaintext secrets in either DB
  (device-local secrets go to OS credential storage — Windows Credential
  Manager/DPAPI). Rust crates keep rusqlite internally (kiwi-mail store) —
  Drizzle governs the TS-facing persistence.
- **Docker Compose** — reproducible local infra: PostgreSQL, kiwi-admin,
  dev/test mail server. Health checks, persistent volumes, `.env.example`,
  documented start/stop. The Tauri desktop app always runs natively — never
  containerized. No Kubernetes.
- **Sandbox** — disposable VM boundary (Firecracker where practical,
  QEMU/KVM + prepared snapshot otherwise) for any active analysis of
  untrusted attachments/documents/links. Prebuilt base image + snapshot/
  revert; isolated FS, controlled egress, no host creds/keys/mailbox,
  resource+time limits, proc/FS/network monitoring, auto-teardown.
  Docker is infra, not the hostile-code boundary.
- **Dependency rule (ADR-009)** — any new infra component requires a written
  justification: need, alternatives, security, cost, testing strategy.

### Execution order (owner directive)

1. PG + Drizzle schema/migrations → 2. SQLite + Drizzle local layer →
3. docker-compose for local infra → 4. interfaces between desktop,
   services, DBs → 5. sandbox technology evaluation (host-OS-dependent) →
6. sandbox base-image/snapshot strategy → 7. basic connectivity/migration/
   health/sandbox-lifecycle tests → 8. document decisions → 9. feature work
   proceeds on verified foundations. Unavailable components are isolated
   behind interfaces — never block unrelated work.
