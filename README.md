<p align="center">
  <img src="images/banner.png" alt="KIWI — security-first email" width="720" />
</p>

<h1 align="center">KIWI</h1>

<p align="center">
  <strong>A security-first desktop email client.</strong><br/>
  Real mail — SMTP, IMAP, POP3 — with deterministic transport-security analysis,<br/>
  endpoint trust, forensic evidence, and organization controls built in.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-early%20development-orange" alt="status" />
  <img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="license" />
  <img src="https://img.shields.io/badge/platform-Windows%20first-lightgrey" alt="platform" />
  <img src="https://img.shields.io/badge/tests-189%20passing-brightgreen" alt="tests" />
</p>

---

## What is KIWI?

KIWI is an independent desktop email client built from scratch — not a fork of
Thunderbird or Mailspring. It behaves like a normal, full-featured mail client
(inbox, folders, unified view, compose, search, contacts, attachments,
multi-account) while quietly doing security work most clients skip: every
connection is inspected, scored deterministically, and recorded as evidence.

The security platform is native — not a plugin, not a wrapper:

- **Transport security analysis** — TLS version, cipher suite, key exchange,
  forward secrecy, certificate chain, STARTTLS behavior on every SMTP/IMAP/POP3
  connection, captured at the protocol layer.
- **Deterministic risk scoring** — evidence-backed findings from a rule engine.
  No invented findings; every issue carries reproducible evidence.
- **Endpoint trust & lock state** — measurable suspicious-session indicators
  feed a trust engine; when trust drops far enough, KIWI locks natively and
  requires re-authentication.
- **Independent authenticator** — asymmetric challenge-response pairing with a
  mobile device; replay-protected, revocable.
- **Forensic analysis** — passive `.pcap`/`.pcapng` ingest, stream
  reconstruction, TLS evidence extraction, weakness → evidence → impact →
  remediation → re-scan/diff reports.
- **Organization controls** — recipient-domain policy enforcement, mail-flow
  metadata audit (never message bodies), tamper-evident audit logs, RBAC.
- **Domain authentication** — SPF / DKIM / DMARC verification on received mail.
- **AI-assisted explanations** — optional, local or API-backed, always grounded
  in structured findings. AI is never the security authority.

Everything runs **local-first**: SQLite storage, local services, no required
cloud.

## Architecture

```
kiwi-app        Tauri 2 desktop shell — React/TS frontend ←→ Rust core (IPC)
 ├─ kiwi-mail        SMTP / IMAP / POP3 clients, rustls transport with
 │                   full TLS-parameter capture, accounts, store, sync, MIME
 ├─ kiwi-core        session security model, trust/lock state, SecureMail
 │                   identity, device registration
 ├─ kiwi-forensics   PCAP ingest + live-session analyzers, deterministic
 │                   rule engine + scoring, evidence/report pipeline
 ├─ kiwi-mailauth    SPF / DKIM / DMARC (offline-testable DNS)
 └─ kiwi-admin       org / policy / RBAC / mail-flow / audit (Node/TS, localhost)
mobile              React Native authenticator (pairing, challenge-response)
```

## Tech stack

| Layer | Technology |
|-------|-----------|
| Desktop shell | Tauri 2 |
| Frontend | React 18 + TypeScript + Vite |
| Mail engine / security core / forensics | Rust (tokio, rustls, rusqlite) — `unsafe` forbidden |
| Admin control plane | Node.js + TypeScript |
| Storage | SQLite (local-first; PostgreSQL-compatible interfaces) |
| Mobile authenticator | React Native (Phase 4) |

## Repository layout

```
kiwi-app/          Tauri app (src-tauri/ backend + src/ frontend)
kiwi-mail/         mail protocol engine
kiwi-core/         security/trust/identity model
kiwi-forensics/    PCAP + live-session security analysis
kiwi-mailauth/     SPF/DKIM/DMARC verification
kiwi-admin/        organization/policy/audit service
tests/             fixtures, transcript corpus, secret-scan tooling
docs/              architecture, contracts, roadmap, threat model, task ledger
docs/agents/       per-agent briefs and status logs
images/            KIWI brand assets (do not overwrite)
source/            Thunderbird checkout — read-only UX/protocol reference
```

## Development

Prerequisites: Rust stable, Node.js ≥ 20, Python 3 (test tooling).

```bash
# Rust workspace — all crates
cargo test --workspace

# Admin service
cd kiwi-admin && npm install && npm test

# Desktop app (dev)
cd kiwi-app && npm install && npm run tauri dev
```

Quality gates: `cargo clippy --workspace -D warnings`, `cargo fmt --check`,
`python tests/tools/secret_scan.py`. See `docs/TESTING.md`.

## Documentation

| Doc | Contents |
|-----|----------|
| `docs/ARCHITECTURE.md` | system design, module boundaries, ownership |
| `docs/SECURITY.md` | secure coding rules, secrets policy |
| `docs/THREAT-MODEL.md` | attacker capabilities, trust boundaries |
| `docs/API_CONTRACTS.md` + `docs/contracts/` | stable internal interfaces |
| `docs/ROADMAP.md` | phased plan |
| `docs/TASKS.md` | task ledger with owners and status |
| `docs/DECISIONS.md` | architecture decision records |
| `docs/TESTING.md` | test strategy and evidence requirements |

## Security principles

Deterministic rules are authoritative for technical findings. AI explains —
it never decides. Secrets are never logged. Security findings must have
reproducible evidence and a test. Endpoint protection means measurable
indicators and trust reduction, not claims of perfect compromise detection.

<p align="center">
  <img src="images/logo.png" alt="KIWI logo" width="96" />
</p>

<p align="center"><sub>MPL-2.0 · Built as a real product — correct architecture over volume.</sub></p>
