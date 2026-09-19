# KIWI — Architecture

> Owner: Lead Agent (Agent 1, Devin SWE-2). Status: Phase 0 — initial draft.
> Master prompt: `prompt.md` (repo root). All agents must read it first.

## 1. System overview

KIWI is a security platform built **inside** a modified Thunderbird desktop client.
Thunderbird remains the mail client; KIWI adds a deterministic security engine,
a trusted-session/endpoint-trust layer, a forensics engine, an organization
control plane, a mobile authenticator, and an optional AI explanation layer.

```
+--------------------------- Thunderbird (modified source) ----------------------------+
|  mailnews (SMTP/IMAP/POP3)   NSS/TLS   cert handling   mail UI (chrome://messenger)  |
|        |                        |            |                    |                  |
|        +---- narrow hooks ------+------------+--------------------+                  |
|                          |                                                         |
|                 KIWI integration layer (JS/C++ shims in tree)                        |
+--------------------------|----------------------------------------------------------+
                           |  local IPC (named pipe / localhost socket, auth'd)
        +------------------+-------------------+----------------------+
        |                                      |                      |
  kiwi-core (Rust)                     kiwi-forensics (Rust)     kiwi-admin (Node/TS)
  session security model               PCAP ingest/parse         org/policy/RBAC
  endpoint trust + lock state          stream reassembly         mail-flow metadata
  SecureMail identity/sessions         TLS/cert/cipher rules     audit log (tamper-evident)
        |                                      |                      |
        +----------- SQLite (local-first) -----+----------------------+
        |
  mobile authenticator (React Native) — asymmetric challenge-response pairing
        |
  kiwi-admin-ui (React + TS, localhost only) — later phase
```

## 2. Repository layout (this checkout)

| Path | Contents | Owner |
|------|----------|-------|
| `prompt.md` | Master multi-agent build prompt | Lead |
| `images/` | Supplied KIWI brand assets (logo, favicon, banner) — do NOT overwrite | Agent 5 (read-only for all) |
| `source/` | Firefox base checkout (`mozilla-firefox/firefox`), gitignored | Lead |
| `source/comm/` | Thunderbird checkout (`thunderbird/thunderbird-desktop`) | Lead assigns integration points |
| `kiwi-core/` | Rust: session security model, trust engine, identity interfaces | Agent 2 |
| `kiwi-forensics/` | Rust: PCAP engine, protocol analyzers, deterministic scoring | Agent 3 |
| `kiwi-admin/` | Node/TS: org/policy service, mail-flow metadata, audit log | Agent 4 |
| `kiwi-admin-ui/` | React+TS local admin UI (Phase 6+) | Agent 4 + Agent 5 |
| `mobile/` | React Native authenticator (Phase 4+) | TBD by Lead |
| `docs/` | Source-of-truth documentation | Lead owns; per-file owners in TASKS.md |
| `docs/contracts/` | Stable internal API/interface contracts | Lead + owning agent |
| `docs/agents/` | Per-agent briefs and status files | Each agent writes own status file only |
| `tests/fixtures/` | Shared test fixtures (PCAP, certs, messages) | Agent 6 |

**Hard boundary:** no agent other than Lead may edit `source/` or `source/comm/`
until Lead publishes the integration-point map (task T-007) and explicitly
assigns a file/module. This prevents uncoordinated Thunderbird rewrites.

## 3. Module boundaries & responsibilities

- **Thunderbird integration layer (in `source/comm/`)** — narrowest-possible
  hooks: read negotiated TLS version, cipher suite, cert chain, auth mechanism
  from NSS/mailnews connection state; surface security status + lock state in
  UI. Never reimplements mail logic.
- **kiwi-core** — normalized `SecuritySession` model; deterministic trust
  evaluation; device registration/revocation; lock/unlock policy; SecureMail
  account/session model. No AV/EDR claims — measurable indicators only.
- **kiwi-forensics** — `.pcap/.pcapng` ingest (untrusted input!), TCP
  reassembly, SMTP/IMAP/POP3 reconstruction, TLS handshake metadata, cert/cipher/
  key-exchange analysis, forward-secrecy assessment, finding+evidence records,
  re-scan diffs. Works with zero AI.
- **kiwi-admin** — orgs, domains, users, roles, devices, policies (recipient
  domain allow/deny, min-TLS, attachment interfaces), mail-flow metadata (no
  message bodies by default), append-only audit log. SQLite now, Postgres-ready
  interfaces.
- **AI layer (optional)** — explanation/correlation/summarization only, behind an
  abstraction; never authoritative for findings (see SECURITY.md §AI).
- **mobile authenticator** — keypair in platform keystore, QR pairing,
  challenge-response bound to device+session+event, replay protection,
  revocation. Local pairing must work without push services.

## 4. Data plane

SQLite first (`kiwi.db`), one file per service boundary or shared file with
per-service schema namespaces — decided in DECISIONS.md ADR-003. All storage
access behind repository interfaces so Postgres can be substituted later.
No message bodies in admin/analytics stores by default.

## 5. Thunderbird source map — PENDING (task T-007)

Blocked on source checkout completing (clone in progress, see DECISIONS.md
ADR-001). Target areas to map once `source/comm/` lands:

- `comm/mailnews/compose/` — SMTP send path (`nsSmtpProtocol`, `nsSmtpService`)
- `comm/mailnews/imap/` — IMAP (`nsImapProtocol`, connection/security state)
- `comm/mailnews/local/` + `comm/mailnews/pop3/` (POP3 protocol objects)
- `comm/mailnews/base/` — server/account prefs, incoming server model
- `comm/mailnews/addrbook/`, `comm/mailnews/mime/` — contacts, rendering
- `comm/mail/components/compose/` — compose window UI
- `comm/mail/components/accountcreation/` — account setup wizard
- `comm/mail/base/` — main mail window, UI surfaces for security indicators
- `security/manager/ssl/` (mozilla side) — NSS integration, cert error paths
- `comm/mail/app/` — startup/profile/session lifecycle, `all-thunderbird.js` prefs

Each mapped path gets: file list, integration point candidates, risk notes,
and the owning agent assignment in TASKS.md before edits begin.

## 6. Build & toolchain (current status)

- Host: Windows, `D:\` drive, ~203 GB free at Phase 0 start.
- VS Build Tools 2022 (17.14) present.
- MozillaBuild: install in progress → `C:\mozilla-build`.
- Firefox source: `git clone --depth 1` into `source/` — in progress.
- Thunderbird source: to be cloned into `source/comm/` after base lands.
- `mozconfig` will contain `ac_add_options --enable-project=comm/mail`.
- Build: `./mach bootstrap` (option 2) then `./mach build` inside
  `C:\mozilla-build\start-shell.bat` environment.
