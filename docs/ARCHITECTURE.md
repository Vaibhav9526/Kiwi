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

## 5. Thunderbird source map (task T-007, initial pass)

Checkout: `source/` = mozilla-firefox/firefox @ `b16f852ba6` (main, depth-1),
`source/comm/` = thunderbird/thunderbird-desktop (main, depth-1).

**Key structural finding:** modern Thunderbird has migrated SMTP and POP3 to
JavaScript ES modules; IMAP remains C++. This means the cheapest, safest KIWI
integration points are `.sys.mjs` files rather than protocol C++.

| Area | Path | Implementation | KIWI integration candidate |
|------|------|----------------|----------------------------|
| SMTP client | `comm/mailnews/compose/src/SmtpClient.sys.mjs` | JS, uses `TCPSocket(hostname, port, {useSecureTransport})`; STARTTLS via `_actionSTARTTLS` + `socket.upgradeToSecure()` | Observe/normalize connection security state after socket open/upgrade; `this._server.socketType`, `_secureTransport`, `_capabilities` |
| SMTP send | `comm/mailnews/compose/src/MessageSend.sys.mjs`, `nsMsgSendLater.cpp`, `SmtpServer.sys.mjs`, `SMTPProtocolHandler.sys.mjs` | JS | outbound policy hook (recipient-domain checks) pre-send |
| POP3 | `comm/mailnews/local/src/Pop3Client.sys.mjs`, `Pop3Service.sys.mjs`, `Pop3Channel.sys.mjs`, `Pop3IncomingServer.sys.mjs`, `nsPop3Sink.cpp` | JS client (TCPSocket; `STLS` cmd for STARTTLS) + C++ sink | same as SMTP: socket security observation |
| IMAP | `comm/mailnews/imap/src/nsImapProtocol.cpp`, `nsImapIncomingServer.cpp`, `nsImapService.cpp`, `nsImapServerResponseParser.cpp` | C++, owns `nsISocketTransport` | `m_socketTransport->GetSecurityInfo()` → `nsITransportSecurityInfo` (TLS version, cipher suite, cert chain, key exchange) |
| TLS/NSS | `security/manager/ssl/` (mozilla side), NSS in `security/nss/` | C++ | `nsITransportSecurityInfo`, `nsIX509Cert` — no second TLS stack; read NSS-negotiated params only |
| Accounts | `comm/mailnews/base/src/nsMsgAccount(Manager).cpp`, `MsgIncomingServer.sys.mjs`, `MsgProtocolInfo.sys.mjs` | C++ + JS | server prefs (`socketType`, auth method) feed SecuritySession |
| Auth | `comm/mailnews/base/src/MailAuthenticator.sys.mjs`, `nsMailAuthModule.cpp`, `MsgPasswordAuthModule.sys.mjs`, OAuth2 in `mailnews/base/src/OAuth2*` | JS + C++ | auth-mechanism classification (cleartext vs OAuth vs CRAM) |
| Compose UI | `comm/mail/components/compose/` | HTML/JS | recipient-domain policy warning surface (Agent 5 S-07) |
| Account setup | `comm/mail/components/accountcreation/` | JS | security status during account autoconfig |
| Main UI | `comm/mail/base/` (`chrome://messenger`) | XHTML/JS | security indicator + lock overlay anchors (Agent 5 spec) |
| Startup/lifecycle | `comm/mail/app/`, `all-thunderbird.js` | JS/prefs | KIWI module init point; lock check before mailbox access |
| Prefs | `mailnews/mailnews.js`, `comm/mail/app/all-thunderbird.js` | pref files | `mail.kiwi.*` pref namespace for feature flags |

**Rule for all agents:** edits to `source/`/`source/comm/` are Lead-gated.
Each integration point above needs an assigned task before any file is touched.
Refinement continues via `searchfox-cli` once bootstrap installs it.

## 6. Build & toolchain (current status)

- Host: Windows, `D:\` drive, ~203 GB free at Phase 0 start.
- VS Build Tools 2022 (17.14) present.
- MozillaBuild: install in progress → `C:\mozilla-build`.
- Firefox source: `git clone --depth 1` into `source/` — in progress.
- Thunderbird source: to be cloned into `source/comm/` after base lands.
- `mozconfig` will contain `ac_add_options --enable-project=comm/mail`.
- Build: `./mach bootstrap` (option 2) then `./mach build` inside
  `C:\mozilla-build\start-shell.bat` environment.
