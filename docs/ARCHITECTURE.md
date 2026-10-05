# KIWI — Architecture (as-built, release/v0.2.0)

> Owner: Lead Agent (Agent 1, Devin SWE-2). Status: Phase 2 — feature-complete standalone client.
> Master prompt: `prompt.md`. **Pivot (ADR-005):** KIWI is a completely
> independent email client built from scratch. Thunderbird = workflow/UX
> reference; Mailspring = productivity reference. Nothing is forked.

## 1. Product identity

KIWI = full-featured desktop mail client + security platform in one.
Mailspring-grade UI polish, Thunderbird-complete feature set, and the
security spine nobody else ships: deterministic transport evidence,
endpoint trust + native lock, independent authenticator, PCAP forensics,
org policy, tamper-evident audit.

Tagline: *"Email that proves its security"* — every claim is evidence-backed;
AI explains but never asserts. Fail-closed beats fabricated success on every
surface (absent data renders absent, never a fake green).

## 2. System overview

```
┌─────────────────────────── kiwi-app (Tauri 2) ────────────────────────────┐
│  React+TS frontend (webview)                                              │
│    views: mailbox compose contacts rules templates security-center        │
│           settings(9 tabs) setup integrations  + plugins (Worker-isolated)│
│          │                                                                │
│          │ IPC — typed commands/events, every data op lock-gated          │
│          ▼                                                                │
│  Rust host (src-tauri):  state.rs AppState · commands/* (~25 modules)     │
│    send/(enqueue+dispatch) · message/(render,update,delete,junk,snooze,   │
│    unsubscribe,attachment) · pair · folders · import/export (mbox) ·      │
│    security · rules · templates · contacts · storage · audit · notify ·   │
│    send_consent (native rfd at integration boundary) · pairing_listen     │
│    (dev-only LAN claim) · lock_matrix · e2e harness hooks                 │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ owns crates via typed calls
        ┌──────────┬───────────┼───────────┬──────────┬──────────┬──────────┐
        ▼          ▼           ▼           ▼          ▼          ▼          ▼
   kiwi-mail   kiwi-core   kiwi-pair   kiwi-     kiwi-      kiwi-       kiwi-
   SMTP·IMAP·  session     canonical  forensics mailauth   integrations sandbox
   POP3·mime·  security    pairing    PCAP+     SPF·DKIM·  temp-mail·   WSL2
   store·sync· model·trust engine     live sess DMARC      deliverab.   guest
   rules·FTS·  device reg  (SQLite)   scoring   Hickory    (consented)   exec
   mbox·search            authority            DNS resolver
        └──────────┴───────┴─────┴─────────┴────┴──────────┴──────────┘
                        SQLite (local-first, mail.db)
        ┌──────────────────────────────────────────────────────────┐
        ▼                                                          ▼
   mobile/ (RN authenticator — scaffold,               kiwi-admin (Node/TS+PG)
   contract-blocked pending R1-R8 ratification)        orgs·policies·mail-flow·audit
   kiwi-admin-ui (React, localhost)                    docker-compose infra
```

## 3. Crate map (workspace, edition 2024)

| Crate | Responsibility | Key modules |
|---|---|---|
| `kiwi-mail` | The mail engine — all protocols + storage + rules | `smtp/`, `imap/`, `pop3`, `mime`, `store/`(schema,queries,outbox,threads,diagnostics), `sync`, `rules/`, `search` (FTS5+operators), `mbox` (rd import+export shared), `linkrisk`, `attachrisk`, `authrisk`, `authstamp`, `category`, `unsub`, `threading`, `transport` (TLS capture), `testutil/` (loopback scripted servers) |
| `kiwi-core` | Security/session domain types | `SecuritySession` model, trust state machine, device identity, policy types |
| `kiwi-pair` | **Canonical device/pairing authority** (T-269) | Persistent `PairEngine`: tickets, challenges, devices, revocation — atomic consume, TOFU evidence, restart-surviving |
| `kiwi-forensics` | Deterministic reports | `pcap/` ingest+reassembly, `analyzers/`, `rules/`, `score`, `report/` (canonical bytes + self-verifying export envelope) |
| `kiwi-mailauth` | Mail authentication | SPF/DKIM/DMARC verification + `dns.rs` (HickoryResolver production + MockResolver tests, bounded fail-closed) |
| `kiwi-integrations` | External services (opt-in) | `tempmail/` (Guerrilla etc.), `deliverability/`, `http.rs` (bounded client), `secret.rs` — all behind consent boundary |
| `kiwi-autoconfig` | Account auto-discovery | ISPDB fixtures + MX hints, provider autoconfig |
| `kiwi-contacts` | Contact model | vCard import/export, address book |
| `kiwi-sandbox` | Disposable guest exec | WSL2 provider, teardown-before-record honest absence |
| `kiwi-app/src-tauri` | The app binary | `commands/` IPC surface, `state.rs`, `audit.rs` (hash-chained JSONL), `syncer.rs`, `notify.rs`, `pairing_listen.rs`, `send_consent.rs`, `observe.rs`, `e2e.rs` |

TS-facing sidecars: `kiwi-admin` (Node/Drizzle/PG — org plane),
`kiwi-admin-ui` (React localhost admin), `mobile/` (RN authenticator
scaffold), `kiwi-app/src` (the renderer).

## 4. IPC boundary (`src-tauri/src/commands/`)

Every renderer↔Rust call is a typed `kiwi_*` command registered in
`lib.rs`, governed by three cross-cutting rules:

- **Lock gate** — commands touching data require unlocked state;
  exemptions are explicit (`unlock_challenge`, pair flow, prefs subset).
  `lock_matrix.rs` (T-340) classifies the full surface.
- **Consent boundary** — `send_consent.rs`: native `rfd` dialog fires in
  the enqueue path only for integration-bound sends (deliverability/
  temp-mail) — the renderer→external-service boundary. Ordinary sends
  don't prompt (the user's Send click is the consent).
- **Audit** — mutations write to `audit.jsonl` (hash-chained, genesis-
  verified on open, re-anchored retention sweep, corruption surfaces as
  `audit-corrupt` → tri-state UI). Counts/ids only, never payloads.

Command families: `accounts`, `autoconfig`, `contacts`, `devices`,
`endpoint`, `export`/`import` (mbox), `folders` (local+IMAP CRUD by
origin), `integrations`, `link` (click-gate+sandbox), `message/*`
(render,update,delete,junk,snooze,unsubscribe,attachment), `oauth2`,
`pair` (§9d canonical + `kiwi_*` aliases), `prefs`, `rules`, `sandbox`,
`security` (sessions/findings/forensics export), `send/*` (enqueue,
dispatch, undo, reschedule), `storage` (stats+compact), `templates`.

Contract: `docs/contracts/ipc.md` is normative; view types in
`src-tauri/src/types/` serialize to camelCase; renderer parses via
`kiwi.ts` + `ipc.ts` wrappers (unknown fields → honest absent, never
crash).

## 5. Security chain

Message-link flow: **stamps → hints → click-gate → sandbox → evidence**

- `linkrisk`/`attachrisk`/`authrisk`/`authstamp` attach evidence at ingest
- `kiwi_link_click` → verdict allow|confirm|sandbox|deny
- `kiwi_open_external` re-checks source risk (no bypass)
- `kiwi-sandbox` opens HTTP(S)-only in the WSL2 guest; tears down before
  record → `kiwi_sandbox_sessions` reports honest `completed` rows
- Everything lands in the audit chain + per-message evidence

Lock state: `PairEngine` + endpoint trust drive a native lock; the IPC
layer enforces (T-340 matrix proves coverage). UI has a LockOverlay with
pairing-QR exemption.

## 6. Plugins (Worker-isolated, T-306)

Plugin entries run in `blob:` Web Workers (CSP `worker-src self blob:`
only — no `unsafe-eval`). Plugin context gets **no** DOM/localStorage/
cookies/`__TAURI__`; fetch inherits `connect-src`; dedicated per-session
ports replace the broadcast bus. Four capabilities have real bounded
whitelist sinks; executable deny-proofs in the Node `worker_threads`
harness (48/48). Install UX: sideload folder picker + validation +
capability badges.

## 7. Frontend (`kiwi-app/src`)

React 18 + TS + Vite. eM-Client-style four-pane shell (`chrome.tsx`):
folder tree + smart counts, tabbed+grouped message list (virtualized,
quick-filter chips, multi-select, drag→folder, ctx-menus incl. Copy-to),
thread-card reader (quote-collapse, in-reply-to jump, source view), agenda
rail + security strip (trust chip tri-state incl. audit-integrity).

Surfaces: compose (floating dock, templates, attachments w/ progress,
contact autocomplete, signatures, undo-send), contacts, rules, templates,
security-center (sessions/findings/audit log), integrations, settings
(9 tabs incl. About+Storage), unified inbox, folder mgmt, import/export,
device mgmt + real pairing QR. Themes: light/dark/high-contrast + sideload.
Zero-dep CDP smoke suite (`scripts/ui-smoke.mjs`) = 25+ real-DOM checks,
CI-wired.

## 8. Async/auxiliary surfaces

- **mobile/** — RN authenticator scaffold: keystore, protocol, QR,
  PairingScreen/PendingApprovals. **Fail-closed honest**:
  `UnavailableKeystore` rejects signing, `OfflineTransport` offline.
  Production blocked on contract rulings R1–R8 (`docs/proposals/
  t311-authenticator-rulings.md`).
- **kiwi-admin** — Node/Drizzle org plane: orgs/domains/users/roles,
  recipient-domain policies, mail-flow metadata (never bodies), audit.
  PG via docker-compose.
- **kiwi-admin-ui** — localhost React admin UI.
- **pairing_listen.rs** — dev-only bounded HTTP POST /pair behind
  `KIWI_PAIR_LISTEN`; production `wss://` pending R3.

## 9. Data flow (canonical paths)

- **Inbound:** IMAP IDLE/poll or POP3 UIDL → transport TLS capture →
  mime parse → store (bodies/attachments on disk, meta+FTS in SQLite) →
  risk stamps + auth stamps → rules apply → unread counts + notify
- **Outbound:** compose → enqueue (undo window, send-later schedule,
  consent boundary check) → outbox row (persisted, retry/held/lastError)
  → dispatch → SMTP wire (XOAUTH2/plain) → IMAP `\Sent` APPEND → audits
- **Security:** sessions→forensics report (canonical bytes) → self-
  verifying SHA-256 export envelope → Security Center
- **Pairing:** `pair_begin` (ticket+QR payload) → mobile scans → LAN/wss
  claim → `claim_ticket_and_register` (atomic) → device row + TOFU →
  challenges → lock/unlock

## 10. Toolchain & release

- Rust 1.98 workspace, Node 22/25, Python 3.14, Vite+React18, Tauri 2.
- Canonical build: `npm run tauri build` (local @tauri-apps/cli 2.11.4 —
  no global cargo-tauri). Verified artifacts: exe 30MB, NSIS 7.3MB, MSI
  10.7MB — unsigned (SmartScreen caveat in `docs/RELEASING.md`), no
  auto-update in alpha.
- Gates: `cargo test --workspace` · `clippy -D warnings` · `fmt --check`
  · `tsc --noEmit` · `vitest` · `vite build` · `npm run test:ui` (CDP
  smoke, CI job). CI = `.github/workflows/ci.yml` (rust+admin+mobile+app
  +statics+live-docker-infra+ui-smoke).
- Local mirror: `scripts/gates.{ps1,sh}` (T-344).

## 11. Hard boundaries

- `source/` (Thunderbird), `reference/` (Mailspring) — **reference only**,
  never shipped; copy-overlap CI gate enforces MPL-clean provenance.
- AI/LLM — explanation only behind an abstraction; never authoritative.
- No remote lookup without explicit opt-in; no plaintext secrets;
  `unsafe_code` forbidden; every surface honors lock state.

## 12. Reference map (study-don't-copy)

| Capability | Thunderbird | KIWI |
|---|---|---|
| SMTP client | `comm/mailnews/compose/src/SmtpClient.sys.mjs` | `kiwi-mail::smtp` |
| IMAP protocol | `comm/mailnews/imap/src/` | `kiwi-mail::imap` |
| POP3 client | `comm/mailnews/local/src/Pop3Client.sys.mjs` | `kiwi-mail::pop3` |
| Account model | `nsMsgAccount*` | `kiwi-mail::account` |
| Mailbox UI | `comm/mail/base/` | `kiwi-app` views |
| Productivity | Mailspring | native (rules/templates/snooze/undo/copy/dock) |
