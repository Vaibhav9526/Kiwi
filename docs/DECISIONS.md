# KIWI — Architecture Decision Records

> Owner: Lead Agent. Append-only; new ADRs at the bottom.

## ADR-001 — Thunderbird acquisition: git clone of official mirrors

- **Date:** 2026-09-19 · **Status:** accepted · **By:** Lead
- **Context:** Workspace had no Thunderbird source. Official docs
  (developer.thunderbird.net) prescribe: `mozilla-firefox/firefox` checkout
  with `thunderbird/thunderbird-desktop` cloned inside as `comm/`, then
  `mozconfig` with `ac_add_options --enable-project=comm/mail`, `./mach
  bootstrap` (option 2), `./mach build`.
- **Decision:** Clone `firefox` with `--depth 1` into `source/` (speed/disk;
  can unshallow later if history is needed), then `thunderbird-desktop`
  `--depth 1` into `source/comm/`. `source/` is gitignored in the outer repo.
- **Consequences:** Phase 0 build is the critical path; all TB-integration
  work is blocked until it completes. ~30–40 GB disk for build; 203 GB free.

## ADR-002 — Standalone security services in Rust; admin service in Node/TS

- **Date:** 2026-09-19 · **Status:** accepted · **By:** Lead
- **Context:** Prompt allows Rust or Node/TS for local services; prefers Rust
  for long-lived security/forensics engines.
- **Decision:** `kiwi-core` (session/trust/identity) and `kiwi-forensics`
  (PCAP/rules) are Rust crates — memory safety for untrusted parsing.
  `kiwi-admin` (org/policy/API) is Node/TypeScript — faster iteration, pairs
  with React+TS admin UI.
- **Consequences:** Two toolchains (cargo + npm) — Agent 6 covers both in
  lint/test baseline.

## ADR-003 — Local data plane: SQLite behind repository interfaces

- **Date:** 2026-09-19 · **Status:** accepted · **By:** Lead
- **Decision:** One SQLite database file per service boundary
  (`kiwi-core.db`, `kiwi-forensics.db`, `kiwi-admin.db`) rather than a shared
  file — keeps service independence and lets Postgres adoption happen
  per-service. All persistence behind repository/DAO interfaces.
- **Consequences:** Cross-service queries go through service APIs, not joins.

## ADR-004 — Source checkout at `D:\kiwi-src` + directory junction

- **Date:** 2026-09-19 · **Status:** accepted · **By:** Lead
- **Context:** mach refuses to run in a checkout whose path contains a space
  (`build/mach_initialize.py::check_for_spaces`). The workspace path
  `D:\Hackathon\PROJECTS\Kiwi Mail` has a space and is fixed.
- **Decision:** Moved the checkout to `D:\kiwi-src` (space-free) and created
  an NTFS directory junction `D:\Hackathon\PROJECTS\Kiwi Mail\source` →
  `D:\kiwi-src` so the workspace layout in ARCHITECTURE.md still holds.
  All mach commands run against `D:\kiwi-src` (realpath).
  MozillaBuild shell invocation for builds:
  `C:\mozilla-build\msys2\usr\bin\bash.exe -lc` with env
  `MOZILLABUILD=C:\mozilla-build`, `HOME/USERPROFILE=C:\Users\VAIBHAV`,
  `PATH=/c/mozilla-build/python3:/c/mozilla-build/bin:$PATH`.
- **Consequences:** Build objdir lands in `D:\kiwi-src\obj-*`. `source/`
  stays gitignored in the project repo.

## ADR-005 — KIWI is a standalone client, not a Thunderbird fork (PIVOT)

- **Date:** 2026-09-19 · **Status:** accepted (supersedes parts of ADR-001/§ARCHITECTURE) · **By:** Lead, per owner directive
- **Context:** Owner directive replaced prompt.md §1–2: build KIWI as a
  completely independent email client from scratch. Do NOT fork or modify
  Thunderbird/Mailspring. Thunderbird = primary reference for mail workflows,
  UI patterns, expected functionality; Mailspring = source of selected
  productivity features (unified inbox, snooze, send later, undo send,
  templates). All security/privacy/auth/forensics/org-control features are
  native KIWI. Thunderbird build effort (T-001) abandoned; `D:\kiwi-src`
  checkout retained as read-only protocol/UX reference.
- **Decision:** Standalone app: **Tauri 2 shell** (Rust backend `src-tauri` +
  React/TypeScript webview frontend — matches ADR-002 stack). New crate
  `kiwi-mail` owns SMTP/IMAP/POP3 protocol clients + account/sync/storage —
  owning the transport gives KIWI first-class access to TLS/security params
  the security mission needs. Mail TLS via `rustls` (explicit config, full
  negotiated-param capture). `kiwi-core`, `kiwi-forensics`, `kiwi-admin`
  unchanged — already standalone.
- **Consequences:** No mach/MozillaBuild dependency; standard cargo+npm
  toolchain (all present). Phase 0 TB build exit criterion replaced by
  "kiwi-app shell runs + kiwi-mail connects to a test server".

## ADR-006 — Drizzle ORM as the database layer

- **Date:** 2026-09-20 · **Status:** accepted (owner directive) · **By:** Lead
- **Decision:** Drizzle ORM everywhere TypeScript touches a database:
  - **PostgreSQL + Drizzle ORM + Drizzle Kit** — persistent service/org data (kiwi-admin: orgs, users, roles, devices, policies, mail-flow, audit).
  - **SQLite + Drizzle ORM** — local desktop/offline state, cache, prefs, temporary forensic data.
  - All DB access behind repository/service interfaces — PG and SQLite are swappable behind business logic.
  - Typed schemas, migrations, relations, indexes, transactions, constraints.
  - **Never** store passwords, private keys, OAuth tokens, secrets as plaintext — OS secure credential/key storage (Windows DPAPI/Credential Manager) for device-local secrets.
- **Consequences:** kiwi-admin's existing sqlite-org driver gets re-expressed as Drizzle schema+migrations behind the existing repository interfaces. kiwi-mail's Rust store stays rusqlite (Rust, not TS — Drizzle applies to the TS layer; the mail store boundary stays internal to kiwi-mail).

## ADR-007 — Docker Compose for local infrastructure

- **Date:** 2026-09-20 · **Status:** accepted (owner directive) · **By:** Lead
- **Decision:** `docker-compose.yml` + Dockerfiles + `.env.example` for reproducible local infra: PostgreSQL, kiwi-admin service, dev/test mail server (mailpit), other supporting services as needed. Redis only if a concrete need appears (none today).
- **Constraint:** the KIWI desktop app (Tauri) runs natively on the host — NEVER in Docker. Docker is for services, not the client.
- **Required:** health checks, persistent dev volumes, documented start/stop. No Kubernetes, no cloud infra.
- **Security note:** Docker containers are NOT a hostile-code execution boundary — see ADR-008.

## ADR-008 — Disposable VM sandbox for hostile content

- **Date:** 2026-09-20 · **Status:** proposed → evaluation in progress (T-132) · **By:** Lead
- **Context:** KIWI must never execute untrusted attachments/documents/links on the host. Docker containers are explicitly NOT an adequate boundary.
- **Decision:** disposable sandbox via **Firecracker microVM where practical**; **QEMU/KVM with prepared snapshot** otherwise; native OS isolation only if it provides a real boundary. **Prebuilt base image + snapshot/revert** — never fresh VM per analysis.
- **Sandbox guarantees:** isolated FS, controlled egress, no host credentials, no KIWI private keys, no mailbox access, resource/time limits, process+FS+network monitoring, automatic teardown/revert.
- **Open question for T-132 (Agent 7):** Firecracker requires KVM (Linux-only). Windows dev host → likely QEMU/WHPX or Hyper-V, or Firecracker inside WSL2 with documented caveats. Evaluation must be honest about what boundary each option actually provides.
- **Fallback:** isolate the dependency behind an interface; development continues with the sandbox OFF and active analysis clearly marked unavailable (per owner rule: don't block unrelated dev).

## ADR-009 — Infrastructure decision rule

- **Date:** 2026-09-20 · **Status:** accepted (owner directive)
- Before adding any DB, Docker service, Redis, VM/sandbox component, or external service, the implementing agent must document in `docs/DECISIONS.md` or its status file: why required, problem solved, why a simpler alternative is insufficient, security implications, perf/resource cost, testing strategy. Prefer the simplest secure implementation.

## ADR-0xx — License boundary + notices (T-197)

- Repo ships MPL-2.0 (LICENSE file added; was missing — F3 fix).
- `reference/` (mailspring GPL-3.0, mailflow AGPL-3.0) is gitignored study-only;
  verified zero copied lines via 45-char overlap scan (audit
  license-secret-scan-1.md). The same scan is the merge gate for T-190/T-191.
- webpki-roots is CDLA-Permissive-2.0 (file-level copyleft, compatible) —
  recorded for future NOTICE sweep.
- gitleaks added to CI static-checks (was doc-only — F1 fix); Python
  secret_scan.py kept as fallback.
