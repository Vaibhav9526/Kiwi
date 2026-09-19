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
