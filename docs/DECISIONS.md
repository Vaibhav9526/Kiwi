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

## ADR-010 — External mail-service integrations behind `kiwi-integrations` (ADR-009 justification)

- **Date:** 2026-09-25 · **Status:** proposed → Lead review · **By:** Agent 11 (T-226)
- **Need / problem solved:** Two features on the roadmap require third-party mail services: (a) a disposable inbox for throwaway/outbound self-tests, (b) an independent deliverability/spam verdict on KIWI's own outbound mail (the security mission includes SPF/DKIM/DMARC outcomes observed by a real receiver — `kiwi-mailauth` verifies what *we* receive; it cannot tell us what a receiver thinks of what we *send*).
- **Why not simpler alternatives:** Deterministic local scoring already exists (kiwi-mailauth T-122) but cannot observe receiver-side placement — that is only measurable by an external sink. GuerrillaMail is the standard no-auth disposable-inbox API; email-spam-tester needs no API key and returns per-check RFC-cited evidence rather than a bare score. Both are read-only against APIs; the real action (sending the message) stays in `kiwi-mail` under existing policy.
- **Decision:** New crate `kiwi-integrations`: two traits (`TempMailProvider`, `DeliverabilityTester`) over one `HttpClient` seam; impls `GuerrillaMail` + `EmailSpamTester`; `reqwest` (`rustls` feature → rustls + platform verifier) as the HTTP stack — first crate in the workspace to need an HTTP client. Full contract: `docs/contracts/integrations.md`.
- **Security implications (load-bearing):** HTTPS-only (constructor + transport double-check), redirects never followed, response bodies capped mid-stream, all secrets (PHPSESSID, `sid_token`, test slug — a capability secret) in memory only and redacted from Debug/errors, transport errors stripped of URLs. Temp inboxes are PUBLIC (contract §3.0) — UI must disclose via `PUBLIC_INBOX_NOTICE`; fetched bodies are provider-pre-filtered and synthesized into RFC822 — render via the sanitized path only. Opt-in per-run is the caller's duty; the crate never initiates sends.
- **Perf/resource cost:** negligible — idle structs, a handful of small HTTPS calls per user-initiated action; GM rate limits push polling ≥10 s (contract §3.5).
- **Testing strategy:** recorded-fixture only — `ScriptedHttp` replays transcript steps and asserts request shape; 30 tests, zero live calls. New external dependency surface: `reqwest`+`hyper-rustls`+`rustls-platform-verifier` (lockfile-pinned; `cargo audit` re-run is Agent 6's gate per SECURITY.md §7).
- **Consequences:** kiwi-app can wire temp-inbox + deliverability-test IPC behind these traits without touching HTTP details. Any further third-party mail service lands here behind a trait — never ad-hoc `reqwest` calls elsewhere.

## ADR-011 — Integrations IPC surface: notice-on-every-response + backend-enforced consent

- **Date:** 2026-09-25 · **Status:** proposed → Lead review · **By:** Agent 11 (T-227)
- **Need / problem solved:** kiwi-integrations (ADR-010) had no IPC path. The webview is untrusted (SECURITY.md B2), so two properties must hold that a UI flag cannot provide: (a) the public-inbox disclosure cannot be dropped or drifted by a view, and (b) deliverability's consent cannot be skipped by a renderer calling `send` directly.
- **Decision:** Nine `kiwi_integrations_*` commands, all behind the lock gate (ipc.md §9e). **Temp mail:** one in-memory GuerrillaMail session in `AppState`; every response — create/poll/fetch/discard/extend — carries `publicInboxNotice` verbatim so the flag is structural, not convention. `fetch` never returns raw MIME: synthesized RFC822 is parsed in-process and the HTML runs through the same `sanitize_html` allowlist as `kiwi_render_body` with remote resources ALWAYS off (public inbox ⇒ tracking surface). **Deliverability:** `begin` mints an opaque `testId` + a single-use CSPRNG `consentToken`; `send` must present it — compared and consumed atomically under the sessions lock before enqueue, so consent is a capability the backend verifies, not a UI boolean. Recipient fields in the passed message are ignored; the only recipient is the reserved single-use address. Sends ride the normal outbox (undo-send grace applies, `send-queued` audited). Provider slug stays in `AppState` memory — never serialized to IPC.
- **Why not simpler alternatives:** A `consentRequired: true` flag on `begin` is UI-trust — the renderer could call `send` anyway; the token makes consent an enforced precondition. Per-call provider construction over a shared injected `HttpClient` keeps the seam testable (`ScriptedHttp` injection via `open_test_with_http`) without wiring network into state.
- **Security implications:** session secrets in-memory only, dropped with the session/`Discard`; audit records `testId`+address only, never slug/token; `consent-required` gives one code for missing/wrong/consumed (no validity oracle); `rate-limited`/`integration-error` added to §11; transport errors keep the no-URL rule from integrations.md §1. `MailError::InvalidInput` arm added to the IPC error map (kiwi-mail grew the variant mid-task).
- **Perf/resource cost:** negligible — a bounded session map (32) and one optional provider struct; single-shot polls, UI owns loops.
- **Testing strategy:** `cargo test -p kiwi-app` — 59 tests incl. 7 new: full temp-mail lifecycle with notice assertions + sanitized fetch (script/remote-img stripped), deliverability begin→send→status→report over scripted fixtures, consent replay refused, recipients forced to the reservation, `not-found`/`locked` gates. Zero live calls.
- **Consequences:** Agent 12's UI can drive both tools via typed `ipc.ts` wrappers; any future integration lands behind the same shape (notice field for disclosure-bearing responses, capability token for destructive outbound steps).

## ADR-012 — Forensics serde vocabulary: FSV-1

- **Date:** 2026-09-25 · **Status:** accepted (T-238) · **By:** Lead
- **Context:** Contract-drift audit FOR-1/FOR-2 found 19+ divergent enum spellings. `Report::to_json` emits derived Serde tags (`tls12`, `start_tls`, `x_o_auth2`, `triple_des`) while `forensics.md` describes mixed semantic `as_str()` forms (`tls1.2`, `starttls`, `xoauth2`, `3des`). `TlsVersion::Unknown(u16)` is externally tagged as `{"unknown":N}`, not the contract's bare string. The Tauri session-view vocabulary (`tls1.3`, `xoauth2`, `hostname-mismatch`) is a separate projection boundary.
- **Decision:** FSV-1 is the canonical **forensics serde vocabulary**: lower `snake_case` enum variant names; unit variants are JSON strings; data-bearing variants use Serde's externally tagged object form and retain payloads. `EvidenceValue` remains internally tagged with `type` and snake_case variants. `as_str()` is not changed: it remains semantic/display vocabulary for evidence text, policy references, and stable finding/subject keys. A lossy legacy reader may accept the bare-string `unknown` input, but it must not invent the missing raw value. Forensics report enum tags and core/Tauri session-view vocabulary remain explicitly mapped rather than silently shared.
- **Migration:** preserve original stored-report bytes; version the wire change (`kiwi.forensics/2` or an explicit wire-schema version); use dual-read/single-write during the compatibility window; update `forensics.md` and embedded-forensics IPC examples atomically. Unknown future enum variants remain a separate forward-compatibility gate (FOR-6); `#[serde(other)]` is not a blanket solution for newtype/struct variants.
- **Consequences:** the current Serde output becomes the canonical report wire, eliminating per-enum spelling drift while preserving raw `TlsVersion::Unknown` payloads. A code owner must add compatibility tests, migrate consumers, and update contracts before treating the change as implemented; this ADR does not itself change source code.


## ADR-012 — Plugin alpha = trusted-code model (owner amendment)

Sideload-only plugins v1 declare capabilities via manifest but run as **trusted code** — sandbox/isolation enforcement deferred to post-alpha. Risk accepted by owner directive; A25 records the threat-model entry + follow-up hardening task.
