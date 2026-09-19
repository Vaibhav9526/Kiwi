# Agent 2 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-19 — T-002 in-progress → ready for review

**Status:** T-002 deliverables complete; awaiting Lead review/merge into ledger.

**Files changed (all inside my boundary):**
- `kiwi-core/Cargo.toml`, `kiwi-core/src/lib.rs` — crate scaffold (`cargo new --lib`, zero dependencies, edition 2024)
- `kiwi-core/src/session.rs` — normalized `SecuritySession` model (protocol, transport, TLS version, cipher suite, key-exchange group, cert-chain summary, auth mechanism, FS flag, provenance; `SCHEMA_VERSION = 1`)
- `kiwi-core/src/trust.rs` — `TrustMachine` state machine (`Trusted → Degraded → Locked`), `TrustSignal`/`TrustEvaluation`, deterministic `evaluate()`
- `kiwi-core/src/policy.rs` — `TrustPolicy` (thresholds, hard-lock set, min-TLS, unlock requirements) + `session_signals()` deterministic session→signal mapping
- `kiwi-core/src/device.rs` — `DeviceRegistry` (register/activate/suspend/revoke; revocation terminal)
- `kiwi-core/src/identity.rs` — `SecureMailAccount`, `SessionBook` (device-bound sessions, expiry, `revoke_all_for_device`)
- `kiwi-core/src/challenge.rs` — `ChallengeBook` (device+session+event+nonce+expiry binding, canonical signed bytes, single-use/replay rejection, `SignatureVerifier` trait seam — no accept-all impl in non-test code)
- `docs/contracts/security-session.md` — contract v1: full field table, trust eval inputs/outputs, lock-state semantics, challenge-binding rules, versioning rules
- `docs/agents/agent-2-status.md` — this entry

**Commands run:**
- `cargo new --lib kiwi-core --vcs none`
- `cargo test` — **32 passed, 0 failed**
- `cargo clippy -- -D warnings` — clean (fixed too-many-args via `ChallengeSpec`, collapsible-if)

**Test coverage (evidence):**
- Trust: clean→trusted, weak→degraded, low score→locked, hard-lock signal→locked regardless of score, locked never self-recovers, degraded auto-recovery, authenticator-required unlock, unlock→degraded when signals persist, unlock-when-unlocked error
- Challenge binding: valid verify, replay rejection, expiry, device/event binding mismatch, bad signature, unknown challenge, duplicate-nonce rejection at issue, canonical-bytes coverage
- Policy/session: plaintext, STARTTLS-offered-unused downgrade, deprecated TLS, min-TLS policy violation, hostname-mismatch hard lock, plaintext AUTH weak mechanism
- Device/identity: pending→active lifecycle, terminal revocation, device revocation kills sessions, session expiry/binding

**Assumptions:**
- `SignatureVerifier` is the intentional seam for Phase-4 authenticator crypto (Ed25519/ECDSA per `contracts/authenticator.md`, Lead-owned); test uses a `cfg(test)` double only
- Session→signal mapping kept minimal in `policy.rs`; deep weakness classification is kiwi-forensics' finding pipeline (boundary noted in contract §3)
- Persistence (SQLite, ADR-003) deferred — registries are in-memory behind future repository interfaces

**Risks / open items:**
- `seen_nonces` grows unbounded in-memory — needs persistence+expiry when storage lands
- `server_host` trust depends on TB hook supplying configured name, not banner/greeting
- Contract is draft until Lead review; Agent 3 should cross-check overlap with `contracts/forensics.md`
- No `source/` touched; Thunderbird hooks blocked on T-007 as expected


## 2026-09-19 — PIVOT acknowledged; T-101..T-106 complete → in-review

**Status:** kiwi-mail engine built out per brief v2. `cargo test -p kiwi-mail -p kiwi-core`: **62 passed, 0 failed** (30 mail + 32 core). `cargo clippy -p kiwi-mail -p kiwi-core -- -D warnings`: clean. `unsafe_code` remains forbidden workspace-wide (none written).

**Files changed (all in my boundary):**
- `kiwi-mail/src/transport.rs` — TCP+rustls client; `TlsObservation` (TLS version, cipher suite + IANA id, KEX group, ALPN, peer cert DER chain, STARTTLS flag, `CertVerdict`); `SocketSecurity` modes; `starttls_upgrade()`; `RecordingVerifier` wraps webpki to capture verdict while keeping strict-by-default validation; `accept_invalid_certs` is an explicit test-only hatch.
- `kiwi-mail/src/lines.rs` (new module) — bounded line/dot-block IO shared by protocols (16KB line cap, 64MB block cap).
- `kiwi-mail/src/smtp.rs` — EHLO/HELO + extension parse (STARTTLS/AUTH/SIZE), fail-closed `require_starttls`, re-EHLO post-upgrade (RFC 3207), AUTH PLAIN/LOGIN/XOAUTH2 (plaintext creds refused unless `allow_plaintext_auth`), MAIL/RCPT/DATA with dot-stuffing + SIZE check + per-recipient outcomes, RSET/NOOP/QUIT, `SendQueue` with undo-window + not_before (undo-send/send-later hooks). Envelope CRLF-injection validated.
- `kiwi-mail/src/imap.rs` — tagged-command client; `{n}` literal inlining; bounded S-expr parser; CAPABILITY/LOGIN/AUTHENTICATE(PLAIN,XOAUTH2; SASL-IR + continuation fallback)/SELECT/EXAMINE/LIST/CREATE/DELETE/RENAME/STATUS/FETCH/UID FETCH/UID STORE/UID SEARCH/UID COPY/UID MOVE(COPY+EXPUNGE fallback)/APPEND (LITERAL+ and sync-literal paths)/EXPUNGE/NOOP/LOGOUT/IDLE collect. STLS fail-closed.
- `kiwi-mail/src/pop3.rs` — greeting + APOP banner capture, CAPA, STLS (fail-closed), USER/PASS + APOP (MD5 — RFC 1939 legacy interop only), STAT/LIST/UIDL/RETR/TOP/DELE/RSET/NOOP/QUIT.
- `kiwi-mail/src/account.rs` — `MailAccount`/`ServerConfig`/`AuthRef` (credential keys, never secrets); `CredentialStore` trait + `MemoryCredentialStore` (marked test/dev-only).
- `kiwi-mail/src/store.rs` — SQLite schema v1 (`accounts`, `folders`, `messages`, `pop3_seen`; `user_version` migrations, FK on, parameterized queries) + write-then-rename body files + attachment dir; flag updates, UID sets, `uids_without_body`, UIDVALIDITY reset wipe.
- `kiwi-mail/src/sync.rs` — IMAP folder sync (UIDVALIDITY reset → wipe, UID SEARCH ALL diff, chunked UID FETCH metadata + flag refresh, expunge), `fetch_missing_bodies`, POP3 UIDL-diff ingest with leave-on-server default.
- `kiwi-mail/src/mime.rs` — `parse_message` via mail-parser (bounded typed summary: envelope, bodies, attachments, snippet); `build_message` native builder (CRLF, encoded-words, QP text, base64 attachments, multipart/alternative+mixed, header-injection sanitization, Bcc never emitted).
- `kiwi-mail/Cargo.toml` — new deps (justified below).

**New dependencies (each justified):**
- `x509-parser 0.17` — parse captured DER certs into `CertificateSummary` fields for the security contract (added; leaf-parse wiring is the next step — currently DER is captured raw).
- `sha2 0.10` — SHA-256 cert fingerprints.
- `zeroize 1` — secret material (`Zeroizing<String>`) for all password/token fields.
- `md5 0.8` — APOP only (RFC 1939 mandates MD5); no other use permitted.
- `time 0.3` — RFC 2822 Date header formatting for outbound builder.
(Lead's manifest already had tokio/tokio-rustls/rustls/webpki-roots/rusqlite/mail-parser/base64/serde/serde_json/thiserror/tracing/bytes/async-trait.)

**Test evidence:** scripted in-memory servers (`tokio::io::duplex`) for EHLO parse, STARTTLS fail-closed (SMTP), plaintext-auth refusal (SMTP+IMAP+POP3), dot-stuffing DATA flow w/ per-recipient reject, IMAP capability+SELECT+UID SEARCH, POP3 USER/PASS+LIST+RETR, APOP digest correctness; pure-parser tests for sexp/envelope/bodystructure/fetch-lines; store roundtrip incl. UIDVALIDITY wipe + expunge + flag update; MIME build→parse roundtrip + header-injection containment; send-queue undo/due semantics.

**Assumptions / open items:**
- `TlsObservation` → `SecuritySession` assembly (cert leaf parse via x509-parser into `CertificateSummary`) is the natural next step — observation struct holds raw DER today.
- No network tests yet (no real server); coordinate transcript fixtures with Agent 6 (T-114).
- IMAP `read_response_line` inlines literals up to 64MB; BODY[] fetch is one message at a time — streaming-to-disk fetch is a refinement for later.
- kiwi-core untouched this round; still green.

**Risks:**
- STARTTLS upgrade inside `duplex` tests isn't exercised end-to-end (needs a rustls test server + fixture CA — Agent 6's T-114 territory).
- POP3 `uid` in store uses message number (POP3 has no UIDs); dedup is UIDL-based as documented.
- APPEND sync-literal path sends `{n}` and relies on continuation callback — covered by code review, not yet by a transcript test.

## 2026-09-19 (2) — T-102 hardening: in-code transcript suite + real STARTTLS handshake

**Status:** smtp.rs state machine now exercised against in-code recorded transcripts (pending Agent 6's T-114 corpus). `cargo test -p kiwi-mail -p kiwi-core`: **73 passed, 0 failed** (41 mail + 32 core). `clippy -D warnings`: clean.

**Fixes found by the new tests:**
- `MAIL FROM` no longer appends `SIZE=n` unless the server advertised SIZE (RFC 1870 compliance).
- DATA terminator now sends bare `.\r\n` when the body already ends in CRLF (no spurious blank line).
- EHLO extension parsing deduplicated into `parse_ehlo_reply` (pre/post-STARTTLS now share it; first 250 line is greeting-only per RFC 5321 §4.1.1.1).

**New transcript tests (duplex-stream scripted servers):**
- greeting non-220 → `ServerReject`
- EHLO 500 → HELO fallback
- multiline reply code mismatch (250-…451) → protocol error
- AUTH LOGIN two-step challenge (asserts exact base64 lines)
- AUTH 535 → `MailError::Auth`
- all RCPTs rejected → DATA skipped, RSET issued, per-recipient list populated
- DATA command 554 → `ServerReject`
- message exceeding advertised SIZE → refused before MAIL FROM
- **STARTTLS end-to-end over real rustls**: in-process `TlsAcceptor` on the duplex peer + rcgen self-signed cert trusted via `extra_roots` → handshake succeeds, `TlsObservation.upgraded_via_starttls`, `cipher_suite`, peer chain, `CertVerdict::Valid` all asserted; AUTH PLAIN allowed post-upgrade
- CA-signed leaf with wrong hostname + trusted CA root → handshake completes under `accept_invalid_certs` but verdict records `CertVerdict::HostnameMismatch`
- same cert, strict settings → `MailError::Tls` (no silent acceptance)

**New dev-dependency:** `rcgen 0.13` (dev-only; generates fixture certs — chosen over 0.14 as the older stable line).

**Notes for Agent 6 (T-114):** the `serve()` helper pattern (expect-prefix → reply steps) and the rcgen `TlsAcceptor`-over-duplex recipe can be lifted directly into the shared transcript harness.

## 2026-09-20 — T-132 sandbox evaluation + design (owner priority, infra before features)

**Status:** DONE (design + contract + lifecycle PoC verified on this host). Branch release/v0.1.0. Note: ADR-008's open question was tagged "Agent 7" but the owner directive assigned T-132 to Agent 2 — flagging for Lead's ledger consistency.

**Deliverables:**
- `docs/sandbox.md` — design: measured host evaluation, option matrix, tier decision, prebuilt-base-image + snapshot/revert strategy, isolation table, monitoring outputs (proc/fs/net→PCAP for kiwi-forensics), degradation model, ADR-009 justification, build order.
- `docs/contracts/sandbox.md` — v1 contract: `SandboxProvider`/`Sandbox` trait shapes, `Availability::{Available,Degraded,Unavailable}`, `SandboxCapabilities`, `SandboxSpec`, bounded `AnalysisReport`, error taxonomy, 7 provider invariants, caller obligations (never host-execute on Unavailable).
- `tests/infra/check-sandbox-host.ps1` — read-only capability probe.
- `tests/infra/sandbox-wsl-poc.ps1` — lifecycle PoC, **PASS** on this host.

**Host evaluation (measured, honest):**
- Windows 11 **Home**; hypervisor running; `vmcompute` up, `vmms` absent (no Hyper-V role on Home — Hyper-V Manager path dead).
- `WinHvPlatform.dll` + `hvix64.exe` present → **QEMU/WHPX viable** (dedicated kernel, qcow2 overlay revert, `-object filter-dump` PCAP). QEMU binary absent — one-off provision needed; chose not to install system software without a provisioning decision.
- **Firecracker impossible**: KVM is Linux-only; `/dev/kvm` absent inside WSL2 (nested virt off). Documented as Linux-host tier only.
- **WSL2 tier works today** — real hypervisor boundary vs host; documented shared-kernel caveat (all distros share the utility-VM kernel → kernel escape lands in utility VM, can reach other WSL2 distros' FS — flagged `dedicated_kernel: false` in capabilities).

**PoC evidence (WSL2 lifecycle):** docker-export busybox → bake `/etc/wsl.conf` (automount+interop off) into rootfs → `wsl --import` → analyze (verified `/mnt` shows only `wsl`,`wslg` internals — **no host drives**) → revert (marker file gone after re-import) → teardown (`--unregister`, VHDX destroyed). Key design note proven: policy must be baked into the base image, not mutated at runtime (in-guest wsl.conf write + restart did NOT take reliably).

**Degradation:** interface reports `Unavailable(reason)`; no host fallback path exists by design (invariant, not just a default).

**Risks/open:**
- QEMU/WHPX provider needs QEMU binaries provisioned (portable build suffices; decision deferred to Lead/owner).
- WSL2 egress control is weakest link (no per-distro net toggle; `unshare -rn` or host firewall — provider reports `egress_control: None` honestly).
- `kiwi-sandbox` crate (trait + Wsl2Provider + NullProvider) is the natural next implementation step; T-114 transcripts can capture the qemu-img/qemu-system command lines once QEMU lands.
- Resuming kiwi-mail T-103..T-106 follow-up hardening after this.
