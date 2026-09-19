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

