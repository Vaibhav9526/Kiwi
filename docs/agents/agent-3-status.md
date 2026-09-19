# Agent 3 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-19 — T-003 (initial scaffold entry, kept for the record)

Read first (per brief): `prompt.md` §2/§6/§10–§15, `docs/ARCHITECTURE.md`,
`docs/TASKS.md`, `docs/SECURITY.md`, `docs/agents/agent-3-brief.md`. No edits
made outside my assigned paths (`kiwi-forensics/`, `docs/contracts/forensics.md`
(not yet created), this status file).

## 2026-09-19 — T-003 — status: **in-progress**, model layer GREEN (36/36 tests, clippy + fmt clean)

### Verification evidence (reproducible)

```
cargo test --lib       -> test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured
cargo clippy --all-targets -> Finished (no warnings, no errors)
cargo fmt --check      -> clean (no diff)
```

Model layer (`src/model/`) is complete and compiles. `src/lib.rs` currently
declares only `pub mod model;`; the remaining six module declarations
(`analyzers`, `findings`, `pcap`, `report`, `rules`, `score`) are commented out
**as a deliberate gating mechanism with a comment in the file** so that the crate
always compiles for the layer that is complete. They are uncommented as each
module lands, and T-003 is only reported done when all six are present and
`cargo test`/`cargo clippy` are green over the whole crate.

### Two real defects found by running the tests (not assumed)

1. **Certificate expiry unit mismatch (fixed).** `CertThresholds`' warning window
   was expressed in seconds (2,592,000) but compared against a millisecond
   remainder (432,000,000 ms for a 5-day expiry), so `ExpiringSoon` was never
   emitted for a 30-day policy. Field renamed to `expiry_warning_ms` with the
   default `30 * 24 * 60 * 60 * 1000` and a comment recording the trap, since the
   field name now makes the unit unmissable.
2. **`AuthMechanism::from_token` rejected real capability syntax (fixed).**
   Servers advertise `AUTH=PLAIN` (IMAP `CAPABILITY`) rather than bare `PLAIN`, so
   the parser returned `Unknown` for genuine captures. It now tolerates the
   `AUTH=` prefix before matching.

A third failure was a test-helper defect, not a product defect: the test
CertificateInfo builder used `DistinguishedName::from_raw`, which by design does
not parse attributes, so the CN-fallback hostname path had no CN. Fixed in the
test helper (`dn()` sets CN explicitly, mirroring the documented "adapters
declare CN" contract).

### Files changed (exact)

```
kiwi-forensics/Cargo.toml
kiwi-forensics/src/lib.rs
kiwi-forensics/src/model/mod.rs
kiwi-forensics/src/model/protocol.rs
kiwi-forensics/src/model/cipher_table.rs
kiwi-forensics/src/model/tls.rs
kiwi-forensics/src/model/auth.rs
kiwi-forensics/src/model/cert.rs
docs/agents/agent-3-status.md
```

### Test inventory now green (36)

`protocol.rs` 3 · `mod.rs` 6 · `cipher_table.rs` 3 · `tls.rs` 6 ·
`auth.rs` 6 · `cert.rs` 12.

Coverage highlights required by `prompt.md` §13 for a security feature:
valid config, invalid config, weak config, missing config, malformed/hostile
input, downgrade/absence indicators, and certificate edge cases
(expired, not-yet-valid, expiring soon, self-issued, hostname mismatch,
weak key, deprecated signature, truncated chain, unvalidated trust).

### Deliverables landed at that point (verified on disk)

| File | Content |
|------|---------|
| `kiwi-forensics/Cargo.toml` | cargo lib, `edition = "2024"` (matches `kiwi-core`), `publish = false`, deps pinned: `serde 1.0.229` (derive) + `serde_json 1.0.151` only; `[lints.rust] unsafe_code = "forbid"`; dependency policy documented inline |
| `src/lib.rs` | module map; `CONTRACT_VERSION = "kiwi.forensics/1"`, `RULE_CATALOG_VERSION = 1`, `SCORING_MODEL_VERSION = "kiwi-score-1"`; non-test `deny(clippy::unwrap_used, expect_used, panic, indexing_slicing)` |
| `src/model/protocol.rs` | `Protocol`, port maps, RFC 8314 implicit-TLS ports, `TransportSecurity` (`Unknown` is **not** protected) — 3 tests |
| `src/model/mod.rs` | `SafeText` (bounded, control-char stripped), `Endpoint`, `PeerRole`, `SessionId`, `SourceRef` (chain of custody), `StartTlsObservation`, `ConnectionSecurityEvent` + builders — 6 tests |
| `src/model/cipher_table.rs` | 58 IANA cipher suites incl. NULL/EXPORT/anon/RC4/3DES/CBC-SHA1/TLS 1.3; sorted+unique invariant test — 3 tests |
| `src/model/tls.rs` | `TlsVersion` (+`Unknown(u16)`, `compare_to` → `Indeterminate`), `KeyExchange`, `BulkCipher`, `MacAlgorithm`, `CipherStrength::classify`, `CipherSuite::from_iana` |

### Commands run + results

```
cargo --version / rustc --version / cargo clippy --version
  -> cargo 1.98.1, rustc 1.98.1, clippy 0.1.98
cargo new --lib kiwi-forensics --vcs none --edition 2024   -> ok (run via cmd /c)
cargo add serde --features derive ; cargo add serde_json   -> serde 1.0.229, serde_json 1.0.151
cargo build                                                -> ok (scaffold only, 7.76s)
cargo check --all-targets                                  -> FAILS: E0583 x8 (analyzers, findings,
                                                              auth, cert, pcap, report, rules, score
                                                              not yet authored) + E0432 TlsObservation
```

### Not yet done (why: mid-authoring, no external blocker)

1. `model/tls.rs`: `TlsObservation` struct (declared in `mod.rs`, not yet written); `model/auth.rs`, `model/cert.rs`.
2. `findings/` (finding/evidence/severity/confidence/stable key + `RescanDiff`), `rules/` (trait + engine + policy + rule catalog), `score.rs`.
3. `analyzers/` (SMTP/IMAP/POP3 trace analyzers), `pcap/` (bounded `.pcap`/`.pcapng` readers + `CaptureSource` + marked Phase-5 reassembly interface), `report.rs`.
4. `docs/contracts/forensics.md` (finding/evidence/report contract + PCAP fixture plan for Agent 6 / T-012).
5. Green `cargo test`, `cargo clippy`, `cargo fmt --check` — required before reporting done.

### Assumptions / decisions sent to Lead for confirmation

1. **No X.509 validation in this crate.** Certificate metadata is adapter input
   (NSS via the Phase 2 integration layer, or the PCAP X.509 parser in Phase 5).
   Consequence: a capture-based report must never claim "chain verified";
   unverifiable facts become a report-level `Limitation`, never a finding.
2. **Type named `ConnectionSecurityEvent`**, deliberately distinct from
   kiwi-core's `SecuritySession`, to avoid duplicated security logic
   (`prompt.md` §15). A documented mapping adapter is required in both
   directions — to be specified in `docs/contracts/forensics.md`.
3. **Own bounded pcap/pcapng readers** instead of `pcap-file` / `etherparse` /
   `pcap` crates: `pcap` requires native libpcap (hostile on Windows CI),
   `etherparse` parses packet headers rather than capture files, and a
   hand-written reader with hard limits (file bytes, packet count, caplen,
   block size; reject `caplen > origlen`, reject non-4-byte-multiple block
   lengths) keeps zero native dependencies and zero `unsafe`. Cost: our own
   malformed-input tests, which are being written. Candidate ADR.

### Determinism guarantees (contract-level)

No system clock, no RNG, no floating point, no map-iteration order. Timestamps
and capture identity are **inputs**, so identical input yields identical
findings and identical scores (needed for the re-scan diff).

### Risks / notes

- T-003 must remain `in-progress`; my brief requires `cargo test` + `cargo clippy`
  green before completion, and the crate does not compile yet.
- Phase 0 tests use synthetic in-code bytes/traces, so T-003 is **not** blocked on
  T-012 fixture generation; the fixture catalog still gets published in
  `docs/contracts/forensics.md` for Agent 6 to own under `tests/fixtures/`.
- No secrets, no real mailbox data, no credentials anywhere in this crate.

