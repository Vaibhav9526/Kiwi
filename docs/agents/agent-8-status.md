# Agent 8 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-20 — T-122 `kiwi-mailauth` crate delivered (claimed → done)

Status: done (pending Lead merge of TASKS.md). `cargo test -p
kiwi-mailauth`: 26/26 green, offline. `cargo clippy -p kiwi-mailauth
--all-targets -- -D warnings`: clean. `cargo fmt -p kiwi-mailauth`:
clean. `unsafe_code = "forbid"` inherited via `[lints] workspace = true`.

Files changed:
- `kiwi-mailauth/Cargo.toml` (new crate; deps: serde/serde_json/
  thiserror/base64/sha2/rsa/ed25519-dalek/rand_core-test-only/
  hickory-resolver/tokio — all pinned in Cargo.lock)
- `kiwi-mailauth/src/lib.rs` (`DomainName`, org heuristic, `Error`,
  `CONTRACT_VERSION = "kiwi.mailauth/1"`)
- `kiwi-mailauth/src/dns.rs` (`DnsResolver` trait, `MockResolver`,
  `HickoryResolver::system()` live adapter)
- `kiwi-mailauth/src/spf.rs` (RFC 7208: all/include/a/mx/ip4/ip6/
  ptr-deprecated/exists/redirect/modifiers; ≤10 lookups, ≤2 void,
  recursion ≤5; full §7 macro expansion)
- `kiwi-mailauth/src/dkim.rs` (RFC 6376: tag-list, simple/relaxed
  canon, RSA-SHA256 + Ed25519 verify, `s._domainkey.d` fetch, `now_unix`
  expiry; RSA+Ed25519 round-trip tests)
- `kiwi-mailauth/src/dmarc.rs` (RFC 7489: record parse, strict/relaxed
  alignment, p/sp/pct, `sampled_out` evidence, org override)
- `Cargo.toml` (root workspace members += `kiwi-mailauth`)
- `docs/contracts/mailauth.md` (new — result schemas v1)
- `docs/agents/agent-8-status.md` (this entry)

Commands run: `cargo test -p kiwi-mailauth` (26 passed),
`cargo clippy -p kiwi-mailauth --all-targets -- -D warnings` (clean),
`cargo fmt -p kiwi-mailauth` (clean).

Assumptions/risks:
- Org-domain = last-two-labels heuristic (NOT the PSL); `co.uk`-style
  suffixes over-approximate. Documented in lib.rs + contract; exact
  deployments must pass `DmarcInput.org_override`. No PSL crate added
  (keeps deps minimal; can revisit if Lead wants `psl` dep).
- `rsa` warn: crate is vulnerable to Marvin timing attack
  (RUSTSEC-2023-0071) — verify-only use here (public-key ops), noted
  for Agent 6 review; alternatives (openssl) rejected (native dep).
- RSA test keygen uses a test-only xorshift RNG + 1024-bit keys
  (test-only, never shipped/trusted); Ed25519 tests use a fixed seed.
- `ptr` evaluated per RFC but flagged via `ptr_deprecated_used`.
- q= other than `dns/txt`, a= other than rsa-sha256/ed25519-sha256 →
  permerror (documented; no alternate query methods implemented).

Proposed fixtures for Agent 6 (`tests/fixtures/`, NOT written — Agent 6
territory): `messages/auth-spf-pass.eml`, `messages/auth-spf-fail.eml`,
`messages/auth-dkim-valid.eml` (+ corresponding `test._domainkey`
TXT), `messages/auth-dkim-tampered.eml`, `messages/auth-dmarc-
reject-aligned.eml`, `messages/auth-dmarc-reject-spoof.eml`,
`transcripts/auth-mixed-results.txt` (SPF pass/DKIM fail/DMARC fail
combo). Mock DNS builders in `dns::MockResolver` already cover all of
these; Agent 6 only needs to map `SpfOutput`/`DkimOutput`/`DmarcOutput`
to findings per contract §8.

