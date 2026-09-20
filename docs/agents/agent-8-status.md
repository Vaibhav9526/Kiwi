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

## 2026-09-20 — T-135 `kiwi-autoconfig` tests + contract (open → done)

Status: done. `cargo test -p kiwi-autoconfig`: **53/53 green, fully
offline** (all network via `MockNet`). `cargo clippy -p
kiwi-autoconfig --all-targets`: clean (one `single_char_add_str` in
test fixed). Note: earlier in this session my truncated edit left
stray tokens + an unclosed test module; Lead fixed the compile breaks —
this session only touched test code and docs, no non-test behavior
changed. One transient build failure was `kiwi-mail` mid-edit by Agent
7 (`mime.rs`/`store.rs`); resolved once they landed.

Files changed:
- `kiwi-autoconfig/src/lib.rs` — tests: `DomainName::parse`
  normalization/bounds (63/64-char labels, hyphen/underscore rules),
  `split_email` accept/reject matrix (local-part charset, `@`-not-
  allowed-in-local, length limits), `CONTRACT_VERSION` stability.
- `kiwi-autoconfig/src/autoconfig_xml.rs` — fixed truncated test
  module (unclosed braces); tests: full clientConfig fixture parse,
  domain exact-vs-order selection, socketType/authKind mapping, IMAP-
  TLS ranking + port defaults, %EMAILADDRESS%/%EMAILLOCALPART%
  substitution, OAuth2→XOAuth2, DOCTYPE/XXE + unknown-entity +
  deep-nesting + mismatched-tag + overlong rejection, entity/CDATA
  decode, non-clientConfig root, unsupported-server skip.
- `kiwi-autoconfig/src/ispdb.rs` — tests: `lookup_in` exact/
  parent-domain/case, Google fixture end-to-end (hosts/ports/auth/
  username), unknown-domain miss, fixture-table wellformedness sweep,
  custom-table override (bundled table has no `example.test` overlap).
- `kiwi-autoconfig/src/heuristics.rs` — tests: `sorted_mx`
  determinism, Google + M365 MX hints, label-boundary suffix rule
  (`notgoogle.com` ≠ `google.com`), generic pattern guess flagging,
  no-MX path, invalid email → None, custom hints table.
- `kiwi-autoconfig/src/manual.rs` — tests: `blank()` placeholders,
  invalid-email no-panic, `with_incoming`/`with_outgoing` edits,
  custom username trim, whitespace-host rejection,
  `from_suggestion` round-trip.
- `kiwi-autoconfig/src/net.rs` — tests: empty default, configured
  records (host normalization via `DomainName`), invalid MX host
  rejected, `MAX_CANDIDATES` cap.
- `kiwi-autoconfig/src/discovery.rs` — tests: deterministic URL
  construction, ISPDB short-circuit (1 attempt, no network), stage
  precedence (autoconfig_host > well_known > mx), full fallthrough
  evidence trail (ispdb miss → 2× unreachable → mx miss → flagged
  pattern guess hit), malformed-document-as-outcome, custom table
  override, invalid-email-only error, `to_mail_account()` mapping
  (protocol/host/port/credential keys), same-input determinism,
  wire spellings.
- `docs/contracts/autoconfig.md` (new — contract `kiwi.autoconfig/1`:
  invariants, stage order, wire spellings, parser rules, output
  shape, network seam, test coverage).

Behavioral facts confirmed by tests (no code change needed):
- `generic_guess` is total over valid emails, so stage 5 (manual) is
  defense-in-depth; a bare fallback ends in a **flagged pattern
  guess**, not Manual. Documented in contract §3.
- ISPDB `lookup_in` suffix match is label-boundary exact-parent only.
- `MAX_EMAIL_LEN` is 256, `MAX_XML_LEN` is 256 KiB, `MAX_CANDIDATES`
  is 16 (contract written to these values).

Risks/notes:
- Stage outcomes `unreachable` vs `miss` distinction for empty-vs-
  failed fetches rests on `MockNet` returning `None` for both; the
  live adapter must preserve this (None = unreachable).
- T-156 (setup wizard) can consume `discover()` + `attempts` as-is;
  `needs_manual_review` is the only gating flag the UI needs.

## 2026-09-20 — T-135 gate flag from Agent 6 cleared

Gate report: "missing impl-close brace + cargo fmt drift". Findings:

- **Missing impl-close brace: not reproducible** — `cargo clippy -p
  kiwi-autoconfig --all-targets` clean and `cargo test`: 53/53 compile
  + pass; a missing brace cannot compile. Most likely a stale gate
  scan (pre-Lead-fix snapshot) or mid-edit race with concurrent
  agents. No source change needed.
- **fmt drift: real, fixed** — `cargo fmt -p kiwi-autoconfig -- --check`
  reported over-width `AuthRef` constructor lines in `suggest.rs`
  (file predates my test work; my modules were already clean). Ran
  `cargo fmt -p kiwi-autoconfig`: reformatted `suggest.rs` (+ minor
  line breaks across the crate); zero behavior change.

Post-fix verification (all green):
- `cargo clippy -p kiwi-autoconfig --all-targets` → clean
- `cargo fmt -p kiwi-autoconfig -- --check` → clean
- `cargo test -p kiwi-autoconfig` → 53 passed / 0 failed

Deliverables unchanged and standing: test suite (53) +
`docs/contracts/autoconfig.md` (`kiwi.autoconfig/1`) + TASKS.md T-135
marked done. Ready for Lead merge.


## 2026-09-20 - T-158 + T-159 done

**T-158 - Autoconfig contract completion (done)**

- `docs/contracts/autoconfig.md` bumped draft -> final (T-135, T-158).
- Added section 3.1: the IPC envelope `DiscoveryOutcome { email, domain,
  source, needs_manual_review, suggestion, attempts[] }` with the
  consumer rules (attempts = audit trail; needs_manual_review is a hard
  gate - pattern guesses and manual fallback must not be persisted
  without user consent). This was the missing piece for IPC consumers.
- Section 8 now enumerates the T-158 test additions by name:
  discovery-order fallthroughs (ISPDB short-circuit, autoconfig_host >
  well_known > mx, pattern-guess-flagged), malformed-XML-as-stage-
  outcome, and domain/email validation edge cases.
- `cargo test -p kiwi-autoconfig`: 53/53 green (no source change needed;
  the requested tests already landed during T-135 hardening).

**T-159 - kiwi-mail FTS5 search module (done)**

- New `kiwi-mail/src/search.rs` (~630 lines), wired via `mod search` in
  `lib.rs`; `MailStore::migrate` calls `search::ensure_schema`.
- External-content FTS5 table `messages_fts` over `messages`
  (subject / from_addr / to_addrs / snippet as body proxy) with
  INSERT/UPDATE/DELETE sync triggers - no text duplication.
- Backfill: marker table `fts_state` + `INSERT INTO
  messages_fts(messages_fts) VALUES('rebuild')` when the index lags
  (idempotent; covered by a drop-and-rebuild test).
- Bounded query API for IPC: `MAX_RESULTS = 200`, `MAX_QUERY_TERMS = 8`,
  `limit.clamp(1, MAX_RESULTS)`. Grammar: plain terms, `from:` / `to:` /
  `subject:` / `body:` scopes, quoted phrases (`subject:"monthly
  report"`), `-term` negation (FTS5 NOT is binary-only, so negations
  chain off a positive anchor; negation-only queries return empty, not
  error). All user text embedded as quoted phrases with inner quotes
  doubled - no MATCH-injection surface (SECURITY.md rule 9).
- Public surface: `search_messages(&MailStore, query, folder_id,
  limit)` + `MailStore::search(...)` wrapper returning `Vec<MessageMeta>`,
  newest first; `folder_id: None` searches all folders.
- 9 tests: column scoping, AND semantics, negation, folder scope,
  ordering + limit cap, noise/empty queries, FTS triggers on
  move/delete, backfill idempotency, parser/builder unit cases.
- Gates: `cargo test -p kiwi-mail` 77/77, clippy --all-targets clean,
  fmt --check clean.

TASKS.md: T-158, T-159 marked done. Handoff note for Agent 5 (T-160):
search UI should call `MailStore::search` via IPC; result shape is
`MessageMeta` (same struct as mailbox listing), so existing IPC
serialization can be reused; surface `-term` / `scope:` grammar hints
in the UI.
