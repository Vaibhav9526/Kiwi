# Agent 10 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-02-15 — kiwi-mail hardening + live interop + T-142 store queue

**Status:** implemented + verified for `kiwi-mail`. `cargo test -p kiwi-mail`
→ **67/67 pass** (was 54 at baseline), `cargo clippy -p kiwi-mail
--all-targets -- -D warnings` clean, `cargo fmt -p kiwi-mail --check` clean.
**No commit** — Lead integrates.

### T-103/T-104 — IMAP + POP3 remaining hardening

- **Aggregate literal bound** (`imap.rs::read_response_line`): the 64 MiB cap
  previously applied per-literal only — a server could send N literals just
  under the cap and grow the response buffer without limit. Now
  `buf.len() + n + 2 > MAX_RESPONSE` fails BEFORE allocation, and the buffer
  itself is re-checked each loop.
- **Tagged-reply boundary** (`is_tagged`): `line.starts_with(tag)` accepted
  `A00010 OK …` as a reply to `A0001`. Now requires `tag + SP`.
- **Missing timeouts**: `await_tagged` (APPEND literal path) and the IDLE
  post-DONE drain had unbounded waits. Both now under `CMD_TIMEOUT`.
- **Greeting strictness**: was `contains(" OK")` — accepted `* BYE … OK` or
  junk lines containing the substring. Now parses `* <OK|PREAUTH>` token;
  `* BYE` → `ServerReject`.
- **SELECT strictness**: `EXISTS`/`RECENT` matched by `ends_with`, so an
  `OK` free-text ending in "EXISTS" would be misread. Now strict
  `<n> EXISTS|RECENT` two-token shape.
- **CRLF/CTL injection guards** on every interpolated argument: quoted args
  (mailbox names, LOGIN user/pass, LIST ref/pattern) reject all CTLs; bare
  args (UID sets, flags, ops, STATUS items) additionally reject
  whitespace/empty; free-form tails (SEARCH criteria, FETCH items) reject
  CTLs only. Same injection class as SMTP envelope validation.
- **APPEND sync-literal bug**: the non-LITERAL+ path built the literal via
  `command_cont`'s callback, and `write_line` appended a second CRLF — a
  phantom empty command line on the wire. Reworked: `send_tagged` →
  `await_continuation` → raw `write_all(message + CRLF)` → `await_tagged`.
- **`[CAPABILITY …]` in tagged replies** (RFC 5161): `capability()` now
  merges tokens from the tagged text — claimed by the old comment, never
  implemented.
- **Bounded collections**: untagged lines per command capped at 8192
  (`MAX_UNTAGGED`); IDLE events at 4096 (`MAX_IDLE_EVENTS`); unrecognized
  non-`*`/`+`/tagged lines now error instead of looping.
- **POP3** (`check_param`): added 0x7F rejection alongside existing
  CRLF/CTL checks. Reviewed greeting/CAPA/USER/PASS/APOP/STLS/LIST/UIDL/
  RETR/DELE — dot-block and `MAX_MESSAGE` bounds already sound.

### T-105 — mail store

- `SCHEMA_VERSION` 2 adds `outbox` (see T-142 below).
- `list_accounts()` / `delete_account()` — closes the gap Agent 7 flagged
  (`MailStore` had no account enumeration/removal). Delete cascades rows
  (FK) and removes `bodies/<fid>`/`attachments/<fid>` payload dirs.
- `delete_messages` / `clear_folder_messages` now remove on-disk
  payloads — expunges and UIDVALIDITY wipes previously left orphan
  `.eml`/attachment files.
- `open_memory()` roots payload dirs at a unique path per call — parallel
  tests in one process shared `kiwi-mail-test-{pid}` and raced deletes
  (this was making `account_folder_message_roundtrip` flaky once
  payload-cleanup tests landed).

### T-142 — send queue

Split discovered mid-task: Agent 7 landed the app-side outbox earlier
(`data_dir/outbox/<id>.{json,eml}` sidecars) and, concurrently with this
session, the store-level `outbox` table (`OutboxRow`, in-row MIME BLOB —
single atomic write) plus `SendQueue::cancel` semantics (recallable while
`now < undo_window_until OR now < not_before`) and `SendQueue::reschedule`.
My additions complete the engine surface:

- `SendQueue::pending()` iterator — closes the flagged gap that forced
  `outbox_meta` duplication in app state.
- `SendQueue::next_due_at()` — scheduler wake-up hint.
- `MailStore::outbox_due(now, limit)` — dispatchable sends after reload.
- `MailStore::outbox_next_due_at()` — earliest scheduled send.
- `list_accounts`/`delete_account` above (outbox rows cascade on account
  delete; in-row MIME means no orphaned files).

### Live interop (Docker Compose)

- `docker compose up -d mailpit greenmail` — both healthy. GreenMail IMAP
  is host **:1143** → container 3143 (compose mapping; the brief's ":3143"
  is the container port).
- `KIWI_MAILPIT=1 cargo test -p kiwi-mail roundtrip` → 6/6 pass:
  - `mailpit_smtp_pop3_roundtrip` — SMTP :1025 → POP3 :1100 `demo/demo`.
  - `greenmail_imap_append_fetch_roundtrip` (**new**) — IMAP :1143 LOGIN
    `demo/demo` (GreenMail auth disabled) → SELECT INBOX → APPEND →
    UID SEARCH → UID FETCH ENVELOPE verifies subject → flag `\Deleted` +
    EXPUNGE cleanup → LOGOUT.

### New tests (13 net: 54 → 67)

- imap: `tagged_match_requires_space`, `command_args_reject_ctl`,
  `connect_rejects_bye_greeting`, `connect_accepts_preauth`,
  `aggregate_literal_bound` (two 60/20 MiB literals over aggregate cap —
  rejected before 2nd alloc), `select_injection_rejected`.
- sync: `internal_date_parses` (INTERNALDATE → unix; space-padded day).
- store: `outbox_due_and_next_due`, `delete_account_cascades_and_cleans_payloads`,
  `delete_messages_removes_body_file`.
- testutil: `imap_append_sync_literal` (catches the phantom-CRLF bug via a
  trailing LOGOUT expectation), `greenmail_imap_append_fetch_roundtrip`.
- Fixed pre-existing clippy `--all-targets` errors in testutil.rs
  (`manual_split_once`, 8× `needless_borrow`) — were blocking `clippy -D
  warnings` on tests.

### Files changed

`kiwi-mail/src/imap.rs`, `pop3.rs`, `smtp.rs`, `store.rs`, `sync.rs`,
`testutil.rs`, `kiwi-mail/Cargo.toml` (time: +`formatting`/`macros`/`parsing`
for INTERNALDATE + mime Rfc2822 format; dropped unused `x509-parser`/`sha2`
— leaf-cert parse landed in `kiwi-app` `observe.rs`), this file.

### Commands run

```
cargo test -p kiwi-mail --offline                          → 67/67
cargo clippy -p kiwi-mail --all-targets --offline -D warnings → clean
cargo fmt -p kiwi-mail --check                             → clean
docker compose up -d mailpit greenmail                     → healthy
KIWI_MAILPIT=1 cargo test -p kiwi-mail --offline roundtrip → 6/6 (live)
```

### Assumptions

- GreenMail auth-disabled + `allow_plaintext_auth: true` is test-only —
  production default still refuses plaintext credentials.
- `time` features enabled are all already in the lockfile dep set
  (`deranged`/`num-conv`/`powerfmt`/`time-macros` present) — offline-safe.
- Outbox rows exist only while queued (terminal outcomes delete); MIME is
  in-row so no orphaned files — matches the concurrent Agent 7 design.

### Risks / open items

- **Concurrent edits**: Agent 7 (or Lead) was writing `store.rs`/`smtp.rs`
  mid-session (outbox table + `reschedule` landed between my read and
  write). All changes coexist and the suite is green, but Lead should
  confirm no interleaved intent was lost.
- Workspace `clippy --workspace -D warnings` is NOT clean — other agents'
  in-flight crates (kiwi-forensics, kiwi-autoconfig) have deny-lint
  errors; out of scope, left untouched.
- `INTERNALDATE` parse failures yield `date_unix: None` (absent fact, no
  guess) — UI should handle null dates.
- Docker stack left running (`kiwi-mailpit-1`, `kiwi-greenmail-1`).
- Not committed per instructions.

## 2026-02-15 — gate re-verification (Lead flag)

Re-ran `cargo clippy -p kiwi-mail --all-targets -- -D warnings` → clean and
`cargo fmt -p kiwi-mail --check` → clean after concurrent-agent churn; the
9 testutil lints were fixed in the entry above. `cargo test -p kiwi-mail`
still 67/67. No additional edits needed.

## 2026-02-15 — T-161: `kiwi-sandbox` crate (Sandbox trait + Wsl2Provider + NullProvider)

**Status:** implemented + verified. New workspace crate `kiwi-sandbox`
implementing `docs/contracts/sandbox.md` v1 against Agent 2's T-132 design
(`docs/sandbox.md`). `cargo test -p kiwi-sandbox` → **5/5 pass**,
`cargo clippy -p kiwi-sandbox --all-targets -- -D warnings` clean,
`cargo fmt --check` clean. **Live lifecycle test verified end-to-end** on
this host (`KIWI_SANDBOX_WSL=1`): docker-export busybox rootfs + baked
`etc/wsl.conf` → `wsl --import` → analyze (marker write detected via FS
diff, stdout captured) → revert (marker gone on re-import) → teardown
(distro absent from `wsl -l`). No commit — Lead integrates.

### Layout

- `src/lib.rs` — contract types (`Availability`, `SandboxCapabilities`,
  `EgressControl`, `Monitors`, `SandboxSpec`, `AnalysisReport`, `FsChange`,
  `ProcEvent`, `NetEvent`) + `SandboxProvider`/`Sandbox` async traits +
  report bounds (`MAX_REPORT_ENTRIES=4096`, `MAX_STDOUT_TAIL=64KiB`,
  `MAX_FINDINGS=256KiB`, artifact cap 64MiB).
- `src/error.rs` — `SandboxError` per contract §Errors (thiserror, same
  style as kiwi-mail).
- `src/null.rs` — `NullProvider`: always `Unavailable(reason)`; `create`
  errors. The honest "no sandbox" answer — no host fallback exists
  anywhere in the crate.
- `src/wsl2.rs` — `Wsl2Provider`/`Wsl2Sandbox`: the proven PoC lifecycle.

### Honest capability reporting (contract invariants honored)

- `dedicated_kernel: false` — shared WSL2 utility-VM kernel, the
  documented Tier-B caveat.
- `egress_control: Blocked` — payload always runs under `unshare -rn`
  (netns drop); if `unshare` is missing in the guest, `analyze` fails
  closed rather than run uncontrolled. `allow_egress: true` is **refused**
  at `create` (invariant 6) — no per-instance egress monitoring exists on
  this tier.
- `monitors`: `fs: true` (before/after `find` diff + guest `sha256sum` of
  created files, ≤256 hashed), `process`/`network: false` — no guest
  agent yet; nothing is faked.
- Reports bounded per invariant 5 (entry caps, string truncation, capped
  pipe capture — a flooding guest blocks on write until the watchdog
  kills it; bounded memory beats unbounded capture).
- Artifact enters read-only via `wsl -e` stdin pipe (invariant 1);
  `wsl.conf` baked in the base image disables automount+interop.
- `teardown` cannot fail open: unregister attempted unconditionally, VHDX
  dir removal tolerates NotFound (WSL removes it itself), Drop is the
  sync best-effort backstop.
- `wsl.exe` quirks handled: management commands emit UTF-16LE (decoded for
  errors), `-e` exec channel is raw bytes; 10s probe / 180s import /
  spec-timeout+15s watchdog bounds.

### Files changed (this task)

`kiwi-sandbox/{Cargo.toml,src/{lib,error,null,wsl2}.rs}` (new),
`Cargo.toml` (workspace member), this file.

### Commands run

```
cargo check/test/clippy -p kiwi-sandbox --offline          → clean
cargo fmt -p kiwi-sandbox --check                          → clean
KIWI_SANDBOX_WSL=1 cargo test -p kiwi-sandbox wsl2_full_lifecycle
    → 1/1 pass (7.5s; real WSL2 distro create/analyze/revert/teardown)
```

### Assumptions / gaps

- Base-image build (docker export + wsl.conf bake) lives in the test and
  PoC script for now — production recipe is design step 6 (versioned,
  hash-pinned rootfs) and out of scope here.
- Payload exec is `sh`-interpretation only (v1, no guest agent) —
  documented in module docs; a real agent lands with the base image.
- WSL2 tier reports `process: false` / `network: false` — honest until a
  guest agent (strace wrapper / PCAP path) ships.
- Cleaned up a leftover PoC distro (`kiwi-sbx-poc-25400`) from Agent 2's
  script run.
- Workspace `clippy --workspace` still fails in other agents' crates
  (kiwi-forensics etc.) — unchanged, out of scope.

## 2026-02-15 — T-168: sandbox guest agent (in-guest runner + report.json)

**Status:** implemented + live-verified. `cargo test -p kiwi-sandbox` →
5/5, clippy `-D warnings` clean, fmt clean. Live lifecycle run
(`KIWI_SANDBOX_WSL=1`) green end-to-end with real agent evidence.

### What landed

- `kiwi-sandbox/agent/kiwi-agent.sh` — busybox-`sh` guest agent, embedded
  via `include_str!`, copied into the distro at analyze-time (never baked
  into the base image). Runs the payload under probed `ulimit`s inside
  `unshare -rn` (netns drop — fail-closed if `unshare` missing, payload
  never executes), captures:
  - process tree: polled `ps -o pid,ppid,comm,args` snapshots, deduped
    (short-format `ps` fallback; poll-interval evasion documented)
  - fs changes: created/modified/deleted + `outside_workdir` flag +
    sha256 of created files (≤256 hashed)
  - network: egress deny-probe inside the netns (`nc` to 1.1.1.1:443 →
    `unreachable`) + outside-netns reachability as context + DNS probe.
    `attempts_observed` is honestly `[]` — nothing can egress inside a
    dropped netns; this tier has no per-packet logging.
  - `limits_applied` — which ulimits the kernel actually accepted
  - writes `kiwi.sandbox.report/1` JSON to guest-side `/kiwi-out/`
- Provider reads `report.json` back over the exec channel before
  teardown — **not** a guest-writable host mount (would violate
  invariant 1). Host-side parse is fully `serde(default)` + bounds —
  hostile/truncated JSON degrades to `incomplete`, never panics.
- Host-side FS-diff kept as fallback when no agent report exists.
- `AnalysisReport.egress: Option<EgressEvidence>` added to the contract
  (serde-default, backward compatible); `docs/contracts/sandbox.md`
  bumped to v1.1 with the full `report.json` schema table.
- Capability honesty: `monitors.process` + `monitors.network` now `true`
  — process = polled snapshots (evasion caveat in contract), network =
  structural enforcement + probe evidence, not packet logging.
- `.gitattributes` added (`*.sh eol=lf`) — CRLF breaks busybox `sh`
  parsing; provider also strips `\r\n` at send-time as belt & suspenders.
- Fixed during debug: `jesc` read `$1` while stdin was piped (empty
  stdout_tail); stale-pid reuse in awk proc emitter; sha256 parse
  fragility on double-space paths; `writes_outside_workdir` empty-var
  JSON break.

### Verified on this host (real run, not simulated)

`probe_inside_netns: unreachable` / `probe_outside_netns: reachable` —
WSL NAT is live but the payload's netns has no link: enforcement proven,
not claimed. `/marker` created-file evidence + sha256, payload chain
`unshare -rn timeout 60 sh /kiwi-artifact` visible in process tree,
`exit_code: 0`, `ulimit -p` honestly reported unsupported.

### Files changed (this task)

`kiwi-sandbox/agent/kiwi-agent.sh` (new), `kiwi-sandbox/src/{lib,wsl2}.rs`,
`docs/contracts/sandbox.md` (v1.1 schema), `.gitattributes` (new),
this file. No commit — Lead integrates.

### Assumptions / gaps

- `ps` polling can miss sub-200ms processes — stated in contract, not
  hidden.
- `nproc`/`ulimit -p` unsupported by busybox ash → noted, not applied.
- Payload exec remains `sh`-interpretation; a real guest binary agent
  (strace/net capture) is the QEMU-tier follow-up.
- Debug distro `kiwi-dbg` and all temp state cleaned up.

## 2026-02-15 — T-174: `kiwi-pair` crate (mobile-authenticator crypto)

**Status:** implemented + verified. `cargo test -p kiwi-pair` → **11/11**
pass, `cargo clippy -p kiwi-pair --all-targets -- -D warnings` clean,
`cargo fmt --check` clean. `#[forbid(unsafe_code)]` via workspace lints.
No commit — Lead integrates.

### Design

Desktop-side engine implementing `contracts/authenticator.md`. Reuses
kiwi-core as the semantic authority — `Challenge`/`ChallengeBook`/
`ChallengeEvent`/`ChallengeSpec`/`ChallengeError`/`SignatureVerifier`
are re-exported, never re-defined; canonical bytes come from a
rehydrated `ChallengeBook::issue`, so the §4.1 encoding can never drift
from kiwi-core (a fixed-vector test locks the byte layout anyway).
`contracts/pair.md` (new, v1 draft) documents the engine API + `pair.db`
schema — the part that differs from authenticator.md's wire contract.

### Layout

- `src/lib.rs` — `PairError` (thiserror; `ChallengeError` wrapped via
  manual `From` since kiwi-core's enum isn't `std::error::Error`) +
  re-exports.
- `src/crypto.rs` — `Ed25519Verifier` (byte-identical to kiwi-app's
  verifier, dalek v2), `algorithm_supported` (Ed25519-only, fail closed),
  `DeviceSigner` (deterministic test/mobile-parity helper — production
  signing stays in the phone keystore), `device_fingerprint`
  (SHA-256[..16] → `XXXX-XXXX`×8 uppercase hex), `os_nonce` (getrandom).
- `src/store.rs` — `PairStore` SQLite (`pair.db`, kiwi-mail pattern):
  devices / pairing_tickets / challenges / nonces tables. Atomic
  single-use consume via `UPDATE … WHERE consumed=0 [RETURNING]` —
  double-use impossible even racing. Nonce ledger: 1h retention + 4096
  cap; challenges capped 4096.
- `src/engine.rs` — `PairEngine`: tickets (issue/consume/QR JSON),
  device register/suspend/revoke/list/fingerprint, challenge
  issue/verify with the contract's exact verify ordering
  (exists → not-revoked → unexpired → unconsumed → binding → Ed25519 →
  consume), device-pairing success auto-activates.

### Deterministic evidence (fixed vectors, no OS entropy)

- RFC 8032 §7.1 Test 1 vector — keypair gen + sign + verify + tamper/malformed rejection
- `device_fingerprint([0;32])` = `6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20`
- canonical-bytes locked layout (94-byte fixed challenge)
- QR payload exact-match JSON string
- ticket lifecycle: single-use, expiry, charset, PK-collision on re-issue
- verify ordering: every `ChallengeError` name exercised; failed verify never consumes; replay → `AlreadyConsumed`; nonce reuse at issue → `ReplayDetected`
- status gates: pending→pairing-only, active→all events, revoked→nothing; revoke terminal + idempotent + `revoked_unix` recorded

### Files changed

`kiwi-pair/{Cargo.toml,src/{lib,crypto,engine,store}.rs,tests/pair_tests.rs}`
(new), `Cargo.toml` (member), `docs/contracts/pair.md` (new), this file.

### Assumptions / gaps

- ed25519-dalek v2 pinned (matches kiwi-app verifier; mailauth uses v3 —
  noted in workspace manifest comment, unifying is a Lead decision).
- Re-revoke returns `Ok` (idempotent) — documented in pair.md; kiwi-core's
  `RevokedIsTerminal` still guards transitions *out* of revoked.
- Pairing transport + kiwi-app IPC wiring are Phase 4 / T-120 — out of
  scope; the engine is the deterministic core those wire into.

## 2026-02-15 — T-180: Phase C1 split of kiwi-mail (dir-per-domain)

**FREEZE NOTICE for Lead:** kiwi-mail/src is being split — please route
kiwi-mail edits through Agent 10 or hold until this lands. (Announced per
task instructions; no other agent was editing kiwi-mail when this ran.)

**Status:** done — pure moves, zero functional changes.
`cargo test -p kiwi-mail` → **77/77** after every move,
`cargo clippy -p kiwi-mail --all-targets -- -D warnings` clean,
`cargo fmt --check` clean.

### New layout

```
kiwi-mail/src/
  imap/{mod,parser,commands}.rs        1543 → 333 + 522 + 720
    mod.rs      consts, ImapClient/ImapConfig/ImapAuth, re-exports, tests
    parser.rs   SExp/SParser/parse_sexp, reply types, fetch-line parsing
    commands.rs impl ImapClient (all commands + response driver)
  smtp/{mod,client,commands}.rs        1289 → 168 + 361 + 190 (approx)
    mod.rs      consts, SmtpReply/EhloInfo/SmtpConfig/SmtpAuth/SmtpClient/
                SendRequest/SendOutcome, re-exports, tests
    client.rs   impl SmtpClient (connect/EHLO/STARTTLS/AUTH/send/quit)
    commands.rs reply/envelope/dot-stuff helpers + QueuedSend/SendQueue
  store/{mod,schema,queries,outbox}.rs 1223 → 439 + 62 + 538 + 217
    mod.rs      MailStore, open/open_memory/migrate, meta types, tests
    schema.rs   SCHEMA_VERSION + DDL (pub(crate))
    queries.rs  impl MailStore — accounts/folders/messages/bodies/pop3
    outbox.rs   OutboxRow + outbox_* (persistent send queue)
  testutil/{mod,script,server,tests}.rs 948 → 20 + ~180 + ~120 + 697
    script.rs   Step/Proto/load/parse + protocol-aware matchers
    server.rs   Wire/serve/spawn_script/tls_acceptor
    tests.rs    the fixture + live-interop + sync test bodies
```

### Move mechanics (zero-change guarantee)

- `impl` blocks split across files (children see parent's private fields —
  no visibility change needed for `ImapClient.t`/`MailStore.conn` etc.).
- Private helpers used by sibling files bumped to `pub(crate)` — the only
  edit class besides moves.
- Public surface preserved via `pub use` in each mod.rs (`crate::imap::X`
  paths unchanged — sync.rs/testutil needed zero edits).
- Imports re-scoped per file; test-only imports moved into `mod tests`.
- Seam fixes during split: one doc comment straddled a cut (smtp
  `parse_ehlo_reply`), one line dropped at a file tail (testutil) — both
  restored byte-for-byte.
- `lib.rs` module-map comment updated to name the subfiles.

