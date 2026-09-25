# Agent 14 — Status Log (T-180: Phase C1 kiwi-mail splits — verify + finish)

> Agent 14 (OpenCode Zen xhigh). Terminal e26f119b. Predecessor: Agent 10.

## 2026-09-25 — T-180 verification: splits land intact, all gates green, no further splits needed

**Status:** done (verification-only — zero code changes required).

**Finding:** Agent 10's Phase C1 split is fully present and green. All four
target dirs exist with no monolith remnants at top level (no `smtp.rs`,
`imap.rs`, `store.rs`, `testutil.rs` files — only the dirs). No broken
imports (suite compiles + passes). No files >800 lines, so the sweep
requires no further splits. Working tree clean under `kiwi-mail/`.

### Layout confirmed (line counts)

```
kiwi-mail/src/
  imap/mod.rs 331 / parser.rs 522 / commands.rs 719
  smtp/mod.rs 776 / client.rs 357 / commands.rs 184
  store/mod.rs 440 / schema.rs 62 / queries.rs 538 / outbox.rs 217
  testutil/mod.rs 17 / script.rs 118 / server.rs 129 / tests.rs 697
  account.rs 154 / error.rs 28 / lib.rs 33 / lines.rs 110 / mime.rs 481
  pop3.rs 489 / search.rs 634 / sync.rs 307 / transport.rs 410
```

Largest file is `smtp/mod.rs` at 776 lines — under the 800-line sweep
threshold, so left as-is (splitting it further would churn without mandate).

### Gates (all green, no edits)

```
cargo test -p kiwi-mail --offline                              → 77/77 pass
cargo clippy -p kiwi-mail --all-targets --offline -D warnings  → clean
cargo fmt -p kiwi-mail --check                                 → clean
```

### Sweep checks

- `unsafe` grep over `kiwi-mail/src/**/*.rs` → zero matches.
- `unsafe_code = "forbid"` inherited via `[workspace.lints.rust]` (root
  `Cargo.toml:39-40`) + `[lints] workspace = true` (`kiwi-mail/Cargo.toml:36`).
- No `*.orig`/`*.bak`/`*.rej` leftovers; `git status -- kiwi-mail/` clean.
- Public paths unchanged (`crate::imap::X`, `crate::smtp::X`, etc. via
  `pub use` in each `mod.rs`; `lib.rs` module map documents subfiles).

### Files changed

None (verification only). This status file only.

### Assumptions / risks

- Did not re-run live-interop (`KIWI_MAILPIT=1 … roundtrip`) — Docker-stack
  scope; offline suite green is the T-180 acceptance signal.
- `smtp/mod.rs` (776) will cross 800 on the next feature addition — whoever
  touches it next should pre-split (suggest: types/config → `types.rs`,
  tests → `tests.rs`).
- Workspace-wide clippy was not re-checked (Agent 10 noted other crates'
  deny-lint failures as out of scope); `-p kiwi-mail` is clean.

## 2026-09-25 — T-201 (F2): deterministic email categorization classifier

**Status:** done — implemented + verified. All gates green (see verification
note below for method). Work already swept into git by the repo's auto-commit
process (commits ac02b28, 859a347 include these files); no separate commit
made — Lead integrates.

### What landed (all in `kiwi-mail`, + 4 one-line test/prod fixes in src-tauri)

- **NEW `kiwi-mail/src/category.rs`** (577 lines, incl. 18 tests):
  `Category::{Primary,Newsletters,Social,Notifications,Other}` with stable
  SQLite slugs (`as_str`/`from_slug`, `Display`, `Default=Primary`),
  `Classification{category, reason}`, `categorize(&ParsedMessage)` — pure
  function of From + headers. No network, no clock, no AI. Precedence:
  Auto-Submitted≠no → Notifications; social domain → Social (before list
  headers — LinkedIn digests carry List-Unsubscribe); Precedence
  bulk/list/junk → Newsletters; any `List-*` → Newsletters; bulk-mailer
  X-Mailer/User-Agent → Newsletters; no-reply sender /
  X-Auto-Response-Suppress → Notifications; other ESP fingerprints
  (X-SMTPAPI, X-Campaign-*, …) → Other (deliberate: these also appear on
  transactional mail); fallback Primary (cites personal MUA when visible).
  Every reason cites the firing header/rule. 15 social domains (suffix
  match), 31 bulk-mailer substrings, 22 MUA substrings, 15 automation
  prefixes — all documented in-file.
- **`mime.rs`**: `ParsedMessage.headers: Vec<(String,String)>` (lowercased
  names, bounded 128 headers / 1024-char values, char-boundary-safe).
  Key catch during testing: `List-Unsubscribe: <url>` parses as
  `mail_parser::HeaderValue::Address`, not `Text` — extractor flattens
  Address values (list + group) instead of skipping them.
- **Store (schema v4)**: `messages.category TEXT NOT NULL DEFAULT
  'primary'`; `migrate_conn` (factored for tests) adds the column
  idempotently via `PRAGMA table_info` + best-effort backfill from stored
  bodies (8 MiB cap, per-row failures skipped, missing/unparseable bodies
  keep `'primary'`). `MessageMeta`/`NewMessageMeta` carry typed `Category`;
  `upsert_message` writes it (conflict clause deliberately leaves it
  untouched so re-upserts never clobber a refined tab); new
  `set_category` + `list_messages_by_category`; `move_messages` carries it;
  `search.rs` selects/maps it.
- **Ingest wiring (`sync.rs`)**: POP3 classifies full messages at ingest;
  IMAP `to_meta` classifies from envelope From (domain rules fire,
  list-rules degrade to Primary); `fetch_missing_bodies` refines via
  `set_category` once headers arrive (parse failure keeps existing value).
- **src-tauri** (4 literals, compile-fix only): `update.rs` archive-copy
  preserves `category: m.category` (production path); 3 test literals in
  `mail.rs`, `message/mod.rs` use `Default::default()`.

### Tests (24 new: 77 → 101)

- `category.rs`: slug roundtrip/unknown-reject, fixture per tab, precedence
  duels (social>list+precedence, auto-submitted>all, bulk-mailer>noreply),
  suffix-boundary (`fakex.com`≠`x.com`), case-insensitivity, `Auto-Submitted:
  no` neutral, envelope-only degradation, determinism, hostile-input splits.
- `mime.rs`: header capture incl. Address-valued List-Unsubscribe.
- `store/mod.rs`: persist/refine/filter, no-clobber-on-reupsert,
  move-preserves, **v3→v4 migration test** (hand-built v3 DB → column added,
  body backfilled to `newsletters`, bodyless row stays `primary`,
  idempotent re-run).
- `sync.rs`: `to_meta` envelope classification (social/notification/primary
  degradation).

### Gates

```
isolated copy (kiwi-mail+kiwi-core, same manifests):
  cargo test -p kiwi-mail --offline               → 101/101
  cargo clippy -p kiwi-mail --all-targets -D warnings → clean
  cargo fmt -p kiwi-mail --check                  → clean (ran fmt in workspace)
  unsafe grep over new code → none (workspace forbid lints apply)
file sizes: all kiwi-mail/src files <800 (max store/mod.rs 657)
```

### Verification method + BLOCKER (Lead attention needed)

- **Why isolated copy:** at ~15:14 Agent 11's edit to
  `kiwi-integrations/Cargo.toml` requested reqwest feature
  `rustls-tls-webpki-roots`, which does not exist in reqwest 0.13.5 —
  workspace-wide cargo resolution now fails, blocking ALL crates' cargo
  commands (including a real-workspace re-run of my suite and the
  src-tauri compile check). I did NOT touch their file (active owner).
  **Ask: Agent 11/Lead fix the feature name** (likely `rustls-tls` +
  `webpki-roots`, or provider feature per reqwest 0.13 docs), then re-run
  `cargo test --workspace` as a sanity gate.
- **src-tauri literals unverified by compiler** (4 one-line additions, types
  line up: `Category: Default+Clone+Copy`; `m.category` is `Category`).
  Please confirm with `cargo check -p kiwi-app` (or whatever the Tauri
  package is named) once resolution is fixed.
- **Follow-up for A7/A5 (not mine):** expose `category` in
  `MessageView`/IPC + contract so the F2 UI tabs can consume
  `list_messages_by_category`. No IPC changes made in this task.
- Residual: `fetch_missing_bodies` refinement path (3 lines, public-API
  calls) has no dedicated live test — covered logically by unit tests on
  both sides; a fixture-level test can ride along with the next
  testutil sync-fixture addition.

### Files changed

`kiwi-mail/src/{category.rs(new),lib.rs,mime.rs,search.rs,sync.rs,
store/{mod,schema,queries}.rs}`,
`kiwi-app/src-tauri/src/commands/{mail.rs,message/{mod,update}.rs}`
(4 literals), this file. Committed by repo sweep (859a347 et al) —
Lead owns integration.

## 2026-09-25 — T-202 (F3): one-click unsubscribe, kiwi-mail side + MessageView

**Status:** done — implemented + verified in-workspace (reqwest blocker from
T-201 is resolved). `cargo test -p kiwi-mail` → **116/116** (was 101),
clippy `--all-targets -D warnings` clean, `cargo fmt --check` clean,
`unsafe`-free (workspace forbid). No commit — Lead integrates (repo sweeps
are committing worktree state regularly).

### What landed

- **NEW `kiwi-mail/src/unsub.rs`** (~390 lines, 13 tests):
  `UnsubscribeInfo{http_url, mailto, one_click}`,
  `UnsubscribeAction::{None,Http,Mailto,Both}` via `action()`,
  `has_consent_gated_option()` (mailto present → consent required, never
  auto-send), `parse_unsubscribe(&[(name, value)])`. Policy (in-file docs):
  `<>`-bracketed tokens only; **https-only** (plain-http dropped);
  mailto params stripped to bare address; whitespace/CTL/overlong rejected;
  `List-Unsubscribe-Post` normalized compare for the RFC 8058 flag; first
  https + first mailto win across repeated headers; no offer → `None`.
- **`mime.rs`**: `ParsedMessage.unsubscribe: Option<UnsubscribeInfo>`
  filled on ingest. Two real bugs found by tests and fixed:
  1. `List-Unsubscribe: <url>` parses as `Address`, losing brackets —
     first fix (flatten addresses) worked for unit shapes but failed on
     real parses;
  2. fix proper: `capture_headers` now slices RAW value text via parser
     offsets (`offset_start..offset_end`, unfolded, right-trimmed) with
     typed extraction as defensive fallback; `received` explicitly skipped
     (transport noise that would crowd the 128-header bound).
- **Store schema v5**: `unsub_http TEXT, unsub_mailto TEXT,
  unsub_oneclick INTEGER NOT NULL DEFAULT 0`. `migrate_conn` restructured
  to version-gated append-only steps (v3→v4→v5, v4→v5, fresh skips);
  shared `bodies_to_backfill` helper serves both backfills.
  `MessageMeta`/`NewMessageMeta` carry the 3 fields; upsert writes them
  (conflict clause untouched — refinement-safe); new `set_unsubscribe`;
  `move_messages` carries them; `search.rs` selects/maps them.
- **Ingest (`sync.rs`)**: POP3 stores the offer at ingest; IMAP `to_meta`
  stores empty (no headers); `fetch_missing_bodies` refines both category
  and unsubscribe once headers arrive.
- **MessageView (`src-tauri types/mail.rs`)**: new `category: String`,
  `unsubscribe_url/mailto/one_click/requires_consent` (camelCase
  serialized; `requires_consent = mailto.is_some()`). Single `From` impl
  updated; 4 `NewMessageMeta` literals fixed (`update.rs` archive-copy
  preserves all new fields; 3 test literals defaulted).

### Tests (15 new: 101 → 116)

- `unsub.rs`: missing/garbage headers, https-only, mailto-only (gated),
  both (http primary), first-wins incl. across repeated headers,
  http/ftp dropped, malformed battery (bare/unterminated/empty/no-@/
  CRLF-injection/overlong), RFC 8058 exact/case-folded/wrong-value/
  post-alone, scheme case-insensitivity with value preservation, titles
  ignored, determinism.
- `mime.rs`: ingest sets `.unsubscribe` (params stripped, one-click set);
  absent offer → `None`.
- `store/mod.rs`: v3 test extended (offer+mailto+one-click backfilled,
  bodyless row defaults); NEW v4→v5 test (category untouched, offer
  filled); NEW persist/refine/no-clobber/move-carries test.

### Verification notes / follow-ups (Lead)

- `cargo check -p kiwi-app`: **blocked by another agent's in-flight file**
  — `src-tauri/src/types/integrations.rs` (untracked, saved 15:41) fails
  with E0382 (`r.tallies` partial move) plus an unused-import warning in
  `types/mod.rs`. Not mine, not touched (§8). Evidence my changes are
  sound: rustc reported ONLY that error — `types/mail.rs` and all command
  modules (with my 4 literal fixes + new `From` fields) produced zero
  errors. Please re-run the Tauri check once their file lands.
- Contract/frontend: `ipc.md` documents `MessageView` shape (§~244) and
  the frontend keeps local TS view types — both need the 5 new fields
  (A7/A5 follow-up; additive backend fields break nothing). No IPC
  behavior changes in this task: no fetching, no sending, no new command.
- Syntax-break postscript: my first `unsub.rs` push had 4 delimiter typos
  (`)]))` on multi-tuple arrays) that went workspace-red; user flagged it
  — fixed all four, compile verified, then the header work above. Lesson:
  run `cargo check` before considering any file done, even test-only edits.
- Re-check suggestion: `cargo test --workspace` once integrations.rs lands,
  to confirm no cross-crate regression from the schema bump.

