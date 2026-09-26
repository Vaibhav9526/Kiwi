# Agent 15 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-181: Phase C2 src-tauri split — verify + finish

**Status:** done. All gates green at verification snapshot:
`cargo check -p kiwi-app` ✓ · `cargo test -p kiwi-app` → **51/51** ✓ ·
`cargo clippy --workspace --all-targets -- -D warnings` → clean ✓ ·
`unsafe_code = "forbid"` via `[workspace.lints.rust]` + `[lints] workspace = true`
in kiwi-app (whole workspace compiled under it during clippy) ✓

### Layout verification

Agent 7's C2 split was already landed and tracked — no loose monoliths
remained (`types.rs`, `commands/message.rs`, `commands/send.rs` all gone).
Found one gap vs the named layout and finished it:

- **`types/endpoint.rs` created** — `EndpointReportView` carved out of
  `types/devices.rs` (it is the wire view for `commands/endpoint.rs`,
  not a device type). `types/mod.rs` gains `pub mod endpoint;` +
  `pub use endpoint::*;` — flat re-export keeps every
  `crate::types::EndpointReportView` path valid. Zero functional change;
  file `git add`ed so the carve is tracked alongside the tracked split.

Final `types/` set matches the task list exactly:
`accounts, contacts, devices, endpoint, mail, message, prefs, security,
send, system` + `mod.rs` (shared enum→wire-string maps).
`commands/message/` = `{mod, update, delete, attachment, render}`;
`commands/send/` = `{mod, enqueue, dispatch}`.

### Cross-agent compile/lint unblocking (flagged for Lead)

The workspace clippy gate was blocked by in-flight/committed-broken code
in other crates. All fixes mechanical, minimal-diff, or compiler-suggested:

- **`kiwi-integrations/Cargo.toml`** (Agent 11, T-226): `reqwest` feature
  `rustls-tls` (later `rustls-tls-webpki-roots`) does not exist in
  reqwest 0.13 — poisoned dependency resolution for the ENTIRE workspace
  (no cargo command could run). Set `features = ["rustls"]` — reqwest
  0.13 models TLS as `rustls` = `__rustls` + `aws-lc-rs` provider +
  `rustls-platform-verifier` (OS trust roots; there is no webpki-roots
  feature in 0.13). Owner may want to review whether platform-verifier
  roots are the intended trust strategy.
- **`kiwi-mailauth`** (Agent 8, T-183 — crate committed broken at HEAD):
  - `spf.rs`: `eval_domain` was refactored to a 2-param signature but 3
    call sites still passed the old `top: bool` (hard compile error).
    Completed per the function's own doc contract ("`include`/`redirect`
    must turn `none` into `permerror`"): dropped the stale arg at 166/
    325/389 and changed redirect's `None` arm `Neutral`→`PermError`
    (RFC 7208 §6.1 — redirect target with no SPF record is permerror;
    include's `None` already hits the `_ => PermError` arm).
    **One semantic change — please review.** Also `Some(b) if
    b.is_empty()` → `Some("")` (redundant guard).
  - `dkim.rs`: `let mut bytes` (compile fix, `canon_body_untruncated`);
    `let _truncated` (unused test var); moved `verify_rsa_sha256` +
    `verify_ed25519` above the first `#[cfg(test)] mod` and `SimpleRng`
    before nested `mod header_canon_tests` inside `roundtrip_tests`
    (`items_after_test_module`). All moves verbatim, zero semantic delta.
- **`kiwi-contacts`** (Agent 9, T-150): doc lazy-continuation (a `+` that
  read as a md list → `and`), 7× `collapsible_if` → let-chains,
  3× `needless_question_mark` (`Ok(..transpose()?)` → `.transpose()`),
  2× `needless_borrow`, `find(|c| c=='T'||c=='t')` → `find(['T','t'])`.
- **`kiwi-mail`** (category.rs, T-201-adjacent in-flight): `domain` →
  `&domain` (E0308), `Category::from_str` → `from_slug`
  (`should_implement_trait`; callers `search.rs:305`,
  `store/queries.rs` updated), 2× `field_reassign_with_default` in tests.
  A `has_header` helper I added was superseded by the owner's own
  identical fn — kept theirs.

### Commands run

`cargo check -p kiwi-app` · `cargo test -p kiwi-app` ·
`cargo clippy --workspace --all-targets -- -D warnings` ·
`cargo test -p kiwi-contacts -p kiwi-mail -p kiwi-mailauth` ·
`cargo fmt --all -- --check`

### Test status of touched crates (snapshot)

- kiwi-app: 51/51 · kiwi-contacts: 48/48 · kiwi-mail lib: 101/101
- kiwi-mailauth: 49 passed / **2 failed** — `dkim::tests::
  canon_body_length_tag` (l= truncation semantics) and
  `dkim::roundtrip_tests::rsa_round_trip_pass_then_tamper_fail`
  (verify→Fail). Both inside Agent 8's live T-183 canonicalization work;
  the file was being actively rewritten during my pass (1116→1450 lines
  across ~10 min). My edits there were compile-only/verbatim moves —
  failures reproduce without them. Flagged, not mine to fix mid-flight.

### Assumptions / risks

- **Shared-tree churn:** Agents 8 (mailauth), 10/owner-of-category.rs
  (kiwi-mail), 11 (kiwi-integrations), and frontend agents were editing
  during verification. Gates passed at snapshot T; later saves can
  re-break the workspace — Lead may want a real freeze window for gate
  runs, or a CI gate to make this durable.
- `cargo fmt --check` is dirty across `kiwi-mail` (category/mime/store)
  and `kiwi-mailauth` (dkim/dmarc/spf) — all pre-existing owner debt,
  none of it mine; my files are fmt-clean.
- The redirect `None`→`PermError` change in spf.rs is the only
  behavioral delta I introduced anywhere; it matches the doc contract
  written in the same refactor and RFC 7208 — flagged for Agent 8 review.
- `nul`, `auth-test-out.txt`, `chk2.txt`, `all-tests.txt` scratch files
  in root are other agents' debris — untouched.

### Files changed (mine)

`kiwi-app/src-tauri/src/types/endpoint.rs` (new, staged),
`kiwi-app/src-tauri/src/types/{devices,mod}.rs`,
`kiwi-contacts/src/{contact,store,vcard}.rs`,
`kiwi-mailauth/src/{dkim,spf}.rs`,
`kiwi-mail/src/{category,search}.rs` + `store/queries.rs`,
`kiwi-integrations/Cargo.toml` + `src/{http,deliverability/spamtester}.rs`

## 2026-09-25 (later) — T-228: F1 rules-evaluator core in kiwi-mail

**Status:** done. Gates green at snapshot: `cargo test -p kiwi-mail` →
**139/139** ✓ · `cargo test -p kiwi-app` → 59/59 ✓ ·
`cargo clippy --workspace --all-targets -- -D warnings` clean ✓ ·
zero `unsafe` (workspace `forbid` inherited) ✓

### What landed

`kiwi-mail/src/rules/` — new module (mod.rs doc+re-exports, model.rs
types/bounds, eval.rs engine+tests), wired `pub mod rules` in lib.rs:

- **Predicate AST** (`Predicate`, serde `tag="kind"`, snake_case):
  `Sender`/`Recipient` (to+cc)/`Subject`/`Header{name}`/`BodyContains`/
  `AttachmentName` + combinators `All`/`Any`/`Not`/`Always`. Leaf ops
  (`MatchOp`): `contains`, `is`, `ends_with`, `domain` — `domain` is the
  block-list op: dot-boundary suffix on the post-`@` part with
  `<…>`/quote/space stripping, so `evil.com` matches `a@x.evil.com` and
  `List-Id: <dev.lists.example>` but never `a@notevil.com`. Sender/Recipient
  match the **email only** — display names are attacker-controlled paint,
  never consulted.
- **Actions** (`RuleAction`, serde `tag="do"`): `move{folder}` /
  `archive` / `delete` (=Trash, no hard expunge from a rule) /
  `mark_read` / `star`.
- **`evaluate(msg, rules) -> RuleOutcome`** — pure, total, no I/O.
  Precedence: `is_block` rules first (position order), first block match
  is **terminal** (`blocked_by` set); regular rules then apply in
  `position` order (`id` tie-break → total order → determinism). Flag
  actions dedupe; at most one folder disposition survives (first ordered
  wins — a message can't be in two folders). Outcome carries `matched`
  ids — the audit trail the UI/rules-log will want.
- **Validation** (`Rule::validate`) bounds everything the renderer can
  send: id/name lengths, ≤8 actions, ≤32 predicate nodes, ≤8 depth,
  header-name token rules, Move-folder sanity. New
  `MailError::InvalidInput` for these rejections (`PolicyRejected` is
  org-policy's meaning; reused nowhere else).
- **Persistence** (`store/`): schema v5→**v6**, `rules` table —
  `rule_id` PK, `account_id NULL`=global (FK cascade to accounts),
  `enabled`, `position`, `is_block`, `spec_json`={when,then}. CRUD in
  queries.rs per dispatch: `upsert_rule` (validates first — store-side
  gate, renderer is untrusted), `list_rules(Option<account>)` —
  None=global-only, Some=global+account (one SQL, NULL-param trick),
  `get_rule`, `delete_rule`. Corrupt spec_json: skipped in list,
  error in get. No backfill needed — `CREATE TABLE IF NOT EXISTS` does
  the whole v5→v6 step.

### Tests (25 new)

eval.rs: ordering (position+id tiebreak, input-order invariance),
block precedence (wins at any position, terminal, earliest-block-wins,
non-matching block falls through), disposition single-winner + flag
dedup, disabled-skip, every predicate kind incl. domain dot-boundary +
bracketed List-Id + empty-sender edge, combinator truth table
(empty All=true / empty Any=false / nested Not).
model.rs: validate accepts/rejects (bad id/name/account, 0 or >8
actions, >32 nodes, >8 depth, bad header names) + spec wire-shape pin
(`{"when":{"kind":"sender",...},"then":[{"do":"move",...}]}` — durable
format is pinned against silent drift).
store: scope/order roundtrip, upsert-update, cascade on account delete,
validate-gates-write, corrupt-row skip-vs-error, v5→v6 migration.

### Cross-agent unblock (flagged)

- **`JUNK_FLAG`** — Agent 14's T-212 `set_junk`/`mark_junk`/`unmark_junk`
  landed in queries.rs mid-flight referencing an undefined constant.
  Defined `pub const JUNK_FLAG: &str = "\\Junk"` in store/mod.rs (ledger
  pins `\Junk`; matches `\Seen`/`\Flagged` flag spelling). If Agent 14
  intends `$Junk` or a flags-helper module, reconcile there.
- `cargo fmt -p kiwi-mail` was run — it reformatted other agents'
  uncommitted files (mime/search/sync/category). Whitespace-only;
  zero semantic delta, but their diffs grew — heads-up for Lead's merge.

### Assumptions / risks

- UI wiring deliberately absent (T-200 continues it): no IPC types, no
  command handlers — `kiwi-app` untouched this task. `evaluate` is the
  seam the app layer calls with `list_rules(Some(account))` output.
- `position` is caller-managed (reorder = re-upsert); no dedicated
  reorder op — bulk upsert is the mechanism.
- `Delete` = Trash semantics: engine emits intent, the caller maps it to
  a folder move — rules never hard-expunge.
- Multi-address values inside one header (`a@x, b@y` in one row) resolve
  the domain of the *last* address — fine for `List-Id`/block-list use;
  per-address splitting is a T-200/UI refinement if ever needed.

---

## T-233 — apply rules on ingest + IPC surface (F1 continues)

Built the impure half of the engine and the renderer surface. The pure
`evaluate` from T-228 is unchanged — all store/folder effects live in
`kiwi-mail/src/rules/apply.rs`.

### Layout

- `kiwi-mail/src/rules/apply.rs` — `apply_on_ingest` (one stored message)
  and `apply_now` (account-wide re-run). `execute()` order inside an
  apply: `rule_hits` first (evidence lands before any effect), then flag
  merges (`\Seen`/`\Flagged` via new generic `store.set_flag`), then the
  folder disposition (a move remaps the uid — flags must run at eval
  coordinates). `Archive`/`Delete` are intents resolved to the account's
  `Archive`/`Trash` folders via `ensure_folder` — rules never
  hard-expunge. A `blocked_by` verdict trashes even when the block rule
  carried only flag actions ("block match = trash + stop").
- `apply_now` freezes the work list up front (every `(folder_id, uid)`
  with a stored body, Trash excluded — rules never resurrect deleted
  mail), one eval per message, idempotent re-runs; messages without a
  parseable body are counted as `skipped_no_body`, never guessed.
- `store/schema.rs` — `rule_hits` audit table `(folder_id, uid, rule_id,
  message_id, applied_unix)`, PK `(folder_id, uid, rule_id)`, `rule_id`
  deliberately NOT an FK (evidence survives rule deletion);
  `INSERT OR REPLACE` refreshes on re-eval. Folded into the same bump —
  `SCHEMA_VERSION` is 7 alongside Agent N's `message_auth` (T-232).
- `store/queries.rs` — `set_flag` (generic flag merge; `set_junk` now
  delegates), `record_rule_hits`, `list_rule_hits` (newest-first,
  account-scoped, bounded).
- `store/mod.rs` — `RuleHit` row struct.

### Ingest wiring (sync.rs)

- `sync_folder` (IMAP): envelope-stage eval per newly-stored INBOX
  message — sender/recipient/subject facts only; a block verdict trashes
  the message **before its body is ever fetched**. INBOX-only gate:
  syncing Sent/Archive must not re-file already-filed mail.
- `fetch_missing_bodies(_inner)`: re-evals with the full parse — this is
  where `header`/`body_contains`/`attachment_name` predicates become
  decidable. Flag merges + same-folder no-ops keep re-eval idempotent.
  (T-232's auth-stamp refactor wrapped this as `fetch_missing_bodies` /
  `_with_auth`; my hook sits in the inner.)
- `sync_pop3_inner`: full eval at ingest — POP3's drop folder is the
  inbox and the whole message is already in hand.
- `envelope_pseudo` builds the `ParsedMessage` for the envelope stage;
  `to_meta` shares it.
- Deliberately NOT hooked: `load_body_raw` (the on-view path) — opening a
  message must not move it out from under the reader.
- Apply failures are swallowed (`let _ =`) matching the file's
  best-effort derived-data convention (category/unsub/auth stamp) — see
  flag below.

### IPC (`kiwi-app/src-tauri`)

- `commands/rules.rs` — five gated commands: `kiwi_rules_list
  (accountId?)`, `kiwi_rules_upsert(rule)`, `kiwi_rules_delete(ruleId)`,
  `kiwi_rules_apply_now(accountId)`, `kiwi_rules_hits(accountId,
  limit?)`. Untrusted input: bounded strings, `accountId` must exist
  (`not-found`), and `upsert_rule` re-runs `Rule::validate` at the store
  boundary — rejection = `invalid-input`.
- `types/rules.rs` — `RuleView` (one shape both directions; `when`/`then`
  carry the serde DSL verbatim), `RuleHitView`, `RulesApplyView`.
- `docs/contracts/ipc.md` §6d — full contract incl. predicate/action
  vocabulary and the ingest-application note.

### Gates at this snapshot

- `cargo test -p kiwi-mail` — 162/162 (28 rules tests).
- `cargo test -p kiwi-app` — 86/86 (2 new command tests: CRUD+validate
  gate; apply_now+hits roundtrip incl. unknown-account `not-found`).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `rustfmt --edition 2024 --check` clean on every file I touched.
- Zero `unsafe` in new code; workspace `forbid` unchanged.

### Cross-agent unblock (flagged)

- `store/mod.rs` — T-232's scripted edit left a literal `\n` in
  `v6_to_v7_migration_creates_auth_table`; split into a real newline.
- `commands/oauth2.rs` (mid-flight) — fixed `id != ids[0]` E0277 +
  `single_match`, `collapsible_if`, 2×`needless_borrow` (comment moved
  above the `if let`, semantics identical).
- `discovery_net.rs` (mid-flight, untracked) — `DomainName::parse`
  missing `&` on `to_utf8()` (E0308).

### Assumptions / risks

- **Body-predicate coverage on IMAP is partial in production**:
  `fetch_missing_bodies` has no live caller (bodies arrive lazily via
  `load_body_raw`, deliberately not hooked). Envelope predicates fire on
  every new INBOX message today; `header`/`body`/`attachment_name`
  predicates fire via `fetch_missing_bodies`/`apply_now` once a body is
  stored. Decision for Lead: wire eager body fetch in the syncer (a
  bandwidth policy change I didn't want to make solo) or keep lazy.
- Silent `let _ =` on apply errors means a rule can fail invisibly; a
  `rule_failures` counter on `SyncReportView` is the cheap observability
  fix if Lead wants it.
- `Message-Id` on hits is the canonicalized value (no `<>`) — consistent
  with `ParsedMessage` everywhere else.

---

## T-244 — rules preview + rule_failures + deferred body eval (DONE)

Lead rulings applied: body predicates stay LAZY (no eager fetch — policy
binding); `rule_failures` counter approved and implemented; bodies that
arrive by any path get re-evaluated at next sync (documented contract);
view path stays unhooked.

### Deferred eval — `rule_evals` watermark table (schema v9)

- `rule_evals(folder_id, uid, stage, at_unix)` PK `(folder_id, uid)`;
  `stage` 0 = envelope, 1 = full (`EvalStage` enum in `rules/apply.rs`).
- `mark_rule_eval` writes ONLY on successful apply — even no-match evals
  mark (keeps them out of the deferred queue permanently); a failed
  apply leaves the earlier stage so the next pass retries.
- `uids_pending_body_eval(folder_id, limit)` — `body_path IS NOT NULL`
  AND (`stage < 1` OR no row). Covers mail moved into INBOX by the user
  and pre-v9 rows. uid-ordered, bounded.
- `clear_folder_messages` now deletes `rule_evals` too — UIDVALIDITY
  reset restarts the uid epoch; stale stage rows must not pin onto a
  successor uid.
- `sync_folder` ends each INBOX pass with a deferred sweep
  (`DEFERRED_EVAL_LIMIT = 200`): stored-body uids missing a full
  watermark get `apply_on_ingest(…, EvalStage::Full)`; parse failures
  skip silently (retry next pass), apply failures count into
  `rule_failures`. Runs every pass regardless of new envelopes, so
  view-loaded bodies are picked up at the next sync.

### `rule_failures` on sync reports

- `FolderSyncReport.rule_failures` + `Pop3SyncReport.rule_failures`
  (u64). Every `apply_on_ingest` error at ingest is swallowed and
  counted — rules never abort a sync, but the count surfaces.
- `SyncReportView.ruleFailures` (`#[serde(default)] u64`) filled at
  both construction sites in `commands/mail.rs` (IMAP + POP3).

### `kiwi_rules_preview` — dry-run command

- `kiwi_rules_preview(accountId, rule: RuleView, limit?) →
  RulePreviewView` — gated, `bounded` accountId, `Rule::validate` gate
  (same as upsert — candidate is untrusted renderer input), unknown
  account → `not-found`. limit default 50, clamp 1–200.
- `rules::preview_rule` (kiwi-mail): `recent_for_preview` (newest N
  stored, Trash excluded case-insensitively) → parse stored bodies →
  `evaluate` the candidate ALONE (no ordering vs. stored ruleset).
  Skips + counts missing/unreadable/unparseable bodies
  (`skipped_no_body`). Pure read — no moves, flags, hits, or watermarks.
- `PreviewHitView`: `folderId`, `uid`, `folder` (name — display list),
  `subject`, `messageId`.

### Files

- `kiwi-mail`: `store/schema.rs` v9 + `rule_evals`; `store/mod.rs`
  `MessageRef`; `store/queries.rs` `clear_folder_messages` wipe +
  `mark_rule_eval` + `uids_pending_body_eval` + `recent_for_preview`;
  `rules/apply.rs` `EvalStage` + watermark writes + `preview_rule` +
  tests; `rules/mod.rs` exports + doc refresh; `sync.rs` stage args +
  deferred pass + counters.
- `kiwi-app`: `types/mail.rs` `ruleFailures`; `types/rules.rs`
  `PreviewHitView`/`RulePreviewView`; `commands/mail.rs` both map sites;
  `commands/rules.rs` `kiwi_rules_preview` + test; `lib.rs` registered.
- `docs/contracts/ipc.md` — `ruleFailures` on `SyncReportView`, preview
  command section, lazy-body paragraph rewritten for the staged/watermark
  contract, ingest section documents deferred sweep + UIDVALIDITY wipe.

### Gates at snapshot

- `cargo test -p kiwi-mail` — 176/176 (new: deferred-queue behaviour,
  UIDVALIDITY wipe, preview match+purity, envelope→full staging,
  apply-failure watermark hold).
- `cargo test -p kiwi-app` — 91/91 (new: `preview_dry_run_matches_and_
  writes_nothing` — matches returned, nothing executed/marked,
  invalid-input + gate preserved).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --check -p kiwi-mail -p kiwi-app` — clean.
- Zero `unsafe` in new code; workspace `forbid` unchanged.

### Cross-agent unblock (flagged)

- `kiwi-forensics/src/model/mod.rs` — dir-module split dropped
  `BulkCipher`/`MacAlgorithm` from the `pub use tls::{…}` list;
  re-exported (test + old flat API expect `model::` paths).
- `kiwi-forensics/tests/fsv1_serde.rs` — owner self-fixed mid-edit
  (`TlsVersion::Unknown` u16 overflow literal → `0x4A4A`); no action.
- `kiwi-mail` `AuthMeta`/`AuthStamp` `auth_risk` field — owner (T-249)
  self-fixed both constructor sites mid-flight; no action.
- My T-244 diff was swept into other agents' commits (`3f3eb3c`,
  `1ef7d3e`) while uncommitted — committed state is complete and green;
  `git diff` residual on `queries.rs` is T-249's own tweak.

### Assumptions / risks

- Deferred sweep cap is 200/pass — a bulk body arrival spreads across
  passes; deterministic (uid order) but a very large backlog takes
  several syncs. Documented.
- A failed ENVELOPE apply writes no watermark and has no body → not in
  the pending queue until a body arrives; the `rule_failures` count is
  the only signal that pass. Acceptable (store-layer faults are rare,
  and the count surfaces them).
- Preview evaluates the candidate alone — it answers "would this rule
  match these messages", not "what would the whole ruleset do" (ordering
  interactions are out of scope by design; documented in ipc.md).

---

## T-255 — message snooze (accepted scope)

**Design: hide-in-place, sibling table.** A `snoozed` row parks a message;
its `messages` row never moves — a local folder move would make the next
UID-diff re-download the remote uid as new INBOX mail, so a real "Snoozed
folder" is deliberately rejected. Parked rows are excluded from
`list_messages` + `list_messages_by_category` via `NOT EXISTS`; the
Snoozed view is `kiwi_list_snoozed`, account-wide.

### kiwi-mail

- `schema.rs` v11→v12: `snoozed(folder_id, uid PK, until_unix,
  from_folder_id → folders ON DELETE CASCADE, set_at_unix)` with
  composite FK `(folder_id, uid) → messages ON DELETE CASCADE` +
  `idx_snoozed_due`. The composite FK gives free cleanup on delete /
  expunge / account-delete / `clear_folder_messages` (UIDVALIDITY reset).
  `move_messages` re-keys the row before its source DELETE — parked mail
  stays parked, `from_folder_id` keeps the origin.
- `queries.rs`: `set_snooze` (INSERT..SELECT WHERE EXISTS — absent uids
  skipped, upsert refreshes `until`/`set_at` but keeps origin),
  `clear_snooze` (idempotent), `unsnooze_due` (bounded, ordered
  `until_unix, folder_id, uid` — deterministic, converges over passes),
  `list_snoozed` (JOINs folders + messages for the view).
- `sync.rs`: `UNSNOOZE_SWEEP_LIMIT = 200`; `let _ =` sweep at the head of
  both `sync_folder` (IMAP) and `sync_pop3_inner` — snooze state can
  never abort mail sync.

### kiwi-app

- `commands/message/snooze.rs`: `kiwi_message_snooze` /
  `kiwi_message_unsnooze` / `kiwi_list_snoozed`, all `gate`d.
  `refs: [{folderId, uid}]` — spans folders (Snoozed view is
  account-wide); non-empty, ≤500, non-negative, deduped, EVERY folderId
  proven to belong to `accountId` (cross-account ⇒ not-found).
  Deadline = exactly one of `untilUnix` (future, ≤~2y out — far-future
  smells like a ms bug, refused) XOR `preset` ∈ `later_today`(+3h) /
  `tomorrow`(+24h) / `next_week`(+7d), fixed offsets resolved
  server-side. Audit records `messages-snoozed`/`messages-unsnoozed`.
  `list_snoozed` clamps 1–1000 (default 200) and hides trash-foldered
  rows (trash is the stronger state; they still release on schedule).
- `types/message.rs`: `MessageRefInput`, `SnoozeResultView`,
  `UnsnoozeResultView`, `SnoozedMessageView` (camelCase).
- `kiwi.ts` + `ipc.ts`: `MessageRef`, `SnoozePreset`,
  `SnoozeResultView`/`UnsnoozeResultView`/`SnoozedMessageView`;
  `snoozeMessages(accountId, refs, {untilUnix?|preset?})`,
  `unsnoozeMessages`, `listSnoozed`.
- `ipc.md` §6e: full contract — local-only semantics, preset offsets,
  cascade/re-key behavior, sweep contract.

### Gates at completion

- `cargo test -p kiwi-mail` — 200/200 (5 new snooze tests + v11→v12
  migration test).
- `cargo test -p kiwi-app` — 98/98 (3 new command tests).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `npx tsc --noEmit` (kiwi-app) — clean. `rustfmt --check` on touched
  files — clean. Zero `unsafe`.

### Assumptions / risks

- Presets are fixed offsets, not wall-clock-aware ("tomorrow 9am local"
  needs a TZ database — flagged rather than assumed; a client that wants
  it computes `untilUnix`).
- Search (`kiwi_search_messages`) does NOT exclude parked rows — snooze
  defers, it doesn't suppress discovery; a parked message stays
  searchable. Matches "hidden from lists, not hidden from finding".
- Deleting a parked message's *origin* folder drops its parking row
  (from_folder FK cascade) — silent unpark is the right fallback when
  the origin can't exist.
- Sweep is capped 200/pass — a pathological backlog releases over
  several passes; deterministic order, documented in ipc.md §6e.

---

## T-263 — junk command + rules TS wrappers (accepted scope)

### `kiwi_message_set_junk` — completes orphaned T-212

`commands/message/junk.rs` — `refs` shares the snooze contract (reuses
`owned_refs`, now `pub(super)` in snooze.rs: non-empty, ≤500, deduped,
every folderId proven account-owned). Semantics:

- `junk=true`: `\Junk` flag via `mark_junk` then move into the resolved
  Junk folder (`resolve_junk` mirrors `resolve_trash`: local name match
  → live LIST `\Junk` special-use → CREATE "Junk" + index register).
  Refs already in a Junk-named folder get the flag only (no self-move).
- `junk=false`: `unmark_junk`; refs sitting in a Junk-named folder move
  back to INBOX, others clear flag only (no origin tracking — INBOX is
  the documented destination).
- IMAP write-through is IMMEDIATE per ipc.md §6f — fresh connection per
  call (same as update/delete), `UID STORE ±FLAGS.SILENT (\Junk)` on the
  selected source folder BEFORE `UID MOVE`, so the flag applies at
  current coordinates. No deferred flag queue; next sync's flag-diff is
  the reconciliation net. POP3: local-only (no server flags/folders).
- Local order mirrors update.rs: flag write before move so `\Junk` rides
  the row copy; `move_messages` re-keys snooze rows — a parked message
  stays parked in Junk.
- `SetJunkView { junk, flagged, moved, targetFolderId?, moves[] }` —
  `moves` carries `{fromFolderId, fromUid, toUid}` per leg because refs
  span folders and uids are folder-scoped (flat uid map would collide).
- Audit: `messages-junked` / `messages-unjunked` with counts.

### Rules TS wrappers — the T-200 seam gap

`kiwi.ts`: `RuleMatchOp`, `RulePredicate` (full `{"kind"}` union —
sender/recipient/subject/attachment_name/header/body_contains/all/any/
not/always), `RuleAction` (`{"do"}` union), `RuleView`, `RuleHitView`,
`RulesApplyView`, `PreviewHitView`, `RulePreviewView`,
`SetJunkMoveView`, `SetJunkView`.

`ipc.ts`: `rulesList(accountId?)`, `rulesUpsert(rule)`, `rulesDelete`,
`rulesApplyNow`, `rulesHits`, `rulesPreview`, `setJunk` — every rules
command from §6d now has a typed wrapper.

`ipc.md` §6f documents the junk contract (flag timing, folder
resolution, idempotence, snooze interaction).

### Gates at completion

- `cargo test -p kiwi-app` — 106/106 (3 new junk tests: flag+move
  roundtrip via POP3, direction edges, refs validation/ownership).
- `cargo test -p kiwi-mail` — 203/203.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `npx tsc --noEmit` — clean. `rustfmt --check` on touched files — clean.

### Cross-agent unblock (flagged)

- `kiwi-mail/src/store/queries.rs` — T-261's `stage_attachment` called
  an unwritten `attachment_bytes_from_mime`; wrote it (re-parse stored
  MIME, exact-filename match, invalid-input on miss — caller already
  bounds existence/ambiguity/size).
- `kiwi-sandbox/src/wsl2.rs` — 3 test `SandboxSpec` literals lacked the
  new `link_url`/`evidence_reasons` fields; added `None`/`Vec::new()`
  per the `null.rs` precedent.
- `kiwi-app/src-tauri/src/commands/sandbox.rs` — spliced `use` inside
  `require_available` + stray EOF brace + `FolderEntry` `.copied()` on
  a Clone-only type; fixed. `state.rs` `configured_sandbox` move-order
  hoisted. (Owner was mid-write; several of these self-resolved —
  my edits were the overlap.)
- `mailbox.tsx` — `MessageAttachmentView.filename` became `string|null`
  under another agent; `placeholder={a.filename ?? undefined}`.

### Assumptions / risks

- Junk flag push is immediate (per-call conn), not "next sync push" —
  chose the delete.rs/write-through pattern; documented in §6f.
- Un-junk destination is always INBOX (no origin tracking — Junk rows
  don't carry `from_folder`; adding it for a rare restore-precision
  nicety wasn't in scope).
- Junking a parked message keeps the snooze (releases inside Junk).
- `SandboxSessionRecord.report` dead-field cleared by owner's own fix.

---

## T-264 — folder exists/unseen counts (IPC-6 follow-up)

**Store** — `MailStore::folder_stats(folder_id) → FolderStats {exists, unseen}`:
one indexed `COUNT(*)` per call; `unseen` = rows without a `\Seen` token via
padded-token `LIKE '% \Seen %'` — space-separated `flags` column, so padding
makes the match exact and SQLite's ASCII case-insensitive LIKE matches IMAP
flag semantics. No wildcards in `\Seen`. Literal store counts: snoozed rows
count (defer ≠ suppress), `\Junk` doesn't affect `unseen`, moves carry the
flags so counts travel.

**App** — `FolderView` gained `exists`/`unseen` (non-optional). `From<&
FolderMeta>` deleted in favor of `FolderView::from_meta(meta, stats)` —
the ctor *requires* a real count, so fabricated zeros are unrepresentable
(the exact trap A20's withdrawal note warned about). `list_folders_impl`
runs `folder_stats` inside the existing per-folder meta loop (N+1 → N+2
queries; folders are tens, trivial).

**Contract** — ipc.md §6 `kiwi_list_folders` amended back: `exists`/`unseen`
are real `COUNT`s over stored rows, always fresh at call time; parked mail
counts toward both; badge reads `unseen`. TS `FolderView.unseen` promoted
from `?:` to required + `exists` added — the sidebar badge
(`accounts.ts` `f.unseen ?? 0`) picks it up with zero view changes.

**Tests** — store-level `folder_stats_counts_seen_and_unseen_and_moves`:
seen/unseen mix, empty folder, `\Seen` set/clear (case-insensitive), junk
flag orthogonality, move carrying counts across folders, delete dropping
`exists`, parked-still-counted. App-level `list_folders_reports_exists_
and_unseen`: wire shape end to end through `list_folders_impl`.

**Gates** — `kiwi-mail` 205/205, `kiwi-app` 125/125, workspace clippy
`-D warnings` clean, `tsc` clean, fmt clean.

**Cross-agent unblock** — `queries.rs::message_exists` (in-flight) missed
the `rusqlite::Error → MailError` conversion; added `Ok(...?)`. The e2e
send-test wedge (DATA terminator stall hanging the suite >60s) was
diagnosed + reported — owner landed `TRANSCRIPT_STEP_TIMEOUT` + the fix;
suite now exits clean.



## 2026-09-25 — T-319 local folder management

**Status:** COMPLETE. Folder management is real for **local store folders**;
IMAP server-folder CRUD is explicitly not implemented and is documented as a
deeper sync gap rather than faked.

### Store / schema

- Schema v17 adds `folders.parent_id` and checked
  `folders.origin IN ('remote','local','system')`; the migration preserves ids
  and rows, rebuilds the old account-wide unique constraint into a
  case-insensitive per-parent identity, and classifies canonical mailbox names
  as `system` while other pre-existing sync rows stay `remote`.
- `FolderOrigin` / `FolderMeta` are public typed store values. Smart views
  (Unread, Snoozed, Starred, categories) remain derived, not `folders` rows,
  so they have no id and are non-deletable by construction.
- New store methods: `create_local_folder`, `rename_local_folder`,
  `delete_local_folder`, plus `ensure_target_folder` so T-309 mbox import can
  still target an existing synced folder while new import destinations are
  honestly classified local.
- Validation: trimmed non-empty, ≤255 bytes, no `/`, `\\`, control chars,
  `.`/`..`, reserved system names, or case-insensitive sibling duplicates.
  Parent must be a local folder on the same account. Remote/system rows are
  immutable. Delete fails closed for messages or child folders.

### IPC / TypeScript

- New lock-gated commands in `commands/folders.rs`:
  `kiwi_folder_create(accountId,parentId?,name)`,
  `kiwi_folder_rename(accountId,folderId,newName)`, and
  `kiwi_folder_delete(accountId,folderId)`. Every command checks account
  ownership/existence, records an audit intent before the effect, updates the
  persisted folder index, and returns store-derived counts.
- `FolderView` now carries `parentId` and `origin`; TS `FolderView` matches.
  `ipc.ts` exposes `createFolder`, `renameFolder`, and `deleteFolder`.
- `kiwi_list_folders` now reads the authoritative store folder list rather
  than depending on the sidecar index, so a newly created local folder is
  visible even if index population later diverges.

### Honest non-goal

No IMAP CREATE/RENAME/DELETE, LIST reconciliation, UIDVALIDITY/parent
semantics, capability probing, or offline/conflict policy is claimed. The
contract (`ipc.md` §6, T-319) files that deeper sync question explicitly.

### Tests / gates

- Store: v16→v17 preservation/classification + full local CRUD/ownership/
  validation/fail-closed matrix.
- App: real `AppState` + audit log + index create/rename/delete, cross-account
  denial, system immutability.
- `cargo test -p kiwi-mail --lib` — **227/227**.
- `cargo test -p kiwi-app` — **184/184**.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.
- `kiwi-app: npx tsc --noEmit` — clean.
- `python tests/tools/copy_overlap.py` — OK, `hits=0`.
- `python tests/tools/secret_scan.py` — OK, `hits=0`.

No UI was added; the typed IPC is the handoff to the UI agent.


## 2026-09-25 — T-324 `kiwi_audit_events` read IPC

**Status:** COMPLETE. A25's T-323 Security Center view now has a real,
lock-gated backend over the existing app-audit channel.

### Actual store schema (no invented fields)

The client audit store is the hash-chained `audit.jsonl`, not a SQL table. Its
real record schema is `{seq, ts_unix, action, detail, prev, hash}`. The
`AuditEventView` projection therefore maps only persisted facts:

- `action` → `event`
- `ts_unix` → `atUnix`
- verbatim `detail` → `detailJson` (often plain text, not a JSON object)
- `actor` / `subjectId` → explicit `null` because the store has no such
  columns; nothing is synthesized as `system` or `user`

### IPC / pagination

- Registered `kiwi_audit_events(beforeUnix?, limit?)`; the audit reader runs
  the standard lock gate first because the trail is device-owner sensitive.
- `beforeUnix` is an exclusive `ts_unix` keyset cursor. Results are newest
  first and the reader stops at the bounded result count.
- `limit` defaults to 100 and clamps to 1–500. Negative cursors are
  `invalid-input`; an absent log returns `[]`; malformed persisted rows fail
  closed as `audit-corrupt` instead of silently under-reporting.
- `ipc.md` §8 now documents the real JSONL schema and nullable fields.
  `kiwi.ts` / `ipc.ts` expose the nullable `AuditEventView` and existing
  `api.auditEvents(beforeUnix, limit)` wrapper, ready for A25.

### Tests / gates

- Store-level: absent → empty; real rows newest first; exclusive cursor;
  verbatim detail; no fabricated actor/subject.
- Command-level: 600 persisted rows clamp to 500; negative cursor rejected;
  keyset page returns only strictly older rows; locked endpoint is denied.
- `cargo test -p kiwi-app` — **203/203**.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.
- `kiwi-app: npx tsc --noEmit` — clean.


## 2026-09-26 — T-334 search operators + T-341 conversation mute

**Status:** DONE for both. Both tasks were landed-but-unverified in the
working tree when the runtime restarted (no status entries existed); this
session verified the tree, found and fixed two real gaps, and ran the
full gate matrix.

### T-334 — fielded operators over the FTS path

`kiwi-mail/src/search.rs` rewritten around `ParsedSearch { terms,
predicates }`: free text still runs through FTS5 (`plain`, `"phrase"`,
`-negated`, `body:`/`text:`/`snippet:` scope); `key:value` operators
become real-column predicates AND-ed with the FTS terms:

- `from:`/`to:`/`subject:` — case-insensitive LIKE substring with
  `ESCAPE '\'` (literal `%`/`_`/`\`), bound parameters only.
- `has:attachment` — `has_attachments` column.
- `is:unread`/`is:read`/`is:starred`/`is:flagged` — padded-token flag
  match (same rule as `folder_stats`).
- `before:`/`after:YYYY-MM-DD` — strict calendar parse (`time` crate);
  `before:` is exclusive UTC midnight, `after:` inclusive.
- `in:`/`folder:` — folder-name EXISTS match, `COLLATE NOCASE`, ANDs
  with a `folderId` scope.
- `-` negates an operator (`-is:unread`). Honest fallback preserved:
  unknown operators AND known-operators-with-malformed-values
  (`before:tuesday`, `has:cheese`, `is:sent`, empty `from:`) fall
  through to the FTS path as literal text — nothing typed is silently
  dropped. Filters-only queries skip the FTS join entirely.
- Bound unchanged: `MAX_QUERY_TERMS`=8 shared across terms+predicates;
  `MAX_RESULTS`=200.

**Found + fixed this session:** negated predicates on NULL columns were
SQL-tri-state wrong — `NOT (m.from_addr LIKE ?)` on a NULL sender
evaluates NULL and *drops* the row, so `-from:boss` hid mail whose sender
failed to parse. `nullable_column()` now emits `col IS NULL OR NOT (…)`
for `from`/`to`/`subject`/`before`/`after`; new test
`negated_predicate_keeps_null_column_rows` pins it. Also corrected the
ipc.md limit line (command clamps 1–500 but the engine's effective page
cap is 200 — documented the truth).

UI (`views/search.tsx`): the full grammar now reaches the server (the
old client-side has:/folder: post-filters are deleted); the local
fallback mirrors each operator over envelope fields (to: stays
server-only, noted in-view); chips/placeholder/`?`-overlay updated.
`commands/mail.rs` doc comment reflects the real grammar.

### T-341 — conversation mute (Ignore Thread)

Store-owned conversation identity: `kiwi-mail/src/threading.rs` ports the
list view's subject fold verbatim (`Re:`/`Fwd:`/`Fw:`/`Aw:`/`Sv:` ≤8
passes, one `[list-tag]` ≤40 chars, case-fold + whitespace-collapse, None
when no signal) so the muted set is exactly the set the UI groups — the
honest subject-fold limitation is documented in the module, ipc.md
§6b-ii, and threading.rs.

- Schema v18: `messages.conversation_key` (materialized at ingest in
  `upsert_message`, INSERT-only — conflict path can't re-point a row) +
  `idx_messages_conversation` + bounded `backfill_conversation_keys` +
  `muted_conversations(account_id, conversation_key, muted_at_unix)` —
  deliberately NOT FK'd to messages (mutes outlive their rows and
  suppress future arrivals); account cascade only.
- Suppression: `folder_stats` `unseen` excludes muted conversations
  (exists stays the honest total; smart badges derive for free);
  `total_unseen` (tray) same predicate; `muted_uids_in` is the notify
  seam (chunked 400-uid IN list, join through folders for the account).
- `notify.rs`: `maybe_notify` resolves muted arrivals from the store and
  `decide()` gained `muted_thread` — an all-muted batch is an explicit
  suppressor, not a side effect of an emptied vec.
- IPC: `kiwi_thread_set_muted` / `kiwi_thread_list_muted` —
  lock-gated, composite `conversationId = "accountId\n<folded subject>"`
  re-normalized server-side (renderer can't smuggle a non-canonical
  key), unknown account → not-found, idempotent with honest `changed`,
  audited as `thread-muted`/`thread-unmuted` (key, never subject).
  `ThreadMuteView` + TS wrappers (`threadSetMuted`/`threadListMuted`).
  UI seam deferred per contract (context-menu item → next UI pass).

**Found + fixed this session:** `move_messages`/`copy_messages`
re-INSERTed rows without `conversation_key` — moved muted mail silently
lost suppression. Both now carry the stored key verbatim (insert #17);
new test `a_mute_survives_its_messages_being_moved` covers move + copy.

### Gates at snapshot

- `cargo test -p kiwi-mail` — **257/257** (+2 this session).
- `cargo test -p kiwi-app` — **234/234** (thread cmd + notify tests).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — my files clean; ONE foreign diff
  remains in `commands/pair.rs:464` (A11's active T-282 file — their
  `decision`-field compile break self-resolved while I watched; the
  format! wrap is theirs to land).
- `kiwi-app: npx tsc --noEmit` — clean.

### Cross-agent / merge notes (Lead)

- Everything below is **uncommitted** in the shared tree — fleet
  convention is Lead-sweep; file map for attribution:
  - **T-334 mine:** `kiwi-mail/src/search.rs`, `kiwi-app/src/views/
    search.tsx`, `kiwi-app/src/components/shortcuts.tsx` (operator row),
    `commands/mail.rs` (search doc hunk only), ipc.md search section.
  - **T-341 mine:** `kiwi-mail/src/threading.rs`, `store/threads.rs`;
    `store/schema.rs` v18 hunks; `store/mod.rs` (conversation_key
    column/backfill fns); `store/queries.rs` (key materialization,
    folder_stats suppression, move/copy carry); `commands/thread.rs`,
    `types/thread.rs`; `notify.rs` (mute seam + decide arg); `lib.rs`
    (2 registrations), `commands/mod.rs`/`types/mod.rs` (mod decls);
    `ipc.ts`/`kiwi.ts` (thread wrappers + ThreadMuteView); ipc.md §6b-ii.
  - **Also mine, ledger-done, still uncommitted:** T-330 diagnostics.rs
    + commands/storage.rs + types/storage.rs; T-319 store half (schema
    v17, FolderOrigin, folder CRUD, FolderView parentId/origin).
  - **Foreign hunks inside shared files (not mine):** queries.rs
    `rename/delete_remote_folder` + `total_unseen` (T-328/T-345);
    schema.rs `message_parts` v19 (A19 T-339); sync.rs `is_attachment_
    leaf`/`disp_params` (T-339); lib.rs tray/send_consent/lock_matrix
    registrations; state.rs notifier/tray/consent fields; ipc.ts/kiwi.ts
    tray wrappers; types/system.rs `decision`/`audit_ok`/`tray_available`.
- `lm*.txt` scratch files in root are foreign debris — untouched.

### Assumptions / risks

- `conversation_key` derives from envelope `subject` at ingest — a
  subject edited post-store (impossible today) would diverge; the
  conflict-clause freeze is deliberate.
- `in:`/`folder:` matches folder *names* across accounts (a folder named
  "Work" on two accounts is one filter, matching Thunderbird semantics).
- `is:` vocabulary is deliberately narrow (unread/read/starred/flagged) —
  `is:sent`/`is:muted` degrade to literal text, documented in ipc.md.
- Negated-only operator queries (`-from:x` alone) are legal — predicates
  anchor — and return every non-matching row, bounded as usual.

### Committed (Lead-directed surgical staging, 2026-09-26)

Lead verified the claims and directed self-commit with hunk-level staging.
Done via per-hunk `git apply --cached` patches (helper: `.git/a15/stage.py`,
repo-internal scratch, not tracked):

- **`c24b774`** — `A15 → T-319+T-330 unswept halves`: schema.rs v17 folders
  DDL, mod.rs v17 migration + folder mgmt fns + T-319 tests, diagnostics.rs,
  commands/storage.rs, types/storage.rs, storage mod decls + registrations,
  types/mail.rs FolderView parentId/origin, ipc.md storage sections.
  (Side effect: fixes committed-but-unwired refs — HEAD's mod.rs already
  used `MailError`/`FolderOrigin`/`create_local_folder` without the schema.)
- **`d5e8d9a`** — `A15 → T-334+T-341 search operators + thread mute`:
  search.rs (full T-334 rewrite + NULL-safe negation fix), threading.rs,
  store/threads.rs, schema.rs v18 (conversation_key + muted_conversations),
  mod.rs v18 migration + backfill + mute-aware test edits, queries.rs
  (upsert key materialization, folder_stats + total_unseen suppression,
  move/copy carry — T-328 `*_remote_folder` fns excluded, A19's),
  commands/thread.rs + types/thread.rs, notify.rs mute seam,
  commands/mod.rs + types/mod.rs thread decls, lib.rs thread regs,
  mail.rs search doc hunk, ipc.ts thread wrappers, kiwi.ts ThreadMuteView,
  views/search.tsx, components/shortcuts.tsx, ipc.md search § + §6b-ii +
  tooltip wording. `pub mod threading` in kiwi-mail/lib.rs folded in via
  --amend (initially missed — would have broken the committed crate).

Left uncommitted (foreign, by design): queries.rs T-328 fns; mod.rs
copy_messages_* tests + stray blank line; commands/mod.rs lock_matrix +
audit_ok; types/mod.rs T-260 tests; types/mail.rs T-316 hunks; lib.rs
notify/send_consent/tray/export-import/folder/copy/audit/forensics wiring;
mail.rs T-329 hunks; ipc.ts `decision` (T-282); ipc.md foreign sections;
state.rs/syncer.rs/prefs.rs/system.rs/pair.rs/etc.

**Post-commit verification on committed state:** `cargo test -p kiwi-mail
--lib search` 15/15, `threading` 6/6, `threads::` 10/10 (incl.
a_mute_survives_its_messages_being_moved); `cargo test -p kiwi-app --lib
commands::thread` 5/5, `notify` 6/6. Lead-flagged foreign failures
(parts.rs base64, rules/blocklist idempotent, testutil EOF) untouched
and unstaged as instructed.

A concurrent foreign staging race was observed mid-commit (A25 UI pass#5
files entered the index while I was staging); foreign entries were
unstaged before committing — `git show` audit confirms zero foreign
content in either commit.
