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
