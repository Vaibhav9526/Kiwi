# Agent 7 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-20 — T-164 completion: §11 query params + live auth threading

**Status:** implemented + verified. `cargo test -p kiwi-app` → 46/46
green (3 new); clippy `-p kiwi-app --all-targets --no-deps` + fmt clean.

Agent 6's forensics.md §11 is now the binding contract for the Security
view seam. Conformance:

- **`kiwi_security_findings` ≡ `list_findings`**: gained `severity`
  (`info|low|medium|high|critical`; unknown → `invalid-input`, never
  silently dropped) and `limit` (default 100, clamp 1000) params,
  ANDed with `accountId`. Sort changed to the binding total order:
  severity weight desc → `observed_at_unix_ms` desc → `rule_id` asc →
  `subject_key` asc. `kiwi_security_report` deliberately does NOT reuse
  the limited path — it aggregates the full retained set (a 1000-cap
  would silently truncate reports).
- **`kiwi_security_events` ≡ `list_events`**: gained `accountId` filter
  (sessions already carry it — was client-side-filtered before).
- **`kiwi_finding_detail` ≡ `finding_detail`**: already implemented per
  §11 (Agent 6 recorded the command name in the contract).
- **Live auth threading** (the T-164-adjacent item): `observe.rs` now
  builds `LiveAuthObservation` from `ctx.auth_mechanism`/`auth_succeeded`
  per the §11 mapping — core spelling → `AuthMechanism::from_token`,
  `none` → absent (AUTH rules stay silent for unauthenticated
  connections, as designed), `client-cert` → `External`,
  `other:<name>` → `from_token(name)` (`Unknown` on mismatch),
  `succeeded` verbatim, `attempts`/`failures` counted from the observed
  exchange. AUTH rules 001–006 are now live on the real path, not
  capture-only. The shared spelling helper (`types::auth_mechanism`)
  is `pub(crate)` so the core spelling can't drift between session
  serialization and the adapter mapping.

### Files changed

`commands/security.rs` (§11 params + sort + events accountId + 1 test),
`observe.rs` (`live_auth_of` + 2 tests), `types.rs` (`auth_mechanism` →
`pub(crate)`), `ipc.md` (§8 signatures).

## 2026-09-20 — T-169: threading headers (inReplyTo/references) on views

**Status:** implemented + verified. `cargo test -p kiwi-app` → 43/43
green (2 new); clippy + fmt clean on my files.

**Coordination honored:** Agent 8's `search.rs`/`store.rs` were actively
mid-edit (uncompilable at check time) — so this feature is deliberately
implemented WITHOUT touching kiwi-mail. Threading headers live in the
sidecar index as a derived cache (`thread_headers`, key `f<fid>:u<uid>`,
bounded 50k, crude key-order eviction). When Agent 8's work settles and
`MessageMeta` grows real columns, the cache can be replaced or left as
the join layer — both are compatible.

### How it works

- `MessageView` + `MessageBodyView` gained `inReplyTo` / `references`.
- **Sync capture** (`capture_thread_headers`, mail.rs): after each
  `sync_folder` pass — manual sync, live full pass, and IDLE-wake INBOX
  re-sync — newly-seen uids get one `UID FETCH (BODY.PEEK[HEADER.FIELDS
  (IN-REPLY-TO REFERENCES)])` per ≤200-uid chunk (≤2000 uids). Folded
  References headers parse via `mime::parse_message`. Best-effort:
  failures leave fields null, never fail sync.
- **Lazy fill** in `kiwi_list_messages`: index miss + stored body →
  parse (≤32/call) → cache + return. POP3 bodies are always stored, so
  POP3 threading fully populates on first list.
- **`load_body_raw`** records headers on every body fetch/read (get,
  render, attachment paths converge there) — idempotent, skips parse
  when the key is cached.
- `MessageBodyView.inReplyTo/references` come from the parsed body —
  authoritative, also feeds the reply composer.

### Files changed

`state.rs` (ThreadHeaders, index field, cap), `types.rs` (2 view
fields each), `commands/mail.rs` (capture + lazy fill + `list_messages_impl`
extraction + 2 tests), `syncer.rs` (capture in live pass + IDLE wake),
`ipc.md` (§6a shape + provenance note).

### Known gaps added

- Messages with no stored body AND no post-feature sync pass show
  `null`/`[]` until either happens — acceptable for a derived cache.
- Index eviction is key-order, not LRU — crude bound; documented.

## 2026-09-20 — T-163 delete/move IPC + T-164 finding detail

**Status:** implemented + verified. `cargo test -p kiwi-app` → 41/41
green (7 new); `clippy -p kiwi-app --all-targets --no-deps` clean;
`rustfmt --check` clean on my files. **Caveat for Lead:**
`cargo test -p kiwi-mail` currently fails 5 tests — all in Agent 2's
in-flight `search.rs` FTS5 module (quoted-phrase parsing, bare `-`
negation, `NOT` in MATCH grammar). Not mine; left for its owner. My
kiwi-mail additions all pass (`move_messages_remaps_uids_and_moves_payloads`,
`outbox_*`, `delete_account_*`).

### T-163 — `kiwi_delete_messages` + `kiwi_move_messages`

- **Store** (`kiwi-mail/store.rs`): `list_folders(account_id)` (name
  order — trash discovery + pickers) and `move_messages(src, dst, uids)`.
  Move re-inserts each row under a **fresh dst uid** (UID COPY semantics —
  uids never reused across folders), relocates the body file +
  attachment dir, then deletes the source row. Crash order is
  dst-then-src: worst case a duplicate the next sync reconciles, never a
  loss. Returns `Vec<(src_uid → dst_uid)>`.
- **`kiwi_delete_messages(accountId, folderId, uids, permanent?)`** —
  uid set bounded 500. Soft: move to Trash — resolved local-name →
  server `\Trash` LIST flag → `CREATE "Trash"`. Hard — `permanent` OR
  source IS the trash (empty-trash): `\Deleted` + `EXPUNGE`. IMAP
  write-through via `uid_move`/`uid_store`+`expunge`; POP3 local-only.
  Returns `{movedToTrash, deleted, trashFolderId, uidMap}`.
- **`kiwi_move_messages(accountId, srcFolderId, dstFolderId, uids)`** —
  cross-account guard per Agent 5's note: BOTH folders must resolve on
  `accountId` (`owned_folder` on each → foreign id = `not-found`); src≠dst
  enforced. IMAP `UID MOVE` + local move; POP3 local-only.
- Both audited (`messages-deleted` / `messages-moved`) and IMAP sessions
  journaled (`imap delete` / `imap move`).

### T-164 — `kiwi_finding_detail(findingId)`

The forensics feed already existed (`kiwi_security_findings`,
`kiwi_security_events`, `kiwi_session_detail`, `kiwi_security_report` —
all real `kiwi.forensics/1` data). The missing piece was per-finding
detail for the dialog (KIWI-UI-004): full `Finding` (evidence, impact,
remediation) + the producing session (nullable — findings outlive the
bounded session ring on purpose) + that session's signals + sibling
finding ids. Joined via `finding.subject.session_id`. Unknown id →
`not-found`.

### Files changed

`kiwi-mail/src/store.rs` (list_folders, move_messages + test),
`commands/message.rs` (delete/move + 5 tests), `commands/security.rs`
(`kiwi_finding_detail` + 2 tests), `types.rs` (DeleteResultView,
MoveResultView, FindingDetailView), `lib.rs` (3 registrations — 36 total),
`ipc.md` (§6b + §8).

### Cross-agent notes (flagged for Lead)

- Agent 2's `search.rs` landed mid-session twice in broken states — I
  applied mechanical fixes only (missing `Scoped`→`Subject` variant,
  `conn_for_test` → new `pub(crate) MailStore::conn()`, unclosed
  `mod tests` + duplicate `#[cfg(test)]`). Remaining 5 test failures are
  real logic gaps in their FTS5 module — theirs to finish.
- `store.root` is private — my test reads it (same-module access); fine.

### Known gaps added

- Trash resolution guesses by name/special-use only — a custom-named
  trash folder the server doesn't flag `\Trash` will miss and create a
  parallel "Trash". Acceptable: RFC 6154 servers flag it; others get a
  working Trash.
- `move_local` (T-146 archive path) still same-uid re-inserts while
  `move_messages` remaps — intentional (archive preserves the archive
  test's uid expectations); converging them is cosmetic.
- Findings/sessions are bounded in-memory rings — detail lookup after
  eviction returns `session: null` by design.

## 2026-09-20 — T-157: live sync engine (IMAP IDLE + POP3 poll)

**Status:** implemented + verified. `cargo test -p kiwi-app` → 34/34
green (5 new syncer tests); `clippy -p kiwi-app --all-targets --no-deps`
clean; `cargo fmt -p kiwi-app --check` clean.

### What was built

New module `syncer.rs` — supervisor + per-account workers:

- **Supervisor** (`sync_supervisor`, spawned in `setup()`): 2 s reconcile
  tick — spawns a worker for every `index.account_ids` entry without one,
  reaps finished handles, prunes status for removed accounts.
- **Workers are dedicated `std::thread`s** each with a current-thread
  tokio runtime — kiwi-mail clients are `!Send` inside futures (the
  `run_mail_io` constraint), so they can't live on the command runtime.
  Emission crosses back via a `Arc<dyn Fn(&MailChangedEvent)>` — `app.emit`
  in production, capture vec in tests.
- **IMAP worker** (`imap_live`): `connect_imap` → full `sync_folder` pass
  over all listed folders (cap 64) → record session once (`"imap live"`)
  → `SELECT INBOX` → `idle_collect` 30 s cycles. Any EXISTS/EXPUNGE/FETCH
  untagged notification → `sync_folder` INBOX → `mail-changed` emit +
  §11 received events (same session's tls_label/security_status reused —
  same connection, same facts).
- **POP3 worker**: reuses `pop3_sync` (connect→auth→sync→observe→§11 emit
  all inside) every 60 s; emits `mail-changed` only on actual changes.
- **Lock**: workers pause while `Locked` — checked before connect, and a
  worker that notices the lock mid-IDLE logs out rather than holding an
  authenticated session. Account-existence is checked BEFORE the lock so
  removal still kills a paused worker.
- **Backoff**: 5 s doubling to 120 s cap; `interruptible_sleep` wakes
  early on lock or account removal.
- **`kiwi://mail-changed`**: `{accountId, folder?, folderId?, reason:
  sync|idle|poll, newMessages, flagUpdates, expunged, atUnix}`. `"sync"`
  emits unconditionally after the connect pass (UI's initial-sync signal);
  `idle`/`poll` only on real changes.
- **`kiwi_sync_status(accountId?)`** — 33rd registered command, gated.
  Per-account `{state, lastSyncUnix, lastError, nextRetryUnix,
  foldersSynced, newMessages, attempts}`; missing worker → `"pending"`;
  unknown id → `not-found`.

### Files changed

`syncer.rs` (new), `state.rs` (`AccountSyncStatus` + `sync_status` map),
`types.rs` (`MailChangedEvent`, `SyncStatusView`), `commands/mail.rs`
(`collect_received`/`emit_received`/`pop3_sync` → `pub(crate)` for worker
reuse; `kiwi_sync_status`), `lib.rs` (mod + supervisor spawn + command —
33 total), `ipc.md` (new §6c + header task list).

### Cross-agent fixes (flagged for Lead — workspace was mid-edit)

- `kiwi-forensics/pcap/reassembly.rs:336` — typo `Some(end)` →
  `Some(start + length)` (hard compile break, one line).
- `kiwi-mail/search.rs` (Agent 2's new FTS5 module, mid-flight):
  `SearchColumn::Scoped` variant didn't exist → `Some(Self::Subject)`;
  production code called `#[cfg(test)]` `conn_for_test` → added
  `MailStore::conn()` as `pub(crate)` and pointed the call there.

### Tests added (5)

- `backoff_progression` — 5/10/20/40/80/120 cap shape.
- `mail_changed_event_shape` — camelCase wire shape.
- `worker_pauses_when_locked_never_connects` — locked endpoint: status
  `paused-locked`, zero sessions journaled (no credential use).
- `worker_marks_backoff_on_refused_connect` — real worker thread vs
  127.0.0.1:1 → `backoff` + `nextRetryUnix` + attempts=1.
- `worker_exits_when_account_removed` — clean `stopped` exit + join.

### Known gaps added

- IDLE watches INBOX only — non-INBOX folders refresh on the connect-time
  pass and on the next reconnect; per-folder IDLE or periodic fan-out is a
  follow-up if the UI needs it.
- Lock-pause latency is bounded by the 30 s IDLE cycle, not instant.
- `kiwi_sync_account` (manual) doesn't share the worker's connection —
  it opens its own; both paths record sessions independently (honest —
  they ARE separate connections).
- No e2e IDLE test yet — needs the fixture IMAP server (T-147, Agent 6).

## 2026-09-20 — T-142 done properly: SQLite outbox + send-later reschedule

**Status:** implemented + verified. `cargo test -p kiwi-mail -p kiwi-app`
→ 67/67 + 29/29 green; `clippy -p kiwi-app --all-targets --no-deps` clean;
`rustfmt --check` clean on every file I touched.

Owner note: TASKS.md lists T-142 under Agent 2 (`kiwi-mail/`); Lead
re-dispatched it to me spanning kiwi-mail + src-tauri. Agent 2 was
concurrently editing kiwi-mail mid-session — we converged: their
`list_accounts`/`delete_account`/`outbox_due`/`outbox_next_due_at` landed
alongside my `outbox` table without conflict, and I wired
`kiwi_remove_account` → `store.delete_account` (closes a documented gap).

### What changed

- **kiwi-mail `store.rs`** — schema v2: `outbox` table (queue_id PK,
  account_id FK cascade, from/to/subject/message_id, `mime BLOB` in-row,
  not_before/undo_until/attempts/created_unix). In-row MIME makes a
  committed send ONE atomic write — no torn meta/body pair. API:
  `outbox_put` (INSERT OR REPLACE), `outbox_list(limit)` (corrupt rows
  skipped, never fatal), `outbox_set_timing`, `outbox_delete`.
- **kiwi-mail `smtp.rs`** — `SendQueue::reschedule(queue_id, not_before)`;
  `cancel` semantics widened: recallable while `now < undo_until` **or**
  `now < not_before` — a send-later item must be deletable until its slot,
  not just inside a 10 s undo window.
- **src-tauri `state.rs`** — file-based `outbox/*.json|.eml` persistence
  replaced by the store table; `reload_outbox` imports legacy files once
  (bounded 256/32 MiB/100 MiB, then deletes them) → `outbox_list` rebuild
  of queue + meta map. `open_test` switched to a real file-backed
  `MailStore` so restart-resume is exercised honestly.
- **src-tauri `send.rs`** — persist = `outbox_put` before enqueue (32 MiB
  bound kept); terminal paths → `outbox_delete`; retry backoff →
  `outbox_set_timing`. New command `kiwi_schedule_send(queueId,
  sendAtUnix)` (32 total) — reschedules any still-queued send; undo window
  untouched; audited. `cancel_impl`/`schedule_impl` extracted for tests.
- **`kiwi_remove_account`** now calls `store.delete_account` (cascade +
  payload sweep) — no more orphaned config row.
- **ipc.md §7/§12** — `kiwi_schedule_send` documented; cancel rule
  precise; persistence note rewritten for the SQLite design.

### Cross-agent fixes (flagged for Lead)

- `kiwi-forensics/src/pcap/reassembly.rs:336` — one-line typo fix
  (`cursor = Some(end)` → `Some(start + length)`); it was a hard compile
  error in Agent 6's dirty file blocking the whole workspace build.
- Transient test failure `delete_account_cascades…` was a mid-edit
  snapshot of Agent 2's code — passes on current tree.

### Tests added (4 new in kiwi-app, 29 total)

- `outbox_survives_reopen` — extended: restart-resume dispatch at the
  persisted `not_before` slot.
- `enqueue_then_cancel_within_grace` — now asserts the SQLite row is
  deleted with the queue entry + double-cancel no-op.
- `scheduled_send_recalled_past_undo_window` — send-later recallable until
  its slot even with undo window closed.
- `reschedule_moves_dispatch_and_persists` — `not_before` moved in queue +
  row; unknown id → `not-found`.
- `legacy_file_outbox_imported` — pre-SQLite files fold into mail.db and
  are removed.

### Known gaps added

- `outbox_next_due_at`/`outbox_due` (Agent 2's additions) are unused by my
  dispatcher — it drains via the 1 s tick + in-memory `due()`, which is
  correct but leaves a smarter store-driven wake-up on the table.
- Undo-send window remains per-send (`undoGraceSecs` opt); no global
  account-level default knob yet.

## 2026-09-20 — Session restart: re-verified T-146 + T-142, no work outstanding

**Status:** verified, no changes needed. Resume prompt listed T-146/T-142
as remaining, but both were completed and logged in the prior session.
Re-verified this session:

- All 4 T-146 commands registered in `lib.rs` (31 total) and lock-gated
  (`gate()` first statement in each: `message.rs` lines 59/291/394/559).
- `ammonia` 4.x + `mail-parser` 0.11 deps present in `Cargo.toml`.
- Outbox persistence wired in `send.rs`; `outbox_survives_reopen` green.
- `cargo test -p kiwi-app` → **26/26 pass** (4.09s), clean compile.
- `ipc.md` §6b/§7/§12 already document the new surface.
- `git status`: only foreign files dirty (`kiwi-app/src/*` Agent 5,
  `kiwi-autoconfig` Agent 8) — my src-tauri changes are committed.

Note: TASKS.md still lists T-144/T-146 as `open` — ledger is Lead-maintained
and stale relative to this log; both are done from the src-tauri side.
T-142's kiwi-mail-side queue work is Agent 2's scope (ledger row T-142);
the app-side persistence + undo-send + send-later wiring is complete here.

**No open Agent 7 tasks.** Awaiting next assignment from Lead.

## 2026-02-14 — T-146 + T-142: message actions + outbox persistence

**Status:** implemented + verified. `cargo check -p kiwi-app` clean,
`cargo test -p kiwi-app` 26/26, `cargo clippy -p kiwi-app --all-targets
--no-deps -- -D warnings` clean (`--no-deps` needed: kiwi-forensics has
~35 deny-lint errors in its in-flight `pcap/` code — another agent's crate,
left untouched), `cargo fmt -p kiwi-app --check` clean.

### T-146 — message actions (new module `commands/message.rs`, all gated)

- `kiwi_update_message(accountId, folderId, uid, {seen?, starred?,
  archived?})` — tri-state patch. Flags write-through: live IMAP
  `UID STORE ±FLAGS.SILENT` first, then `store.update_flags` (local truth
  for the list view; next sync reconciles). POP3 accounts → local-only.
  `archived:true` → IMAP `UID MOVE` (MOVE-capable) or kiwi-mail's
  COPY+Deleted+EXPUNGE fallback, with `CREATE Archive` if absent; local
  move copies the meta row + body file into the archive folder then
  deletes the source row. `archived:false` → INBOX. Audited.
- `kiwi_download_attachment(accountId, folderId, uid, attachmentIndex,
  destPath)` — `mail-parser` re-parse of the stored body (kiwi-mail's
  `AttachmentMeta` is metadata-only; bytes come from the raw MIME).
  ≤50 MiB decoded bound, destPath refused inside `data_dir`, parents
  created, audited. Filename/content-type from the MIME part.
- `kiwi_render_body(accountId, folderId, uid)` — `ammonia` 4.2 (new dep;
  `mail-parser` 0.11 added too, same version kiwi-mail uses). Strict
  allowlist — script/style/iframe/form/object simply aren't allowed tags;
  `img src` filtered per-URL: cid:/data:/relative always pass, remote
  http(s) only when `remote_content_allowed` — stripped count returned
  for the UI's "allow remote content?" affordance. Output ≤8 MiB.
  javascript:/vbscript: backstop in the attribute filter.
- `kiwi_set_remote_content(accountId, allowed)` — per-account opt-in in
  `AccountMeta` (serde-defaulted false), audited.

### T-142 — outbox persistence (undo-send delay + send-later already landed)

- `data_dir/outbox/<queueId>.json` (OutboxMeta, now Serialize) +
  `.eml` (built MIME). Persist-before-enqueue so a crash can't lose a
  committed send; write-then-rename per file.
- `reload_outbox` in `AppState::open`/`open_test` rebuilds queue+meta —
  bounded (256 items / 32 MiB each / 100 MiB total), malformed files
  skipped with warn-log, never fatal.
- Retry backoff re-persists meta (`update_outbox_meta`); every terminal
  path (sent/blocked/failed/cancelled/flush) removes both files via
  `drop_outbox`.
- Semantics after restart: expired undo window → not cancelable, due
  immediately; still-valid undo window → honored. This is the correct
  "committed" reading — sends persisted while offline resume.

### Refactor

- `get_message_impl` body path extracted to `load_body_raw` (store →
  on-demand IMAP fetch → store), now shared by get/render/download.

### Files changed (this task)

`message.rs` (new), `state.rs` (outbox persist/load, `remote_content_allowed`,
`OutboxMeta` serde), `send.rs` (persist/remove/re-persist wiring),
`mail.rs` (`load_body_raw` extraction, `auth_mech_of` pub(crate)),
`accounts.rs` (meta literal), `types.rs` (5 new views), `lib.rs`
(4 commands registered — 31 total), `Cargo.toml` (ammonia 4.2,
mail-parser 0.11), `ipc.md` (§6b, §7 persistence note, §12 note), this log.

### Known gaps added

- Attachment bytes aren't on disk separately — download re-parses the
  stored MIME each time (bounded; fine at mail sizes).
- Archive uses the conventional `Archive` name — no \Special-Use list
  detection yet (kiwi-mail doesn't expose it).
- Outbox `.eml` files are message bodies at rest — same sensitivity class
  as `mail.db` bodies; covered by the same "local disk only" guarantee.

## 2026-02-14 — T-144: enforcement loop complete

**Status:** implemented + verified. `cargo check -p kiwi-app` clean,
`cargo test -p kiwi-app` 21/21, `cargo clippy -p kiwi-app --all-targets`
clean for this crate (workspace `-D warnings` currently fails inside
`kiwi-forensics`/`kiwi-autoconfig` — other agents' in-flight code, not
touched here), `cargo fmt -p kiwi-app --check` clean.

### §10 evaluate-outbound — now resolves config + env

- `bridge::resolve_endpoint` (`resolve_endpoint_with` is the pure,
  testable core): index org binding → `KIWI_ADMIN_URL`/`KIWI_ADMIN_ORG`
  env → none. Loopback enforced at resolve time for BOTH sources — a
  non-loopback env URL or binding is refused outright.
- No endpoint at all → once-per-process warn (stderr + `policy-bridge-absent`
  audit) and the send proceeds — local-first dev degrade per task brief.
- Endpoint without `org_id` (env URL without `KIWI_ADMIN_ORG`) → once-per-
  process `policy-no-org` warn; evaluation skipped, mailflow still emits.
- Configured + unreachable → unchanged fail-closed: `policy-unavailable` →
  outbox `held`, linear backoff, max 5 attempts.
- `policy.block` path now also records the connection observation (the
  SMTP session really happened — cert/TLS facts belong in the journal
  even when DATA never ran).
- Dev-auth headers on every request: `x-kiwi-subject: kiwi-client`,
  `x-kiwi-roles: org_admin` (carries `policy.read` + `mailflow.ingest`),
  `x-kiwi-org: <org>` (§12 scaffold — loopback only by construction).

### §11 mailflow emit — send + receive

- `bridge::MailflowEvent` = §6 wire shape (snake_case, metadata only).
  `build_send_attempt_events` (one per recipient, verdict from §10 result,
  unknown-normalized) and `build_received_event` (org_id nullable,
  `policy_verdict` always `unknown`) — Rust ports of the §11 builders.
- Send path (`deliver_inner`): emits on EVERY attempt outcome — sent,
  policy-blocked, transport failure. `message_id` correlates the MIME
  Message-ID (stored in `OutboxMeta`); `tls_version` is the observed
  negotiated label.
- Receive path (`imap_sync`/`pop3_sync`): per-folder UID-set delta around
  `sync_folder`/`sync_pop3` → `collect_received` pulls store metas for new
  UIDs (≤200/sync, bounded scan) → one inbound event each. Sender-less
  messages skipped (§6 requires non-empty sender).
- `security_status` = `security_status_label(observed, findings)` — maps
  finding severities only (none→clean, ≤medium→warn, ≥high→suspicious,
  unobserved→unknown); never the policy verdict (§11 honest rule).
- `emit_events`: posts each event to `POST /api/v1/mailflow/events`;
  on first failure the failed event + unattempted remainder requeue into
  `AppState.mailflow_pending` (VecDeque, 512 cap, drop-oldest) and retry
  at the head of the next emission. Emission NEVER fails send/sync.

### Files changed (this task)

`bridge.rs` (endpoint resolution, post_json w/ dev-auth headers, §11
builders, emit+pending queue, `security_status_label`, 5 new tests),
`state.rs` (`mailflow_pending`, `policy_warned`/`no_org_warned`,
`OutboxMeta.message_id`), `send.rs` (attempt-ctx refactor, warn-once
degrade, emit on all outcomes), `mail.rs` (UID-delta collect + emit on
IMAP+POP3), `ipc.md` (§7 bridge/env/emit semantics, §9 env fallback,
§12 note), this log.

### Known gaps added

- `mailflow_pending` is in-memory — events queued while admin is down are
  lost on restart (outbox too). Acceptable for v1 dev transport.
- Receive emission discovers new messages via UID-set delta — works for
  IMAP+POP3 sync but not for a hypothetical "bodies-only" refresh (no new
  UIDs → no events; correct).

## 2026-02-14 — Task correction: T-132 not mine

T-132 (sandbox eval) was reassigned to Agent 2 — dropped from my queue.
It was never touched here (no files, no code). My scope remains T-120
(IPC command layer) and T-121 (endpoint signals) — both complete below.

## 2026-02-14 — T-120 + T-121: IMPLEMENTED, all gates green

**Status:** complete. `cargo check`, `cargo test --workspace` (185 tests,
16 new in kiwi-app), `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --check` all pass. Command catalog written to
`docs/contracts/ipc.md`.

### What was built (T-120 — IPC layer)

27 registered commands in `kiwi-app/src-tauri/src/lib.rs`
(`IPC_CONTRACT_VERSION = "kiwi.ipc/1"`):

- **system/lock path (gate-exempt):** `kiwi_ping`, `kiwi_app_info`,
  `kiwi_security_status`, `kiwi_lock`, `kiwi_request_challenge`,
  `kiwi_submit_challenge`
- **accounts:** `kiwi_list_accounts`, `kiwi_add_account`,
  `kiwi_remove_account`, `kiwi_test_account`, `kiwi_verify_server`
- **mail:** `kiwi_list_folders`, `kiwi_list_messages`, `kiwi_get_message`,
  `kiwi_sync_account`
- **send/outbox:** `kiwi_send_message`, `kiwi_cancel_send`,
  `kiwi_list_outbox`, `kiwi_flush_outbox` + 1s background dispatcher
  emitting `kiwi://outbox` events
- **security data:** `kiwi_security_findings`, `kiwi_security_events`,
  `kiwi_session_detail`, `kiwi_security_report`
- **devices/org:** `kiwi_register_device`, `kiwi_list_devices`,
  `kiwi_revoke_device`, `kiwi_set_org_binding`
- **endpoint:** `kiwi_collect_endpoint_signals` (exempt — feeds trust)

New modules:

| file | role |
|------|------|
| `error.rs` | `IpcError { code, message }` + MailError→stable-code map |
| `state.rs` | `AppState` (store, trust machine, registries, journals, outbox meta, sidecar `index.json`), `refresh_trust` with documented lock order index→devices→endpoint→sessions→trust |
| `audit.rs` | append-only hash-chained JSONL audit log (tamper-evident; verified on open) |
| `credstore.rs` | `keyring` binding for `CredentialStore` (service `kiwi.mail`) |
| `verifier.rs` | `Ed25519Verifier` for `ChallengeBook::verify` |
| `observe.rs` | `TransportFacts` snapshot → `SecuritySession` → `session_signals` → live forensics adapter → `RuleEngine` findings → bounded journals |
| `signals.rs` | T-121 endpoint collector (below) |
| `bridge.rs` | loopback-only `evaluate-outbound` HTTP/1.1 client (4 s timeout, 64 KiB bound) |
| `types.rs` | all wire/view types + contract enum spellings |
| `commands/*` | `mod` (gate, validation, `run_mail_io`), `system`, `accounts`, `mail`, `send`, `security`, `devices`, `endpoint` |

### What was built (T-121 — endpoint signal collector)

`signals.rs` is a **pure collector over `ProbeInput`** (production gathers
the probe, tests inject it — deterministic, unit-tested):

- remote-session indicators: `%SESSIONNAME%` ≠ `Console` (RDP/ICA), SSH
  context env-var *names* (values never collected — they carry addresses);
- process-integrity TOFU baseline: SHA-256 + path of the running exe vs
  `endpoint-baseline.json`, mismatch → `endpoint-integrity-failure`;
- cap 32 observations/collection; every observation persisted to
  `endpoint-evidence.jsonl` and carries `evidence_ref` → the record.

`kiwi_collect_endpoint_signals` folds them into `AppState.endpoint_signals`
→ `refresh_trust` → `TrustMachine::evaluate`. Exempt from the gate so a
locked endpoint keeps reporting posture.

### Security properties wired

- **Lock gate** at the IPC boundary (`commands::gate`) — UI cannot bypass.
- **Secrets:** `kiwi/*/in|out` credential-store keys only; never in IPC,
  DB, index, or logs. `MailAccount` rows carry `AuthRef` key names.
- **Fail closed:** bridge unreachable → send `held` in outbox (retried,
  max 5); `policy-blocked` → dropped + audited with per-recipient reasons;
  plaintext-auth refusal and STARTTLS-fail-closed come from kiwi-mail.
- **Determinism:** all findings come from `RuleEngine` over observed facts;
  unknown TLS/cipher stays `unknown`. No AI anywhere in this layer.
- **Audit:** lock/unlock/account/device/org/send-queue/send-block actions
  recorded in the hash-chained log.

### Non-obvious design decisions

- **`run_mail_io`** (`commands/mod.rs`): kiwi-mail protocol clients are
  `!Send`-unfriendly inside futures — `ImapClient` keeps
  `&mut dyn FnMut` SASL continuations, `Transport` (`dyn MailStream`) and
  `MailStore` (rusqlite `RefCell`s) are `!Sync`. Commands that touch them
  run on `spawn_blocking` + a per-call current-thread runtime (block_on has
  no `Send` bound). Pure store-read commands stay on the main runtime.
- **`TransportFacts`** owned snapshot — no `&Transport`/`&MailStore` ever
  crosses an `.await` in a Tauri command future.
- **`AppState` is managed as `Arc<AppState>`** so `run_mail_io` closures
  can own a reference.
- **`outbox_meta`** sidecar map backs `kiwi_list_outbox` — `SendQueue` has
  no item iterator (kiwi-mail gap).
- **Undo-send** is real: `undo_window_until` frozen dispatch;
  `cancel` only works inside the window (kiwi-mail `SendQueue::cancel`).
- **`boot_session_id`** is per-process state (not persisted) — challenges
  die with the app session by construction.
- **Device-status `SignalKind` → `TrustSignal` mapping table** lives in
  `observe::device_signal` — kiwi-core returns kinds only; severity/penalty
  table noted as a candidate to upstream into kiwi-core.

### Tests added (16, all passing)

- `audit`: hash-chain detects tail tampering.
- `bridge`: loopback allowlist (rejects https/foreign/metadata IP).
- `signals`: console quiet, RDP session flags, SSH env flags, binary-hash
  change → integrity failure.
- `observe`: TLS-version + kex-group name maps.
- `system`: gate blocks while locked & exempt path alive; **full Ed25519
  challenge roundtrip** (pairing → active → lock → unlock); bad signature
  rejected without consuming the challenge (retry-safe).
- `send`: recipient validation, enqueue→cancel inside grace, gate blocks
  send while locked.
- `state`: index roundtrip.
- `error`: stable `{code,message}` shape.

### Verification commands run

```
cargo check -p kiwi-app          → clean (0 warnings)
cargo test --workspace           → 185 passed, 0 failed
cargo clippy --workspace --all-targets -- -D warnings  → clean
cargo fmt --check                → clean
secret scan (grep password/secret/token literals + log sinks) → clean;
  only log sink is eprintln! of IpcError.message (never carries secrets)
```

### Assumptions

- `TrustPolicy::default()` (`unlock_requires_authenticator: true`,
  `challenge_ttl_secs: 120`) is the shipped policy; policy mutation is not
  exposed over IPC.
- Outbox is **in-memory** (kiwi-mail `SendQueue` is in-memory by design;
  T-105 persists later) — pending sends do not survive restart.
- `x509-parser` DER parsing for `CertificateSummary` leaf is bounded by
  rustls' own capture; parse failure → `leaf: null` (absence of fact).
- `record_connection` is called post-auth (success) or post-failure; a
  connection that dies before the client is built produces no session —
  the failing probe step is the record (documented).

### Known gaps / follow-ups for other agents

- `MailStore` lacks `list_accounts`/`delete_account` — account enumeration
  and removal are index-side; an orphaned config row remains in mail.db.
  (kiwi-mail gap — flag for the mail-store owner.)
- `SendQueue::pending()` iterator missing → `outbox_meta` duplicated in
  app state. Fine now; would matter for a persisted outbox (T-105).
- `device_id` on `SecuritySession` left `null` (no device↔session binding
  model yet — Phase-4 seam).
- `recovery` / `elevated-action` challenges verify but return
  `unsupported-event` — flows unwired (authenticator app not in scope).
- Non-Ed25519 device keys register but `submit_challenge` →
  `unsupported-algorithm` until ECDSA/RSA verifiers land.
- Endpoint collector is Windows-first by design (env vars); on other
  platforms it still runs — SSH markers + exe baseline work anywhere,
  `SESSIONNAME` simply absent → no remote-session signal. No WMI/registry
  calls yet (kept bounded per brief).
- `eprintln!` on dispatcher failure writes error `message` to stderr —
  contains server-reply text only, never secrets (SmtpAuth is `!Debug`).
- Frontend binding (`invoke` wrappers + types) is NOT in scope — ipc.md is
  the contract the UI agent implements against.

### Files changed

`kiwi-app/src-tauri/Cargo.toml`, `src/{lib,error,state,audit,credstore,
verifier,observe,signals,bridge,types}.rs`, `src/commands/{mod,system,
accounts,mail,send,security,devices,endpoint}.rs`,
`docs/contracts/ipc.md` (new), this file.
