# Agent 7 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

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
