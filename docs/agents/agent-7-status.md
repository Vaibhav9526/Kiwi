# Agent 7 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

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
