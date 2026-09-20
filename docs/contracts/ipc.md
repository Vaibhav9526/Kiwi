# Contract — Tauri IPC Command Catalog (`kiwi.ipc/1`)

> Owner: Agent 7 · **Contract version: `kiwi.ipc/1`** · Status: implemented
> (T-120, T-121, T-142, T-144, T-146, T-157, T-163, T-164, T-169, T-175)
> Implemented by `kiwi-app/src-tauri` (Rust, Tauri 2). This document is
> authoritative for the frontend ↔ backend boundary; the registered handler
> list in `kiwi-app/src-tauri/src/lib.rs` is the reference implementation.
> Changes require Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: **kiwi-app webview** (React, untrusted — SECURITY.md B2) →
**kiwi-app backend** (trusted; enforces the lock gate, input validation,
secret handling). The backend never delegates security decisions to the UI.

## 1. Conventions

- All commands are `invoke("kiwi_*", args)`. Arg and field names are
  `camelCase` on the wire (`serde rename_all`). Rust types live in
  `kiwi-app/src-tauri/src/types.rs` (request) and view structs (response).
- **`kiwi_ping()`** returns `"kiwi backend ok"` and reports the contract
  version via `kiwi_app_info().contractVersion` (`"kiwi.ipc/1"`).
- Errors serialize as `{ "code": string, "message": string }` — see §8.
- Times are Unix epoch **seconds** unless the field name says `_ms`.
- No IPC response ever contains a password, token, private key, or
  credential-store secret. Compose bodies are accepted as *input* to
  `kiwi_send_message` only; they are never echoed back (outbox views carry
  envelope metadata + subject only).
- Everything is local-first: the only outbound calls are the configured
  mail servers and, when bound, the loopback kiwi-admin bridge (§10 of
  admin-api.md).

## 2. Lock gate (enforced in the backend)

While `kiwi_security_status().state == "locked"` every **gated** command
fails with `code: "locked"`. Exempt commands — the renderer must always be
able to drive the lock UI — are marked **[exempt]** below:

- `kiwi_ping`, `kiwi_app_info`, `kiwi_security_status`, `kiwi_lock`,
  `kiwi_request_challenge`, `kiwi_submit_challenge`,
  `kiwi_collect_endpoint_signals` (signals feed trust even while locked).

Everything else — accounts, folders, messages, sync, send/outbox, findings,
events, session detail, report, devices, org binding — is **gated**.

Lock/unlock semantics come from `kiwi-core::TrustMachine` (sticky `Locked`;
unlock requires an authenticator-verified challenge when
`policy.unlock_requires_authenticator`, which is the default).

## 3. Trust & status shapes

### `SecurityStatusView`

```jsonc
{
  "state": "trusted | degraded | locked",
  "score": 0,                       // u32, 100 − Σ penalties
  "locked": true,                   // convenience = state == "locked"
  "requiredAction": "none | notify-user | require-authenticator | block-access",
  "signals": [SignalView],
  "endpointSignals": ["remote-session-indicator", "…"],
  "knownDevices": 1
}
```

### `SignalView` — one active trust signal

```jsonc
{ "kind": "starttls-stripped", "severity": "info|low|medium|high|critical",
  "penalty": 25, "evidenceRef": "endpoint:ep-…" }
```

### `SessionView` — wire view of `kiwi-core::SecuritySession`

Field names follow `security-session.md` §3 verbatim, camelCased
(`sessionId`, `tlsVersion`, `certChain`, `authMechanism`, …). Enum spellings
match the contract (`"tls1.3"`, `"hostname-mismatch"`, `"xoauth2"`, …).

## 4. Commands — system / lock path **[exempt]**

### `kiwi_ping() → string`
Liveness. Returns `"kiwi backend ok"`.

### `kiwi_app_info() → AppInfoView`
```jsonc
{ "version": "0.1.0", "contractVersion": "kiwi.ipc/1",
  "deviceId": "dev-…", "org": {"orgId": "…", "baseUrl": "…"} | null,
  "accountCount": 2, "sessionsObserved": 14 }
```

### `kiwi_security_status() → SecurityStatusView`
Current trust/lock verdict (recomputed from live signals).

### `kiwi_lock() → SecurityStatusView`
Administrative lock — audited. Idempotent while locked.

### `kiwi_request_challenge(deviceId, event) → ChallengeView`
Issues a challenge bound to `(deviceId, bootSessionId, event)`.
`event`: `"unlock" | "device-pairing" | "recovery" | "elevated-action"`.
Pairing requires a `pending` device; unlock/recovery require `active`.

```jsonc
{ "challengeId": "chal-…", "deviceId": "dev-…", "sessionId": "boot-…",
  "event": "unlock", "nonceB64": "…", "canonicalBytesB64": "…",
  "issuedUnix": 0, "expiresUnix": 0 }
```
`canonicalBytesB64` is what the authenticator signs.

### `kiwi_submit_challenge(response: ChallengeResponseInput) → SecurityStatusView`
```jsonc
// response
{ "challengeId": "…", "deviceId": "…", "sessionId": "…",
  "event": "unlock", "signatureB64": "…" }
```
Ed25519-verified against the registered device key over canonical bytes
(expiry + single-use + binding enforced by `ChallengeBook`). On success the
bound action runs: `unlock` → `attempt_unlock`, `device-pairing` →
`pending → active`. `recovery`/`elevated-action` verify but currently return
`unsupported-event`. Errors: `invalid-signature`, `challenge-expired`,
`already-consumed`, `binding-mismatch`, `unknown-challenge`,
`device-not-active`, `unsupported-algorithm`.

## 5. Commands — accounts **[gated]**

### `kiwi_list_accounts() → AccountView[]`
```jsonc
{ "id": "acct-…", "displayName": "…", "email": "…",
  "incomingProtocol": "imap | pop3",
  "incoming": {"host": "…", "port": 993, "security": "tls"},
  "outgoing": {"host": "…", "port": 465, "security": "tls"},
  "username": "…", "unreadCount": 3,
  "trustToken": "trusted | degraded | warning | locked | unknown",
  "color": "#2563eb" }
```

### `kiwi_add_account(account: AddAccountInput) → AccountView`
```jsonc
{ "displayName": "…", "email": "a@b.test",
  "incomingProtocol": "imap",
  "incoming":  { "host": "…", "port": 993, "security": "tls | starttls | plaintext" },
  "outgoing":  { "host": "…", "port": 465, "security": "tls" },
  "username": "…",                    // optional, defaults to email
  "outgoingUsername": "…",            // optional, defaults to username
  "incomingAuth": { "kind": "password | xoauth2 | apop | none",
                    "secret": "…" },  // secret used once → OS keystore
  "outgoingAuth": { … },
  "acceptInvalidCerts": false }
```
Secrets are stored under generated `kiwi/<accountId>/<in|out>` keys in the
OS credential store (service `kiwi.mail`) — never persisted, logged, or
returned. `apop` is valid for POP3 only; `xoauth2` not for POP3.

### `kiwi_remove_account(accountId) → { removed: bool }`
Best-effort deletes the account's credential-store keys, drops the account
from the index, and cascades the mail.db rows + on-disk payloads
(`MailStore::delete_account`). Audited.

### `kiwi_test_account(accountId) → VerifyResult[]`
Connect + authenticate incoming AND outgoing servers; returns one
`VerifyResult` per direction (incoming first).

### `kiwi_verify_server(input: VerifyServerInput) → VerifyResult`
One-shot probe used by the setup wizard — nothing is persisted except the
observation (session + findings) it produces.

```jsonc
// input
{ "protocol": "smtp | imap | pop3",
  "server": { "host": "…", "port": 993, "security": "tls | starttls | plaintext" },
  "username": "…",                    // optional
  "auth": { "kind": "password", "secret": "…" } | null,
  "acceptInvalidCerts": false }
// result
{ "ok": true,
  "steps": [ { "stage": "connect | smtp-handshake | … | auth | evaluate",
               "ok": true, "detail": "…" } ],
  "session": SessionView | null,      // the recorded observation
  "findings": [Finding],              // kiwi.forensics/1 shape
  "trust": SecurityStatusView }
```
A failed probe returns `ok: false` with the failing step — it is *not* an
IPC error. IPC errors are reserved for invalid input / locked.

### `kiwi_discover_account(email) → DiscoveryOutcomeView` **[gated]** — REQUESTED (T-178, not yet implemented)

> Request by Agent 8 (authoritative shape source: autoconfig.md,
> `kiwi.autoconfig/1`). To be implemented by Agent 7 in
> `kiwi-app/src-tauri` (command + `types.rs` structs). Field names below
> follow ipc.md camelCase conventions; the Rust source
> (`kiwi_autoconfig::discover`) is snake_case — rename per field as shown.

Setup-wizard autoconfiguration: runs the full discovery pipeline
(ISPDB fixtures → `autoconfig.<domain>` → `/.well-known/autoconfig` →
MX heuristics; stage order is binding, autoconfig.md §3) and returns the
winning suggestion plus the stage-attempt audit trail. Nothing is
persisted — the caller decides what to do via `kiwi_add_account`.

```jsonc
// input:  { "email": "user@example.test" }
// output:
{ "email": "user@example.test",        // normalized
  "domain": "example.test",
  "source": "ispdb | autoconfig_host | well_known | mx_heuristic | manual",
  "needsManualReview": false,          // true ⇒ UI must ask before saving
  "suggestion": {
    "source": "…", "email": "user@example.test", "displayName": "…",
    "incoming": { "kind": "imap | pop3", "host": "…", "port": 993,
                  "security": "tls | starttls | plaintext",
                  "auth": "password | xoauth2", "username": "…" },
    "outgoing":  { "host": "…", "port": 587,
                   "security": "tls | starttls | plaintext",
                   "auth": "password | xoauth2", "username": "…" } },
  "attempts": [ { "source": "…",
                  "outcome": "hit | miss | unreachable | malformed | unsupported",
                  "detail": "…" } ] }
```

Mapping rules (binding): security `implicit_tls → "tls"`,
`start_tls → "starttls"`, `plaintext → "plaintext"` (same vocabulary as
the §5 inputs); auth `password → "password"`, `xoauth2 → "xoauth2"`
(matches `AddAccountInput.auth.kind`, so a suggestion feeds straight
into `kiwi_add_account` without re-interpretation). `suggestion` is
always present for a valid email; `attempts` is the audit trail —
render or log it, and treat `needsManualReview == true` as a hard gate
(pattern guesses must not persist without explicit user consent).
Errors: only `invalid-input` (autoconfig `Error::InvalidEmail`) and
`locked`. Discovery performs network calls (MX + HTTPS document fetch);
it stays offline-first — every network miss is a recorded attempt, and
an empty result set still yields a flagged suggestion, never an error.


## 6. Commands — mail read **[gated]**

### `kiwi_list_folders(accountId) → FolderView[]`
```jsonc
{ "id": 1, "name": "INBOX", "exists": 42, "unseen": 2, "uidValidity": 123 }
```
Folders appear after the first sync (IMAP LIST auto-registers them).

### `kiwi_list_messages(accountId, folderId, limit?) → MessageView[]`
Newest first. `limit` default 50, clamp 1–500. `folderId` must belong to
`accountId` (cross-account reads → `not-found`).

```jsonc
{ "id": 12, "folderId": 1, "uid": 991, "messageId": "<…>" | null,
  "subject": "…", "fromAddr": "…", "toAddrs": "…",
  "dateUnix": 0, "size": 1234, "flags": ["\\Seen"],
  "hasAttachments": false, "snippet": "…",
  "inReplyTo": "<…>" | null, "references": ["<…>"] }
```

`inReplyTo`/`references` (T-169, header-chain threading): populated from
a bounded sidecar cache (50k entries) filled by the sync-time
`BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]` fetch on newly-seen
uids, or lazily from stored bodies (≤32 parses per list call). `null`/
`[]` means "unknown" — no-body messages predating the cache learn on
their next sync or body fetch.

### `kiwi_get_message(accountId, folderId, uid) → MessageBodyView`
Reads the stored body; for IMAP, missing bodies are fetched on demand
(`BODY[]`) and stored — that fetch is itself recorded as a session.
`inReplyTo`/`references` come from the parsed body (authoritative).

```jsonc
{ "folderId": 1, "uid": 991, "messageId": "<…>" | null, "subject": "…",
  "from": ["a@b"], "to": ["…"], "cc": [], "dateUnix": 0,
  "textBody": "…", "htmlBody": "…" | null,
  "attachments": [ { "filename": "…", "contentType": "…", "size": 123 } ],
  "bodyPresent": true,
  "inReplyTo": "<…>" | null, "references": ["<…>"] }
```

### `kiwi_sync_account(accountId, folders?) → SyncReportView[]`
IMAP: LIST (when `folders` omitted) → register → incremental
`sync_folder` per folder. POP3: UIDL-diff into `INBOX`
(leave-on-server; `deleteAfter` is not exposed yet).

```jsonc
{ "protocol": "imap", "folder": "INBOX", "folderId": 1,
  "newMessages": 3, "flagUpdates": 0, "expunged": 0, "remoteExists": 42,
  "uidValidityReset": false,
  // pop3 instead fills:
  "downloaded": 0, "deletedRemote": 0 }
```

## 6b. Commands — message actions **[gated]** (T-146)

### `kiwi_update_message(accountId, folderId, uid, patch) → MessageUpdateView`
Tri-state patch — `{seen?, starred?, archived?}`, each absent = unchanged.
`seen`→`\Seen`, `starred`→`\Flagged`. Write-through order: live IMAP
`UID STORE` first (IMAP accounts only), then local store — POP3 is
local-only by nature. `archived: true` moves to the account's `Archive`
folder (IMAP `UID MOVE` with COPY+DELETE+EXPUNGE fallback; the mailbox is
created if absent), `archived: false` moves back to `INBOX`; locally the
row + body file move with it. Returns `{folderId, uid, flags,
movedToFolderId}` — `folderId` is the *source* the caller passed. Audited.

### `kiwi_download_attachment(accountId, folderId, uid, attachmentIndex, destPath) → AttachmentSavedView`
Extracts part N of the stored MIME body to `destPath` (the UI save-dialog
path; parents created as needed). Bound: decoded bytes ≤50 MiB. `destPath`
inside the app data dir is refused. `filename`/`contentType` come from the
MIME part — never the caller. Audited (`attachment-saved`).

### `kiwi_render_body(accountId, folderId, uid) → RenderedBodyView`
Sanitized HTML fragment for the webview — ammonia strict allowlist
(scripts/styles/iframes/forms/remote styles never survive). `img src` is
filtered per-URL: `cid:`/`data:`/relative always pass; remote `http(s)`
sources pass **only** when the account's remote-content opt-in is on —
otherwise stripped and counted (`remoteImagesStripped`, so the UI can show
"N blocked — allow remote content?"). `html: null` for text-only or
unfetched bodies. Output capped at 8 MiB.

### `kiwi_set_remote_content(accountId, allowed) → RemoteContentView`
Per-account opt-in for remote resources in rendered bodies — default off
(tracking surface). Persisted in the sidecar index, audited.

### `kiwi_delete_messages(accountId, folderId, uids, permanent?) → DeleteResultView` (T-163)
Batch delete, uid set bounded at 500. **Soft delete** (default): moves to
the account's Trash — resolved by local name match → server `\Trash`
special-use LIST flag → `CREATE "Trash"` (idempotent). IMAP uses
`UID MOVE` (COPY+`\Deleted`+EXPUNGE fallback inside kiwi-mail); local rows
move via `store.move_messages` with **fresh destination uids** (UIDs are
folder-scoped; the map is returned). **Hard delete** — `permanent: true`,
or the source folder already IS the trash (empty-trash): `\Deleted` +
`EXPUNGE` on IMAP, row+payload removal locally. POP3 is local-only in
both paths. Audited.
```jsonc
{ "folderId": 1, "movedToTrash": 2, "deleted": 0,
  "trashFolderId": 4, "uidMap": { "12": 7 } }
```

### `kiwi_move_messages(accountId, srcFolderId, dstFolderId, uids) → MoveResultView` (T-163)
Generic folder move. **Cross-account guard**: both folders must resolve
on `accountId` — a foreign `dstFolderId` is `not-found`, never a partial
cross-account write. IMAP `UID MOVE` + local move; POP3 local-only.
Audited.
```jsonc
{ "srcFolderId": 1, "dstFolderId": 5, "moved": 3,
  "uidMap": { "12": 41 } }
```

## 6c. Live sync engine **[background]** (T-157)

A supervisor (spawned at startup) runs one sync worker per configured
account. Reconcile happens on a 2 s tick **or immediately** when
`kiwi_add_account`/`kiwi_remove_account` poke the wake signal — the
wizard's account-create path starts its live worker without waiting.
Workers are dedicated threads with their own
current-thread runtime — kiwi-mail clients are `!Send` inside futures, so
they cannot live on the command runtime (same constraint as
`run_mail_io`).

- **IMAP:** connect + auth → full `sync_folder` pass over every listed
  folder (cap 64) → `SELECT INBOX` → `IDLE` cycles (30 s max each). Any
  untagged EXISTS/EXPUNGE/FETCH notification triggers a `sync_folder`
  re-sync of INBOX. The connection's session is recorded once
  (`"imap live"` label) and §11 received-events emit per sync pass.
- **POP3:** no push channel — `sync_pop3` pass every 60 s.
- **Lock:** while `SecurityStatusView.locked`, workers pause — no
  connects, no credential use; a worker that notices the lock mid-IDLE
  logs out rather than holding an authenticated session.
- **Failure:** any connect/sync error → exponential backoff 5 s → 120 s
  cap (`state: "backoff"`, `nextRetryUnix` set), then reconnect.
- **Removal:** deleting the account stops its worker and drops its status.

### Event `kiwi://mail-changed`
```jsonc
{ "accountId": "acct-…", "folder": "INBOX" | null, "folderId": 1 | null,
  "reason": "sync | idle | poll",
  "newMessages": 2, "flagUpdates": 1, "expunged": 0, "atUnix": 0 }
```
`reason: "sync"` is the connect-time full pass (emitted unconditionally —
it's the UI's "initial sync done" signal; folder fields are `null`).
`"idle"` fires per IDLE-triggered INBOX re-sync, `"poll"` per POP3 pass —
both only when something actually changed.

### `kiwi_sync_status(accountId?) → SyncStatusView[]` **[gated]**
One row per configured account (all accounts when `accountId` omitted;
unknown id → `not-found`). A worker that hasn't run yet reports
`state: "pending"`.

```jsonc
{ "accountId": "…", "state": "pending | connecting | syncing | idle |
    polling | backoff | paused-locked | stopped",
  "lastSyncUnix": 0 | null, "lastError": "…" | null,
  "nextRetryUnix": 0 | null, "foldersSynced": 3, "newMessages": 5,
  "attempts": 0 }
```

## 7. Commands — send / outbox **[gated]**

### `kiwi_send_message(accountId, message: ComposeInput, options?) → SendReceipt`
Validates + MIME-builds + enqueues. Delivery is async via the background
dispatcher (1 s tick); undo-send grace (`undoGraceSecs`, default 10, clamp
0–120) and send-later (`sendAtUnix`) are real. Queued sends persist in
mail.db's `outbox` table (schema v2 — one row per send, built MIME in-row)
and reload on restart (T-142). Persist-before-enqueue: a crash between the
two cannot lose a committed send.

```jsonc
// message
{ "to": ["b@y"], "cc": [], "bcc": [], "subject": "…",
  "text": "…", "html": "…" | null,
  "inReplyTo": "<…>" | null, "references": [],
  "attachments": [ { "filename": "…", "contentType": "…",
                     "dataB64": "…" } ] }            // ≤25 MiB decoded total
// options
{ "sendAtUnix": 0 | null, "undoGraceSecs": 10 | null }
// receipt
{ "queueId": "send-…", "notBeforeUnix": 0, "undoWindowUntilUnix": 0 }
```

### `kiwi_cancel_send(queueId) → { cancelled: bool }`
Recall a queued send. Succeeds while the item is still recallable:
`now < undoWindowUntilUnix` (true undo-send) **or** `now < notBeforeUnix`
(deleting a scheduled send before its slot). Once committed AND due the
send belongs to the dispatcher — and once dispatched it no longer exists
to cancel. Audited; `false` is a normal outcome, not an error.

### `kiwi_schedule_send(queueId, sendAtUnix) → SendReceipt`
Send-later reschedule — moves a pending send's dispatch time. Works on
anything still queued (grace-window item, scheduled send, held retry);
`not-found` if unknown or already dispatched. The undo window is
untouched — rescheduling is not an undo. Audited.

### `kiwi_list_outbox() → OutboxItem[]`
Envelope metadata only (never bodies):
```jsonc
{ "queueId": "…", "accountId": "…", "from": "…", "to": ["…"],
  "subject": "…", "notBeforeUnix": 0, "undoWindowUntilUnix": 0,
  "attempts": 0, "cancelable": true }
```
`cancelable` mirrors the `kiwi_cancel_send` rule (undo window open or
send-later slot still ahead).

### `kiwi_flush_outbox() → { sent, failed, held }`
Force-drain everything (explicit "send now" — skips remaining grace).

### Event `kiwi://outbox`
`{ queueId, accountId, status: "sent|held|blocked|failed", detail, atUnix }`

### Policy bridge behavior (admin-api §10)
The admin endpoint resolves: org binding (`kiwi_set_org_binding`, config) →
`KIWI_ADMIN_URL` + `KIWI_ADMIN_ORG` env vars → none. Non-loopback URLs are
refused from either source (B5). When an org-bound endpoint exists, each
send is evaluated *after* connect+auth with the observed TLS version:

- `overall == "block"` → send dropped, audited (`send-blocked` with
  per-recipient reasons), `kiwi://outbox` emits `blocked`.
- bridge unreachable / timeout / non-200 / malformed → **fail closed**:
  `held` + linear backoff (30 s × attempt, max 5 attempts).
- transport/auth failure → `held` (retried), terminal at 5 attempts.
- While locked, the dispatcher holds everything (no credential use).
- **No endpoint configured at all** (neither binding nor env) → the check
  is skipped with a once-per-process warn (stderr + `policy-bridge-absent`
  audit record) — the local-first dev degrade. An endpoint with no org id
  (`KIWI_ADMIN_ORG` unset) warns once similarly (`policy-no-org`); policy
  evaluation is skipped but mailflow emission still runs.

### Mailflow events (admin-api §11)
When an admin endpoint is resolvable, the backend POSTs §6 `MailflowEvent`s
to `/api/v1/mailflow/events` — metadata only (no subject/body anywhere):

- **post-send-attempt**: one outbound event per recipient, on every
  outcome (sent, blocked, failed). `policy_verdict` comes from the §10
  verdict (`unknown` when no evaluation ran); `message_id` is the MIME
  Message-ID; `tls_version` is the observed transport label.
- **post-receive-sync**: one inbound event per *newly synced* message
  (UID-set delta per folder, ≤200/sync). `org_id` may be null inbound;
  `policy_verdict` is always `unknown`; messages without a From address
  are skipped (§6 requires non-empty sender).
- `security_status` maps observed session findings only — never the policy
  verdict: no findings → `clean`, medium/low → `warn`, high/critical →
  `suspicious`, nothing observed → `unknown`.
- Emit failures never fail send/sync — undelivered events queue in-process
  (`mailflow_pending`, 512 max, drop-oldest) and retry on the next
  emission opportunity.
- Requests carry dev-auth headers (`x-kiwi-subject: kiwi-client`,
  `x-kiwi-roles: org_admin`, `x-kiwi-org`) per §12 — loopback only.

## 8. Commands — security data **[gated]**

### `kiwi_security_findings(accountId?, severity?, limit?) → Finding[]`
Retained deterministic findings (`kiwi.forensics/1` shape verbatim,
evidence included). This is forensics.md §11 `list_findings`:
`accountId` (≤256) and `severity` (`info|low|medium|high|critical` —
unknown string → `invalid-input`, never silently ignored) AND together.
Sort is binding and total: severity desc → `observedAt` desc → `ruleId`
asc → `subjectKey` asc. `limit` default 100, clamp 1000.

### `kiwi_security_events(limit?, accountId?) → EventRow[]`
Session journal rows, newest first (default 100, clamp 1000);
`accountId` filters to that account's sessions:
```jsonc
{ "id": "app:imap:3", "tsUnix": 0, "accountId": "…" | null,
  "category": "imap sync", "severity": "high",
  "summary": "IMAP imap.x.test:993 tls tls1.3",
  "detailRef": "session:app:imap:3" }
```

### `kiwi_finding_detail(findingId) → FindingDetailView`
One finding's full record + the session it was observed in (finding
dialog, KIWI-UI-004). `findingId` is the stable `rule|subject` key.
```jsonc
{ "finding": { /* full kiwi.forensics/1 Finding, evidence included */ },
  "session": SessionView | null,   // null once the session ring evicts it
  "signals": [SignalView],         // that session's trust signals
  "siblingFindingIds": ["KIWI-AUTH-001|imap:h:993"] }
```
Unknown id → `not-found`.

### `kiwi_session_detail(sessionId) → SessionDetailView`
```jsonc
{ "session": SessionView, "signals": [SignalView],
  "findings": [Finding], "label": "imap sync" }
```
(cert viewer KIWI-UI-008, finding dialog KIWI-UI-004.)

### `kiwi_security_report(accountId?) → Report`
`kiwi.forensics/1` report built from retained findings
(`generatedFrom: "live"`, limitation noting live-observation scope).

## 9. Commands — devices / org binding **[gated]**

### `kiwi_register_device(input: RegisterDeviceInput) → DeviceView`
```jsonc
// input
{ "label": "…", "algorithm": "ed25519 | ecdsa-p256 | rsa3072",
  "publicKeyB64": "…", "keystoreRef": "…" | null }
// view
{ "deviceId": "dev-…", "label": "…", "algorithm": "ed25519",
  "status": "pending | active | suspended | revoked",
  "registeredUnix": 0, "lastSeenUnix": 0 }
```
New devices are `pending` — they activate via a `device-pairing` challenge
(§4). Only `ed25519` signatures verify today (`unsupported-algorithm`
otherwise). The private key never enters this process.

### `kiwi_list_devices() → DeviceView[]`

### `kiwi_revoke_device(deviceId) → SecurityStatusView`
Terminal revocation — audited; feeds `device-revoked` (hard-lock kind)
into the next trust evaluation.

### `kiwi_set_org_binding(orgId?, baseUrl?) → OrgBindingView | null`
Both args required to set; both omitted (`null`) clears. `baseUrl` must be
`http://{localhost|127.0.0.1|[::1]}:<port>` — non-loopback fails with
`policy-unavailable` at config time. Audited. Equivalent env fallback when
no binding exists: `KIWI_ADMIN_URL` (+ optional `KIWI_ADMIN_ORG`) — same
loopback rule applies.

## 9b. Commands — contacts **[gated]** (T-175, implements kiwi.contacts/1 §3)

The address book lives in `contacts.db` under the profile dir (owned by
`kiwi-contacts`; never shares mail.db's tables). All field bounds and the
`local-` id reservation are crate-enforced (`Contact::prepare` runs on
every write); this layer adds the lock gate, IPC input bounds, §7 error
mapping, and audit records on writes.

```jsonc
// ContactView (camelCase projection of Contact — contacts.md §2)
{ "id": "local-7", "displayName": "…", "givenName": null, "familyName": null,
  "middleName": null, "namePrefix": null, "nameSuffix": null,
  "org": null, "title": null, "notes": null, "tags": ["…"],
  "emails": [ { "address": "a@b", "label": "work" | null } ],
  "phones": [ { "number": "…", "label": null } ],
  "sourceUid": null, "revUnix": null,
  "createdUnix": 0, "updatedUnix": 0 }

// ContactInput = Contact minus {id, createdUnix, updatedUnix}
// (store-owned — values sent are ignored on create, preserved on update)
```

| command | returns | notes |
|---------|---------|-------|
| `kiwi_list_contacts(limit?, offset?)` | `ContactView[]` | `displayName`,`id` order; `limit` clamps to 500 |
| `kiwi_search_contacts(query, limit?)` | `ContactView[]` | substring over name/org/notes/tags/emails; `%`/`_`/`\` literal; empty → list |
| `kiwi_get_contact(contactId)` | `ContactView` | `not-found` when absent |
| `kiwi_create_contact(contact)` | `ContactView` | assigns `local-N` |
| `kiwi_update_contact(contactId, contact)` | `ContactView` | full replace; `not-found` on unknown id |
| `kiwi_delete_contact(contactId)` | `{removed}` | `false` when already absent |
| `kiwi_contacts_by_email(address)` | `ContactView \| null` | recipient→name (composer/reader) |
| `kiwi_contacts_by_tag(tag, limit?)` | `ContactView[]` | case-insensitive tag |
| `kiwi_contact_tags()` | `{tag, count}[]` | most-used first |
| `kiwi_import_vcards(vcard)` | `VCardImportView` | below |
| `kiwi_export_vcards(contactIds?)` | `{vcard}` | all contacts when omitted; unknown explicit id → `not-found` |

`kiwi_import_vcards` — hard stream errors abort as `invalid-input`;
per-card issues never discard the rest. Re-import dedupes on the card's
`UID` → `sourceUid`: a known `UID` updates in place (id + `createdUnix`
preserved, card wins wholesale — §5.4); a store-level failure on one
card lands in `issues` instead of aborting the batch.

```jsonc
{ "contacts": [ ContactView ],
  "issues": [ { "cardIndex": 3, "detail": "email exceeds 320 bytes" } ] }
```

## 9c. Commands — preferences **[gated]** (T-175)

Small key/value store in the sidecar index for the settings UI. Two
scopes: global (`accountId` absent) and per-account (`accountId` present
— must name a known account, else `not-found`; a typo'd id must not
silently write into the void). Not a credential store — secrets go to
the OS keystore via account auth only.

| command | returns | notes |
|---------|---------|-------|
| `kiwi_prefs_get(key, accountId?)` | `value \| null` | `null` = unset |
| `kiwi_prefs_set(key, accountId?, value)` | `{key, value}` | overwrites in-scope |
| `kiwi_prefs_list(accountId?)` | `{key, value}[]` | scope enumeration, key-ordered |

Bounds: `key` 1–128 chars, `:` refused (scope separator); `value` any
JSON ≤ 64 KiB serialized; 1024 entries total.

## 10. Commands — endpoint signals **[exempt]** (T-121)

### `kiwi_collect_endpoint_signals() → EndpointReportView`
Collects bounded endpoint indicators, persists evidence to
`endpoint-evidence.jsonl`, feeds the trust engine, returns the report:

```jsonc
{ "collectedAtUnix": 0,
  "observations": [
    { "id": "ep-…", "kind": "remote-session-indicator | endpoint-integrity-failure",
      "severity": "medium", "penalty": 20,
      "detail": "non-console session name: RDP-Tcp#3",
      "evidenceRef": "endpoint:ep-…" } ],
  "status": SecurityStatusView }
```

Measured indicators today (bounded, no process scanning / no network
telemetry — see `signals.rs` header):

- **Remote session**: `%SESSIONNAME%` ≠ `Console` (RDP/ICA), or SSH context
  env vars present (`SSH_CLIENT`/`SSH_CONNECTION`/`SSH_TTY` — names only,
  values never collected).
- **Process integrity (TOFU)**: SHA-256 + path of the running executable vs
  a baseline recorded at first run (`endpoint-baseline.json`).

Non-Windows: the collector still runs — `SESSIONNAME` is simply absent, so
no remote-session signal fires; the TOFU baseline works on any platform.
Collection caps at 32 observations per run.

## 11. Error codes

| code | meaning |
|------|---------|
| `locked` | gated command while endpoint locked |
| `invalid-input` | boundary validation failure |
| `not-found` | unknown account/folder/session/device/challenge |
| `connect-failed` | TCP/connect failure |
| `tls-failed` | TLS handshake / validation failure |
| `auth-failed` | auth rejected OR stored credential missing |
| `protocol-error` | server spoke out of spec |
| `server-reject` | SMTP recipient/DATA rejection |
| `store-error` | mail store / index error |
| `io-error` | local file/IO error |
| `policy-unavailable` | admin bridge unreachable/bad (send fails closed) |
| `policy-blocked` | org policy blocked the send |
| `invalid-signature` | challenge signature mismatch |
| `challenge-expired` / `already-consumed` / `binding-mismatch` / `unknown-challenge` | challenge lifecycle |
| `device-not-active` / `device-error` / `unsupported-algorithm` | device path |
| `unsupported-event` | verified challenge for unwired flow |
| `replay-detected` | challenge nonce collision |
| `audit-corrupt` | audit-log chain break |
| `internal` | unexpected backend fault |

## 12. Notes & known gaps (see agent-7-status.md)

- `MailStore::delete_account` cascades account→folders/messages/pop3_seen/
  outbox rows and sweeps on-disk payload dirs; `kiwi_remove_account` calls
  it (gap closed by Agent 2's T-105 work landing mid-session).
- `SendQueue` has no item iterator; `outbox_meta` backs `kiwi_list_outbox`.
  Outbox **persists** across restarts (T-142): each send is one row in
  mail.db's `outbox` table (schema v2 — meta + built MIME together, so a
  committed send is a single atomic write). Reload is bounded (≤256 items,
  ≤32 MiB MIME enforced at enqueue). Pre-SQLite `outbox/*.json|.eml` files
  are imported once at open, then removed. Expired undo windows simply
  aren't cancelable after restart; a still-future `notBeforeUnix` is
  honored — the dispatcher picks it up on its next tick. The mailflow
  pending queue (§11 retry) is in-memory only — events queued while the
  admin service is down are lost on restart.
- `device_id` on `SecuritySession` is `null` (endpoint binds the session,
  not a device); challenge `sessionId` binds to the boot session.
- Session/findings journals are bounded in-memory rings (512 / 4096).
- `recovery`/`elevated-action` challenges verify but are `unsupported-event`
  until their flows land.
