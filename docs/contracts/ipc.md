# Contract — Tauri IPC Command Catalog (`kiwi.ipc/1`)

> Owner: Agent 7 · **Contract version: `kiwi.ipc/1`** · Status: implemented for
> the registered command catalog (T-120, T-121, T-142, T-144, T-146, T-157,
> T-163, T-164, T-169, T-175, T-227); §9d is the **Lead-ratified T-188 wire contract**,
> with handlers still pending implementation. Implemented by
> `kiwi-app/src-tauri` (Rust, Tauri 2). This document is authoritative for the
> frontend ↔ backend boundary; the registered handler list in
> `kiwi-app/src-tauri/src/lib.rs` is the reference implementation. Changes
> require Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: **kiwi-app webview** (React, untrusted — SECURITY.md B2) →
**kiwi-app backend** (trusted; enforces the lock gate, input validation,
secret handling). The backend never delegates security decisions to the UI.

## 1. Conventions

- All implemented commands are `invoke("kiwi_*", args)`. Arg and field names are
  `camelCase` on the wire (`serde rename_all`). Rust types live in
  `kiwi-app/src-tauri/src/types.rs` (request) and view structs (response).
  §9d uses the logical command names assigned by T-188 (`pair_begin`, etc.);
  a Tauri registration would follow the same prefix rule, for example
  `invoke("kiwi_pair_begin", request)`. The names are documentation only until
  Lead approves and the handlers are registered.
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

## 9d. Commands — pairing engine, kiwi-pair **[partly gated]** (T-188, ratified)

> **RATIFIED by Lead 2026-09-25 (T-188).** The five logical command names
> below are canonical: `pair_begin`, `pair_status`, `unlock_challenge`,
> `device_list`, and `device_revoke`. Existing §4/§9 `kiwi_*` names may be
> compatibility aliases only; two independent implementations or frontend
> call paths are rejected. `pair_status` still requires the read-only
> ticket API plus atomic ticket-to-device persistence described in §9d.3.
> The command handlers are not yet registered; this section fixes the ratified
> wire contract before implementation.

`kiwi-pair` (T-174) is the desktop-side pairing engine: pairing tickets,
device records, and Ed25519 challenge issue/verify over kiwi-core's canonical
bytes. It is a **library**, not a transport — `kiwi-app`'s backend owns the
IPC surface, the lock gate, and audit records; the engine owns persistence and
the cryptographic checks. `pair.md` is authoritative for the engine API and
the `pair.db` schema; this section only fixes the wire shapes.

### 9d.1 Engine binding

| IPC command | `PairEngine` call | Notes |
|-------------|-------------------|-------|
| `pair_begin` | `issue_pairing_ticket(deviceLabel, os_nonce()?, now)` then `qr_payload_json(ticket, desktopEndpoint, deviceLabel, desktopPublicKeyB64, now)` | nonce, clock, LAN endpoint, and desktop key are backend-owned; never renderer-supplied |
| `pair_status` | **none today** | requires a non-mutating ticket lookup plus ticket-to-device linkage; see §9d.3 |
| `unlock_challenge` | `issue_challenge(ChallengeSpec { challenge_id, device_id, session_id, event: Unlock, nonce }, now, CHALLENGE_TTL_SECS)` | backend generates every field except `device_id` |
| `device_list` | `list_devices()` + `device_fingerprint(device_id)` per row | projects `DeviceRow`; never returns the raw public key |
| `device_revoke` | `revoke_device(deviceId, now)`, then refresh trust | engine result is `Result<()>`; IPC preserves §9's `SecurityStatusView` return |

`challenge_id` and `session_id` are backend-generated per issue; the session is
the same boot-session id §4 binds. `now` is one backend clock read per request.
`PairError` mapping is fixed by §9d.9.

**Lead rulings — ratified 2026-09-25:**

| decision | binding contract rule |
|----------|----------------------|
| command names | `pair_begin`, `pair_status`, `unlock_challenge`, `device_list`, `device_revoke` are canonical; no duplicate handler path |
| challenge nonce | `nonceB64` is the canonical wire field: RFC 4648 standard Base64, padded, decoding to exactly 32 bytes |
| ticket/QR | `pair_begin` may return the ticket/QR for local-only renderer display; it never crosses an admin/mobile trust boundary or enters logs/preferences/evidence |
| lock gate | `unlock_challenge` is always exempt; `pair_begin`/`pair_status` are exempt only while a backend-tracked pairing flow is active; outside that flow they are gated |
| first device | the trusted first-device TOFU pairing path is approved; TOFU evidence never substitutes for the authenticator challenge |
| device names | duplicate names are rejected with admin `409 conflict`; IPC duplicate device identity uses `device-exists`; listings remain deterministic and never merge rows |

### 9d.2 `pair_begin({ deviceLabel }) → PairBeginView` **[exempt only in active pairing flow]**

```jsonc
// request
{ "deviceLabel": "Pixel 8" }        // string, 1..=128 UTF-8 bytes, no ASCII controls

// response
{ "ticket": "…",                    // string; 43 base64url chars — BEARER SECRET
  "expiresUnix": 1729000300,        // integer Unix seconds; now + QR_TTL_SECS (300)
  "qrPayload": "{\"desktop_endpoint\":…,…}" }
```

This is the direct projection of `PairingTicket { ticket, expires_unix }` plus
the `String` returned by `qr_payload_json`. `desktopEndpoint` and
`desktopPublicKeyB64` are **not request fields**: the backend must obtain them
from a trusted pairing-channel configuration/identity store. The renderer
must not be able to substitute another desktop key or arbitrary endpoint. If
that backend identity is unavailable, the command fails closed;
it must not invent one.

`qrPayload` is rendered verbatim. It is a compact JSON **string** whose current
`serde_json` field order is:

```jsonc
{ "desktop_endpoint": "wss://192.168.1.20:49310/pair",
  "desktop_public_key_b64": "ed25519:<base64 of 32 bytes>",
  "device_label": "Pixel 8", "expires_unix": 1729000300,
  "issued_unix": 1729000000, "pairing_ticket": "…",
  "type": "kiwi-pairing", "v": 1 }
```

The engine validates the endpoint/label bounds and requires the
`ed25519:` prefix, but it treats the key text as opaque. The IPC boundary must
also require `ed25519:` followed by RFC 4648 **standard Base64 with padding**
for exactly 32 bytes (44 characters including `=`). Decode, verify the byte
length is 32, then require a byte-for-byte match with a canonical re-encode;
URL-safe or unpadded forms are not accepted. `ticket` and `qrPayload` must
never be logged, written to `prefs` (§9c), put in an evidence reference, quoted
in an error, or echoed by `pair_status`.

**RATIFIED local-render exception.** The ticket authorizes one pairing claim
until it expires. Lead approved returning the ticket/QR to the untrusted
renderer **only for local screen rendering**; it is never forwarded to
`kiwi-admin`, the mobile transport, logs, preferences, evidence, or any other
trust boundary. It grants no mailbox access by itself; activation still
requires the registered device's Ed25519 signature over a `device-pairing`
challenge.

### 9d.3 `pair_status({ ticket }) → PairStatusView` **[exempt only in active pairing flow]**

```jsonc
// request
{ "ticket": "…" }                    // 8..128 chars, [A-Za-z0-9_-]

// response
{ "state": "awaiting-phone | claimed | expired",
  "device": PairDeviceView | null,
  "expiresUnix": 1729000300 }
```

State invariants are normative:

- `awaiting-phone`: ticket exists, is linked to no device, and `now <
  expiresUnix`; `device` is `null`.
- `claimed`: the pairing transaction has persisted the registered device id;
  `device` is non-null. `state` describes ticket claim, not device trust: the
  projected status may be `pending`, `active`, `suspended`, or `revoked` at
  poll time.
- `expired`: the ticket has no device link and `now >= expiresUnix`; `device`
  is `null`. Expiry takes precedence over a consumed-but-unlinked flag, which
  matters because the current store marks a ticket consumed before it checks
  expiry. A claimant is never reported as successful merely because its ticket
  expired.

Unknown or malformed tickets fail with `pairing-ticket-invalid`. Unknown and
already-consumed-but-unlinked tickets deliberately produce the same error, so
polling is not a live-ticket oracle. The response never echoes the ticket.

**This shape is not implementable from today's public API.** `PairEngine` has
only mutating `consume_pairing_ticket`; there is no read-only lookup.
Moreover, `pairing_tickets` stores only `device_label`, while
`register_device` neither accepts a ticket nor writes a ticket-to-device link.
A correct implementation therefore requires BOTH:

1. a persistent, non-consuming engine method that returns ticket state and
   the linked device id; and
2. a schema/registration extension in which ticket consumption, device-row
   creation, and the ticket-to-`device_id` link commit in one SQLite
   transaction. Partial consumption without a linked registration must be
   impossible.

Calling `consume_pairing_ticket` from a polling UI would be a correctness and
security defect. Caching the bearer ticket in kiwi-app to work around the gap
is also refused; the cache would create a second secret store outside
`pair.db`.

### 9d.4 `unlock_challenge({ deviceId }) → PairChallengeView` **[always exempt]**

```jsonc
// request
{ "deviceId": "dev-…" }              // string, 1..=128 UTF-8 bytes, no ASCII controls

// response — T-188 PairChallengeView wire contract
{ "challengeId": "chal-…",
  "deviceId": "dev-…",
  "sessionId": "boot-…",              // backend boot session; not caller-selectable
  "event": "unlock",                 // fixed by this command
  "nonceB64": "…",                   // standard Base64, exactly 32 decoded bytes
  "canonicalBytesB64": "…",          // standard Base64 of kiwi-core canonical bytes
  "issuedUnix": 1729000000,
  "expiresUnix": 1729000120 }
```

**RATIFIED canonical wire format.** `nonceB64` is the only nonce field:
RFC 4648 standard Base64 with canonical padding, decoding to exactly 32
bytes. It matches `authenticator.md` §4.2. The current Rust
`ChallengeView` still serializes `nonceHex`; the required backend/frontend
migration must remove that spelling rather than support both.

The renderer supplies only `deviceId`. The backend generates `challengeId`,
uses `os_nonce()` for the 32-byte nonce, binds the current boot `sessionId`,
reads the clock once, fixes `event = Unlock`, and passes
`CHALLENGE_TTL_SECS` (120; engine maximum 300). No `nonce`, `sessionId`,
`challengeId`, `event`, or `ttlSecs` request field exists: each would let an
untrusted renderer weaken binding or replay protection.

`unlock` requires an `active` device. Pending/suspended devices return
`device-not-active`; revoked devices return `device-revoked` and can never be
challenged again. The signed response is submitted through §4's
`kiwi_submit_challenge` shape; when this proposed catalog is wired to
`kiwi-pair`, that handler must delegate to `verify_response` and must not keep
a second in-memory `ChallengeBook`.

### 9d.5 `device_list({}) → PairDeviceView[]` **[gated]**

```jsonc
// request
{}

// response
[{ "deviceId": "dev-…",
   "label": "Pixel 8",
   "algorithm": "ed25519",            // only live verifier today
   "status": "pending | active | suspended | revoked",
   "keyFingerprintTail": "1A2B3C4D5E6F7788", // preserve §9's existing field
   "fingerprint": "6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20",
   "keystoreRef": "android-key-alias" | null,
   "registeredUnix": 1729000000,
   "lastSeenUnix": 1729000000,
   "revokedUnix": null }]
```

This is a safe projection of `DeviceRow` plus key-derived display fields.
It preserves §9's existing `keyFingerprintTail` (the final 8 hex characters of
the full SHA-256 digest) while adding kiwi-pair's dash-grouped
`fingerprint`, so adopting it for `kiwi_list_devices` is additive. The raw
`public_key` is deliberately omitted: `fingerprint` is for human out-of-band
comparison and is never an automatic trust input. `keystoreRef` is an opaque
alias, not key material or a secret. Device identity is `deviceId`; duplicate
ids fail with `device-exists`. For the separate org-admin inventory, duplicate
normalized device names are rejected with `409 conflict` (admin-api.md §14)
and are never silently merged.

The IPC projection MUST impose a total order: `registeredUnix` ascending,
then `deviceId` ascending. The store currently orders only by
`registeredUnix`; equal-second rows therefore need an IPC-level tie-breaker to
make output deterministic across SQLite and repeated calls.

`lastSeenUnix` is set at registration and advanced by every
`set_device_status`. Successful **device-pairing** verification therefore
advances it when it activates the device; successful unlock/recovery/
elevated-action verification does not. The UI must not label the field "last
authenticated". A true last-seen signal needs an engine/schema change.

### 9d.6 `device_revoke({ deviceId }) → SecurityStatusView` **[gated]**

```jsonc
// request
{ "deviceId": "dev-…" }

// response — preserve the existing §9 return contract
{ "trust": "warning", "locked": false, "state": "degraded",
  "score": 75, "requiredAction": "none",
  "signals": [ /* §3 SignalView[] */ ],
  "sessionsObserved": 0, "deviceId": "dev-…" }
```

`PairEngine::revoke_device` returns `Result<()>`; the backend then refreshes
trust and returns the existing `SecurityStatusView` used by
`kiwi_revoke_device`. Keeping that return type avoids a breaking change for
current callers. The revoked `PairDeviceView` is available from §9d.5's
`device_list` projection, not substituted here.

Unknown id is `not-found`. Revocation is terminal and idempotent: a second
call succeeds without advancing the original `revoked_unix`. The device can
never return to `pending` or `active`, and both `verify_response` and
`issue_challenge` refuse it. The backend MUST audit `device-revoked` on both
the transition and the idempotent retry.

### 9d.7 Lock gate

Per §2, gated commands fail with `code: "locked"` whenever
`SecurityStatusView.state == "locked"`.

| command | locked | rationale |
|---------|--------|-----------|
| `pair_begin` | **exempt only during an active backend-tracked pairing flow** | opens/continues local QR setup; outside that flow it is gated |
| `pair_status` | **exempt only during that active pairing flow** | lets the renderer finish/expire its visible QR; outside it, gated |
| `unlock_challenge` | **always exempt** | this is the authenticator unlock path |
| `device_list` | **blocked** | inventory read is not required to render or submit the unlock flow |
| `device_revoke` | **blocked** | destructive device administration is not a lock-lift operation |

The pairing flow is backend-owned and cannot be opened, extended, or selected
by a renderer-supplied flag. The initial local flow action is a trusted
backend event; thereafter the backend binds the flow to its ticket/capability.
Outside that active flow, `pair_begin` and `pair_status` return `locked` even
though their handlers exist.

**RATIFIED first-device TOFU path.** During the active first-device flow, the
backend records the endpoint's executable path + SHA-256 as TOFU baseline
evidence. TOFU is evidence, not authorization: it never activates a device or
unlocks the mailbox. The trusted pairing-channel handler may, while locked,
validate/consume the ticket, create the `pending` device, and issue/verify its
`device-pairing` challenge, subject to its TLS/pin and ticket rules. Only
successful authenticator verification activates the device.

### 9d.8 Bounds and validation

Rust's `str::len()` is bytes, so the engine limits below are UTF-8 byte
bounds, not Unicode scalar counts. `check_field` rejects empty/overlong values
and ASCII control bytes (`< 0x20` or `0x7f`); the IPC layer MUST NOT relax
them.

| value | bound / rule | failure |
|-------|--------------|---------|
| `deviceLabel` (pair ticket/register label) | 1..=128 UTF-8 bytes, no ASCII controls | `invalid-input` naming `device_label`/`label` |
| `deviceId`, generated `challengeId` | 1..=128 UTF-8 bytes, no ASCII controls | `invalid-input` |
| generated `sessionId` | 1..=256 UTF-8 bytes, no ASCII controls | `invalid-input` |
| `keystoreRef` | optional; 1..=256 UTF-8 bytes, no ASCII controls | `invalid-input` |
| backend `desktopEndpoint` | 1..=256 UTF-8 bytes, no ASCII controls | `invalid-input` |
| ticket input | 8..=128 ASCII chars, `[A-Za-z0-9_-]`; generated tickets are exactly 43 | `pairing-ticket-invalid` |
| challenge TTL | 1..=300 seconds; fixed at 120 and not caller-exposed | `invalid-input` only on backend wiring fault |
| device public key | exactly 32 bytes, Ed25519 only | `invalid-input` / `unsupported-algorithm` |
| desktop public-key text | `ed25519:` + canonical RFC 4648 standard Base64, padded, exactly 32 decoded bytes | `unsupported-algorithm` / `invalid-input` |

`InvalidField.reason` is fixed and does not echo the value. Store/IO messages
still require sanitization (§9d.9).

### 9d.9 Error mapping (`PairError` → §11)

`pair.md` requires semantic names to survive the boundary. The mapping is
normative, not stylistic:

| `PairError` | IPC code | response message rule |
|-------------|----------|-----------------------|
| `Challenge(UnknownChallenge)` | `unknown-challenge` | fixed, bounded |
| `Challenge(Expired)` | `challenge-expired` | fixed, bounded |
| `Challenge(AlreadyConsumed)` | `already-consumed` | fixed, bounded |
| `Challenge(BindingMismatch)` | `binding-mismatch` | fixed, bounded |
| `Challenge(InvalidSignature)` | `invalid-signature` | fixed, bounded |
| `DeviceNotFound` | `not-found` | do not echo the id |
| `DeviceNotActive(status)` | `device-not-active` | status may be named; id may not |
| `DeviceRevoked` | `device-revoked` | do not echo the id |
| `DeviceExists` | `device-exists` | do not echo the id |
| `ReplayDetected` | `replay-detected` | fixed |
| `UnsupportedAlgorithm` | `unsupported-algorithm` | fixed; do not echo key material |
| `BadKeyLength` | `invalid-input` | name `publicKey`; no bytes |
| `InvalidField` | `invalid-input` | fixed engine reason is safe |
| `InvalidTicket` | `pairing-ticket-invalid` | never quote the ticket |
| `TicketConsumed` | `pairing-ticket-consumed` | never quote the ticket |
| `TicketExpired` | `pairing-ticket-expired` | never quote the ticket |
| `Entropy` | `internal` | fixed generic message |
| `Store` | `store-error` | fixed generic message |
| `Io` | `io-error` | fixed generic message; never expose a path |

These five codes are declared in §11 but are not all reachable in the
current engine. In particular, `consume_pairing_ticket` currently collapses
unknown and already-consumed tickets to `InvalidTicket`; `pairing-ticket-consumed`
is reserved for the future non-mutating status API and must not be fabricated
by the IPC layer. `device-revoked` must not collapse into
`device-not-active`: terminal revocation and a recoverable status mismatch
require different operator responses. `Store.display()` can contain SQL/object
names and `Io.display()` can contain local paths, so neither is forwarded
verbatim.

### 9d.10 Invariants the IPC layer must not violate

- **Canonical bytes are kiwi-core's.** Never re-encode, reorder, or normalize
  them; desktop and phone must sign the same bytes.
- **No private key crosses a production boundary.** The phone's keystore
  signs; the desktop verifies. `DeviceSigner` is publicly exported for
  deterministic tests/mobile-parity vectors, but no IPC command or production
  path may instantiate it and no private key may enter IPC or `pair.db`.
- **Ed25519 only.** `ecdsa-p256`/`rsa3072` remain reserved and fail closed.
- **Replay state is persistent within its documented retention.** Challenges
  and nonces survive process restart, but nonces are pruned after one hour or
  beyond 4096 rows, and challenges beyond 4096 rows. There is no IPC reset.
  The engine must also check `consume_challenge`'s atomic boolean before
  reporting verification success; the current code ignores it, so a
  multi-instance race is a known implementation gap (§9d.11).
- **The engine has no ambient clock or RNG.** The backend supplies `now`,
  challenge id, boot session, and `os_nonce()` values. The renderer supplies
  only the values shown in the request objects above.
- **The renderer cannot choose desktop identity or transport.** Endpoint and
  desktop public key come from the trusted pairing backend; QR text is opaque
  and rendered verbatim.
- **Tickets are never an audit/evidence value.** Only non-secret status,
  expiry, row count, and action may be audited.

### 9d.11 Ratified decisions and implementation follow-ups

**Ratified by Lead (2026-09-25):** the five logical command names, canonical
`nonceB64`, local-only ticket/QR rendering, flow-scoped pairing exemptions,
and the first-device TOFU path are contract decisions, not open questions.
The following remain implementation gates:

1. **Challenge wire migration.** Replace current Rust `nonceHex` and the
   existing `expired` spelling with the ratified `nonceB64` and
   `challenge-expired` mappings in one coordinated backend/frontend change.
2. **`pair_status` engine + schema change.** A read-only API alone is
   insufficient; consume/register/link must be one transaction (§9d.3).
3. **Atomic challenge consumption.** `verify_response` currently ignores the
   false return from `consume_challenge`, permitting a race across two engine
   instances. It must treat false as `AlreadyConsumed` before any activation.
4. **Pairing transport provisioning.** Implement the approved trusted
   first-device flow with its TLS/pin enforcement and backend-owned flow
   state; do not add a renderer-controlled bypass.
5. **Resource bounds.** Add per-profile ticket issuance/retention limits and an
   engine-level device-list bound or pagination before these commands ship.
6. **Admin device-name uniqueness.** Enforce normalized per-org uniqueness at
   the future admin write boundary with `409 conflict`; keep list order
   deterministic and never merge rows (admin-api.md §14).
7. **Fingerprint and `lastSeenUnix`.** Fingerprints remain display-only;
   either add a real last-seen update or document the narrower meaning already
   used by `PairEngine`.

## 9e. Commands — external integrations **[gated]** (T-227, implements kiwi.integrations/1)

IPC surface for `kiwi-integrations` (docs/contracts/integrations.md). All
nine commands are **gated** (the lock gate applies — no exempt member of
this family). All transport is HTTPS-only via the shared `ReqwestClient`;
no redirects; response bodies capped. Session material (`PHPSESSID`,
`sid_token`, test slugs, consent tokens) lives in memory only — nothing
here is persisted, and none of it ever appears in an IPC payload.

### 9e.1 Temp mail — `kiwi_integrations_tempmail_*`

One disposable-inbox session at a time (GuerrillaMail sessions are
single-mailbox). `create` replaces any live session; `discard` clears it.
**Every response in this family carries `publicInboxNotice`** — the
binding warning that the UI must display before/alongside use; it is
forwarded verbatim from `PUBLIC_INBOX_NOTICE` so the copy cannot drift.
Disposable inboxes are PUBLIC: anyone who knows the address can read its
mail.

#### `kiwi_integrations_tempmail_create(localPart?) → TempMailboxView`

Initializes the session (`f=get_email_address`); when `localPart` is
present it is applied (`f=set_email_user`) after charset validation —
`invalid-input` on bad charset before any network call. Returns
`{address, addressCreatedUnix?, publicInboxNotice}`.

#### `kiwi_integrations_tempmail_poll() → TempPollView`

`f=check_email` against the live session (the `seq` cursor advances
server-side). Returns `{messages: TempMessageSummaryView[], totalNew,
address?, publicInboxNotice}`. `address` is the session-resync signal.
`not-found` when no session exists.

`TempMessageSummaryView`: `{mailId, from, subject, excerpt,
timestampUnix?, date, read}` — provider-escaped entities are already
decoded; text is still untrusted (render as text, never HTML).

#### `kiwi_integrations_tempmail_fetch(mailId) → TempMessageView`

`f=fetch_email` → the provider's synthesized RFC822 is parsed and the
HTML body runs through the same `ammonia` allowlist as
`kiwi_render_body` — **with remote resources always stripped** (a public
inbox never honors `remote_content_allowed`; it is a tracking surface on
a public address). Returns `{mailId, from, subject, date, contentType?,
html?, text?, remoteImagesStripped, publicInboxNotice}`. Raw MIME never
crosses IPC.

#### `kiwi_integrations_tempmail_discard() → TempDiscardView`

Clears the local session unconditionally, then best-effort `forget_me`
remotely. `{discarded: true, remoteForgotten, publicInboxNotice}` —
`remoteForgotten: false` means the provider may still hold the address
until it ages out (60 min).

#### `kiwi_integrations_tempmail_extend() → TempExtendView`

`f=extend` — one extra hour, once. `{extended, expired,
addressCreatedUnix?, publicInboxNotice}`.

### 9e.2 Deliverability — `kiwi_integrations_deliverability_*`

Flow: `begin` → send the real message (consent-gated) → `status` polls →
`report`. The reservation `slug` is a capability secret and never leaves
the backend — IPC sees only the opaque `testId`.

#### `kiwi_integrations_deliverability_begin() → DeliverabilityBeginView`

`POST /api/v1/inbox` → `{testId, address, expiresAtUnix?,
expiresAtRaw?, consentToken, consentNotice}`. `consentToken` is a
single-use CSPRNG capability the backend minted; `consentNotice` is the
mandatory UI copy describing what consent covers.

#### `kiwi_integrations_deliverability_send(testId, consentToken, accountId, message) → DeliverabilitySendView`

**Consent is non-bypassable**: `consentToken` must match the stored
single-use token, compared and consumed atomically under the sessions
lock — missing/wrong/consumed all fail `consent-required` (no oracle on
which). The message's `to`/`cc`/`bcc` are IGNORED; the sole recipient is
the reserved address. The send rides the normal outbox
(`SendOptions`-less enqueue: default undo grace, audited `send-queued`).
Returns `{testId, queueId, notBeforeUnix}` — `kiwi_cancel_send` still
works inside the grace window.

#### `kiwi_integrations_deliverability_status(testId) → DeliverabilityStatusView`

Single-shot `GET /tests/{slug}/status`. `{testId, analysisStatus,
checksDone, checksTotal, ready, sent}` — `ready` means `checks_ready`
(`report` is fetchable); `sent` reports whether consent was consumed.
Any poll loop belongs to the UI (provider rate limits: `rate-limited`
carries the hint).

#### `kiwi_integrations_deliverability_report(testId) → DeliverabilityReportView`

`GET /tests/{slug}` → `{testId, scoreOursMilli?, scoreCompatMilli?,
complete, reportUrl?, subscores, tallies, checks, authFailureIds}`.
Scores are integers in milli-units; `tallies` are computed from
`checks[]` deterministically (never trusted from the wire);
`authFailureIds` is the auth-gate set for the UI banner; `checks[]`
carries `category` (normalized) + `categoryRaw` (verbatim), `status`,
`title`, `summary`, `citations[]`. Unknown statuses/categories pass
through as strings — forward-compat is contract.

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
| `device-not-active` / `device-error` / `device-exists` / `device-revoked` / `unsupported-algorithm` | device path |
| `pairing-ticket-invalid` / `pairing-ticket-consumed` / `pairing-ticket-expired` | pairing-ticket path |
| `unsupported-event` | verified challenge for unwired flow |
| `replay-detected` | challenge nonce collision |
| `audit-corrupt` | audit-log chain break |
| `consent-required` | deliverability send without the unconsumed consent token (wrong/missing/consumed are indistinguishable) |
| `rate-limited` | provider 429; message carries the retry hint when present |
| `integration-error` | external-integration failure that isn't a covered class (HTTP status, malformed response, oversized body) |
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
