# Contract — Tauri IPC Command Catalog (`kiwi.ipc/1`)

> Owner: Agent 7 · **Contract version: `kiwi.ipc/1`** · Status: implemented (T-120, T-121)
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
from the index. Audited.

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
  "hasAttachments": false, "snippet": "…" }
```

### `kiwi_get_message(accountId, folderId, uid) → MessageBodyView`
Reads the stored body; for IMAP, missing bodies are fetched on demand
(`BODY[]`) and stored — that fetch is itself recorded as a session.

```jsonc
{ "folderId": 1, "uid": 991, "messageId": "<…>" | null, "subject": "…",
  "from": ["a@b"], "to": ["…"], "cc": [], "dateUnix": 0,
  "textBody": "…", "htmlBody": "…" | null,
  "attachments": [ { "filename": "…", "contentType": "…", "size": 123 } ],
  "bodyPresent": true }
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

## 7. Commands — send / outbox **[gated]**

### `kiwi_send_message(accountId, message: ComposeInput, options?) → SendReceipt`
Validates + MIME-builds + enqueues. Delivery is async via the background
dispatcher (1 s tick); undo-send grace (`undoGraceSecs`, default 10, clamp
0–120) and send-later (`sendAtUnix`) are real.

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
True undo — only while `now < undoWindowUntilUnix`.

### `kiwi_list_outbox() → OutboxItem[]`
Envelope metadata only (never bodies):
```jsonc
{ "queueId": "…", "accountId": "…", "from": "…", "to": ["…"],
  "subject": "…", "notBeforeUnix": 0, "undoWindowUntilUnix": 0,
  "attempts": 0, "cancelable": true }
```

### `kiwi_flush_outbox() → { sent, failed, held }`
Force-drain everything (explicit "send now" — skips remaining grace).

### Event `kiwi://outbox`
`{ queueId, accountId, status: "sent|held|blocked|failed", detail, atUnix }`

### Policy bridge behavior (admin-api §10)
When an org is bound (`kiwi_set_org_binding`), each send is evaluated by the
local admin service *after* connect+auth with the observed TLS version:

- `overall == "block"` → send dropped, audited (`send-blocked` with
  per-recipient reasons), `kiwi://outbox` emits `blocked`.
- bridge unreachable / timeout / non-200 / malformed → **fail closed**:
  `held` + linear backoff (30 s × attempt, max 5 attempts).
- transport/auth failure → `held` (retried), terminal at 5 attempts.
- While locked, the dispatcher holds everything (no credential use).

## 8. Commands — security data **[gated]**

### `kiwi_security_findings(accountId?) → Finding[]`
Retained deterministic findings (`kiwi.forensics/1` shape, evidence
included), newest first.

### `kiwi_security_events(limit?) → EventRow[]`
Session journal rows, newest first (default 100, clamp 1000):
```jsonc
{ "id": "app:imap:3", "tsUnix": 0, "accountId": "…" | null,
  "category": "imap sync", "severity": "high",
  "summary": "IMAP imap.x.test:993 tls tls1.3",
  "detailRef": "session:app:imap:3" }
```

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
`policy-unavailable` at config time. Audited.

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

- `MailStore` has no `delete_account`/`list_accounts`; account removal is
  effective via the sidecar index (orphaned row, documented).
- `SendQueue` has no item iterator; `outbox_meta` (in-process) backs
  `kiwi_list_outbox`. Outbox is **in-memory** — pending sends do not
  survive a restart (documented limitation).
- `device_id` on `SecuritySession` is `null` (endpoint binds the session,
  not a device); challenge `sessionId` binds to the boot session.
- Session/findings journals are bounded in-memory rings (512 / 4096).
- `recovery`/`elevated-action` challenges verify but are `unsupported-event`
  until their flows land.
