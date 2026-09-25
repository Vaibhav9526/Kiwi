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
  §9d's canonical commands are registered under their logical names verbatim —
  `invoke("pair_begin", request)` etc. The pre-existing §4/§9 `kiwi_*`
  spellings remain registered as compatibility aliases over the same
  `PairEngine` handlers (no second implementation).
- **`kiwi_ping()`** returns `"kiwi backend ok"` and reports the contract
  version via `kiwi_app_info().contractVersion` (`"kiwi.ipc/1"`).
- Errors serialize as `{ "code": string, "message": string }` — see §8.
- **Wire evolution (serde posture):** view structs are serialize-only —
  consumers must ignore unknown fields. Input structs *also* ignore
  unknown fields (`deny_unknown_fields` is deliberately not set, and
  `#[serde(other)]` is not used anywhere) so a newer renderer may send
  newer optional fields to an older backend without breaking. Enum-typed
  inputs travel as `string` and are validated by command-layer parse
  functions — an unrecognized variant fails closed as `invalid-input`,
  never silently coerced. Enum-typed *outputs* use the kebab-case
  spellings in this contract and security-session.md; a consumer that
  meets an unknown token must render `unknown`, never treat it as a pass
  (SECURITY.md rule 1).
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
  `kiwi_request_challenge`, `kiwi_submit_challenge`, `unlock_challenge`,
  `kiwi_collect_endpoint_signals` (signals feed trust even while locked).
- `pair_begin` / `pair_status` are exempt **only while a backend-owned
  pairing flow is active** (§9d.7); outside it they are gated like the rest.

Everything else — accounts, folders, messages, sync, send/outbox, sandbox
open, findings, events, session detail, report, devices, org binding — is
**gated**.

Lock/unlock semantics come from `kiwi-core::TrustMachine` (sticky `Locked`;
unlock requires an authenticator-verified challenge when
`policy.unlock_requires_authenticator`, which is the default).

## 3. Trust & status shapes

### `SecurityStatusView`

```jsonc
{
  "trust": "secure | warning | danger | unknown", // ui-surfaces §2 token
  "state": "trusted | degraded | locked",
  "score": 0,                       // u32, 100 − Σ penalties
  "locked": true,                   // convenience = state == "locked"
  "requiredAction": "none | warn-user | require-reauth | require-authenticator-unlock | block-access",
  "signals": [SignalView],
  "sessionsObserved": 14,           // connection observations behind the verdict
  "deviceId": "dev-…"
}
```

`requiredAction` spellings are the kiwi-core `RequiredAction` vocabulary
(security-session.md §4). The endpoint-signal list and device registry are
deliberately **not** embedded — this view is re-polled on every UI refresh;
fetch detail via `kiwi_collect_endpoint_signals` (§10) and
`kiwi_list_devices` (§9) instead.

### `SignalView` — one active trust signal

```jsonc
{ "kind": "starttls-downgrade-suspected", "severity": "info|low|medium|high|critical",
  "penalty": 25, "evidenceRef": "endpoint:ep-…" }
```

### `SessionView` — wire view of `kiwi-core::SecuritySession`

Field names follow `security-session.md` §3 verbatim, camelCased
(`sessionId`, `tlsVersion`, `certChain`, `authMechanism`, …). Enum spellings
match the contract (`"tls1.3"`, `"hostname-mismatch"`, `"xoauth2"`, …).
These are **session-view tokens, not forensics wire tags** — embedded
`Finding`/`Report` objects (§8) use FSV-1 snake_case (`"tls13"`,
`"hostname_mismatch"`, `"x_o_auth2"`, `"start_tls"`, …); the two
vocabularies are deliberately distinct (forensics.md §12).

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

### `kiwi_request_challenge(deviceId, event) → ChallengeView` *(compat alias — §9d)*
Compatibility alias over `PairEngine::issue_challenge` — the canonical
unlock issuer is `unlock_challenge(deviceId)` (§9d.4); this name remains
only for the non-unlock events. Issues a challenge bound to
`(deviceId, bootSessionId, event)`.
`event`: `"unlock" | "device-pairing" | "recovery" | "elevated-action"`.
Pairing requires a `pending` device; unlock/recovery require `active`.

```jsonc
{ "challengeId": "chal-…", "deviceId": "dev-…", "sessionId": "boot-…",
  "event": "unlock", "nonceB64": "…", "canonicalBytesB64": "…",
  "issuedUnix": 0, "expiresUnix": 0 }
```
`canonicalBytesB64` is what the authenticator signs.

### `kiwi_submit_challenge(response: ChallengeResponseInput) → SecurityStatusView` *(compat alias — §9d)*
```jsonc
// response
{ "challengeId": "…", "deviceId": "…", "sessionId": "…",
  "event": "unlock", "signatureB64": "…" }
```
Ed25519-verified against the registered device key over canonical bytes —
delegates to `PairEngine::verify_response`, which atomically consumes the
challenge (single-use enforced in the same SQLite transaction as the
activation write; `pair.db` is the persistent nonce/replay ledger). On
success the bound action runs: `unlock` → `attempt_unlock`,
`device-pairing` → `pending → active`. `recovery`/`elevated-action` verify
but currently return `unsupported-event`. Errors: `invalid-signature`,
`challenge-expired`, `already-consumed`, `binding-mismatch`,
`unknown-challenge`, `device-not-active`, `unsupported-algorithm`.
`challenge-expired` is the only emitted spelling; the legacy `expired`
code is withdrawn.

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

`trustToken` is the worst-session-severity roll-up for the account:
`trusted` = clean history, `warning` = medium-severity signals, `locked` =
high/critical signals observed (top tier of this vocab), `unknown` =
nothing observed yet. `degraded` is in the vocabulary but not currently
emitted.

### `kiwi_add_account(account: AddAccountInput) → AccountView`
```jsonc
{ "displayName": "…", "email": "a@b.test",
  "incomingProtocol": "imap",
  "incoming":  { "host": "…", "port": 993, "security": "tls | starttls | plaintext" },
  "outgoing":  { "host": "…", "port": 465, "security": "tls" },
  "username": "…",                    // optional, defaults to email
  "outgoingUsername": "…",            // optional, defaults to username
  "incomingAuth": { "kind": "password | xoauth2 | apop | none",
                    "secret": "…",            // secret used once → OS keystore
                    "oauth2Ticket": "oauth2-…" }, // §9f grant ticket (xoauth2 only)
  "outgoingAuth": { … },
  "acceptInvalidCerts": false }
```
Secrets are stored under generated `kiwi/<accountId>/<in|out>` keys in the
OS credential store (service `kiwi.mail`) — never persisted, logged, or
returned. `apop` is valid for POP3 only; `xoauth2` not for POP3.

**OAuth2 wizard path (T-230, §9f):** when `kind` is `"xoauth2"` an
`oauth2Ticket` naming a *completed* `kiwi_oauth2_begin` grant binds the
already-stored token set — both `AuthRef`s carry the grant's
`oauth2/<provider>/<email>` key (one grant covers IMAP+SMTP), and
`secret` is unnecessary/ignored. When both `incomingAuth` and
`outgoingAuth` name a ticket it must be the SAME ticket; a ticket begun
with an email must match `email` (case-insensitive). Unknown/incomplete/
mismatched tickets → `oauth2-incomplete` or `invalid-input`. Without a
ticket, `xoauth2` keeps its legacy behavior: `secret` is the raw token
blob stored under the generated `kiwi/` key.

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
  "findings": [Finding],              // kiwi.forensics/2 shape (FSV-1 tags)
  "trust": SecurityStatusView }
```
A failed probe returns `ok: false` with the failing step — it is *not* an
IPC error. IPC errors are reserved for invalid input / locked.

### `kiwi_discover_account(email) → DiscoveryOutcomeView` **[gated]** — implemented (T-230)

> Requested by Agent 8 (authoritative shape source: autoconfig.md,
> `kiwi.autoconfig/1`); implemented in `kiwi-app/src-tauri`
> (`commands/autoconfig.rs`). Field names below follow ipc.md camelCase
> conventions; the Rust source (`kiwi_autoconfig::discover`) is
> snake_case — rename per field as shown.

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
                   "auth": "password | xoauth2", "username": "…" },
    "oauth2": { "provider": "google | microsoft",
                "grant": "loopback_code | device_code" } | null },
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

`suggestion.oauth2` (T-230) is present iff the suggestion needs XOAUTH2
**and** the incoming host is one a shipped provider config can service
(IMAP `imap.gmail.com`/`outlook.office365.com`, incl. MX-heuristic hits —
fail-closed for unsupported OAuth2 providers and for POP3). The wizard
passes `oauth2.provider` to `kiwi_oauth2_begin` directly; `grant` tells
it which UX to render without a second lookup.

**Alias** (T-230, drift-audit UIS-6): `kiwi_lookup_autoconfig(email)`
is registered with the identical signature and response — the name the
pre-reconcile `ipc.ts` wrapper invoked. New code must call
`kiwi_discover_account`; the alias exists so stale wrappers keep working.


## 6. Commands — mail read **[gated]**

### `kiwi_list_folders(accountId) → FolderView[]`
```jsonc
{ "id": 1, "accountId": "a1", "name": "INBOX",
  "uidValidity": 123 | null, "uidNext": 995 | null, "highestUid": 994,
  "exists": 42, "unseen": 7 }
```
Folders appear after the first sync (IMAP LIST auto-registers them).
`uidValidity`/`uidNext` are `null` until a sync has selected the folder.
`exists`/`unseen` (T-264) are real `COUNT` queries over stored rows —
`exists` is the row total, `unseen` is rows lacking a `\Seen` token
(exact token match, case-insensitive per IMAP flag semantics). Counts
always reflect the store at call time: flag ops, moves, junk marking,
and deletes are all accounted — nothing is cached or approximated.
Snoozed/parked rows **count** toward both (snooze defers display, it
doesn't suppress — same principle as §6e search). The unread badge reads
`unseen`.

### `kiwi_list_messages(accountId, folderId, limit?) → MessageView[]`
Newest first. `limit` default 50, clamp 1–500. `folderId` must belong to
`accountId` (cross-account reads → `not-found`).

```jsonc
{ "id": 12, "folderId": 1, "uid": 991, "messageId": "<…>" | null,
  "subject": "…" | null, "fromAddr": "…" | null, "toAddrs": "…" | null,
  "dateUnix": 0 | null, "size": 1234 | null, "flags": ["\\Seen"],
  "unread": true, "starred": false,
  "hasAttachments": false, "snippet": "…" | null, "bodyStored": true,
  "inReplyTo": "<…>" | null, "references": ["<…>"],
  "category": "primary | newsletters | social | notifications | other",
  "unsubscribeUrl": "https://…" | null, "unsubscribeMailto": "…" | null,
  "unsubscribeOneClick": false, "unsubscribeRequiresConsent": false,
  "auth": AuthView | null, "attachRisk": AttachRiskView | null }
```

`subject`/`fromAddr`/`toAddrs`/`dateUnix`/`size`/`snippet` are `null` when
the envelope field was not captured — `null` is honest absence, never an
empty string. `unread`/`starred` are derived from `flags` (`\\Seen` /
`\\Flagged`); `unsubscribe*` are the T-202 sender-advertised endpoints
(`unsubscribeRequiresConsent` marks a `mailto:`-only offer — compose needs
explicit consent); `category` is the T-201 deterministic inbox tab;
`auth` (T-232) and `attachRisk` (T-254) are `null` until the stored body
has been parsed — render unknown, never safe.

`inReplyTo`/`references` (T-169, header-chain threading): populated from
a bounded sidecar cache (50k entries) filled by the sync-time
`BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]` fetch on newly-seen
uids, or lazily from stored bodies (≤32 parses per list call). `null`/
`[]` means "unknown" — no-body messages predating the cache learn on
their next sync or body fetch.

### `kiwi_search_messages(query, folderId?, limit?) → SearchHitView[]` (T-231)
FTS5 over the local store (`kiwi_mail::search` — subject/from/to/snippet
columns; `body:` terms match the snippet proxy). Grammar: plain terms,
`subject:`/`from:`/`to:`/`body:` scopes, `"quoted phrases"`, `-negation`;
≤8 terms, `limit` default 50 clamp 1–500, `query` bounded at 512 chars.
`folderId` (must be ≥0) scopes to one folder; omitted → every folder.
`accountId` is resolved server-side from the folder row per hit.
`has:`/`folder:` are UI post-filters and are not part of this grammar.

```jsonc
{ "accountId": "a1", "folderId": 1, "uid": 991, "subject": "…",
  "fromAddr": "…", "snippet": "…", "dateUnix": 0,
  "hasAttachments": false }
```

Errors: `invalid-input` (query >512 chars, `folderId` < 0), `locked`,
`internal` (store failure).

### `kiwi_get_message(accountId, folderId, uid) → MessageBodyView`
Reads the stored body; for IMAP, missing bodies are fetched on demand
(`BODY[]`) and stored — that fetch is itself recorded as a session.
`inReplyTo`/`references` come from the parsed body (authoritative).

```jsonc
{ "folderId": 1, "uid": 991, "messageId": "<…>" | null,
  "subject": "…" | null,
  "from": ["a@b"], "to": ["…"], "cc": [], "dateUnix": 0 | null,
  "textBody": "…" | null, "htmlBody": "…" | null,
  "attachments": [ { "filename": "…" | null, "contentType": "…",
                   "size": 123 } ],
  "bodyPresent": true,
  "inReplyTo": "<…>" | null, "references": ["<…>"] }
```

`subject`/`dateUnix`/`textBody`/`attachments[].filename` are `null` when
the source message lacked the field or the body part was not parsed —
honest absence, never an empty string. `textBody: null` with
`bodyPresent: true` means the message has no text/plain alternative;
render the sanitized `htmlBody` path instead.

### `kiwi_message_source(accountId, folderId, uid) → MessageSourceView` (T-295)
Verbatim RFC822 source for the reader's "view source" surface (T-292
flagged this as missing). Same fetch semantics as `kiwi_get_message`:
stored body, IMAP `BODY[]` on-demand fetch (recorded + stored) when
absent. A body that is absent locally AND unfetchable is **`not-found`**
— never an empty string. `source` is UTF-8-lossy decoded and capped at
**8 MiB of bytes** with char-boundary walk-back (same rule as
`kiwi_render_body`); `bytes` reports the stored total and `truncated`
marks the cap firing, so the UI can label "first 8 MiB of N".

```jsonc
{ "folderId": 1, "uid": 991, "source": "From: …\r\n…",
  "bytes": 152300, "truncated": false }
```

### `kiwi_sync_account(accountId, folders?) → SyncReportView[]`
IMAP: LIST (when `folders` omitted) → register → incremental
`sync_folder` per folder. POP3: UIDL-diff into `INBOX`; per-account
delete-after-download applies via `kiwi_set_pop3_policy` (below) —
default is leave-on-server.

```jsonc
{ "protocol": "imap", "folder": "INBOX", "folderId": 1,
  "newMessages": 3, "flagUpdates": 0, "expunged": 0, "remoteExists": 42,
  "uidValidityReset": false,
  // pop3 instead fills:
  "downloaded": 0, "deletedRemote": 0,
  // both fill (T-244): rule-apply errors swallowed this pass —
  // rules never fail a sync, but nonzero means some rules didn't run;
  // those messages keep an unwritten eval watermark and retry next pass.
  "ruleFailures": 0 }
```

### `kiwi_set_pop3_policy(accountId, deleteAfterDownload) → Pop3PolicyView` (T-295)
Per-account POP3 server-side deletion. **Default `false`** — drops stay on
the server and UIDL-dedup makes repeat syncs no-ops. `true` issues `DELE`
per ingested message at every later sync: the mail then exists only
locally, so treat the toggle as destructive-on-success and confirm in the
UI. POP3 accounts only — `invalid-input` on IMAP. Persisted in the
sidecar index (`AccountMeta.pop3_delete_after_download`), audited
(`pop3-delete-policy`). The live-sync worker reads the same flag, so the
policy applies identically to manual and scheduled passes.

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
unfetched bodies. Output capped at **8 MiB of UTF-8 bytes** — truncation
rounds down to a code-point boundary, so the wire value is always valid
UTF-8 and never exceeds the cap.

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
  "trashFolderId": 4 | null, "uidMap": { "12": 7 } }
```
`trashFolderId` is `null` when nothing moved (hard delete, already-empty
selection) — `movedToTrash > 0` guarantees it is set.

### `kiwi_move_messages(accountId, srcFolderId, dstFolderId, uids) → MoveResultView` (T-163)
Generic folder move. **Cross-account guard**: both folders must resolve
on `accountId` — a foreign `dstFolderId` is `not-found`, never a partial
cross-account write. IMAP `UID MOVE` + local move; POP3 local-only.
Audited.
```jsonc
{ "srcFolderId": 1, "dstFolderId": 5, "moved": 3,
  "uidMap": { "12": 41 } }
```

### `kiwi_message_unsubscribe(accountId, folderId, uid, action, consent?) → UnsubscribeResultView` (T-234)

Executes the stored List-Unsubscribe offer on a message — the action the
unsubscribe chip actually performs. `action` is `"http"` or `"mailto"`;
the endpoint comes from the message row (`unsub_http` / `unsub_mailto`
from §6 ingest), never from caller-supplied URLs.

**`action: "http"`** — POSTs the stored `unsub_http` URL through the
shared integration transport (HTTPS-only — a stored `http://` URL is
`invalid-input` before any socket; no redirects; capped response body).
When the message carries the RFC 8058 marker (`unsub_oneclick`), the POST
sends `Content-Type: application/x-www-form-urlencoded` +
`List-Unsubscribe=One-Click`; otherwise it is a bare POST.
**Consent rule:** one-click offers execute on the click alone; a plain
http URL requires `consent: true`.

**`action: "mailto"`** — enqueues a minimal `unsubscribe` message to the
stored `unsub_mailto` address through the normal outbox (`send-queued`
audited, undo-send grace applies — `queueId` + `undoWindowUntilUnix`
returned). **Always requires `consent: true`** — sending from the user's
own address reveals identity to the list operator; never silent.

Consent is enforced server-side; the flag is a request field, not UI
trust. A refused call returns `consent-required` and touches nothing —
no HTTP request, no outbox row, no audit entry. `action` values outside
`"http"`/`"mailto"` are `invalid-input`; a message with no stored offer
of the requested kind is `not-found`. Every executed action writes one
audit row (`unsubscribe-http` / `unsubscribe-mailto`).

```jsonc
// http → { "action": "http", "executed": true, "httpStatus": 200,
//          "queueId": null, "undoWindowUntilUnix": null }
// mailto → { "action": "mailto", "executed": true, "httpStatus": null,
//            "queueId": "send-…", "undoWindowUntilUnix": 1758300000 }
```

`executed: true` means the request left the process (http: a response was
received; mailto: queued). `httpStatus` <400 means the endpoint accepted
the unsubscribe — a 4xx/5xx is still `executed` but reported so the UI
can tell "sent" from "probably ignored".

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

Consumer (T-271): `onMailChanged` (ipc.ts) is subscribed once at App
level and debounced ~300 ms into a single message-list + folder-count
refresh; a burst carrying `newMessages > 0` raises one summary toast.
A listener MUST debounce — a sync pass emits per folder, and a naive
per-event reload re-enters `listMessages` under the worker.

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

## 6d. Commands — inbox rules **[gated]** (T-228 engine, T-233 surface)

Deterministic mail-file rules (F1 / backlog T-200's frontend continues
separately). Evaluation lives in `kiwi_mail::rules` — the IPC layer is a
thin pass-through; renderer-supplied specs are re-validated at the store
boundary (`Rule::validate`), rejections surface as `invalid-input`.

Semantics contract: **block rules first** (`isBlock: true` — evaluated
before all regular rules, first match is terminal, verdict = move to
Trash), then regular rules by `position` ascending with `id` as
tie-breaker — a total order. Flag actions dedupe; at most one folder
disposition applies. The evaluator is pure: no I/O, no clock, no guessed
facts — a missing header/body/attachment fact simply doesn't match.

**Body predicates are lazy.** IMAP metadata sync evaluates only the
envelope-stage rules available for newly stored messages; it does **not**
fetch a body solely to evaluate a body, header, or attachment predicate.
Instead, evaluation is staged and watermarked per message (the store's
`rule_evals` table): stage `envelope` marks an envelope-facts eval, stage
`full` a complete-parse eval. A stored-body message that has only the
envelope watermark is a **deferred** candidate — whenever its body arrives
by *any* fetch path (lazy view load, prefetch, `apply_now`), the *next*
`sync_folder` pass re-evaluates it with the full predicate set. That
re-eval is the documented contract; the on-view loader itself never runs
rules, so a rule can't move a message while it's open under the reader.
POP3 has a full body at download and evals `full` immediately. A missing
body is skipped rather than downloaded for rules; this bandwidth policy is
binding. `kiwi_rules_apply_now` is the deliberate way to evaluate stored
mailbox bodies on demand. Apply failures are counted on `SyncReportView`'s
`ruleFailures` and leave the watermark unwritten — the next pass retries.

### `kiwi_rules_list(accountId?) → RuleView[]`
With `accountId`: the rules in scope for that account (global `accountId:
null` rules **plus** its own), in evaluation order. Omitted: global rules
only. `accountId` bound: ≤128 chars.

```jsonc
[{ "id": "r1", "accountId": "a1" | null, "name": "…", "enabled": true,
   "position": 0, "isBlock": false, "failureCount": 0,
   "lastError": null, "lastFailureUnix": null,
   "when": { "kind": "sender", "op": "domain", "value": "corp.example" },
   "then": [{ "do": "move", "folder": "Work" }] }]
```

`when` is a predicate tree — kinds `sender` / `recipient` / `subject` /
`header` (`{kind:"header","name":"list-id", …}`) / `body_contains` /
`attachment_name`, with combinators `all` / `any` / `not` and `always`.
Match ops: `contains` | `is` | `ends_with` | `domain` (`domain` = dot-
boundary suffix match on the post-`@`/domain part — `evil.com` matches
`x.evil.com`, never `notevil.com`; `sender`/`recipient` match the email
address, never the display name). `then` is `{"do":"move","folder":…}` |
`{"do":"archive"}` | `{"do":"delete"}` | `{"do":"mark_read"}` |
`{"do":"star"}`. `archive`/`delete` resolve to the account's
`Archive`/`Trash` folders — rules never hard-expunge.

### `kiwi_rules_upsert(rule: RuleView) → RuleView`
Create-or-replace by `id` (ids are caller-assigned, ≤64 chars). Full
`Rule::validate` bounds run again at the store (id/name/fields, ≤8
actions, ≤32 predicate nodes, ≤8 nesting depth, header-name token
rules). `accountId` must reference an existing account → `not-found`.
Returns the stored view.

### `kiwi_rules_delete(ruleId) → { removed: bool }`
Deletes the rule. Its audit rows in `rule_hits` survive — `ruleId` there
is evidence, not a join (kiwi.mail/1 §evidence: a deleted rule must not
erase the record of what it did).

### `kiwi_rules_apply_now(accountId) → RulesApplyView`
"Run rules now": re-evaluates the account's stored mailbox (Trash never
scanned — rules don't resurrect deleted mail), executes outcomes, writes
hit rows. Deterministic + idempotent: the work list is frozen up front,
each message evaluated once; re-runs converge. Messages without a
parseable stored body are skipped, not guessed.
Unknown `accountId` → `not-found`.

```jsonc
{ "scanned": 40, "matched": 7, "moved": 5, "blocked": 1,
  "flagsChanged": 4, "skippedNoBody": 2 }
```

### `kiwi_rules_hits(accountId, limit?) → RuleHitView[]`
The matched-rule audit trail (transparency surface — task requirement
3), newest first. `limit` default 100, clamp 1–1000. `folderId`/`uid` are
the eval-time coordinates (a later move doesn't rewrite the record);
`messageId` is the stable cross-move identity.

```jsonc
[{ "folderId": 3, "uid": 712, "ruleId": "r1",
   "messageId": "<m@x>", "appliedUnix": 1758000000 }]
```

### `kiwi_rules_preview(accountId, rule: RuleView, limit?) → RulePreviewView`
"Test this rule" dry-run for the editor (T-244): evaluates one candidate
rule — alone, not ordered against the stored ruleset — against the newest
`limit` stored messages (Trash excluded; default 50, clamp 1–200).
**Pure read**: no moves, no flag changes, no hit rows, no eval watermarks.
The candidate runs the same `Rule::validate` gate as `upsert` —
`invalid-input` on violation; unknown `accountId` → `not-found`.

```jsonc
{ "scanned": 48, "skippedNoBody": 2, "matched": 3,
  "hits": [ { "folderId": 1, "uid": 9, "folder": "INBOX",
              "subject": "…", "messageId": "…",
              "conditionHits": [ { "path": "$.children[0]", "kind": "sender" } ] } ] }
```

Candidates without a parseable stored body are `skippedNoBody` (a rule
that *would* match an unfetched body does not appear — preview reports
what stored evidence shows, never guesses). `conditionHits` lists only true
predicate leaves using stable AST paths (`$`, `$.children[n]`, `$.child`); it
never returns the matched address, header, or body value.

### Ingest-time application (sync path — no IPC entry)
The same engine runs automatically during sync: IMAP `sync_folder`
evaluates envelope-stage rules on new INBOX messages (block verdicts
trash before the body is ever fetched) and ends each pass with a bounded
deferred sweep — stored-body INBOX messages missing a `full` watermark
get the complete predicate set. `fetch_missing_bodies` and the POP3 path
evaluate `full` after parsing. Other folders are not reprocessed at
ingest — `apply_now` is the deliberate re-run. A UIDVALIDITY reset wipes
the folder's eval watermarks along with its messages (a new UID epoch
can't inherit stale stage records). Apply errors inside a pass are
swallowed and counted on `SyncReportView.ruleFailures`; the unwritten
watermark makes the retry automatic. Each failed application also increments
`failureCount` and stores the bounded `lastError`/`lastFailureUnix` on every
matched rule; list views expose these store-owned fields so the UI can badge a
broken rule. `rules_upsert` ignores renderer-supplied health fields.

## 6g. Commands — sandbox open **[gated]** (T-266)

Both commands are the only path for opening a hostile link or attachment.
They fail closed: an absent/unusable provider returns
`{"code":"sandbox-unavailable"}`; there is **never** a host browser or host
process fallback. A completed open appends the hash-chained `sandbox-opened`
audit action with a sanitized target and its evidence reason codes.

### `kiwi_sandbox_open_link(url) → SandboxOpenView`

`url` is bounded at 2,048 characters and must be an absolute `http://` or
`https://` URL with a host. Other schemes (including `file:`, `mailto:`, and
`javascript:`) return `invalid-input`; hostile HTTP is deliberately passed to
the sandbox boundary. The backend associates the URL with the matching stored
message evidence when possible and passes the message's `linkRisk.reasons` into
the provider session. The returned/report `target` and audit row remove URL
username/password, query, and fragment; the full target is never persisted.

```jsonc
{ "sessionId": "sandbox:3",
  "target": "https://example.test/path",
  "evidenceReasons": ["insecure-http", "ip-literal-host"],
  "report": { /* bounded AnalysisReport; evidenceReasons repeats why */ } }
```

A link-capable provider must enforce and monitor isolated egress. The current
WSL2 artifact tier structurally blocks egress and therefore returns
`sandbox-unavailable` for links rather than claiming the URL was opened.

### `kiwi_sandbox_open_attachment(folderId, uid, filename) → SandboxOpenView`

The input is a **stored payload reference only**: the backend re-opens the
message's stored MIME body, requires exactly one exact filename match, stages
the decoded bytes privately, invokes the provider, and deletes the staging
path afterwards. Raw attachment bytes and host paths never cross IPC and are
not echoed. Decoded size is bounded at 64 MiB and at the active provider's
`maxArtifactBytes`. The message's `attachRisk.reasons` are handed into the
session record; absent evidence is explicitly `evidence-unavailable`, never
clean. `target` is the coordinate `attachment:f<folderId>/u<uid>`, never the
filename or staging path.

Errors: `locked`, `invalid-input`, `not-found` for the stored reference,
`sandbox-unavailable`, or `sandbox-failed`. No host-open fallback.

## 6h. Command — message link-click policy **[gated]** (T-273)

### `kiwi_link_click(accountId, folderId, uid, url) → LinkClickVerdict`

The renderer calls this before `kiwi_open_external` for every link sourced from a
message. The backend resolves the account/folder/message coordinates, reads the
stored T-261 `linkRisk`, and freshly classifies **this exact URL** (no DNS,
resolution, redirect following, or opening). Evidence is merged with
failure-first precedence; the click URL is never persisted. A missing stored
sibling row is `requireConfirm` with `stored-evidence-unavailable`, never clean.

```jsonc
{ "action": "allow | requireConfirm | requireSandbox | deny",
  "reasons": ["insecureHttp", "ipLiteralHost"] }
```

- `allow` — stored evidence exists and the merged risk is clean.
- `requireConfirm` — merged risk is noted; this is advisory UI copy.
- `requireSandbox` — merged risk failed. The caller must use
  `kiwi_sandbox_open_link`; `kiwi_open_external` refuses this source with
  `sandbox-required` and has no host-browser bypass.
- `deny` — the clicked URL is not absolute HTTP(S), regardless of stored risk.

Every returned verdict appends hash-chain audit action `link-clicked` with the
message coordinate, verdict, and bounded reason codes (never URL/domain/body).

## 6e. Commands — snooze **[gated]** (T-255)

Reversible **local-only** parking: a snoozed message keeps its `messages`
row in place — nothing moves server-side or locally — but the `snoozed`
table hides it from `kiwi_list_messages` (and category tabs) until the
deadline passes. Deletion, expunge, account removal, and UIDVALIDITY
reset all drop the parking row by foreign-key cascade; a store move
re-keys it, so a parked message dragged to another folder stays parked
(`snoozedFromFolderId` still records where it was parked). Because the
remote uid never moves, a parked message is never re-downloaded as new
mail.

### `kiwi_message_snooze(accountId, refs, untilUnix?, preset?) → SnoozeResultView`

```jsonc
// refs — 1..500 entries, deduped, non-negative, EVERY folderId must
//        belong to accountId (cross-account ref ⇒ not-found):
{ "accountId": "…", "refs": [ { "folderId": 1, "uid": 9 } ],
  "preset": "tomorrow" }            // XOR:
{ "accountId": "…", "refs": [ … ], "untilUnix": 1730000000 }

{ "snoozed": 1, "untilUnix": 1730086400 }
```

Deadline is exactly one source — both set or neither ⇒ `invalid-input`.
`untilUnix` must be in the future and ≤ ~2 years out (a far-future value
is a renderer bug — usually milliseconds — so it's refused). Presets are
**fixed offsets resolved server-side** (clients can't disagree):
`later_today` +3h, `tomorrow` +24h, `next_week` +7d — they are *not*
wall-clock-aware ("tomorrow 9am local" needs a TZ database; if a client
wants that it computes `untilUnix` itself). Unknown preset ⇒
`invalid-input`. Re-snoozing a parked message updates the deadline
(`set_at` refreshed, `from_folder` kept). Audit record
`messages-snoozed` is written (trivial, per T-255).

### `kiwi_message_unsnooze(accountId, refs) → UnsnoozeResultView`

Same `refs` shape and validation. Removes the parking row — the message
reappears in whatever folder it lives in (snooze never moved it).
Idempotent: unsnoozing a non-parked ref counts 0, not an error.
`{ "unsnoozed": n }`. Audit record `messages-unsnoozed`.

### `kiwi_list_snoozed(accountId, limit?) → SnoozedMessageView[]`

The account's parked mail, soonest-due first (`limit` default 200, clamp
1–1000; unknown `accountId` ⇒ `not-found`). Messages parked into a
Trash-named folder stay hidden here — trash is the stronger state — but
still release on schedule.

```jsonc
[ { "folderId": 1, "uid": 9, "folder": "INBOX",
    "snoozedFromFolderId": 1, "snoozedUntil": 1730086400,
    "snoozedAt": 1730000000, "subject": "…", "fromAddr": "…",
    "messageId": "…", "dateUnix": 1729990000 } ]
```

### Due release (sync path — no IPC entry)

Every sync pass starts with a bounded sweep
(`MailStore::unsnooze_due`, ≤200 rows, ordered by `until_unix` then
`folder_id`/`uid` — deterministic, converges pass-to-pass): rows with
`until_unix <= now` are deleted, so the messages reappear in their
folder lists on that pass. Runs for both IMAP `sync_folder` and POP3
`sync_pop3`; sweep errors are swallowed — snooze state never aborts
mail sync. There is no push event for a release; the next mail-changed
emission covers it.

## 6f. Commands — junk **[gated]** (T-263)

User-driven junk marking — sets/clears the canonical `\Junk` store flag
(T-212's `JUNK_FLAG`) and moves the message to/from the account's Junk
folder. This is the manual path; deterministic verdicts elsewhere
(auth/attachment/link evidence) never auto-junk — junking is the user's
call or a rule's explicit action.

### `kiwi_message_set_junk(accountId, refs, junk) → SetJunkView`

```jsonc
{ "accountId": "…", "junk": true,
  "refs": [ { "folderId": 1, "uid": 9 } ] }   // same contract as §6e —
                                            // 1..500, deduped, every
                                            // folderId on this account

{ "junk": true, "flagged": 2, "moved": 2,
  "targetFolderId": 7,
  "moves": [ { "fromFolderId": 1, "fromUid": 9, "toUid": 1 } ] }
```

- **`junk: true`** — add `\Junk` locally + `UID STORE +FLAGS.SILENT
  (\Junk)`, then move into the account's Junk folder (`UID MOVE` /
  local `move_messages`). Junk folder resolution mirrors Trash: local
  name match (`junk`, `spam`, `junk e-mail`, `bulk mail`, …) → live
  LIST for `\Junk` special-use → CREATE "Junk". Refs already inside a
  Junk-named folder only get the flag — no self-move.
- **`junk: false`** — remove `\Junk`; refs sitting in a Junk-named
  folder move back to INBOX, others only lose the flag. There is no
  origin tracking — INBOX is the un-junk destination by convention.
- **Flag timing** — IMAP applies the flag *immediately* on the
  command's own connection (flag first, then the move, at the source
  coordinates). There is no deferred flag queue; the next sync's
  flag-diff is the reconciliation net. POP3 has neither server flags
  nor folders — the local flag + move is the whole effect.
- **Idempotent** — already-correct flags aren't counted (`flagged`
  counts real changes); absent uids are skipped, not errors.
- **Snooze interaction** — the move re-keys parking rows, so junking a
  snoozed message keeps it parked (it releases on schedule inside
  Junk). Audit: `messages-junked` / `messages-unjunked` with counts.
- `moves` lists every relocation as `{fromFolderId, fromUid, toUid}`
  (uids are folder-scoped; a move is copy-under-fresh-uid + source
  delete). `targetFolderId` is the Junk id for `junk`, the INBOX id
  for un-junk-from-Junk; `null` when nothing moved.

## 6i. Commands — message templates **[gated]** (T-288)

Composer boilerplate: a flat named list — content, not policy, so no
account scoping or ordering. The stored row keeps `{{name}}`
placeholders verbatim; substitution happens only at `render`.

```ts
interface TemplateView {
  id: string;            // `tpl-N`, store-assigned on create
  name: string;          // non-blank, ≤128 B
  subject: string;       // ≤998 B (RFC 5322 line cap)
  bodyText: string;      // ≤64 KiB
  bodyHtml?: string;     // optional, ≤128 KiB — omitted (not null) when absent
  createdUnix: number;
  updatedUnix: number;
}
interface TemplateInput {      // create payload — no id/timestamps
  name: string;
  subject?: string;
  bodyText?: string;
  bodyHtml?: string;
}
interface RenderedTemplateView {
  subject: string;
  bodyText: string;
  bodyHtml?: string;           // omitted when the template has none
  missingVars: string[];       // sorted+deduped well-formed names with no value
}
```

### `kiwi_templates_list() → TemplateView[]`
Name-then-id order.

### `kiwi_templates_create(template: TemplateInput) → TemplateView`
Store assigns `tpl-N` + both timestamps. The `tpl-` prefix is reserved —
a caller-supplied id using it fails `invalid-input`; any other explicit
id is stored as given. Audit: `template-created` (id only — bodies are
user content and never enter the log).

### `kiwi_templates_update(template: TemplateView) → TemplateView`
Full replace by `id`, not a merge — `createdUnix` is preserved from the
stored row, `updatedUnix` bumps. Absent id → `not-found`.
Audit: `template-updated` (id only).

### `kiwi_templates_delete(templateId) → { removed: bool }`
Idempotent — `removed: false` is a normal answer, not an error.
Audit: `template-deleted` (id only, only when a row existed).

### `kiwi_templates_render(templateId, vars?) → RenderedTemplateView`
Server-side `{{name}}` substitution — the composer gets ready-to-use
fields, and placeholder semantics stay tested once in Rust rather than
re-implemented in the renderer. Grammar (`kiwi_mail::templates`):

- Token: `{{` + name + `}}`; name is `[A-Za-z0-9_.-]+` ≤64 B, inner
  whitespace trimmed (`{{ name }}` works). Invalid or unterminated
  tokens are literal text — never reported, never guessed.
- Single non-recursive pass: a substituted value containing `{{x}}`
  stays literal.
- Unknown names stay verbatim **and** are reported in `missingVars`
  (sorted, deduped) — the composer flags them.
- `vars` is a flat `{name: value}` object: ≤64 entries, values ≤4 KiB;
  violating bounds fails `invalid-input` (no partial render).

Errors: `locked`, `invalid-input` (bounds/validation), `not-found`
(render/update of an absent id).

Audit posture: create/update/delete are recorded (drafts-adjacent writes
— tamper-evident trail costs nothing and matches contacts); `list` and
`render` are reads and unaudited. Template **content** never enters the
log — event detail is the id only.

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
{ "queueId": "…", "accountId": "…" | null, "from": "…", "to": ["…"],
  "subject": "…", "notBeforeUnix": 0, "undoWindowUntilUnix": 0,
  "attempts": 0, "cancelable": true,
  "state": "queued" | "held", "lastError": "…" | null }
```
`accountId` is always set by `kiwi_list_outbox` today — the field is
`Option` headroom for queue rows that predate account binding; clients
must tolerate `null` (render "unbound"), never assume an account.
`cancelable` mirrors the `kiwi_cancel_send` rule (undo window open or
send-later slot still ahead).

**`state` (T-298)** — derived from persisted row fields, never stored
as a label: `attempts > 0` means a dispatch attempt already failed and
the row only survives because retries remain → `"held"`; `attempts == 0`
→ `"queued"` (covers send-later slots and undo-grace). The wire
vocabulary is `queued | sending | held | cancelled | sent`, but the
list only ever emits the first pair — `sending` is a sub-second
in-memory transient not derivable from the row, and terminal outcomes
(`sent`, `cancelled`, retry-exhausted `failed`) delete the row, so they
are observable only via the `kiwi://outbox` event below.

**`lastError`** — sanitized `code: message` of the most recent failed
attempt (persisted on the row, survives restart, ≤512 B at the store
boundary). `null` until the first failure — a queued send has nothing
to report. Cleared when a human reschedules (a recommit, not a retry).

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
Retained deterministic findings (`kiwi.forensics/2` shape verbatim —
FSV-1 enum tags, forensics.md §12; session-view spellings like
`tls1.3`/`starttls` apply only to `SessionView`/`EventRow`, §3),
evidence included. This is forensics.md §11 `list_findings`:
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
{ "finding": { /* full kiwi.forensics/2 Finding, evidence included */ },
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
`kiwi.forensics/2` report built from retained findings
(`generatedFrom: "live"`, limitation noting live-observation scope).

## 9. Commands — devices / org binding **[gated]**

### `kiwi_register_device(input: RegisterDeviceInput) → DeviceView` *(compat alias — §9d)*
```jsonc
// input
{ "label": "…", "algorithm": "ed25519 | ecdsa-p256 | rsa3072",
  "publicKeyB64": "…", "keystoreRef": "…" | null }
// view — the §9d.5 PairDeviceView projection
{ "deviceId": "dev-…", "label": "…", "algorithm": "ed25519",
  "status": "pending | active | suspended | revoked",
  "registeredUnix": 0, "lastSeenUnix": 0,
  "keyFingerprintTail": "a1b2c3d4",
  "fingerprint": "6668-7aad-…", "keystoreRef": "…" | null,
  "revokedUnix": null }
```
`keyFingerprintTail` = last 8 hex chars of SHA-256 over the raw public
key — a short display fingerprint for the registry UI (ui-surfaces §3),
NOT an authentication token; verification goes through the challenge
flow (§4). `fingerprint` is kiwi-pair's full dash-grouped digest for
out-of-band comparison; `keystoreRef` is an opaque alias.
New devices are `pending` — they activate via a `device-pairing` challenge
(§4). Only `ed25519` signatures verify today (`unsupported-algorithm`
otherwise). Duplicate normalized labels are rejected with `conflict`
(§9d.5). The private key never enters this process.

### `kiwi_list_devices() → DeviceView[]` *(compat alias for `device_list` — §9d.5)*

### `kiwi_revoke_device(deviceId) → SecurityStatusView` *(compat alias for `device_revoke` — §9d.6)*
Terminal revocation — audited; persisted in `pair.db` (survives restart);
feeds `device-revoked` (hard-lock kind) into the next trust evaluation.

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
| `kiwi_import_vcards(vcardText)` | `VCardImportView` | below |
| `kiwi_export_vcards(contactIds?)` | `{vcard}` | all contacts when omitted; unknown explicit id → `not-found` |

`kiwi_import_vcards(vcardText)` — the argument is `vcardText` (Rust
`vcard_text` → Tauri camelCase; `vcard` is rejected as an unknown arg).
Hard stream errors abort as `invalid-input`;
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

## 9d. Commands — pairing engine, kiwi-pair **[partly gated]** (T-188, ratified; T-269, implemented)

> **RATIFIED by Lead 2026-09-25 (T-188); implemented T-269.** The five
> logical command names below are canonical and registered:
> `pair_begin`, `pair_status`, `unlock_challenge`, `device_list`, and
> `device_revoke`. The §4/§9 `kiwi_request_challenge`,
> `kiwi_submit_challenge`, `kiwi_register_device`, `kiwi_list_devices`,
> and `kiwi_revoke_device` names are compatibility aliases over the same
> `PairEngine` handlers — there is no second implementation or frontend
> call path. `pair_status` is served by the read-only `ticket_status` API
> and the atomic consume+register+link transaction described in §9d.3.
> `AppState` owns exactly one persisted `PairEngine` (`pair.db` under the
> profile dir); the old in-memory `DeviceRegistry`/`ChallengeBook`
> stand-ins are removed.

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
| `pair_status` | `ticket_status(ticket, now)` | non-mutating lookup over the `pairing_tickets.device_id` link (schema v2); see §9d.3 |
| `unlock_challenge` | `issue_challenge(ChallengeSpec { challenge_id, device_id, session_id, event: Unlock, nonce }, now, CHALLENGE_TTL_SECS)` | backend generates every field except `device_id` |
| `device_list` | `list_devices(limit)` + `device_fingerprint(device_id)` per row | projects `DeviceRow`; never returns the raw public key; store orders `registered_unix, device_id` |
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

**Implemented (T-269).** `PairEngine::ticket_status` is the persistent,
non-consuming lookup returning ticket state plus the linked device id, and
schema v2 adds `pairing_tickets.device_id`. Ticket consumption, device-row
creation, and the ticket→`device_id` link commit in one SQLite transaction
(`claim_ticket_and_register`) — partial consumption without a linked
registration is impossible. Expired claimed rows are retained so a `claimed`
verdict survives ticket expiry; only expired *unlinked* rows are pruned.

Calling `consume_pairing_ticket` from a polling UI remains a correctness and
security defect and is not done. Caching the bearer ticket in kiwi-app to
work around the lookup is also refused; `AppState.pair_flow` holds only the
*active-flow* ticket for the renderer's own open QR — never a lookup cache —
and its lifetime is bounded by the ticket expiry.

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

**RATIFIED canonical wire format — implemented (T-269).** `nonceB64` is the
only nonce field: RFC 4648 standard Base64 with canonical padding, decoding
to exactly 32 bytes. It matches `authenticator.md` §4.2. The `nonceHex`
spelling is withdrawn; no handler emits or accepts it.

The renderer supplies only `deviceId`. The backend generates `challengeId`,
uses `os_nonce()` for the 32-byte nonce, binds the current boot `sessionId`,
reads the clock once, fixes `event = Unlock`, and passes
`CHALLENGE_TTL_SECS` (120; engine maximum 300). No `nonce`, `sessionId`,
`challengeId`, `event`, or `ttlSecs` request field exists: each would let an
untrusted renderer weaken binding or replay protection.

`unlock` requires an `active` device. Pending/suspended devices return
`device-not-active`; revoked devices return `device-revoked` and can never be
challenged again. The signed response is submitted through §4's
`kiwi_submit_challenge` shape, which delegates to `PairEngine::verify_response`
— the in-memory `ChallengeBook` is gone; `pair.db` is the sole challenge and
replay store.

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
ids fail with `device-exists`. Duplicate *normalized labels* (case/space-
folded) are rejected with `conflict` on registration — the IPC analogue of
the admin `409` — and rows are never silently merged (T-269). The separate
org-admin inventory enforces the same rule at its write boundary
(admin-api.md §14).

The IPC projection MUST impose a total order: `registeredUnix` ascending,
then `deviceId` ascending. The store enforces it in SQL
(`ORDER BY registered_unix, device_id`) with the IPC-side `limit` bound
clamped to 500.

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

All codes above are reachable in the current engine (T-269): `ticket_status`
distinguishes unknown/consumed/expired tickets honestly, and a
consumed-but-unlinked row reports `pairing-ticket-invalid` (never fabricated
as consumed). `device-revoked` must not collapse into
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
  `verify_response` checks `consume_challenge`'s atomic boolean before
  reporting success — a false return is `AlreadyConsumed`, and the device
  activation commits in the same transaction (T-269 closed the
  multi-instance race).
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
Implementation status (T-269):

1. **Challenge wire migration — landed.** `nonceB64`/`challenge-expired` are
   the only emitted spellings; `nonceHex`/`expired` are withdrawn.
2. **`pair_status` engine + schema change — landed.** `ticket_status` is the
   read-only lookup; `pairing_tickets.device_id` (schema v2) links claims;
   `claim_ticket_and_register` commits consume+register+link atomically.
3. **Atomic challenge consumption — landed.** `verify_response` treats a
   false `consume_challenge` return as `AlreadyConsumed`; activation commits
   in the same transaction.
4. **Pairing transport provisioning — partially landed.** The backend owns
   the trusted channel: desktop endpoint from `KIWI_PAIR_ENDPOINT` or
   `<profile>/pairing-channel.json`, desktop Ed25519 key via the credential
   store (`kiwi.pair.desktop-key`), and `AppState.pair_flow` bounds the
   renderer-visible flow to the live ticket. The LAN claim transport itself
   (TLS/pin listener the phone POSTs to) remains a future task; the ticket
   claim path is exercised through `claim_ticket_and_register` only.
5. **Resource bounds — landed.** Ticket issuance is capped (live unclaimed
   rows) and device listing is `LIMIT`-bounded with the
   `registered_unix, device_id` total order.
6. **Admin device-name uniqueness — deferred** to the admin write boundary
   (admin-api.md §14). IPC-side duplicate normalized labels return `conflict`.
7. **Fingerprint and `lastSeenUnix` — documented.** `fingerprint` is
   display-only on every projection; `lastSeenUnix`'s narrower meaning
   (status transitions only) is documented at §9d.5.

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

## 9f. Commands — OAuth2 acquisition **[gated]** (T-230, implements `kiwi.oauth2/1`)

IPC surface for `kiwi-autoconfig::oauth2` (docs/contracts/oauth2.md). The
account-wizard seam:

1. `kiwi_discover_account` (§5) — its suggestion carries `oauth2` when
   the endpoints are grant-capable.
2. `kiwi_oauth2_begin(provider, email?)` — starts a grant. Returns a
   `ticketId` plus what the user must see.
3. User completes the provider flow (browser redirect, or device-code
   entry) while the UI polls `kiwi_oauth2_poll(ticketId)`.
4. On `status: "complete"` the token set is already persisted through the
   `CredentialStore` seam (`oauth2/<provider>/<email>` key) — or deferred
   in-session when `begin` had no `email`.
5. `kiwi_add_account` with `oauth2Ticket` binds the grant to the account
   and consumes the ticket (§5).

**Secrets discipline (binding):** no IPC payload ever carries access or
refresh tokens, the device code, the PKCE verifier, or the authorization
code. `credentialKey`/`ticketId` are key *names*/opaque ids — none is a
secret. Grants live in a bounded in-memory map (`MAX_OAUTH2_SESSIONS` =
32, evicted expired/failed-first then oldest) and die with the process;
only the persisted `TokenSet` survives, and only inside the OS keystore.
Audit entries record provider + email + outcome, never grant material.

`client_id` is deployment config (never a secret): env
`KIWI_OAUTH2_<PROVIDER>_CLIENT_ID` beats pref `oauth2.<provider>.clientId`
(global scope). Missing/malformed → `oauth2-not-configured` before any
network call.

#### `kiwi_oauth2_begin(provider, email?) → OAuth2BeginView`

```jsonc
// in:  { "provider": "google | microsoft", "email": "u@x.test" }   // email optional
// out (device_code — Microsoft):
{ "ticketId": "oauth2-…", "kind": "device_code",
  "userCode": "ABCD-EFGH", "verificationUri": "https://microsoft.com/devicelogin",
  "verificationUriComplete": "https://…?otc=ABCD",   // when the provider supplies one
  "expiresAtUnix": 0, "pollIntervalSecs": 5 }
// out (loopback_code — Google):
{ "ticketId": "oauth2-…", "kind": "loopback_code",
  "authorizeUrl": "https://accounts.google.com/o/oauth2/v2/auth?…",
  "expiresAtUnix": 0, "pollIntervalSecs": 1 }
```

`device_code`: display `userCode` + `verificationUri`; the user approves
there. `loopback_code`: open `authorizeUrl` in the **system browser** —
the `127.0.0.1` listener is already bound and a waiter thread parks on it
with a 600 s deadline. `provider` is validated against the shipped
registry (`invalid-input`); `email`, when present, is validated
(`invalid-input`) and binds the eventual credential key.

#### `kiwi_oauth2_poll(ticketId) → OAuth2PollView`

```jsonc
{ "status": "pending",                 // pending | complete | error
  "ticketId": "oauth2-…",
  "retryAfterSecs": 5,                 // poll cadence hint (present on pending)
  "provider": "microsoft",             // set on complete
  "email": "u@x.test",                 // set on complete when known
  "credentialKey": "oauth2/microsoft/u@x.test",   // set when persisted
  "errorCode": "oauth2-denied",        // set on error
  "errorMessage": "…" }
```

`status` is a grant state, not an IPC error. **Terminal** failures —
user denial, expiry, endpoint rejection, malformed payloads — arrive as
`status: "error"` (the ticket then stays in `Failed`, repeat polls
re-report it). **Transient** failures (transport) surface as real IPC
errors and the grant stays alive. Unknown ticket → `not-found`. Polling
is single-flight per ticket (the sessions mutex serializes concurrent
pollers); `slow_down` bumps `retryAfterSecs` per RFC 8628 §3.5.

#### `kiwi_oauth2_cancel(ticketId) → OAuth2CancelView`

`{cancelled: bool}` — drops the session. A loopback grant's listener may
stay bound until its deadline (bounded); its outcome is discarded —
cancelling frees the ticket and the wizard path, not the socket's
remaining lifetime.

#### `kiwi_oauth2_status(accountId) → OAuth2StatusView`

Read-only posture of a *stored* account — for settings/troubleshooting
surfaces, never the grant flow.

```jsonc
{ "accountId": "acct-…",
  "authMethod": "xoauth2 | password | apop | none",   // incoming side
  "provider": "microsoft" | null,    // parsed from an oauth2/ grant key
  "email": "u@x.test" | null,
  "credentialPresent": true,         // ANY credential exists at the key
  "expiresAtUnix": 0 | null,         // stored TokenSet expiry
  "needsRefresh": false | null,      // inside/past the 60 s skew window
  "hasRefreshToken": true | null }
```

`provider`/`email`/`expiresAtUnix`/`needsRefresh`/`hasRefreshToken` are
populated only when the credential key is an `oauth2/<provider>/<email>`
grant holding a parseable token blob — legacy `kiwi/` keys and missing
credentials report `credentialPresent` with the lifecycle fields `null`.
Unknown `accountId` → `not-found`.

**Error vocabulary added:** `oauth2-not-configured` (no client id),
`oauth2-incomplete` (ticket unknown at `add_account`, grant not finished,
or `oauth2Ticket` misuse), `oauth2-denied`, `oauth2-expired`,
`oauth2-reauth` (`invalid_grant` — re-authorize), `oauth2-endpoint`
(provider `{error,error_description}` payload), `oauth2-error` (HTTP/
listener/redirect faults). All messages are secret-free by construction.

#### `kiwi_open_external(url, sourceUrl?) → null` **[gated]** — implemented (T-243, T-273 gate)

Opens `url` in the **system browser** — the OAuth2 browser handoff
(`authorizeUrl`, `verificationUri`). Provider sign-in never runs inside
the webview (embedded-webview sign-in is blocked by Google and is a
phishing surface). Validation is fail-closed: unsourced opens require
`https://`; message-sourced opens accept HTTP(S) only after §6h classification.
Both are ≤2048 bytes with no whitespace or quote characters; the URL is passed as a
single argv element to the OS opener (`rundll32 url.dll,FileProtocolHandler`
/ `open` / `xdg-open`) — no shell is involved, so no argument or command
injection is possible. Errors: `invalid-input` (scheme/shape), `locked`,
`internal` (no browser/opener available). Returns nothing on success;
the UI always renders the raw URL as a copyable fallback.

`sourceUrl` is required by message-link callers and identifies the original
message link. The backend freshly classifies both `url` and `sourceUrl`; any
failed classification returns `sandbox-required` before spawning a host
browser, and any non-HTTP(S) source returns `link-denied`. `requireConfirm`
remains advisory. When `sourceUrl` is omitted, the existing trusted OAuth2 /
generic HTTPS behavior is preserved (`default allow` policy); callers must not
omit it for message links. There is no sandbox receipt bypass on this host-open
command: a failed message link is opened only through T-266's sandbox IPC.

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
| `not-locked` | unlock/submit attempted while the endpoint is not `Locked` — informational, safe to treat as already-unlocked |
| `authenticator-required` | `unlock_requires_authenticator` policy is set and no approved challenge was presented — obtain one via `kiwi_request_challenge` + `kiwi_submit_challenge` (§4) |
| `challenge-expired` / `already-consumed` / `binding-mismatch` / `unknown-challenge` | challenge lifecycle |
| `device-not-active` / `device-error` / `device-exists` / `device-revoked` / `unsupported-algorithm` | device path |
| `pairing-ticket-invalid` / `pairing-ticket-consumed` / `pairing-ticket-expired` | pairing-ticket path |
| `unsupported-event` | verified challenge for unwired flow |
| `replay-detected` | challenge nonce collision |
| `audit-corrupt` | audit-log chain break |
| `consent-required` | deliverability send without the unconsumed consent token (wrong/missing/consumed are indistinguishable); unsubscribe without the required consent flag (mailto always, non-one-click http) |
| `rate-limited` | provider 429; message carries the retry hint when present |
| `integration-error` | external-integration failure that isn't a covered class (HTTP status, malformed response, oversized body) |
| `sandbox-unavailable` / `sandbox-failed` | sandbox provider absent/unusable, or isolated execution failed |
| `sandbox-required` | host external-open refused a failed message link; use `kiwi_sandbox_open_link` |
| `link-denied` | host external-open refused a non-HTTP(S) message source |
| `oauth2-not-configured` | no usable `client_id` for the provider (pref/env unset) |
| `oauth2-incomplete` | grant ticket unknown/expired, grant not yet complete, or `oauth2Ticket` misuse at `kiwi_add_account` |
| `oauth2-denied` | user declined authorization |
| `oauth2-expired` | grant deadline passed before completion |
| `oauth2-reauth` | stored grant dead (`invalid_grant`) — interactive re-authorization required |
| `oauth2-endpoint` | provider returned an OAuth `{error,error_description}` payload |
| `oauth2-error` | other OAuth2 acquisition fault (HTTP status, listener, redirect, malformed payload) |
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
