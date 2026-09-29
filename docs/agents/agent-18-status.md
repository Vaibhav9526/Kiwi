# Agent 18 — Status Log

## 2026-09-25 — T-188: pair/challenge IPC + kiwi-admin device/export contracts

**Status:** initial documentation pass complete; Lead rulings are applied in
the second entry below. No source code changed by Agent 18.

### Delivered

- `docs/contracts/ipc.md` §9d now specifies the five requested logical
  commands: `pair_begin`, `pair_status`, `unlock_challenge`, `device_list`,
  and `device_revoke`, with camelCase request/response JSON, PairEngine call
  bindings, lock gates, bounds, PairError mapping, and known implementation
  gaps called out rather than hidden.
- The IPC pass records that `pair_status` needs both a read-only ticket API
  and atomic ticket-to-device persistence; it cannot safely be implemented by
  polling `consume_pairing_ticket` or caching the bearer ticket in kiwi-app.
- The IPC pass preserves existing `SecurityStatusView` revoke semantics,
  documents the current `nonceHex`/`nonceB64` wire mismatch, and flags the
  PairEngine atomic-consume race and unbounded ticket/device queries for
  Lead/engine follow-up.
- `docs/contracts/admin-api.md` §13 documents the exact NDJSON export line
  types/order, signed and unsigned trailers, trimmed HMAC-key semantics,
  full-chain/cap behavior, auth requirements, error envelopes, timestamp
  units, and the known denial-audit/concurrency gaps.
- `docs/contracts/admin-api.md` §14 specifies the proposed
  `GET /api/v1/orgs/{orgId}/devices` response, bounded `limit`, real-path
  org scoping, auth behavior, denial audit row, deterministic ordering,
  timestamp/revocation invariants, and the distinction between the admin,
  current in-memory app, and kiwi-pair device registries.

### Verification

- Source-parity review completed against `kiwi-pair/src/{lib.rs,engine.rs,
  store.rs,crypto.rs}`, kiwi-core challenge/device types,
  `kiwi-admin/src/audit/{export.ts,model.ts,chain.ts}`, current admin
  transport/RBAC/repository code, and the existing IPC/device tests.
- `git diff --check -- docs/contracts/ipc.md docs/contracts/admin-api.md
  docs/agents/agent-18-status.md` passed with no whitespace errors.
- `npm run typecheck` in `kiwi-admin` passed.
- `cargo check -p kiwi-pair` passed.
- `cargo test -p kiwi-pair` passed: 11 integration tests, 0 failures.
- `npm test -- --run` in `kiwi-admin` passed: 106 tests, 1 skipped, 0
  failures. The skipped migration leg is the existing environment-dependent
  PostgreSQL case; the shared worktree also contains concurrent T-193 source
  and test edits, which were not attributed to or reset by this task.

### Files changed by Agent 18

- `docs/contracts/ipc.md`
- `docs/contracts/admin-api.md`
- `docs/agents/agent-18-status.md`

The shared worktree also contains unrelated concurrent edits from other
agents, including T-193 changes to `admin-api.md` and admin source/tests;
those were preserved.

### Initial assumptions (superseded by the ratified entry below)

- Lead must ratify or reject the T-188 command names, `nonceB64` wire
  migration, pairing-ticket-in-response exception, lock exemptions, and
  first-device trusted pairing-channel path.
- Lead must decide whether global cross-org `audit.export` is intentional;
  current RBAC checks `audit.export` with a null target.
- The admin export denial-audit deviation from §1/§2 and the concurrent
  snapshot/audit-append gap remain explicit implementation decisions.
- The proposed device endpoint is intentionally marked not implemented until
  repository/service/route/tests land.

## 2026-09-25 — T-188 Lead rulings applied + T-229 OAuth2 contract review

**Status:** T-188 rulings applied in `ipc.md` and `admin-api.md`; T-229
OAuth2 drift review complete. Documentation only; no source code changed by
Agent 18.

### T-188 rulings recorded

- `pair_begin`, `pair_status`, `unlock_challenge`, `device_list`, and
  `device_revoke` are marked canonical/ratified; existing `kiwi_*` names are
  compatibility aliases only.
- `nonceB64` is documented as the canonical RFC 4648 standard-Base64 wire
  field decoding to exactly 32 bytes; the current `nonceHex` backend is an
  explicit migration gate.
- The ticket/QR response is explicitly limited to local renderer display and
  cannot cross admin/mobile trust boundaries or enter logs/preferences/
  evidence.
- `unlock_challenge` is always exempt; `pair_begin`/`pair_status` are exempt
  only while a backend-owned pairing flow is active and gated otherwise.
- The first-device TOFU path is marked approved, with authenticator
  verification—not TOFU evidence—as the only activation authority.
- `audit.export` is org-scoped: `org_admin` cannot use the legacy global NDJSON
  route; only the future `system-admin` role may take the global path. The
  future `/api/v1/orgs/{orgId}/audit/export` is ratified but not implemented.
  Duplicate normalized org device names are rejected with `409 conflict`, and
  listings never merge rows.
- Device inventory remains explicitly **ratified but not implemented** until
  repository, service, route, and tests land.

### T-229 OAuth2 review

`docs/contracts/oauth2.md` now distinguishes shipped matches from verified
source gaps: secret-bearing `Debug` envelopes, stored-blob validation,
public redirect construction, live-vs-injected transport guarantees, stateless
grant replay/cadence, soft loopback bounds, and the unwired T-230 app seam.
The test claim is corrected to 92 total / 32 OAuth tests and the gap register
is explicit. No code was changed to hide or claim away these gaps.

### Files changed by Agent 18 in this pass

- `docs/contracts/ipc.md`
- `docs/contracts/admin-api.md`
- `docs/contracts/oauth2.md`
- `docs/agents/agent-18-status.md`

Concurrent Agent 19/T-193 worktree edits were preserved and not reset.

### Verification for this pass

- Source-parity review compared the OAuth2 contract against all current
  `kiwi-autoconfig/src/oauth2/*.rs`, `kiwi-integrations/src/http.rs`,
  `kiwi-mail/src/account.rs`, and OAuth2 tests.
- `git diff --check` passed for all edited contract/status files.
- T-229 runtime verification passed: `cargo test -p kiwi-autoconfig` — 92
  tests, 0 failures (32 OAuth2 tests); `cargo clippy -p kiwi-autoconfig
  --all-targets -- -D warnings` — clean; `cargo fmt -p kiwi-autoconfig --
  --check` — clean. The shared worktree contains unrelated source changes
  but none were modified by Agent 18.

**Commands run:** read/glob/grep inspection; `git status --short`; targeted
`git diff`; `git diff --check`; `cargo test -p kiwi-autoconfig`; `cargo clippy
-p kiwi-autoconfig --all-targets -- -D warnings`; `cargo fmt -p
kiwi-autoconfig -- --check`. No commit made by Agent 18.

## 2026-09-26 — T-229 close-out: re-review after T-230 landed

**Status: CLAIMED by Agent 18.** Ledger row `docs/TASKS.md:189` still reads
`queued`, but the 2026-09-25 review was committed (`4353d35`) and T-230 has
since landed (`9ce5dfe`, "fully wired IPC+wizard seam"). Scope of this pass:
re-verify the T-195 contract claims against current source, and fix the
three places where `docs/contracts/oauth2.md` still says T-230 is deferred
(header, §5, gap-register item 7). Target files: `docs/contracts/oauth2.md`
(clean — verified via `git status`) + this status file. `docs/TASKS.md` and
`docs/contracts/ipc.md` are dirty/foreign; per prompt §5/ledger header I do
not edit the ledger directly (Lead merges), and ipc.md stays read-only.

## 2026-09-26 — T-229 close-out (re-review)

**Status: CLAIMED by Agent 18.** Owner Agent 18, status in-progress, target
files `docs/contracts/oauth2.md` + `docs/agents/agent-18-status.md`
(read-only review of `kiwi-autoconfig/src/oauth2/`, T-230 IPC seam, and test
counts). Claimed before any edit, per the fleet rule.

**Why a second pass:** the 2026-09-25 review is recorded in this file and in
`oauth2.md`, but `docs/TASKS.md:189` still shows T-229 as `queued`, and the
contract header + gap-register item 7 still describe the T-230 app seam as
unwired — while T-230 is now `done` (Agent 19, IPC + wizard seam landed).
This pass re-verifies gaps 1–6 against current source, resolves or re-words
the stale T-230 language with evidence, re-runs the test-count evidence, and
hands the Lead a close-out verdict for the ledger row.

### Close-out results

**Status: COMPLETE — contract updated, no source changed.** Files changed by
Agent 18 in this pass: `docs/contracts/oauth2.md`, `docs/agents/agent-18-status.md`.

**Gap 7 is CONFIRMED OPEN against the landed T-230 code — and it is worse
than "unwired".** T-230 wired storage and ceremony but not the connect path.
Verified evidence chain (all read-only):

- `save_tokens` stores `to_blob()` JSON (`{"v":1,"access_token",
  "refresh_token"?…}`) at `oauth2/<provider>/<email>`
  (`kiwi-autoconfig/src/oauth2/mod.rs:449-458`); `auth_ref()` points
  `AuthRef::XOAuth2` at that same key for both directions (`mod.rs:440-444`).
- `resolve_secret` (`kiwi-app/src-tauri/src/commands/mod.rs:169-187`)
  returns the credential-store value **verbatim** for every `AuthRef` kind —
  no `from_blob`, no `ensure_fresh`.
- Live IMAP sync (`commands/mail.rs:835-843` via `connect_imap`), the
  verify/test probe (`commands/accounts.rs:552-554,606-607`), and live SMTP
  send (`commands/send/dispatch.rs:297`) all pass that raw value straight
  into `XOAuth2 { token: secret }`.
- `ensure_fresh`/`load_tokens` have zero callers on any connect path
  (`load_tokens` is used only by the `kiwi_oauth2_status` display view).

Net effect: every OAuth2 account sends the full JSON blob — **including the
refresh token** — as the XOAUTH2 bearer on every connection. Real providers
reject it (OAuth2 mail auth is broken end-to-end), and the refresh token is
needlessly exposed to the mail server. The fix (decode via `from_blob`,
refresh via `ensure_fresh`, pass only `access_token()`) is a code task for
the mail-command owners (A15/A19 scope), explicitly NOT done here — this
review touches no source outside the two contract/status files.

**Gaps 1–6 re-verified still open in current source:** secret-bearing
`Debug` derives present (`pkce.rs:28`, `transport.rs:26`, `mod.rs:217`;
only `TokenSet` has a redacted impl); `from_blob` still ignores
`token_type`, has no input-size cap, no expiry range check
(`token.rs:183-195`). Post-review crate changes are purely additive and
create no new drift: `provider_id_for_suggestion` + `grant_kind_str`
(T-251, `9a11c47`) — now documented in contract §3.

**Stale counts corrected (§10):** `cargo test -p kiwi-autoconfig` → **97
passed, 0 failed** (was 92/32 at the 09-25 review; now 97 total, **33**
OAuth2 — T-251 added the delta).

**Contract edits made** (`docs/contracts/oauth2.md`, clean per `git
status` before editing): header (T-230 landed, close-out date, gap-7
pointer); T-229 disposition paragraph; §3 discovery helpers; §5 T-230
bullet rewritten from "deferred" to the confirmed defect with file:line
evidence; gap-register item 7 rewritten as CONFIRMED OPEN; §10 counts.
No "deferred to T-230" / "not yet wired" language remains.

### Verification for this pass

- `cargo test -p kiwi-autoconfig` — 97 passed, 0 failed (33 OAuth2).
- `cargo clippy -p kiwi-autoconfig --all-targets -- -D warnings` — clean.
- `cargo fmt -p kiwi-autoconfig -- --check` — clean.
- `git diff --check` on both edited files — clean.
- `npm run typecheck` in `kiwi-app` (`tsc --noEmit`) — clean, exit 0
  (docs-only change; run per the fleet gate rule).
- `docs/TASKS.md:189` still reads `queued` — **not edited by me** (ledger
  header forbids direct agent edits; Lead merges). Recommended ledger
  update: T-229 → `done`, with a follow-up fix task for the gap-7
  connect-time decode owned by the mail-command lane.

**Follow-up needed (for Lead dispatch, not Agent 18):** connect-time OAuth2
decode+refresh at `resolve_secret` or its call sites, owned by whoever owns
`commands/mail.rs` + `commands/send/` + `commands/mod.rs`; needs a live
XOAUTH2 assertion (blob-as-bearer must fail, access-token must pass) —
T-257/T-262 e2e did not cover an OAuth2 login path.