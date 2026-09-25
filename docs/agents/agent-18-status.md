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