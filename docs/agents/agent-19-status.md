# Agent 19 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-195 OAuth2 grant acquisition (claimed → done, pending Lead review)

Status: **done** — code + contract + tests landed; `cargo test -p
kiwi-autoconfig` **92/92 green, fully offline** (39 new oauth2 tests on
recorded `ScriptedHttp` fixtures + real 127.0.0.1 loopback sockets; no
live calls). `cargo clippy -p kiwi-autoconfig --all-targets -- -D
warnings`: clean. `cargo fmt -p kiwi-autoconfig`: clean. `unsafe_code`
forbidden via workspace lints.

Scope delivered (task spec):

1. `docs/contracts/oauth2.md` — `kiwi.oauth2/1`: Google auth-code +
   loopback + PKCE and Microsoft device-code flows; endpoint matrix;
   token lifecycle (access/refresh/expiry, 60 s skew, rotation rule);
   CredentialStore seam (never DB / plaintext / logged); transport +
   listener hardening; error taxonomy; client-id deployment note.
2. `trait OAuthFlow { begin, begin_with, exchange, poll, refresh,
   provider_id, grant_kind }` + `OAuthClient` impl dispatching on
   `GrantKind`; `ProviderConfig` presets `google()` / `microsoft()` /
   `microsoft_tenant()` + `by_id` registry; `PendingGrant` (non-Clone,
   redacted Debug) carrying bound `LoopbackListener` or device grant.
3. Tests: `oauth2/tests.rs` — no network beyond 127.0.0.1 sockets.

Files changed:

- `kiwi-autoconfig/src/oauth2/mod.rs` — new. `OAuthError`, `GrantKind`,
  `PendingGrant`/`LoopbackGrant`/`DeviceGrant`, `RedirectOutcome`,
  `PollOutcome`, `OAuthFlow` trait, `credential_key`/`auth_ref`/
  `save_tokens`/`load_tokens`/`delete_tokens`/`ensure_fresh` glue,
  `CONTRACT_VERSION`, `EXPIRY_SKEW_SECS`, `MAX_TOKEN_FIELD`.
- `kiwi-autoconfig/src/oauth2/transport.rs` — new. `OAuthTransport`
  (single `post_form` verb) blanket-implemented for every
  `kiwi_integrations::http::HttpClient`; `live_transport()`
  (`ReqwestClient`, 64 KiB cap); strict `form_encode`/`form_decode`.
- `kiwi-autoconfig/src/oauth2/pkce.rs` — new. `GrantSecrets`
  (`generate` via getrandom; `fixed` for deterministic tests), S256
  challenge only.
- `kiwi-autoconfig/src/oauth2/token.rs` — new. `TokenSet` (Zeroizing
  fields, redacted Debug, `needs_refresh`, versioned JSON blob for the
  credential store, wire validation).
- `kiwi-autoconfig/src/oauth2/provider.rs` — new. `ProviderConfig` +
  Google/Microsoft presets, `KNOWN_PROVIDERS`, tenant validation.
- `kiwi-autoconfig/src/oauth2/loopback.rs` — new. `LoopbackListener`:
  127.0.0.1-only ephemeral bind, nonblocking accept + deadline,
  8 KiB / 5 s per-conn bounds, fixed no-secret response pages, noise
  requests ignored.
- `kiwi-autoconfig/src/oauth2/flow.rs` — new. `OAuthClient`:
  begin/exchange/poll/refresh incl. state-first CSRF check, provider
  error-code mapping (`authorization_pending`, `slow_down`,
  `authorization_declined`, `expired_token`, `invalid_grant`, …).
- `kiwi-autoconfig/src/oauth2/tests.rs` — new. The fixture suite.
- `kiwi-autoconfig/src/lib.rs` — `pub mod oauth2` + crate-doc note that
  oauth2 is the (seam-disciplined) exception to "never opens
  connections".
- `kiwi-autoconfig/Cargo.toml` — + `kiwi-integrations` (path),
  `async-trait`, `zeroize`, `base64`, `sha2`, `getrandom`; dev-dep
  `tokio`.
- `kiwi-integrations/src/lib.rs` — ONE LINE added by me:
  `pub use error::{IntegrationError, TransportKind}` (was
  `IntegrationError` only). Needed to name `TransportKind` in
  `OAuthError::Transport{kind}`. Flagging for Agent 11 / Lead — additive,
  backward-compatible.
- `docs/contracts/oauth2.md` — new contract.
- `docs/agents/agent-19-status.md` — this file.

Commands run:

- `cargo check -p kiwi-autoconfig` — clean
- `cargo test -p kiwi-autoconfig` — 92 passed / 0 failed
- `cargo clippy -p kiwi-autoconfig --all-targets -- -D warnings` — clean
- `cargo fmt -p kiwi-autoconfig` — applied; `--check` clean

Assumptions / decisions (for Lead ratification):

- Module lives in `kiwi-autoconfig` (task allowed autoconfig or
  kiwi-mail): it is the account-setup crate, ISPDB already flags
  Google/Microsoft as `AuthKind::XOAuth2`, and it keeps `kiwi-mail`
  free of an HTTP stack. The crate's "never opens connections" invariant
  now applies to the discovery pipeline; the oauth2 module is its
  documented exception (lib.rs + contract §1).
- Reused `kiwi-integrations::http` seam rather than duplicating a
  reqwest+rustls adapter (prompt.md §15 no-duplication); new crate edge
  `kiwi-autoconfig → kiwi-integrations` recorded above.
- `begin_with(http, Option<&GrantSecrets>, now)` is the deterministic
  test seam (`begin` = fresh entropy); `now_unix` injected everywhere —
  no wall-clock reads.
- One trait (`OAuthFlow`) carries `exchange` and `poll`; the
  not-applicable verb returns `Err(UnsupportedGrant)` — keeps a single
  object-safe contract per the task spec.
- No client_id shipped — provider registrations are deployment config;
  `begin` fails closed on a bad one (`InvalidConfig("client_id")`).
- Refresh-token rotation handled: response token replaces; absent →
  keep old (Google semantics). `ensure_fresh` persists the rotated blob.
- MS tenant default `common`; validated `[A-Za-z0-9.-]` ≤128.
- `poll` never sleeps — cadence is the caller's loop (`SlowDown` returns
  `interval + 5` per RFC 8628 §3.5). `wait_for_redirect` is blocking —
  app must spawn_blocking (documented in contract §3.1).

Risks / notes for integrators:

- `OAuthClient::begin` for Google binds a real loopback socket — the
  wizard must call it only when the user is ready to be sent to the
  browser; the grant owns the listener until dropped.
- Token `expires_in` > 1 y is clamped (suspicious input); absent →
  non-expiring `TokenSet` (refresh driven by auth failures).
- POP3 XOAUTH2 wiring and token revocation endpoints are out of scope
  (contract §11).
- Not wired into src-tauri IPC yet — that is a follow-up task for the
  app layer (command + wizard surface); the crate API + store glue is
  complete and contract-pinned.

## 2026-09-25 — Blocker report resolved (kiwi-autoconfig red at HEAD)

Lead reported `cargo check -p kiwi-autoconfig` failing with 3× E0425.
Root cause: checkpoint `859a347` had swept a **pre-fix** snapshot of the
oauth2 sources and never captured `oauth2/tests.rs` (untracked), so HEAD
was red even though the working tree was green. No errors were in my
current edit state — `cargo check --all-targets`, `cargo test` (92/92),
clippy and fmt were all clean on the tree.

Action taken: committed the verified final state as **`de1970c`**
("T-195 oauth2: land verified module state + recorded-fixture tests",
7 files, +864/−29) — HEAD is now green for kiwi-autoconfig.

Workspace remains red from other agents' in-flight edits (reported
file:line to Lead, not edited — not my files):

- `kiwi-mailauth/src/spf.rs:1351` — stray `}` after `mod tests` closes
  at 1350 (unexpected closing delimiter).
- `kiwi-mail/src/unsub.rs:252` — test code missing delimiters ~L246–249
  (`parse_unsubscribe(&h(&[…` unclosed). Breaks `cargo check -p
  kiwi-autoconfig` transitively (kiwi-autoconfig deps kiwi-mail).

`orca terminal send` report to `term_c20c6737-…`: `accepted: true`
(input_accepted; provider reports no delivery observation — same as the
original DONE report).

## 2026-09-25 — T-230 OAuth2 IPC + account-wizard seam (claimed → done, pending Lead review)

Status: **done** — `cargo test -p kiwi-app` **86/86 green**, all offline
(`ScriptedHttp` replays; the loopback test uses a real 127.0.0.1 socket
only). `cargo check --all-targets`, `cargo clippy --all-targets -D
warnings`, `cargo fmt --check`: all clean. `kiwi-autoconfig` still 92/92.

Scope delivered (task spec):

1. `kiwi_oauth2_begin(provider, email?)` → `{kind, userCode?,
   verificationUri?, verificationUriComplete?, authorizeUrl?,
   expiresAtUnix?, pollIntervalSecs?, ticketId}` — device-code returns
   the code+URI to display; loopback returns `authorizeUrl` to open
   externally with the `127.0.0.1` listener already bound and a waiter
   thread parked (600 s deadline, own current-thread runtime).
2. `kiwi_oauth2_poll(ticketId)` → `pending | complete | error`:
   terminal failures (denied/expired/endpoint/malformed) arrive as
   `status:"error"` + sticky `Failed` state; transient transport errors
   stay IPC errors so the grant survives. Single-flight per ticket via
   the sessions mutex. `slow_down` bumps `retryAfterSecs` per RFC 8628.
3. `kiwi_oauth2_status(accountId)` → read-only posture of a stored
   account: authMethod, provider/email parsed from `oauth2/…` grant keys,
   credentialPresent, expiry + needsRefresh + hasRefreshToken from the
   persisted TokenSet blob — never token material.
4. `kiwi_oauth2_cancel(ticketId)` — drops the session (bounded listener
   lifetime documented).
5. `kiwi_discover_account(email)` — landed the T-178 contract shape
   (`commands/autoconfig.rs`); `suggestion.oauth2` spec (`{provider,
   grant}`) present iff the suggestion is XOAUTH2 **and** the incoming
   IMAP host is one a shipped config services — fail-closed for Yahoo/
   AOL-style OAuth2 providers and POP3.
6. `kiwi_add_account` binding: `AuthInput.oauth2Ticket` (xoauth2 only;
   same ticket both directions; grant email must match account email)
   → both `AuthRef::XOAuth2`s carry `oauth2/<provider>/<email>`;
   deferred grants (no email at begin) persist on consume; ticket
   consumed only after the account row exists. Legacy inline-secret
   xoauth2 preserved.

Files changed:

- `kiwi-app/src-tauri/src/commands/oauth2.rs` — new. begin/poll/cancel/
  status commands + `oauth2_ticket_key`/`consume_oauth2_ticket`/
  `oauth2_spec_for` seam fns + `SharedTransport` (Arc<dyn HttpClient> →
  OAuthTransport bridge) + 11 tests.
- `kiwi-app/src-tauri/src/commands/autoconfig.rs` — new.
  `kiwi_discover_account` + wire mapping (auth `xoauth2`, security
  `tls|starttls|plaintext`) + 6 tests.
- `kiwi-app/src-tauri/src/commands/accounts.rs` — oauth2Ticket binding
  in `add_account_impl`, `auth_ref`/`store_secret` ticket path,
  `auth_input_from` field update.
- `kiwi-app/src-tauri/src/commands/mod.rs` — + `autoconfig`, `oauth2`.
- `kiwi-app/src-tauri/src/discovery_net.rs` — new. `LiveDiscoveryNet`:
  HTTPS fetch via shared integrations transport (body-capped); MX via
  hickory `TokioResolver` (system config), private runtime per call.
- `kiwi-app/src-tauri/src/state.rs` — `OAuth2Session`/
  `OAuth2SessionState` (Device/Loopback/Completed/CompletedDeferred/
  Failed), `oauth2_sessions` map bounded at `MAX_OAUTH2_SESSIONS=32`
  (evict expired/failed → oldest), `OAUTH2_LOOPBACK_TIMEOUT_SECS=600`,
  `autoconfig_net` field, `open_test_with_net` injector.
- `kiwi-app/src-tauri/src/types/oauth2.rs` — new wire views
  (`OAuth2BeginView`/`PollView`/`StatusView`/`CancelView`/`SpecView`).
- `kiwi-app/src-tauri/src/types/accounts.rs` — `AuthInput.oauth2Ticket`;
  discovery views (`DiscoveryOutcomeView`, `SuggestionView`, …).
- `kiwi-app/src-tauri/src/types/mod.rs`, `lib.rs` — module + handler
  registration.
- `kiwi-app/src-tauri/Cargo.toml` — + `kiwi-autoconfig` (path),
  `hickory-resolver` 0.26 (tokio), `async-trait`.
- `kiwi-autoconfig/src/oauth2/provider.rs` — `provider_id_for_suggestion`
  (XOAUTH2+IMAP+host→provider, fail-closed), `grant_kind_str`.
- `kiwi-autoconfig/src/net.rs` — `DiscoveryNet: Send + Sync` supertrait
  (needed for `Arc<dyn DiscoveryNet>` inside `AppState`).
- `docs/contracts/ipc.md` — §5 `oauth2Ticket` field + discover `oauth2`
  spec (marked implemented); new §9f command family; §11 error rows
  (`oauth2-not-configured|-incomplete|-denied|-expired|-reauth|
  -endpoint|-error`).

Security properties: no token/PKCE-verifier/device-code/auth-code bytes
cross IPC — `credentialKey`/`ticketId` are names/opaque ids; tokens reach
the OS keystore only; audit sees provider+email+outcome; grant map is
bounded in-memory and dies with the process; client_id resolves env
`KIWI_OAUTH2_<PROVIDER>_CLIENT_ID` > pref `oauth2.<provider>.clientId`,
missing → `oauth2-not-configured` before any network call.

Assumptions / decisions (for Lead ratification):

- Completed-grant tickets are consumable exactly once (post-upsert) — a
  second `add_account` with the same ticket gets `oauth2-incomplete`.
- Poll is the only refresh of grant state — no push; loopback waits are
  driven by `pollIntervalSecs` hint (1 s fixed; device = provider's).
- `kiwi_discover_account` runs on `spawn_blocking` — `LiveDiscoveryNet`
  drives a private runtime per call (block_on inside a worker panics).
- POP3+XOAUTH2 stays unsupported: the spec is never emitted for POP3
  suggestions and `auth_ref` unchanged.
- Token refresh at connect time stays inside `ensure_fresh` (T-195);
  IPC `status` is read-only posture, not a refresh trigger.

Blockers hit: transient foreign reds during the session —
`kiwi-mail/src/store/mod.rs:1083` (`PLACEHOLDER_STORE_TESTS` mid-edit,
self-resolved) and `kiwi-app/.../types/mail.rs:90` (T-232 `auth` field
mid-wire, self-resolved). Nothing foreign was edited.
