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
