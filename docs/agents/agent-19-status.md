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

## 2026-09-25 (later) — Drift-audit follow-up (contract-drift-1.md)

Audit items assigned to T-195/T-230 scope:

- **ACFG-1 (H, fixed)**: `docs/contracts/autoconfig.md` still asserted the
  pre-oauth2 invariant "no secrets and never opens connections". Amended
  preamble + §1: discovery pipeline keeps the invariant; `oauth2` is the
  documented exception — **no secrets in DB / plaintext / logs; the OS
  credential store is the sanctioned sink** (`kiwi.oauth2/1`). Crate doc
  in `kiwi-autoconfig/src/lib.rs` reworded to the same formulation.
- **UIS-6 (H, resolved in tree)**: audit snapshot saw `ipc.ts` invoking
  `kiwi_lookup_autoconfig`; current tree invokes `kiwi_discover_account`
  (post-024e87d reconcile), which T-230 registered. Per Lead instruction
  the stale-name path is also covered: **`kiwi_lookup_autoconfig` is now
  registered as a documented alias** of `kiwi_discover_account`
  (`commands/autoconfig.rs`, same signature/response; ipc.md §5 alias
  note). Both spellings work; new code should use the contract name.
- **ACFG-2 (M, already resolved)**: `oauth2::CONTRACT_VERSION` cites
  `docs/contracts/oauth2.md` — absent at audit snapshot, exists since
  T-195. No action needed.
- **IPC-10 (M, fixed — adjacent in my seam)**: `xoauth2` was accepted for
  POP3 at add time, rejected only at connect (unusable account persisted).
  `auth_ref` now rejects `xoauth2` when incoming protocol is POP3
  (`invalid-input`), per ipc.md §5. Regression test
  `xoauth2_rejected_for_pop3_at_add_time` added. **Supersedes the T-230
  assumption "`auth_ref` unchanged"** logged above.

Remaining ACFG-3..10 findings (local-part charset, GoDaddy fixture,
MX_HINTS/pphosted, TooLong-vs-MalformedXml, PI skipping, emailProvider
root, domain fallback, %EMAILDOMAIN%) are pre-existing autoconfig-parser
drift owned by the contract owner (Agent 8) — flagged in the Lead report,
not touched here.

Verification: `cargo test -p kiwi-app` **87/87 green** (incl. new
`xoauth2_rejected_for_pop3_at_add_time`); `cargo test -p kiwi-autoconfig`
92/92 green; `cargo fmt --check` clean; `cargo clippy -p kiwi-app -p
kiwi-autoconfig --all-targets -- -D warnings` clean **with
`-A clippy::trim_split_whitespace`** — full-workspace clippy is red on
foreign lint `kiwi-mail/src/authstamp.rs:205` (`.trim()` before
`.split_whitespace()`, T-232-era file mid-edit by its owner; reported to
Lead, not edited). Same session also saw foreign `authstamp.rs` E0425s
(`out` unbound mid-write) — self-resolved.

## 2026-09-25 (later) — T-243 wizard OAuth2 branch + re-auth badge (done)

Scope delivered:

- `kiwi-app/src/components/oauth2.tsx` — new shared `OAuth2SignIn` card:
  begin → device-code (`userCode` large + `verificationUri` link/copy) or
  loopback ("Open sign-in page" + waiting) → poll loop honoring
  `pollIntervalSecs`/`retryAfterSecs` (clamped 1–60 s) → `complete` calls
  `onDone(ticketId)`; §9f codes → human copy (`oauth2-expired` → "Start
  over"); transient IPC errors keep polling, `BackendUnavailableError`/
  `locked`/`not-found` end the flow; unmount cancels in-flight grants but
  never a completed ticket (consumed by `kiwi_add_account`).
- `kiwi-app/src/views/setup.tsx` — suggestion `oauth2` spec → Credentials
  step renders the provider sign-in ("Sign in with Google/Microsoft")
  instead of a token box; `oauth2Ticket` flows into both
  `incomingAuth`/`outgoingAuth` of `kiwi_add_account`; pasted-token
  fallback preserved (and fixed — xoauth2 now sends `{kind, secret}`
  instead of a null auth that would have persisted `AuthRef::None`);
  verify step skipped for ticket path (grant itself authorizes).
- `kiwi-app/src/views/settings.tsx` — per-account `kiwi_oauth2_status`
  on Accounts cards: `OAuth2 · <Provider> — re-auth needed` pill when
  `credentialPresent==false || needsRefresh==true`; inline OAuth2SignIn
  re-auth (completing the grant rewrites the same credential-store key —
  no re-add), status re-polled on completion.
- `kiwi-app/src/kiwi.ts` — `OAuth2Begin/Poll/Status/CancelView` + tolerant
  parsers; `AutoconfigSuggestion.oauth2`; `parseAutoconfigSuggestion` now
  unwraps the real `DiscoveryOutcomeView.suggestion` envelope (the
  previous parser read top-level fields and would have always returned
  null against the live command).
- `kiwi-app/src/ipc.ts` — `oauth2Begin/Poll/Cancel/Status` +
  `openExternal` wrappers; stale "backend pending" comment corrected.
- Backend `kiwi_open_external(url)` — gated, `https://`-only, bounded,
  no quotes/whitespace; direct exec to `rundll32 url.dll,FileProtocolHandler`
  / `open` / `xdg-open` (no shell, no injection surface); ipc.md §9f entry.
  Chosen over tauri-plugin-opener to keep the npm surface unchanged.
- ipc.md: `kiwi_open_external` documented (§9f tail).

Verification: `npm run build` (tsc + vite) green; `cargo test -p
kiwi-app` **91/91** (incl. new `open_external_rejects_unsafe_urls` — 9
rejection shapes); `cargo clippy -p kiwi-app --all-targets -- -D
warnings` clean; `cargo fmt` clean on my files.

Foreign reds during session (all self-resolved, none edited):
`kiwi-mail` `apply_on_ingest` signature churn (sync.rs E0061 ×3 →
queries.rs `auth_risk` E0063 ×2 → resolved), `authstamp.rs:205` clippy
lint (resolved), `commands/mail.rs` collapsible_if (resolved).

## T-251 — ACFG-7/8/9 parser hardening (2025 …)

Scope: `kiwi-autoconfig` autoconfig-XML parser, per
`docs/audits/autoconfig-drift-1.md` rulings. Files changed:
`kiwi-autoconfig/src/autoconfig_xml.rs`, `docs/contracts/autoconfig.md`.

- **ACFG-7 (processing instructions):** `Parser::skip_misc` split —
  `skip_misc(prolog)` permits one `<?xml …?>` declaration in the prolog
  only (target exactly `xml` + whitespace; `<?xml-stylesheet?>` and
  `<?xmlfoo?>` are NOT the declaration). Every other PI in prolog,
  epilog, or comment-skip context is `MalformedXml("processing
  instruction prohibited")`; unterminated PI keeps its own error.
  PIs inside elements were already fatal via `parse_name`.
- **ACFG-8 (root):** `ClientConfig::parse` no longer accepts a bare
  `<emailProvider>` root — `clientConfig` only, per contract.
- **ACFG-9 (provider selection):** unconditional first-provider
  fallback removed. Order is now exact `<domain>` match, then the
  documented compat exception (provider `id` == queried domain), else
  `MalformedXml("no emailProvider for queried domain")` so discovery
  falls through instead of suggesting a foreign provider's config.

Contract: `autoconfig.md` §5 amended for the two *intentional* compat
exceptions only (XML-declaration-in-prolog; provider-id second source)
and now states explicitly that there is no first-provider fallback.
No other contract wording touched.

Tests (+5, all offline, in-file fixtures):
`processing_instructions_rejected_except_xml_decl` (6 rejection shapes
incl. `xml-stylesheet`/`xmlfoo`/second decl/prolog+epilog PIs, plus
decl+comment acceptance and unterminated-PI),
`bare_emailprovider_root_rejected`, `no_first_provider_fallback`,
`provider_id_match_is_second_source`, `exact_domain_beats_provider_id`.

Verification: `cargo test -p kiwi-autoconfig` **97/97** green;
`cargo clippy -p kiwi-autoconfig --all-targets` clean;
`cargo fmt -p kiwi-autoconfig --check` clean. Pre-existing uncommitted
T-230 diffs in `net.rs`/`oauth2/{mod,provider}.rs` observed, not
touched.

## T-257 — account-add → first-sync E2E (offline, scripted fixtures)

New: `kiwi-app/src-tauri/src/e2e.rs` (4 tests). Seam fix:
`kiwi-mail/src/testutil/server.rs` — `Wire`/`serve`/`spawn_script`
generalized `DuplexStream` → `S: AsyncRead + AsyncWrite + Unpin`, so the
transcript harness drives a real loopback `TcpStream` (the actual
`Transport::connect` path is exercised — genuine TCP + TLS handshake,
not a mock). `TlsAcceptor` re-exported from `testutil`; `e2e-fixtures`
feature on kiwi-mail (rcgen → optional dep, kept in dev-deps for
in-crate tests) enabled via kiwi-app dev-dep. Widenings:
`list_folders_impl`, `list_accounts_impl` → `pub(crate)`;
`integrations_transport` → `pub(crate)` (test arg seam).

Coverage — `e2e.rs`:
- `e2e_discover_add_sync_list_green_path`: MockNet serves an autoconfig
  doc pointing at `127.0.0.1:<listener>` → `discover_account_impl`
  (autoconfig_host hit, suggestion fields asserted) → `add_account_impl`
  (wizard-shaped input, `accept_invalid_certs` for the self-signed
  acceptor) → `list_accounts_impl` (persisted) → `sync_account_impl`
  over STARTTLS-scripted transcript (CAPABILITY→STARTTLS→TLS
  boundary→LOGIN→LIST→SELECT→UID SEARCH→UID FETCH envelopes→header
  fetch→LOGOUT) → `list_folders_impl` + `list_messages_impl` (2
  envelopes, newest-first, \Seen honored, message-id parsed). Server
  task joined — a wire divergence would fail the test.
- `e2e_unreachable_host_surfaces_connect_error`: bound-then-dropped
  port → sync returns `connect-failed`, no crash/hang.
- `e2e_auth_rejection_surfaces_server_reject`: scripted `NO
  [AUTHENTICATIONFAILED]` on LOGIN → `server-reject` with the server
  reply surfaced.
- `e2e_undiscoverable_domain_flagged_not_crash`: empty MockNet →
  `mx_heuristic` + `needs_manual_review` (failure as data).

PASS/FAIL matrix:

| stage                 | green | bad host            | auth fail             | undiscoverable        |
|-----------------------|-------|---------------------|-----------------------|-----------------------|
| discover              | PASS  | n/a (doc reachable) | n/a                   | PASS (flagged guess)  |
| add_account           | PASS  | PASS (row persists) | PASS                  | n/a                   |
| sync_folder           | PASS  | PASS (`connect-failed`) | PASS (`server-reject`) | n/a                |
| list_folders/messages | PASS  | n/a                 | n/a                   | n/a                   |

Integration gap found+fixed: testutil's `serve`/`spawn_script` were
DuplexStream-only — unusable for a real-socket E2E. Fixed in-place
(generic stream); no production-code changes needed — the real path
was already coherent.

Verification: `cargo test -p kiwi-app` **98/98**; `-p kiwi-autoconfig`
97/97; `-p kiwi-mail` 197+2 foreign failures (`linkrisk.rs:376` —
untracked in-flight file, owner mid-edit, reported not touched);
`testutil` suite 15/15 green; `clippy -p kiwi-app kiwi-mail
kiwi-autoconfig --all-targets -D warnings` clean; rustfmt clean on my
files.
