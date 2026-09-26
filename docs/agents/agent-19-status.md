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

## T-262 — send-path E2E (mirror of T-257) — DONE

Compose → `kiwi_send_enqueue` → outbox due → scripted loopback SMTP
(real TCP + STARTTLS via testutil seam) → outbox drain + Sent copy +
audit. Four new tests in `src-tauri/src/e2e.rs`.

- `e2e_send_delivers_files_sent_copy`: `send_impl` enqueues a
  compose-shaped input (queue+`outbox` row+meta all asserted);
  `due()` drains; `deliver` runs a scripted loopback SMTP session —
  greeting/EHLO/STARTTLS boundary/post-TLS EHLO/AUTH PLAIN/MAIL FROM
  (SIZE tolerated)/RCPT/DATA/354 + the verbatim MIME bytes line-by-line
  + `.` + 250 + QUIT. `Delivered::Sent` → `drop_outbox` drains
  queue+meta+persisted row; audit shows `send-queued` + `send-sent`;
  the Sent copy then *round-trips*: a scripted APPEND session files the
  MIME into `Sent`, and a follow-up `sync_account_impl` lists it back
  (subject/from/`\Seen`→read asserted). Both server tasks joined.
- `e2e_send_smtp_reject_retains_outbox`: `554` after DATA →
  `server-reject` → `Held` — re-enqueued with linear backoff
  (`attempts=1`, `not_before` in future), persisted row kept, and the
  failure is tamper-evident via the new `send-attempt-failed` audit
  row (`server-reject` recorded).
- `e2e_send_cancel_inside_undo_window_never_transmits`: `cancel_impl`
  inside the 30 s grace window → queue/meta/persisted row all gone,
  `send-cancelled` audited, and no `send-attempt-failed`/`send-sent`
  rows (ports are dead — any dispatch would have audited a
  `connect-failed`).
- `e2e_send_starttls_refusal_fails_closed`: EHLO without STARTTLS →
  `Held` (fail closed — retained for retry, not dropped), failure
  audited; a new `# EOF` transcript step proves **zero client bytes**
  past the refused EHLO — no plaintext AUTH leak possible.

PASS/FAIL matrix:

| stage                    | green | 5xx DATA           | undo-cancel         | STARTTLS refusal     |
|--------------------------|-------|--------------------|---------------------|----------------------|
| send_impl enqueue        | PASS  | PASS               | PASS                | PASS                 |
| outbox persisted + due   | PASS  | PASS               | PASS                | PASS                 |
| TCP+TLS+STARTTLS session | PASS  | PASS               | n/a (never dials)   | PASS (EHLO only)     |
| MAIL/RCPT/DATA + body    | PASS  | PASS (all seen)    | n/a                 | PASS (`# EOF` clean) |
| drain + Sent copy        | PASS  | n/a (held)         | n/a                 | n/a                  |
| retention/retry          | n/a   | PASS (Held+backoff)| n/a                 | PASS (Held)          |
| audit rows               | PASS  | PASS               | PASS                | PASS                 |

Integration gaps found + fixed in-place (my seam crates/commands):

1. `dispatch.rs` — **no Sent copy existed at all**. Added
   `file_sent_copy`: after SMTP accept + `send-sent` audit, a dedicated
   IMAP session `LIST "" "*"` → `\Sent`-flagged mailbox (fallback
   `Sent`, RFC 6154) → `APPEND (\Seen)`. Best-effort: copy failure
   audits `send-sent-copy-failed`, never retries (recipient already
   accepted) — avoids duplicate delivery.
2. `dispatch.rs` — failed attempts were stderr-only. Added
   `send-attempt-failed` audit (code + sanitized message) so the 5xx/
   refusal paths are tamper-evident.
3. `kiwi-mail/src/imap/commands.rs` — **real bug**: LIST parse
   uppercased the whole untagged line before extracting fields, so
   `MailboxInfo.name` arrived as `SENT` not `Sent` — APPEND would have
   filed into a duplicate uppercase mailbox on a real server. Now
   matches the verb case-insensitively but parses the tail verbatim
   (mailbox names are case-sensitive; only INBOX is case-invariant).
4. `testutil` — new `# EOF`/`Step::ExpectEof` step (silence-or-timeout
   = pass, any bytes = fail) enabling fail-closed wire proofs; session
   accept/serve wrapped in a 30 s cap so a parked transcript fails
   fast instead of wedging the test binary (hit twice while
   debugging).

Also fixed a script-gen bug my own harness had: `smtp_data_steps`
emitted a phantom empty `C:` line before `.` (a mime not ending in
CRLF gets `\r\n.\r\n`, not a blank line). Deadlock bisected via
per-step server tracing, since removed.

Verification: `cargo test -p kiwi-app` **125/125** (incl. all 8 e2e);
`-p kiwi-mail` **205/205** (testutil 16/16); `-p kiwi-autoconfig`
97/97; clippy clean on kiwi-app/kiwi-mail (one foreign warning in
kiwi-mailauth, not mine); rustfmt clean on touched files. Transient
foreign reds observed mid-session (mailauth dns.rs lifetime, pair.rs
test-module fallout) — self-resolved on owner's next edits; reported
not touched.

## T-285 — POP3 E2E (DONE)

Third protocol leg closed, mirroring the T-257 (IMAP) / T-262 (SMTP)
harness shape: scripted loopback POP3 via `kiwi_mail::testutil`
(`Proto::Pop3` + `spawn_sessions`), real TCP + implicit-TLS boundary,
5 tests appended to `kiwi-app/src-tauri/src/e2e.rs`.

- `e2e_pop3_sync_ingests_keeps_and_dedups` — add → sync → report
  (downloaded 2, remote_exists 2, deleted_remote 0) → envelopes
  (subject/from/message_id/unread) + body landing incl. dot-UNSTUFF
  proof via `load_body_raw` → second sync over a second scripted
  session: same UIDLs, `pop3_seen` dedups → downloaded 0, zero RETR
  on the wire. Keep-on-server = the IPC pin (`sync_pop3_with_auth`
  hardcodes `delete_after_download=false`): a stray DELE would
  diverge the transcript at join.
- `e2e_pop3_auth_err_surfaces_server_reject` — `-ERR` on PASS →
  `server-reject`.
- `e2e_pop3_dead_port_surfaces_connect_error` — refused loopback →
  `connect-failed`.
- `e2e_pop3_malformed_retr_surfaces_server_reject` — garbage status
  line on RETR → `server-reject` (surfaced, not panic/fabrication).
- `e2e_pop3_delete_after_download_sends_dele` — the delete policy is
  engine-level only (no IPC toggle exists): drives
  `kiwi_mail::sync::sync_pop3(_, delete_after_download=true)` over the
  same real TCP+TLS loopback; `DELE 1`/`DELE 2` witnessed in the
  transcript; report.deleted_remote=2; envelopes+bodies still land
  locally; folder registered in the state index like `pop3_sync` does
  (store guard dropped before index lock — same ordering).

Verified: e2e module 13/13 green (incl. T-262's send tests — owner
landed the DATA-terminator fix); full kiwi-app suite 130/130;
clippy `-D warnings` clean; fmt clean.

Note: `MailStore` guard held across `list_*` self-deadlocks — the
delete test scopes the guard before readback calls.

Flags: the IPC path has NO delete-after-download switch today —
hardcoded keep-on-server. If the contract grows a per-account flag,
`pop3_sync` just needs to pass it through.

## T-295 — message_source IPC + POP3 delete-after-download policy (2026-09-25)

Two backend closes, delivered together.

### `kiwi_message_source` (T-292 follow-up — view-source had no command)

- `commands/mail.rs`: `kiwi_message_source` → `message_source_impl`. Lock-gated.
  Resolves `account_id` (len-bound) + `folder_id`/`uid` (negative uid →
  `invalid-input`), asserts folder belongs to the account
  (`store.folder_meta` cross-check → `not-found` on foreign/ghost folder),
  then `store.body_file` → bounded raw read via `load_body_raw`. Absent body
  → `not-found` — honest error, never an empty string.
- `types/mail.rs`: `MessageSourceView { accountId, folderId, uid, source,
  bytes, truncated }` — `bytes` reports the true stored size even when the
  wire payload is truncated (reader sees honesty, not a guess).
- Cap: same 8 MiB UTF-8 discipline as `message_body` — `MAX_SOURCE_BYTES` +
  `truncate_to_byte_cap` char-boundary walk-back (verified with a multi-byte
  `€` straddling the cap).
- lib.rs registered; `kiwi.ts` type + `ipc.ts` `api.messageSource`; ipc.md
  §6 row.
- Frontend: `SourceDialog` gains a **Raw** tab — lazy-loads on first open,
  renders verbatim `<pre>` source, shows `bytes` + a truncation notice when
  `truncated`; error/loading states are honest.

### POP3 delete-after-download policy (the T-285 flag)

- `state.rs`: `AccountMeta.pop3_delete_after_download: bool`
  (`#[serde(default)]` — existing sidecars keep keep-on-server).
- `accounts.rs`: init `false` on account add.
- `mail.rs::pop3_sync`: reads the flag from `index.account_meta` alongside
  `accept_invalid_certs`, passes through to `sync_pop3_with_auth` — covers
  manual sync AND the worker path (single funnel).
- `kiwi_set_pop3_policy` → `set_pop3_policy_impl`: bounds account id,
  `not-found` on unknown account, `invalid-input` on non-POP3 accounts
  (IMAP has expunge semantics, not this), persists to sidecar index, audits
  `pop3-delete-policy` with the account id + new value.
- `types/mail.rs`: `Pop3PolicyView { accountId, deleteAfterDownload }`;
  `kiwi.ts` + `ipc.ts api.setPop3Policy`; ipc.md documents default-keep,
  UIDL dedup, and the destructive nature of enabling DELE.

### Tests

- `message_source_roundtrips_stored_rfc822` — verbatim RFC822 (no parse),
  `bytes`/folder/uid echo; folded-in absent-body → `not-found`, negative
  uid → `invalid-input`, ghost account → `not-found`.
- `message_source_byte_cap_is_honest` — 8MiB+ straddling `€` →
  `truncated:true`, `bytes` = full size, source ends on a char boundary.
- `pop3_policy_toggle_persists_and_is_pop3_only` — toggle on a POP3 row
  persists via `set_pop3_policy_impl` + `Pop3PolicyView` reflects it;
  same call on an IMAP row → `invalid-input`; ghost → `not-found`.
- The e2e DELE wire branch was already proven in T-285
  (`e2e_pop3_delete_after_download_sends_dele`); the policy command is the
  new IPC surface.

### Verified

`cargo test -p kiwi-app` — **139/139 green** on the final binary.
`cargo clippy -p kiwi-app --all-targets -- -D warnings` clean; fmt clean;
tsc clean.

### Caveats (cross-agent churn, not this change)

- The tree was heavily contended all session: kiwi-integrations +
  `send/` T-298 (outbox `last_error`) + pairing_listen tests were all
  mid-write during verification. Gates were taken on quiet windows;
  two suite runs saw transient failures inside other agents' modules
  (a stale-exe schema mismatch and a socket-contention stall) — both
  resolved on rerun with zero changes from me.
- `store_body` requires an existing message row (`UPDATE messages SET
  body_path`) — the source tests `upsert_message` first. Noted for future
  fixture authors.

## T-309 — mbox import (mailbox migration path) — DONE

### Landed

- **Parser** (`kiwi-mail/src/mbox.rs`, `pub mod mbox`): line-start `From `
  separators (mboxrd), envelope-sender token extracted for `fromAddr`
  fallback, `>+From ` unescape (one level), LF+CRLF, EOF-terminated last
  member, leading-junk flag, X-Mozilla-Status/-Status2 → `\Seen`/`\Answered`/
  `\Flagged`/`\Junk` best-effort, `0x0008` Expunged surfaced (skip, don't
  resurrect deleted mail). `split()`/`member()` share one offset walk.
- **Store**: `has_message_id(account_id, mid)` + `idx_messages_mid`;
  `max_uid(account_id)` for import-side uid minting.
- **`kiwi_import_mbox`** (`commands/import.rs`): lock-gated; path must be
  a regular file ≤512MiB (metadata check first — over-cap never read), no
  `From ` → `invalid-input`, ≤50k members. `folder` defaults to `Import`
  (local folder — IMAP reconcile would expunge imported uids from a synced
  folder); explicit synced folder is allowed with that documented caveat.
  Minted uids = `max_uid+1..`. Dedup on Message-ID (account-wide, null mid
  always imports). Rows run the full sync-side ingest pipeline:
  `EvalStage::Full` rules (errors → `ruleFailures`), attach/link risk,
  authstamp with no SMTP receipt (spf=none — never fabricated), threading
  headers indexed. Honest accounting: imported+dup+expunged+failed ==
  min(found,cap); `truncated` marks never-parsed overflow; `issues`
  bounded (≤200×160ch, no bodies/filenames). Audited `mbox-imported`
  (counts only, no path). Front-end: `api.importMbox`, `MboxImportView`,
  ipc.md §6 row with the synced-folder caveat. UI seam deferred per task.

### Tests

- `import_multi_member_with_unescape_expunge_and_bad_skip` — 3-member
  fixture: envelope-sender fallback, `>>From`/`>From` unescape, flags map
  (read/starred/replied/junk + unseen default), Expunged skipped, a member
  with zero parseable headers fails-not-fatals, order preserved, bodies
  stored verbatim.
- `import_dedups_on_message_id_and_rejects_bad_inputs` — re-import dedups,
  bad path / dir / over-cap / no-separator / bad folder / unregistered
  account all typed errors, counter invariant held.
- `import_is_lock_gated`.
- `kiwi-mail`: 6 parser tests (split/unescape/status map/junk/no-sep/eof).

### Caveats

- "Malformed" = zero parseable headers (mail-parser is deliberately
  forgiving); still deterministic + reported.
- Line endings stored verbatim (never normalized) — bytes stay exact.
- Import lands rows only; bodies go to `store_body`'s files dir.
- Heavy concurrent churn (export/folders/forensics agents mid-write);
  final gates taken once tree quieted.

### Final verification (quiet tree, 22:2x)

- `cargo test -p kiwi-mail` — **227/227**
- `cargo test -p kiwi-app` — **184/184** (incl. import 3 + export/folders/
  forensics tests landed by other agents during the session)
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo fmt --all -- --check` — clean; `tsc --noEmit` — clean
- Interim breakage during the session was cross-agent mid-write
  (mbox export half, folders v17 migration, T-320 envelope): three
  mechanical unblocks applied in passing (parse_borrowed::<2>,
  execute_batch literal, one redundant `&`) — all other agents' files,
  no semantic changes.

## T-326 — synced-folder import refusal (2026-09-25 ~22:3x)

Closes the caveat T-309 documented: imported rows carry locally-minted
uids with no server identity, so an IMAP reconcile treating the server as
authoritative would expunge them on the next pass.

Chose option (a) — refuse synced targets at resolution; option (b)
(origin flag on message rows + reconcile skip-list) would have touched
the hot sync path for a corner already avoidable by folder choice, and
T-319's `FolderOrigin` made (a) a ~25-line store change.

Change:

- `kiwi-mail/src/store/queries.rs` `ensure_target_folder` (import-only
  caller): now resolves **local-only** — reuses a local row of the name,
  creates one when none exists, and `PolicyRejected` (→ `policy-blocked`
  on the wire) when only remote/system rows match. A same-name local row
  wins over a synced twin (folders table has no unique constraint —
  remote+local "Archive" can coexist). Unrecognized origin fails closed
  (counts as synced, never writable).
- `commands/import.rs` module doc updated (the "allowed but expunges"
  caveat → refusal).
- ipc.md §`kiwi_import_mbox` bullet rewritten to the refusal semantics;
  `folderIsSynced` deliberately absent — a returned view is non-synced
  by construction.

Tests: `import_refuses_synced_target_folders` — remote `Work` and system
`INBOX` targets → `policy-blocked` (no rows written); local `Shared`
coexisting with a same-name remote row resolves local and imports 2.
Existing import tests unchanged (targets default/new → local).

Verification: `cargo test -p kiwi-mail` **227/227**; fmt clean.
`kiwi-app` gates blocked mid-session by a foreign audit-retention
migration (`audit.rs`/`security.rs`/`state.rs` — duplicate
`kiwi_audit_events`, `RetentionPolicy`/`clamp_u32` unresolved, owner
actively writing) — re-verified once it landed (see below).

### T-326 follow-up (quiet-tree re-verify)

The foreign audit-retention migration landed. Final state:

- `cargo test -p kiwi-app --lib` — **201 pass / 2 fail**, both foreign:
  `audit::tests::sweep_is_audited_with_counts_only` and
  `audit::tests::prune_keeps_newest_and_the_chain_still_verifies`
  (audit-retention cutoff math — that migration's own tests, owner
  still iterating; reported in-band, untouched by me).
- `cargo test -p kiwi-mail --lib` — **229/229** (store change covered;
  `v16_to_v17_preserves_folders_and_classifies_origins` green).
- `cargo clippy -p kiwi-mail -p kiwi-app --all-targets` — clean.
- fmt clean on my files (`queries.rs`, `import.rs`); one pre-existing
  fmt drift in foreign `store/mod.rs` test code left untouched.
- Design note surfaced during test: `idx_folders_sibling_name` is
  UNIQUE `(account_id, COALESCE(parent_id,0), name COLLATE NOCASE)` —
  same-name remote+local twins cannot coexist, so the resolver lookup
  is `COLLATE NOCASE` too: a case-variant of a synced name refuses
  rather than dying on the unique index as a raw store error.

## T-328 — IMAP server-folder CRUD on real wire commands

Closed T-319's filed gap: `kiwi_folder_create|rename|delete` now route by
ownership — IMAP accounts perform real `CREATE`/`RENAME`/`DELETE` on the
wire, local rows/POP3 keep the T-319 store-only path.

**Ordering (fail-closed, nothing faked locally first):** validate → audit
intent (`folder-*-requested`) → wire op → verifying `LIST` → local mirror →
audit outcome (`folder-*-remote`). Server `NO`/`BAD` → `server-reject` with
reply text verbatim; an `OK` that LIST contradicts → `protocol-error`; a
refused or failed op leaves zero local residue.

**Files:**

- `kiwi-mail/src/imap/commands.rs` — new `hierarchy_delimiter()`:
  `LIST "" ""` probe, parses the delimiter off the root row, `None` = NIL
  (flat namespace). `create_mailbox`/`delete_mailbox`/`rename_mailbox`
  already existed with `ok_or_reject` surfacing server text.
- `kiwi-mail/src/store/queries.rs` — `rename_remote_folder` (local rows
  refuse, NOCASE sibling-duplicate check, target + `old<sep>…` inferiors
  rewritten in **one unchecked transaction**, returns refreshed metas) and
  `delete_remote_folder` (local rows refuse, `clear_folder_messages` drops
  messages/evidence/watermarks/payload dirs, inferiors survive — flat
  model, server keeps them).
- `kiwi-app/src-tauri/src/commands/folders.rs` — routing:
  - `with_imap_session` — `connect_imap` → op → `record_connection`
    observation (`imap folder create|rename|delete` labels) → logout.
  - create (IMAP): `LIST "" ""` delimiter → leaf rejects controls,
    `.`/`..`, `%`/`*` wildcards, reserved names, and the server delimiter
    → `<parentWire><sep><leaf>` → `CREATE` → `LIST` verify → `ensure_folder`
    mirror (server spelling wins).
  - rename (remote/system row): `INBOX` → `policy-blocked`; leaf keeps
    the old wire prefix (`A/B` → `C` issues `RENAME A/B A/C`); `RENAME` →
    `LIST` verify → `rename_remote_folder` mirrors target + inferiors.
  - delete (remote/system row): `INBOX` → `policy-blocked`; `DELETE` →
    `LIST` must show absent → `delete_remote_folder` mirror.
  - POP3 remote/system rows → `policy-blocked` (no server namespace);
    local rows unchanged T-319 path. Local parent under IMAP →
    `invalid-input` (server can't see it).
- `kiwi-app/src-tauri/src/e2e.rs` — 3 scripted-loopback tests (real TCP +
  TLS, same harness as T-262/T-285):
  - `e2e_imap_folder_crud_hits_the_wire` — 4 sessions: CREATE `Work` →
    CREATE `Work/Sub` (delimiter composition) → `RENAME Work Tasks` (local
    mirror renames `Tasks` + `Tasks/Sub`) → `DELETE Tasks` (row gone,
    `Tasks/Sub` survives) → audit intents + outcomes all present.
  - `e2e_imap_folder_no_reply_surfaces_server_reject` — tagged `NO
    [CANNOT] denied: read-only server` → `server-reject` + reply text +
    zero folders mirrored.
  - `e2e_imap_folder_refusals_never_dial` — dead port; `W*rk`, `a%b`,
    `INBOX` create → `invalid-input`; INBOX rename/delete →
    `policy-blocked`; local-parent under IMAP → `invalid-input`. Codes
    prove refusal before connect.
- `docs/contracts/ipc.md` — 3-command section rewritten: protocol/origin
  routing, delimiter probing, LIST-verify ordering, error mapping,
  audit labels; T-319 non-goal block replaced with the T-328 contract.

**Verification:** `cargo test -p kiwi-app` **219/219** (all e2e incl.
T-285's POP3 delete green — that hang is resolved in-tree); `cargo test
-p kiwi-mail` **235/235**; `cargo clippy --workspace --all-targets --
-D warnings` clean; `cargo fmt --all -- --check` clean.

## STAND-DOWN checkpoint (Lead EOD, ~22:3x)

### In-flight state
None. T-309 mbox import was completed, verified, and DONE-reported
(`input_accepted`) before the stand-down. No atomic step was in progress;
no half-written files are mine.

### Files touched this task (T-309)
- `kiwi-mail/src/mbox.rs` — mboxrd parser (split/member/flags/
  envelope-sender/unescape). NOTE: the mbox-*export* half (separator,
  `escape_for_mbox`, `mozilla_status_lines`, asctime) was added on top by
  another agent; I applied two compile unblocks in their half
  (`parse_borrowed::<2>` for the deprecated `parse`, collapsed a
  `format!`/redundant-closure) — mechanical only.
- `kiwi-mail/src/store/queries.rs` — `has_message_id` + `idx_messages_mid`,
  `max_uid`. Later agents added v17–v19 folder/mute/parts schema around it.
- `kiwi-app/src-tauri/src/commands/import.rs` — `kiwi_import_mbox` + 3
  tests. Later: T-326 owner changed synced-folder targets from
  caveat-allowed to refused (`policy-blocked` via `ensure_target_folder`)
  and added `tray::refresh_tooltip` — contract already reflects it (§6j).
- `kiwi-app/src-tauri/src/types/mail.rs`, `kiwi.ts`, `ipc.ts`,
  `docs/contracts/ipc.md` — `MboxImportView`/`MboxImportIssueView`,
  `api.importMbox`, §6j row (relocated + updated by later agents).
- `kiwi-app/src-tauri/src/lib.rs`, `commands/mod.rs` — registration.

### Verified at checkpoint
kiwi-mail 227/227, kiwi-app 184/184, workspace clippy `-D warnings` clean,
fmt/tsc clean — all on the merged tree *before* the EOD land-rush in the
diff burst above. That burst (T-316/319/320/323-345, tray/notify/consent/
copy/storage/thread-mute/search-ops) is unverified by me.

### Next exact action on resume
1. `cargo clippy --workspace --all-targets -- -D warnings` and
   `cargo test -p kiwi-mail && cargo test -p kiwi-app` on the post-land-rush
   tree — confirm nothing in the T-3xx wave broke (they touch my import.rs
   via `ensure_target_folder` + `tray::refresh_tooltip`).
2. If green: nothing — T-309 is closed. Await next task from Lead.
3. If red in import/mbox: fix on my files only; flag the rest to owners.
4. Live e2e (mailpit/greenmail) is down until infra restart — do not
   interpret `e2e_*` connection failures as regressions tomorrow.

## 2026-09-26 — T-339 lazy attachment fetch (claimed → in progress)

Status: **in progress**. Assigned at `f405b0b`; session restarted mid-
flight — this log entry is the formal claim/re-claim.

Found pre-restart work already in the tree (mine, per file headers):
`kiwi-mail/src/parts.rs` (untracked — plan/compose skeleton),
`BodyStructure::Single` disposition+disp_params in `imap/parser.rs`,
`message_parts` DDL at schema v19 in `store/schema.rs`, `sync.rs`
has_attachment_parts → `parts::is_attachment_leaf` delegation.

### Design (locked after reading the full tree)

- **Sync**: metadata fetch gains `BODYSTRUCTURE`; `plan_parts` →
  `set_message_parts` rows. Body fetch (`fetch_missing_bodies` +
  `load_body_raw`): when parts rows exist → fetch
  `BODY.PEEK[HEADER]` + `{sec}.MIME` for every leaf/container + `{sec}`
  for eager leaves → `compose_skeleton` → `store_body`. Any plan/
  compose/fetch failure or `too_complex` → fall back to full `BODY[]`
  and `clear_message_parts` (absent rows = complete body; present rows =
  skeleton). Skeletons never leak as "complete RFC822".
- **On-demand**: `ensure_part_fetched` — `UID FETCH (UID BODYSTRUCTURE)`
  re-plan → drift check (`section`+`mime` must match the stored row,
  fails closed on stale uids/moved messages) →
  `BODY.PEEK[<section>]` → `decode_transfer_encoding` → ≤50 MiB cap →
  `store_attachment` (`attachments/<fid>/<uid>/<idx>`) →
  `mark_part_fetched` → merge `inspect_attachment` evidence into
  `message_attachment_risk` → observe + audit (`attachment-fetched`,
  ids/names only, never bytes).
- **Surfaces**: `kiwi_download_attachment` + `kiwi_sandbox_open_attachment`
  resolve through `message_parts` rows when present (rows are
  authoritative — never the skeleton's empty parts); `kiwi_message_source`
  + `kiwi_mailbox_export_mbox` switch to `load_body_full` (real BODY[],
  never skeleton bytes); `AttachmentView` gains `index`/`fetched`.
- **Consistency**: `move_messages` re-keys rows, `copy_messages`/`move_local`
  copy rows + payload dir, delete/expunge/uidvalidity cascade via the
  composite FK, `clear_message_parts` removes payload dir.
- **Honesty**: deferred attachment = unfetched, never "clean"; export/
  source paths never emit skeletons; copies of deferred messages fail
  closed at the drift check (server uid differs) rather than fetching a
  wrong message's bytes.

### Foreign-file caution
`kiwi-mail/src/threading.rs`, `store/threads.rs`, `thread_mutes` schema
chunk = T-341 (another agent). queries.rs move/copy already carries
their `thread_mutes` re-key — I add `message_parts` alongside without
touching their lines.

### T-339 verification (DONE)

- `e2e_lazy_attachment_body_peek` (new, kiwi-app/src-tauri/src/e2e.rs):
  scripted two-connection loopback — sync asserts BODYSTRUCTURE in the
  metadata UID FETCH, no BODY[] on the wire; `message_parts` row persists
  (`fetched=0`, section "2", wire size); reader body is the skeleton;
  `kiwi_download_attachment` triggers a fresh `BODYSTRUCTURE` re-verify +
  `BODY.PEEK[2]`, base64-decodes, stores, marks fetched;
  `kiwi_message_source` forces a complete `BODY[]`.
- Gates: `cargo fmt` clean, `cargo clippy --workspace --all-targets
  -D warnings` clean, `kiwi-app` `tsc --noEmit` clean,
  `cargo test -p kiwi-mail` 284/284, `cargo test -p kiwi-app` 242/242.
- Bug found+fixed by the tests: lenient base64 silently misdecoded
  mid-stream `=` padding — decoder now preserves padding bytes, re-pads
  only truncated tails, rejects misplaced padding (parts.rs tests pin it).
- Testutil `rewrite_tag` hardened: bare `a`/letter+digit tags rewrite,
  literal-payload lines (`Content-Type:`, `From:`) pass through
  unrewritten — was mangling literal-bearing fixtures.
- Committed as `A19 → T-339` with hunk-level staging: foreign in-flight
  work (T-328/329/334/341/345/316/319/282…) in shared files left
  unstaged; my hunks only.

DONE: Agent-19 T-339 — lazy attachment fetch landed: BODYSTRUCTURE-first
sync persists message_parts + skeleton bodies, attachments fetch
on-demand via BODY.PEEK[section] with drift re-verification; export/
source/sandbox stay honest; all gates green.
