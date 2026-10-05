# Contract — OAuth2 Grant Acquisition (`kiwi-autoconfig::oauth2`)

> Owner: Agent 19 · **Contract version: `kiwi.oauth2/1`** · Status: crate
> implementation landed; **T-229 contract review complete** (2026-09-25,
> close-out re-verified 2026-09-26 after T-230 landed). T-230 wired the IPC
> ceremony (begin/poll/cancel/status/discover, ticket→account binding,
> `save_tokens` persistence) — but the connect-time decode+refresh is still
> missing (gap 7, now confirmed against the landed T-230 code). Implemented
> by `kiwi-autoconfig/src/oauth2/` (Rust). This document is authoritative for
> provider endpoints, grant capabilities, token lifecycle, and credential-store
> wiring. Changes require Lead review → record in DECISIONS.md.

Parties: `kiwi-autoconfig::oauth2` (grant acquisition + token lifecycle) →
`kiwi-app` setup wizard + `src-tauri` command layer (browser hand-off,
credential persistence, connect-time refresh) → `kiwi-mail` (`AuthRef::XOAuth2` consumed by `imap`/`smtp` XOAUTH2 SASL).

**T-229 disposition:** the provider/grant API, PKCE vector, recorded
transport fixtures, and normal token refresh path match the implementation.
The contract below explicitly marks the remaining source gaps instead of
describing them as shipped guarantees: secret-bearing `Debug` envelopes,
stored-blob validation, public redirect construction, live-vs-injected
transport guarantees, stateless grant replay, soft loopback bounds, and —
since T-230 wired storage/ceremony but not the connect path — the missing
connect-time blob decode + refresh (gap 7, confirmed 2026-09-26).

## 1. Invariants (binding)

- **Secrets never logged, never in a DB, never plaintext on disk.**
  `access_token`, `refresh_token`, `code_verifier`, `device_code`, the
  authorization `code`, grant state, serialized blob, and raw HTTP
  request/response bodies are secret material. Every `Debug` surface that can
  contain one MUST be redacted; the only persistence path is
  `kiwi_mail::account::CredentialStore` (OS keystore — SECURITY.md rules 6,
  8, 16). **Implementation gap (T-229):** `GrantSecrets`,
  `RedirectOutcome`, and transport envelopes still derive body-bearing
  `Debug` in the current crate; they must be fixed before this requirement is
  considered satisfied.
- **HTTPS-only for the live adapter.** The shipped Google/Microsoft presets
  use `https://` endpoints. `live_transport`/`ReqwestClient` refuses anything
  else before a socket opens (`InsecureUrl`), never follows redirects, and
  streams at most `MAX_TOKEN_BODY` bytes. An injected/custom
  `OAuthTransport` is responsible for enforcing the same rules; the blanket
  `HttpClient` adapter does not make a test double safe by itself.
  **Implementation gap (T-229):** `ProviderConfig` fields are public and
  mutable, and `ScriptedHttp` does not enforce the live URL/body policies.
- **No client secrets.** KIWI is an installed public client: PKCE
  (`S256` only, `plain` never emitted) and the device code carry the
  security. `client_id` is a public identifier, not a secret.
- **Deterministic where possible.** Provider expiry and token logic use
  injected `now_unix` (seconds since epoch); the module does not read a wall
  clock. The loopback listener necessarily uses a monotonic `Instant` only for
  its local wait deadline. Entropy (`getrandom` CSPRNG) is confined to
  `GrantSecrets::generate`; tests pin it via `begin_with`/`GrantSecrets::fixed`.
- **Validation is field-specific and bounded.** Token fields are printable
  ASCII without whitespace and at most 8 KiB. Redirect/device payloads have
  documented field bounds; verification URLs are currently prefix/length
  checked, and scope/error text is length-bounded but not control-free.
  Callers must use `RedirectOutcome::from_query` rather than construct its
  public fields directly. **Implementation gaps (T-229):** the public
  `RedirectOutcome` fields, optional `verification_uri_complete`, and stored
  credential blob are not yet validated to the stronger contract wording.
- **Fail closed for mapped cases.** Unknown provider ids, malformed required
  payloads, non-bearer token responses, state mismatches, and dead grants are
  errors — never silently degraded. The T-229 implementation gaps below are
  explicit exceptions until the source is tightened.
- `CONTRACT_VERSION` = `"kiwi.oauth2/1"`.

## 2. Providers and grant shapes

`ProviderConfig` carries fixed endpoint facts; `client_id` is the only
deployment input. Registry: `ProviderConfig::by_id` over `KNOWN_PROVIDERS
= ["google", "microsoft"]` — unknown ids fail closed.

| Provider | `ProviderConfig::` | Grant kind | Authorize / device-code endpoint | Token endpoint | Scopes |
|----------|-----------|------------|----------------------------------|----------------|--------|
| Google | `google(client_id)` | `loopback_code` | `https://accounts.google.com/o/oauth2/v2/auth` | `https://oauth2.googleapis.com/token` | `https://mail.google.com/` |
| Microsoft | `microsoft(client_id)` / `microsoft_tenant(client_id, tenant)` | `device_code` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | `https://outlook.office.com/IMAP.AccessAsUser.All`, `…/SMTP.Send`, `offline_access` |

- Microsoft `tenant` defaults to `common` (personal + work/school
  accounts). Tenant is charset-validated `[A-Za-z0-9.-]` ≤128 chars — it
  is interpolated into URL paths.
- Google `authorize_extra`: `access_type=offline`, `prompt=consent` — a
  refresh token is issued on every interactive grant, including
  re-authorization.

## 3. API surface (`kiwi_autoconfig::oauth2`)

```text
trait OAuthFlow: Send + Sync {
    fn provider_id(&self) -> &str;
    fn grant_kind(&self) -> GrantKind;                      // loopback_code | device_code
    async fn begin(&self, http, now_unix) -> Result<PendingGrant>;
    async fn begin_with(&self, http, secrets: Option<&GrantSecrets>, now)
                                                        -> Result<PendingGrant>;
    async fn exchange(&self, http, grant, redirect: &RedirectOutcome, now)
                                                        -> Result<TokenSet>;
    async fn poll(&self, http, grant, now) -> Result<PollOutcome>;
    async fn refresh(&self, http, tokens: &TokenSet, now) -> Result<TokenSet>;
}
```

`OAuthClient` is the implementation (`OAuthClient::new(ProviderConfig)`,
`OAuthClient::google(cid)`, `OAuthClient::microsoft(cid)`). `http` is an
`&dyn OAuthTransport` (§6). Registry lookup is
`ProviderConfig::by_id(id: &str, client_id: &str) -> Result<ProviderConfig,
OAuthError>`; unknown ids fail closed. Discovery helpers (added post-T-195
review, T-251): `provider_id_for_suggestion(&AccountSuggestion) ->
Option<&'static str>` — the provider id for a suggestion whose mail host is
one a shipped config can mint tokens for (`None` for password suggestions,
POP3, and XOAUTH2 providers without a client config); `grant_kind_str()` —
the provider's grant kind in wire spelling.

### 3.1 `PendingGrant` — immutable capability, not a serialized state machine

`PendingGrant` is an in-flight capability, not serializable and not `Clone`.
It is passed by shared reference and the crate does not mark it consumed or
terminal. The caller owns lifecycle state and must discard it after
completion, denial, expiry, or invalidation. A replayed call is the caller's
responsibility unless a future provider-side token check rejects it.

- `PendingGrant::Loopback(LoopbackGrant)` — `authorize_url` (open in
  system browser), `redirect_uri` (`http://127.0.0.1:{port}`), `state`
  (public), `code_verifier` + bound `LoopbackListener` (private).
  `grant.wait_for_redirect(timeout)` blocks for the provider redirect —
  callers on async runtimes must `spawn_blocking`/thread it.
- `PendingGrant::Device(DeviceGrant)` — `user_code` + `verification_uri`
  (+ optional `verification_uri_complete`) shown to the user;
  `expires_at_unix`, `poll_interval_secs`; `device_code` is private.
- Accessors: `kind()`, `authorize_url()`, `user_code()`,
  `verification_uri()`, `wait_for_redirect()`.
- `exchange` on a device grant / `poll` on a loopback grant →
  `Err(UnsupportedGrant { expected })`; `expected` identifies the required
  grant kind.

### 3.2 Loopback auth-code exchange (Google)

1. `begin` binds `127.0.0.1:0`, mints `state` + `code_verifier`
   (`code_challenge = BASE64URL-NOPAD(SHA-256(verifier))`), and returns the
   authorize URL — **no endpoint call happens in `begin`**.
2. Browser approves → provider redirects to `http://127.0.0.1:{port}
   /?code=…&state=…` (or `?error=…`).
3. `grant.wait_for_redirect()` → `RedirectOutcome { code, state, error,
   error_description }`. `RedirectOutcome::from_query` is the required parser
   for a pasted redirect (query or full URL) and bounds the raw input. The
   fields are public for integration convenience, so callers MUST NOT
   construct them from unbounded untrusted text; direct construction is an
   implementation gap because `exchange` only checks a non-empty `code`.
4. `exchange` checks **state first** (`StateMismatch` — CSRF guard, before
   any network call and before trusting an `error` claim), then maps a
   redirect `error`, then POSTs the token endpoint:
   `client_id, code, redirect_uri, grant_type=authorization_code,
   code_verifier`.
5. `Err(Denied)` on `access_denied`; `Err(InvalidGrant)` on
   `invalid_grant`.

### 3.3 Device-code grant + poll (Microsoft)

1. `begin` POSTs `{client_id, scope}` to the device-code endpoint →
   `PendingGrant::Device`. Response validated: `device_code`, `user_code`
   (≤64 bytes), `verification_uri` (must start with `https://`, ≤1024 chars),
   `expires_in` (required, >0; the implementation clamps it to one year when
   computing `expires_at = now.saturating_add(min(expires_in, 31_536_000))`),
   `interval` (optional, ≤300 s; default 5 s). Optional
   `verification_uri_complete` is accepted only when it passes the same
   prefix/length check; it is silently discarded when invalid in the current
   implementation (T-229 gap).
2. Caller displays `user_code` + `verification_uri`, then calls `poll`
   once per interval — `poll` itself never sleeps. The `SlowDown` result is
   advisory; the crate does not mutate or retain an increased cadence, so the
   caller must do so.
3. `poll` POSTs `{grant_type=urn:ietf:params:oauth:grant-type:device_code,
   client_id, device_code}` and maps:
   - `authorization_pending` → `PollOutcome::Pending`
   - `slow_down` → `PollOutcome::SlowDown { retry_after_secs }`
     (`interval + 5`, RFC 8628 §3.5; callers SHOULD keep the larger cadence
     for subsequent polls)
   - success → `PollOutcome::Complete(TokenSet)`
   - `access_denied`/`authorization_declined` → `Err(Denied)`;
     `expired_token` → `Err(Expired)`; `bad_verification_code` →
     `Err(InvalidGrant)`
   - `now >= expires_at_unix` → `Err(Expired)` **without a request**.

## 4. Token lifecycle

`TokenSet` (secrets private; `access_token()`, `refresh_token()`,
`expires_at_unix()`, `scope()` accessors; redacted `Debug`):

- `expires_at_unix = now_unix + clamp(expires_in, 0, 1 year)`; absent
  `expires_in` → `None` (non-expiring until the provider says otherwise —
  refresh is then availability-driven).
- `needs_refresh(now)` ⇔ `now >= expires_at_unix - EXPIRY_SKEW_SECS`
  (`60 s`). Consumers refresh inside the skew, not after a 401.
- `refresh` POSTs `{grant_type=refresh_token, client_id, refresh_token,
  scope?}`; a carried scope is echoed verbatim. The module does not compare it
  with the originally granted provider scopes, so callers must ensure the
  stored scope is trustworthy and can never widen a grant (RFC 6749 §6).
  **Rotation rule:** a response `refresh_token` replaces the stored one
  (Microsoft rotates on every refresh — the new blob MUST be persisted
  immediately); an absent field preserves the existing refresh token (Google
  semantics). Google's `access_type=offline`/`prompt=consent` requests a
  refresh token, but a response may still omit one; such a grant is not
  refreshable.
- `refresh`/`exchange` errors: `invalid_grant`/`bad_verification_code` →
  `InvalidGrant` (dead grant — interactive re-auth required);
  `expired_token` → `Expired`; OAuth `{error,error_description}` →
  `Endpoint` (code ≤128 chars, description ≤256); non-2xx without a
  parseable payload → `Http{status}`.
- Connect-time helper: `ensure_fresh(http, flow, store, email, now)` —
  load → `needs_refresh`? → `refresh` → persist → return. `Ok(None)` when
  no grant is stored; `Err(InvalidGrant)` when re-auth is needed.
- Validation of token responses: `access_token` required, non-empty,
  printable-ASCII-without-whitespace, ≤8 KiB (`MAX_TOKEN_FIELD`); an absent
  response `token_type` defaults to `Bearer`, while a present value must be
  `Bearer` (case-insensitive); `scope` ≤8 KiB, empty normalizes to absent;
  unknown JSON fields ignored. `from_blob` currently does **not** enforce
  the stored `token_type`, an input-size cap, or a safe expiry range — those
  are T-229 implementation gaps and must be fixed before persisted blobs are
  treated as fully validated.

## 5. CredentialStore seam (binding)

- Blob: `TokenSet::to_blob()` → JSON
  `{"v":1,"access_token","refresh_token"?,"expires_at_unix"?,"token_type",
  "scope"?}`; `from_blob` rejects unknown `v` and revalidates the fields it
  currently uses. The blob is **secret-bearing**: `CredentialStore::set`
  only — never a DB row, never a file, never a log line. **T-229 gap:** the
  current `from_blob` does not validate the stored `token_type`, impose a
  total input-size cap, or reject extreme expiry values; those are required
  hardening items.
- Key derivation (deterministic, mirrors `autoconfig/<email>/…`):
  `credential_key(provider, email) = "oauth2/<provider>/<email.trim().to_ascii_lowercase()>"`.
- `auth_ref(provider, email)` → `AuthRef::XOAuth2 { credential_key }` —
  assign to **both** `incoming.auth` and `outgoing.auth`; one grant covers
  IMAP+SMTP for both providers.
- `save_tokens` / `load_tokens` / `delete_tokens` wrap the seam; store errors
  map to `OAuthError::CredentialStore`. The generic `CredentialStore` trait
  does not itself enforce secret-free diagnostics, so every adapter MUST omit
  key/blob/token values from its error text.
- **T-230 wired storage but not connect-time decode (gap 7, confirmed
  2026-09-26).** T-230 landed the IPC ceremony
  (`kiwi_oauth2_begin/poll/cancel/status`, ticket→account binding,
  `save_tokens` persistence) — but no connect path decodes the stored blob.
  `save_tokens` writes `to_blob()` JSON at `oauth2/<provider>/<email>`;
  `resolve_secret` (`kiwi-app/src-tauri/src/commands/mod.rs:169-187`)
  returns that value verbatim for every `AuthRef` kind; live IMAP sync
  (`commands/mail.rs:835-843`, via `connect_imap`) and live SMTP send
  (`commands/send/dispatch.rs:297`) pass it straight into
  `XOAuth2 { token: secret }`. `ensure_fresh`/`load_tokens` have zero callers
  on any connect path (`load_tokens` is used only by the status view).
  Net effect: the app sends the full JSON blob — **including the refresh
  token** — as the XOAUTH2 bearer on every connection. Real providers reject
  it (auth fails), and the refresh token is needlessly exposed to the mail
  server. The fix (decode via `from_blob`, refresh via `ensure_fresh`, pass
  only `access_token()`) is a code task for the mail-command owners, not this
  review.
- Wizard integration (T-230): on an `xoauth2` suggestion (autoconfig.md §6),
  run the provider's grant, `save_tokens`, then set `auth_ref` on the account
  instead of a password key.

## 6. Transport seam

`OAuthTransport` — one verb: `post_form(url, &[(&str,&str)]) ->
Result<TransportReply{status, body}>`. Blanket-implemented for every
`kiwi_integrations::http::HttpClient`:

- `ReqwestClient` (production): reqwest 0.13 + rustls,
  `redirect::Policy::none()`, timeout, streaming body cap —
  `live_transport(timeout_ms)` builds it with `body_cap = MAX_TOKEN_BODY`
  (64 KiB). These are guarantees of the live adapter, not of every injected
  transport.
- `ScriptedHttp` (tests/fixtures): ordered recorded responses that also
  assert request method/URL/headers/body — fixture runs replay exactly. It
  does not itself enforce the live URL/body policies.
- Any custom `OAuthTransport` MUST enforce HTTPS, no redirects, bounded
  response bodies (`BodyTooLarge` when exceeded), and opaque transport errors;
  the blanket adapter cannot infer those properties for an arbitrary
  `HttpClient`.
- Form encoding is strict percent-encoding (unreserved `[A-Za-z0-9._~-]`
  pass through; everything else `%XX`, space → `%20`) — identical wire
  bytes on every transport.
- Transport failures map to `OAuthError::Transport{kind: TransportKind}`
  via `kiwi_integrations`' classifier — the underlying message (which can
  embed the request URL) is dropped.

## 7. Loopback listener rules

- Binds `127.0.0.1` only, OS-assigned ephemeral port — never a routable
  interface, never a fixed port.
- `wait(timeout)` accepts connections until one carries `code`/`error`/
  `state` (→ `RedirectOutcome`) or the deadline hits (→ `Err(Expired)`).
  The deadline is checked between accepted connections; a selected peer may
  extend the return by its 5-second socket timeout, and the 8 KiB read guard
  can buffer one additional 1 KiB chunk before stopping. These are **current
  implementation gaps (T-229)**, not stronger guarantees.
- Non-grant requests — favicon fetches, probes, malformed request lines —
  get a minimal fixed page and the wait continues. Per-connection I/O uses
  `MAX_REQUEST_LINE` = 8 KiB (internal constant) and 5 s read/write timeouts.
- Response pages carry no grant material.
- The grant owns the listener: it closes when the `PendingGrant` drops.

## 8. Error taxonomy

| `OAuthError` | When |
|---|---|
| `InsecureUrl` | non-`https://` endpoint (refused pre-connect) |
| `Transport{kind}` | connect/timeout/decode/other, no URL carried |
| `BodyTooLarge` | response exceeded body cap |
| `Http{status}` | non-2xx, no OAuth error payload |
| `Endpoint{error, description}` | OAuth error payload, unmapped code |
| `Denied` | user refused (`access_denied`/`authorization_declined`) |
| `Expired` | grant expired (incl. local pre-poll check, loopback timeout) |
| `InvalidGrant` | `invalid_grant`/`bad_verification_code`/missing refresh token — re-authorize |
| `StateMismatch` | redirect `state` ≠ pending grant (CSRF) |
| `Malformed(field)` | response/redirect shape violation (names the field, never contents) |
| `UnsupportedGrant { expected }` | `exchange`/`poll` called on the wrong grant kind; `expected` is the required `GrantKind` |
| `Loopback` | listener I/O failure |
| `InvalidConfig` | bad `client_id`/`tenant`/`provider`/PKCE material |
| `CredentialStore` | OS keystore failure (opaque adapter text; adapters must omit secrets) |
| `Entropy` | CSPRNG failure |

## 9. Client IDs (deployment, not shipped)

Both providers require an app registration: Google — "Desktop app" OAuth
client (loopback redirect auto-allowed); Microsoft — public client with
device-code + the `outlook.office.com` scopes. `client_id` arrives from
app config/environment at `ProviderConfig` construction; an absent/bad
one fails `begin` (`InvalidConfig("client_id")`). KIWI ships no client
id yet — that is a Lead/product decision (per-tenant ids are also
supported via `microsoft_tenant`).

## 10. Testing

`cargo test -p kiwi-autoconfig` — 97 tests total, of which **33** are
OAuth2 tests, fully offline (92/32 at the 2026-09-25 review; T-251 added
`provider_id_for_suggestion` coverage). The OAuth tests cover the RFC 7636 §B vector;
form codec; provider/tenant/client-id validation; device begin/poll
transitions; expiry short-circuit; authorize URL and exact exchange bodies;
state/error/missing-code guards; wrong-grant calls; refresh rotation and
preservation; token/blob roundtrips and `TokenSet` redaction; skew, credential
key/`auth_ref`, store roundtrip, and `ensure_fresh`; plus real
`127.0.0.1` loopback noise/error/timeout tests. All endpoint exchanges use
`ScriptedHttp`; the only real sockets are loopback tests. No test performs
an external provider call. The suite is not an exhaustive negative-input
matrix: the T-229 gaps above (secret-bearing envelope `Debug`, blob
validation, direct redirect construction, live transport caps, and hard
loopback deadline) still need targeted tests and implementation fixes.

## 11. T-229 implementation-gap register

These are verified source findings, not hypothetical risks. They remain open
until the corresponding implementation and regression tests land:

1. **Secret-bearing `Debug` leaks (High).** `GrantSecrets`,
   `RedirectOutcome`, `TransportReply`, and the underlying HTTP envelopes
   derive body/value-bearing `Debug`; redact authorization codes, verifiers,
   device codes, tokens, and raw bodies or remove those `Debug` impls.
2. **Stored blob validation (High).** `from_blob` ignores `token_type`, has
   no total input-size cap, and accepts extreme expiry values; validate all
   three and use saturating expiry/skew arithmetic.
3. **Redirect/URL boundaries (Medium).** `RedirectOutcome` fields are public;
   direct construction bypasses `from_query`. Device verification URLs are
   prefix/length checked only, and invalid optional
   `verification_uri_complete` is discarded. Either harden the source or keep
   the weaker field-specific wording above.
4. **Stateless replay/cadence (Medium).** `PendingGrant` is not consumed and
   `slow_down` does not mutate the interval; the caller owns terminal state
   and increasing cadence.
5. **Transport scope (Medium).** HTTPS/no-redirect/64-KiB guarantees belong to
   `live_transport`/`ReqwestClient`; custom transports must enforce them.
6. **Loopback bounds (Medium).** Deadline is checked between connections and
   the read cap can overshoot by one chunk; either tighten the implementation
   or retain the explicitly soft-bound wording.
7. **App seam (T-230 wired storage, NOT the connect path — CONFIRMED OPEN
   2026-09-26, High).** T-230 landed the IPC ceremony
   (`kiwi_oauth2_begin/poll/cancel/status`, ticket→account binding,
   `save_tokens` persistence at `oauth2/<provider>/<email>`) — but no connect
   path decodes the stored blob. `resolve_secret`
   (`kiwi-app/src-tauri/src/commands/mod.rs:169-187`) returns the
   credential-store value verbatim for every `AuthRef` kind; live IMAP sync
   (`commands/mail.rs:835-843` via `connect_imap`) and live SMTP send
   (`commands/send/dispatch.rs:297`) pass it straight into
   `XOAuth2 { token: secret }`. `ensure_fresh`/`load_tokens` have zero callers
   on any connect path (`load_tokens` is used only by the status view).
   Net effect: the app sends the full JSON blob — **including the refresh
   token** — as the XOAUTH2 bearer on every connection. Real providers
   reject it (OAuth2 mail auth is broken end-to-end), and the refresh token
   is needlessly exposed to the mail server. Fix (decode via `from_blob`,
   refresh via `ensure_fresh`, pass only `access_token()`) is a code task
   for the mail-command owners, not this review.

## 12. Out of scope (future work)

- Token revocation endpoints (Google `revoke`, Microsoft logout) —
  `delete_tokens` covers local removal only.
- Brokered auth (Windows WAM/WebView2), `prompt=select_account` variants,
  POP3 XOAUTH2 wiring, `id_token` claims validation (we take no OIDC
  dependency — identity is the user's own mailbox address).
