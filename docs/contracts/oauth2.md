# Contract — OAuth2 Grant Acquisition (`kiwi-autoconfig::oauth2`)

> Owner: Agent 19 · **Contract version: `kiwi.oauth2/1`** · Status: final
> (T-195) · Implemented by `kiwi-autoconfig/src/oauth2/` (Rust). This
> document is authoritative for provider endpoints, grant state machines,
> token lifecycle, and credential-store wiring. Changes require Lead
> review → record in DECISIONS.md.

Parties: `kiwi-autoconfig::oauth2` (grant acquisition + token lifecycle) →
`kiwi-app` setup wizard + `src-tauri` command layer (browser hand-off,
credential persistence, connect-time refresh) → `kiwi-mail` (`AuthRef::
XOAuth2` consumed by `imap`/`smtp` XOAUTH2 SASL).

## 1. Invariants (binding)

- **Secrets never logged, never in a DB, never plaintext on disk.**
  `access_token`, `refresh_token`, `code_verifier`, `device_code`, and the
  serialized blob are secret material. `Debug` impls are hand-written and
  redacted; the only persistence path is `kiwi_mail::account::
  CredentialStore` (OS keystore — SECURITY.md rules 6, 8, 16).
- **HTTPS-only.** All provider endpoints are `https://`; the transport
  refuses anything else before a socket opens (`InsecureUrl`). Redirects
  are never followed — a 3xx is a response, not a chase target.
- **No client secrets.** KIWI is an installed public client: PKCE
  (`S256` only, `plain` never emitted) and the device code carry the
  security. `client_id` is a public identifier, not a secret.
- **Deterministic where possible.** No wall-clock reads: `now_unix`
  (seconds since epoch) is injected into `begin`/`exchange`/`poll`/
  `refresh`. Entropy (`getrandom` CSPRNG) is confined to `GrantSecrets::
  generate`; tests pin it via `begin_with`/`GrantSecrets::fixed`.
- **`unsafe` forbidden** (workspace lint). No panics on adversarial input:
  every externally-supplied byte (token JSON, redirect query, device-code
  response) is length-bounded and charset-validated.
- **Fail closed.** Unknown provider ids, malformed payloads, non-bearer
  token types, state mismatches, and dead grants are errors — never
  silently degraded.
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
`&dyn OAuthTransport` (§6).

### 3.1 `PendingGrant` — in-flight grant, not serializable, not `Clone`

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
  `Err(UnsupportedGrant)`.

### 3.2 Loopback auth-code exchange (Google)

1. `begin` binds `127.0.0.1:0`, mints `state` + `code_verifier`
   (`code_challenge = BASE64URL-NOPAD(SHA-256(verifier))`), and returns the
   authorize URL — **no endpoint call happens in `begin`**.
2. Browser approves → provider redirects to `http://127.0.0.1:{port}
   /?code=…&state=…` (or `?error=…`).
3. `grant.wait_for_redirect()` → `RedirectOutcome { code, state, error,
   error_description }`. `RedirectOutcome::from_query` parses a pasted
   redirect too (query or full URL).
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
   (≤64 chars), `verification_uri` (must be `https://`, ≤1024 chars),
   `expires_in` (required, >0 → `expires_at = now + expires_in`),
   `interval` (optional, ≤300 s; default 5 s).
2. Caller displays `user_code` + `verification_uri`, then calls `poll`
   once per interval — `poll` itself never sleeps.
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
  scope?}` (scope echoed only if the `TokenSet` carries one — RFC 6749 §6
  forbids widening). **Rotation rule:** a response `refresh_token`
  replaces the stored one (Microsoft rotates on every refresh — the new
  blob MUST be persisted immediately); an absent field preserves the
  existing refresh token (Google semantics).
- `refresh`/`exchange` errors: `invalid_grant`/`bad_verification_code` →
  `InvalidGrant` (dead grant — interactive re-auth required);
  `expired_token` → `Expired`; OAuth `{error,error_description}` →
  `Endpoint` (code ≤128 chars, description ≤256); non-2xx without a
  parseable payload → `Http{status}`.
- Connect-time helper: `ensure_fresh(http, flow, store, email, now)` —
  load → `needs_refresh`? → `refresh` → persist → return. `Ok(None)` when
  no grant is stored; `Err(InvalidGrant)` when re-auth is needed.
- Validation of token payloads: `access_token` required, non-empty,
  printable-ASCII-without-whitespace, ≤8 KiB (`MAX_TOKEN_FIELD`);
  `token_type` must be `Bearer` (case-insensitive); `scope` ≤8 KiB, empty
  normalizes to absent; unknown JSON fields ignored.

## 5. CredentialStore seam (binding)

- Blob: `TokenSet::to_blob()` → JSON
  `{"v":1,"access_token","refresh_token"?,"expires_at_unix"?,"token_type",
  "scope"?}`; `from_blob` rejects unknown `v` and revalidates every field.
  The blob is **secret-bearing**: `CredentialStore::set` only — never a
  DB row, never a file, never a log line.
- Key derivation (deterministic, mirrors `autoconfig/<email>/…`):
  `credential_key(provider, email) = "oauth2/<provider>/<lowercased
  email>"`.
- `auth_ref(provider, email)` → `AuthRef::XOAuth2 { credential_key }` —
  assign to **both** `incoming.auth` and `outgoing.auth`; one grant covers
  IMAP+SMTP for both providers.
- `save_tokens` / `load_tokens` / `delete_tokens` wrap the seam; store
  errors map to `OAuthError::CredentialStore` (error text only, per the
  keyring adapter's no-secrets rule).
- Wizard integration: on an `xoauth2` suggestion (autoconfig.md §6), run
  the provider's grant, `save_tokens`, then set `auth_ref` on the account
  instead of a password key.

## 6. Transport seam

`OAuthTransport` — one verb: `post_form(url, &[(&str,&str)]) ->
Result<TransportReply{status, body}>`. Blanket-implemented for every
`kiwi_integrations::http::HttpClient`:

- `ReqwestClient` (production): reqwest 0.13 + rustls,
  `redirect::Policy::none()`, timeout, streaming body cap —
  `live_transport(timeout_ms)` builds it with `body_cap = MAX_TOKEN_BODY`
  (64 KiB).
- `ScriptedHttp` (tests/fixtures): ordered recorded responses that also
  assert request method/URL/headers/body — fixture runs replay exactly.
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
- Non-grant requests — favicon fetches, probes, malformed request lines —
  get a minimal fixed page and the wait continues. Per-connection I/O is
  bounded (`MAX_REQUEST_LINE` = 8 KiB, 5 s read/write timeouts).
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
| `UnsupportedGrant` | `exchange`/`poll` called on the wrong grant kind |
| `Loopback` | listener I/O failure |
| `InvalidConfig` | bad `client_id`/`tenant`/`provider`/PKCE material |
| `CredentialStore` | OS keystore failure (text only) |
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

`cargo test -p kiwi-autoconfig` — 92 tests, fully offline (39 new for this
module): RFC 7636 §B challenge vector; form codec incl. malformed-escape
rejection; provider/tenant/client-id validation; device begin validation
matrix; poll `pending → slow_down → complete → denied/expired`;
pre-expired poll short-circuit (no request consumed); authorize-URL
contents; exchange exact-body assertion + state-mismatch/error/missing-
code guards (no request consumed); wrong-grant-kind calls; refresh
rotation/preservation/`invalid_grant`; `TokenSet` parse matrix, blob
roundtrip + version rejection + `Debug` redaction; `needs_refresh` skew
boundary; credential-key/`auth_ref` shapes; store roundtrip via
`MemoryCredentialStore`; `ensure_fresh` refresh+persist/fresh-no-request/
absent paths; loopback listener over real `127.0.0.1` sockets (noise
requests ignored, error redirect, timeout). No test performs a live call.

## 11. Out of scope (future work)

- Token revocation endpoints (Google `revoke`, Microsoft logout) —
  `delete_tokens` covers local removal only.
- Brokered auth (Windows WAM/WebView2), `prompt=select_account` variants,
  POP3 XOAUTH2 wiring, `id_token` claims validation (we take no OIDC
  dependency — identity is the user's own mailbox address).
