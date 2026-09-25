# Contract — External Integrations (`kiwi-integrations`)

> Owner: Agent 11 · **Contract version: `kiwi.integrations/1`** · Status: draft
> (T-226) · Implemented by `kiwi-integrations/` (Rust). This document is
> authoritative for the provider-trait boundary, wire spellings, secrecy
> rules, and test posture. Changes require Lead review → record in
> DECISIONS.md.

Two provider seams, one transport boundary:

- **`TempMailProvider`** — disposable inbox. Impl: `GuerrillaMail`
  (`api.guerrillamail.com/ajax.php`).
- **`DeliverabilityTester`** — single-shot outbound deliverability test.
  Impl: `EmailSpamTester` (`email-spam-tester.com/api/v1`).

Consumers (kiwi-app IPC, CI tooling) see only the traits + types; providers
hold no state outside memory and expose no provider internals.

## 1. Invariants (binding)

1. **HTTPS only.** Any URL not starting `https://` is refused —
   constructor-time for base URLs (`IntegrationError::InsecureUrl`),
   request-time in `ReqwestClient` as defense-in-depth. Redirects are never
   followed (a 3xx is an answer; following could carry a secret-bearing URL
   to another host).
2. **No credential persistence.** Session material (PHPSESSID, `sid_token`,
   test slugs) lives in `Mutex` memory only. Nothing writes to disk, OS
   keystore, SQLite, or the mail store. `Drop`/process end = gone.
3. **Secrets never logged.** `TestSlug` Debug/Display print `[redacted]`;
   `GuerrillaMail`/`EmailSpamTester` Debug redact session state. Transport
   errors are classified (`TransportKind`) and the provider's own error text
   — which embeds the request URL, which for email-spam-tester contains the
   slug — is **dropped**, never propagated.
4. **Disposable inboxes are PUBLIC.** See §3. Consumers must display
   `tempmail::PUBLIC_INBOX_NOTICE` before enabling the feature.
5. **Untrusted input.** All provider responses are capped before parse
   (`ReqwestClient::body_cap`, enforced while streaming), parsed through
   `serde_json`, unknown fields ignored, unknown enum spellings preserved
   (`CheckStatus::Other`, `AnalysisStatus::Other`) — never fatal.
6. **Deterministic core.** No floats cross the boundary (scores are
   milli-unit integers), no wall-clock reads inside the crate, no RNG.
   Polling loops/timers belong to the caller — the crate provides
   single-shot calls only.
7. **No plaintext downgrade metadata games.** A provider returning an error
   payload surfaces `ProviderRejected`/`Malformed`, never a fake success.

## 2. Transport seam (`http`)

```text
HttpClient (async trait)         — request(HttpRequest) -> HttpResponse
  ├─ ReqwestClient               — reqwest 0.13 + `rustls` feature
  │   (rustls-platform-verifier: OS trust store; rustls everywhere).
  │   redirect policy = none. timeout 30 s. body cap enforced while
  │   streaming (default 1 MiB, per-provider override).
  └─ ScriptedHttp                — ordered recorded transport for tests:
      each Step asserts method + URL fragments + required headers +
      exact body before answering the recorded response. Exhaustion
      is asserted at test end.
```

`HttpResponse.headers` preserves duplicates (`Set-Cookie` rotation).
`HttpResponse::json()` parses the capped body — a cap-truncated body fails
as `Malformed`, never parses a prefix.

## 3. `TempMailProvider` — GuerrillaMail

### 3.0 PUBLIC-INBOX WARNING (normative)

A temp address is a **public mailbox**: anyone who knows/guesses it can
read its mail; content transits a third-party server KIWI does not control
and is *filtered by that server* (see §3.4). Legitimate uses: throwaway
sign-ups, receiving mail you do not care about being public, and **outbound
self-tests**. Never receive real personal/confidential mail on it. The UI
copy constant is `tempmail::PUBLIC_INBOX_NOTICE`.

### 3.1 Session model

- One `GuerrillaMail` instance = one mailbox session. `Session{php_sessid,
  sid_token, address, created_unix, last_seq}` — in-memory only.
- `PHPSESSID` is re-read from `Set-Cookie` on **every** response (the server
  rotates it at will; value charset-filtered `[A-Za-z0-9_-]`, ≤128 chars).
  Sent as `Cookie: PHPSESSID=<v>` on every subsequent request.
- `sid_token` (returned by `get_email_address`) is echoed as a query param
  when present.
- The API demands the caller's `ip` + `agent`. We send constants —
  `ip=127.0.0.1`, `agent=<caller string, ≤160>` — never the user's real
  IP/UA.

### 3.2 Method → wire map

| Trait method | Request | Notes |
|---|---|---|
| `get_email_address` | `GET {base}?f=get_email_address&ip=…&agent=…&lang=en` | also harvests `sid_token`; on an expired session the server silently binds a *new* address |
| `set_email_user` | `POST …?f=set_email_user&email_user=<p>` | `local_part` `[A-Za-z0-9._-]{1,64}`, no leading/trailing/double dot — else `Malformed("email_user")`; switches the session address and resets the poll cursor |
| `check_email` | `GET …?f=check_email&seq=<last_seq>` | `seq` = highest numeric `mail_id` seen; returns ≤20 `list` items; requires session (`NoSession` otherwise); echoed `email` field resyncs `address` |
| `fetch_email` | `GET …?f=fetch_email&email_id=<digits>` | `mail_id` must be `^[0-9]{1,32}$` — else `Malformed` **before** request; session-owned mail only |
| `forget_me` | `POST …?f=forget_me&email_addr=<addr>` | clears local address/cursor/created; PHPSESSID survives (session persists server-side per API) |
| `extend` | `POST …?f=extend` | `{expired, affected, email_timestamp}` → `ExtendOutcome`; server caps at +1h once (2h max) |

All calls carry `Accept: application/json`. Status mapping: 2xx → parse;
404 → `NotFound`; 410 → `Expired`; 429 → `RateLimited{retry_after_ms}` from
`Retry-After` (≤1h); other → `Http{status}`.

### 3.3 Field handling

- GM emits numbers inconsistently as strings/ints — `ju64` accepts both.
- `mail_subject`/`mail_excerpt` arrive HTML-entity-escaped → decoded
  (`amp lt gt quot apos`, `&#NN;`, `&#xHH;`; unknown entities verbatim).
- Every free-text field is char-capped (`MAX_FIELD` 8 KiB; body 4 MiB).

### 3.4 `fetch_email` → synthesized RFC822 (important caveat)

GuerrillaMail has **no raw-source endpoint**: `fetch_email` returns JSON
fields, and `mail_body` is already **server-filtered** (script/iframe
stripped). `TempMessage.raw_rfc822` is therefore *synthesized*:
`From/To/Subject/Date/MIME-Version/Content-Type/Content-Transfer-Encoding`
+ `X-Guerrilla-Mail-Id` + `X-Kiwi-Temp-Provider: guerrillamail
(provider-filtered body; sanitize before render)` + CRLF + verbatim body.

Header values are CTL-stripped before interpolation (CR/LF injection guard).
Result ≤ `MAX_RFC822`. **It is not the original wire message** — it is an
untrusted-content container for KIWI's existing sanitized render path
(T-146). Any claim of "raw source fidelity" would be false — do not add one.

### 3.5 Expiry semantics

Address dies 60 min after `email_timestamp` (one `extend` → +1h, max 2h);
session idles out ~18 min (any call refreshes). The crate reads no clock —
callers compute `3600 - (now - created_unix)` for countdown display. GM
rate limits are unpublished — callers must poll politely (≥10 s suggested).

## 4. `DeliverabilityTester` — email-spam-tester

### 4.1 Flow (single-shot methods; caller drives the loop)

1. `reserve_inbox()` — `POST {base}/inbox` → `{address, slug, expires_at}`.
   The address accepts **exactly one** message; expires ~1h.
2. Caller sends the real message via the real relay to `reservation.address`.
   (A trivial message measures nothing — most checks read relay-added
   headers. This guidance belongs in UI copy.)
3. `poll_status(&res)` — `GET {base}/tests/{slug}/status`:
   - `202` → `AnalysisStatus::Pending`
   - `200` → `{analysis_status, checks_done, checks_total}` →
     `received | analyzing | checks_ready` (`ready()`), `failed` →
     `AnalysisFailed` error, unknown spellings → `Other` (forward-compat)
   - `410` → `Expired`; `404` → `NotFound`; `429` → `RateLimited`
4. `fetch_report(&res)` — `GET {base}/tests/{slug}` once `ready()`.

### 4.2 Slug secrecy (normative)

`slug` is a **capability secret** — bearer of it can poll/read the report.
- Type `TestSlug`: `Debug`/`Display` → `[redacted]`; `as_str()` is
  `pub(crate)`; `Serialize` exists only to cross the IPC boundary to the
  orchestrating caller — never persist to DB/audit/logs.
- Slug travels in the URL path → transport errors drop the URL (invariant 3).
- Slug is percent-encoded into the path segment (`encode_param`).

### 4.3 Report model

```text
DeliverabilityReport {
  score_ours_milli:   Option<u64>,   // 0–100 ×1000; null→None (incomplete)
  score_compat_milli: Option<u64>,   // classic 0–10 ×1000
  complete: bool,                    // false ⇒ score is optimistic
  report_url: Option<String>,        // human page — show this, not JSON
  subscores: BTreeMap<String,u64>,   // wire `subscores`/`scores` (milli) —
                                     // today: auth, infra_spam, content,
                                     // compliance; unknown keys preserved
  tallies: BTreeMap<String, CategoryTally>,  // derived from checks[]
  checks: Vec<CheckEvidence>,        // ≤512; per-check evidence
}
CheckEvidence { id, category_raw, status, title, summary, citations[] }
CitedSource { kind /* standards|receiver|… */, title, url }
```

- `tallies` is **computed**, never trusted from wire — keyed by lowercased
  raw category; `CheckCategory::parse` buckets
  `auth|infra_spam|content|compliance` (+`Other`). New categories/statuses
  land in `Other` buckets — parse never fails on new data.
- `auth_failures()` = `category==auth && status==fail` — the recommended
  hard gate (content can score while DKIM signs the wrong domain).
- `check.status`: `pass|warn|fail|skip` (`skip` = N/A, neutral).
- Citations flatten `citations.<kind>[]` preserving `kind`; RFC/receiver
  links are evidence for humans — UI should link them, never fetch them.

### 4.4 Privacy/flow notes

- The test message itself transits the provider's server — that's the
  service's purpose; **user must opt in per-run** (consent surface is the
  caller's job; the crate never initiates sends).
- Reservation address domain is provider-assigned — never hardcode it.
- Address is single-use: one message, then closed. Re-send needs a new
  reservation.

## 5. Error taxonomy (`IntegrationError`)

| Variant | Meaning | Carries |
|---|---|---|
| `Transport{kind}` | connect/timeout/decode/other | kind only — **no URL** |
| `Http{status}` | unmapped non-2xx | status |
| `RateLimited{retry_after_ms}` | 429 | server hint ≤1h |
| `Expired` | 410 | — |
| `NotFound` | 404 | — |
| `AnalysisFailed` | `analysis_status=failed` | — |
| `Malformed(&'static str)` | schema violation | field *name* only |
| `BodyTooLarge` | cap exceeded | — |
| `InsecureUrl` | non-https refused | — |
| `NoSession` | op needs live session | — |
| `ProviderRejected(&'static str)` | in-band error payload | static tag only |

## 6. Test posture

- **No live calls anywhere in the test suite.** `ScriptedHttp` replays
  recorded exchanges (fixtures under `kiwi-integrations/tests/fixtures/`,
  synthetic data only — SECURITY.md §4) and asserts request shape.
- Live path exists (`::live()` constructors) but is exercised only by
  explicit future e2e runs behind an env gate, never CI.
- `cargo test -p kiwi-integrations` → 30 tests (26 unit + 4 integration
  flows): cookie rotation, seq cursor, entity decoding, CRLF-injection
  stripping, RFC822 synthesis, session lifecycle, status mapping
  (202/404/410/429/failed), milli-score parse, tallies derivation,
  `auth_failures`, slug redaction, non-HTTPS refusal, error taxonomy.

## 7. Non-goals

- No `del_email`/`get_email_list`/`SUBSCR` subscription handling (unused;
  add deliberately if needed — SUBSCR would introduce a persistence-shaped
  cookie, which this crate deliberately has none of).
- No polling loops, retries, or sleeps inside the crate.
- No rendering — `raw_rfc822` feeds the existing sanitized path only.
