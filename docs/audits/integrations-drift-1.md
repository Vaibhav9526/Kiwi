# External Integrations Drift Audit 1 (T-278)

**Reviewer:** Agent 23 · **Date:** 2026-09-25 · **Snapshot:** `abf0c4f` plus the current shared worktree
**Mode:** read-only implementation audit. No source, contract, task-ledger, test, or findings-register file was changed. This report and `docs/agents/agent-23-status.md` are the only T-278 writes.

## Scope and verdict

This audit compares `docs/contracts/integrations.md` and IPC §9e with the complete `kiwi-integrations` crate, the nine registered Tauri commands, Rust IPC views, TypeScript wrappers/types, the Integrations UI, shared send/outbox behavior, and deterministic tests.

**Verdict: the documented command surface is implemented; the crate is not smaller than the contract implies.** All eight `TempMailProvider` trait methods (six provider-I/O operations plus `name`/`address`), all four `DeliverabilityTester` methods (three provider-I/O operations plus `name`), and all nine Tauri aggregate commands are present/registered. Rust/TypeScript camelCase wire shapes currently align. The material drift is in consent trust, secret representability, hostile response/link handling, lifecycle state, rate-limit semantics, audit ordering, and missing app/frontend verification.

No webhook registration, inbound callback, browser callback, loopback listener, or server-push endpoint exists in this domain. External state is obtained by outbound HTTPS plus caller-owned polling. `Set-Cookie` rotation is the only callback-like response behavior.

## Surface inventory

### `kiwi-integrations` provider operations

| Contract operation | Endpoint/method | Implementation | Result |
|---|---|---|---|
| `get_email_address` | GM `GET ...?f=get_email_address` | `tempmail/guerrilla.rs:192-210` | Implemented |
| `set_email_user` | GM `POST ...?f=set_email_user` | `tempmail/guerrilla.rs:212-228` | Implemented |
| `check_email` | GM `GET ...?f=check_email&seq=…` | `tempmail/guerrilla.rs:230-243` | Implemented |
| `fetch_email` | GM `GET ...?f=fetch_email&email_id=…` | `tempmail/guerrilla.rs:245-260` | Implemented |
| `forget_me` | GM `POST ...?f=forget_me` | `tempmail/guerrilla.rs:262-279` | Implemented with response-shape drift below |
| `extend` | GM `POST ...?f=extend` | `tempmail/guerrilla.rs:281-292` | Implemented with error-payload drift below |
| `reserve_inbox` | spam-tester `POST /inbox` | `deliverability/spamtester.rs:95-104` | Implemented |
| `poll_status` | spam-tester `GET /tests/{slug}/status` | `deliverability/spamtester.rs:106-130` | Implemented |
| `fetch_report` | spam-tester `GET /tests/{slug}` | `deliverability/spamtester.rs:132-140` | Implemented |

Trait declarations are at `tempmail.rs:112-147` and `deliverability.rs:294-318`.

### Tauri commands and frontend surface

| IPC §9e command | Rust registration/handler | TypeScript wrapper/type | Result |
|---|---|---|---|
| `kiwi_integrations_tempmail_create` | `lib.rs:157`; `commands/integrations.rs:61-122` | `ipc.ts:629-631`; `kiwi.ts:1092-1095` | Implemented, shape matches |
| `kiwi_integrations_tempmail_poll` | `lib.rs:158`; `commands/integrations.rs:124-147` | `ipc.ts:632-634`; `kiwi.ts:1107-1111` | Implemented, shape matches |
| `kiwi_integrations_tempmail_fetch` | `lib.rs:159`; `commands/integrations.rs:149-202` | `ipc.ts:635-639`; `kiwi.ts:1113-1124` | Implemented; link-policy finding below |
| `kiwi_integrations_tempmail_discard` | `lib.rs:160`; `commands/integrations.rs:204-238` | `ipc.ts:640-642`; `kiwi.ts:1126-1129` | Implemented |
| `kiwi_integrations_tempmail_extend` | `lib.rs:161`; `commands/integrations.rs:240-263` | `ipc.ts:643-645`; `kiwi.ts:1131-1135` | Implemented |
| `kiwi_integrations_deliverability_begin` | `lib.rs:162`; `commands/integrations.rs:287-346` | `ipc.ts:654-656`; `kiwi.ts:1137-1145` | Implemented; consent finding below |
| `kiwi_integrations_deliverability_send` | `lib.rs:163`; `commands/integrations.rs:360-437` | `ipc.ts:657-669`; `kiwi.ts:1147-1151` | Implemented; lifecycle findings below |
| `kiwi_integrations_deliverability_status` | `lib.rs:164`; `commands/integrations.rs:439-468` | `ipc.ts:670-672`; `kiwi.ts:1153-1161` | Implemented |
| `kiwi_integrations_deliverability_report` | `lib.rs:165`; `commands/integrations.rs:470-493` | `ipc.ts:673-675`; `kiwi.ts:1187-1198` | Implemented; auth/report findings below |

All nine wrappers call the common lock gate (`commands/integrations.rs:72,134,158,212,245,295,377,446,478`). The gate permits Trusted/Degraded/Unknown and rejects Locked; there are no per-provider roles or scopes.

## Security-invariant matrix

| Invariant | Current result | Evidence |
|---|---|---|
| HTTPS only; no redirects; streaming body cap | **Implemented for `ReqwestClient`; transport-seam qualification remains** | `http.rs:143-205,222-275`; custom `HttpClient` implementations are not constrained |
| No provider state persistence | **Implemented in app memory model** | `state.rs:215-239`; provider sessions are in-memory |
| No secrets in logs/audit | **Partial** | `TestSlug` and provider Debug redact, but several request/response/session types derive raw Debug; see INTG-02 |
| Public-inbox notice | **Implemented structurally on successful temp-mail responses and shown in current UI** | `types/integrations.rs:38-153`; `views/integrations.tsx:180-186` |
| Explicit per-run deliverability consent | **Divergent** | token possession is enforced; human consent is not trusted; see INTG-01 |
| Untrusted response validation | **Partial** | body/field caps exist; in-band errors, auth truncation, and numeric score bounds diverge |
| Deterministic crate core | **Implemented** | integer milli scores, no clock/RNG/sleep/retry in crate (`deliverability.rs:14-18`; `lib.rs`) |
| No fake success from provider errors | **Divergent** | several parsers ignore top-level in-band errors; see INTG-04 |
| Caller owns polling/retry | **Implemented in crate, divergently used by UI** | crate calls are single-shot; UI polls every 15 seconds without honoring errors |
| Raw MIME never crosses IPC | **Implemented** | temp mail is parsed/sanitized before `TempMessageView` (`commands/integrations.rs:149-202`) |
| Reserved recipient confinement | **Implemented** | send clears caller `to`, `cc`, and `bcc` (`commands/integrations.rs:422-426`) |
| Citation/report URLs are not fetched | **Implemented as copy-only UI** | `views/integrations.tsx:333-339,398-405` |

## Findings and proposed rulings

### INTG-01 — H — “Consent is non-bypassable” is stronger than the implementation

The backend mints and returns the consent capability from `deliverability_begin`, then accepts possession of that same capability in `deliverability_send` (`commands/integrations.rs:299-345,399-426`). The only human signal is a React checkbox (`views/integrations.tsx:470-480,536-566`). Under the repository's untrusted-renderer model, a compromised renderer can call `begin`, echo the returned token, and enqueue a third-party-bound message without a trusted user gesture.

**Evidence:** `integrations.md:186-193`; `DECISIONS.md:134-143`; `commands/integrations.rs:299-345,399-426`; `views/integrations.tsx:470-480,536-566`.

**Proposed ruling:** **code-fix.** Put the per-run confirmation outside renderer control, or stop calling the token consent. If Lead intends only replay/accident protection, amend ADR-011 and the contract to say “single-use capability gate,” not non-bypassable user consent.

### INTG-02 — M — Secret-bearing public types are not uniformly redacted or zeroized

`TempAddress` derives raw `Debug` and contains `sid_token` (`tempmail.rs:43-55`). `HttpRequest`/`HttpResponse` derive raw Debug and can expose cookies, slug-bearing URLs, bodies, and response data (`http.rs:49-60,102-109`). `DeliverabilityBeginView` derives Debug and contains the consent capability (`types/integrations.rs:159-179`). `TestSlug`/`TestReservation` are serializable, but the secret strings are not zeroized (`deliverability.rs:38-76`). No current caller was found logging these values, so this is a defense-in-depth/contract-invariant gap rather than an observed live leak.

**Proposed ruling:** **code-fix.** Use redacting Debug implementations, minimize serde derives, zeroize session/capability strings on drop, and add security tests for Debug, serde, audit, and IPC serialization.

### INTG-03 — M — `report_url` can contradict the slug-never-crosses-IPC rule

The provider report URL is forwarded unchanged (`deliverability/spamtester.rs:248-259`; `types/integrations.rs:222-224,356-370`) and shown with a Copy control (`views/integrations.tsx:398-405`). The recorded fixture places the same slug in both the reservation and report path (`tests/fixtures/spamtester/reserve.json:1-5`; `report.json:1-6`). Fixtures are synthetic, so bearer capability cannot be proven without a live contract check.

**Proposed ruling:** **contract-amend first.** Define whether `report_url` is intentionally public/shareable. If it is, explicitly exempt it from the “slug never crosses IPC” rule. If it is bearer-capable, **code-fix** by rejecting/redacting report URLs containing the slug.

### INTG-04 — M — In-band provider errors can become apparent success

The contract requires in-band errors to surface as `ProviderRejected`/`Malformed`, never success (`integrations.md:44-45`). `forget_me` accepts any body beginning with `{`; `extend` ignores an error field; GM poll ignores an error field (`tempmail/guerrilla.rs:262-291,317-363`). Spam-tester reservation/status/report parsers do not centrally reject a top-level error payload (`deliverability/spamtester.rs:95-140,147-259`).

**Proposed ruling:** **code-fix.** Parse a common provider-error envelope before every success parser and require the exact `forget_me` success shape. Add `{"error":...}` tests for every operation.

### INTG-05 — M — Authentication hard-gate semantics fail open on unknown/truncated checks

`auth_failures()` returns only auth checks with exact `CheckStatus::Fail` (`deliverability.rs:281-290`). An auth check with an unknown future status is omitted. Report parsing silently truncates `checks[]` at 512 while preserving provider `complete` (`deliverability/spamtester.rs:176-259`). The UI treats the returned IDs as the auth-gate set (`views/integrations.tsx:348-366`). A failure beyond the retained window or a new status can therefore disappear while the report appears complete.

**Proposed ruling:** **code-fix.** Unknown auth statuses and client-side truncation must produce an explicit unknown/incomplete/blocked state. Add auth-`Other` and over-cap tests.

### INTG-06 — M — Sanitized temp mail still permits external navigation

The shared sanitizer allows `<a href>` and `http`, `https`, and `mailto` schemes (`commands/message/render.rs:102-190`). Temp-mail HTML is mounted with `dangerouslySetInnerHTML` and no click interception (`views/integrations.tsx:275-286`). Remote resources are correctly stripped, but a public message can still navigate the app/webview when a link is activated.

**Proposed ruling:** **code-fix.** Make temp-mail anchors inert or route clicks through the approved link policy; add HTTP(S), `data:`, `javascript:`, event-handler, SVG, and form-payload tests.

### INTG-07 — M — `sent=true` can survive a failed enqueue

The send path consumes consent and sets `sent = true` before `send_impl` (`commands/integrations.rs:399-420`). Account lookup, MIME construction, persistence, enqueue, and audit can then fail. The IPC contract says `sent` reports whether consent was consumed (`ipc.md:1576-1582`), while the view says “consent consumed + send enqueued” (`types/integrations.rs:202-206`).

**Proposed ruling:** **code-fix.** Track `consent_consumed` and `enqueued` separately, or set `sent` only after enqueue. Add unknown-account, invalid-message, MIME, persistence, and audit-failure tests.

### INTG-08 — M — Normal SMTP retry can duplicate into a single-use provider address

The reservation is documented as accepting exactly one message (`integrations.md:136-140`; `deliverability.rs:304-306`). Deliverability uses the normal outbox (`commands/integrations.rs:422-436`), whose dispatch retries transient failures up to five times (`commands/send/dispatch.rs:23,111-168`). An ambiguous SMTP acceptance can therefore retry the same message to a single-use sink and distort/invalidate analysis.

**Proposed ruling:** **code-fix.** Use a no-ambiguous-retry dispatch class or reserve a fresh test after ambiguous failure. Only amend the single-use claim if the provider explicitly accepts duplicates.

### INTG-09 — M — Rate-limit hints are lost and polling amplifies failures

`retry_after_ms` is flattened into a human message rather than exposed as a stable field (`error.rs:193-199`). The UI polls every 15 seconds whenever `sent` is set and `ready` is false (`views/integrations.tsx:451-458`); errors and terminal provider states do not stop the interval, and a 30-second request may overlap the next timer. No backend cooldown or concurrency bound exists.

**Proposed ruling:** **code-fix.** Return a structured retry hint, stop on terminal errors, prevent overlap, and enforce provider/test cooldown. If the IPC must remain message-only, amend the contract and UI claim.

### INTG-10 — M — Temp-mail create/replacement can orphan remote public mailboxes

A new provider gets a remote address before state replacement (`commands/integrations.rs:98-115`). If `set_email_user` fails, the new remote mailbox is dropped without `forget_me`. Replacing an existing session also drops the old provider without remote cleanup. The public address can remain readable until expiry.

**Proposed ruling:** **code-fix.** Best-effort `forget_me` on failed creation and explicitly retire the old remote session before replacement, with deterministic cleanup tests.

### INTG-11 — M — Audit writes occur after irreversible external/state effects

Temp-mail create replaces state after provider allocation and then audits (`commands/integrations.rs:98-120`). Deliverability begin reserves externally, stores state, then audits (`commands/integrations.rs:315-345`). Send consumes consent/enqueues, then audits (`commands/integrations.rs:399-431`). `AuditLog::record` can fail after the effect (`audit.rs:72-96`).

**Proposed ruling:** **code-fix.** Pre-write/audit-intent before irreversible effects or define a transaction/compensation strategy. If post-commit errors are intentional, amend the contract with exact partial-success semantics; evidence must never be silently omitted.

### INTG-12 — M — Offline isolation and live constructors are convention-only

The contract requires no live network calls in tests and describes an env-gated live path (`integrations.md:211-223`). Public `GuerrillaMail::live` and `EmailSpamTester::live` directly construct `ReqwestClient` with no environment gate (`tempmail/guerrilla.rs:98-102`; `deliverability/spamtester.rs:62-66`). Default app test state also installs a real transport (`state.rs:613-618`). Current tests avoid live calls by convention, not an infrastructure fail-closed rule.

**Proposed ruling:** **code-fix.** Make test transports reject external network by default and require an explicit non-CI opt-in for any live canary. Add local loopback TLS tests for redirect, body-cap, timeout, and error-redaction behavior.

### INTG-13 — M — Frontend consent, notice, polling, and rendering have no automated gate

No frontend test files or test runner exist under `kiwi-app`; `package.json:6-11` has no test/lint/typecheck scripts, and CI has no `kiwi-app` frontend job (`.github/workflows/ci.yml:43-72`). The Integrations UI contains the public notice, consent checkbox, 15-second polling, clipboard/report behavior, and HTML rendering, but none is behaviorally tested.

**Proposed ruling:** **code-fix.** Add component/parser tests and a frontend CI gate before treating T-242 as fully verified.

### INTG-14 — L — Frontend trusts compile-time IPC types without runtime validation

Rust views and TypeScript interfaces currently align on camelCase/nullability (`types/integrations.rs:38-372`; `kiwi.ts:1075-1198`). The generic frontend `call<T>` trusts `T` and performs no runtime shape validation (`ipc.ts:111-118,621-675`). A backend/provider drift can therefore become `undefined` fields or unhandled UI states.

**Proposed ruling:** **code-fix.** Prefer generated/shared schemas or explicit runtime decoders and exact Rust serialization golden tests for all nine response shapes.

### INTG-15 — L — IPC/secret/notice wording is internally contradictory

IPC §9e says no consent token ever appears in an IPC payload (`ipc.md:1493-1500`) but returns `consentToken` from `deliverability_begin` (`ipc.md:1558-1563`). “Every response” carries `publicInboxNotice` (`ipc.md:1502-1508`), while error envelopes carry only code/message and successful views are the only notice-bearing shapes. The app uses one shared 6 MiB HTTP cap for all integrations (`state.rs:911-921`), broader than the crate default.

**Proposed ruling:** **contract-amend.** Distinguish the intentional consent capability from provider session secrets and say “every successful temp-mail response.” Define whether the app-wide 6 MiB cap is normative for this family.

### INTG-16 — L — Error/status comments and reachable states drift

`IntegrationError::RateLimited` says 429 or explicit `Retry-After`, but both providers create it only for HTTP 429 (`error.rs:37-39`; `tempmail/guerrilla.rs:147-155`; `deliverability/spamtester.rs:73-85`). Redirects are described under transport errors but surface as `Http { status }`. `AnalysisStatus::Failed` is a public success variant (`deliverability.rs:78-127`) but the provider converts it to an error (`spamtester.rs:117-124`); the TypeScript comment still includes `failed` as a status (`kiwi.ts:1153-1157`).

**Proposed ruling:** **contract-amend plus narrow code cleanup.** Align comments/types with actual reachable outcomes; do not fabricate an error-carrying status view.

### INTG-17 — L — “Real IP is never sent” is too broad

GuerrillaMail places the constant `127.0.0.1` in the API query (`tempmail/guerrilla.rs:22-25,43-44,117-131`). The remote provider and network path still observe the connection's source IP. The accurate guarantee is that KIWI does not place the user's real IP/user-agent in the API's `ip`/`agent` parameters.

**Proposed ruling:** **contract-amend** the privacy claim.

### INTG-18 — L — Transport guarantees do not apply to every public `HttpClient`

The constructor and `ReqwestClient` enforce a literal HTTPS prefix, no redirects, timeout, and streaming cap (`http.rs:143-275`). The public trait permits arbitrary injected transports (`http.rs:152-158`), which may not implement those controls. Production app endpoints are hardcoded, so no current renderer-controlled SSRF was found.

**Proposed ruling:** **contract-amend.** Scope the guarantees to `ReqwestClient`/trusted production wiring, or seal the transport behind a security-enforcing abstraction. Optional hardening: parse URLs and allowlist production hosts.

### INTG-19 — L — Scripted request assertions are weaker than the contract wording

`ScriptedHttp` uses URL substring matching and optional method/header/body matchers (`http.rs:296-315`). App test setup discards the `ScriptedHttp` handle and does not assert exhaustion (`commands/integrations.rs:507-517`). Omitted provider calls can leave unused steps without failing the app tests.

**Proposed ruling:** **code-fix in test infrastructure.** Retain handles, assert exhaustion, and use exact URL/query/header/body expectations where normative.

## External-service and webhook disposition

- **GuerrillaMail:** real external public inbox; receives cookie/session token, query values, and message metadata/body. HTTPS/no redirects/body cap are implemented for the production transport. The public-notice gate is UI-side.
- **email-spam-tester:** real external reservation/report service; receives the real test message through the user's relay and returns a slug, status, and report. Per-run consent is disputed/drifted as above.
- **Configured mail relay:** the integrations crate does not send directly. The app injects the message into the normal outbox, which introduces the retry/single-use mismatch.
- **Report/citation URLs:** not fetched by Rust and copy-only in the current UI; URL validation/capability classification remains incomplete.
- **Webhooks/callbacks:** none. No inbound endpoint, signature verification, redirect callback, browser deep link, SSE, or push status channel exists in this crate/app surface.
- **Temp-mail links:** sanitized remote resources are removed, but clickable anchors remain a navigation trust boundary.

## Existing finding disposition

- The old broad `INT` row (`FINDINGS.md:181`) is stale: the contract, crate, nine registered commands, wrappers, UI, consent token, and Agent 11 evidence now exist. Supersede the “contract absent/no consumer” wording with T-278's narrower findings.
- Keep `INT-6` fixed: the contract index includes `integrations.md`.
- T-227 remains stale/open in `docs/TASKS.md`, while Agent 11 reports implementation and tests. That metadata conflict is not itself a security finding.
- API fixtures are documented/synthetic, not wire-captured (`agent-11-status.md:101-107`); this audit does not claim live provider-schema verification.

## Verification

- `cargo test -p kiwi-integrations` — **30 passed, 0 failed** (26 unit + 4 recorded-fixture integration flows).
- `cargo clippy -p kiwi-integrations --all-targets -- -D warnings` — passed.
- `cargo fmt -p kiwi-integrations -- --check` — passed.
- Tests use `ScriptedHttp`/synthetic fixtures and made no live provider calls during T-278.

## T-278 conclusion

The integrations domain is substantially implemented end to end: no documented trait method or registered Tauri command is missing, and the Rust/TypeScript wire shapes currently match. The release-relevant work is not a larger command catalog; it is to make consent and disclosure claims match the untrusted-renderer reality, close secret/error/link/auth/lifecycle gaps, pin audit ordering, and add app/frontend/transport regression gates.
