# Agent 11 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-226: `kiwi-integrations` crate (TempMailProvider + DeliverabilityTester)

**Status:** implemented + verified. New workspace crate `kiwi-integrations`
with two provider traits over one async HTTP seam.
`cargo test -p kiwi-integrations` → **30/30 pass** (26 unit + 4 recorded-
fixture integration flows), `cargo clippy -p kiwi-integrations --all-targets
-- -D warnings` clean, `cargo fmt -p kiwi-integrations --check` clean,
`unsafe_code = "forbid"` (workspace lints + `#![forbid]` on lib.rs).
Contract: `docs/contracts/integrations.md` (`kiwi.integrations/1`, draft).
ADR-010 filed in DECISIONS.md (ADR-009 was already taken by the infra
decision rule — this *is* the justification entry that rule requires,
numbered next in sequence, flagged for Lead). **No commit** — Lead
integrates.

### Layout

- `src/lib.rs` — crate docs, module map, standing rules.
- `src/error.rs` — `IntegrationError` (PartialEq) + `TransportKind`
  {Connect, Timeout, Decode, Other}. Error strings carry no URLs —
  transport-error text is dropped because it embeds the request URL, which
  for email-spam-tester contains the capability secret.
- `src/http.rs` — `HttpClient` async seam, `HttpRequest/HttpResponse`,
  `ReqwestClient` (reqwest 0.13 `rustls` feature, redirect=none, 30 s
  timeout, streaming body cap default 1 MiB + `with_body_cap`), header
  CTL validation, `encode_param`/`check_https_base` helpers, and
  `ScriptedHttp`+`Step` — the ordered recorded transport that asserts
  method/URL-fragments/headers/body before answering a fixture.
- `src/tempmail.rs` — `TempMailProvider` trait + `TempAddress`,
  `TempMessageSummary`, `InboxPoll`, `TempMessage`, `ExtendOutcome`,
  `PUBLIC_INBOX_NOTICE` (mandatory UI disclosure constant) + bounds.
- `src/tempmail/guerrilla.rs` — `GuerrillaMail`: PHPSESSID rotation tracking,
  `sid_token` echo, `f=` query building, `seq` cursor, HTML-entity decode,
  local-part validation, RFC822 synthesis w/ CTL-stripped headers +
  `X-Kiwi-Temp-Provider` provenance marker. Constants `ip=127.0.0.1`,
  `agent=KIWI/<ver>` — user's real IP/UA never sent.
- `src/deliverability.rs` — `DeliverabilityTester` trait + `TestReservation`,
  `TestSlug` (Debug/Display `[redacted]`), `TestStatus`/`AnalysisStatus`,
  `CheckStatus`, `CheckCategory`, `CheckEvidence`, `CitedSource`,
  `CategoryTally`, `DeliverabilityReport` (milli-unit scores — no floats).
- `src/deliverability/spamtester.rs` — `EmailSpamTester`: `POST /inbox`
  reserve, `GET /tests/{slug}/status` (202→Pending, failed→Err, unknown
  statuses forward-compatible), `GET /tests/{slug}` report parse
  (`score_ours`/`score_compat` → milli, `subscores` map, deterministic
  per-category `tallies` computed from `checks[]`, `auth_failures()` gate).
- `tests/integration_flow.rs` + `tests/fixtures/{guerrilla,spamtester}/*.json`
  — full lifecycles via `dyn` trait objects over recorded fixtures
  (cookie rotation mid-session, seq advancement, secret redaction, HTTPS
  refusal, sanitized transport errors). Fixture data is synthetic.

### Key security decisions (contract §1)

- HTTPS-only twice: constructor rejects non-`https://` bases AND
  `ReqwestClient` re-checks per request. Redirects never followed.
- No persistence: session = `Mutex<Session>` in memory; nothing to disk /
  keystore / SQLite.
- Slug = capability secret: redacting newtype, `as_str()` is `pub(crate)`,
  Serialize kept only for IPC hand-off (documented never-log/never-DB).
- `fetch_email` synthesizes RFC822 — GM has no raw-source endpoint and
  pre-filters bodies; documented loudly, output feeds the existing
  sanitized render path only.
- `check_email` echoes resync `s.address` (server is authoritative on
  session rebound). `forget_me` keeps PHPSESSID (session persists
  server-side per API), clears local address state.
- Deterministic: no clock/RNG/floats in the crate; polling loops are the
  caller's job (single-shot calls only).

### Files changed

`kiwi-integrations/{Cargo.toml, src/{lib,error,http,tempmail,
tempmail/guerrilla,deliverability,deliverability/spamtester}.rs,
tests/{integration_flow.rs, fixtures/guerrilla/{get_email_address,
check_email,fetch_email,extend}.json, fixtures/spamtester/{reserve,
status_ready,report}.json}}` (new), `Cargo.toml` (workspace member),
`docs/contracts/integrations.md` (new), `docs/DECISIONS.md` (+ADR-010),
this file.

### Commands run

```
cargo test -p kiwi-integrations                                 → 30/30
cargo clippy -p kiwi-integrations --all-targets -- -D warnings  → clean
cargo fmt -p kiwi-integrations --check                          → clean
```

### New dependencies (SECURITY.md §4 justification)

`reqwest 0.13` (`default-features = false`, `features = ["rustls"]` — the
0.13-era name; pulls `hyper-rustls` + `rustls-platform-verifier` → OS trust
store with webpki-roots fallback, matching the "platform security APIs"
rule; AWS-LC backend via `__rustls-aws-lc-rs`). First HTTP client in the
workspace — resolved to lockfile-pinned 0.13.5 (same tree as tauri).
Justification: external APIs are the crate's entire purpose; ADR-010.
`cargo audit` re-run belongs to Agent 6's dep-change gate. No other new
deps — everything else is existing workspace deps (serde/serde_json/
thiserror/tokio/async-trait).

### Assumptions / gaps / risks

- **API shapes are doc-verified, not wire-verified** — tests replay
  documented/recorded response shapes; first real call may surface schema
  drift (that's what the `Malformed`/`Other` forward-compat posture is for).
  A gated live smoke (`KIWI_INTEGRATIONS_LIVE=1`, env-gated, never CI) is a
  reasonable follow-up for whoever wires the IPC.
- `get_email_list`/`del_email`/`SUBSCR` cookie flows intentionally not
  implemented (unused by the task; SUBSCR is persistence-shaped and this
  crate deliberately persists nothing).
- Deliverability `poll`/`fetch` single-shot per contract; the IPC layer
  owns any wait-loop + backoff (429 `retry_after_ms` is surfaced).
- GM rate limits are unpublished → contract recommends ≥10 s poll spacing.
- EmailSpamTester `subscores` wire shape isn't in the public doc — parser
  accepts `subscores`/`scores` objects when present and always derives
  `tallies` from `checks[]` regardless (deterministic evidence stands on
  its own).
- Workspace `cargo clippy --workspace`/`test --workspace` not run —
  other agents' crates have in-flight state; my scope is
  `-p kiwi-integrations` (green).

### Addendum — dep-audit finding C1 (reqwest feature name)

`dep-vuln-1.md` C1 flagged `features = ["rustls-tls-webpki-roots"]` —
that name only existed in an intermediate draft; reqwest 0.13 dropped
the `rustls-tls-*` split in favor of a single `rustls` feature, and the
fix was applied during T-226 before the gates were run. Current state:

- `kiwi-integrations/Cargo.toml:15` — `reqwest = { version = "0.13",
  default-features = false, features = ["rustls"] }` (valid 0.13.5
  feature set).
- `cargo check -p kiwi-integrations` → **clean**.
- `cargo metadata --no-deps` (full-workspace resolution) → **clean**;
  the workspace is not red on this.
- Only one reqwest declaration exists workspace-wide.

## 2026-09-25 — T-227: wire `kiwi-integrations` into kiwi-app IPC

**Status:** implemented + verified. Nine `kiwi_integrations_*` commands
registered, all behind the lock gate (ipc.md §9e).
`cargo test -p kiwi-app` → **59/59 pass** (7 new integration tests),
`cargo clippy -p kiwi-app --all-targets -- -D warnings` clean,
`cargo fmt` clean (kiwi-app + kiwi-integrations + kiwi-mail).
ipc.md §9e written; typed wrappers in `src/ipc.ts` + views in
`src/kiwi.ts` for Agent 12. ADR-011 filed (consent-capability +
notice-on-every-response design). **No commit** — Lead integrates.

### Surface

- `tempmail_create(localPart?)` → `{address, addressCreatedUnix?,
  publicInboxNotice}` — one GuerrillaMail session in `AppState`
  (`Mutex<Option<GuerrillaMail>>`); localPart charset validated at the
  boundary (`invalid-input`, not a provider round-trip).
- `tempmail_poll` → `TempPollView` (seq cursor inside provider; the
  session lock is held across the await deliberately — serializes the
  mailbox, no other state locks taken inside).
- `tempmail_fetch(mailId)` → parses synthesized RFC822 via
  `kiwi_mail::mime::parse_message`, HTML through the shared
  `sanitize_html` allowlist with remote resources HARD OFF (public
  inbox ⇒ tracking surface; `remote_content_allowed` does not apply).
  Raw MIME never crosses IPC.
- `tempmail_discard` → local session cleared unconditionally;
  `remoteForgotten` reports `forget_me` outcome.
- `tempmail_extend` → `ExtendOutcome` view.
- `deliverability_begin` → `{testId, address, expires*, consentToken,
  consentNotice}`; slug stays backend-side (capability secret, in-memory).
- `deliverability_send(testId, consentToken, accountId, message)` —
  consent verified + consumed atomically under the sessions lock
  (`consent-required`, single code for missing/wrong/consumed — no
  oracle); recipients forced to the reserved address; rides the normal
  outbox (`send-queued` audited, undo-send applies).
- `deliverability_status`/`_report` → single-shot poll/report views;
  `sent` flag surfaces consent consumption; tallies + authFailureIds
  deterministic from `checks[]`.

### Files changed

`kiwi-app/src-tauri/Cargo.toml` (+`kiwi-integrations` dep),
`src/state.rs` (+`integrations_http` transport field, `tempmail`
session, `deliverability` map bounded at 32, `DeliverabilitySession`
with redacting Debug, `open_test_with_http` injection point),
`src/error.rs` (+`From<IntegrationError>`, +`MailError::InvalidInput`
arm — new variant landed mid-task by another agent), `src/types/
integrations.rs` (new), `src/types/mod.rs`, `src/commands/
integrations.rs` (new), `src/commands/mod.rs`, `src/lib.rs`
(registration), `docs/contracts/ipc.md` (§9e + §11 codes
`consent-required`/`rate-limited`/`integration-error`), `src/kiwi.ts`
(+views), `src/ipc.ts` (+wrappers), `docs/DECISIONS.md` (+ADR-011),
this file.

### Cross-agent repairs during this session (flag for owners)

- `kiwi-mail/src/store/queries.rs` — doc comment swallowed
  `fn map_message_row` signature (missing newline broke workspace
  compile); single-line fix applied so `-p kiwi-app` gates run.
- `kiwi-app/src/state/mailbox.ts` — `tsc` reports `MessageEnvelope`
  missing `category`/`unsub`: the fields were added to `kiwi.ts` by the
  T-202 work in flight; envelope builder not yet updated. NOT mine —
  left for the owning agent; my additions typecheck clean.

### Assumptions / gaps

- Poll loops belong to the UI (`status`/`check_email` are single-shot);
  GM spacing ≥10 s per integrations.md §3.5.
- Sessions die with the process (by design — nothing persists).
- Deliverability `report` before `ready` defers to the provider.
- Live smoke remains env-gated follow-up (T-226 status entry).

## 2026-09-25 — T-234: unsubscribe execution command (completes F3)

**Status:** implemented + verified.
`cargo test -p kiwi-app` → **86/86 pass** (7 new unsubscribe tests),
`cargo clippy -p kiwi-app --all-targets -- -D warnings` clean,
`cargo fmt --check` clean (kiwi-app + kiwi-mail + kiwi-integrations +
kiwi-autoconfig), `tsc --noEmit` clean. ipc.md §6b entry written; typed
wrapper + views in `src/ipc.ts` + `src/kiwi.ts`. **No commit** — Lead
integrates.

### Surface

- `kiwi_message_unsubscribe(accountId, folderId, uid, action, consent?)`
  → `UnsubscribeResultView{action, executed, httpStatus?, queueId?,
  undoWindowUntilUnix?}`. Lock-gated; folder ownership checked like
  every message action (`owned_folder`).
- `action="http"` — POSTs the STORED `unsub_http` URL through the shared
  `integrations_http` seam (HTTPS-only, no redirects, capped body).
  RFC 8058 offers send `List-Unsubscribe=One-Click` with
  `application/x-www-form-urlencoded`; plain offers send a bare POST.
  Consent: one-click runs on the click alone; non-one-click requires
  `consent:true`. Stored non-https URL → `invalid-input` before any
  socket. Response status surfaces as `httpStatus` (<400 = accepted;
  higher still counts as `executed` so the UI can tell "sent" from
  "probably ignored").
- `action="mailto"` — minimal `unsubscribe`/`unsubscribe` message to
  the stored `unsub_mailto` via `send_impl` (normal outbox: undo grace,
  `send-queued` audit). **Always** `consent:true` — the send exposes
  the user's own address.
- Consent failure → `consent-required`, touches nothing (no HTTP, no
  outbox, no audit). Executed actions audit `unsubscribe-http` /
  `unsubscribe-mailto` (message ref + status/queueId; no URLs).
- kiwi-mail gained `MailStore::unsubscribe_offer(folder_id, uid)` —
  single-row read of the T-202 columns.

### Files changed

`kiwi-mail/src/store/queries.rs` (+`unsubscribe_offer`),
`kiwi-mail/src/search.rs` (+`auth: None` in its `map_message_row` —
T-232 added `MessageMeta.auth` mid-task and missed this initializer),
`kiwi-autoconfig/src/net.rs` (`DiscoveryNet: Send + Sync` — required by
`AppState.autoconfig_net`; the missing bound took `Arc<AppState>`'s
Send/Sync and broke all ~90 commands), `kiwi-app/src-tauri/src/types/
message.rs` (+`UnsubscribeResultView`), `src/commands/message/
unsubscribe.rs` (new), `src/commands/message/mod.rs`, `src/commands/
mod.rs` (+`pub mod oauth2;` — file landed undeclared), `src/lib.rs`
(+`mod discovery_net;`, +`kiwi_message_unsubscribe` registration),
`docs/contracts/ipc.md` (§6b entry + `consent-required` row), `src/
kiwi.ts`, `src/ipc.ts`.

### Cross-agent repairs during this session (flag for owners)

- T-230 landed mid-task with undeclared modules + missing trait bound —
  applied the four minimal glue fixes above (two `mod` declarations,
  `Send + Sync`, `auth: None`) to unblock `-p kiwi-app` gates; owner
  then re-landed their own clippy fixes. Suite went red transiently on
  oauth2/autoconfig/rules tests while churning; green at 86/86 now.
- oauth2.rs test scripts assert `grant_type` as a URL fragment via
  ScriptedHttp `expect_query` — fixed by owner (device+loopback tests
  pass now).

### Assumptions / gaps

- Non-one-click http POST sends an empty body (RFC 2369 gives no
  defined body; the endpoint's own page/confirm flow owns semantics).
- Stored `unsub_mailto` is re-validated with `valid_addr` at execution
  (check-on-use; ingest already strips mailto params).
- `executed` means "request left the process", not "provider honored
  it" — `httpStatus` carries the endpoint's answer.
- No live smoke; ScriptedHttp asserts the RFC 8058 body + content-type.

## 2026-09-25 — T-242: integrations UI surfaces (own-vertical wiring)

**Status:** implemented + verified. `npm run build` (tsc + vite) green,
`tsc --noEmit` clean. CSP-strict: no remote assets, no remote anchors —
URLs render as `<code>` + Copy; temp-mail HTML mounts pre-sanitized
(remote stripped backend-side) via the same dangerouslySetInnerHTML
idiom as the reading pane.

### Surface

- `src/views/integrations.tsx` (new) — `IntegrationsView` rendered as the
  new **Preferences ▸ Integrations** tab (settings.tsx SECTIONS + render,
  same embed idiom as Mail Rules → FiltersView; `ms-tabs`/`ms-tab`,
  `ms-btn`, `kiwi-banner`, `kiwi-card`, `kiwi-pill`, `kiwi-evidence`,
  `ms-view-enter` throughout — Mailspring tokens only, no new CSS).
- **TempMail panel:** `PUBLIC_INBOX_NOTICE` (TS const mirroring the Rust
  constant verbatim, exported from kiwi.ts) shown BEFORE the Create
  control, then re-rendered from each response's `publicInboxNotice`.
  Create (optional localPart), address + Copy, manual "Check for mail"
  poll, click-to-fetch with sanitized-html expand, Extend, Discard
  (shows remoteForgotten). Sessions reconnect on remount via one poll
  (`not-found` → fresh state).
- **Deliverability panel:** Begin → testId + reserved address + expiry +
  consentNotice verbatim; consent checkbox ("single-use; backend refuses
  replay") + account select gate [Send test]; queueId shown; status via
  manual check + 15 s auto-poll while in flight; report renders score
  (milli→decimal), compat score, subscores + per-category tallies as
  pills, per-check list (status pill, title, summary, citations as
  copyable text), authFailureIds as a danger banner, reportUrl as
  copyable code — never a navigable link.
- **UnsubscribeChip (mailbox.tsx):** T-231's copy-only chip now executes
  `api.messageUnsubscribe` in live mode — oneClick POSTs directly (the
  click IS the RFC 8058 action), plain-https and mailto go through a
  labeled confirm step (`consent: true`; mailto copy states it sends
  from the user's address, undo window applies). Copy fallback kept;
  result/error states shown inline; demo mode degrades to copy-only.

### Files changed

`src/kiwi.ts` (+`PUBLIC_INBOX_NOTICE` const), `src/views/integrations.tsx`
(new, ~470 lines), `src/views/settings.tsx` (+Integrations tab),
`src/views/mailbox.tsx` (UnsubscribeChip execution wiring).

### Assumptions / gaps

- Temp-mail poll is manual-only (GM spacing ≥10 s per integrations.md
  §3.5 — an always-on interval on a public inbox adds noise without
  user benefit); deliverability status auto-polls 15 s only while a
  test is in flight.
- `TempPollView.address` is Option — reconnect fills it when present;
  absent → user sees the create surface (next create replaces the
  remote session anyway).
- consentToken lives in component state only — never rendered, never
  persisted; testId/address shown as evidence identifiers.
- Demo mode renders the surfaces disabled with a live-backend note.

---

## T-231 — LIVE-DATA WIRING (inherited from A12)

**Outcome:** the last demo fallbacks are gone — search hits a real FTS
IPC, contacts is IPC-only in live mode, category tabs confirmed on real
`MessageEnvelope.category` data.

### Backend — `kiwi_search_messages` (commands/mail.rs)

The frontend wrapper (`ipc.ts: searchMessages`) and `MailStore::search`
FTS existed, but no Tauri command bridged them — the IPC name 404'd.
Added `kiwi_search_messages(query, folderId?, limit?)`:

- Lock-gated; `query` bounded 512 chars, `folderId` ≥ 0, `limit`
  default 50 clamp 1–500 (`clamp_u32`).
- Delegates to `store.search` — the real grammar (terms,
  `subject:`/`from:`/`to:`/`body:`, `"phrases"`, `-negation`; ≤8 terms).
- `accountId` resolved server-side per hit via `folder_meta`, cached per
  unique folder — callers never guess ownership.
- New `SearchHitView` in types/mail.rs (camelCase wire shape matching
  `parseSearchHit`: accountId/folderId/uid/subject/fromAddr/snippet/
  dateUnix/hasAttachments).
- Registered in lib.rs; documented in ipc.md §6 with error codes.
- Tests: cross-account search resolves owners, folder scope narrows,
  scoped/negation grammar passes through, bounds enforced, empty store
  → empty. (2 new tests; suite 89/89 green.)

### Category tabs — client filter, documented (mailbox.tsx)

Tabs already filter the loaded list on real `MessageView.category`
(normalized via `normalizeCategory`; unknown → primary). **Choice
recorded in-code:** no `list_messages_by_category` IPC exists, so tab
scope is the loaded list — labeled on the tab tooltips and empty state.
A server-scoped variant slots in unchanged if ever exposed.

### Demo-fixture leaks sealed

- **contacts.tsx** — was: any `listContacts` failure silently loaded the
  seeded localStorage book (demo cards) into a live account; writes fell
  back to local with a "not in the backend yet" note. Now: `demo` →
  local book with no IPC; live → IPC-only, failures surface as error
  banners / notes. Import counts per-card failures honestly instead of
  diverting to localStorage. Footer/badge copy updated ("demo" label).
- **compose.tsx** — address-book autocomplete no longer falls back to
  the seeded book on IPC failure in live mode (empty autocomplete);
  demo mode owns the local book. Label updated.
- **mailbox.tsx** — "add sender to contacts" writes IPC-only in live
  mode (failure → note); demo writes the local book.
- **search.tsx** — stale "IPC pending" comments/copy updated; the
  labeled local fallback only mirrors grammar over already-loaded real
  envelopes, and only on IPC error — never fixtures.

Audited every `DEMO_*` reference in `state/` and `views/`: all are
`demo`-flag-gated. `state/mailbox.ts` live loader already surfaces IPC
errors via `messagesError` (no mock injection); `state/accounts.ts`
demo branches are guarded.

### Files changed

`src-tauri/src/commands/mail.rs` (+`kiwi_search_messages` + tests),
`src-tauri/src/types/mail.rs` (+`SearchHitView`), `src-tauri/src/lib.rs`
(registration), `src/views/contacts.tsx`, `src/views/compose.tsx`,
`src/views/mailbox.tsx`, `src/views/search.tsx`,
`docs/contracts/ipc.md` (§6 entry).

### Verified

`cargo test -p kiwi-app` 89/89; `npx tsc --noEmit` clean;
`npm run build` (tsc + vite) green; `cargo fmt` clean. CSP untouched —
no remote assets or navigation.

### Cross-agent flags (Lead)

- While working, `src/views/setup.tsx` (T-230) and `kiwi-mail/src/
  sync.rs`+`store/queries.rs` (T-233 EvalStage param, T-232 auth_risk
  field) churned mid-flight — transient red states; owners landed their
  own fixes. One minimal repair from me: `#[allow(clippy::too_many_
  arguments)]` on `rules::apply::apply_on_ingest` after T-233's new
  `stage` param pushed it to 7 args (matches existing allows on
  `execute` and sync.rs helpers — flagged for the T-233 owner).

---

## T-253 — §14 device-inventory endpoint (ADM-T250-08)

**Outcome:** `GET /api/v1/orgs/{orgId}/devices` implemented to the
ratified §14 contract — the endpoint 404'd before; now org-scoped,
bounded, audited-on-denial.

### Layers

- **Repo** (`db/interfaces.ts` + both impls): `listDevices(orgId,
  limit)` returns `{id, org_id, label, revoked, revoked_at, created_at}`
  — `revoked_at` read from the real column (never fabricated null),
  `created_at ASC, id ASC` ordering with the mandatory id tie-breaker,
  `limit` enforced in SQL (`DrizzleOrgRepository` sync +
  `PgOrgRepository` async, `bit()` on the PG boolean).
- **Service** (`policy/services.ts` `OrgService.listDevices`):
  `assertIdentifier` → `requirePermission(actor, "device.read", oid)`
  on the validated path org — fail-closed for null-org actors per
  §14.2. Denial writes the fixed §14.3 row (`device.list`, resource +
  org_id = path org, `outcome: "denied"`, `details.permission =
  "device.read"`, `request_id: null`, ms ts) via the new
  `ServiceContainerLike.auditAppend` — deliberately NOT `auditWrap`,
  which would also stamp successful reads (§14.3 forbids that).
  Successful reads stay unaudited, consistent with listUsers. The
  `revoked=1 ⇔ revoked_at≠null` invariant is checked per row —
  inconsistent legacy data → sanitized `500 internal`, never silently
  normalized.
- **Route** (`server.ts`): `GET` inside the orgs block,
  `numParam(url,"limit",50)` decimal grammar → service clamps 1..=500.
- **Contract**: admin-api.md §3 row updated (no longer "not
  implemented"); §14 header marked implemented-T-253.

### Tests (tests/server.test.ts + infra/e2e/test_admin_e2e.py)

- Wire shape: exact key set `{id, org_id, label, revoked,
  revoked_at, created_at}`, `revoked` as integer 0|1 (never boolean).
- Ordering: `created_at ASC`, same-millisecond rows tie-broken by id.
- Revoked row carries real `revoked_at`.
- Bounds: `limit=1` → 1 row, `limit=99999` → clamp 500, `limit=0` →
  clamp 1, `limit=1e3` → `400 validation.failed`.
- Cross-org → `403 auth.denied` + `details.permission`; null-org actor
  → 403; both denials asserted on the raw `audit_log` rows (the service
  query projection omits resource/org_id — ADM-T250-02).
- Unknown-but-valid orgId → `200 {items:[]}` (per §14.1 — a 404 for
  unknown orgs is a deferred contract decision, consistent with
  listUsers).
- Duplicate normalized labels ("Dup Phone" / "dup phone") returned
  unmerged — the 409 rule binds future create paths (§14.6), the read
  never canonicalizes.
- Malformed path id → `400 validation.failed`.
- e2e: `test_t253_device_inventory_route` in DialectLeg seeds via the
  existing backend device helpers, exercises wire shape / ordering /
  stray-org exclusion / bounds / both denials + audit rows / ghost org.

### Verified

`npm test` in kiwi-admin — 112 passed, 1 skipped (server.test.ts 24);
`tsc --noEmit` clean; `npm run build` clean; e2e file parses (runs under
docker compose when the stack is up).

### Note for Lead

The task brief listed "unknown-org not.found" — §14.1 ratifies
`200 {items:[]}` for an unknown-but-valid orgId (consistent with
listUsers; the 404 variant is a deferred contract decision per the same
section). Implemented spec-faithful; flagging in case Lead wants the
contract amended instead.

---

## T-259 — code-side admin-drift fixes (ADM-T250-01/02/03/04/05/06/07/12/13/15)

**Outcome:** every code-fix disposition in `docs/audits/admin-drift-1.md`
is implemented; contract-only items are flagged below for Lead.

### Implemented

- **ADM-01** — `listPolicies` now returns the ratified §5.1 snake_case
  `PolicyObject` (`{id, org_id, name, enabled, min_tls,
  external_recipients, domain_rules}`). New `PolicyObject` wire type in
  `policy/model.ts`; the internal camelCase `PolicyDefinition` stays the
  evaluator's model. Contract wins over code.
- **ADM-12/13** — `PolicyDecision.evaluatedPolicyId` renamed to
  `policyId` (canonical with the §10 outbound bridge, which already used
  `policyId`); producers in `evaluator.ts`/`services.ts` updated; the
  single-evaluate route passes it through verbatim.
- **ADM-14 (audit ADM-T250-13)** — unknown-org writes → `404 not.found`:
  `createUser`/`createPolicy`/`createDevice` check `getOrg` inside the
  audited work (a `not.found` is an `error`-outcome row, same convention
  as grantRole's missing-user 404). Path identifiers are also validated
  BEFORE `auditWrap` now (the grantRole pattern), so malformed ids never
  reach the permission check or the audit row.
- **ADM-04** — denial-only audit rows on EVERY read path:
  `user.list`, `domain.list`, `policy.list`, `mailflow.query`,
  `audit.query`, `audit.verify`, `audit.export` (global + org). Reads
  append directly via `ctx.auditAppend`/`this.append` — `append` never
  re-enters the permission check (no recursion; the §13.4 withdrawal is
  honored). Successful reads stay unaudited.
- **ADM-05** — `system-admin` platform role added (`types.ts` +
  `rbac.ts`): holds ONLY `audit.export`. `ALL_ORG_ROLES` admits it via
  the header scaffold; `GRANTABLE_ORG_ROLES` excludes it so `grantRole`
  can never write it into `user_org_roles` (which would fail the CHECK
  as a 500). The global export gates on role membership explicitly —
  `audit.export` at null target alone would still pass for org_admin.
- **ADM-06** — `export` appends an `audit.export` denial row before
  throwing (org_id null, `details.permission`); a failed append
  propagates as sanitized 500 with no body. Same for `exportOrg`
  (org-scoped row).
- **ADM-07** — `GET /api/v1/orgs/{orgId}/audit/export` implemented:
  `AuditService.exportOrg` (path-scoped `audit.export`, so
  `orgId == actor.orgId` by construction) + `buildOrgAuditExport` —
  `kiwi.audit-export-org/1`, header carries `scope:"org"` + `org_id`,
  trailer is `scope_state` with `chain_claim:"none"` (an org slice can
  never carry a whole-chain verdict), signature covers
  header+records+scope_state like the global artifact. Self-audit row
  has `org_id = {orgId}` per §13.4. Cap: `AUDIT_EXPORT_MAX_ROWS` +
  refuse-not-truncate.
- **ADM-02** — `GET /audit` returns the full `AuditRecord`
  (`org_id`/`resource`/`request_id`/`prev_hash`/`entry_hash` included;
  `actor_roles`/`details` stay JSON-encoded strings per §13.5).
- **ADM-03** — `verify` fetches limit+1: `complete` reports whether the
  checked window is the whole chain, and `valid` is never a full-chain
  verdict when `complete:false` (`{valid:false, complete:false}` =
  inconclusive, not corrupt — documented in §3).
- **ADM-15** — `createDevice` gate corrected: new `device.create`
  permission granted to org_admin + security_admin (the method stays
  service-only; POST /devices remains unimplemented per §14.5).
- **Contract** (`admin-api.md`): §3 rows updated for all of the above;
  §13.0 "non-conforming" note removed (conforming since T-259); §13.4
  rewritten to describe implemented denial auditing + the read-denial
  action names (`audit.query`/`audit.verify`/`*.list`/`mailflow.query`);
  new **§13.7** documents the org-scoped export format.

### Tests

`server.test.ts` +9 (T-259 describe): `policyId` canonical, PolicyObject
wire shape, ghost-org 404s, full audit record, verify `complete`, read-
denial audit row, org-scoped export (+cross-org/system-admin denials +
denial row), `system-admin` grant refused. `audit.export.test.ts` +4:
system-admin export, org_admin refused on global + denial row asserted,
org-scoped artifact/signature/self-audit/denial coverage.
`services.test.ts` updated to the §5.1 shape. e2e leg
`test_t259_admin_drift_fixes` in `DialectLeg` + the three global-export
calls repointed to `SYSTEM_ADMIN` headers (org_admin now correctly
refused globally).

### Verified

`npm test` — 126 passed, 1 skipped (was 113). `tsc --noEmit` clean;
`npm run build` clean; e2e file parses (docker-gated).

### Flags for Lead (contract-only decisions, not code)

- **ADM-T250-11**: mailflow `security_status`/`policy_verdict` silently
  coerce unknown values to `unknown` while `tls_version` is strict —
  needs a ruling (document asymmetry or make all `400`).
- **ADM-T250-14**: §4 says `audit_log.seq` is `PRIMARY KEY AUTOINCREMENT`
  but code deliberately assigns contiguous seqs in a transaction —
  contract-fix (describe the app-assigned invariant), NOT a code change
  (AUTOINCREMENT would conflict with the hash-chain contract).
- **ADM-T250-10 remainder**: §3 rows now document the shapes I touched;
  `{ok:true}` (revoke/grantRole), `{id}` creates, and the mailflow query
  envelope remain undocumented pending a wire-shape pass.
- Denial-row action names (`user.list`, `domain.list`, `policy.list`,
  `mailflow.query`, `audit.query`, `audit.verify`, `audit.export`) are a
  new convention — §13.4 documents them; ratify or amend.
- `system-admin` arrives only via the header scaffold (§12.2 DEV-AUTH) —
  never grantable into `user_org_roles` (CHECK would reject it).
