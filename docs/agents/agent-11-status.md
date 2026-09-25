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
