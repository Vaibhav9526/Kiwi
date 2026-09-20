# Agent 5 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-19 — T-111 standalone UI spec v2 complete; T-112 blocked on T-110

- **Status:** T-111 done (in-review). T-112 blocked: `kiwi-app/` does not exist
  yet (verified — no dir), T-110 Tauri shell still in-progress with Lead.
  No `src-tauri/` work started; will scaffold frontend the moment T-110 lands.
- **Files changed (rewrote 2):**
  - `docs/ui-spec.md` — full v2 rewrite for the standalone client: app shell +
    three-pane mailbox, folder tree, unified inbox, message list, reader,
    composer (policy banner, templates, send-later, undo-send), snooze,
    4-step setup wizard (manual host/port/security-mode, plaintext
    explicit-consent, inline TLS summary, cert accept-once logging),
    Settings sections, all v1 security surfaces S-01…S-12 re-anchored to our
    frontend, brand/theme-token section (sampled palette: near-white/black,
    amber `#e0b030`-family, red-orange `#d05030`-family, greys — approximate,
    final hexes from SVG at T-112), global rules, checklist, open questions.
  - `docs/contracts/ui-surfaces.md` — v2: IDs `KIWI-UI-001`…`012` kept stable
    (anchors updated, 008 source changed to `kiwi-mail::transport`
    TlsObservation); new `KIWI-UI-013`…`023` app surfaces; payload requests
    incl. mail-view IPC needs for T-110; UI guarantees + wiring order.
- **Commands run (read-only):** workspace listing (confirmed `kiwi-app/` absent;
  `kiwi-mail/`, `kiwi-core/`, `kiwi-forensics/`, `kiwi-admin/`, `tests/`,
  `artifacts/` present); PIL palette bucketing of `logo.png`/`black_bg.png`/
  `banner.png` (read-only; Pillow deprecation warning only, output valid).
- **Tests:** n/a (spec phase). Verification gates: checklist ui-spec §12;
  smoke harness still requested from Agent 6 (T-113/T-114).
- **Assumptions:** Tauri 2 + Vite + React + TS per ARCHITECTURE.md §6; IPC
  command names unknown until T-110 — spec names data needs, not commands;
  Agent 2/3/4 payload field names are requests, UI renders all-optional with
  `unknown`/stale fallback.
- **Risks:** (1) T-112 cannot start until Lead lands T-110 — idle risk if
  shell slips; mitigation: spec is IPC-agnostic so scaffolding can start from
  stub commands immediately on land. (2) No SVG dark-mark variant — still
  flagged, do NOT auto-trace. (3) Read receipts/tracking stay OUT pending
  owner sign-off — spec explicitly defers.
- **Next (T-112, on T-110 land):** Vite+React+TS scaffold in `kiwi-app/`,
  route structure, layout shell (013), theme tokens from `images/` palette,
  stub views bound to IPC stubs; never touch `src-tauri/` Rust (Lead owns).

## 2026-09-19 — T-005 Phase 0 deliverables complete (in-review)

- **Status:** T-005 spec work done; awaiting Lead review + T-007 source map
  before any Thunderbird wiring. No `source/` touched, `images/` read-only.
- **Files changed (created):**
  - `docs/ui-spec.md` — 12 surfaces (S-01…S-12: message pill, account chip,
    security panel, finding dialog, lock overlay, authenticator dialog,
    composer banner, cert viewer, re-scan/diff, event tab, admin UI rules,
    pairing dialog) with triggers/states/keyboard/a11y/theme; brand asset
    audit (§2); global behavior rules; mandatory a11y+workflow checklist (§4).
  - `docs/contracts/ui-surfaces.md` — stable surface IDs KIWI-UI-001…012,
    shared severity vocabulary, minimum payload field requests to Agent 2/3/4,
    UI guarantees, wiring order.
- **Commands run (read-only):** `Get-ChildItem images/` + `Get-FileHash`
  (sizes/hashes), .NET `System.Drawing` PNG dimensions, SVG header read
  (viewBox). No writes outside the two spec files + this log.
- **Tests:** n/a (spec-only phase; no code). Checklist §4 in ui-spec.md is the
  verification gate for future UI implementation; smoke harness requested
  from Agent 6 (T-015).
- **Assumptions:** standard Thunderbird extension points exist for header bar,
  Account Settings section, compose infobar, status bar (to confirm in T-007);
  `SecuritySession`/finding/policy payload names in ui-surfaces §3 are
  requests, not final — Agent 2/3/4 contracts may revise.
- **Risks:** (1) surface anchors may shift after T-007 source map — spec
  written anchor-agnostic where possible; (2) no SVG variant of `black_bg`
  mark exists — flagged in ui-spec §2, do not auto-trace; (3) composer
  send-blocking (S-07) and lock overlay (S-05) need Agent 2/4 semantics
  before implementation (queued as T-014).

## 2026-09-19 — T-112 scaffold done; T-004 verified; T-108/T-109 done (Lead review pending)

- **Status:** T-112 complete (vite build green). Agent 4 handoff absorbed:
  kiwi-admin verified (34/34 inherited green, typecheck clean, no secrets —
  T-004 completion attested), T-108 bridge + T-109 emitter implemented
  (46/46 green). `src-tauri/` untouched (Lead owns). `images/` read-only.
- **Files changed — kiwi-app/src (T-112, new unless noted):**
  - `theme.css` — light/dark tokens from `images/` palette, severity pills,
    banners, dialogs, focus rings, reduced-motion.
  - `kiwi.ts` — Severity/TrustState/Account/Message/Finding/Event types +
    label/glyph helpers (never color-only).
  - `ipc.ts` — typed `api` wrappers (`kiwi_ping/list_accounts/security_status`)
    with unknown-tolerant parsing + demo fallback outside the webview.
  - `router.ts` — dependency-free hash router + `useRoute`.
  - `mock.ts` — demo accounts/messages/findings/events (demo-badged only).
  - `components/chrome.tsx` — AppShell, TopBar (search/Ctrl+K, theme, TrustChip→002),
    Sidebar (folder tree 014, unified inbox 015, accounts, nav).
  - `components/security.tsx` — SecurityPill (001), PolicyBanner (007),
    FindingDialog (004), LockOverlay (005), AuthenticatorDialog (006).
  - `views/mailbox.tsx` (015/016/017+S-01), `views/compose.tsx`
    (018+021+022+007 demo policy), `views/setup.tsx` (019, 4-step + plaintext
    consent + verify), `views/settings.tsx` (023+003 stub+022 CRUD),
    `views/security-center.tsx` (010, filters + JSON export).
  - `App.tsx` (rewrote Lead stub — kept `kiwi_ping` probe, added trust/accounts
    probe, theme, Ctrl+K, dialog orchestration, demo auto-approve labeled),
    `main.tsx` + `index.html` (theme import, title/meta).
- **Files changed — kiwi-admin (T-108/T-109):**
  - `src/db/interfaces.ts` + `src/db/sqlite-org.ts` — `listPoliciesForOrg`.
  - `src/policy/services.ts` — `evaluateOutboundForOrg` pure core +
    `PolicyService.evaluateOutbound` (validated, RBAC `policy.read`, audited).
  - `src/mailflow/emitter.ts` (new) — `buildSendAttemptEvents` /
    `buildReceivedEvent` pure builders, metadata-only, re-validated on ingest.
  - `tests/policy.bridge.test.ts` + `tests/mailflow.emitter.test.ts` (new, 12 tests).
  - `docs/contracts/admin-api.md` — v1.1: bridge endpoint row, §10 bridge
    contract, §11 emitter contract, test map (34→46). **Lead review pending**
    (per contract rule; DECISIONS.md untouched — Lead-owned).
- **Commands run:** `npm run typecheck` + `npm test` in kiwi-admin (clean,
  46/46); `npm run build` in kiwi-app (tsc strict + vite, 40 modules, green);
  rg secret-scan on kiwi-admin src+tests (only a rule-6 comment hit).
- **Tests:** kiwi-admin 46/46 (6 files); kiwi-app `npm run build` green
  (no test runner in scaffold — noted for Agent 6 T-113/T-115).
- **Assumptions:** bridge `overall=block` ⇒ send path holds (Agent 2 wires
  call + fail-closed on bridge unreachable); emitter queue-and-retry on
  ingest failure (Agent 2); no-policy org ⇒ allow+`no-policy-enabled` (matches
  evaluator semantics for disabled policies).
- **Risks / needs:** (1) admin-api v1.1 needs Lead review sign-off.
  (2) Frontend demo policy/banner logic is LOCAL stub — replaced by T-108
  bridge data when IPC lands. (3) kiwi-admin audit-log DB-level tamper guard
  still open (contract §7 known gap — Lead queue). (4) Agent 4 on resume acts
  as reviewer only until Lead re-clears (per handoff §8).
- **Next:** bind views to real kiwi-mail IPC as Agent 2 lands T-101…T-106;
  composer banner → bridge verdicts; Security views → forensics events.

## 2026-09-19 — v1.1 approved; tamper guard implemented; views deepened

- **Status:** Lead sign-off confirmed (admin-api header → v1.1 active).
  Approved tamper guard implemented + 2 extra gaps closed. T-112 views
  deepened with backend-independent interactivity. All suites green.
- **Files changed — kiwi-admin:**
  - `src/db/migrations.ts` — v2 `audit-append-only-guard` (BEFORE
    UPDATE/DELETE triggers on `audit_log`, `RAISE(ABORT)`); `ensureMigrated`
    now skips applied versions (fixes restart-against-existing-DB throw —
    second gap closed).
  - `src/mailflow/services.ts` — `AuditService.verify` requires contiguous
    `seq` in the verified window (gap detection even if hashes recomputed).
  - `tests/audit.guard.test.ts` (new, 4 tests) — UPDATE/DELETE rejected,
    triggers registered, seq-gap flagged, restart reopens same file with data
    intact and versions [1,2].
  - `docs/contracts/admin-api.md` — §7 rewritten (two-layer enforcement +
    honest residual risks: trigger-drop by file-write holder, tail truncation;
    mitigations: file ACLs, verify-on-startup, backups; multi-process lock
    still queued with Lead), test map 46→50.
- **Files changed — kiwi-app/src:**
  - `prefs.ts` (new) — localStorage UI prefs (never credentials/content).
  - `App.tsx` — theme persisted; messages stateful with star/read toggles.
  - `views/mailbox.tsx` — Star/Unstar + Mark read/unread (u) working; n/p
    message-stepping on the list.
  - `views/compose.tsx` — real attachment picker (25 MB total cap, per-file
    remove, overflow alert); undo-grace reads `kiwi.grace` pref.
  - `views/settings.tsx` — theme/grace/min-TLS/templates persist to prefs.
- **Commands run:** kiwi-admin `npm run typecheck` + `npm test` (50/50, 7 files);
  kiwi-app `npm run build` (tsc strict + vite, 41 modules, green).
- **Tests:** +4 guard tests (1 initial failure was my test-shape bug —
  fixed, no prod-code change). Chain unit tests untouched (in-memory model —
  triggers don't affect them, by design: DB tests cover the DB layer).
- **Assumptions/notes:** triggers live in the same trust domain as the file —
  documented, not oversold; `verify()` stays the detection layer. Settings +
  TopBar theme selects both write `kiwi.theme` (TopBar is authoritative live;
  Settings persists for next launch) — acceptable scaffold overlap, unify when
  settings IPC lands.
- **Next:** real IPC bindings as Agent 2/3 land (bridge verdicts → banner,
  forensics → Security views); vitest for frontend pure modules (router/ipc
  parsers) proposed for Agent 6 T-113/T-115 pass.

## 2026-09-20 — T-130 Drizzle foundation done (branch release/v0.1.0)

- **Status:** kiwi-admin DB layer migrated to Drizzle ORM. PG dialect primary
  (schema + Kit migrations), SQLite dialect for tests/local. All 50 prior
  tests pass UNCHANGED on the new stack (only the journal-table assertion,
  which tests new machinery, was touched) + 5 new migration tests.
  Typecheck clean, `drizzle-kit check` clean both dialects. No commits made.
- **ADR-009 justification (infrastructure decision rule):** Drizzle is REQUIRED
  by owner directive (ADR-006) — PG for service/org data is the prerequisite
  for Agent 6's T-131 compose + T-133 verification. Problem solved: hand-written
  SQL strings are untyped and dialect-locked; Drizzle gives typed schemas,
  generated versioned migrations, and one interface behind two dialects.
  Simpler alternative rejected: keeping raw SQL + hand-maintained PG port
  doubles every future schema change and has no migration journal. Security:
  query builder eliminates string-concatenated SQL (all values parameterized);
  no secrets in code/migrations (connection string is caller env only —
  verified by rg scan). Cost: +3 runtime deps (drizzle-orm, pg, better-sqlite3
  with working win64 prebuild — no compiler needed), ~1.5 s test suite.
  Testing: full suite on SQLite-Drizzle + artifact assertions + skip-guarded
  PG live test for compose.
- **Files changed — kiwi-admin (mine only; other agents' tree entries untouched):**
  - `src/db/schema.pg.ts` (new) — 9 tables, CHECKs, FK cascades, indexes,
    typed relations. Timestamps bigint (no 2038 overflow); TEXT+CHECK instead
    of native enums (new values must not need ALTER TYPE).
  - `src/db/schema.sqlite.ts` (new) — table-for-table mirror (0/1 integers).
  - `drizzle.config.ts` + `drizzle.sqlite.config.ts` (new); `drizzle/pg` +
    `drizzle/sqlite` (new) — Kit output: `0000` full schema, custom `0001`
    audit triggers (plpgsql `RAISE EXCEPTION` / sqlite `RAISE(ABORT)`).
  - `src/db/sqlite.ts` + `src/db/pg.ts` (new) — connections, Drizzle bindings,
    journal-tracked migrators (CJS driver via createRequire — tsconfig is
    NodeNext without interop; `openPg` requires caller-supplied string).
  - `src/db/repositories.ts` (new) — sync Drizzle repos, byte-identical return
    shapes to the retired raw-SQL layer. `repositories.pg.ts` (new) — async
    mirrors (`AsyncInterface`, new mapped type in `interfaces.ts`), PG
    booleans mapped to 0/1 at the boundary.
  - `src/services.ts` — container now opens SQLite-Drizzle + migrates;
    `db: Db` facade preserved (tests use it); `close()` closes the real handle.
  - Deleted: `driver.ts`, `migrations.ts` (custom runner superseded by Kit
    journal), `sqlite-org.ts`, `sqlite-mailflow.ts`. `tests/helpers/db.ts` —
    dropped unused `node:sqlite` helper.
  - `tests/db.migrations.test.ts` (new, 5 run + 1 skip) — fresh-file migrate
    (9 tables + triggers), idempotent re-migrate, FK pragma, PG/SQLite DDL
    artifact assertions, PG live round-trip incl. trigger rejection
    (skip-guarded on `DATABASE_URL`), compile-time repo conformance.
  - `tests/audit.guard.test.ts` — restart test now asserts the Drizzle journal
    (`__drizzle_migrations` ≥ 2) instead of the retired `schema_migrations`.
  - `package.json` — drizzle-orm/pg/better-sqlite3 + drizzle-kit/@types/pg;
    `db:generate`, `db:generate:sqlite`, `db:check*` scripts.
  - `README.md` + `src/db/README.md` — Drizzle layout/commands/packaging note
    (ship `drizzle/` with the service).
  - `docs/contracts/admin-api.md` → v1.2 (§4 Drizzle migrations, §8 PG path +
    async-unification follow-up flagged, §9 test map 50→55). **Lead review
    pending** (DECISIONS.md untouched — Lead-owned).
- **Commands run:** npm installs; `db:generate` ×2 + `--custom` ×2;
  `db:check` ×2 (clean); `typecheck` + `test` (55 pass + 1 PG-live skip, 8 files);
  rg secret-scan (only rule-reference comments).
- **Test notes:** 2 failures during the run, both my test-code bugs (journal
  column name; PRAGMA row shape under better-sqlite3) — fixed, no prod change.
  better-sqlite3 `Database` import via createRequire (no tsconfig change).
- **Boundaries:** did NOT touch `docker-compose.yml`/`.env.example`/`infra/`/
  `Dockerfile` (Agent 6 T-131 in progress in-tree), `src-tauri/`, `kiwi-mail*`,
  other agents' status files. PG `DATABASE_URL` wiring composes with T-131.
- **Needs:** (1) Lead review sign-off on admin-api v1.2. (2) Async service-layer
  unification for PG runtime (flagged in contract §8 — needs Lead). (3) Agent 6
  T-133 runs the PG live test once compose provides `DATABASE_URL`.
- **Next:** T-112 IPC bindings as Agent 2 lands mail IPC; frontend views
  otherwise complete for scaffold phase.

## 2026-09-20 — T-134 admin console done (branch release/v0.1.0)

- **Status:** v1.2 approval noted. Delivered: list endpoints + localhost HTTP
  scaffold transport in kiwi-admin, contract v1.3 (Lead review pending), and
  the `kiwi-admin-ui/` React+TS console. No commits made.
- **kiwi-admin additions (mine):**
  - `OrgService.listUsers` (RBAC `user.read`, roles joined) +
    `PolicyService.listPolicies` (RBAC `policy.read`, full definitions);
    `listUsers` added to `OrgRepository` + both Drizzle impls (sync + PG
    async mirror). +2 service tests (57 service-level green).
  - `src/server.ts` (new, stdlib-only `node:http`): full §3+§10 wire mapping,
    extra-contract `GET /healthz`, 127.0.0.1-only bind, 1 MiB body cap,
    boundary validation (policy snake_case wire shape, TLS aliases, role enum),
    uniform error shape (auth.denied 403 / validation.failed 400 / not.found
    404). DEV-AUTH WARNING throughout: `x-kiwi-*` header actors are local-dev
    scaffolding, replaced by kiwi-core sessions (Phase 3+); never non-loopback.
  - `tsconfig.build.json` + `build`/`serve` scripts (`dist/` gitignored);
    built artifact smoke-tested (`/healthz` → ok over real HTTP).
  - `tests/server.test.ts` (new, 7 tests): healthz, users/roles round-trip,
    policy CRUD + single + bridge evaluation, mailflow ingest/query, audit
    query/verify, 403 shape, 400/404 shapes. Full suite: **64 pass + 1 PG-live
    skip, 9 files**. Also answers Agent 6's T-133 expectation (admin /healthz
    + entrypoint now exist; the 2 principled skips can narrow to sandbox).
- **Contract v1.3 (pending):** list-endpoint rows, new §12 dev-transport note
  with the auth warning; test map updated. DECISIONS.md untouched (Lead-owned).
- **kiwi-admin-ui/ (new):** Vite+React+TS, dev server pinned to 127.0.0.1:1421.
  `api.ts` typed client exactly matching v1.3 (HttpAdminApi + ApiError codes);
  `mock.ts` demo adapter enforcing the §2 permission matrix so the header role
  switcher shows real allow/deny paths (bridge verdicts trivially derived,
  labeled DEMO). Hash router, brand token theme (light/dark), shell with
  live/demo badge + base-URL/org/role controls. Views: orgs (create + context —
  honestly notes no list endpoint), users/roles (invite, confirm grant, confirm
  device revoke by id), policies (list, create, §10 bridge evaluation tester),
  mailflow (filters, metadata-only table, send-attempt ingest), audit (table +
  verify panel). Every view: loading/error+retry/empty states; destructive
  actions confirm naming the target (S-11). `npm run build` green (36 modules).
- **Commands run:** kiwi-admin typecheck/test/build/serve-smoke; admin-ui
  install/build; rg secret scans on UI + server (zero hits); `npm ls` lockfile
  consistent (answers Agent 6's lock-regen flag — lock already regenerated
  under T-130 installs and verified).
- **Assumptions:** server `now` uses contract-correct Unix seconds; service-
  internal audit timestamps remain Date.now() ms (pre-existing inconsistency,
  left untouched — flagged follow-up). No org/device enumeration endpoints in
  v1.3 — UI states this openly; list endpoints are tracked follow-up.
- **Needs:** (1) Lead review on v1.3. (2) Real session auth to replace header
  actors (Phase 3+). (3) Async service unification for PG (prior flag stands).
- **Next:** T-112 IPC bindings when Agent 2 lands mail IPC.

## 2026-09-20 — T-143 frontend bound to kiwi.ipc/1 (branch release/v0.1.0)

- **Status:** all kiwi-app views now consume Agent 7's 27-command surface via
  typed wrappers; local stubs replaced wherever a command exists. `npm run
  build` green (tsc strict + vite, 42 modules). `src-tauri/` untouched.
  No commits made.
- **Foundation:**
  - `kiwi.ts` — backend view types (AppInfo, SecurityStatus, Account, Folder,
    Message, Body, Challenge, Device, Outbox, VerifyResult…) + total mappers
    (`toTrustState`, `trustTokenToSeverity`, `eventSeverityToSeverity`,
    `findingToInfo`, `eventToRow`, `unixToIso`). Renderer never crashes on
    missing fields — unknown/stale instead (fail-closed display).
  - `ipc.ts` — all 27 wrappers, camelCase args per contract. Error split:
    transport failure → `BackendUnavailableError` (labeled demo fallback);
    backend `{code, message}` → `IpcError` (`locked` included → lock UI,
    never demo-as-real).
- **Views wired:**
  - Mailbox: live folders/messages/body, per-account sync with new-count note,
    outbox pseudo-folder (cancel/flush + `kiwi://outbox` live refresh),
    account-trust pills (honest summary: per-message session attribution not
    yet exposed — no invented verdicts). Star/read stay local-only, labeled
    (no flag command in kiwi.ipc/1). HTML bodies intentionally not rendered
    (remote content stays blocked); attachment download noted missing.
  - Compose: account selector, real `kiwi_send_message` (b64 attachments,
    25 MB cap), receipt-driven undo countdown + `kiwi_cancel_send`, send-later
    via `sendAtUnix`, Ctrl+Enter. No client policy invention — server
    `policy-blocked`/`policy-unavailable` outcomes render as the S-07 banner.
  - Security: live events/findings, finding dialog via mapper, session-detail
    dialog (`kiwi_session_detail`), JSON report export. Demo keeps fixtures.
  - Settings: live accounts (test/remove + verify-step detail), devices
    (list/revoke), org binding set/clear (loopback only), endpoint-signal
    collection display, Lock-now. Prefs sections untouched.
  - Setup: incoming+outgoing `kiwi_verify_server` probes with step detail and
    recorded-observation note, then `kiwi_add_account`; secret sent once,
    cleared from state after Add; plaintext ack retained.
- **App orchestration:** probe (ping + appInfo + status + accounts + devices),
  15 s trust re-poll, per-scope message/body loading with locked-gate
  handling, real challenge flow (active device → `kiwi_request_challenge`
  unlock → dialog with challengeId + expiry → 3 s status poll → approve/
  expired; UI-never-signs noted in-dialog), demo auto-approve retained.
  Status bar shows contract version, session count, score, required action.
- **Commands run:** `npm run build` (green after 2 fix rounds: readonly-tuple,
  demo fixture shape drift — both frontend-side). rg secret scan: password
  only in setup state → single IPC send → cleared; no logs/storage.
- **Assumptions/limits:** backend trusted for shapes; per-message trust =
  account trust until session attribution lands; outbox in-memory (backend
  limitation, surfaced in-view); recovery/elevated-action unsupported-event
  untouched; `submitChallenge` wrapped but uncalled (no local signing, ever).
- **Needs:** (1) Agent 7 T-144 (bridge/emitter wiring affects send outcomes —
  UI already renders both codes). (2) Future commands for flags, attachment
  download, sanitized-HTML render (tracked gaps, stated in-view).
- **Next:** manual click-through against the Tauri shell once Agent 7's build
  is runnable here; a11y re-audit of the rewired views (Agent 6 T-113).

## 2026-09-20 — T-145 UI elevation pass (branch release/v0.1.0)

- **Status:** operate-mode surface only — zero function/route/data/IPC changes
  (same 42 modules, `npm run build` green). `src-tauri/` untouched.
  No commits made.
- **Direction executed:** deep-black flagship (`#0e0e12` base, layered
  `#15151c/#0a0a0e` surfaces, hairline `#2a2a35` borders — no flat gray);
  orange→pink gradient (`#EAA132→#E580CC`) rationed to wordmark, one primary
  action per surface (Compose nav, Send, Add-account), secure/lock accents,
  reader top-line, selected markers. Light theme kept + refined (warm paper,
  dark-amber focus), still user-selectable.
- **Type:** Inter-first stack, tight-tracked 650-weight headings, 1.55 body
  rhythm, uppercase micro section labels, gradient KIWI wordmark.
- **States everywhere:** buttons/inputs/rows/tree/nav share 120 ms
  hover/focus/selected motion; focus rings amber with soft halo; message rows
  lift on hover, amber inset bar when selected; inputs glow on focus;
  thin branded scrollbars; `::selection` tint.
- **Pills/badges:** secure (emerald + soft glow), warning (amber), danger
  (red + glow), unknown (muted), locked (gradient-border) — glyph + text
  always, never color-only. Banners gained accent left-bars.
- **Loading/empty:** shimmer skeleton rows (list) + skeleton text (reader),
  designed empty states (mailbox, outbox); static fallback under
  `prefers-reduced-motion`.
- **Lock overlay:** radial amber/pink glow, gradient-ring lock mark with halo,
  elevated blurred dialog.
- **Default theme now dark** (fresh installs land on the flagship; saved prefs
  respected; toggle unchanged in TopBar + Settings).
- **Evidence:** headless Edge screenshots, `artifacts/ui/` (gitignored):
  before `t145-before-{mail,compose,security}.png` (old dist, dark-forced);
  after `t145-after-{mail,compose,security,settings}.png` (dark default) +
  `t145-after-mail-light.png` (light verified via temporary default flip,
  reverted + rebuilt — final dist is dark-default, JS hash `xKtivQ8Q`).
  Reviewed after-shots: hierarchy, pills, gradient line, selected row, Send
  gradient all render; light theme clean.
- **Commands run:** `npm run build` ×3 (green; one interim build for the
  light check only); python http.server + Edge `--headless=new --screenshot`
  (task-provider ERROR lines in stderr are benign headless noise).
- **Assumptions/limits:** no bundled Inter file (stack falls back to system —
  shipping a font asset is a follow-up if the owner wants pixel-identical
  type); sidebar All-Inboxes unread-vs-total count labeling is pre-existing,
  left untouched per operate-mode rules.
- **Next:** owner visual review of the screenshots; any taste deltas go
  through another operate-mode pass (tokens/classes only).

## 2026-09-20 — T-151 T-146 gaps wired; compose + settings deepened (branch release/v0.1.0)

- **Status:** Agent 7's T-146 commands (`kiwi_update_message`,
  `kiwi_download_attachment`, `kiwi_render_body`, `kiwi_set_remote_content` —
  verified present in `commands/message.rs` + registered in `lib.rs`
  generate_handler, contract ipc.md §6b) are now wired through the whole
  frontend. Compose gained a plaintext formatting toolbar + per-account
  localStorage draft autosave (no draft command exists in kiwi.ipc/1 — local
  only, attachments excluded, labeled). Settings Privacy/Notifications/
  Advanced sections completed without inventing backend behavior.
  `npm run build` green (tsc strict + vite, 42 modules). `src-tauri/`
  untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `kiwi.ts` — new tolerant views: `MessagePatch`, `MessageUpdateView`,
    `AttachmentSavedView`, `RenderedBodyView`, `RemoteContentView`.
  - `ipc.ts` — 4 new wrappers (`updateMessage`, `downloadAttachment`,
    `renderBody`, `setRemoteContent`), camelCase args per contract; same
    transport/verdict error split.
  - `App.tsx` — `applyPatch` path: live flag/archive via
    `kiwi_update_message` (returned flags become the override source of
    truth; archive moves bump `mailboxRev` + reload folders; failures keep a
    local override + honest syncNote, reconciles on next sync); demo stays
    local-only. Rendered-body load chained after `getMessage` (render failure
    never hides plaintext); `setAllowRemote` re-renders after toggle;
    `saveAttachment` via `kiwi_download_attachment` with notes. New state:
    rendered/renderLoading/renderError, remoteContent map, attachNote/
    attachBusy, mailboxRev.
  - `views/mailbox.tsx` — new Archive button; `AttachmentList` (per-file
    save-path input defaulting to MIME filename + Save via backend, demo
    labeled needs-backend); `BodyPane` (sanitized `rendered.html` via
    dangerouslySetInnerHTML — never raw `htmlBody` — with blocked-count
    notice + allow/block toggle, plaintext toggle; honest fallbacks for
    text-only/demo/render-error). Reader footnote corrected (no more
    "no flag-mutation command").
  - `views/compose.tsx` — toolbar (Bold/Italic/Underline/Code/Quote/List,
    wraps textarea selection with markers; text-only send path unchanged);
    draft autosave `kiwi.draft.<accountId>` (recipients/subject/body/
    scheduled, 1 s debounce, restore on account switch, consumed on send,
    Discard button; quota-failure note).
  - `views/settings.tsx` — Privacy: per-account remote-content allow/block
    via `kiwi_set_remote_content` (pre-toggle state honestly labeled backend
    default since no getter command exists); Notifications: local-only
    `kiwi.notify`/`kiwi.poll` prefs; Advanced: contract label, draft count +
    Clear-all-drafts, backend-data boundary note. Placeholders gone.
- **Commands run:** `npm run build` in kiwi-app (green first try — tsc
  strict + vite, 42 modules, no new deps).
- **Assumptions/limits:** no `@tauri-apps/plugin-dialog` dep — save uses a
  typed path input (backend still bounds + refuses app-data-dir paths);
  dialog-plugin file picker is a follow-up. Remote-content pre-toggle state
  is unknowable without a render — labeled, not guessed. Drafts in
  localStorage are device-local plaintext (same trust as prefs; never
  credentials/attachments).
- **Needs:** (1) Agent 7 T-144 send-path (bridge/emitter) — UI already
  renders both policy codes. (2) Click-through vs the Tauri shell + a11y
  re-audit (Agent 6 T-113). (3) TASKS.md has no T-151 row — Lead to confirm
  numbering (worked per session brief).
- **Next:** T-142 send-queue UI polish if Agent 2 changes outbox shapes;
  otherwise idle until review feedback.

## 2026-09-20 — T-153 productivity layer done (branch release/v0.1.0)

- **Status:** Mailspring-style layer delivered: Ctrl+K command palette,
  full keyboard map with `?` help overlay, toast system for send/sync/
  policy events. Demo-mode fallbacks kept everywhere (backend-only actions
  no-op with an explanatory toast). `npm run build` green first try (tsc
  strict + vite, 42→45 modules). `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src (new):**
  - `components/toasts.tsx` — `Toast`/`ToastKind`/`ToastStack` (aria-live
    polite, error role=alert, glyph+text per kind, dismiss buttons).
  - `components/palette.tsx` — `CommandPalette` dialog (combobox input,
    ↑↓/Enter/Esc, per-row search including current TopBar query, "Search
    messages for …" row driving the query + mail route).
  - `components/shortcuts.tsx` — `ShortcutsHelp` dialog (static 11-row map,
    Esc/backdrop close).
- **Files changed — kiwi-app/src (edited):**
  - `theme.css` — `.kiwi-toasts`/`.kiwi-toast` (+kind accents reusing
    severity tokens) and `.kiwi-palette(-row)` styles for both themes.
  - `App.tsx` — `notify`/`dismissToast` (max 5, 6 s auto-dismiss); global
    keys: Ctrl+K toggles palette (replaces old focus-search), `/` focuses
    search, `?` opens help (all guarded off text fields); `paletteActions`
    memo (compose, search-focus, theme cycle with toast, security, settings,
    shortcuts, go-to per folder, sync/lock live with labeled demo no-ops);
    palette search routes to mail folder; toasts wired into doSync (incl.
    demo early-return), doFlushOutbox (ok/warn/error by outcome),
    doCancelSend, applyPatch archive/failure, saveAttachment, doLock,
    allow-remote untouched (in-view note stands); `ComposeView` gains
    `onNotify`.
  - `components/chrome.tsx` — TopBar: palette button (⌘ Commands) +
    shortcuts button (?), search placeholder now `(/)`.
  - `views/mailbox.tsx` — listbox keys: ArrowDown/j + ArrowUp/k + n/p move,
    s star, e archive, r reply→composer, u read/unread; aria-label updated.
  - `views/compose.tsx` — `onNotify` prop: queued/undo/policy-blocked/
    policy-unavailable/send-error toasts in both modes (demo labeled).
- **Commands run:** `npm run build` in kiwi-app (green first try, 45
  modules, no new deps).
- **Assumptions/limits:** palette go-to list grows with folder count —
  filter handles it; shortcuts `r` opens a blank composer (no quoted reply
  — no reply-context plumbing exists yet). Toasts are UI-local (no
  persistence, no backend).
- **Next:** owner click-through (palette focus/keys, toast timing); a11y
  re-audit with Agent 6 T-113.

## 2026-09-20 — T-155 send-path UI closure (branch release/v0.1.0)

- **Status:** All six items verified against ipc.md §6b/§7/§12. Backend
  surface is unchanged since T-151 (same 31 handlers in `lib.rs` — no new
  Agent 7 commands), so items 3–6 were already live and re-verified; the two
  real gaps (outbox countdown, toast Cancel action) are now closed.
  `npm run build` green first try (tsc strict + vite, 45 modules).
  `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `components/toasts.tsx` — `ToastAction { label, run }` + optional
    `Toast.action`; action renders as a primary button that runs then
    dismisses.
  - `App.tsx` — `notify` accepts `opts { action?, ttlMs? }` (default 6 s).
  - `views/compose.tsx` — `onNotify` gains the same opts; send fires an
    undo toast with a working **Undo send** action (ttl = grace window, both
    modes); `undo()` takes an explicit queue id (fixes a real stale-closure
    bug: the toast fires before `queueId` state commits, so the old path
    would have no-op'd); send-later validation added (invalid/past datetime
    rejected client-side with an error, before IPC).
  - `views/mailbox.tsx` — `OutboxList` now ticks (1 s, skipped under
    `prefers-reduced-motion`): per-row "Undo open — Ns left" on the button
    + status line, "Scheduled — sends <locale>" from `notBeforeUnix`,
    "Dispatching… (attempt N)" after the window; exact timestamps stay in
    `title` attributes.
- **Verified, no change needed:** (3) send-later picker → `sendAtUnix`
  (plus the new validation above); (4) Mark read/Star/Archive all go
  through `kiwi_update_message` — zero stub paths in live mode (remaining
  "local-only" strings are honest demo-mode labels); (5) reader Save via
  `kiwi_download_attachment`; (6) reader + Settings toggles via
  `kiwi_set_remote_content`, default off, audited server-side.
- **Commands run:** `npm run build` in kiwi-app (green first try, 45
  modules, no new deps).
- **Assumptions/limits:** outbox ticking re-renders one small subtree per
  second while the outbox folder is open — negligible. Toast action callbacks
  are UI-local closures (no persistence).
- **Next:** T-144 send-path review support if needed; otherwise idle until
  review feedback.

## 2026-09-20 — T-156 setup wizard + account management (branch release/v0.1.0)

- **Status:** All items delivered. No autoconfig IPC exists in the backend
  yet (verified: no `kiwi_lookup_autoconfig` in `src-tauri/`, no
  `docs/contracts/autoconfig.md` — Agent 8's T-135 crate
  `kiwi.autoconfig/1` exists with ISPDB/XML/MX/manual stages), so the
  resolver runs behind the permanent `api.lookupAutoconfig` wrapper with a
  labeled local stub until the IPC lands (zero view changes needed on land).
  `npm run build` green first try (tsc strict + vite, 45 modules).
  `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `kiwi.ts` — `AutoconfigSuggestion` (flat wizard shape, source incl.
    `local-guess`) + tolerant `parseAutoconfigSuggestion` (accepts flat and
    nested Rust `AccountSuggestion` shapes, both security vocabularies —
    `tls/starttls/plaintext` and `ImplicitTls/StartTls/Plaintext`).
  - `ipc.ts` — `lookupAutoconfig(email)` → `kiwi_lookup_autoconfig`
    (throws BackendUnavailableError until the backend lands).
  - `views/setup.tsx` — step 0 "Look up settings": IPC first, local stub on
    any failure (BackendUnavailable vs lookup-failed labeled differently),
    backend-null falls back too; applied fields invalidate prior probe
    results; source note shown. `localAutoconfigGuess`: gmail + outlook
    presets, generic `mail.<domain>` guess — always TLS/password, always
    labeled, verify remains source of truth. Step 1 preset buttons (SSL/TLS
    993-995/465, STARTTLS 143-110/587; ports+security only, hosts never
    overwritten). Reconfigure handoff (`kiwi.editAccount`, server fields
    only — never secrets): prefills, jumps to step 1, banner explains
    add-then-remove-old. Credential copy hardened (OS store; never DB/
    localStorage/logs). Plaintext ack gate + STARTTLS-required posture
    unchanged (fail-closed server-side).
  - `views/settings.tsx` — Accounts: default badge + Set/Clear default
    (`kiwi.defaultAccount` pref, cleared on remove), Reconfigure… (live
    only; stages handoff, routes to setup).
  - `views/compose.tsx` — From selector honors `kiwi.defaultAccount` when
    it matches a known account, else first account.
- **Commands run:** `npm run build` in kiwi-app (green first try, 45
  modules, no new deps).
- **Assumptions/limits:** no edit IPC in kiwi.ipc/1 — reconfigure is
  honestly add-then-remove-old, stated in both banners. Stub guesses must
  survive verify to be used. Default account is frontend-local (no backend
  default concept).
- **Next:** drop the stub the moment Agent 8's lookup IPC lands (wrapper +
  parser already match `kiwi.autoconfig/1` shapes); otherwise idle until
  review feedback.

## 2026-09-20 — T-160 search UI + lock screen (branch release/v0.1.0)

- **Status:** Both views delivered. No search IPC exists in the backend yet
  (verified: no `search` in `src-tauri/` — Agent 8's command pending), so
  search runs behind the permanent `api.searchMessages` wrapper with a
  labeled client-side fallback (zero view changes on land). Lock screen
  upgraded per ui-surfaces KIWI-UI-005. `npm run build` green first try
  (tsc strict + vite, 45→46 modules). `src-tauri/` untouched. No commits
  made.
- **Files changed — kiwi-app/src (new):**
  - `views/search.tsx` — `SearchView`: debounced (300 ms) server attempt,
    labeled fallback (`server` / `local demo fixtures` / `local — IPC
    pending, loaded messages only` + error banner when the server fails but
    local covers); `parseSearchQuery` (`from:`/`has:attachment`/`folder:`
    tokens + terms, honored by the fallback); chips rewrite the query
    (sender input, attachment toggle, folder input, clear-filters);
    case-insensitive `<mark>` `Highlight`; rows open the message in its
    folder (keyboard Enter included).
- **Files changed — kiwi-app/src (edited):**
  - `router.ts` — `search` route (`#/search`).
  - `kiwi.ts` — `SearchHit` + tolerant `parseSearchHit` (accepts
    `fromAddr`/`from` spellings; null when unusable).
  - `ipc.ts` — `searchMessages(query, limit?)` → `kiwi_search_messages`.
  - `App.tsx` — `visibleMessages` split into `baseMessages` (overrides, no
    query — feeds mailbox + search) with identical mailbox behavior;
    `#/search` render (hit → mail folder/messageId); palette "Search
    messages for …" now routes to the results view; TopBar gains
    `onSubmitSearch` (Enter → results).
  - `components/chrome.tsx` — search placeholder notes Enter-for-results.
  - `components/shortcuts.tsx` — help map gains the Enter-in-search row.
  - `components/security.tsx` — `LockOverlay` gains trust-reason lines
    (state/score/required-action), paired-device mobile-approve hint, QR
    **placeholder** box (explicitly labeled, real codes come with
    device-pairing), and challenge-id match line once Verify issues one.
  - App lock render passes all three (demo: Demo authenticator, no
    challenge id).
- **Commands run:** `npm run build` in kiwi-app (green first try, 46
  modules, no new deps).
- **Assumptions/limits:** fallback searches loaded messages only (current
  folder scope live, fixtures in demo) — stated in-view. QR box is a
  placeholder, not a code. Challenge flow itself unchanged (T-143).
- **Next:** drop the fallback the moment Agent 8's search IPC lands;
  otherwise idle until review feedback.

## 2026-09-20 — T-162 bulk actions + selection model (branch release/v0.1.0)

- **Status:** Selection model + action bar delivered. Backend reality
  checked first: kiwi.ipc/1 has flags/archive moves ONLY
  (`kiwi_update_message` seen/starred/archived — verified in
  `commands/message.rs`; no delete/spam/empty-trash command exists), so
  destructive actions are rendered disabled with the reason rather than
  faked. `npm run build` green first try (tsc strict + vite, 46 modules).
  `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `App.tsx` — `bulkPatch(ids, patch, label)`: sequential live pass over
    N (per-message verdict → overrides, one reload on moves, one summary
    toast + syncNote); demo applies seen/starred locally, archive honestly
    refused as demo-no-backend. Passed as `onBulkPatch`.
  - `views/mailbox.tsx` — selection (`picked` ids + range anchor, cleared
    on folder change / after moves): hover checkbox (real
    `<input type=checkbox>`, native checked semantics), Ctrl/Cmd-click
    toggle, Shift-click range, header select-all with indeterminate state;
    listbox `aria-multiselectable`, rows announce "Selected for bulk
    actions"; `BulkBar` toolbar (count, Mark read/unread, Archive,
    Move-to select limited to the backend's real targets Archive/Inbox,
    disabled Delete + Spam with titled reasons, Clear); header Mark-all-read
    with live unread count (direct — reversible, toast confirms count) and
    Empty-trash disabled with titled reason; focus returns to the folder
    heading when moves unmount the bar.
  - `theme.css` — `.kiwi-select-box` reveal (hover/focus-within/checked),
    `.kiwi-actionbar` styling for both themes.
  - `components/shortcuts.tsx` — help map gains the Ctrl/Shift-click row.
- **Commands run:** `npm run build` in kiwi-app (green first try, 46
  modules, no new deps).
- **Assumptions/limits:** move submenu is Archive/Inbox only (the backend's
  whole move vocabulary); cross-account moves in All-Inboxes apply per
  message's own account. Empty-trash has no confirm because it has no
  action — enabling it needs backend work, flagged below.
- **Needs (Agent 7, proposed):** `kiwi_delete_messages`
  (folder-scoped uids → Trash semantics + expunge?) to enable Delete /
  Spam / Empty-trash (with count-naming confirms) — UI surface is ready
  and waiting.
- **Next:** enable the three disabled actions the moment the delete IPC
  lands; otherwise idle until review feedback.

## 2026-09-20 — T-165 conversation threading (branch release/v0.1.0)

- **Status:** Threading delivered as pure client-side grouping. Store
  reality checked first: list views expose `message_id` + `subject` but NOT
  `In-Reply-To`/`References` (verified in `kiwi-mail/src/store.rs` +
  `src-tauri/src/types.rs` — headers live only in the MIME parser and the
  compose input), so threads group by normalized subject within an account
  and the limitation is stated in-view and in code. `npm run build` green
  first try (tsc strict + vite, 46→47 modules). `src-tauri/` untouched. No
  commits made.
- **Files changed — kiwi-app/src (new):**
  - `threading.ts` — `normalizeSubject` (iterative Re/Fw/Fwd/Aw/Sv strip,
    `[tag]` drop, case-fold; conservative prefix set), `displaySubject`,
    `buildThreads` (account-scoped groups, members oldest→newest to match a
    future header-chain fold, threads newest-activity-first).
- **Files changed — kiwi-app/src (edited):**
  - `mock.ts` — third demo message (`Fwd: launch checklist`) so the demo
    shows a 3-message thread exercising prefix normalization.
  - `views/mailbox.tsx` — Threads/List toggle (`kiwi.threadMode` pref,
    threads default); collapsed `ThreadGroup` rows (chevron + subject +
    participants + `N msgs` + `N unread` badges, latest date/snippet,
    whole-thread checkbox, Enter toggles, `aria-expanded`); expanded
    children reuse the extracted `MessageRow` (single-message threads
    render identically to list mode); selection/bulk/j-k stepping unchanged
    (ids are flat); reader `ThreadStrip` (collapsible sibling list, current
    marked, only for 2+ threads).
- **Commands run:** `npm run build` in kiwi-app (green first try, 47
  modules, no new deps).
- **Assumptions/limits:** subject collisions across distinct conversations
  can over-group (inherent to subject threading — header chains fix it when
  IPC exposes the fields; no view changes needed then). Cross-folder
  threads appear only where the loaded list spans folders (all-inboxes).
- **Needs (Agent 7, proposed):** expose `inReplyTo`/`references` on
  `MessageView` for header-chain threading.
- **Next:** chain fold when the fields land; otherwise idle until review
  feedback.

## 2026-09-20 — T-167 settings depth + prefs chain (branch release/v0.1.0)

- **Status:** All sections deepened. Backend reality checked first: NO
  prefs IPC exists (only `prefix` string matches in `src-tauri/` — no
  `kiwi_get/set_prefs`, no rename/update-account command), so prefs run on
  localStorage with permanent wrappers + merge policy ready for land (zero
  view changes then). `npm run build` green first try (tsc strict + vite,
  47 modules). `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `prefs.ts` — `PREF_KEYS` registry, `accountPref()` suffixed keys,
    `collectPrefs` (incl. signature/syncFreq enumeration),
    `applyPrefsBag` (backend-wins merge + `applyUiPrefs`),
    `loadMuted`, `applyUiPrefs` (theme/accent/density attrs).
  - `ipc.ts` — `getPrefs`/`setPrefs` wrappers (throw until backend lands).
  - `theme.css` — `[data-density=compact]` (tighter rows/cards/inputs) +
    `[data-accent=subtle|vivid]` treatments for both themes.
  - `App.tsx` — `notify` honors the toast kill-switch (in-view lines still
    update) + best-effort WebAudio blip when sound is on (guarded, no
    assets); muted accounts excluded from unread counts; theme state
    follows Settings via `kiwi-theme` event; `applyTheme` replaced by
    `applyUiPrefs`.
  - `kiwi.ts` + `chrome.tsx` — `AccountInfo.muted?`; sidebar muted pill +
    muted unread label.
  - `views/settings.tsx` — new Appearance section (theme/accent/density,
    theme moved out of General); Accounts cards gain per-account pane
    (display name read-only + rename-via-reconfigure note, Re-probe
    servers staged as wizard handoff, sync-frequency pref with honest
    manual-today note, mute checkbox, signature textarea); Notifications
    replaced the dead `kiwi.notify` toggle with toasts on/off + sound +
    per-account mute list; Privacy states the blocked-by-default +
    always-strip receipts posture above the per-account toggles; prefs
    pull on live mount + debounced push with a visible store note.
  - `views/compose.tsx` — per-account signature appended at send
    (`-- ` separator) behind a checkbox shown only when a signature
    exists; drafts never gain it silently.
- **Commands run:** `npm run build` in kiwi-app (green first try, 47
  modules, no new deps).
- **Assumptions/limits:** display-name rename and sync-frequency actuation
  need backend commands (`kiwi_update_account`, scheduler) — both flagged
  honestly in-view. Dropped the orphaned `kiwi.notify` toggle (superseded
  by `kiwi.toasts`; stored value untouched). Sound is a synthesized blip
  (no audio assets shipped).
- **Needs (Agent 7, proposed):** `kiwi_get/set_prefs` (localStorage merge
  already implements the contract side), `kiwi_update_account` (rename).
- **Next:** wire the push/pull live the moment the prefs IPC lands;
  otherwise idle until review feedback.

## 2026-09-20 — T-163/T-164 enablement: delete/spam/empty-trash + finding detail (branch release/v0.1.0)

- **Status:** Agent 7's T-163 (`kiwi_delete_messages`,
  `kiwi_move_messages` — verified in `commands/message.rs` + `lib.rs` +
  ipc.md §6b) and T-164 (`kiwi_finding_detail` — `commands/security.rs` +
  ipc.md §8) wired through. T-162's disabled actions are now live with
  count-naming confirms; the finding dialog joins the full record.
  `npm run build` green first try (tsc strict + vite, 47 modules).
  `src-tauri/` untouched. No commits made.
- **Files changed — kiwi-app/src:**
  - `kiwi.ts` — `DeleteResultView`, `MoveResultView`,
    `FindingDetailView` (tolerant).
  - `ipc.ts` — `deleteMessages`, `moveMessages`, `findingDetail`.
  - `App.tsx` — `bulkDelete` (folder-grouped, 400-uid chunks under the
    500 bound, soft→Trash vs permanent-from-Trash reported separately, one
    summary toast + reload; demo toasts); `bulkSpam` (per-account Spam/
    Junk resolve from folder lists, same-account moves only, missing
    folders named not failed-silently, already-there counts as done);
    `openFinding`/`closeFinding` (list renders instantly, live joins
    `kiwi_finding_detail` on stable `rule|…` ids, `finding-N` fallbacks
    skip); empty-trash delegates to `bulkDelete` over the visible list.
  - `views/mailbox.tsx` — BulkBar Delete (two-step confirm naming count,
    permanent copy in Trash) + Spam (two-step confirm) enabled, demo
    labeled; header Empty-trash enabled in Trash folders
    (`/trash|deleted|bin/i`) with count confirm, hidden elsewhere.
  - `components/security.tsx` — FindingDialog detail sections (observed
    session line, session signals, sibling ids, evicted-session note,
    fetch-error fallback to the retained summary).
- **Commands run:** `npm run build` in kiwi-app (green first try, 47
  modules, no new deps).
- **Assumptions/limits:** spam needs a known Spam/Junk folder (sync
  first — stated when absent); backend Trash auto-create covers delete.
  Move-to select stays Archive/Inbox (arbitrary-folder moves need dst
  resolution UI — follow-up if wanted). `kiwi_schedule_send` also landed
  but is out of this brief's scope (send-later already works via
  `sendAtUnix`).
- **Next:** idle until review feedback.

