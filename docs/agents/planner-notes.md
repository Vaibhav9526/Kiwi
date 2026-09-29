# KIWI Planner — Scratchpad

> Role: KIWI PLANNER agent. Owner discusses features/architecture here; output
> is structured PLAN specs sent to the Lead terminal via `orca terminal send`.
> I do NOT write code and do NOT dispatch workers.

## Handoff channel

- Leader terminal: `term_c20c6737-9b80-4911-bcd2-38aa5113e4d7`
  (updated 2026-09-25 — old handle term_a262bc09 went stale after an
  Orca runtime restart; identified by title "Contact Other Open
  Terminals" + agentIdentity devin. Handles are runtime-scoped: if a
  send fails `terminal_handle_stale`, re-run `orca terminal list --json`
  and find the replacement — never dual-send to old + new.)
- Send format:
  `orca terminal send --terminal term_c20c6737-9b80-4911-bcd2-38aa5113e4d7 --text "PLAN: <structured spec>" --enter`
- Verify receipt: check `accepted: true` in the response; use
  `--wait-submit 10` if submission proof is needed.

## Current state snapshot (as of 2026-09-20)

- Branch: `release/v0.1.0`. Release rule: push to GitHub at each phase gate.
- Pivot (ADR-005): KIWI is a STANDALONE Tauri 2 client — NOT a Thunderbird
  fork. `source/` → `D:\kiwi-src` is read-only reference.
- Stack: Rust workspace (kiwi-mail, kiwi-core, kiwi-forensics, kiwi-mailauth,
  kiwi-autoconfig, kiwi-contacts pending, kiwi-app/src-tauri), React+TS
  frontend, kiwi-admin Node/TS + Drizzle (PG), SQLite local state,
  docker-compose infra (postgres + mailpit + kiwi-admin).
- Hard rules to enforce in every plan:
  - `#![forbid(unsafe_code)]` in Rust crates.
  - No secrets in plaintext/logs; device-local secrets → OS credential store
    (DPAPI/Credential Manager).
  - Deterministic security engine is authoritative; AI is explanation-only.
  - All DB access behind repository interfaces; Drizzle governs TS-side
    persistence; rusqlite stays internal to kiwi-mail.
  - Tauri IPC is the only frontend↔backend boundary (contract: ipc.md);
    no business logic in frontend.
  - Docker = infra only, never the hostile-code boundary (sandbox = ADR-008).
  - New infra component → ADR-009 justification required.
  - Sandbox attachments/links: disposable VM boundary only (T-132 done:
    WSL2 PoC proven, QEMU/WHPX viable, Firecracker N/A on Windows).

## Open/in-flight work (reconciled ledger, post-Lead ack 2026-09-20)

- A5: T-004 (admin, in-progress), T-145 UI elevation, T-151 frontend
  continuation, T-165 threading view — owns `kiwi-app/src/` exclusively.
- A6: T-113, T-114, T-115 (gate review in-progress), T-133, T-140 CI,
  T-141 mailauth fixtures, T-147 IMAP fixture server, T-166 forensics→app
  seam. Biggest queue but low-contention (docs/tests/tools).
- A7: T-163 (delete/move IPC) → T-164 (forensics IPC). Live critical path
  for app↔backend wiring.
- A8: T-158 (autoconfig completion), T-159 (FTS5 search in kiwi-mail).
- A9: T-149 (admin e2e, reassigned from A4 — user-approved parametrized
  e2e + PG wiring), T-150 (contacts).
- A10: T-161 (kiwi-sandbox crate — my "optional spawn" landed as an
  assignment instead; fine, crate boundary still clean).
- A2/A3 gone; A4 unreliable (timeout loops) — treated as non-capacity.
- In-review awaiting Lead merge: T-002, T-005, T-006, T-102, T-122.

## Dependency hot spots

- T-163 → T-164 → (A5 frontend consumers) is the live wiring chain.
- T-166 (forensics seam contract) gates T-164's real-data Security view.
- A6's queue is long; if T-166 blocks T-164, escalate reprioritization.
- kiwi-mail/src shared by A8 (T-159) and any A10 follow-ups — serialize.

## Phase position (my read)

- Phase 0: effectively complete (workspace green, app launches, live
  send+receive vs mailpit/greenmail proven).
- Phase 1: nearly complete — mail engine + transport capture + forensics
  engine all done. Remainder: forensics→app seam (T-166/T-164) so
  Security view shows real findings.
- Phase 2: substantially done already (mailbox/composer/search/threads/
  outbox/undo-send/send-later/setup wizard all landed).
- Next frontier: Phase 3 (identity + trusted device) — kiwi-core is
  in-memory; needs SQLite persistence + IPC wiring to lock state.
  Phase 4 mobile impl pending (contract done T-136).

## Plan-spec template

```
PLAN: <title>
Scope: <what's in / explicitly out>
Acceptance criteria: <testable bullets; test evidence required>
Suggested task split: <T-style items w/ suggested owner role + deps>
Constraints: architecture rules touched, contracts to update, files/dirs
Risks/conflicts: <contract conflicts, shared-file contention, unknowns>
```

## Log

- 2026-09-20 — Session start. Context loaded; scratchpad created.
- 2026-09-20 — Owner Q: "more agents?" Answer: no — liveness problem, not
  headcount. Evidence: A4 stuck in resume loop (T-149), A10 parked at
  bypass-permissions prompt, A6 working-but-not-logging 5h+, A7 idle,
  TASKS.md stale vs status files (T-101/103-107/111/135/142/146/153/155/
  156/160 done per status, open in ledger). SENT PLAN to leader
  (term_a262bc09, accepted:true): reconcile ledger, transfer T-149 → A7/A8,
  T-144 → A7, resolve A10 gate, require A6 status update, optional
  kiwi-sandbox crate spawn (only justified new headcount — clean boundary,
  contracts/sandbox.md ready). Constraints flagged: serialize
  kiwi-mail/src + kiwi-app/src edits (A7/A10 already collided once on
  store.rs/outbox).
- 2026-09-20 — Lead ack: plan executed; most items were already in flight
  (T-149 → A9 w/ user-approved PG e2e, kiwi-sandbox = T-161 → A10,
  T-144 done by A7, A10 gate was false positive, A6 resolved with 111
  tests). Ledger now true-state — always re-read TASKS.md before
  planning. Lesson: watcher terminal-idle data over-reports stalls;
  status files + TASKS.md are authoritative.
- 2026-09-20 — Security audit (owner request): CLEAN — zero unsafe,
  secrets scan 0/321, no install hooks, no telemetry, deps standard.
  Findings: compose ports on 0.0.0.0 (greenmail auth-off + PG dev creds
  LAN-exposed — real), kiwi-core missing [lints] workspace, 175MB
  MozillaBuild exe at root, watcher ps1s use Invoke-Expression.
- 2026-09-20 — SENT PLAN: structural hardening, Thunderbird-style
  (dir-per-domain, file-per-responsibility — verified vs
  source/comm/mailnews). Phase A hygiene now (lints/compose/exe/scripts);
  Phase B workspace.dependencies atomic commit; Phase C serialized splits
  (kiwi-mail >800-line files, src-tauri types.rs, App.tsx) in owner quiet
  windows. Gates: full green per phase, zero functional diffs.
- 2026-09-20 — SENT PLAN: Thunderbird-faithful UI replica for kiwi-app.
  Owner wants TB UI "same to same" + non-webby desktop feel. Key honesty
  note baked in: literal XUL port infeasible (Mozilla chrome doesn't run
  in a Tauri webview) — spec is faithful reproduction: layout/tokens/
  menus/shortcuts/density cloned from source/comm/mail + mailnews
  (MPL-compatible). Preserves all IPC bindings + KIWI security surfaces
  in TB idiom. Subsumes T-145/151/165 — Lead reconciles ledger.
- 2026-09-20 — SUPERSEDED by Mailspring plan: owner chose replica-not-copy
  after license fork (Mailspring = GPL-3.0; direct code use would force
  KIWI to GPL — owner picked MPL replica). Sent PLAN-UPDATE: clone
  Mailspring to reference/mailspring/ (gitignored, study-only), extract
  design tokens + animation catalog + layout maps → docs/ui-mailspring-map,
  rebuild kiwi-app in Mailspring idiom, port feature CONCEPTS (task queue,
  undo-send, snooze) as reimplementation. Backend unchanged — mailsync is
  C++/Electron-bound, port explicitly rejected. Compliance gate: no GPL
  files/verbatim blocks in repo.
- 2026-09-20 — SENT PLAN: MailFlow feature-mine (repo is AGPL-3.0 +
  $500 commercial — study-only, reference/mailflow/, zero copying).
  Selected: F1 inbox rules engine (kiwi-mail ingest, deterministic),
  F2 category tabs (header heuristics, AI-reclassify seam only),
  F3 unsubscribe (URL-open default, never auto-send), F4 block list,
  F5 mark-read prefs, F6 GTD labels as real IMAP folders, F7 sent-mail
  autocomplete ranking, F8 LOCAL-only avatars (rejected remote favicons —
  metadata leak), F9 remap shortcuts + layouts. EXPOSED GAP: OAuth2
  token-acquisition flows (Google/M365) — kiwi-mail has XOAUTH2 but no
  acquisition; needs own spec. Rejected: PWA/multi-user/TOTP/SSO/Todoist/
  CardDAV-server/remote-favicons. Sequenced as BACKLOG — don't interrupt
  Mailspring replica or current T-tasks.
- 2026-09-20 — SENT PLAN-APPEND (F10–F15): rich composer (tables/emoji/
  img-resize/Excel-paste — ammonia must cover new markup), native OS
  notifications via Tauri on T-157 events (lock-aware: no body leak when
  degraded/locked), threads incl. Sent items, junk marking (\Junk flag +
  folder move, deterministic), X-Priority header, extra theme schemes;
  custom CSS deferred. Rejections documented.
- 2026-09-20 — Owner directive: FULL MailFlow feature parity. Sent
  PLAN-APPEND-2: every rejected item got a KIWI-native mapping (TOTP as
  secondary unlock factor, OIDC for admin plane P6, recovery-email into
  P3 spec, CardDAV server P6/7, opt-in direct favicon fetch instead of
  proxying, i18n/custom-CSS P8, AI summarize/draft/ask P7). True-rejects
  remaining: remote favicon PROXYING, literal multi-user webmail model.
  Rule now: parity-by-adaptation — nothing dropped without a home;
  Phase 6+ items need owner sign-off before starting.
- 2026-09-20 — SENT PLAN: product identity lock-in (owner-confirmed).
  KIWI = full-featured mail client (Mailspring polish + MailFlow
  feature set) + security spine. Tagline direction: "Email that proves
  its security." Leader to record in ARCHITECTURE §1 + README; evidence-
  first language rule for all UI/report copy; parity never compromises
  deterministic-security rules.
- 2026-09-25 — SENT PLAN: kiwi-integrations crate — Guerrilla temp-mail
  (public-inbox warning, 60min TTL, HTTPS-only, gentle polling) +
  email-spam-tester deliverability (per-send consent — content leaves
  device; slug = capability-secret; score + evidence/RFC-cited checks;
  placement-beta excluded). Deps: reqwest-rustls, ADR-009 entry.
  Leader handle had gone stale; re-listed terminals, resent to new
  leader term_c20c6737. Context: project pushed to GitHub now
  (Vaibhav9526/Kiwi); T-183/194/195 exist — OAuth2 gap (T-195) queued.
- 2026-09-25 — DRAFT SPEC (awaiting owner send-word): T-fidelity — pixel-faithful UI rebuild against docs/ui/reference-layout.png (owner-supplied eM Client 4-pane shot — NOTE: image is eM Client, not Mailspring; same clean-room rules, closed-source = design imitation only):
  * Light theme DEFAULT: white content, gray-blue pane bg, blue selection, orange primary-action accent (+New)
  * 4-pane: folder tree | msg list | reader | collapsible right sidebar (Agenda/tasks)
  * Folder pane: "Mail" header, Favorites, smart folders w/ right-aligned unread counts (All Inboxes, Outbox, Sent, Trash, Drafts, Junk, Unread, Flagged, Unreplied, Snoozed), per-account expandable sections (email header + subfolders)
  * Toolbar: hamburger | +New (orange) | Refresh | Reply / Reply All / Forward / Mark / Archive / Snooze / Quick Actions / Delete — SVG icons + labels + chevron dropdowns; centered search pill "Search (type ? for help)"
  * Msg list: category tabs (Primary/Other +N), date groups (Today/Older collapsible), rows = circular avatar + bold sender + subject + colored category pill (News/Personal/Logs etc — hooks F2) + gray snippet + date + unread dot + paperclip + count badge; selected = light blue
  * Reader: thread title, stacked message cards (avatar, blue sender, timestamp, collapse-to-snippet)
  * Right rail: Agenda panel — Add task, date-grouped items w/ checkbox + flags (No Date/Today/Tomorrow); hosts GTD rail (F-features) + can host security summary
  * Status bar: bottom icon strip (mail/calendar/contacts/tasks)
  * Replace ALL emoji icons with monochrome stroke SVG set (~16px, consistent grid)
  * System sans ~13px, sender semibold, snippet muted; density = compact professional
  * Keep: all IPC wiring, KIWI security pill/lock/policy surfaces re-dressed to match
- 2026-09-25 — DRAFT SPEC (same batch): extensibility — Mailspring-style plugins + themes:
  * Themes (ship first): CSS theme packages under themes/ w/ manifest {name,author,version,vars}; Appearance picker; stock light(default)+dark
  * Plugins: sideload-only v1 (no store — deferred like Mailspring); manifest {id,version,permissions[]}; capability-scoped API — declared caps only (message-list-read, composer-action, settings-page, notify); NO raw DOM/net by default; message-passing bridge; per-plugin enable/disable + remove UI; locked/degraded-state behavior; Getting Started doc + starter template
  * SECURITY: plugin = code exec in a security client → isolation model must be spec'd (iframe sandbox vs scoped bridge) + caps reviewed before any IPC access; unsigned/unreviewed plugins never get IPC-bridging caps; THREAT-MODEL.md update required
  * OWNER AMENDMENT (2026-09-25): alpha release — defer isolation enforcement; plugins trusted-code in alpha. Keep manifest + capability declarations + bridge API (contract now, enforcement later). Record accepted risk in THREAT-MODEL.md w/ hardening task for post-alpha. Not a silent skip — documented decision.
- 2026-09-25 — SENT (leader term_c20c6737, req 3ec27de0): both above specs dispatched + owner staffing request: TWO new dedicated Devin design agents — one for layout/CSS fidelity (Item A), one for icons/motion + plugin/theme scaffolding (Item B).
- 2026-09-25 — DRAFT ADDITION (same pending batch, awaiting send-word):
  * UI PLACEMENT pass per Mailspring source study: temp-mail promoted to SIDEBAR (Disposable Inbox section under Mailboxes, icon+unread badge, opens inbox-style view w/ list+reader; "+ New disposable" quick-action) — mirrors Mailspring's userSections/OutlineView plugin pattern (send-later et al register sections, not settings pages); Settings>Integrations keeps management surface only. DENSITY pass: populated sidebar sections, agenda rail content, richer rows (avatar+sender+subject+snippet+chips every row), Mailspring-style illustrated empty states — kills "empty" feel.
  * COMPOSE = Gmail-style floating dock: bottom-right floating panel (~510px, elevated card), header = subject + minimize/expand/close, To/Cc/Bcc chips + subject + body, bottom bar = Send pill + attach/format icons + discard; multi-draft stacks right-to-left; minimized drafts collapse to chips in bottom bar; ESC/minimize preserves draft via existing outbox path.
  * GLOBAL RADIUS scale: soft corners everywhere — buttons/inputs 6-8px, cards/panels 10-14px, composer/dialogs ~16px; define radius tokens, sweep all views (no sharp corners anywhere).
- 2026-09-25 — SENT (leader term_c20c6737, req 7d7a08be): UI pass #2 — temp-mail sidebar promotion (Mailspring userSection pattern), density/empty-state pass, Gmail floating composer dock, global radius sweep.
- 2026-09-25 — SENT (leader term_c20c6737): README rewrite task — professional README + architecture image. archify image at artifacts/architecture-preview.png verified: correct for core crates, predates kiwi-integrations/autoconfig/contacts/sandbox → spec'd coordinate w/ T-346 (A26 regenerating architecture.svg to as-built, must include new crates); embed regenerated diagram. Verified-correctness rule: cross-check Cargo.toml members, package.json scripts, .env.example ports.
  Also observed: UI pass#2 + Gmail composer already LIVE as T-342 (A25) / T-343 (A24).

## Dispatch 2026-09-26 — Account experience package (user-approved)

### Item A — Provider quick-pick entry (setup wizard step 1)
- Branded provider cards on first screen: **Google**, **Microsoft**, **Other/IMAP manual**.
- Google card → straight into OAuth2 loopback-PKCE sign-in; on grant completion pre-fill servers (imap.gmail.com:993/tls, smtp.gmail.com:465/tls — presets already in setup.tsx) + display name/email from token claim. Skip manual fields.
- Microsoft card → device-code flow, same auto-fill (outlook.office365.com presets).
- Other → existing email-first path; keep domain detection fallback.
- App-password paste stays under "advanced" for Gmail.
- Goal: real-provider add = ~2 clicks, no host/port typing.

### Item B — Dev plaintext fixture mode (BUG/GAP — blocks all local testing)
- Findings: production binary hard-locks endpoint on ANY plaintext session (`plaintext-transport` signal → sticky lock, `require-authenticator-unlock`). No dev escape: unlock needs paired-authenticator signature; no paired phone; mobile is scaffold-only. `allow_plaintext_auth` is never wired in shipped code (only examples/tests set it) so password auth to mailpit/greenmail is always refused. Result: mailpit/greenmail unusable with production binary.
- Fix: `KIWI_DEV_PLAINTEXT=1` env gate that (1) enables allow_plaintext_auth for **loopback hosts only** (127.0.0.1/::1/localhost), (2) exempts loopback sessions from the plaintext-transport hard-lock signal (keep recording as info/low finding, not lock), (3) visibly labels dev mode in UI (status bar chip "DEV — plaintext allowed").
- Document accepted risk in docs/THREAT-MODEL.md. Production default stays fail-closed.

### Item C — Credential-store write doesn't persist (BUG)
- Evidence: `kiwi_add_account` with password auth returned OK (store_secret → OsCredentialStore::set → keyring set_password, errors propagate via `?`), yet `cmdkey /list` shows NO kiwi.mail entry, and runtime logs "stored credential is missing from the OS credential store". Key format `kiwi/{account_id}/{in|out}`, service `kiwi.mail` (kiwi-app/src-tauri/src/credstore.rs, accounts.rs:242).
- Investigate keyring 3.6 Windows backend target naming/persistence; add a write→read-back verify in add path so silent no-op fails loudly.

### Item D — Lock recovery UX (related)
- Currently an unpaired endpoint that locks has zero recovery path (no dismiss, no reset, mobile scaffold can't sign). Spec needed: either a dev-unlock seam under KIWI_DEV_PLAINTEXT or an explicit "reset security state" destructive action in Settings with clear warnings. Fleet decides; needs a THREAT-MODEL entry either way.

Refs: accounts.rs:242 store_secret; credstore.rs (OsCredentialStore); dispatch.rs SmtpConfig::default() never sets allow_plaintext_auth; trust.rs PlaintextTransport high signal; pairing_listen.rs dev seam pattern to copy.

## Dispatch 2026-09-26b — Cozy/minimal Gmail-ergonomics polish (user screenshots)

User flagged 4 live UI issues + 1 reference. Reference composer saved: docs/ui/reference-compose-gmail.png.

### Issue 1 — Gradient accent is off-brand (screenshots: Send button, + New contact, contacts header strip)
- Orange→pink gradient on primary actions looks garish. Replace with FLAT accent: primary = solid orange (--accent), hover = slightly darker. No gradients anywhere on buttons/chips/strips. eM reference uses flat orange; Gmail uses flat blue. Pick flat orange (brand) — but flat, never gradient.

### Issue 2 — Disabled toolbar buttons look broken (screenshot 1)
- Reply/Forward/Mark/Archive/Snooze render nearly invisible-faint when nothing selected. Fix: keep disabled but raise contrast (disabled = muted icon+label, not ghost). Also: Snooze/Quick Actions icon-only buttons need labels consistent with siblings.

### Issue 3 — Add-account page is generic + demo banner (screenshot 2)
- Already specced as provider cards (2026-09-26 dispatch A). Additional: the "Demo mode" banner is showing because user views browser (localhost:1420) not Tauri — ensure the desktop app surfaces a REAL state chip instead (locked/no-backend/offline) rather than demo copy.

### Issue 4 — Compose doesn't match Gmail (screenshots 3 vs 5)
- Current: floating card exists but Send uses gradient; toolbar icons sparse/unstyled.
- Target (reference-compose-gmail.png): white card, rounded-16, header "New Message" w/ minimize/expand/close; To + Cc/Bcc inline links; Subject underlined-subtle; large body; footer = blue/orange solid Send PILL w/ split chevron + icon row (format Aa, attach, link, emoji?, image, confidential?, pen?, overflow ⋯, trash). Solid flat colors, hairline dividers, comfortable padding. Match proportions.

### Item 5 — Global "cozy minimal Gmail" pass
- Density: more whitespace breathing room (Gmail row ~48px), fewer visible borders — use whitespace not lines; hairline dividers only.
- Typography: keep 13px but increase line-height for readability; sender semibold, snippet 60% gray.
- Surfaces: near-white panes (#fff), rail #f6f8fc-ish, NO heavy shadows — 1-2px soft shadow only on floating composer/cards.
- Roundness already specced; verify corners actually applied on inputs/menus/modals.

Priority: flat-accent + toolbar contrast + composer footer are small/high-impact; do first.

## Dispatch 2026-09-26c — Palette fix + theme expansion + settings professionalism

### Item 1 — Flat color palette (replaces gradient)
Root cause: --kiwi-gradient (orange→pink #EAA132→#E580CC) is wired into .kiwi-btn-primary (theme.css:157/164/187/386), brand wordmark, lock ring, radial glows (theme.css:289-290), gradient-border trick (302-303).
- Define a real palette token set: --accent (flat orange #F5A623 or brand orange), --accent-hover, --accent-ink (text on accent), --surface, --surface-2, --border (hairline), --text/--text-muted, semantic: --ok/--warn/--danger/--info, --selection (blue per eM ref).
- .kiwi-btn-primary → flat accent bg + hover darken; keep wordmark gradient ONLY if user wants brand mark (else flat accent text). Kill radial glows + gradient border-box tricks on data surfaces.
- Sweep: composer Send pill, +New contact, contacts header strip, lock ring, any chip using gradient.

### Item 2 — More stock themes (currently 3: light/dark/high-contrast)
Add stock theme packages under themes/stock/: per accent variants — e.g. Light-Blue (Gmail-ish), Light-Orange (brand), Dark-Blue, Dark-OLED, Sepia/Paper (cozy warm). Each = manifest + vars overriding the token set. ThemePicker already renders installed list — new stock themes appear automatically. Include 1-2 "cozy" low-contrast warm themes since user asked for cozy.

### Item 3 — Settings + secondary pages professional redesign (Mailspring pattern)
Current settings feels formy/unfinished. Mailspring pattern: left nav rail with grouped sections, content area = stacked cards with consistent row height, section headers w/ muted descriptions, controls right-aligned, no floating loose labels.
- Settings: left rail nav (Accounts, Appearance, Notifications, Shortcuts, Plugins, Security, Integrations, About), each pane = card sections w/ hairline dividers between rows.
- Contacts/Tasks/Calendar secondary surfaces: same card+row language, consistent paddings, toolbar alignment.
- Targets: settings.tsx, views/integrations.tsx, contacts view, agenda rail cards.

## Dispatch 2026-09-26d — Fleet pickup: backlog, verification, landing sweeps (Lead)

Fleet reality: A11/A12/A15/A19/A20/A24/A25/A26 idle; A21 (T-340) + A23 (T-321) busy.
My last two UI passes landed as Lead direct-edits — remaining work is hereby
dispatched, not held.

### Item A — A24: claim T-349 provider quick-pick (in-flight, verify + land)
- setup.tsx already carries an uncommitted `em-provider-cards` implementation
  (providerPick state, PROVIDER_PRESETS, pickProvider/providerGranted,
  OAuth2SignIn inline, "Enter manually" escape) + matching shell.css block.
- Verify against Dispatch 2026-09-26 item A: Google card → loopback-PKCE via
  OAuth2SignIn, Microsoft → device-code, presets fill servers on grant,
  identity from token claim, manual path intact for Other/reconfigure.
- Add ui-smoke coverage (cards render, click→OAuth panel, cancel→manual form).
- Surgical commit: only the provider-card hunks in setup.tsx + shell.css.

### Item B — A20 + A24: T-348 blocklist settings UI (split by ownership)
- A20: `kiwi_blocklist_{list,block,unblock}` bindings in ipc.ts + kiwi.ts —
  thin typed wrappers only; §7.3 says id/normalization stay backend-owned.
- A24: Settings → Mail Rules section blocklist card consuming those bindings
  (row-per-sender, add/remove, honest empty/disabled states).
- A12's T-348 handoff note (agent-12-status.md) is the contract — do NOT
  reimplement derivation in TS.

### Item C — A26: wire ui-stress.mjs into the gates
- New suite `kiwi-app/scripts/ui-stress.mjs` (19 checks: flagged-item computed
  styles + latency/jank/leak stress + backend-boundary honesty). 19/19 green
  on Edge, exits 1 on any FAIL, prints STRESS_JSON for CI.
- Add a ci.yml step beside the existing ui-smoke job, add to gates.ps1/sh,
  one line in docs/TESTING.md §2. Keep honest-skip when no browser.

### Item D — A24: land UI pass#5 remainder (staged, uncommitted)
- My staged work: compose.tsx (Gmail field rows, chips inline, Cc link,
  comma-commit, send folds pending text), shell.css hunks (.ms-prefs-layout
  split + .em-field* block + .kiwi-dispo), settings.tsx (ms-prefs-layout),
  ui-smoke.mjs selector hunks (closest('.em-field')), ui-stress.mjs (new).
- Verify visually vs docs/ui/reference-compose-gmail.png; run tsc + vite +
  ui-smoke + ui-stress; commit with per-hunk staging — index still carries
  foreign threading work, do NOT sweep it.

### Item E — A19: live e2e verification (KIWI_DEV_PLAINTEXT=1 + mailpit)
- The dev-plaintext/unlock/send path (T-350/T-351/T-352, a9e8cdc) has never
  been run end-to-end. Boot the Tauri app against local mailpit: unlock via
  kiwi_dev_unlock, add loopback account, real send smoke. Report pass/fail.

## Dispatch 2026-09-26e — Mailspring migration (branch ui-migration, Lead)

User directive: restructure KIWI mail UI on Mailspring's component layer —
port/copy from `vendor/mailspring/` (full source vendored, LICENSE kept).
Lead writes no component code; contract is `docs/MAILSPRING-MIGRATION.md`.
Read it first — seam map + forbidden deps + port order are binding.

Starter kit already in `src/ms/` (tsc-clean, uncommitted): ms-utils.ts,
ms-dom-utils.ts, ms-regexp-utils.ts — verbatim subsets, `any`-annotated where
Mailspring's looser tsconfig required. classnames+underscore deps installed.

### Item A — A25: T-355 kit completion (unblocks everything)
Finish src/ms/ per seam map: ms-electron.ts (Menu/MenuItem→DOM ctx menu on
`.em-ctx`, clipboard→navigator.clipboard+fallback), ms-contact.ts (Contact /
ContactGroup thin classes over ContactView; ContactStore async provider
calling `api.searchContacts` + contactBook; parseContactsInString via
ms-regexp-utils), ms-i18n.ts, ms-keymap.ts (Disposable/CommandCallback shape
over DOM listeners), ms-exports.ts barrel. Standalone-compile gate.

### Item B — A25: T-356 composer chain port (after kit)
Copy menu.tsx, key-commands-region.tsx, tokenizing-text-field.tsx,
participants-text-field.tsx from vendor → src/ms/, verbatim except seam
imports; port tokenizing-text-field.less into ms-components.css with
--kiwi-*/--em-* token mapping (no gradients, no hardcoded colors). Keep
clipboard/context-menu via ms-electron, not Electron.

### Item C — A24: T-357 wire composer (after T-356)
compose.tsx To/Cc rows → MsParticipantsTextField; participants {to,cc} map
↔ existing recipients/ccRecipients state; suggestions through kit provider.
Invariants: reply-prefill seeds To chip w/ `To:` display, comma/Enter commit,
pending-text-on-send commit, dock/minimize/discard untouched, ui-smoke
27/27 + ui-stress 19/19 green.

### Item D — A24: T-358 outline-view folder rail (after kit, parallel w/ C)
Port disclosure-triangle/drop-zone/outline-view-item/outline-view → replace
nav.em-folders account sections with IOutlineViewItem[] built from
FolderView. Preserve: drag-drop targets (T-317), folder ctx menus (T-322),
smart folders (undroppable), unread counts, unread-only suppression.

### Open (claim in order): T-359 thread-list (A24), T-360 themes (A25),
T-361 composer-view full (A24), T-362 preferences (A25).

Still in flight from 26d: T-348 (A20+A24), T-349 (A24), T-353 (A26),
T-354 (A19) — those land first where already claimed; migration tasks slot
behind current claims per agent.

## Dispatch 2026-09-26f — check-in assignments (Lead)

### A11 → T-363 (own-surface audit, not new code)
Your status file is current; T-227/T-282 logged. The worktree still carries
uncommitted diffs on YOUR paths — commands/{integrations,pair,prefs}.rs,
types/{integrations,system}.rs, contracts/{integrations,authenticator,
oauth2,ipc}.md. Nobody else may touch them, so they never land unless you
drive it. Sweep per hunk: superseded-by-commit → discard; in-flight →
finish + verify + commit (surgical); foreign → leave + name the owner in
your report. Also verify T-349's oauth2 contract half while you're in
oauth2.md — flag if the token-claim identity path is unwired. Report to
planner-notes + status file.

### A15 → T-206 + leftover review (your offer, accepted)
1. Review leftover uncommitted kiwi-mail hunks (the 3 foreign-failure files
   you correctly left unstaged) — classify land/discard/report; do NOT
   commit anything that isn't verifiably yours.
2. Then T-206 (was unassigned backlog): sent-frequency-ranked contact
   autocomplete. The ported Mailspring ParticipantsTextField now consumes
   ContactStore.searchContacts → kiwi_search_contacts — so ranking directly
   improves live completions. KIWI_MAIL side only: ranking signal/source;
   keep kiwi_search_contacts signature stable (rank inside the command,
   no API break). Coordinate with A20 if an ipc.md row changes.

Migration lane status (informational): T-355/356/358/360/362 done;
T-357/359 running. T-361 reserved for the compose wiring owner.

## Dispatch 2026-09-26g — T-364 XOAUTH2 connect-time decode (A11, priority)

A18's T-229 close-out re-verified oauth2.md against landed T-195/T-230:
gaps 1-6 open as documented; **gap 7 confirmed open in source** —
`save_tokens` persists the token JSON, `resolve_secret` returns it verbatim,
and the three live connect sites (`mail.rs:835-843` IMAP sync,
`accounts.rs` probe, `send/dispatch.rs:297` SMTP send) pass the full blob —
refresh_token included — as the XOAUTH2 bearer. Real providers reject it;
it's also a credential-leak class bug. `ensure_fresh`/`load_tokens` exist
but have zero connect-path callers.

**A11**: this slots ABOVE T-363 in your queue (audit can follow after).
Fix shape: decode the stored blob at each connect site (access_token +
refresh/expiry aware via ensure_fresh so a stale access_token refreshes
rather than raw-passes), keep resolve_secret's contract honest for
non-oauth2 secrets, add the live XOAUTH2 assertion (format: 'user=…\x01
auth=Bearer <access_token>' proving the bearer is the decoded token, not
JSON). Verify against the T-229 gap list + autoconfig suite. Contracts:
touch oauth2.md only to flip gap-7 status after the fix lands.

A18: T-229 marked done — thanks for the verified report.
