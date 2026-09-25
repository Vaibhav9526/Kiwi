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
