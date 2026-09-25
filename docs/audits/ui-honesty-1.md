# UI Honesty Audit — ui-honesty-1.md (T-297)

**Scope:** every interactive surface in `kiwi-app` — toolbar, menus, folder tree,
list rows, reader, dialogs, rail, settings tabs, composer, search, contacts,
filters/rules, security center, setup.

**Method:** scripted CDP click-census (`kiwi-app/artifacts/t297/audit.mjs`,
`audit2.mjs`) driving headless Chromium against the vite dev server — 21 route
passes + all 8 Settings tabs, ~1,100 control clicks. A control is *working* if
it produces an observable effect: navigation, toast, DOM mutation, checked/aria
flip, or (for text inputs) focus. Destructive/dialog-confirm controls were
skipped and verified by handler binding in source. Console errors captured
during the whole sweep: **0**.

## Verdicts

| Class | Count | Notes |
|---|---|---|
| working | ~980 attempted clicks | every control except the one below |
| dead | 1 | Quick Actions main button — **fixed this task** |
| mocked (unlabeled) | 0 | — |
| gap | 4 | labeled affordances missing a backend pair — below |

### Dead control — FIXED

| Control | File | Finding | Fix |
|---|---|---|---|
| Quick Actions main button | `components/chrome.tsx` `ToolBtn` | Split-button main half was `onClick={() => undefined}` — only the caret opened the menu; the labelled half was dead | `ToolBtn` gained `menuOnMain` — main click toggles the menu with `aria-haspopup/expanded`. CDP-verified: menu opens with Mark all read / Security details / Lock mailbox now |

### Gaps — affordance exists, backend does not (all honestly labelled)

| Surface | File | What's missing | Label state |
|---|---|---|---|
| Message source → raw RFC822 | `views/mailbox.tsx` SourceDialog | `kiwi_message_source` IPC (parsed headers/parts shown instead) | Title text says so explicitly. Backend task: **T-295** (Agent 19) |
| Mobile pairing QR | `components/security.tsx` ~264 | device-pairing flow | Title: "QR placeholder — real codes arrive with the device-pairing flow" |
| Outbox held/failed state + reason | `views/mailbox.tsx` `outboxState` | `OutboxItem.state`/`lastError` fields | UI derives only real states; gap filed in T-296 + code comment |
| Plugin `message-list-read` / `composer-action` | `src/plugins/runtime.ts` | host methods | **Wired in T-302** — bounded snapshot sinks + composer-action store, harness-proven 47/47 |

## Surfaces verified working (no observable-effect misses)

- **Toolbar:** New/Refresh/Reply/ReplyAll/Forward/Mark/Archive/Snooze/Delete split buttons + all caret menus; every item maps to a real `on*` prop.
- **Folder tree:** smart folders + per-account folders navigate; unread badges real (`smartUnread`).
- **List:** Primary/Other tabs, select-all, row checkboxes, star/archive row actions, thread-mode toggle, filter focus, group collapse, splitters (T-293).
- **Reader:** star, print (`window.print`, T-292), view-source, SecurityPill evidence, add-sender-to-contacts, security-details link, reply actions, collapse.
- **Agenda rail:** collapse, add task, checkbox done, flag, delete, Security Center link — all persist via `kiwi.agenda` (T-283).
- **Outbox (T-296):** Send all now, per-item Undo/Send-now/Reschedule.
- **Settings × 8 tabs:** General/Accounts/Identity/Appearance/Shortcuts/Mail Rules/Integrations/Plugins — all controls live; theme picker applies+p persists (T-290).
- **Composer:** fields, attach, send (demo-gated toast), discard confirm.
- **Search:** query, scope chips, filters; results navigate.
- **Palette** (Ctrl+K) and **shortcuts overlay** (`?`) — real.
- **Toasts:** dismiss button works; demo gates announce "Demo mode — needs the Tauri backend" instead of faking success.

## Mocked data check

- Demo mode is globally labelled: `demo data` topbar chip + `demo` chips on
  agenda security rows + every demo-gated action toasts "Demo mode — …".
  No surface renders fabricated data without a visible marker.
- Security card (T-283) shows only real trust/findings/devices/unread;
  unavailable aggregates are omitted by design.

## Unhandled IPC check

- Zero console errors / unhandled rejections across the full sweep.
- All IPC failure paths render `kiwi-banner error` or toasts (T-287 sweep).

## Context menu (landed mid-audit by A24 — verified after it settled)

- Right-click row menu (`components/contextmenu.tsx` + `views/mailbox.tsx`
  `ctxEntries`): opens with 10 real items (Reply / Reply All / Forward /
  Mark read / Star / Snooze submenu / Archive / Move-to submenu / Mark as
  junk / Delete). Snooze + Move-to + Junk are **demo-disabled with the
  honest title "Needs the Tauri backend"**; Move-to empty-account state
  says "No other folders on this account". Click-through exercised.
- The transient tsc errors seen during the sweep (CtxEntry icon union,
  `folderLists`/`onSnooze`/`onMoveToFolder` callsite) resolved as the
  agent's edit completed — repo-wide `tsc` is green.

## Verdict

**One dead control existed and is fixed.** Nothing on screen silently lies:
the only remaining non-functional affordances are the four labelled gaps above,
each filed to a backend owner. `vite build` green.

**T-302 addendum:** plugin host surfaces for the last two declared caps are now
wired (`messages.list`/`getEnvelope` whitelist-projected; `composer.registerAction`
→ compose-toolbar button → `composer.action` evt). One live-exec constraint
surfaced: `index.html` CSP (`script-src 'self'`) refuses the loader's
`new Function`, so plugin sessions run only in the harness today — documented
in GETTING-STARTED post-alpha hardening; `'unsafe-eval'` deliberately not added
(B2 CSP backstop). No UI lies implied: the Plugins tab surfaces real install/
enable state and the capability gates are honest.
