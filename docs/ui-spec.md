# KIWI Standalone Client — UI/UX Spec v2 (T-111)

> Owner: Agent 5 (OpenCode Muse 1.3 #1). Status: Phase 0/1 draft (standalone pivot).
> Replaces the v1 Thunderbird-integration spec (T-005) in this file. The v1
> security-surface designs (S-01…S-12) are carried over and re-anchored to our
> own React+TS frontend in `kiwi-app/` (Tauri 2 shell, Lead T-110).
> Architecture: `docs/ARCHITECTURE.md` (standalone pivot, ADR-005).
> Surface registry: `docs/contracts/ui-surfaces.md`.
> References: Thunderbird (mail workflows, UI patterns), Mailspring
> (unified inbox, snooze, send later, undo send, templates).

## 0. Design principles

1. **Familiar mail client first.** Three-pane mailbox, folder tree, composer,
   and account setup follow Thunderbird workflow parity (ARCHITECTURE.md §5) —
   a Thunderbird user must feel at home on first launch.
2. **KIWI security is native, not bolted on.** Indicators, panels, lock state,
   and policy banners are first-class citizens of the layout, sharing the same
   design tokens, but quiet by default (see §7 noise budget).
3. **Productivity without surveillance.** Mailspring-inspired features
   (unified inbox, snooze, send later, undo send, templates) are implemented
   locally. Deferred: read receipts/tracking — privacy-sensitive, needs owner
   sign-off (ARCHITECTURE.md §4). No tracking pixels are ever rendered or sent.
4. **Deterministic display.** UI renders what `kiwi-mail` / `kiwi-core` /
   `kiwi-forensics` / `kiwi-admin` report. UI never invents severity, never
   claims compromise detection (`docs/SECURITY.md` rules 1–3).
5. **Locked means locked.** Lock state makes sensitive content inert at the
   data/IPC layer (Agent 2 lock semantics); the UI additionally removes bodies,
   attachments, and send affordances from view — never merely hides them.
6. **No business logic in the frontend** beyond UI state (ARCHITECTURE.md §3).
   Every view below names its IPC/data source; loading/error states assume the
   backend may be unreachable.

---

## 1. App shell & three-pane mailbox (`KIWI-UI-013`)

- **Layout:** left sidebar (account/folder tree + app nav) | center message
  list | right/below message reader. Resizable dividers (persisted widths),
  collapsible sidebar. Default: Thunderbird-classic 3-pane; a "vertical view"
  (list above reader) toggle in View settings.
- **Top bar:** global search field (center), sync/refresh button with per-account
  spinner, KIWI account avatar/menu, "KIWI: <trust>" status chip (§7 S-02).
- **States:** `ready` / `syncing` (progress in status bar, cancellable per
  account) / `offline` (banner: "Offline — showing cached mail", queued sends
  held) / `locked` (→ §7 S-05 overlay) / `error` (backend/IPC unreachable →
  retry, cached data timestamped "Last known …").
- **Keyboard:** `F6` cycles panes (sidebar → list → reader → top bar);
  `Ctrl+K` focuses search; `Ctrl+1..9` jumps accounts; arrow keys navigate
  tree/list natively. All pane headers are real headings.
- **A11y/theme:** landmarks (`nav`/`main`/`complementary`/`search`); severity
  and sync state always as text, never color-only; full dark/light token set
  (§9); 200% zoom without horizontal clip of essential controls.

## 2. Folder tree & unified inbox (`KIWI-UI-014`, `KIWI-UI-015`)

- **Folder tree (`014`):** per-account expandable nodes (Inbox, Drafts, Sent,
  Snoozed, Scheduled, Spam, Trash, custom folders) with unread badges and a
  trailing 16px security icon only when that folder's account is non-`secure`
  (decorative, `aria-hidden`; the operable path is the status chip §7).
- **Unified inbox (`015`):** virtual "All Inboxes" node at tree top (default
  selection on launch when ≥1 account exists), merging all accounts sorted by
  date; each row shows an account color-dot + account name in the secondary
  line. Per-account Inboxes remain one click away. Unified Sent/Drafts views
  follow the same pattern (v2 scope: Inbox first, Sent/Drafts next).
- **Mailspring parity notes:** unified node persists across restarts; unread
  counts aggregate; per-account sync errors surface as inline row warnings on
  the affected account node, not as modal dialogs.
- **States:** normal / syncing (per-node spinner) / error (node warning +
  tooltip naming the failing account/server) / empty ("No folders yet —
  complete account setup").
- **Keyboard:** tree is a `role="tree"` with arrow-key semantics; `Enter`
  selects; type-ahead jumps to folder names.
- **A11y:** unread counts in `aria-label` ("Inbox, 12 unread"); security icon
  never the sole carrier of meaning.

## 3. Message list (`KIWI-UI-016`)

- **Row content:** sender, subject, date (relative + absolute `title`),
  unread dot, star/flag, attachment clip, account dot (in unified view),
  16px security glyph (severity shape differs per state, §7 S-01 rules apply).
- **Behaviors:** multi-select (Ctrl/Shift), bulk actions toolbar (mark
  read/unread, star, snooze, move, delete, spam), sortable (date/sender/
  subject/unread/starred), virtualized rendering for large folders, sticky
  date-group headers ("Today", "Yesterday", …).
- **States:** normal / loading (skeleton rows on folder switch) / empty
  ("No messages" + folder-specific hint) / error (sync failure with Retry) /
  offline (cached rows + "Offline" badge on the list header).
- **Keyboard:** up/down moves, `Enter` opens in reader, `Space` toggles
  selection preview, `x` toggles select, `r` reply / `Shift+R` reply-all /
  `f` forward, `u` mark unread, `s` star, `Delete` trash, `/` back to search.
  Shortcut help (`?`) dialog lists all bindings.
- **A11y:** listbox/row semantics with `aria-selected`; unread + severity
  announced in row labels; bulk toolbar is a real toolbar with labels.

## 4. Message reader (`KIWI-UI-017`)

- **Header:** sender (avatar initial, name, address), recipients (expandable),
  date (full + relative), spot for the security pill (§7 S-01), action bar
  (reply, reply-all, forward, archive, snooze, delete, print, view-source).
- **Body:** sanitized HTML render (no remote content by default — "Load remote
  content" per-message opt-in, matching Thunderbird parity; never loads
  tracking pixels silently), plain-text fallback toggle, attachment strip
  (open/save-all with sizes; blocked-while-locked per §7 S-05).
- **Security pill (S-01, re-anchored):** right-aligned pill in the reader
  header: `secure` / `warning` / `danger` / `unknown` / `loading` / `error`
  (severities per `ui-surfaces.md` §2). `Enter` opens finding dialog (S-04).
  Same fail-closed rules as v1: unknown/error never green; stale timestamped.
- **States:** normal / loading / error (message fetch failed → Retry; headers
  may still show) / locked (body + attachments replaced by lock notice +
  "Verify" button → S-05) / offline (cached body labeled "Cached copy").
- **Keyboard:** reader is in the `F6` cycle; `Tab` reaches pill then action
  bar; `n`/`p` next/previous message; body region scrollable by keyboard.
- **A11y:** pill is a button with severity+summary `aria-label`; remote-content
  opt-in is a real button announcing state; attachments list uses list semantics.

## 5. Composer (`KIWI-UI-018`)

- **Fields:** From selector (per-account identity + alias), To/Cc/Bcc chips
  with address validation, subject, body (rich-text with plain-text fallback;
  rich editor is contenteditable with toolbar: bold/italic/lists/links/quotes),
  attachment well (drag-drop + picker, per-file size, total-size guard),
  send-options split button (Send now / Send later / Schedule).
- **Policy banner (S-07, re-anchored):** inline infobar below addressing —
  `warn` (amber, send allowed) / `block` (red, Send + `Ctrl+Enter` disabled
  until offending recipients removed) / `checking` (fail-closed for
  block-policies) / `error` (service unreachable → block-policies stay blocked
  with "Policy check unavailable"). Banner carries the scope-honesty line:
  "Blocked in this client. Organization-wide enforcement happens at the mail
  gateway." Per-recipient "Remove" buttons; `aria-disabled` + describedby on Send.
- **Templates (`KIWI-UI-022`):** snippet picker (`Ctrl+T` or toolbar) inserting
  named templates with `{{placeholders}}` tab-stops; manage (create/edit/
  delete/duplicate) in Settings (§8). No auto-send of templates.
- **Send later / scheduled (`KIWI-UI-021`):** schedule popover (preset slots +
  custom datetime, timezone shown); scheduled mail lives in Scheduled folder
  with edit/cancel; outbox worker sends when due (offline at due time → sends
  on reconnect, labeled "Delayed — sent HH:MM").
- **Undo send (`KIWI-UI-021`):** every send enters a grace window (default 10 s,
  configurable 5/10/20/30 s in Settings): toast with countdown + Undo button;
  message sits in Outbox "sending in Ns" state; Undo returns it to Drafts.
- **States:** editing / sending (disabled chrome, cancellable in grace
  window) / grace-countdown / scheduled-saved / send-failed (error + Retry +
  preserved draft) / blocked (policy) / offline (queued, "Will send on
  reconnect").
- **Keyboard:** `Ctrl+Enter` send (announces block reason when blocked),
  `Ctrl+S` save draft, `Esc` closes (dirty → save/discard confirm), `F6`
  reaches banner; template placeholders tab-stop in order.
- **A11y:** banner `role="alert"` on block / `role="status"` on warn; grace
  toast is a live region with one announcement, not a countdown spam;
  editor toolbar buttons labeled; attachments announced on add/remove.

## 6. Productivity surfaces detail

- **Snooze (`KIWI-UI-020`):** row/reader action → popover (Later today /
  Tomorrow / Next week / Pick date-time); snoozed mail leaves the inbox for a
  Snoozed folder and returns (unread, "Snoozed" badge) at due time; works
  offline (local scheduler); empty-state explains where snoozed mail went.
- **Unified inbox:** see §2 (`015`).
- **Send later / undo send / templates:** see §5 (`021`, `022`).
- Deferred (NOT v2): read receipts, link/open tracking, send-side "did they
  read it" — requires owner sign-off per ARCHITECTURE.md §4.

## 7. Account setup wizard (`KIWI-UI-019`)

- **Flow (4 steps, resumable):** 1) Email address (+ display name) → 2) Provider
  auto-detect (well-known domains) or Manual (IMAP/SMTP/POP3 host/port/security
  mode: SSL-TLS / STARTTLS / plaintext-with-warning) → 3) Credentials
  (password or OAuth2 browser flow; OAuth tokens stored by backend, never shown)
  → 4) Verify (test SMTP send-path + IMAP/POP3 login, TLS observation captured
  → immediate security summary: TLS version/cipher/chain status shown inline,
  failures named per-field) → Done (folder list + first sync starts).
- **Security-first touches:** security-mode selector defaults to the strongest
  available; choosing plaintext requires an explicit "I understand" checkbox
  and the account opens with a persistent `danger`-level banner until upgraded;
  certificate warnings during setup show fingerprint + reason with
  Accept-once/Reject (decision logged to audit).
- **States per step:** idle / checking (async verify with cancel) / success /
  field-error (inline, named fields) / fatal (server unreachable → keep inputs,
  Retry). Progress is a step indicator, resumable after close.
- **Keyboard:** full tab order, step buttons labeled ("Step 2 of 4: Server"),
  error summary region receives focus on failed verify.
- **A11y:** `aria-current="step"` on the indicator; password field has
  show/hide toggle with announced state; OAuth step explains the browser
  handoff in text.

## 8. Settings (`KIWI-UI-023`)

- **Sections (left nav):** General (theme, language, grace-window length,
  default send-later timezone) → Accounts (per-account server/security/identity
  edit, re-verify, remove) → KIWI Security (minimum-TLS policy selector,
  lock-policy sensitivity, trusted devices list → pairing dialog S-12, event
  history link → S-10) → Templates (CRUD) → Notifications → Privacy (remote
  content default, receipt/tracking kill-switches locked OFF pending sign-off)
  → Advanced (local data location, export, reset).
- **Behavior:** instant-apply with per-row confirmation state ("Saved HH:MM:SS");
  destructive actions (remove account, revoke device, reset data) use confirm
  dialogs naming the target; RBAC-denied rows (managed/org policy) render
  disabled with "Managed by your organization" text.
- **Keyboard/a11y:** nav is `role="navigation"` with `aria-current`; every
  control labeled; section headings hierarchical.

## 9. Security surfaces (v1 S-01…S-12, re-anchored to our frontend)

v1 semantics carry over; only the host anchors change (no Thunderbird chrome).

| ID | Surface | New anchor in kiwi-app | Notes vs v1 |
|----|---------|------------------------|-------------|
| S-01 | Message security pill | Reader header (§4) + list glyph (§3) | Same severities/states; severity = worst finding for delivering session |
| S-02 | Trust status chip | Top bar + sidebar account node | `role="status"` on escalation only; text always present |
| S-03 | Account security panel | Settings → KIWI Security → per-account card + Account view panel | TLS/cipher/KEX/FS/cert summary, last-scan, Re-scan (S-09), Event history (S-10) |
| S-04 | Finding-detail dialog | Modal from pill/panel/diff/event rows | Fixed order: severity→session→evidence (verbatim, copyable)→impact→remediation→AI collapsible (labeled non-authoritative)→finding ID + engine version; "Evidence unavailable — finding not confirmed" when empty |
| S-05 | Lock-screen overlay | Full-app overlay above all panes | KIWI mark per §10; reason category only; Verify (S-06) + Retry trust check; content panes inert; `role="alertdialog"`; `Esc` never unlocks |
| S-06 | Authenticator dialog | Modal above S-05 / standalone enrollment test | Event-bound label ("Unlock mailbox"), device name + fingerprint tail, expiry countdown, waiting/approved/denied/expired/error; QR black-on-white always |
| S-07 | Composer policy banner | Composer infobar (§5) | warn/block/checking/error + scope-honesty line |
| S-08 | Certificate viewer | Sub-dialog of S-03/S-04 | Leaf+chain cards, per-hop status, PEM toggle |
| S-09 | Re-scan / diff | S-03 section + results dialog | new/resolved/unchanged groups, progressbar, cancellable |
| S-10 | Security event center | App-nav view ("Security"), table + filters + JSON export | Real `<table>` semantics, result-count live region |
| S-11 | Local admin UI | Standalone localhost app (Agent 4 builds, Agent 5 reviews a11y/responsive) | ≥900px two-pane rule, confirm dialogs, RBAC-denied text |
| S-12 | Device pairing dialog | Settings → KIWI Security → Devices → "Add device" | QR + manual fallback; no key material displayed |

## 10. Brand assets & theme tokens (`images/` — READ-ONLY)

Audit baseline from T-005 still holds (sizes/hashes in agent status log v1 entry):

| Asset | Size | Role |
|-------|------|------|
| `logo.svg` / `logo.png` | 1200×1200 | Primary mark: lock screen (light), About, setup-wizard welcome, account avatar fallback |
| `favicon.svg` / `favicon.png` | 1200×1200 badge | Small sizes (<32px): sidebar mini-mark, window/app icon, chip glyph base |
| `banner.svg` / `banner.png` | 1800×1200 (3:2) | Welcome/first-run header, S-10 empty-state art; letterbox, never crop to square |
| `black_bg.png` | 1200×1200 dark mark | Dark-surface mark: lock screen dark theme, splash; never on light backgrounds; no SVG exists — request from owner if vector needed, do NOT auto-trace |

Sampled palette (bucketed 4-bit render of PNGs, 2026-09-19 — approximate,
final hexes to be lifted from SVG sources at T-112 theme build):

- near-white `#f0f0f0`-family backgrounds (light theme base)
- black `#000000`-family (dark theme base, banner ground)
- amber/gold `#e0b030`-family (brand accent → warning + focus-ring family)
- red-orange `#d05030`-family (brand secondary → danger family)
- neutral greys `#606060`/`#808080` (secondary text/borders)

Theme token plan (CSS custom properties, `[data-theme="light"|"dark"]` root):

- `--kiwi-brand` (amber), `--kiwi-brand-strong` (red-orange),
  `--kiwi-secure/warning/danger/unknown` (+ `-fg` text variants, 4.5:1 verified
  both themes), `--kiwi-surface-*` (app/sidebar/card/input), `--kiwi-text-*`
  (primary/secondary/disabled), `--kiwi-focus` (visible ring,
  `:focus-visible` everywhere), `--kiwi-mark` (asset swap: `logo.*` light /
  `black_bg.png` dark — never CSS-invert the artwork).
- Severity is never color-only: icon shape + text label carry meaning;
  high-contrast theme check per §11.

Brand rules: reuse supplied assets, no replacement logo; SVG first in UI, PNG
where SVG unsupported; mark ≥16px (text "KIWI" below that), lock mark ≥96px,
banner ≥320px wide; derived rasters (ICO/ICNS) generated at build time, never
committed over `images/`.

## 11. Global behavior rules

- **Noise budget:** one persistent indicator per account (§7 S-02) + one per
  open message (S-01). No toasts for `secure`; warnings in place; only
  `danger` + `locked` may notify once.
- **Fail-closed display:** unknown/error IPC states render grey/error, never
  green; stale data timestamped ("Last known …").
- **Copy tone:** factual ("TLS 1.0 negotiated — upgrade the server"), no FUD
  ("compromised", "hacked"); endpoint states say "trust reduced".
- **Performance targets:** list scroll 60fps (virtualized), indicator paint
  ≤100 ms after message render, panel open ≤300 ms to first paint, IPC fetch
  async and never blocking message display.
- **Reduced motion:** `prefers-reduced-motion` honored (static "Working…"
  fallbacks for spinners/progress).

## 12. Accessibility + workflow checklist (mandatory per UI change)

- [ ] Core workflows unaffected: setup, list, open, compose, send, receive,
      folders, unified inbox, search, contacts, attachments, snooze,
      send-later, undo-send, templates, reconnect, offline/online.
- [ ] Error state designed + reachable (IPC down, sync fail, send fail,
      policy unreachable, expired challenge, failed scan) with retry path.
- [ ] Loading state designed (skeleton/spinner, cancellable where long).
- [ ] Locked state: content inert, unlock operable, focus managed.
- [ ] Keyboard: full reachability, visible focus, dialog trap + `Esc` return,
      `F6` pane cycle, app shortcuts + `?` help.
- [ ] Screen reader: names/roles/severity-as-text; live regions sparse and correct.
- [ ] Overflow/clipping: 200% zoom, 320px narrow window, long addresses/cert
      strings wrap/ellipsize with full text available.
- [ ] Dark + light + high-contrast themes checked per surface.
- [ ] No secrets in strings, tooltips, screenshots, fixtures.
- [ ] Brand assets per §10; no new logo invented.

## 13. Open questions → Lead / other agents

1. Lead (T-110): Tauri IPC command names + event channels — spec §1–§9 name
   data needs; `ui-surfaces.md` §3 lists required fields. Confirm on shell land.
2. Agent 2: `SecuritySession`/`TlsObservation`/finding payload field names
   (T-101…T-106, T-002) — UI treats all fields optional, falls back to
   `unknown`/stale.
3. Agent 4: policy evaluation payload for S-07 (T-108) + mail-flow event shape
   (T-109) + admin-UI split for S-11 (Agent 4 builds, Agent 5 reviews).
4. Agent 3: finding/evidence schema + live-session adapter (T-107); max evidence
   length + display redaction rules.
5. Agent 6: client-layer test matrix + UI smoke harness (T-113/T-114); fixture
   transcripts the wizard/sync states can demo against.
