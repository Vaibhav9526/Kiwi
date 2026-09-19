# KIWI-in-Thunderbird — UX Spec (T-005)

> Owner: Agent 5 (OpenCode Muse 1.3 #1). Status: Phase 0 draft.
> Master prompt: `prompt.md`. Architecture: `docs/ARCHITECTURE.md`.
> Surface registry: `docs/contracts/ui-surfaces.md`.
> Constraint: Thunderbird source (`source/`, `source/comm/`) is still being
> acquired — this spec defines **where** KIWI surfaces live and **how** they
> behave. No Thunderbird code is modified in T-005.

## 0. Design principles (prompt.md §2, §17)

1. **Thunderbird first.** KIWI adds small, native-feeling security affordances
   inside existing windows (3-pane mail tab, message header, Account Settings,
   compose window, status bar). No dashboard-app redesign, no new top-level
   application window for daily use.
2. **Quiet by default, visible when useful.** Normal secure state = a single
   unobtrusive indicator. Warnings, lock state, policy blocks, and
   authenticator requests are the only things allowed to interrupt.
3. **Evidence one click away.** Every indicator links to a finding-detail view
   showing weakness → evidence → impact → remediation (prompt.md §1).
4. **Deterministic display.** UI renders what `kiwi-core` / `kiwi-forensics`
   report. UI never invents severity, never claims compromise detection
   (see `docs/SECURITY.md` rules 1–3).
5. **Locked means locked.** In lock state the UI must prevent sensitive mailbox
   access (message body/attachments/compose-send), not merely hide it.

---

## 1. Surfaces

### S-01 — Per-message connection-security indicator (message header + thread pane)

- **Location:** message header bar (adjacent to the existing From/Date row,
  right-aligned pill) + optional 16px icon column in the thread pane
  (off by default; enabled via View → Threads → KIWI Security column).
- **Trigger conditions:**
  - Shown for every open message once a `SecuritySession` exists for the
    account/server that delivered it.
  - Severity = worst deterministic finding for that message's receiving
    session (from `kiwi-core` trust evaluation / `kiwi-forensics` report).
- **States:**
  - `secure` (green shield-check): TLS ≥ 1.2, valid chain, strong cipher,
    forward secrecy. Tooltip: "Secure connection — TLS 1.3, …".
  - `warning` (amber shield-exclamation): weak but functional (e.g. TLS 1.0/1.1,
    non-FS cipher, soon-expiring cert). Tooltip summarizes top finding.
  - `danger` (red shield-x): plaintext, STARTTLS stripped/downgraded,
    invalid chain. Tooltip summarizes.
  - `unknown` (grey shield-question): no session data yet (local folders,
    pre-KIWI archive, IPC unavailable). Tooltip: "No connection data".
  - `loading` (spinner): session evaluation in flight (< 2 s expected).
  - `error`: IPC/service failure — "Security check unavailable", never
    presented as secure.
- **Keyboard path:** `Tab` reaches the pill in the message header; `Enter`/`Space`
  opens S-04 (finding detail). Thread-pane icon is decorative (`aria-hidden`),
  detail is reached from the header pill.
- **A11y:** pill is a `<button>` with `aria-label` including severity + short
  summary (e.g. "Connection security: warning. TLS 1.0 negotiated. Activate
  for details."). Never color-only: icon shape + text label differ per state.
- **Theme:** uses Thunderbird CSS variables (`--in-content-*`, theme-aware
  shield icons); amber/red/green pass 4.5:1 on both light and dark themes.
  High-contrast mode: border + text label carry the meaning.

### S-02 — Account security chip (folder pane + status bar)

- **Location:** folder-pane account row (16px trailing icon) + status-bar
  right section (text chip: "KIWI: Secure" / "KIWI: 2 warnings" / "KIWI: Locked").
- **Trigger conditions:** reflects the account's current session trust from
  `kiwi-core` (worst open session / lock state). Updates on session change,
  re-scan completion, lock/unlock events.
- **States:** mirror of S-01 severities + `locked` (padlock, see S-05).
  Status-bar chip text is always present (no icon-only meaning).
- **Keyboard path:** status-bar chip is focusable; `Enter` opens S-03 (account
  security panel). Folder-pane icon is `aria-hidden` (chip is the operable path).
- **A11y:** `role="status"` live region for severity *escalations only*
  (de-escalations announce on focus, not via live region, to avoid noise).
- **Theme:** same token scheme as S-01; chip background uses
  `color-mix()` tints of the severity color so it adapts to light/dark.

### S-03 — Account security panel

- **Location:** new section "KIWI Security" inside Account Settings for the
  selected account (below the existing server/security rows), plus a read-only
  summary card in the Account Hub / account central page if present in this
  Thunderbird version (exact XUL/HTML file mapped in T-007).
- **Contents:** negotiated TLS version, cipher suite, key exchange, forward
  secrecy, cert summary (subject/issuer/expiry, "view full chain" → S-08),
  last-scan time, finding counts by severity, policy name in force,
  "Re-scan now" button (→ S-09), "Event history" link (→ S-10).
- **Trigger conditions:** always present for IMAP/POP3/SMTP accounts;
  placeholder `unknown` state for Local Folders / RSS / newsgroup accounts
  ("Not applicable to local folders").
- **States:** normal / loading (skeleton rows while IPC fetches) / error
  (service unreachable → retry button; cached last-known values labeled
  "Last known, HH:MM" — never presented as current).
- **Keyboard path:** native Account Settings tab order; section heading is a
  real heading (`h2`/`caption`) so screen-reader and `F6`-pane navigation work.
- **A11y:** definition-list semantics (`<dl>`) for key/value rows; expiry and
  severity text are literal text, not icon-only.
- **Theme:** inherits Account Settings page styles; no custom background.

### S-04 — Finding-detail view

- **Location:** modal dialog launched from S-01 pill, S-03 finding rows, S-09
  diff rows. (Dialog, not a new tab — keeps mail context visible behind.)
- **Contents (fixed order):** severity + title → affected session
  (protocol/server/port/STARTTLS/TLS version/cipher) → evidence block
  (verbatim, monospace, copyable) → impact (one paragraph) → remediation
  (numbered steps) → "AI explanation" collapsible (only if AI layer enabled;
  labeled "AI-generated, not authoritative") → finding ID + engine version.
- **Trigger conditions:** opened on demand; shows exactly one finding.
  Prev/Next buttons page through the session's finding list.
- **States:** normal / loading (finding fetch) / error (finding unavailable).
  Evidence block always shows raw values; if evidence is missing the dialog
  states "Evidence unavailable — finding not confirmed" (per SECURITY.md
  rule 2: never display evidence-free findings as confirmed).
- **Keyboard path:** focus trap while open; `Esc` closes and returns focus to
  the invoking control; Prev/Next are buttons in tab order; evidence `<pre>`
  region is scrollable via keyboard.
- **A11y:** `role="dialog"` + `aria-modal="true"` + labelledby the finding
  title; severity announced in the title string.
- **Theme:** standard Thunderbird dialog styling; evidence `<pre>` uses the
  code/monospace treatment of the host dialog.

### S-05 — Native lock screen (trust-reduced lock state)

- **Location:** full mail-window overlay (covers 3-pane + tabs), rendered by
  Thunderbird chrome — not a web page, not dismissible by DOM inspection from
  content scope.
- **Trigger conditions:** `kiwi-core` lock policy fires (endpoint-trust drop,
  suspicious remote-session indicators, admin lock). Overlay appears within
  1 s of the lock event; a status-bar "KIWI: Locked" chip (S-02) persists.
- **Contents:** KIWI lock mark (see §3, `black_bg.png` on dark / `logo.png`
  on light), "Mailbox locked" heading, short reason category (e.g. "Untrusted
  device posture" — never raw sensor dumps), "Verify with authenticator"
  button (→ S-06), "Retry trust check" secondary button, admin contact hint
  if org policy sets one.
- **States:** `locked` / `authenticator-waiting` (S-06 embedded or linked) /
  `unlocking` (spinner, inputs disabled) / `unlock-failed` (reason + retry;
  attempt counter visible after 3 failures) / transient `error`.
- **While locked:** message list, preview pane, tabs with message content,
  compose send, attachment open/save, address-book details, and search
  previews are inert (no message bodies readable). Folder structure and the
  lock UI itself remain visible so the product still looks like Thunderbird.
- **Keyboard path:** on lock, focus moves to the dialog heading; `Tab` cycles
  Verify/Retry only; `Esc` does NOT unlock (announces "Mailbox remains
  locked").
- **A11y:** `role="alertdialog"`, reason announced on open; countdown/attempt
  text is plain text; reduced-motion respected (no animated lock art).
- **Theme:** follows Thunderbird light/dark; lock mark swaps asset
  (`logo.png` light, `black_bg.png` dark) so the mark is never invisible.

### S-06 — Authenticator waiting / verification dialog

- **Location:** modal dialog above S-05 (or standalone if invoked from
  Account Settings → device enrollment test).
- **Contents:** purpose line ("Approve sign-in on your KIWI authenticator"),
  device name (truncated fingerprint, e.g. "Pixel 8 · ends 9F3A"), 6-digit
  or QR pairing code where the protocol requires it, countdown to challenge
  expiry, Approve/Deny state once the device responds, Cancel button.
- **Trigger conditions:** unlock flow, new-device enrollment verification,
  step-up verification for policy-gated send. Challenge is bound to
  device + session + event (SECURITY.md rule 10); dialog shows the event
  being approved ("Unlock mailbox", not a generic "Approve?").
- **States:** `waiting` (spinner + countdown) / `approved` (auto-continues,
  brief confirmation) / `denied` (reason + return to S-05) / `expired`
  (explicit "Code expired — request a new one", replay of the old code must
  fail) / `error` (transport failure → retry).
- **Keyboard path:** focus trap; Cancel is reachable first via `Shift+Tab`
  from the heading; countdown is `aria-live="off"` with a polite one-time
  "30 seconds remaining" note to avoid screen-reader spam.
- **A11y:** the approved/denied/expired transition is announced via a
  `role="status"` line; pairing codes use monospaced, letter-spaced text
  with `aria-label` reading digits grouped.
- **Theme:** standard dialog theme; QR code (Phase 4) always rendered black
  on white with a white quiet-zone margin even in dark mode (scannability).

### S-07 — Policy-violation composer warning

- **Location:** inline banner at the top of the compose window (below
  addressing, above body) + blocking confirm-dialog at Send when policy
  = block; non-blocking warning style when policy = warn.
- **Trigger conditions:** recipient-domain allow/deny evaluation and
  minimum-TLS/policy checks from `kiwi-admin` policy contract fire on
  addressing change and at Send. Evaluation is per-recipient; the banner
  lists offending addresses literally.
- **States:** `warn` (amber banner, Send allowed, banner persists) / `block`
  (red banner, Send disabled until offending recipients removed; Send hotkey
  `Ctrl+Enter` announces the block) / `checking` (brief skeleton while policy
  service responds; Send allowed only after evaluation completes for block
  policies — fail-closed) / `error` (policy service unreachable → treat as
  block for block-policies with "Policy check unavailable" text; never
  silently allow).
- **Keyboard path:** banner is focusable (`F6` pane cycle reaches it), lists
  offending addresses as text, "Remove" button per address; Send button has
  `aria-disabled` + describedby the banner id when blocked.
- **A11y:** banner `role="alert"` on block only (warn uses `role="status"`);
  never rely on red/amber alone — text states "Blocked"/"Warning".
- **Theme:** Thunderbird infobar patterns (same as attachment-blocked and
  remote-content bars) so it reads as native compose UI.
- **Honesty rule:** banner text states enforcement scope — "Blocked in this
  client. Organization-wide enforcement happens at the mail gateway."
  (prompt.md Agent 4 note: never present UI-only block as complete
  organizational enforcement.)

### S-08 — Certificate details view

- **Location:** sub-dialog of S-03 / S-04 ("View certificate"), reusing
  Thunderbird's existing certificate viewer patterns where the mapped source
  allows (T-007 decides reuse vs. KIWI dialog).
- **Contents:** leaf + chain (one card per cert: subject, issuer, serial,
  validity window, fingerprint SHA-256, signature algorithm, key usage),
  chain-status line per cert (OK/expired/self-signed/hostname-mismatch with
  the failing field named), raw PEM toggle (copyable).
- **States:** normal / loading / error (chain unavailable → which hop is
  missing is stated).
- **Keyboard path:** cert cards in tab order; PEM `<textarea readonly>`
  selectable via keyboard; `Esc` returns to parent dialog focus.
- **A11y:** status text per cert, never icon-only; expiry dates in full
  date format, not relative-only.
- **Theme:** inherits viewer/dialog theme; fingerprints monospace.

### S-09 — Re-scan / diff UI

- **Location:** section inside S-03 + results dialog after a re-scan; diff
  entries link to S-04 for per-finding detail.
- **Contents:** "Re-scan now" + scope selector (this account / all accounts) +
  results list grouped new/resolved/unchanged with severity chips +
  scan timestamps (before → after) + engine version line.
- **Trigger conditions:** manual button; automatic re-scan offered (button,
  not auto-run) after remediation steps are viewed in S-04.
- **States:** `idle` / `scanning` (progress bar, cancellable; partial results
  labeled "partial") / `done` / `error` (failed scope named, prior results kept).
- **Keyboard path:** results are a list; each row's "Details" button opens S-04;
  focus returns to the row on dialog close.
- **A11y:** progress uses `role="progressbar"` with min/max/now; diff groups
  are headings ("New (2)", "Resolved (1)") so AT users can jump.
- **Theme:** standard dialog/list styling; severity chips reuse S-01 tokens.

### S-10 — Security event center / audit history

- **Location:** new Thunderbird tab ("KIWI Security", opened from S-02 chip →
  "Event history" or AppMenu → KIWI section). Read-only list; this is the one
  surface allowed to look slightly dashboard-like, kept inside a Thunderbird
  content tab so back/forward and tab-close behave natively.
- **Contents:** chronological event rows (time, account, category, severity,
  summary, "Details" → S-04/S-08 as applicable); filter by account + severity;
  export button (JSON forensic export, Phase 5 format from `kiwi-forensics`).
- **States:** normal / loading / empty ("No security events for this filter")
  / error. Export states: ready/exporting/done/failed with the failure named.
- **Keyboard path:** filter controls + table in tab order; table uses real
  `<table>` semantics with sortable column headers as buttons.
- **A11y:** table has caption + scope headers; live region announces result
  counts after filtering ("14 events shown").
- **Theme:** `about:`-style content theme, follows light/dark automatically.

### S-11 — Local admin UI surfaces (Phase 6+, responsive web)

- **Location:** standalone localhost React+TS app (`kiwi-admin-ui`), NOT inside
  Thunderbird chrome. Agent 4 owns data/API; Agent 5 owns layout/a11y review.
- **Phase 0 scope:** only responsive/a11y ground rules are fixed here —
  mobile-first single column → desktop two-pane at ≥ 900px; every data table
  gets caption + text severity; all destructive actions (revoke device,
  block domain) require a confirm dialog naming the target; RBAC-denied
  controls render disabled with "Requires admin role" text (never hidden
  without explanation).
- **Keyboard/a11y/theme:** same rules as S-10 plus visible focus rings,
  `prefers-reduced-motion` support, and dark-mode parity checklist (§4).

### S-12 — Device pairing / enrollment dialog (Phase 4)

- **Location:** modal from Account Settings → KIWI → Devices → "Add device".
- **Contents:** QR code (local pairing, no push dependency for dev), manual
  code fallback, device-name field, "Waiting for device…" state → success /
  failure. Private keys stay in platform keystore; dialog never displays key
  material (SECURITY.md rule 8).
- **States:** `showing-code` / `waiting` / `paired` / `expired` / `error`.
- **Keyboard path:** focus trap; manual code in a readonly labelled field;
  `Esc` cancels pairing (old codes invalidated).
- **A11y/theme:** same QR-on-white rule as S-06; expiry announced once.

---

## 2. Brand asset audit (`images/` — READ-ONLY, never overwritten)

Verified 2026-09-19 by direct inspection (sizes via .NET `System.Drawing`;
hashes recorded for change detection). No file was modified.

| Asset | Format | Dimensions | Size | Role / usage guidance |
|-------|--------|------------|------|------------------------|
| `logo.svg` | SVG (Affinity export, `viewBox 0 0 1200 1200`) | 1200×1200 (square) | 25,016 B | **Primary mark.** Use for all chrome UI (S-05 light, About dialog, Account Hub card). SVG scales to 16/24/32px without re-rasterizing. |
| `logo.png` | PNG, 1200×1200 | 1200×1200 | 184,216 B | Fallback where SVG is unsupported (installer, notifications). Downscale, never upscale. |
| `favicon.svg` | SVG (rounded-square badge variant, `viewBox 0 0 1200 1200`) | 1200×1200 | 25,457 B | Tab/app icon, S-02 chip at 16px, dialog title-bar icons. Badge shape reads at small sizes — prefer over `logo.svg` below 32px. |
| `favicon.png` | PNG, 1200×1200 | 1200×1200 | 186,523 B | Same fallback rule as `logo.png`. |
| `banner.svg` | SVG (wide, `viewBox 0 0 1800 1200`, 3:2) | 1800×1200 | 17,071 B | Welcome/first-run page header, S-10 empty-state art, admin-UI login header. Never crop to square — letterbox instead. |
| `banner.png` | PNG, 1800×1200 | 1800×1200 | 163,559 B | Same fallback rule; use for email-safe contexts needing raster. |
| `black_bg.png` | PNG, 1200×1200 (dark-background mark variant) | 1200×1200 | 167,372 B | **Dark-surface mark.** S-05 lock screen dark theme, splash screens, high-contrast-dark. Never place on light backgrounds (use `logo.*` there). No SVG exists — request one from the owner before shipping if vector dark variant is needed; do NOT auto-trace. |

SHA-256 (baseline — re-run `Get-FileHash images\*` if tampering is suspected):

- `banner.png` `7FD638F3…213B20`, `banner.svg` `843F9951…5AAB`
- `black_bg.png` `E51CE141…8AC6`, `favicon.png` `9345F22C…15D`
- `favicon.svg` `3DCB8FD4…57B1`, `logo.png` `39A2CD06…D10`
- `logo.svg` `4A5E7582…0687` (full hashes in agent status log)

### Brand rules for all KIWI UI work

1. Reuse these assets; do not invent a replacement logo (prompt.md §4).
2. SVG first in product UI; PNG only where the host cannot render SVG.
3. Small sizes (< 32px): use `favicon.*` (badge variant), not `logo.*`.
4. Dark surfaces: use `black_bg.png`; light surfaces: `logo.*`. Never CSS-invert
   the mark to fake a theme variant.
5. Minimum legible sizes: mark ≥ 16px, lock-screen mark ≥ 96px, banner ≥ 320px
   wide. Below these, use text ("KIWI") instead of the artwork.
6. `images/` stays read-only for every agent; new derived assets (ICO/ICNS,
   16/32px rasters) are generated at build time into the build tree, never
   committed over `images/`.

---

## 3. Global behavior rules

- **Noise budget:** at most one persistent indicator per account (S-02) + one
  per open message (S-01). No toasts for `secure` states; warnings surface in
  place; only `danger` + `locked` may use a one-time notification.
- **Fail-closed display:** unknown/error IPC states render as grey/error, never
  as green. Stale data is always timestamped ("Last known …").
- **Copy tone:** factual, deterministic ("TLS 1.0 negotiated — upgrade the
  server"), no FUD verbs ("compromised", "hacked", "protected from all threats").
  Endpoint states say "trust reduced", never "malware detected".
- **Performance:** indicators render from cached session state synchronously;
  IPC fetch is async and must not block message display. Target: indicator
  paint ≤ 100 ms after message render; panel open ≤ 300 ms to first paint.
- **Reduced motion:** all spinners/progress honor `prefers-reduced-motion`
  (static "Working…" text fallback).

---

## 4. Accessibility + workflow checklist (mandatory per UI change)

Every KIWI UI change must be verified against this list (prompt.md §6 Agent 5,
§13–§14). Record results in the implementing task's status entry.

- [ ] Normal Thunderbird workflows unaffected: list, open, compose, send,
      receive, folders, search, contacts, attachments, setup, reconnect,
      offline/online (run the TESTING.md E2E set where the build exists).
- [ ] Error state designed and reachable (IPC down, policy service down,
      expired challenge, failed scan) — with retry path.
- [ ] Loading state designed (skeleton/spinner, cancellable where long).
- [ ] Locked state: sensitive content inert, unlock path operable, focus managed.
- [ ] Keyboard: all actions reachable, focus visible, focus trap + `Esc` return
      for dialogs, `F6` pane cycling preserved.
- [ ] Screen reader: names + roles + severity-as-text verified (no color-only
      or icon-only meaning; live regions used sparingly and correctly).
- [ ] Overflow/clipping: 200% zoom, 320px narrow window, long addresses/cert
      strings wrap or ellipsize with full text available.
- [ ] Dark + light + high-contrast themes checked for every new surface.
- [ ] No secrets in UI strings, tooltips, screenshots, or fixtures.
- [ ] Brand assets used per §2 rules; no new logo invented.

---

## 5. Open questions → Lead / other agents

1. T-007 (Lead): exact XUL/HTML/JS file paths for S-01 header bar, S-03
   Account Settings section, compose-window infobar slot, status-bar API —
   spec assumes standard Thunderbird extension points; adjust surface anchors
   after the source map lands.
2. Agent 2: field names of `SecuritySession` / finding payloads (T-002) —
   `ui-surfaces.md` §3 lists the UI's required fields; confirm or revise.
3. Agent 4: policy payload for S-07 (T-013) + admin-UI layout ownership split
   for S-11 (Agent 4 builds, Agent 5 reviews a11y/responsive).
4. Agent 3: finding/evidence schema (T-003) backs S-04/S-09 — UI renders
   `evidence` verbatim; confirm max length + redaction rules for display.
5. Agent 6: UI smoke-test harness for the checklist §4 (T-015).
