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

