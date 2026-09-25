# Agent 12 — Status Log (Muse Spark, frontend owner kiwi-app/src)

> Append dated entries. Owns kiwi-app/src exclusively.

## 2026-09-25 — T-190b Mailspring archaeology done; build green

- **Status:** T-190b done. Delivered `docs/ui-mailspring-map.md` (tokens,
  component inventory, animation catalog A1–A24, layout maps for shell/
  sidebar/thread-rows/reader/composer/prefs, interaction states, T-191
  worklist) + `kiwi-app/src/mailspring-tokens.css` (clean-room
  `--kiwi-ms-*` tokens: colors light+dark, type, spacing, radii, shadows,
  motion ladder, reduced-motion kill-switch). `npm run build` green
  (tsc strict + vite, 55 modules). `src-tauri/` untouched. No commits made.
- **Legal:** reference/mailspring is GPL-3.0 — STUDY ONLY. Surveyed via 3
  read-only subagents + lead pass; all values paraphrased observations with
  file:line provenance; zero Mailspring code copied into our tree.
- **Key findings for T-191:** (1) Wide thread rows = c1–c5 icon/star/
  participants-200px/subject-flex/date/hover-actions @36px, narrow stacked
  @85px under ~540px — our stacked cards must become this grid. (2) Motion
  ladder 30ms→10s (nav 125ms, hover 150ms, popover 240ms overshoot, modal
  100ms veil + 360ms rise/untilt, toast 150ms lift, undo ring 10s linear).
  (3) Mailspring has NO prefers-reduced-motion handling — our kill-switch
  must cover all new tokens. (4) Keep flagship deep-black dark default;
  adopt light direction + sidebar/list/reader tonal structure. (5) Composer
  = modal + popout + plugin slot (send-later/undo hook); prefs = 6 tabs
  (General/Accounts/Identity/Appearance/Shortcuts/Mail Rules).
- **Files changed (created, mine only):**
  - `docs/ui-mailspring-map.md` — new (map + catalog + worklist).
  - `kiwi-app/src/mailspring-tokens.css` — new (opt-in; not yet imported —
    T-191 wires it, flagship untouched).
- **Commands run:** `npm run build` in kiwi-app (green, 55 modules, no new
  deps); `orca terminal --help` probe (send next).
- **Assumptions/limits:** token file intentionally unimported until T-191
  rebuild (zero visual change this task); dark `ui-dark` green accent noted
  but NOT adopted (flagship brand wins); tracking/open-receipt colors mapped
  as deferred per owner privacy gate.
- **Needs:** Lead to queue T-191 rebuild (owns kiwi-app/src, ready).
- **Next:** T-191 Mailspring-faithful rebuild per the map (sidebar, thread
  rows w/ hover actions, reading pane, modal composer, tabbed prefs,
  animations; preserve all IPC) → T-192 security re-integration.
