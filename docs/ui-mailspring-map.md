# Mailspring UI Map — anatomy for the KIWI rebuild (T-190b)

> Source: `reference/mailspring/` checkout (app + internal_packages).
> **Legal: GPL-3.0 — STUDY ONLY.** No Mailspring code was copied into our
> tree; every value below is a paraphrased observation (behavior/tokens),
> rewritten as clean-room KIWI tokens in `kiwi-app/src/mailspring-tokens.css`.
> Purpose: layout/animation/component parity targets for T-191.
> Companion: `docs/ui-thunderbird-map.md` (workflow/shortcut reference).
> Survey method: 3 parallel read-only surveyors + lead verification pass.

## 1. Design tokens (observed → KIWI mapping)

### 1a. Type

| Token | Mailspring observation | KIWI target (own stack) |
|---|---|---|
| Base size | 14px, line-height 1.5 (~20px floor) | Keep 14px / 1.55 (existing) |
| Scale | tiny ~10.5 · smaller ~12 · small ~13 · large ~16 · larger ~18 | Same ladder (add `--kiwi-ms-text-*`) |
| Headings | H1/H2 ~24 · H3 ~20 · H4 ~18 · H5 14 · H6 ~12; H1 semi-bold, H2/H3 light | Keep our 650-weight tight headings; adopt H-scale for prefs/docs surfaces |
| Weights | 200 thin · 300 light · 400 normal · 500 medium · 600 semi-bold (700 on Windows for Segoe legibility) | Keep Inter stack; add 300/500 steps where missing |
| Sans stack | Proprietary sans → Helvetica → sans-serif; Windows: system-UI family | Ours stays `Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` (TB-map §14 compatible) |
| Serif / Mono | Georgia stack / DejaVu+Menlo+Monaco+Consolas+Courier stack | Adopt mono stack for evidence blobs (`ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace`) |
| Reading | Lead copy ~1.15× base, weight 300, LH 1.4; headings LH 1.1 | Adopt for reader subject/snippet hierarchy |

Provenance: `app/static/style/base/ui-variables.less` (≈lines 88–125),
`app/static/style/type.less`, `app/static/style/workspace.less` (≈694–700).

### 1b. Colors — light

| Role | Observed (light) | KIWI token maps to |
|---|---|---|
| Text primary / heading / link | near-black `#231f20` / slate `#434648` / blue `#419bf9` (hover/active darker `#3187e1`) | `--kiwi-ms-text`, `--kiwi-ms-text-heading`, `--kiwi-ms-link` |
| Text subtle / very-subtle | faded variants of primary | `--kiwi-ms-text-secondary/muted` |
| Surfaces | white primary · `#fdfdfd` off-primary · `#f6f6f6` secondary · `#6d7987` tertiary | `--kiwi-ms-bg`, `--kiwi-ms-surface`, `--kiwi-ms-surface-2/3` |
| Sidebar / panel | gray-lighter ≈ `#eee` family | `--kiwi-ms-sidebar` |
| List bg / border / hover | white / `#ddd` / darken ~4% | `--kiwi-ms-list-bg/border/hover` |
| Toolbar base | white darkened ~17.5% | `--kiwi-ms-toolbar` |
| Borders | primary darkened-white ~10%, secondary darkened-secondary ~10%, divider = secondary; input 1px faded primary | `--kiwi-ms-border`, `--kiwi-ms-border-strong`, `--kiwi-ms-divider` |
| Accent | blue `#419bf9`, active = mix-to-black 10%; button emphasis `#5b90fb`; icon gray `#919191` | `--kiwi-ms-accent`, `--kiwi-ms-accent-active` |
| Status | info blue-dark · success `#5cb346` · warning `#f0ad4e` · danger `#d9534f` | `--kiwi-ms-info/success/warning/danger` |
| Notifications | info `#009ec4` · success `#00ac6f` · warning `#ff4800` · error `#ca2541` · pending `#b4babd` | toast kind accents |
| Tracking | open `#7c19cc` (faded when unopened) · link-click `#d43353` | deferred (privacy-gated; no tracking without sign-off) |
| Search match / current | `#fff000` / `#ff8b1a` | `--kiwi-ms-search-match/current` |

### 1c. Colors — dark (two variants observed)

`ui-dark` (neutral dark):

| Role | Observed |
|---|---|
| BG primary / off-primary | `#212121` |
| Secondary / toolbar / panel | `#121212` |
| List bg / border | `#333` / `#383838` |
| Text / heading / thread-dim | `#eee` / `#fff` / `#aaa` |
| Input / dropdown | `#2e2e2e` / `#404040` |
| Accent / link | green `#58b660` |
| Borders | lighten ~10% off dark BGs |
| Reminder row | bg `#312856`, header text `#7d5bef`, border `#4d3b8a` |

`ui-darkside` (tinted dark, accent coral `#f18260`):

| Role | Observed |
|---|---|
| Sidebar | `#313042`; sidebar text = desaturated/lightened sidebar; active sidebar text `#ffffff` |
| Thread list / message list | `#ffffff` thread list; message list ≈ sidebar tinted 95% toward white |
| Active thread text | sidebar color; generic border = 10% faded sidebar |
| Traffic/swipe | danger `#ff5f56` · snooze/minimize `#fbd852` · archive/maximize `#8dd07d` |
| Alt palettes (commented) | Luna `#202C46`/`#39DFF8`, Zond `#333333`/`#F6D49C`, Gemini `#00203C`/`#F6B312`, Mercury `#555`/`#999`, Apollo `#3A1E15`/`#F6AA1C` |

**KIWI call (owner decision for T-191):** keep our flagship deep-black dark
(`#0e0e12` family, owner-approved T-145) as default; adopt Mailspring
*structure* (sidebar/list/reader tonal separation, tinted selection, accent
system) + light palette direction. Do NOT adopt darkside white-threadlist.

### 1d. Spacing / radii / shadows

| Group | Observed | KIWI mapping |
|---|---|---|
| Spacing unit | 14px standard; quarter ~3.5 · half ~7 · ¾ ~10.5 · double ~28 | `--kiwi-ms-space-*` (keep our rem scale alongside) |
| Sidebar margin | 15px | sidebar gutter |
| Component pad / icon pad / icon / line-height / radius | 10px / 5px / 16px / 25px / 2px | row/icon metrics |
| Button padding | base 5px/12px · large 9/16 · small 4/10 · xs 1/5 | button sizes |
| Radii | base 3px · large 5px · small 2px; Windows square 0; Linux toolbar 6px; macOS capsule (30px height); gumdrops 50% (14–15px) | `--kiwi-ms-radius-*` (we keep 8–14px flagship radii; use 3–6px for Mailspring-faithful dense controls) |
| Shadows | `rgba(0,0,0,0.15)` with 0/1px/4px/0 offsets + up variant; hairline via 0.5px four-way; button hairline + soft 1px; macOS toolbar inset rims + faint outer + soft drop | `--kiwi-ms-shadow-*` + hairline token |
| Borders | input 1px faded primary, focus accent + ~1.5px glow; toolbar bottom 1px; thread divider 1px list-border; message cards inset 1px; blurred toolbar lightened ~14% gradient | focus-ring + divider tokens |

### 1e. Accent / selection / unread / badges

- **Accent:** light blue `#419bf9` (active = darker mix); dark green `#58b660`;
  darkside coral `#f18260`. Theme picker maps active/panel to accent/sidebar.
- **Selection:** 17%-accent tint over list bg + 50% border; focused = solid
  active color; darkside selected = 90%-tint accent, blurred = 90%-tint
  sidebar, keyboard cursor = left accent edge.
- **Unread:** subject/participants semi-bold, snippet subtle; unread-dot icon
  asset recolored to accent in darkside (no separate dot hex — inherits accent).
- **Badges/counts:** pill min-height 15px, tiny font, small radius; default
  faded-subtle text + hairline; inbox/alt-count = filled active-on-active-bg
  (darkside: filled accent + sidebar text; normal: accent text + 50%-faded
  accent inset). Adopt: unread badge = filled accent pill; total = subtle outline.

## 2. Component inventory

Reusable primitives (`app/src/components/*` + internal packages):

| Family | Components | KIWI equivalent (own code) |
|---|---|---|
| Buttons/toolbars | ButtonDropdown, RovingTabIndexToolbar, MultiselectToolbar, CopyButton, metadata toggle; `btn/btn-toolbar/btn-send/btn-emphasis/btn-attach/btn-trash` conventions | Keep `.kiwi-btn-primary` (one-per-surface); add `btn-toolbar` + split Send dropdown for T-191 |
| Dropdowns/menus/popovers | Menu, DropdownMenu, MultiselectDropdown, FixedPopover, DatePickerPopover, emoji popover | Add popover primitive (240ms overshoot pop, §3) |
| Tokens/inputs | TokenizingTextField, ParticipantsTextField, AccountColorBar, ContactProfilePhoto, DateInput/TimePicker/DatePicker, Switch, ConfigPropContainer | Recipient tokens ≈ our chips; add account color bar + switch primitive |
| Tabs/focus | TabGroupRegion (IME-aware focus shift), KeyCommandsRegion, FocusContainer | Tabbed prefs via our router + roving tabindex |
| Lists/trees | MultiselectList, ListTabular(+Item), OutlineView(+Item), DisclosureTriangle, EditableList/Table, ScrollRegion, EmptyListState, SyncingListState, SwipeContainer, DropZone | OutlineView ≈ our folder tree (add disclosure twist + drop target); ListTabular ≈ thread rows |
| Chrome | Flexbox, ResizableRegion, Modal, RetinaImg, Spinner/SendingSpinner, InjectedComponent(Set), composer-editor toolbar + factories/plugins | Modal + resizable splitters + spinner for T-191 |
| Composer editor | ComposerEditorPlaintext vs Slate ComposerEditor, toolbar factories, plugins | Ours stays plaintext (no HTML send); toolbar = marker-wrap (T-151) |
| Package surfaces | account-sidebar, thread-list, message-list, composer, preferences, send-later, send-reminders, snooze, templates, signatures, link/open tracking, unsubscribe, notifications, activity, contacts, calendar, undo-redo | Map 1:1 to T-191 layouts (§4); tracking/snooze per existing owner gates |

## 3. ANIMATION CATALOG (durations / easings / triggers)

> All values paraphrased observations. KIWI implements its own
> `--kiwi-ms-motion-*` tokens (§3.3) — same ladder, own code.

| # | Trigger | Element | Duration | Easing / curve | Effect |
|---|---|---|---|---|---|
| A1 | Sheet push/pop | sheet stack | 125ms | enter ease-out, exit ease-in | Detail pane slides ~30px + fades |
| A2 | Generic view swap | opacity helper | 125ms | ease-out in / ease-in out | Quick fade |
| A3 | Deferred content | lazy-rendered content | 220ms | default (linear-ish) | Fade-in on mount |
| A4 | Toolbar button hover/press | Darwin toolbar btn | 120ms Darwin / 300ms Win32 | ease-out Darwin | Background tint shift; `:active` instant color elsewhere |
| A5 | List row reorder | list rows | 120ms | ease-out, `top` only | Rows glide on insert/remove |
| A6 | Selection bar drop | multiselect bar | 200ms | ease-in-out, opacity+top | Bar slides down from toolbar |
| A7 | Thread swipe | swipe backing + row | 150ms CSS tint/icon slide (linear); JS settle ~1400ms spring; 550ms reset delay if row gone | linear CSS; spring (freq ~360, friction ~440) in JS | Drag follows pointer (`translate3d`); release springs to 0/full-width; threshold ~110px; confirmed = saturated color |
| A8 | Message open/ready | message list container / wrap / item | 125ms container; 0s hidden → 100ms fade when ready; 100ms height | ease-in-out container; linear fade | Stays transparent until measured (no flash), then fades; expand/collapse = short height tween |
| A9 | Message actions/participants hover | action pill / spinner / participants | 100ms opacity + 150ms width/padding (50ms delay) | ease-in/out | Hover reveals action pill; pending swaps actions→spinner |
| A10 | Sidebar card | contact card | 100ms | ease-out, opacity | Fade in |
| A11 | Composer action-bar reveal | plugin slot / cover | 30ms opacity; 200ms `left` | default / ease-out | Cover wipes right to uncover plugins |
| A12 | Popover pop | fixed popover | 240ms | overshoot (~0.56,0.25,0.25,1.56), scale 0.87→1 + fade | Menus/tooltips spring-pop |
| A13 | Modal veil + dialog | modal container / dialog | 100ms veil; 360ms dialog shift/tilt + 240ms fade | ease-out both | Dialog rises ~10px, un-tilts from `rotateX(-7deg)` |
| A14 | Toast (undo/send) | undo-redo toast; notifications | 150ms in/out; sidebar activity height 400ms + 2s delay | ease-out in / ease-in out, ~10px vertical drift | Toast lifts while fading |
| A15 | Countdown ring | undo-send ring | 10s | linear forwards | Stroke draws down, warning color at end |
| A16 | Disclosure twist | chevron | 90ms | linear, transform | Rotates 0↔90° |
| A17 | Switch toggle | slide switch knob | 150ms | soft-out (~0.22,0.61,0.36,1) | Knob slides ~21px + track recolors |
| A18 | Spinner dots | spinner | 200ms fade; 1.1s loop (staggered) | linear fade; bouncy (~0.45,0.05,0.55,0.95) scale 0→1 | 4 dots pulse; `paused` freezes loop (CPU) |
| A19 | Scrollbar auto-hide | track/handle | 300ms opacity, 500ms hide delay (0s on hover/scroll/drag) | default | Track ghosts in only while interacting |
| A20 | Participant expand | profile card | 150ms | ease-in-out, height | Card grows |
| A21 | Draft send bar | draft progress | 1000ms width; 2s loop stripes | linear | Fills then shimmers |
| A22 | Grammar/sync/activity spinners | misc indicators | 0.8s / 1.4s spins; 3s border-pulse/ellipsis; 1s blink; 900ms clip + 225ms fade (825ms delay); 1s indicator loop | linear spins/pulses; ease blink | Rotation, border flash, staggered dots, dashboard wipe |
| A23 | Onboarding wizard | stepped art | 150ms all/width; 200ms opacity; 260ms custom (~0.65,0.05,0.36,1); 400ms all/width; 1–2s hero fades | ease-out/in, ease-in-out | Slides/fades per step |
| A24 | Micro (download/token/tooltip/empty) | attachment bar etc. | 300ms width (linear); 150ms opacity/margin; 50ms left/opacity; 1s opacity | linear / ease-in | Download fill, token field, tooltip, empty-state fade |

### 3.1 Required mappings for T-191

- **Hover:** row tint 120ms ease-out (§A4/A5); quick-actions fade 100ms (A9).
- **Thread open/close:** 125ms slide+fade for pane (A1); 100ms height tween for
  collapse + `N older messages` bundle (A8).
- **Composer slide:** modal 100ms veil + 360ms rise/untilt (A13); inline
  composer = 125ms fade (A2); action-bar wipe 200ms (A11).
- **Toast:** 150ms lift+fade in/out, 10px drift (A14); undo ring 10s linear (A15).
- **Button feedback:** hover tint 120ms; `:active` instant darken/translateY(1px)
  (ours already); focus-visible 2px accent outline, mouse-focus suppressed (A4).

### 3.2 Standard curves + duration ladder (adopt as tokens)

- Curves: `ease-out` entrances · `ease-in` exits · `ease-in-out` 100–200ms
  toggles · `linear` 90–150ms icon/tint/track + all loops.
- Sparing customs: pop (~0.56,0.25,0.25,1.56) 240ms · switch
  (~0.22,0.61,0.36,1) 150ms · spinner (~0.45,0.05,0.55,0.95) 1.1s ·
  onboarding (~0.65,0.05,0.36,1) 260ms · expand (~0,1,0.5,1) 500ms.
- Ladder: 30–50ms instant reveal · 90–125ms navigation/list/row ·
  150–200ms hover/switch/selection/composer-wipe ·
  220–360ms veil/modal/popover/scrollbar · 1s+ ambient/loop · 10s countdown.

### 3.3 Reduced motion (KIWI goes further)

Mailspring has **no** `prefers-reduced-motion` handling (grep returns zero;
all loops run unconditionally). KIWI already kills motion under
`prefers-reduced-motion` (theme.css) — T-191 must extend the kill-switch to
every new token (`--kiwi-ms-motion-*` forced to 0/neutral) + skip the 1s
outbox tick animation path.

## 4. Layout maps

### 4a. Workspace shell

Vertical stack: `header.sheet-toolbar` (order 0) + `Header` injection (1) +
`main` workspace (2, flex:1) + `footer` injection (3). Stacked sheets get
`inert` + 125ms stack transitions. Column order per mode:

| Mode | Columns (left→right) |
|---|---|
| Threads `list` | RootSidebar, ThreadList |
| Threads `split` | RootSidebar, ThreadList, MessageList, MessageListSidebar |
| Threads `splitVertical` | RootSidebar, ThreadList, MessageListSidebar |
| Thread sheet | MessageList, MessageListSidebar |

Column mechanics: each location resolves registered components, derives
min/max width, persists widths; widest column flex-fills (`flex:1`); left
columns get right resize handle, right columns left handle; resizable →
splitter else fixed/flex div with column ARIA meta. Toolbar mirrors columns
(per-column divs positioned to matching sheet-column offset/width on layout).
Depth > 0 adds back affordance; popout adds window title; RTL flips controls.

Declared widths: sidebar min 165 / max 250 · thread-list min 100 / max 3000 ·
message pane min 480 / unbounded (the flex filler) · popout composer min
480×250.

**KIWI target:** same 3-pane (`split`) + `list`/`splitVertical` switcher
(T-208 backlog covers the switcher; T-191 ships `split` + collapse). Add
persisted splitters (ours lacks them — TB-map §16 item 3).

### 4b. Sidebar (accounts + folders + unread badges)

Container: column flex → scroll region → AccountSwitcher + `Mailboxes` nav
section (OutlineView standard + user sections).

- **AccountSwitcher:** button + dropdown (account commands + Add/Manage).
- **Tree:** heading (title + add-item + show/hide collapse) + `role=tree` rows.
  Keys: Up/Down/Home/End + Left/Right expand/collapse + Enter/Space select.
- **Row:** treeitem (level/selected/expanded) → container → disclosure triangle
  + drop zone (selected/editing) → count box + icon + name/input → ••• action
  button → child group.
- **Standard sections:** single account = standard categories minus
  drafts/snoozed, `Unread,Starred` inserted at index 1, `Drafts` last;
  multi-account = aggregate inbox/important/sent/archive/all/spam/trash with
  per-account children labeled by account; plugin items with top-insert.
- **User sections:** hierarchy split on folder separator; Gmail-style
  (inbox-is-label) → Labels/tag icon else Folders/folder icon;
  `titleColor = account color`, collapsible, create-category on item-created.
- **Item model:** unread count only for inbox or `showUnreadForAllCategories`;
  inbox counter uses alt (filled) style; default collapsed; drag payload typed
  with account-prefix check; select focuses the mailbox perspective.
- **Context groups:** Mark All as Read · New Subfolder/Sublabel, Rename,
  Delete · Export .eml/.mbox.

**KIWI delta:** add AccountSwitcher dropdown, disclosure triangles,
alt-style inbox badge, `role=tree` semantics, account color bar prefix,
drag payload guard. Keep our unified inbox + muted pills.

### 4c. Thread rows — single-line with hover quick-actions (the core T-191 change)

Mode switch at ~540px list width: **Wide** (row height 36) vs **Narrow**
(height 85, two-column stacked).

Wide columns `c1..c5`:

| Col | Content | Width/behavior |
|---|---|---|
| c1 | star + important + injected icons | icon cell; click toggles star; states: star / unread+star-on-hover / replied-or-forwarded+star-on-hover / none+star-on-hover |
| c2 | participants (+ draft pencil) | ~200px; prefer From unless all-is-from-me then To; dedupe consecutive same; cap 3 (`first … last-2,last-1`); append `(N)`; account-color-bar prefix |
| c3 | labels + subject + snippet + attachment icon | flex 4; subject `dir=auto`; snippet subtle; paperclip when visible attachments |
| c4 | date | sent-vs-received timestamp (short string), injectable |
| c5 | hover quick-actions | injected; default Trash (order 110) + Archive (order 100), gated by can-archive/can-trash |

Narrow `cNarrow`: icons column (star + ≤1 injected + important) +
info column (participants row with pencil/spacer/attachment/timestamp,
subject, snippet+labels right-aligned).

Selection/toolbar: multiselect bar overlays toolbar (count + Clear);
list/thread toolbars show injected buttons only when focused/selected
non-empty. Extras: swipe archive/trash/snooze, canvas drag image, context
menu, syncing/empty footer states.

**KIWI delta (biggest):** rebuild rows from stacked From/subject/snippet cards
to this column grid (default set: icon/star/participants/subject+snippet/date;
hover reveals Trash/Archive + KIWI security shortcut). Sortable Date minimum;
column picker later. Keep threads/bulk/selection semantics + unread bold.

### 4d. Reading pane

Shell: key-commands region → find-in-thread → width-restricted section →
scroll region → subject block + headers injection + message items + spinner.

- **Subject block:** important icon + subject + removable label set (+current)
  + icons (Expand/Collapse All, Print, render-mode toggle, Popout/Popin).
- **Per-message:** article → white wrap → area → header + body + attachments +
  footer status. Header right cluster: timestamp + status injection + controls;
  below: From + To/Cc/Bcc/ReplyTo rows (+ Subject/Folder rows and disclosure
  only in detailed-headers mode).
- **Action bar:** primary Reply|ReplyAll split-button (by default-reply-type;
  menu Reply/ReplyAll/Forward/Show Original) + ellipsis menu (log data, show
  original, copy debug, download .eml + extension items).
- **Collapse:** collapsed row = from + snippet + draft-pencil + timestamp +
  attachment-dot; most-recent never collapses; ≥3 consecutive collapsed (past
  first) bundle into `N older messages`; footer `Write a reply…` inline area.
- **Right rail:** participant picker + plugin container; popout thread window
  reuses the same list at center location.

**KIWI delta:** move our action buttons to a header-top bar (we render them at
bottom today); encryption pill slot = our SecurityPill (TB-map §11 agrees);
add Expand/Collapse All + Popout; keep sanitized-HTML + remote-block + save-all
attachment bar.

### 4e. Modal composer

Entry: inline composer for draft client-ids in main/thread windows; popout
window composer bootstrapped from draft JSON, OS title syncs to subject.

Frame: key-commands region → tab-group region → drop zone (attach cover) →
centered width-restricted content (header + body [editor + quoted control +
attachments] + footer plugin slot + action-bar workspace) + footer action bar
with roving-tabindex toolbar. Popout wraps content in a scroll region.

- **Header:** always To; optional Cc/Bcc/ReplyTo (mounted for Tab order);
  From scoped to single account for replies; Subject input (hidden for
  replies with subject). Toggles + popout button.
- **Body:** plaintext vs rich editor + quoted-text control + attachments area;
  file/thread-`.eml` drops.
- **Footer/action bar:** left plugin slot (extension point — send-later/snooze
  live here), Delete Draft, Attach File, spacer, Send split-button
  (primary Send + menu of extra send actions, validity-gated, send sound).
  Core has no send-later/undo buttons — undo lives in the task layer
  (toast + 10s ring, A14/A15).

**KIWI delta:** keep plaintext-only send; add modal + popout + Cc/Bcc toggles
+ plugin-slot convention (send-later/undo hook here in T-191); policy banner
stays top-of-composer (S-07); drafts autosave stays local until IPC lands.

### 4f. Tabbed preferences

Registration order: General(1), Accounts(2), identity/Subscription(3),
Appearance(4), Shortcuts/Keymaps(5), Mail Rules(6); single-column sheet all modes.

Root: key-commands region → column flex → tabs bar + scroll content →
config-prop container → per-tab component. Thread shortcuts suppressed;
scroll resets + first input focused on tab change. Bar: centered tablist with
flex spacers; each tab = 40px icon + name; arrow/Home/End navigation.

**KIWI delta:** restructure our scrolling settings into these six tabs
(Appearance/Accounts/Privacy/Notifications/Advanced fold into the six;
rules → Mail Rules tab reusing filters view). Keep prefs push/pull wrappers.

## 5. Interaction states

| Family | States (all need KIWI coverage) |
|---|---|
| Buttons/toolbars | default gradient/hairline · hover tint/link · active darkened · focus-visible 2px accent (mouse focus suppressed) · disabled faded+locked · blurred-window desaturated |
| Lists | default · hover (darken + reveal quick-actions/star/important) · selected · focused · selected+focused (inverted check) · next-is-selected border fix · keyboard-cursor left rail · unread bold · blurred grey wash |
| Sidebar/outline | hover reveals add/collapse/action · selected accent fill · dropping = lightened target · editing = inline input |
| Menus/popovers | hover faint fill · selected/active accent fill + inverse text · checked checkmark · divider non-interactive header |
| Inputs | focus accent border + glow · disabled washed 0.7 |
| Scrollbars | hover/scrolling/with-ticks/dragging force opaque; handle darkens while dragging; tooltip hidden until drag |
| Dialogs/toasts | animate/enter visible · exit faded/dropped; variants info/developer/upgrade/error/offline; toast loading-action state |
| Misc | collapsed/expanded message · pending spinner swap · empty illustration + fade · confirmed swipe · dragging resize · archived/trashed/snoozed backing colors |

Keyboard/a11y notes: tree + tablist + toolbar all roving-index with
arrow/Home/End; rows expose treeitem/listbox semantics; focus-visible only
(not mouse). T-191 must preserve our existing ARIA (listbox/multiselect,
dialog combobox, lock overlay) and add tree/tablist roles.

## 6. T-191 rebuild worklist (from this map)

1. **Shell:** 3-pane `split` (sidebar 165–250 + thread list + flex reader +
   right rail slot) with persisted resizable splitters; toolbar mirrors columns.
2. **Sidebar:** AccountSwitcher dropdown, disclosure twist (90ms linear), alt
   inbox badge, account color bars, `role=tree`, drag guard, context groups.
3. **Thread rows:** Wide-column grid (c1–c5) @36px + Narrow stacked @85px
   under ~540px; hover quick-actions (Trash/Archive + security peek); unread
   bold + accent dot; swipe (150ms + spring) optional phase 2.
4. **Reader:** top action bar (Reply-split + ellipsis), subject block
   (important + labels + expand/collapse + popout), SecurityPill in header,
   attachment bar with counts + save-all, `N older messages` bundle.
5. **Composer:** modal + popout, Cc/Bcc toggles, scoped From, plugin slot
   (send-later/undo), Send split-button, 30/200ms reveal + 100/360ms modal.
6. **Prefs:** six tabs (General/Accounts/Identity/Appearance/Shortcuts/
   Mail Rules) with arrow-key tablist.
7. **Motion:** `--kiwi-ms-motion-*` ladder (§3.2) + popover overshoot +
   toast lift + countdown ring; reduced-motion kill-switch on everything.
8. **Tokens:** `mailspring-tokens.css` (this task) → flagship mapping in T-191;
   keep deep-black default, adopt light direction + structure.
9. **Keep (no regressions):** all `kiwi.ipc/1` bindings, policy banner, lock
   overlay, security center tab, toasts, palette, contacts, filters, threads,
   bulk, search, prefs wrappers. T-192 re-integrates security surfaces in
   this idiom.

## Appendix — provenance (files surveyed, read-only)

- `app/static/style/base/ui-variables.less`, `type.less`, `workspace.less`,
  `inputs.less`, `buttons.less`, `components/outline-view.less`,
  `components/list-tabular.less`, `components/disclosure-triangle.less`,
  `components/switch.less`, `components/scroll-region.less`,
  `components/modal.less`, `components/fixed-popover.less`,
  `components/menu.less`, `components/spinner.less`
- `app/internal_packages/thread-list/lib/thread-list{,-columns,-icon,-participants,-toolbar,-quick-actions}.tsx`,
  `styles/thread-list.less`
- `app/internal_packages/message-list/lib/message-list.tsx`,
  `message-item.tsx`, `message-controls.tsx`, `message-participants.tsx`,
  `subject-line-icons.tsx`, `styles/message-list.less`
- `app/internal_packages/account-sidebar/lib/account-sidebar.tsx`,
  `account-switcher.tsx`, `sidebar-section.ts`, `sidebar-item.ts`
- `app/internal_packages/composer/lib/main.tsx`, `composer-view.tsx`,
  `composer-header{,-actions}.tsx`, `action-bar-plugins.tsx`,
  `send-action-button.tsx`, `styles/composer.less`
- `app/internal_packages/preferences/lib/main.tsx`, `preferences-root.tsx`,
  `preferences-tabs-bar.tsx`
- `app/internal_packages/ui-dark/styles/ui-variables.less`,
  `ui-darkside/styles/ui-variables.less`, `theme-colors.less`,
  `darkside-{sidebar,threadlist,thread-icons,message-list}.less`
- `app/internal_packages/undo-redo/styles/index.less`,
  `undo-redo/index.less`, `notifications` styles,
  `app/src/components/{outline-view,outline-view-item,multiselect-toolbar,tab-group-region,swipe-container,resizable-region,modal,fixed-popover,notification,switch}.tsx`,
  `app/src/sheet{,-container,-toolbar}.tsx`
