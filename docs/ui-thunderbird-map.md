# Thunderbird UI Map — Supernova-era anatomy for the KIWI rebuild (T-190)

> Source: unmodified `source/` checkout (comm-central + mozilla-central).
> All `comm/mail/…` paths below are relative to `source/comm/mail`.
> Purpose: layout/workflow parity targets for T-191. Legal is clean
> (both MPL-2.0) — replicate tokens/layout, write our own components.
> KIWI column = where each surface lives (or will live) in `kiwi-app/`.

## 1. Main-window shell (`base/content/messenger.xhtml`)

Top-to-bottom stack:

| # | Element | Notes | KIWI |
|---|---|---|---|
| 1 | Command sets (`mailCommands`, `mailKeys`, calendar keys) | All shortcuts + enabled-state live here | `App.tsx` global key handler + palette |
| 2 | Popup set (context menus, panels) | — | Row/header context menus (T-191+) |
| 3 | In-app notification bar | Transient warnings above everything | Toasts (keep) |
| 4 | Spaces toolbar (vertical, left edge) | Mail / Address Book / Calendar / Tasks / Chat icons + badge; Settings + collapse at bottom (`spacesToolbar.inc.xhtml:48-123`) | Sidebar nav (vertical icon strip target) |
| 5 | Unified toolbar (`html:unified-toolbar`) | Customizable; mail-space default = Get Messages, Write, Address Book, Reply/Reply-All/Forward, Archive, Junk, Delete, search-bar (`CustomizableItems.sys.mjs`) | Top action bar (Get, Write, Reply…, Archive, Junk, Delete) |
| 6 | Menu bar (autohide): File Edit View Go Message Tools Help (+ Events/Tasks, mac Window) | Full tree in §2 | Menu bar (T-191) |
| 7 | Tab bar (`tabmail-tabs` + all-tabs button) | Mail tab, message tabs, Settings/Contacts/Search tabs | Tab bar (T-191): mail + message + security/contacts/search/settings tabs |
| 8 | 3-pane content (`about:3pane` browser) | Folder pane + thread pane + message pane, splitters | Keep our 3-pane, add splitters + layouts |
| 9 | Status bar | Offline icon, status text, progress, quota meter (`mainStatusbar.inc.xhtml`) | Status bar (T-191): backend note, sync progress, quota→outbox |

## 2. Menu tree (`messenger-menubar.inc.xhtml`)

### File
New ▸ (Message **Ctrl+N**, Contact, Folder…) · Open Message File · Close · Save As ▸ · Get New Messages For ▸ (All Accounts **Shift+F5**, Current **F5**) · Send Unsent Messages · Subscribe · New Folder · Rename Folder · Compact Folders · Empty Trash · Offline ▸ · Print **Ctrl+P** · Exit.

### Edit
Undo/Redo · Cut/Copy/Paste · Select ▸ (All **Ctrl+A**, Thread **Ctrl+Shift+A**, Flagged) · Find ▸ (in message, Search Messages, Gloda) · Account Settings.

### View
Toolbars ▸ (Quick Filter Bar **Ctrl+Shift+K**, Spaces Toolbar, Status Bar) · Layout ▸ (**Classic / Wide / Vertical**, Folder Pane, Message Pane **F8**) · Folder Views · **Density ▸ Compact/Normal/Touch** · Sort By ▸ (Date/Received/Starred/From/Subject/… + Asc/Desc + Threaded/Unthreaded/Grouped) · Show ▸ (All/Unread/…) · Threads ▸ (Expand All **Shift+\***, Collapse All **\**) · Headers ▸ (Normal/All) · Message Body As ▸ (HTML/Sanitized/Plain).

### Go
Next ▸ (Message **F**, Unread **N**, Flagged, Thread **T**) · Previous ▸ (**B**, **P**) · Back/Forward (**[**, **]**) · Folder ▸ · Start Page **Alt+Home**.

### Message
New Message · Reply **Ctrl+R** · Reply All **Ctrl+Shift+R** · Reply List **Ctrl+Shift+L** · Forward **Ctrl+L** (Inline/Attachment) · Redirect · Edit as New **Ctrl+E** · Open **Ctrl+O** / in Conversation **Ctrl+Shift+O** · Archive **A** · Mark ▸ (Read/Unread **M**, Thread as Read **R**, All Read **Shift+C**, Flag **S**, Junk **J** / Not-Junk **Shift+J**, Tag 0-9) · Move To / Copy To ▸ · Move Again **Ctrl+Shift+M** · Tag ▸ · Create Filter From · Ignore Thread **K** (+Subthread **Shift+K**) · Watch **W** · Delete (**Del**, hard **Shift+Del**).

### Tools
Address Book **Ctrl+Shift+B** · Saved Files **Ctrl+J** · Message Filters · Run Junk Controls · Import/Export · OpenPGP Key Manager · Developer Tools · Settings.

### Help
Get Help **F1** · Shortcuts · Donate · Troubleshoot Mode · About.

## 3. Shortcut map (accel = Ctrl on Win/Linux)

Message handling (bare keys, list focused — **note: no Gmail j/k**; `j` = Junk):

| Keys | Action | KIWI today → target |
|---|---|---|
| **Ctrl+N** | New message | Palette only → **Ctrl+N** |
| **Ctrl+Enter** | Send (compose window only) | Already in composer ✓ |
| **F5** / Shift+F5 | Get current / all accounts | Sync button → **F5** |
| **F / N** · **B / P** · **T** | Next (unread) · Prev (unread) · next unread thread | n/p only → add F/B/T |
| **M** · **S** · **A** · **J/Shift+J** | Read toggle · Star · Archive · Junk | u/s/e → **M/S/A/J** (+ keep aliases?) |
| **Ctrl+R / Shift+R / Shift+L / L** | Reply/All/List/Forward | r → full set |
| **Ctrl+E** · **Ctrl+O** · **Del** | Edit as new · Open · Delete | new |
| **Ctrl+Shift+A** · **Shift+C** · **K/W** | Select thread · All read · Ignore/Watch | new |
| **Ctrl+Shift+M** | Move again | new |
| **Ctrl+K** | Quick-filter focus (TB!) | Ours opens palette — **conflict, decide in T-191** (TB parity says `/` for palette or move palette) |
| **Ctrl+Shift+K** | Toggle quick-filter bar | new |
| **Ctrl+Shift+B** | Address Book | new (contacts route) |
| **F8** | Toggle message pane | new |
| **Ctrl+Tab / F6** | Cycle panes | new (a11y win) |
| **\ / Shift+\*** | Collapse/expand all threads | new |
| 0-9 | Tag / untag | future (no tags backend) |

## 4. Folder pane (`about3Pane.xhtml:65-92`)

Row anatomy: twisty ▸ · new-mail dot · folder icon · account color chip (unified mode) · name · **unread badge** · total badge (optional) · size (optional) · status icon. Header has Write (primary) + Get Messages buttons. ARIA: `role=tree`, rows announce name + unread + total. Sort by order + collator.

KIWI delta: add twisty (unified accounts), new-mail dot, total badge, header Write/Get buttons, tree roles.

## 5. Thread list (`ThreadPaneColumns.mjs`, 22 columns)

| # | Column | Shows | Default |
|---|---|---|---|
| 1 | Select ☐ | checkbox | hidden |
| 2 | Thread | threaded indicator | shown |
| 3 | Starred ★ | toggle | shown |
| 4 | Attachments 📎 | paperclip | shown |
| 5 | **Subject** | twisty + status icon + subject (indent by depth) | shown, always |
| 6 | Read ● | dot toggle | shown |
| 7-8 | From / Recipient | (adaptive) | hidden (From shows for news/feeds) |
| 9 | **Correspondents** | smart From-or-To | shown (mail) |
| 10 | Spam 🔥 | junk toggle | shown |
| 11 | Date | | shown, **default sort: Date desc** |
| 12-21 | Received, Status, Size, Tags, Account, Priority, Unread-N, Total-N, Location, Order-ID | | hidden |
| 22 | Delete 🗑 | per-row delete | hidden |

Adaptive: Sent-type folders show Recipient instead of Correspondents; Gloda search adds Location. Column picker on last column; order/width/visibility persisted per folder. Sort menu: 14 keys + asc/desc + threaded/unthreaded/grouped.

KIWI delta: rebuild rows as real columns (today: From/subject/snippet stacked). Target default set: Thread, Starred, Attach, Subject, Read, Correspondents, Spam, Date. Sortable Date/Subject/From at minimum; column picker later.

## 6. Quick-filter bar (`quickFilterBar.inc.xhtml`)

Sticky toggle · text search (maxlength 192) · chip menu · chips: **Unread · Starred · In-Address-Book · Tags · Attachment** · throbber + result count · Esc relaxes then closes. Second row: Sender/Recipients/Subject/Body text scopes + tag mode (Any/All/None).

KIWI delta: our search view ≈ Gloda; add an in-list quick-filter strip with Unread/Starred/Attachment chips + Esc behavior.

## 7. Message header block (`msgHdrView.inc.xhtml`)

Order: correspondent toolbar (Reply/ReplyAll-menu/ReplyList/Forward/Archive/Junk/Delete + Star + Other-actions menu) → From row (avatar, full address, + add-to-address-book) → To row + Date (right) → Cc/Bcc/Reply-To (hidden unless present) → Subject (large) + **encryption pill** (`#cryptoBox`: label + encrypted/signed icons → security panel) → Tags → hidden rows (Message-ID, In-Reply-To, List-*, User-Agent…; All-headers mode).

Attachment bar below: toggle + icon + count + name + size + Open/SaveAll/Detach/DeleteAll + multi-select list.

KIWI delta: header toolbar row (we have buttons at bottom — move up), From→contact add (we have ✓), **encryption pill slot** (our SecurityPill goes here, not top bar), attachment bar with counts + save-all.

## 8. Multi-message / conversation summary (`multimessageview.xhtml`)

Selected N>1 or collapsed thread → summary: header (Archive/Delete/Star act on selection) + per-thread items (star, author, tags, date, snippet ≤300B) + footer (total bytes, caps at 100 threads/10k msgs). Single thread selected → thread template with replies inline.

KIWI delta: our BulkBar ≈ summary header; add summary list when selection > 1 (no backend needed).

## 9. Status bar (`mainStatusbar.inc.xhtml`, `messenger.xhtml:670-692`)

Left→right: spaces-reveal button · offline indicator · **status text (flex)** · progress meter (hidden) · quota meter (hidden) · calendar invites.

KIWI delta: status text (backend note ✓) + sync progress + outbox counts; offline indicator maps to lock/backend state.

## 10. Compose (`compose/content/messengercompose.xhtml`)

Toolbar (customizable, Send first): Send · Encryption · Contacts sidebar · Spelling · Save · Attach · Print. Identity menulist → To/Cc/Bcc rows (**address pills**, not chips) → Subject → formatting toolbar (paragraph, font, size, color, bold/italic/underline, lists, align, insert, emoji) → editor → attachment bucket (count + size, per-file menus) → status bar (status text, progress, language).

KIWI delta: Send-first toolbar order; address pills ≈ our chips (keep); our plaintext toolbar stays (no HTML send); attachment bucket with count/size; identity selector ✓.

## 11. Account setup (Account Hub, `accountcreation/`)

Flow: type grid (Mail/Calendar/AddressBook/Chat/Feed) → email auto-config → config-found → password → sync-accounts → success; branches for auth, protocol select, manual in/outgoing. Legacy wizard: identity → server → name → done.

KIWI delta: our 4-step wizard (Address/Servers/Credentials/Verify) ≈ legacy shape — keep, add Account-Hub-style config-found confirmation screen.

## 12. Address book (`addrbook/content/aboutAddressBook.xhtml`)

3-pane: books list · cards list (search + sort) · detail article + edit form; vCard field editors per property.

KIWI delta: our Contacts view is list+detail already — add books pane later (single local book today).

## 13. Density (`UIDensity.sys.mjs`, pref `mail.uidensity` 0/1/2)

Applied as `uidensity="compact"|"touch"` on root (normal = attr removed).

| Token | Normal | Compact | Touch |
|---|---|---|---|
| `--tab-min-height` | 33px | 30px | 39px |
| `--list-item-min-height` | 26px | 18px | 32px |
| `--button-min-height` | 32px | 30px | — |
| `--space-base` (`--space-step` 3px const) | 6px | 3px | 9px |
| menuitem vertical padding | 3px | 1px | 8px |
| folder icon | 16px | 16px | 20px |

KIWI delta: our density pref is comfortable/compact only — add touch + root-attr mechanism (we use `data-density`; TB parity = `uidensity` attr, keep ours, values align: compact 18px rows ≈ ours).

## 14. Type

OS font everywhere (`font: message-box`; no custom stack). Sizes relative (h1 2em, badges 0.8rem). Compose-only stacks: Helvetica/Arial, Times, Courier.

KIWI delta: drop Inter-first stack → system stack (`-apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` + `message-box` first where supported). Keep heading scale.

## 15. Tokens light / dark (`themes/shared/mail/colors.css`, `layout.css`)

Light: bg `#feffff`, subtle `#f7f7f7`, border `#d9d9de`, border-intense `#91939f`, text `#1a202c`, secondary `#4c4d58`, muted `#737584`, primary `#1373d9` (hover `#175fb6`), backgrounds 1-4 `#fafafa/#f4f4f5/#e4e4e7/#d4d4d8`, danger `#dc2626` (text `#991b1b`).

Dark: base `#1a202c`, raised/subtle `#262d3b`, lower `#18181b`, border `#3d4d67`, intense `#5e7799`, text `#eeeef0`, secondary `#e4e4e7`, muted `#7f94ac`, primary `#58c9ff` (hover `#32aeff`), bg 1-4 `#27272a/#3f3f46/#52525b/#71717a`, danger text `#fca5a5`.

Accent defaults to OS `AccentColor`; Thunderbird-blue forced via pref. Separators: light `#d4d4d8`, dark `#18181b`.

KIWI delta: retoken toward these values (we're deep-black `#0e0e12` flagship vs TB `#1a202c` dark — owner call in T-191: keep flagship vs TB-faithful; recommend keeping flagship dark, adopting TB light + structure + density, since flagship is owner-approved T-145).

## 16. T-191 rebuild worklist (from this map)

1. Shell: spaces strip + unified toolbar (Get/Write/Reply…/Archive/Junk/Delete) + menu bar + tab bar + status bar.
2. Folder pane: twisty, new-dot, total badge, header Write/Get, tree roles.
3. Thread list: column rows (Thread/Star/Attach/Subject/Read/Correspondent/Spam/Date), sortable Date, quick-filter strip, splitters + Classic/Wide/Vertical.
4. Header block: top toolbar, From+contact add, encryption-pill slot (SecurityPill), attachment bar.
5. Keys: adopt TB map (§3), resolve Ctrl+K conflict (palette → keep Ctrl+K? TB uses it for quick-filter — recommend palette moves to Ctrl+P… no, keep Ctrl+K palette + quick-filter on Ctrl+Shift+K per TB).
6. Tokens: adopt light palette + structure; keep flagship dark (owner call); system font stack.
7. Keep: all IPC bindings, policy banner, lock overlay, security center tab, toasts, palette, contacts, filters, threads, bulk, search.
