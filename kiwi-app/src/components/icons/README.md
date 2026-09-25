# KIWI icon set (T-268)

Hand-authored monochrome stroke SVGs on a 16×16 grid — `stroke="currentColor"`,
`stroke-width 1.25`, round caps/joins. Inline React components: **no icon
library, no remote assets, no font**. Inherit color from context, so both
themes and every pill/button treatment work unchanged.

```tsx
import { Icon } from "../components/icons";

<Icon name="reply" />                    // 16px, decorative (aria-hidden)
<Icon name="star-filled" size={14} />
<Icon name="lock" label="Locked" />      // exposes role="img" + aria-label
<Icon name="search" strokeWidth={1.5} />
```

`SEVERITY_ICON` maps `Severity` (secure/warning/danger/unknown) → icon name;
it replaces `severityGlyph` for React surfaces (`severityGlyph` stays as the
text fallback in `kiwi.ts`).

## Emoji → icon map (inventory 2026-09-25, grep of `src/`)

Every emoji/dingbat used as UI chrome and its replacement. Glyphs used as
literal *keyboard-hint text* (`↑↓`, `→` inside prose/log strings, `⌘` as a
key name is replaced by the `command` icon) stay as text.

| Glyph | Site (file:line at inventory time) | Replacement |
|-------|------------------------------------|-------------|
| 🔒 | `chrome.tsx:17` (locked chip), `security.tsx:229` (lock overlay) | `lock` |
| ⇅ | `chrome.tsx:185` (Get/sync button) | `sync` |
| ✎ | `chrome.tsx:189,314` (Write/Compose) | `compose` |
| ⌘ | `chrome.tsx:210` (command palette) | `command` |
| ? | `chrome.tsx:213` (shortcuts) | `help` (or keep `?` text) |
| ▾ / ▸ | `chrome.tsx:287`, `mailbox.tsx:1168,1240`, `integrations.tsx:267` | `chevron-down` / `chevron-right` (`.ms-disclosure` twist is a CSS transform — put the down-chevron in the element and rotate it, or swap per state) |
| 👥 | `chrome.tsx:317` (nav), `contacts.tsx:376` (empty state) | `accounts` |
| 🔀 | `chrome.tsx:320`, `filters.tsx:202` | `filters` |
| 🛡 | `chrome.tsx:328` (Security nav) | `shield` |
| ⚙ | `chrome.tsx:336` (Settings nav) | `settings` |
| ✓ | `toasts.tsx:23` (ok), `oauth2.tsx:216`, `kiwi.ts:1109`, `settings.tsx:546,653`, `setup.tsx:292`, `mailbox.tsx:1079`, `search.tsx:384`, `integrations.tsx:381` | `check` / `check-circle` |
| ✕ / ✗ | `toasts.tsx:25,58`, `App.tsx:1064`, `compose.tsx:595,603`, `filters.tsx:312`, `mailbox.tsx:1089`, `kiwi.ts:1113` | `close` / `x-circle` |
| ! | `toasts.tsx:24` (warn), `kiwi.ts` severityGlyph | `alert-triangle` |
| ℹ | `toasts.tsx:22` (info) | `info` |
| ⚠ | `integrations.tsx:381` | `alert-triangle` |
| ⊘ | `integrations.tsx:381` | `blocked` |
| ☰ | `compose.tsx:659` | `menu` |
| ✉ | `mailbox.tsx:427` (empty list) | `mail` (`size={32}` for `.kiwi-empty-icon`) |
| ★ / ☆ | `mailbox.tsx:549,1033` | `star-filled` / `star` |
| ● | `mailbox.tsx:1042,1176,1254` (unread dot) | `dot` (fill glyph) |
| 📦 | `mailbox.tsx:1066` (archive) | `archive` |
| 🗑 | `mailbox.tsx:1101` (delete) | `trash` |
| 📤 | `mailbox.tsx:1383` (outbox empty) | `outbox` |
| 📎 | `mailbox.tsx:847`, `search.tsx:451` | `paperclip` |
| 🔍 | `search.tsx:429` (empty state) | `search` (`size={32}`) |
| ← / → (nav buttons) | `security.tsx:186,189`, `setup.tsx:542,546` | `arrow-left` / `arrow-right` |
| ↑ / ↓ (rule reorder) | `filters.tsx:228,236` | `arrow-up` / `arrow-down` |
| ✓ default pill | `settings.tsx:546` | `check` |
| ☰/✕/other dialog buttons | `compose.tsx:595,603,659` | `close`, `menu` |

Not replaced (intentionally): arrows inside prose/log strings
(`"saved → path"`, `"Settings → Accounts"`), keyboard-hint legends
(`↑↓ to move`, `j/↓ k/↑`), and typographic punctuation (`—`, `“”`).

## Toolbar icon needs (A24 / T-267 eM-Client toolbar)

`menu` (hamburger), `plus` (+New), `refresh`, `reply`, `reply-all`,
`forward`, `mail-open` (Mark), `archive`, `snooze`, `bolt` (Quick Actions),
`trash` (Delete), `chevron-down` (dropdown affordance), `search`,
`folder`, `account`/`accounts`, `checkbox`/`checkbox-checked`, `flag`,
`agenda` (right rail), `inbox`, `outbox`, `send`, `compose`, `paperclip`,
status set (`check-circle`, `alert-triangle`, `x-circle`, `help-circle`,
`info`, `blocked`), `lock`/`unlock`, `shield`/`shield-check`/`shield-x`,
`key`, `device`, `settings`, `contacts→accounts`, `filters`, `command`,
`help`, `close`, `check`, `sun`/`moon`/`monitor` (theme picker), `eye`/
`eye-off`, `link`, `external`, `download`, `list`, `calendar`, `clock`,
`file`, `puzzle` (plugins), `more`, `bell`/`bell-off`, `dot`, `star`/
`star-filled`, `sync`, arrows and chevrons in all four directions.
