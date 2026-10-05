# Mailspring UI Metrics Reference (extracted from `vendor/mailspring/`)

All paths are relative to `vendor/mailspring/`. Defaults assume the wide thread-list layout on Windows/Linux unless noted.

## Base typography

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Base font family | `@font-family` / `@font-family-sans-serif` | `'Nylas-Pro', 'Helvetica', sans-serif` | app/static/style/base/ui-variables.less:88,92 |
| Serif stack | `@font-family-serif` | `Georgia, 'Times New Roman', Times, serif` | ui-variables.less:89 |
| Monospace stack | `@font-family-monospace` | `'DejaVu Sans Mono', Menlo, Monaco, Consolas, 'Courier New', monospace` | ui-variables.less:90 |
| Base font size | `@font-size-base` | 14px | ui-variables.less:106 |
| Base font size alias | `@font-size` | 14px | ui-variables.less:111 |
| Tiny / smaller / small | `@font-size-tiny` / `@font-size-smaller` / `@font-size-small` | 10.5px / 12px / 13px | ui-variables.less:108-110 |
| Large / larger | `@font-size-large` / `@font-size-larger` | 16px / 18px | ui-variables.less:112-113 |
| Headings | `@font-size-h1`/`h2` / h3 / h4 / h6 | 24px / 20px / 18px / 12px | ui-variables.less:115-120 |
| Base line-height | `@line-height-base` | 1.5 | ui-variables.less:123 |
| Computed line-height | `@line-height-computed` | ~20px (`floor(14*1.5)`) | ui-variables.less:124 |
| Base spacing unit | `@spacing-standard` | 14px (= `@font-size-base`) | ui-variables.less:131 |
| Spacing fractions | `@spacing-quarter` / `@spacing-half` / `@spacing-three-quarters` / `@spacing-double` | 3.5 / 7 / 10.5 / 28px | ui-variables.less:133-136 |
| Base padding | `@padding-base-vertical` / `@padding-base-horizontal` | 5px / 12px | ui-variables.less:138-139 |
| Large padding | `@padding-large-vertical` / `@padding-large-horizontal` | 9px / 16px | ui-variables.less:141-142 |
| Semi-bold weight | `@font-weight-semi-bold` | 600 (700 on Windows) | app/static/style/workspace.less:5,695 |
| Root font/line-height applied | `html, body` font-size / line-height | `@font-size` (14px) / 1.5 | workspace.less:11-15 |

## Thread list

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Wide row height (one-line) | `--thread-list-item-height-wide` / `itemHeight` | 36px | app/internal_packages/thread-list/lib/thread-list.tsx:100; row `line-height: 36px` at thread-list.less:134 |
| Narrow row height (two-line) | `--thread-list-item-height-narrow` / `itemHeight` | 85px | thread-list.tsx:103 |
| Narrow item line-height | `.list-tabular-item` | 21px | thread-list.less:463 |
| Row padding/spacing | list-item | `border-bottom: 1px`, `line-height: 36px` | thread-list.less:131-135 |
| Participants font size | `font-size: @font-size-small` | 13px | thread-list.less:160 |
| Participants font size (narrow) | `@font-size-base` | 14px | thread-list.less:470 |
| Subject font size | `@font-size-small` | 13px | thread-list.less:176 |
| Subject font size (narrow) | `@font-size-base` | 14px | thread-list.less:481 |
| Subject weight (read) | `@font-weight-normal` | 400 | thread-list.less:177 |
| Subject weight (unread) | `@font-weight-semi-bold` | 600/700 | thread-list.less:234 |
| Snippet font size | `@font-size-small` | 13px | thread-list.less:186 |
| Snippet opacity | opacity | 0.62 | thread-list.less:190 |
| Timestamp font size | `@font-size-small` | 13px | thread-list.less:208 |
| Timestamp min-width | min-width | 70px | thread-list.less:210 |
| Timestamp right margin | `@scrollbar-margin` | 8px | thread-list.less:4,211 |
| Participants column width | `ListTabular.Column width` | 200px | thread-list-columns.tsx:88 |
| Message column | `flex: 4` | 4 flex units | thread-list-columns.tsx:110 |
| Thread icon box | width/height | 25px × 24px | thread-list.less:257-258 |
| Thread icon glyph | background-size | 15px (star 16px) | thread-list.less:260,280 |
| Unread indicator | `.thread-icon-unread` background image | icon within 25×24 box, 15px glyph | thread-list.less:270-272 |
| Unread participants weight | `.unread-true` / `@font-weight-semi-bold` | 600/700 | thread-list.less:241 |
| Message count badge padding | padding | 4px 6px 2px 6px | thread-list.less:149 |
| Date format | `DateUtils.shortTimeString` | <1d: time; <5d: weekday+time; <1y: "Mon d"; else "Mon d, yyyy" | app/src/date-utils.ts:393-427; used at thread-list-columns.tsx:23 |
| Narrow icons column | width / margin-right | 25px / 5px | thread-list.less:441-442 |
| Narrow subject+snippet min-height | `.snippet` min-height | 21px | thread-list.less:504 |

## Toolbar / chrome

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Sheet toolbar height (win/linux) | `.sheet-toolbar` height/min/max | 34px | app/static/style/workspace.less:128,132-133 |
| Sheet toolbar line-height | line-height | 34px | workspace.less:157 |
| Toolbar height (macOS) | `@toolbar-height-darwin` | 46px | ui-variables.less:204 |
| Toolbar button height (macOS) | `@toolbar-btn-height-darwin` | 30px | ui-variables.less:205 |
| Account sidebar min/max width | `--account-sidebar-min-width` / `-max-width` | 165px / 250px | account-sidebar.tsx:23-24 |
| Toolbar window controls width | width | 72px | workspace.less:70-72 |
| Sidebar section width | content min/max width | 430px / 800px; desktop panel 600px | preferences.less:124-125,139 |

## Message pane (message-list)

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Content max width | `@message-max-width` | 800px | message-list.less:4 |
| Message spacing | `@message-spacing` | 6px | message-list.less:5 |
| Subject row | `.message-subject-wrap` margin / line-height / padding | `5px auto 10px` / `@font-size-large*1.8` / `0 @padding-base-horizontal` | message-list.less:206-211 |
| Message subject font | `@font-size-large` | 16px | message-list.less:219 |
| Message header font size | `@font-size-small` | 13px | message-list.less:400 |
| Message header padding-top | padding-top | 19px | message-list.less:402 |
| Message time min-width | min-width | 125px | message-list.less:480 |
| Message actions pill height | `.message-actions` height | 23px | message-list.less:450 |
| Body area padding | `.message-item-area` padding | `0 20px @spacing-standard 20px` (bottom 14px) | message-list.less:509 |
| Collapsed message padding | `.collapsed .message-item-white-wrap` | padding-top 19px, padding-bottom 8px | message-list.less:297-298 |
| Message iframe margin-top | margin-top | 10px | message-list.less:512 |
| Collapse region height | `.collapse-region` height | 56px | message-list.less:525 |
| Scroll content inner padding | `.scroll-region-content-inner` | 6px | message-list.less:268 |
| Reply area padding | `.footer-reply-area` padding | `12px @spacing-standard*1.5` (21px) | message-list.less:575 |
| Message body font size (HTML) | `html, body` font-size (email frame) | 14.5px | app/static/style/email-frame.less:52 |
| Message body line-height | line-height | 1.5 | email-frame.less:53 |
| Message body font family | `#inbox-html-wrapper` | `'Nylas-Pro', 'Helvetica', 'Lucidia Grande', sans-serif` | email-frame.less:72 |
| Plaintext body | `#inbox-plain-wrapper` font-size/family | 14px monospace | email-frame.less:90-92 |
| Body max width (win32/class `restrict-width`) | body max-width | 840px | email-frame.less:108 |

## Composer

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Composer max width | `@compose-width` | 800px | composer.less:6 |
| Composer min body height | `@compose-min-height` | 70px | composer.less:7 |
| RichEditor root padding | padding / min-height | `0 22px` / 70px | composer.less:33-34 |
| RichEditor content padding-top | padding-top | 12px | composer.less:37 |
| Plaintext compose padding | textarea padding | `13px 22px` | composer.less:16 |
| Formatting toolbar | `.RichEditor-toolbar` font-size / min-height | 14px / 29px | composer.less:107,115 |
| Toolbar button padding | padding | `4px 4.7px` | composer.less:138 |
| Subject field input padding | padding | `13px 22px 9px 22px` | composer.less:503 |
| Subject/participant divider | `.composer-field-bottom-border` | left 23px, height 1px | composer.less:246-253 |
| Participant (To/From) field min-height | `.composer-participant-field` min-height | 46px | composer.less:718 |
| Participant field padding | `.tokenizing-field-wrap` padding | `0 22px` | composer.less:722 |
| Header actions padding | `.composer-header-actions` padding | top 12px, right `@spacing-standard + @spacing-half` (21px) | composer.less:424-425 |
| Action bar padding | `.composer-action-bar-content` padding | `9px 22.5px` | composer.less:345 |
| Footer padding | `.composer-footer-region` padding | `0 22px` | composer.less:588 |
| Quoted text control margin | margin | `0 @spacing-standard @spacing-standard 22px` | composer.less:560 |

## Preferences

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Pane font size | `.preferences` font-size | `@font-size-smaller` (12px) | preferences.less:35 |
| Content min/max width | min-width / max-width | 430px / 800px | preferences.less:124-125 |
| Desktop panel width | width | 600px | preferences.less:139 |
| Panel heading | h2 font-size / padding | 11px uppercase semi-bold, padding 25px | message-list.less:774-775 (sidebar-section), preferences.less:168 |

## Avatars & icons

| Element | css-var / property | Value | Source |
|---|---|---|---|
| Contact profile photo | `.contact-profile-photo` width/height | 50px | contact-profile-photo.less:4-5 |
| Small profile photo | small variant | 44px | contact-profile-photo.less:15-16 |
| Gravatar request size | `?s=88` | 88px | app/src/components/contact-profile-photo.tsx:22 |
| Component icon size | `@component-icon-size` | 16px | ui-variables.less:239 |
| Component icon padding | `@component-icon-padding` | 5px | ui-variables.less:238 |
| Component line-height | `@component-line-height` | 25px | ui-variables.less:240 |

## Theming hooks

| Token | Value | Source |
|---|---|---|
| `--font-weight-semi-bold` | 600 (700 on Windows) | workspace.less:5,695 |
| `--thread-list-item-height-wide` | 36 | thread-list.tsx:100 (via `DOMUtils.getWorkspaceCssNumberProperty`, dom-utils.ts:202) |
| `--thread-list-item-height-narrow` | 85 | thread-list.tsx:103 |
| `--account-sidebar-min-width` | 165 | account-sidebar.tsx:23 |
| `--account-sidebar-max-width` | 250 | account-sidebar.tsx:24 |
| `--system-accent` / `--system-accent-dark` | optional OS tint override | ui-variables.less:33-40 |
