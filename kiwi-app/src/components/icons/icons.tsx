/**
 * KIWI icon registry (T-268) — hand-authored monochrome stroke glyphs on a
 * 16×16 grid. `stroke="currentColor"`, round caps/joins; `fill` glyphs are
 * marked per-entry. No icon-library dependency, no remote assets.
 *
 * Emoji/glyph → icon mapping for the emoji-replacement pass (inventoried
 * 2026-09-25 via regex sweep of src/): see README.md in this directory.
 */
import type { ReactNode } from "react";

export interface IconDef {
  /** Inner SVG nodes rendered inside the 16×16 viewBox. */
  body: ReactNode;
  /** Fill-mode glyph (uses `fill="currentColor"`, no stroke). */
  fill?: boolean;
}

export const ICONS = {
  /* ---------- mail primitives ---------- */

  mail: {
    body: (
      <>
        <rect x="1.6" y="3.1" width="12.8" height="9.8" rx="1.4" />
        <path d="m2.3 4.5 5.7 4.3 5.7-4.3" />
      </>
    ),
  },
  "mail-open": {
    body: (
      <>
        <path d="M8 1.9 2.5 6.2 8 9.7l5.5-3.5z" />
        <path d="M2.5 6.2v5.3A1.5 1.5 0 0 0 4 13h8a1.5 1.5 0 0 0 1.5-1.5V6.2" />
      </>
    ),
  },
  inbox: {
    body: (
      <>
        <path d="M2.5 8.6v2.9A1.5 1.5 0 0 0 4 13h8a1.5 1.5 0 0 0 1.5-1.5V8.6" />
        <path d="M2.5 8.6h3.2l.8 1.4h3l.8-1.4h3.2" />
        <path d="M8 2.4v3.8M5.9 4.3 8 6.4l2.1-2.1" />
      </>
    ),
  },
  outbox: {
    body: (
      <>
        <path d="M2.5 8.6v2.9A1.5 1.5 0 0 0 4 13h8a1.5 1.5 0 0 0 1.5-1.5V8.6" />
        <path d="M2.5 8.6h3.2l.8 1.4h3l.8-1.4h3.2" />
        <path d="M8 6.4V2.6M5.9 4.5 8 2.4l2.1 2.1" />
      </>
    ),
  },
  send: {
    body: (
      <>
        <path d="M14.7 1.3 10 14.7 7.3 8.7 1.3 6z" />
        <path d="M14.7 1.3 7.3 8.7" />
      </>
    ),
  },
  compose: {
    body: (
      <>
        <path d="M10.9 2.6a1.5 1.5 0 0 1 2.1 0l.4.4a1.5 1.5 0 0 1 0 2.1l-7 7-3 .9.9-3z" />
        <path d="m9.9 3.6 2.5 2.5" />
      </>
    ),
  },

  /* ---------- message actions ---------- */

  reply: {
    body: (
      <>
        <path d="M6.5 3.2 2.4 7.3l4.1 4.1" />
        <path d="M2.6 7.3h6.2a4.6 4.6 0 0 1 4.6 4.6v.9" />
      </>
    ),
  },
  "reply-all": {
    body: (
      <>
        <path d="M6.6 3.2 2.5 7.3l4.1 4.1" />
        <path d="M10.3 3.2 6.2 7.3l4.1 4.1" />
        <path d="M2.7 7.3h5.9a4.6 4.6 0 0 1 4.6 4.6v.9" />
      </>
    ),
  },
  forward: {
    body: (
      <>
        <path d="M9.5 3.2l4.1 4.1-4.1 4.1" />
        <path d="M13.4 7.3H7.2a4.6 4.6 0 0 0-4.6 4.6v.9" />
      </>
    ),
  },
  archive: {
    body: (
      <>
        <rect x="2" y="2.4" width="12" height="3.1" rx="0.9" />
        <path d="M3.2 5.5v6A1.5 1.5 0 0 0 4.7 13h6.6a1.5 1.5 0 0 0 1.5-1.5v-6" />
        <path d="M6.4 8.2h3.2" />
      </>
    ),
  },
  snooze: {
    body: (
      <>
        <circle cx="8" cy="8" r="5.6" />
        <path d="M8 5v3.2l2.3 1.5" />
      </>
    ),
  },
  trash: {
    body: (
      <>
        <path d="M2.6 3.9h10.8" />
        <path d="M6.2 3.9V3a.9.9 0 0 1 .9-.9h1.8a.9.9 0 0 1 .9.9v.9" />
        <path d="M3.9 3.9l.6 8.4a1.5 1.5 0 0 0 1.5 1.4h4a1.5 1.5 0 0 0 1.5-1.4l.6-8.4" />
        <path d="M6.6 6.4v4.4M9.4 6.4v4.4" />
      </>
    ),
  },
  star: {
    body: (
      <path d="M8 1.9l1.9 3.8 4.2.6-3 3 .7 4.1L8 11.5l-3.8 1.9.7-4.1-3-3 4.2-.6z" />
    ),
  },
  "star-filled": {
    fill: true,
    body: (
      <path d="M8 1.9l1.9 3.8 4.2.6-3 3 .7 4.1L8 11.5l-3.8 1.9.7-4.1-3-3 4.2-.6z" />
    ),
  },
  paperclip: {
    body: (
      <path d="m14.3 7.4-6.1 6.1a4 4 0 0 1-5.7-5.6l6.1-6.1a2.67 2.67 0 0 1 3.8 3.7l-6.2 6.1a1.33 1.33 0 0 1-1.9-1.9l5.7-5.6" />
    ),
  },
  image: {
    body: (
      <>
        <rect x="1.6" y="2.6" width="12.8" height="10.8" rx="1.4" />
        <circle cx="5.6" cy="6" r="1.2" />
        <path d="m14.4 10.2-3.2-3.2a1 1 0 0 0-1.4 0L4.2 12.8" />
      </>
    ),
  },
  flag: {
    body: (
      <>
        <path d="M3.4 14V2.6" />
        <path d="M3.4 3.1c2.8-1.6 5.6 1.6 9.2 0v6.4c-3.6 1.6-6.4-1.6-9.2 0" />
      </>
    ),
  },

  /* ---------- chrome / navigation ---------- */

  search: {
    body: (
      <>
        <circle cx="7" cy="7" r="4.6" />
        <path d="m10.4 10.4 3.4 3.4" />
      </>
    ),
  },
  menu: {
    body: <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />,
  },
  "chevron-down": { body: <path d="m4 6 4 4 4-4" /> },
  "chevron-up": { body: <path d="m4 10 4-4 4 4" /> },
  "chevron-left": { body: <path d="m10 4-4 4 4 4" /> },
  "chevron-right": { body: <path d="m6 4 4 4-4 4" /> },
  "arrow-left": { body: <path d="M13.5 8h-11M6 4.5 2.5 8l3.5 3.5" /> },
  "arrow-right": { body: <path d="M2.5 8h11M10 4.5 13.5 8 10 11.5" /> },
  "arrow-up": { body: <path d="M8 13.5v-11M4.5 6 8 2.5l3.5 3.5" /> },
  "arrow-down": { body: <path d="M8 2.5v11M4.5 10 8 13.5l3.5-3.5" /> },
  refresh: {
    body: (
      <>
        <path d="M15.3 2.7v4h-4" />
        <path d="M.7 13.3v-4h4" />
        <path d="M2.3 6a6 6 0 0 1 9.9-2.2l3.1 2.9M.7 9.3l3.1 2.9A6 6 0 0 0 13.7 10" />
      </>
    ),
  },
  sync: {
    body: (
      <>
        <path d="M5 13.5V2.5M5 13.5 2.8 11.3M5 13.5l2.2-2.2" />
        <path d="M11 2.5v11M11 2.5 8.8 4.7M11 2.5l2.2 2.2" />
      </>
    ),
  },
  bolt: {
    body: <path d="M8.7 1.3 2 9.3h4l-.7 5.4 6.7-8h-4z" />,
  },
  plus: { body: <path d="M8 2.6v10.8M2.6 8h10.8" /> },
  more: {
    fill: true,
    body: (
      <>
        <circle cx="3.4" cy="8" r="1.05" />
        <circle cx="8" cy="8" r="1.05" />
        <circle cx="12.6" cy="8" r="1.05" />
      </>
    ),
  },
  command: {
    body: (
      <path d="M12 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2 2 2 0 0 0 2-2 2 2 0 0 0-2-2H4a2 2 0 0 0-2 2 2 2 0 0 0 2 2 2 2 0 0 0 2-2V4a2 2 0 0 0-2-2 2 2 0 0 0-2 2 2 2 0 0 0 2 2h8a2 2 0 0 0 2-2 2 2 0 0 0-2-2z" />
    ),
  },
  print: {
    body: (
      <>
        <path d="M4.5 6V2.5h7V6" />
        <path d="M4.5 11.5H2.5v-6h11v6h-2" />
        <path d="M4.5 9.5h7v4h-7z" />
      </>
    ),
  },
  "collapse-right": {
    body: <path d="M6 3.5 9.5 8 6 12.5M10 3.5 13.5 8 10 12.5" />,
  },
  "collapse-left": {
    body: <path d="M10 3.5 6.5 8l3.5 4.5M6 3.5 2.5 8 6 12.5" />,
  },
  unreplied: {
    body: (
      <>
        <path d="M6.5 3.5 3 7l3.5 3.5" />
        <path d="M3.5 7h5a4 4 0 0 1 4 4v2" />
        <path d="m12.5 3.5-3 3" />
      </>
    ),
  },
  external: {
    body: (
      <>
        <path d="M6.6 3.4H3.2v9.4h9.4V9.4" />
        <path d="M9.2 3.2h3.6v3.6" />
        <path d="M12.7 3.3 7.4 8.6" />
      </>
    ),
  },
  link: {
    body: (
      <>
        <path d="M6.6 9.4l2.8-2.8" />
        <path d="M7.4 4.7l1.9-1.9a2.4 2.4 0 0 1 3.4 3.4l-1.9 1.9" />
        <path d="M8.6 11.3l-1.9 1.9a2.4 2.4 0 0 1-3.4-3.4l1.9-1.9" />
      </>
    ),
  },
  download: {
    body: (
      <>
        <path d="M8 2.2v7.2M5.2 6.6 8 9.4l2.8-2.8" />
        <path d="M2.6 13.4h10.8" />
      </>
    ),
  },

  /* ---------- folders / identity ---------- */

  folder: {
    body: (
      <path d="M2.2 4.6A1.6 1.6 0 0 1 3.8 3h2.5l1.4 1.9h4.5a1.6 1.6 0 0 1 1.6 1.6v4.9a1.6 1.6 0 0 1-1.6 1.6H3.8a1.6 1.6 0 0 1-1.6-1.6z" />
    ),
  },
  "folder-open": {
    body: (
      <>
        <path d="M2.4 11.9V4.6A1.6 1.6 0 0 1 4 3h2.3l1.4 1.9h4.4a1.6 1.6 0 0 1 1.5 1.6v.4" />
        <path d="M2.4 8h10.9a1.2 1.2 0 0 1 1.1 1.6l-1.2 3.4a1.5 1.5 0 0 1-1.4 1H3.4a1.2 1.2 0 0 1-1.1-1.6z" />
      </>
    ),
  },
  account: {
    body: (
      <>
        <circle cx="8" cy="5.2" r="2.7" />
        <path d="M3.2 13.6a4.8 4.8 0 0 1 9.6 0" />
      </>
    ),
  },
  accounts: {
    body: (
      <>
        <circle cx="6.1" cy="5.4" r="2.4" />
        <path d="M1.9 13.6a4.2 4.2 0 0 1 8.4 0" />
        <path d="M10.6 3.4a2.4 2.4 0 0 1 0 4.5" />
        <path d="M11.9 9.6a4.2 4.2 0 0 1 2.2 4" />
      </>
    ),
  },
  "account-circle": {
    body: (
      <>
        <circle cx="8" cy="8" r="5.8" />
        <circle cx="8" cy="6.2" r="1.9" />
        <path d="M4.2 12.5a4.4 4.4 0 0 1 7.6 0" />
      </>
    ),
  },
  checkbox: {
    body: <rect x="2.6" y="2.6" width="10.8" height="10.8" rx="1.8" />,
  },
  "checkbox-checked": {
    body: (
      <>
        <rect x="2.6" y="2.6" width="10.8" height="10.8" rx="1.8" />
        <path d="m5 8.1 2.1 2.1L11 6.3" />
      </>
    ),
  },
  agenda: {
    body: (
      <>
        <rect x="2.2" y="3" width="11.6" height="10.6" rx="1.4" />
        <path d="M2.2 6.6h11.6M5.4 1.6v2.6M10.6 1.6v2.6" />
        <path d="m5.7 9.8 1.4 1.4 2.6-2.6" />
      </>
    ),
  },
  calendar: {
    body: (
      <>
        <rect x="2.2" y="3" width="11.6" height="10.6" rx="1.4" />
        <path d="M2.2 6.6h11.6M5.4 1.6v2.6M10.6 1.6v2.6" />
      </>
    ),
  },
  list: {
    body: (
      <>
        <path d="M5.6 4h7.9M5.6 8h7.9M5.6 12h7.9" />
        <path d="M2.6 4h.01M2.6 8h.01M2.6 12h.01" />
      </>
    ),
  },
  clock: {
    body: (
      <>
        <circle cx="8" cy="8" r="5.6" />
        <path d="M8 4.8V8l2.2 1.4" />
      </>
    ),
  },
  file: {
    body: (
      <>
        <path d="M9.2 1.9H4.4A1.4 1.4 0 0 0 3 3.3v9.4a1.4 1.4 0 0 0 1.4 1.4h7.2a1.4 1.4 0 0 0 1.4-1.4V5.2z" />
        <path d="M9.2 1.9v3.3H13" />
      </>
    ),
  },

  /* ---------- security / status ---------- */

  lock: {
    body: (
      <>
        <rect x="3.4" y="7" width="9.2" height="6.6" rx="1.3" />
        <path d="M5.4 7V5.2a2.6 2.6 0 0 1 5.2 0V7" />
        <path d="M8 9.7v1.4" />
      </>
    ),
  },
  unlock: {
    body: (
      <>
        <rect x="3.4" y="7" width="9.2" height="6.6" rx="1.3" />
        <path d="M5.4 7V5.2a2.6 2.6 0 0 1 5.1-.9" />
        <path d="M8 9.7v1.4" />
      </>
    ),
  },
  key: {
    body: (
      <>
        <circle cx="5.2" cy="9.4" r="2.7" />
        <path d="m7.3 7.5 5.5-4.8" />
        <path d="m10.6 4.7 1.5 1.3M9 6l1.2 1" />
      </>
    ),
  },
  device: {
    body: (
      <>
        <rect x="5" y="1.8" width="6" height="12.4" rx="1.5" />
        <path d="M7.2 12.3h1.6" />
      </>
    ),
  },
  shield: {
    body: (
      <path d="M8 1.7 12.9 3.4v4.1c0 3.2-2.1 5.2-4.9 6.4-2.8-1.2-4.9-3.2-4.9-6.4V3.4z" />
    ),
  },
  "shield-check": {
    body: (
      <>
        <path d="M8 1.7 12.9 3.4v4.1c0 3.2-2.1 5.2-4.9 6.4-2.8-1.2-4.9-3.2-4.9-6.4V3.4z" />
        <path d="m5.9 7.5 1.4 1.4 2.8-2.8" />
      </>
    ),
  },
  "shield-x": {
    body: (
      <>
        <path d="M8 1.7 12.9 3.4v4.1c0 3.2-2.1 5.2-4.9 6.4-2.8-1.2-4.9-3.2-4.9-6.4V3.4z" />
        <path d="m6.2 6.4 3.6 3.6M9.8 6.4l-3.6 3.6" />
      </>
    ),
  },
  settings: {
    body: (
      <>
        <circle cx="8" cy="8" r="2.2" />
        <path d="M8 1.9v1.7M8 12.4v1.7M1.9 8h1.7M12.4 8h1.7M3.7 3.7l1.2 1.2M11.1 11.1l1.2 1.2M12.3 3.7l-1.2 1.2M4.9 11.1l-1.2 1.2" />
      </>
    ),
  },
  filters: {
    body: <path d="M2.4 3h11.2l-4.4 5.2v4l-2.4 1.4V8.2z" />,
  },
  puzzle: {
    body: (
      <path d="M8 1.8a1.7 1.7 0 0 1 1.7 1.7v.8h2.3a1.3 1.3 0 0 1 1.3 1.3v2.2h.8a1.7 1.7 0 1 1 0 3.4h-.8v1.3a1.3 1.3 0 0 1-1.3 1.3H4.3a1.3 1.3 0 0 1-1.3-1.3V5.6a1.3 1.3 0 0 1 1.3-1.3h2V3.5A1.7 1.7 0 0 1 8 1.8z" />
    ),
  },
  bell: {
    body: (
      <>
        <path d="M8 1.9v.9" />
        <path d="M11.9 10.4H4.1l1.1-1.6V6.6a2.8 2.8 0 0 1 5.6 0v2.2z" />
        <path d="M6.9 12.7a1.3 1.3 0 0 0 2.2 0" />
      </>
    ),
  },
  "bell-off": {
    body: (
      <>
        <path d="M8 1.9v.9" />
        <path d="M5.2 8.8l-1.1 1.6h6.4" />
        <path d="M5.2 6.9V6.6a2.8 2.8 0 0 1 4.2-2.4" />
        <path d="M10.8 8.5V6.9" />
        <path d="M6.9 12.7a1.3 1.3 0 0 0 2.2-.3" />
        <path d="M2.5 2.5l11 11" />
      </>
    ),
  },
  eye: {
    body: (
      <>
        <path d="M1.7 8S4.1 4.2 8 4.2 14.3 8 14.3 8 11.9 11.8 8 11.8 1.7 8 1.7 8z" />
        <circle cx="8" cy="8" r="1.9" />
      </>
    ),
  },
  "eye-off": {
    body: (
      <>
        <path d="M4.3 5.2C2.9 6.3 1.7 8 1.7 8s2.2 3.8 6.3 3.8a6 6 0 0 0 2.9-.7M11.9 10.5c1.3-1 2.4-2.5 2.4-2.5s-2.2-3.8-6.3-3.8a6.1 6.1 0 0 0-1.6.2" />
        <path d="M6.6 6.9a1.9 1.9 0 0 0 2.7 2.5" />
        <path d="M2.4 2.4l11.2 11.2" />
      </>
    ),
  },

  /* ---------- status / feedback ---------- */

  check: { body: <path d="m2.8 8.4 3.4 3.4 7.6-7.2" /> },
  close: { body: <path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6" /> },
  "check-circle": {
    body: (
      <>
        <circle cx="8" cy="8" r="5.7" />
        <path d="m5.3 8.2 1.9 1.9 3.5-3.8" />
      </>
    ),
  },
  "x-circle": {
    body: (
      <>
        <circle cx="8" cy="8" r="5.7" />
        <path d="m5.8 5.8 4.4 4.4M10.2 5.8l-4.4 4.4" />
      </>
    ),
  },
  "alert-triangle": {
    body: (
      <>
        <path d="M8 2.1 14.6 13.2H1.4z" />
        <path d="M8 6.4v2.8M8 11.4h.01" />
      </>
    ),
  },
  info: {
    body: (
      <>
        <circle cx="8" cy="8" r="5.7" />
        <path d="M8 7.3V11M8 4.7h.01" />
      </>
    ),
  },
  "help-circle": {
    body: (
      <>
        <circle cx="8" cy="8" r="5.7" />
        <path d="M6.3 6a1.8 1.8 0 0 1 3.5.6c0 1.1-1.8 1.5-1.8 2.5" />
        <path d="M8 11.7h.01" />
      </>
    ),
  },
  help: {
    body: (
      <>
        <path d="M6.3 6a1.8 1.8 0 0 1 3.5.6c0 1.1-1.8 1.5-1.8 2.5" />
        <path d="M8 11.7h.01" />
      </>
    ),
  },
  blocked: {
    body: (
      <>
        <circle cx="8" cy="8" r="5.7" />
        <path d="m4.2 4.2 7.6 7.6" />
      </>
    ),
  },
  dot: {
    fill: true,
    body: <circle cx="8" cy="8" r="2.6" />,
  },

  /* ---------- appearance ---------- */

  sun: {
    body: (
      <>
        <circle cx="8" cy="8" r="3" />
        <path d="M8 1.6v1.5M8 12.9v1.5M1.6 8h1.5M12.9 8h1.5M3.3 3.3l1 1M11.7 11.7l1 1M12.7 3.3l-1 1M4.3 11.7l-1 1" />
      </>
    ),
  },
  moon: {
    body: <path d="M13.5 9.7A5.9 5.9 0 0 1 6.3 2.5a5.9 5.9 0 1 0 7.2 7.2z" />,
  },
  monitor: {
    body: (
      <>
        <rect x="2" y="2.8" width="12" height="8.6" rx="1.3" />
        <path d="M6 14h4M8 11.4V14" />
      </>
    ),
  },

  /* ---------- window caption controls ----------
   * Win11 caption glyphs (undecorated window): minimize is a centered rule,
   * maximize a single rounded square, restore the two overlapping squares.
   * Same 16x16 stroke grid + currentColor as every other entry, so they
   * inherit the active theme's ink without extra theming. */
  minimize: {
    body: <path d="M3.4 11.4h9.2" />,
  },
  maximize: {
    body: <rect x="3" y="3" width="10" height="10" rx="1.4" />,
  },
  restore: {
    body: (
      <>
        <rect x="2.4" y="5.2" width="8.4" height="8.4" rx="1.3" />
        <path d="M5.4 5.2V3.8A1.4 1.4 0 0 1 6.8 2.4h5.4A1.4 1.4 0 0 1 13.6 3.8v5.4a1.4 1.4 0 0 1-1.4 1.4h-1.4" />
      </>
    ),
  },
} satisfies Record<string, IconDef>;

export type IconName = keyof typeof ICONS;

export function isIconName(value: unknown): value is IconName {
  return typeof value === "string" && value in ICONS;
}

/**
 * Severity → icon for trust pills / finding badges. Mirrors
 * `severityGlyph` in ../kiwi.ts (which stays as the text fallback for
 * non-React surfaces); glyph + label keeps meaning non-color-only.
 */
export const SEVERITY_ICON = {
  secure: "check-circle",
  warning: "alert-triangle",
  danger: "x-circle",
  unknown: "help-circle",
} satisfies Record<string, IconName>;
