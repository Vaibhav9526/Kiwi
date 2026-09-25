/**
 * STUB monochrome stroke icon set (T-267). Placeholder components so the
 * eM-idiom shell ships emoji-free; every export is a TODO(icon) marker —
 * A25 replaces these with the real set under `components/icons/` (T-268).
 * Keep exported names + the `size`/`className` prop contract stable so the
 * swap is a pure re-export.
 *
 * Style contract: 16×16 grid, `currentColor` strokes, `fill="none"`,
 * strokeWidth 1.5, round caps — matches the owner-supplied reference
 * (monochrome outline glyphs, never filled pictographs).
 */
import type { ReactNode } from "react";

export interface IconProps {
  /** Edge length in px (default 16). */
  size?: number;
  className?: string;
  /** Accessible name; omit (default) for decorative use. */
  title?: string;
}

function Stroke({ size = 16, className, title, children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      className={`em-icon${className ? ` ${className}` : ""}`}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
    >
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  );
}

// TODO(icon): hamburger
export function IconMenu(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2 4h12M2 8h12M2 12h12" />
    </Stroke>
  );
}

// TODO(icon): search magnifier
export function IconSearch(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 14 14" />
    </Stroke>
  );
}

// TODO(icon): plus
export function IconPlus(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M8 2.5v11M2.5 8h11" />
    </Stroke>
  );
}

// TODO(icon): refresh / sync circular arrow
export function IconRefresh(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M13 8A5 5 0 1 1 8 3c1.8 0 3.4.9 4.2 2.3" />
      <path d="M12.9 2.3v3h-3" />
    </Stroke>
  );
}

// TODO(icon): reply (left return arrow)
export function IconReply(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M6.5 3 2.5 7l4 4" />
      <path d="M3 7h6.5a4 4 0 0 1 4 4v2" />
    </Stroke>
  );
}

// TODO(icon): reply-all (double return arrows)
export function IconReplyAll(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M4.5 4 1.5 7l3 3M8.5 4 5.5 7l3 3" />
      <path d="M9 7h2.5a3 3 0 0 1 3 3v3" />
    </Stroke>
  );
}

// TODO(icon): forward (right arrow)
export function IconForward(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M9.5 3l4 4-4 4" />
      <path d="M13 7H6.5a4 4 0 0 0-4 4v2" />
    </Stroke>
  );
}

// TODO(icon): flag (mark / flagged)
export function IconFlag(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M3 14V2.5" />
      <path d="M3 3h9l-2 3.5L12 10H3" />
    </Stroke>
  );
}

// TODO(icon): archive box
export function IconArchive(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 3.5h11v3h-11z" />
      <path d="M4 6.5v6h8v-6" />
      <path d="M6.5 9h3" />
    </Stroke>
  );
}

// TODO(icon): snooze clock
export function IconSnooze(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="8" cy="9" r="5" />
      <path d="M8 6v3l2.2 1.3" />
      <path d="M5.5 2 3.5 3.7M10.5 2l2 1.7" />
    </Stroke>
  );
}

// TODO(icon): quick-actions lightning bolt
export function IconBolt(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M9 1.5 3.5 9H7l-1 5.5L11.5 7H8l1-5.5z" />
    </Stroke>
  );
}

// TODO(icon): trash / delete
export function IconTrash(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 4h11M6 4V2.5h4V4" />
      <path d="M4 4l.7 9.5h6.6L12 4" />
      <path d="M6.5 6.5v4.5M9.5 6.5v4.5" />
    </Stroke>
  );
}

// TODO(icon): chevron down
export function IconChevronDown(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M4 6l4 4 4-4" />
    </Stroke>
  );
}

// TODO(icon): chevron right
export function IconChevronRight(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M6 4l4 4-4 4" />
    </Stroke>
  );
}

// TODO(icon): chevron up
export function IconChevronUp(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M4 10l4-4 4 4" />
    </Stroke>
  );
}

// TODO(icon): star outline
export function IconStar(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M8 2l1.8 3.7 4.2.6-3 3 .7 4.2L8 11.7l-3.7 1.8.7-4.2-3-3 4.2-.6L8 2z" />
    </Stroke>
  );
}

// TODO(icon): paperclip (attachments)
export function IconPaperclip(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M11 3.5 5.6 8.9a2.1 2.1 0 0 0 3 3l5.4-5.4a3.6 3.6 0 0 0-5.1-5.1l-4.9 4.9" />
    </Stroke>
  );
}

// TODO(icon): printer
export function IconPrint(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M4.5 6V2.5h7V6" />
      <path d="M4.5 11.5H2.5v-6h11v6h-2" />
      <path d="M4.5 9.5h7v4h-7z" />
    </Stroke>
  );
}

// TODO(icon): overflow ellipsis
export function IconMore(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="3.5" cy="8" r="0.9" />
      <circle cx="8" cy="8" r="0.9" />
      <circle cx="12.5" cy="8" r="0.9" />
    </Stroke>
  );
}

// TODO(icon): mail envelope
export function IconMail(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 3.5h11v9h-11z" />
      <path d="m3 4.5 5 4 5-4" />
    </Stroke>
  );
}

// TODO(icon): calendar
export function IconCalendar(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 4h11v9.5h-11z" />
      <path d="M2.5 6.5h11M5 2.5v2.5M11 2.5v2.5" />
      <path d="M5 9.5h2M9 9.5h2M5 11.5h2" />
    </Stroke>
  );
}

// TODO(icon): contacts person
export function IconContacts(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="8" cy="5.5" r="2.7" />
      <path d="M3 13.5c0-2.8 2.2-4.5 5-4.5s5 1.7 5 4.5" />
    </Stroke>
  );
}

// TODO(icon): tasks checkbox list
export function IconTasks(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 4.5h3v3h-3z" />
      <path d="m3 6 .8.8L5 5.5" />
      <path d="M8 5h5.5M8 10.5h5.5" />
      <path d="M2.5 9.5h3v3h-3z" />
      <path d="m3 11 .8.8L5 10.5" />
    </Stroke>
  );
}

// TODO(icon): inbox tray
export function IconInbox(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 9.5 4 4h8l1.5 5.5v3h-11z" />
      <path d="M2.5 9.5H6a2 2 0 0 0 4 0h3.5" />
    </Stroke>
  );
}

// TODO(icon): outbox tray (arrow up)
export function IconOutbox(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 10 4 5h8l1.5 5v2.5h-11z" />
      <path d="M8 2.5v4M6 4l2-2 2 2" />
    </Stroke>
  );
}

// TODO(icon): sent paper-plane
export function IconSent(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="m2.5 8 11-5-3.2 10.5L8 10.5 2.5 8z" />
      <path d="m13.5 3-5.5 7.5" />
    </Stroke>
  );
}

// TODO(icon): drafts pencil-on-page
export function IconDrafts(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M9.5 2.5h-6v11h9v-7z" />
      <path d="M9.5 2.5v3h3" />
      <path d="M5.5 10.5 9 7l1.5 1.5L7 12l-2 .5z" />
    </Stroke>
  );
}

// TODO(icon): junk / spam shield-x
export function IconJunk(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M8 1.8 3 4v4c0 3 2.2 5.4 5 6.5 2.8-1.1 5-3.5 5-6.5V4L8 1.8z" />
      <path d="M6 6.5l4 4M10 6.5l-4 4" />
    </Stroke>
  );
}

// TODO(icon): unread (open envelope)
export function IconUnread(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 6.5 8 3l5.5 3.5v6h-11z" />
      <path d="M2.5 6.5 8 10l5.5-3.5" />
    </Stroke>
  );
}

// TODO(icon): unreplied (arrow with strike)
export function IconUnreplied(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M6.5 3.5 3 7l3.5 3.5" />
      <path d="M3.5 7h5a4 4 0 0 1 4 4v2" />
      <path d="m12.5 3.5-3 3" />
    </Stroke>
  );
}

// TODO(icon): plain folder
export function IconFolder(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 4h4l1.5 1.8h5.5v7.7h-11z" />
    </Stroke>
  );
}

// TODO(icon): check
export function IconCheck(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="m3 8.5 3.5 3.5L13 4.5" />
    </Stroke>
  );
}

// TODO(icon): filter funnel
export function IconFilter(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M2.5 3.5h11l-4.2 5v4.2L6.7 14V8.5z" />
    </Stroke>
  );
}

// TODO(icon): command palette ⌘
export function IconCommand(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M5 5h6v6H5z" />
      <path d="M5 5H4a1.5 1.5 0 1 1 1.5-1.5V5zM11 5h1a1.5 1.5 0 1 0-1.5-1.5V5zM5 11H4a1.5 1.5 0 1 0 1.5 1.5V11zM11 11h1a1.5 1.5 0 1 1-1.5 1.5V11z" />
    </Stroke>
  );
}

// TODO(icon): question mark / help
export function IconHelp(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="8" cy="8" r="6" />
      <path d="M6.2 6.2a1.9 1.9 0 1 1 2.6 1.8c-.6.3-.8.7-.8 1.5" />
      <path d="M8 12h.01" />
    </Stroke>
  );
}

// TODO(icon): lock
export function IconLock(p: IconProps) {
  return (
    <Stroke {...p}>
      <rect x="3.5" y="7" width="9" height="6.5" rx="1" />
      <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
      <path d="M8 9.5v1.8" />
    </Stroke>
  );
}

// TODO(icon): shield (security)
export function IconShield(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M8 1.8 3 4v4c0 3 2.2 5.4 5 6.5 2.8-1.1 5-3.5 5-6.5V4L8 1.8z" />
      <path d="m5.8 7.8 1.6 1.6 3-3" />
    </Stroke>
  );
}

// TODO(icon): settings gear
export function IconSettings(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="8" cy="8" r="2" />
      <path d="M8 1.8v1.9M8 12.3v1.9M1.8 8h1.9M12.3 8h1.9M3.6 3.6l1.3 1.3M11.1 11.1l1.3 1.3M12.4 3.6l-1.3 1.3M4.9 11.1l-1.3 1.3" />
    </Stroke>
  );
}

// TODO(icon): user/account circle
export function IconUser(p: IconProps) {
  return (
    <Stroke {...p}>
      <circle cx="8" cy="8" r="6" />
      <circle cx="8" cy="6.4" r="2" />
      <path d="M4.2 12.6c.7-1.9 2.1-2.9 3.8-2.9s3.1 1 3.8 2.9" />
    </Stroke>
  );
}

// TODO(icon): collapse/expand panel (double chevron)
export function IconCollapseRight(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M6 3.5 9.5 8 6 12.5M10 3.5 13.5 8 10 12.5" />
    </Stroke>
  );
}

// TODO(icon): leftwards pencil (compose)
export function IconCompose(p: IconProps) {
  return (
    <Stroke {...p}>
      <path d="M11.5 2.5a1.6 1.6 0 0 1 2 2L5 13l-2.7.7L3 11z" />
    </Stroke>
  );
}
