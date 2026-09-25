/**
 * Shell icon adapters (shell-icons) (T-267 → T-268 seam). Every export delegates to the
 * monochrome stroke set in `components/icons/` (Agent-25). `print`,
 * `collapse-right`, `unreplied` landed in the registry — stubs removed.
 * Stable contract: `{size?, className?, title?}`.
 */
// NOTE: "./icons" resolves to THIS file (icons.tsx shadows icons/) — the
// registry lives behind the explicit directory specifier.
import { Icon } from "./icons/index";
import type { IconName } from "./icons/index";

export interface IconProps {
  /** Edge length in px (default 16). */
  size?: number;
  className?: string;
  /** Accessible name; omit (default) for decorative use. */
  title?: string;
}

function named(name: IconName) {
  return function NamedIcon({ size = 16, className, title }: IconProps) {
    return <Icon name={name} size={size} className={className} label={title} />;
  };
}

/* ---------- mapped to the T-268 registry ---------- */

export const IconMenu = named("menu");
export const IconSearch = named("search");
export const IconPlus = named("plus");
export const IconRefresh = named("refresh");
export const IconReply = named("reply");
export const IconReplyAll = named("reply-all");
export const IconForward = named("forward");
export const IconFlag = named("flag");
export const IconArchive = named("archive");
export const IconSnooze = named("snooze");
export const IconBolt = named("bolt");
export const IconTrash = named("trash");
export const IconChevronDown = named("chevron-down");
export const IconChevronRight = named("chevron-right");
export const IconChevronUp = named("chevron-up");
export const IconStar = named("star");
export const IconPaperclip = named("paperclip");
export const IconMore = named("more");
export const IconMail = named("mail");
export const IconCalendar = named("calendar");
export const IconContacts = named("accounts");
export const IconTasks = named("agenda");
export const IconInbox = named("inbox");
export const IconOutbox = named("outbox");
export const IconSent = named("send");
export const IconDrafts = named("file");
export const IconJunk = named("shield-x");
export const IconUnread = named("mail-open");
export const IconFolder = named("folder");
export const IconCheck = named("check");
export const IconClose = named("close");
export const IconFilter = named("filters");
export const IconCommand = named("command");
export const IconHelp = named("help-circle");
export const IconLock = named("lock");
export const IconShield = named("shield-check");
export const IconSettings = named("settings");
export const IconUser = named("account-circle");
export const IconCompose = named("compose");
export const IconPrint = named("print");
export const IconCollapseRight = named("collapse-right");
export const IconUnreplied = named("unreplied");
