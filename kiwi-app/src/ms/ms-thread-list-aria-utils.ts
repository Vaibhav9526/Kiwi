// Ported from Mailspring
// `app/internal_packages/thread-list/lib/thread-list-aria-utils.ts` —
// verbatim label composition.
//
// Seams adapted: `FocusedPerspectiveStore`/`localized`/`Thread` →
// `./ms-thread`/`./ms-i18n`; `DateUtils` → `./ms-date-utils` (native-Date
// port). `thread.labels`/`__messages` read off the MsThread adapter.
import { FocusedPerspectiveStore } from "./ms-thread";
import { DateUtils } from "./ms-date-utils";
import { localized } from "./ms-i18n";
import type { MsThread } from "./ms-thread";

export function threadAriaLabel(thread: MsThread): string {
  const parts: string[] = [];

  if (thread.unread) parts.push(localized("Unread"));

  const participants = thread.participants || [];
  const names = participants
    .filter((c) => !c.isMe())
    .slice(0, 3)
    .map((c) => c.displayName({ compact: false }))
    .join(", ");
  if (names) parts.push(names);

  const subj = (thread.subject || "").trim() || localized("No Subject");
  parts.push(subj);

  const isSent = FocusedPerspectiveStore.current().isSent?.();
  const rawTs = isSent ? thread.lastMessageSentTimestamp : thread.lastMessageReceivedTimestamp;
  if (rawTs) parts.push(DateUtils.shortTimeString(rawTs));

  const msgCount = thread.__messages?.length || 0;
  if (msgCount > 1) parts.push(localized("%1$@ messages", msgCount));

  if (thread.attachmentCount > 0) parts.push(localized("has attachment"));
  if (thread.starred) parts.push(localized("starred"));

  return parts.join(", ");
}
