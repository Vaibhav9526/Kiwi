// Ported from Mailspring
// `app/internal_packages/thread-list/lib/thread-list-icon.tsx` — icon
// class-name logic + star toggle verbatim.
//
// Seams adapted:
//  - `localized` → `./ms-i18n`.
//  - `Actions`/`TaskFactory` → `./ms-thread` task bridge — queueTask routes
//    `invert-starred` tasks to the row's KIWI onToggleStar handler.
//  - `ExtensionRegistry.ThreadList.extensions()` → honest empty list.
//  - `ThreadWithMessagesMetadata` → `MsThread` (./ms-thread).
import React from "react";
import { localized } from "./ms-i18n";
import { Actions, TaskFactory, ExtensionRegistry } from "./ms-thread";
import type { MsThread } from "./ms-thread";

function nonDraftMessages(thread: MsThread) {
  const msgs = thread.__messages;
  if (!msgs || !(msgs instanceof Array)) {
    return [];
  }
  return msgs.filter((m) => m.id && !m.draft);
}

function iconClassNames(thread: MsThread) {
  if (!thread) {
    return "thread-icon-star-on-hover";
  }

  const extensionIconClassNames = ExtensionRegistry.ThreadList.extensions()
    .filter((ext) => ext.cssClassNamesForThreadListIcon != null)
    .reduce((prev, ext) => prev + " " + ext.cssClassNamesForThreadListIcon!(thread), "")
    .trim();
  if (extensionIconClassNames.length > 0) {
    return extensionIconClassNames;
  }

  if (thread.starred) {
    return "thread-icon-star";
  }
  if (thread.unread) {
    return "thread-icon-unread thread-icon-star-on-hover";
  }

  const msgs = nonDraftMessages(thread);
  const last = msgs[msgs.length - 1];

  if (msgs.length > 1 && (last.from[0] != null ? last.from[0].isMe() : undefined)) {
    if (last.isForwarded()) {
      return "thread-icon-forwarded thread-icon-star-on-hover";
    } else {
      return "thread-icon-replied thread-icon-star-on-hover";
    }
  }

  return "thread-icon-none thread-icon-star-on-hover";
}

const ThreadListIcon: React.FC<{ thread: MsThread }> = React.memo(
  ({ thread }) => {
    const starred = thread && thread.starred;
    const ariaLabel = starred ? localized("Unstar") : localized("Star");

    const onToggleStar = (event: React.MouseEvent | React.KeyboardEvent) => {
      Actions.queueTask(
        TaskFactory.taskForInvertingStarred({
          threads: [thread],
          source: "Thread List Icon",
        })
      );
      event.stopPropagation();
    };

    const onKeyDown = (event: React.KeyboardEvent) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        onToggleStar(event);
      }
    };

    return (
      <div
        className={`thread-icon ${iconClassNames(thread)}`}
        role="button"
        tabIndex={-1}
        aria-label={ariaLabel}
        aria-pressed={starred || false}
        title={ariaLabel}
        onClick={onToggleStar}
        onKeyDown={onKeyDown}
      />
    );
  },
  (prev, next) => prev.thread === next.thread
);
ThreadListIcon.displayName = "ThreadListIcon";

export default ThreadListIcon;
