// Adapter for Mailspring `app/src/components/mail-label-set.tsx`. The vendor
// renders `MailLabel` chips for `thread.sortedCategories()` filtered by
// CategoryStore/hidden-category rules — KIWI has no label/folder categories
// per thread, but `MessageView.category` (F2 tab slug) is the honest analog,
// carried per message. This renders one `.em-cat-pill` per distinct category
// on the thread's messages, inside the same `thread-injected-mail-labels`
// InjectedComponentSet wrapper the vendor emits.
import React from "react";
import type { MessageCategory } from "../kiwi";
import { InjectedComponentSet } from "./ms-injected-component";
import type { MsThread } from "./ms-thread";

/** Same category→pill mapping as the mailbox rows (T-201 eM idiom). */
const CATEGORY_PILL: Record<MessageCategory, { label: string; cls: string } | null> = {
  primary: { label: "Personal", cls: "em-cat-personal" },
  newsletters: { label: "News", cls: "em-cat-news" },
  social: { label: "Social", cls: "em-cat-social" },
  notifications: { label: "Logs", cls: "em-cat-logs" },
  other: { label: "Other", cls: "em-cat-other" },
};

type MailLabelSetProps = {
  thread: MsThread;
  messages?: any[];
  includeCurrentCategories?: boolean;
  removable?: boolean;
};

export default class MailLabelSet extends React.Component<MailLabelSetProps> {
  static displayName = "MailLabelSet";

  render() {
    const { thread, messages } = this.props;
    const msgs = thread.__messages ?? [];
    const seen = new Set<MessageCategory>();
    const labels: React.ReactNode[] = [];
    for (const m of msgs) {
      const cat = (m.__env.category ?? "primary") as MessageCategory;
      if (seen.has(cat)) continue;
      seen.add(cat);
      const pill = CATEGORY_PILL[cat];
      if (!pill) continue;
      labels.push(
        <span key={cat} className={`em-cat-pill ${pill.cls}`} aria-label={`Category: ${pill.label}`}>
          {pill.label}
        </span>,
      );
    }
    return (
      <InjectedComponentSet
        inline
        containersRequired={false}
        matching={{ role: "Thread:MailLabel" }}
        className="thread-injected-mail-labels"
        exposedProps={{ thread, messages }}
      >
        {labels}
      </InjectedComponentSet>
    );
  }
}
