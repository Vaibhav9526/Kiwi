// Adapter factory + runtime bridges for the ported thread-list row
// components (`ms-thread-list-*`, `ms-list-tabular-*`).
//
// `msThreadFromEnvelope` / `msThreadFromThread` build the
// `ThreadWithMessagesMetadata`-shaped view model the ported resolvers
// consume (`__messages`, `participants`, `lastMessage*Timestamp`, …) from
// KIWI's real `MessageEnvelope`/`Thread` data — no Mailspring Model classes,
// no fabricated fields: `to` participants exist only when the envelope
// carries `toAddrs`; `files` carries a single marker entry when
// `hasAttachments` is true so the vendored `showIconForAttachments`
// predicate reflects the backend flag.
//
// Runtime seams adapted here (contract §forbidden deps):
//   Actions / TaskFactory     → dispatch to per-row handlers on thread.__kiwi
//   FocusedPerspectiveStore   → module-level perspective set by MailboxView
//   ExtensionRegistry         → empty extension list (KIWI has no plugins)
//   CategoryStore             → honest empty (KIWI has no label categories)
//   AccountStore colors       → registry seeded from AccountView.color
import type { MouseEvent as ReactMouseEvent } from "react";
import type { MessageCategory, MessageEnvelope } from "../kiwi";
import type { Thread } from "../threading";
import { Contact } from "./ms-contact";
import { Disposable } from "./ms-keymap";
import { emailIsEquivalent } from "./ms-utils";

/* ------------------------------------------------------------------ */
/* Contact seam: vendor `Contact.isMe()` → real account-email compare.  */
/* ------------------------------------------------------------------ */

export class MsContact extends Contact {
  me = false;

  isMe() {
    return this.me;
  }
}

/** "Full Name <addr@x>" → MsContact; bare address → {name:"", email}. */
export function contactFromAddress(raw: string, meEmail: string): MsContact {
  const m = (raw ?? "").match(/^(.*)<([^>]+)>\s*$/);
  const email = (m ? m[2] : (raw ?? "")).trim();
  const name = (m ? m[1] : "").trim().replace(/^["']|["']$/g, "");
  const c = new MsContact({ name, email });
  c.me = !!email && !!meEmail && emailIsEquivalent(email, meEmail);
  return c;
}

/** Split a To/Cc header value into contacts (comma/semicolon separated). */
export function contactsFromAddrList(raw: string | null | undefined, meEmail: string): MsContact[] {
  if (!raw) return [];
  const out: MsContact[] = [];
  for (const token of raw.split(/[,;]+/)) {
    const t = token.trim();
    if (!t) continue;
    out.push(contactFromAddress(t, meEmail));
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Message / Thread view-model factories                               */
/* ------------------------------------------------------------------ */

export interface MsMessage {
  id: string;
  draft: boolean;
  unread: boolean;
  snippet: string;
  from: MsContact[];
  to: MsContact[];
  /** Marker entries only: one `{size:0}` item when `hasAttachments`, so the
   *  vendored `showIconForAttachments(files)` predicate yields truth. */
  files: { size?: number; contentId?: string }[];
  date: Date | null;
  accountId: string;
  isFromMe(): boolean;
  isForwarded(): boolean;
  /** The envelope this view-model wraps — KIWI backend truth. */
  __env: MessageEnvelope;
}

export interface MsThread {
  id: string;
  accountId: string;
  subject: string;
  snippet: string;
  unread: boolean;
  starred: boolean;
  participants: MsContact[];
  labels: { id: string }[];
  attachmentCount: number;
  lastMessageSentTimestamp?: Date | null;
  lastMessageReceivedTimestamp?: Date | null;
  __messages: MsMessage[];
  /** KIWI row wiring — handlers/state the mailbox view stamps per row. */
  __kiwi: MsKiwiRow;
}

/** Row wiring the ported components dispatch into (KIWI seams). */
export interface MsKiwiRow {
  /** Row DOM id — `em-row` option element + aria-activedescendant target. */
  rowId: string;
  /** Envelope id used for navigation on plain click/Enter. */
  navId: string;
  /** Folder key + view flags. */
  folder: string;
  /** Every envelope id the row's bulk/pick/context actions target. */
  ids: string[];
  isPicked: boolean;
  /** Two-step delete: `confirmDel` arms the confirm pair in hover actions. */
  confirmDel: boolean;
  acctTag?: { label: string; color: string };
  /** Avatar chip content (mailbox's avatarTint/senderName mapping). */
  avatar: { initial: string; color: string };
  /** aria-label text (KIWI wording preserved — carries trust + pick state). */
  label: string;
  /** Drag payload (`application/x-kiwi-messages`). */
  dragIds?: string[];
  dragSubject?: string;
  onPick(range: boolean): void;
  onToggleStar(): void;
  onArchive(): void;
  /** First Delete click — arms the confirm pair (KIWI keeps its 2-step). */
  onRequestTrash(): void;
  onDelete(): void;
  onDisarmTrash(): void;
  onContextMenu(e: ReactMouseEvent): void;
}

function msMessageFromEnvelope(m: MessageEnvelope, draftsView: boolean): MsMessage {
  const from = m.from ? [contactFromAddress(m.from, m.accountEmail)] : [];
  const to = contactsFromAddrList(m.toAddrs, m.accountEmail);
  const date = m.date ? new Date(m.date) : null;
  return {
    id: m.id,
    draft: draftsView,
    unread: m.unread,
    snippet: m.snippet ?? "",
    from,
    to,
    files: m.hasAttachments ? [{ size: 0 }] : [],
    date: date && !Number.isNaN(date.getTime()) ? date : null,
    accountId: m.accountId,
    isFromMe() {
      return from.some((c) => c.me);
    },
    // KIWI envelopes carry no forwarded bit — honest `false` (unknown).
    isForwarded() {
      return false;
    },
    __env: m,
  };
}

function msThreadBase(
  messages: MessageEnvelope[],
  draftsView: boolean,
  row: MsKiwiRow,
): Omit<MsThread, "__messages"> {
  const ms = messages.map((m) => msMessageFromEnvelope(m, draftsView));
  const newest = messages[messages.length - 1];
  // Vendor semantics: the newest message sent by me vs received from others.
  const lastSent = [...ms].reverse().find((m) => m.isFromMe());
  const lastReceived = [...ms].reverse().find((m) => !m.isFromMe());
  const participants = new Map<string, MsContact>();
  for (const m of ms) {
    for (const c of m.isFromMe() ? m.to : m.from) {
      const key = (c.email || c.name).toLowerCase();
      if (key && !participants.has(key)) participants.set(key, c);
    }
  }
  return {
    id: row.rowId,
    accountId: newest?.accountId ?? "",
    subject: newest?.subject ?? "",
    snippet: newest?.snippet ?? "",
    unread: messages.some((m) => m.unread),
    starred: messages.some((m) => m.starred),
    participants: [...participants.values()],
    labels: [],
    attachmentCount: messages.filter((m) => m.hasAttachments).length,
    lastMessageSentTimestamp: lastSent?.date ?? null,
    lastMessageReceivedTimestamp: lastReceived?.date ?? null,
    __kiwi: row,
  };
}

/** Flat-list row: one envelope as a single-message thread. */
export function msThreadFromEnvelope(m: MessageEnvelope, ctx: MsRowContext): MsThread {
  const base = msThreadBase([m], ctx.draftsView, ctx.row);
  return { ...base, __messages: [msMessageFromEnvelope(m, ctx.draftsView)] };
}

/** Threads-mode row: KIWI subject-normalized Thread → Mailspring shape. */
export function msThreadFromThread(t: Thread, ctx: MsRowContext): MsThread {
  const base = msThreadBase(t.messages, ctx.draftsView, ctx.row);
  const participants = new Map<string, MsContact>();
  for (const m of t.messages) {
    const c = contactFromAddress(m.from, m.accountEmail);
    const key = c.email.toLowerCase() || c.name.toLowerCase();
    if (key && !participants.has(key)) participants.set(key, c);
  }
  return {
    ...base,
    subject: t.subject,
    participants: [...participants.values()],
    __messages: t.messages.map((m) => msMessageFromEnvelope(m, ctx.draftsView)),
  };
}

/** Context the row host supplies per adapt — view state, not model data. */
export interface MsRowContext {
  draftsView: boolean;
  row: MsKiwiRow;
}

/* ------------------------------------------------------------------ */
/* Actions / TaskFactory seams — task objects route to row handlers.    */
/* ------------------------------------------------------------------ */

export interface MsTask {
  kind: "invert-starred" | "archive" | "trash" | "change-labels" | string;
  threads?: MsThread[];
  source?: string;
  labelsToAdd?: { id: string }[];
  labelsToRemove?: { id: string }[];
}

function runTask(task: MsTask | null | undefined) {
  if (!task || !task.threads) return;
  for (const t of task.threads) {
    const k = t.__kiwi;
    if (!k) continue;
    switch (task.kind) {
      case "invert-starred":
        k.onToggleStar();
        break;
      case "archive":
        k.onArchive();
        break;
      case "trash":
        k.onRequestTrash();
        break;
      default:
        break; // change-labels has no KIWI handler — honest no-op.
    }
  }
}

export const TaskFactory = {
  taskForInvertingStarred({ threads, source }: { threads: MsThread[]; source: string }): MsTask {
    return { kind: "invert-starred", threads, source };
  },
  tasksForArchiving({ threads, source }: { threads: MsThread[]; source: string }): MsTask[] {
    return [{ kind: "archive", threads, source }];
  },
  tasksForMovingToTrash({ threads, source }: { threads: MsThread[]; source: string }): MsTask[] {
    return [{ kind: "trash", threads, source }];
  },
};

export const Actions = {
  queueTask(task: MsTask | null | undefined) {
    runTask(task);
  },
  queueTasks(tasks: MsTask[] | null | undefined) {
    (tasks ?? []).forEach(runTask);
  },
};

/* ------------------------------------------------------------------ */
/* FocusedPerspectiveStore — mailbox sets it per folder render.         */
/* ------------------------------------------------------------------ */

export interface MsPerspective {
  isSent(): boolean;
  isInbox(): boolean;
  accountIds: string[];
  canArchiveThreads(_threads: MsThread[]): boolean;
  canMoveThreadsTo(_threads: MsThread[], _role: string): boolean;
  categories(): unknown[];
  name?: string;
}

let currentPerspective: MsPerspective = {
  isSent: () => false,
  isInbox: () => true,
  accountIds: [],
  canArchiveThreads: () => true,
  canMoveThreadsTo: () => true,
  categories: () => [],
};
const perspectiveListeners = new Set<() => void>();

export function setThreadListPerspective(p: MsPerspective) {
  currentPerspective = p;
  perspectiveListeners.forEach((cb) => cb());
}

export const FocusedPerspectiveStore = {
  current(): MsPerspective {
    return currentPerspective;
  },
  listen(cb: () => void): Disposable {
    perspectiveListeners.add(cb);
    return new Disposable(() => perspectiveListeners.delete(cb));
  },
};

/* ------------------------------------------------------------------ */
/* ExtensionRegistry / CategoryStore — honest empties (no plugins).     */
/* ------------------------------------------------------------------ */

export const ExtensionRegistry = {
  ThreadList: {
    extensions(): { cssClassNamesForThreadListIcon?: (t: MsThread) => string }[] {
      return [];
    },
  },
};

export const CategoryStore = {
  // Declared `{id} | null` (the vendor contract) even though KIWI always
  // returns null — a literal `null` return type narrows callers to never.
  getCategoryByRole(_account: string, _role: string): { id: string } | null {
    return null;
  },
  hiddenCategories(_accountId: string): { id: string }[] {
    return [];
  },
};

/* ------------------------------------------------------------------ */
/* Account color registry (AccountStore seam for AccountColorBar).      */
/* ------------------------------------------------------------------ */

const accountColors = new Map<string, string>();
const colorListeners = new Set<() => void>();

/** Seed the registry from AccountView/AccountInfo rows (App.tsx, on change). */
export function registerAccountColors(accounts: { id: string; color?: string | null }[]) {
  let changed = false;
  const seen = new Set<string>();
  for (const a of accounts) {
    seen.add(a.id);
    if (a.color && accountColors.get(a.id) !== a.color) {
      accountColors.set(a.id, a.color);
      changed = true;
    }
  }
  for (const id of [...accountColors.keys()]) {
    if (!seen.has(id)) {
      accountColors.delete(id);
      changed = true;
    }
  }
  if (changed) colorListeners.forEach((cb) => cb());
}

export function accountColorFor(accountId: string): string | null {
  return accountColors.get(accountId) ?? null;
}

export function onAccountColorsChanged(cb: () => void): () => void {
  colorListeners.add(cb);
  return () => colorListeners.delete(cb);
}

/* Re-export the MessageCategory type the row composition uses. */
export type { MessageCategory };
