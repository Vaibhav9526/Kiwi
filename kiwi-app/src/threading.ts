/**
 * Conversation threading (T-165): pure client-side grouping.
 *
 * The list views (`MessageView`) expose `message_id` + `subject` but NOT
 * `In-Reply-To`/`References` (those live only in the MIME parser and the
 * compose input — verified against `kiwi-mail/src/store.rs` and
 * `src-tauri/src/types.rs`). So threads group by **normalized subject
 * within an account**: reply/forward prefixes stripped iteratively, mailing-
 * list `[tags]` dropped, case folded. Header-chain threading (parent ←→
 * child via Message-ID) lands when the IPC exposes the fields — the
 * `Thread.messages` oldest→newest ordering already matches what a chain
 * fold would produce, so no view changes then.
 */

import type { MessageEnvelope } from "./kiwi";

/** Reply/forward prefixes stripped iteratively (conservative set). */
const PREFIX_RE = /^(re|fw|fwd|aw|sv)\s*:\s*/i;
/** Leading mailing-list style tag, e.g. "[dev] ". */
const TAG_RE = /^\[[^\][]]{1,40}\]\s*/;

function stripPrefixes(s: string): string {
  let out = s.trim();
  for (let i = 0; i < 8; i++) {
    const next = out.replace(PREFIX_RE, "").trim();
    if (next === out) break;
    out = next;
  }
  return out.replace(TAG_RE, "").trim();
}

/** Normalized grouping key; null when the subject carries no signal. */
export function normalizeSubject(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const s = stripPrefixes(raw).toLowerCase().replace(/\s+/g, " ").trim();
  return s || null;
}

/** Display form: prefixes/tags stripped, original casing kept. */
export function displaySubject(raw: unknown): string {
  if (typeof raw !== "string" || !raw) return "(no subject)";
  const s = stripPrefixes(raw);
  return s || "(no subject)";
}

export interface Thread {
  /** `${accountId}\n${normalized}` — stable while the list is loaded. */
  key: string;
  /** Display subject (newest message, prefixes stripped). */
  subject: string;
  /** Oldest → newest (matches future header-chain fold order). */
  messages: MessageEnvelope[];
  unreadCount: number;
  starredAny: boolean;
  /** ISO of the newest message (empty when unknown). */
  latestDate: string;
  participants: string[];
}

function byDateAsc(a: MessageEnvelope, b: MessageEnvelope): number {
  if (a.date === b.date) return a.uid - b.uid;
  return a.date < b.date ? -1 : 1;
}

/** Group a flat (usually newest-first) list into newest-thread-first threads. */
export function buildThreads(list: MessageEnvelope[]): Thread[] {
  const groups = new Map<string, MessageEnvelope[]>();
  for (const m of list) {
    const n = normalizeSubject(m.subject);
    // Subjects with no signal thread alone (keyed by message id).
    const key = n === null ? `!\n${m.id}` : `${m.accountId}\n${n}`;
    const g = groups.get(key);
    if (g) g.push(m);
    else groups.set(key, [m]);
  }
  const threads: Thread[] = [];
  for (const [key, members] of groups) {
    const ordered = members.slice().sort(byDateAsc);
    const newest = ordered[ordered.length - 1];
    const seen = new Set<string>();
    const participants: string[] = [];
    for (const m of ordered) {
      if (m.from && !seen.has(m.from)) {
        seen.add(m.from);
        participants.push(m.from);
      }
    }
    threads.push({
      key,
      subject: displaySubject(newest.subject),
      messages: ordered,
      unreadCount: ordered.reduce((n, m) => n + (m.unread ? 1 : 0), 0),
      starredAny: ordered.some((m) => m.starred),
      latestDate: newest.date,
      participants,
    });
  }
  // Newest activity first (matches the flat list's newest-first order).
  threads.sort((a, b) => {
    if (a.latestDate === b.latestDate) return 0;
    if (!a.latestDate) return 1;
    if (!b.latestDate) return -1;
    return a.latestDate < b.latestDate ? 1 : -1;
  });
  return threads;
}
