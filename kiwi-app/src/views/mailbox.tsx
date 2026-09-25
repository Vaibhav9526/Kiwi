/**
 * Mailbox view (T-143, T-151, T-162, T-165, T-267 eM-idiom rebuild):
 * live folders/messages/body via kiwi.ipc/1, sync, outbox with
 * cancel/flush, per-account trust pills. Star/read/archive go through
 * kiwi_update_message in live mode (demo stays local-only and says so);
 * attachments save through kiwi_download_attachment; HTML bodies render
 * through kiwi_render_body (server-side ammonia sanitizer, remote images
 * blocked unless the per-account opt-in is on). List keys (T-153):
 * j/k/arrows/n/p move · s star · e archive · r reply · u read/unread.
 * Bulk selection (T-162): hover checkbox, Ctrl/Cmd-click toggle,
 * Shift-click range, header select-all; the action bar runs one bulk pass
 * per action (flags/archive via kiwi_update_message, delete via
 * kiwi_delete_messages with count confirms, spam via kiwi_move_messages,
 * empty-trash from Trash folders). Demo explains itself per action.
 * Conversations (T-165): subject-normalized threads (In-Reply-To/
 * References aren't in list views) — a thread row carries a count badge
 * and the reader stacks per-message cards (collapse-to-snippet chevron).
 * T-267 layout: Primary/Other tabs + Today/Older groups over eM-style
 * rows (avatar, unread dot, bold sender, category pill, snippet).
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { FindingInfo, MessageBodyView, MessageEnvelope, MessagePatch, OutboxItem, RenderedBodyView, SearchHit, UnsubscribeInfo } from "../kiwi";
import { severityLabel } from "../kiwi";
import type { MessageCategory } from "../kiwi";
import { listen } from "@tauri-apps/api/event";
import { api, isTauri } from "../ipc";
import { loadPref, savePref } from "../prefs";
import { loadLocalBook, saveLocalBook, upsertLocal } from "../contacts";
import { navigate } from "../router";
import { SecurityPill } from "../components/security";
import { buildThreads, displaySubject } from "../threading";
import type { Thread } from "../threading";
import {
  IconArchive,
  IconCheck,
  IconChevronDown,
  IconChevronRight,
  IconChevronUp,
  IconClose,
  IconFilter,
  IconMail,
  IconOutbox,
  IconPaperclip,
  IconPrint,
  IconReply,
  IconReplyAll,
  IconStar,
  IconTrash,
} from "../components/shell-icons";

/** Short timestamp for rows: time today, "Day m/d" otherwise. */
function formatDateShort(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (d.getFullYear() === now.getFullYear()) return `${d.toLocaleDateString([], { weekday: "short" })} ${d.getMonth() + 1}/${d.getDate()}`;
  return d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

/** Reader-card timestamp — the reference shows full weekday + date + time. */
function formatDateFull(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleDateString([], { weekday: "short" })} ${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** "Name <addr@x>" → "Name"; bare addresses pass through. */
function senderName(raw: string): string {
  const m = raw.match(/^(.*)<([^>]+)>\s*$/);
  const name = (m ? m[1] : raw).trim().replace(/^["']|["']$/g, "");
  return name || raw;
}

/** Deterministic avatar tint from the sender string (never the skin tone set). */
const AVATAR_TINTS = ["#4a90d9", "#e8963c", "#57a83f", "#8e6bc0", "#2aa5a0", "#c0608e", "#6b7f99"];
function avatarTint(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return AVATAR_TINTS[Math.abs(h) % AVATAR_TINTS.length];
}

/** T-201 category → eM-style colored pill (News=blue/Personal=orange/Logs=green). */
const CATEGORY_PILL: Record<MessageCategory, { label: string; cls: string } | null> = {
  primary: { label: "Personal", cls: "em-cat-personal" },
  newsletters: { label: "News", cls: "em-cat-news" },
  social: { label: "Social", cls: "em-cat-social" },
  notifications: { label: "Logs", cls: "em-cat-logs" },
  other: { label: "Other", cls: "em-cat-other" },
};

export interface MailboxProps {
  folder: string;
  folderLabel: string;
  messages: MessageEnvelope[];
  /** T-231: live FTS hits (kiwi_search_messages). `null` = not searching —
   * the pane shows the normal folder list; `[]` = searched, zero hits. */
  searchResults: SearchHit[] | null;
  searchBusy: boolean;
  searchNote: string | null;
  searchQuery: string;
  messagesLoading: boolean;
  messagesError: string | null;
  selectedId?: string;
  body: MessageBodyView | null;
  bodyLoading: boolean;
  bodyError: string | null;
  rendered: RenderedBodyView | null;
  renderLoading: boolean;
  renderError: string | null;
  remoteAllowed: boolean;
  attachNote: string | null;
  attachBusy: boolean;
  findings: FindingInfo[];
  locked: boolean;
  demo: boolean;
  syncing: boolean;
  syncNote: string | null;
  outbox: OutboxItem[];
  onOpenFinding: (index: number) => void;
  onToggleStar: (id: string) => void;
  onToggleRead: (id: string) => void;
  onArchive: (id: string, archived: boolean) => void;
  onBulkPatch: (ids: string[], patch: MessagePatch, actionLabel: string) => void;
  onBulkDelete: (ids: string[], permanent: boolean, actionLabel: string) => void;
  onBulkSpam: (ids: string[]) => void;
  onEmptyTrash: () => void;
  onAllowRemote: (allowed: boolean) => void;
  onSaveAttachment: (attachmentIndex: number, destPath: string) => void;
  onSync: () => void;
  onFlushOutbox: () => void;
  onCancelSend: (queueId: string) => void;
  onOutboxRefresh: () => void;
}

export function MailboxView(props: MailboxProps) {
  const { folder, folderLabel, messages: allMessages, selectedId, findings, locked } = props;
  const searchHits = props.searchResults;
  const searching = searchHits !== null;
  // T-267 eM tabs: Primary | Other (+N non-primary). The T-201 category
  // slugs still arrive per message — "Other" aggregates the four
  // non-primary slugs, and each row keeps its colored category pill.
  const [catTab, setCatTab] = useState<"primary" | "other">("primary");
  const messages = useMemo(
    () => allMessages.filter((m) => (catTab === "primary" ? (m.category ?? "primary") === "primary" : (m.category ?? "primary") !== "primary")),
    [allMessages, catTab],
  );
  const otherCount = useMemo(() => allMessages.filter((m) => (m.category ?? "primary") !== "primary").length, [allMessages]);
  const selected = messages.find((m) => m.id === selectedId) ?? messages[0];

  // Bulk selection (T-162): explicit id list + range anchor. Cleared on
  // folder/tab change (ids are folder-scoped) and after move actions.
  const [picked, setPicked] = useState<string[]>([]);
  const anchorRef = useRef<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const selectAllRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    setPicked([]);
    anchorRef.current = null;
  }, [folder, catTab]);

  const togglePick = (id: string, range: boolean) => {
    if (range && anchorRef.current) {
      const a = messages.findIndex((m) => m.id === anchorRef.current);
      const b = messages.findIndex((m) => m.id === id);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        const span = messages.slice(lo, hi + 1).map((m) => m.id);
        setPicked((prev) => Array.from(new Set([...prev, ...span])));
        return;
      }
    }
    anchorRef.current = id;
    setPicked((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const allPicked = messages.length > 0 && picked.length >= messages.length;
  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = picked.length > 0 && !allPicked;
    }
  }, [picked, allPicked]);

  const isTrash = folder === "trash" || (folder !== "outbox" && /trash|deleted|bin/i.test(folderLabel));
  const [contactNote, setContactNote] = useState<string | null>(null);
  useEffect(() => {
    setContactNote(null);
  }, [selectedId]);

  /** Add the sender to contacts (T-173, live-wired T-231): live mode is
    * IPC-only — a backend failure surfaces as a note, never a silent
    * local write. Demo mode saves to the seeded local book. */
  const addSenderToContacts = async () => {
    if (!selected) return;
    const raw = props.body?.from?.[0] ?? selected.from;
    const m = raw.match(/^(.*)<([^>]+)>\s*$/);
    const address = (m ? m[2] : raw).trim();
    const name = (m ? m[1] : "").trim().replace(/^["']|["']$/g, "");
    if (!address || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
      setContactNote(`Cannot add — "${raw}" is not a usable address.`);
      return;
    }
    const input = {
      displayName: name || address,
      tags: [] as string[],
      emails: [{ address }],
      phones: [] as { number: string; label: string | null }[],
    };
    if (props.demo) {
      saveLocalBook(upsertLocal(loadLocalBook(), input));
      setContactNote(`Saved ${address} to the demo book.`);
      return;
    }
    try {
      await api.createContact(input);
      setContactNote(`Saved ${address} to contacts.`);
    } catch (e) {
      setContactNote(`Save failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  // Conversation threads (T-165): grouped from the visible list, newest
  // activity first. Thread rows carry the count badge; the reader stacks
  // the thread's messages as cards.
  const threads = useMemo(() => buildThreads(messages), [messages]);
  const [threadMode, setThreadMode] = useState(() => loadPref("kiwi.threadMode", "threads"));
  useEffect(() => savePref("kiwi.threadMode", threadMode), [threadMode]);
  const [groupsOpen, setGroupsOpen] = useState<Record<string, boolean>>({});

  // Today / Older date groups over the (flat or threaded) row list.
  type RowEntry = { kind: "msg"; m: MessageEnvelope } | { kind: "thread"; t: Thread };
  const rows = useMemo<RowEntry[]>(() => {
    const flat: RowEntry[] =
      threadMode === "threads"
        ? threads.map((t) => ({ kind: "thread", t }))
        : messages.map((m) => ({ kind: "msg", m }));
    return flat;
  }, [threadMode, threads, messages]);
  const [todayRows, olderRows] = useMemo(() => {
    const now = new Date();
    const today: RowEntry[] = [];
    const older: RowEntry[] = [];
    for (const r of rows) {
      const iso = r.kind === "msg" ? r.m.date : r.t.latestDate;
      const d = new Date(iso);
      if (!Number.isNaN(d.getTime()) && sameDay(d, now)) today.push(r);
      else older.push(r);
    }
    return [today, older];
  }, [rows]);

  /** Run a bulk pass, then clear selection + return focus to the heading when rows moved. */
  const runBulk = (ids: string[], patch: MessagePatch, label: string, clearsRows: boolean) => {
    props.onBulkPatch(ids, patch, label);
    if (clearsRows) {
      setPicked([]);
      anchorRef.current = null;
      window.setTimeout(() => headingRef.current?.focus(), 0);
    }
  };

  // Live outbox progress (kiwi://outbox status events) — refresh on arrival.
  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    listen("kiwi://outbox", () => props.onOutboxRefresh()).then((fn) => {
      unlisten = fn;
    }).catch(() => undefined);
    return () => unlisten?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [folder]);

  const stepSelection = (dir: 1 | -1) => {
    if (!selected || messages.length === 0) return;
    const i = messages.findIndex((m) => m.id === selected.id);
    const next = messages[(i + dir + messages.length) % messages.length];
    if (next) navigate({ name: "mail", folder, messageId: next.id });
  };

  const selectedThread = useMemo(
    () => (selected ? threads.find((t) => t.messages.some((m) => m.id === selected.id)) ?? null : null),
    [threads, selected],
  );

  return (
    <div className="em-mailbox ms-view-enter">
      <section aria-label={`${folderLabel} message list`} className="em-list-col">
        <div className="em-list-head">
          <h1 ref={headingRef} tabIndex={-1} className="em-pane-title">
            {searching ? "Search results" : folderLabel}{" "}
            <small className="em-pane-sub">
              {searching
                ? `(${searchHits.length} hit(s) — “${props.searchQuery.trim()}”)`
                : `(${folder === "outbox" ? props.outbox.length : `${messages.length} of ${allMessages.length}`})`}
            </small>
          </h1>
          {folder === "outbox" && (
            <button type="button" className="ms-btn" onClick={props.onFlushOutbox} aria-label="Send all queued mail now">
              Send all now
            </button>
          )}
        </div>
        {folder !== "outbox" && !searching && (
          <div className="em-list-tabs" role="tablist" aria-label="Inbox categories (loaded messages)">
            <button
              type="button"
              role="tab"
              aria-selected={catTab === "primary"}
              className="em-tab"
              tabIndex={catTab === "primary" ? 0 : -1}
              onClick={() => setCatTab("primary")}
            >
              Primary
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={catTab === "other"}
              className="em-tab"
              tabIndex={catTab === "other" ? 0 : -1}
              title={`${otherCount} non-primary loaded message(s)`}
              onClick={() => setCatTab("other")}
            >
              Other{" "}
              {otherCount > 0 && (
                <span className="em-tab-badge" aria-hidden="true">
                  +{otherCount}
                </span>
              )}
            </button>
            <span className="em-list-tools">
              <input
                ref={selectAllRef}
                type="checkbox"
                className="em-select-all"
                checked={allPicked}
                onChange={() => {
                  if (allPicked) {
                    setPicked([]);
                    anchorRef.current = null;
                  } else {
                    setPicked(messages.map((m) => m.id));
                    anchorRef.current = messages[messages.length - 1]?.id ?? null;
                  }
                }}
                aria-label={allPicked ? `Deselect all ${messages.length} messages` : `Select all ${messages.length} messages in folder`}
              />
              <button
                type="button"
                className={`em-iconbtn${threadMode === "threads" ? " is-active" : ""}`}
                role="switch"
                aria-checked={threadMode === "threads"}
                onClick={() => setThreadMode(threadMode === "threads" ? "list" : "threads")}
                title="Group messages into conversations by subject"
              >
                <IconReplyAll size={13} />
              </button>
              <button
                type="button"
                className="em-iconbtn"
                aria-label="Filter — focus search"
                title="Filter — focuses the search field"
                onClick={() => document.getElementById("kiwi-search")?.focus()}
              >
                <IconFilter size={13} />
              </button>
            </span>
          </div>
        )}
        {picked.length > 0 && folder !== "outbox" && !searching && (
          <BulkBar
            count={picked.length}
            inTrash={isTrash}
            demo={props.demo}
            onRead={() => runBulk(picked, { seen: true }, "Marked read", false)}
            onUnread={() => runBulk(picked, { seen: false }, "Marked unread", false)}
            onArchive={() => runBulk(picked, { archived: true }, "Archived", true)}
            onMove={(target) => runBulk(picked, { archived: target === "archive" }, target === "archive" ? "Moved to Archive" : "Moved to Inbox", true)}
            onDelete={(permanent) => {
              props.onBulkDelete(picked, permanent, permanent ? "Deleted permanently" : "Deleted");
              setPicked([]);
              anchorRef.current = null;
              window.setTimeout(() => headingRef.current?.focus(), 0);
            }}
            onSpam={() => {
              props.onBulkSpam(picked);
              setPicked([]);
              anchorRef.current = null;
              window.setTimeout(() => headingRef.current?.focus(), 0);
            }}
            onClear={() => {
              setPicked([]);
              anchorRef.current = null;
            }}
          />
        )}
        {props.syncNote && (
          <p role="status" className="em-note">
            <small>{props.syncNote}</small>
          </p>
        )}
        {folder === "outbox" ? (
          <OutboxList outbox={props.outbox} onCancelSend={props.onCancelSend} />
        ) : searching ? (
          <>
            {props.searchBusy && (
              <div role="status" aria-label="Searching messages">
                <div className="kiwi-skeleton" />
                <div className="kiwi-skeleton" />
              </div>
            )}
            {props.searchNote && (
              <div className="kiwi-banner error" role="alert">
                <small>{props.searchNote}</small>
              </div>
            )}
            {!props.searchBusy && !props.searchNote && searchHits.length === 0 && (
              <div className="kiwi-empty">
                <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                  <IconMail size={28} />
                </span>
                <strong>No matches</strong>
                <br />
                <small>Nothing in the mailbox matches “{props.searchQuery.trim()}”.</small>
              </div>
            )}
            <div className="em-rows" role="listbox" aria-label={`Search results for ${props.searchQuery.trim()}`}>
              {searchHits.map((h) => (
                <SearchHitRow key={`${h.accountId}:${h.folderId}:${h.uid}`} hit={h} />
              ))}
            </div>
          </>
        ) : (
          <>
            {props.messagesLoading && (
              <div role="status" aria-label="Loading messages">
                <div className="kiwi-skeleton" />
                <div className="kiwi-skeleton" />
                <div className="kiwi-skeleton" />
              </div>
            )}
            {props.messagesError && (
              <div className="kiwi-banner error" role="alert">
                <small>{props.messagesError}</small>
              </div>
            )}
            {messages.length === 0 && !props.messagesLoading && (
              <div className="kiwi-empty">
                <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                  <IconMail size={28} />
                </span>
                <strong>Nothing here</strong>
                <br />
                <small>
                  {allMessages.length === 0
                    ? "No messages in this folder yet."
                    : `No ${catTab === "primary" ? "Primary" : "Other"} messages in the loaded list.`}
                </small>
              </div>
            )}
            <div
              className="em-rows"
              role="listbox"
              aria-label="Messages. j/k or arrows move, s stars, e archives, r replies, u toggles read. Ctrl-click toggles selection, Shift-click range-selects."
              aria-multiselectable="true"
              aria-activedescendant={selected?.id}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown" || e.key === "j") {
                  e.preventDefault();
                  stepSelection(1);
                } else if (e.key === "ArrowUp" || e.key === "k") {
                  e.preventDefault();
                  stepSelection(-1);
                } else if (e.key === "n") stepSelection(1);
                else if (e.key === "p") stepSelection(-1);
                else if (!selected) return;
                else if (e.key === "u") props.onToggleRead(selected.id);
                else if (e.key === "s") props.onToggleStar(selected.id);
                else if (e.key === "e") props.onArchive(selected.id, true);
                else if (e.key === "r") navigate({ name: "compose" });
              }}
            >
              <DateGroup
                label="Today"
                rows={todayRows}
                open={groupsOpen["today"] ?? true}
                onToggle={() => setGroupsOpen((m) => ({ ...m, today: !(m["today"] ?? true) }))}
                folder={folder}
                currentId={selected?.id}
                picked={picked}
                onTogglePick={togglePick}
                onToggleStar={props.onToggleStar}
                onArchive={(id) => props.onArchive(id, true)}
                onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
              />
              <DateGroup
                label="Older"
                rows={olderRows}
                open={groupsOpen["older"] ?? true}
                onToggle={() => setGroupsOpen((m) => ({ ...m, older: !(m["older"] ?? true) }))}
                folder={folder}
                currentId={selected?.id}
                picked={picked}
                onTogglePick={togglePick}
                onToggleStar={props.onToggleStar}
                onArchive={(id) => props.onArchive(id, true)}
                onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
              />
            </div>
          </>
        )}
      </section>
      <section key={selected?.id ?? "none"} className="em-reader ms-ready" aria-label="Message reader" tabIndex={0}>
        {!selected && folder !== "outbox" && (
          <div className="kiwi-empty">
            <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
              <IconMail size={28} />
            </span>
            <strong>Select a message to read</strong>
          </div>
        )}
        {folder === "outbox" && (
          <p className="em-note">
            <small>Queued sends live here. Undo works while the grace window is open; “Send all now” skips remaining grace.</small>
          </p>
        )}
        {selected && folder !== "outbox" && (
          <>
            <div className="em-reader-head">
              <h2 className="em-thread-title">{selectedThread?.subject ?? displaySubject(selected.subject)}</h2>
              <span className="em-reader-tools">
                <button
                  type="button"
                  className="em-iconbtn"
                  onClick={() => props.onToggleStar(selected.id)}
                  aria-pressed={selected.starred}
                  title={selected.starred ? "Unstar (s)" : "Star (s)"}
                >
                  <IconStar size={14} className={selected.starred ? "em-starred" : undefined} />
                </button>
                <button type="button" className="em-iconbtn" onClick={() => window.print()} title="Print conversation">
                  <IconPrint size={14} />
                </button>
              </span>
            </div>
            <div className="em-reader-meta">
              <SecurityPill
                level={selected.trust}
                summary={`Account trust for ${selected.accountEmail}. Per-message session attribution is not yet exposed by the backend.`}
                onOpen={() => props.onOpenFinding(0)}
              />
              <button type="button" className="em-linkbtn" onClick={() => void addSenderToContacts()} title="Save the sender to contacts">
                Add to contacts
              </button>
              <button
                type="button"
                className="em-linkbtn"
                disabled={findings.length === 0}
                onClick={() => props.onOpenFinding(0)}
              >
                Security details ({findings.length})
              </button>
            </div>
            {contactNote && (
              <p role="status" className="em-note">
                <small>{contactNote}</small>
              </p>
            )}
            <div className="em-cards">
              {(selectedThread ?? { messages: [selected], key: "", subject: selected.subject, unreadCount: 0, starredAny: false, latestDate: "", participants: [] }).messages.map(
                (m) => (
                  <MessageCard
                    key={m.id}
                    m={m}
                    isSelected={m.id === selected.id}
                    folder={folder}
                    body={m.id === selected.id ? props.body : null}
                    bodyLoading={m.id === selected.id && props.bodyLoading}
                    bodyError={m.id === selected.id ? props.bodyError : null}
                    rendered={m.id === selected.id ? props.rendered : null}
                    renderLoading={m.id === selected.id && props.renderLoading}
                    renderError={m.id === selected.id ? props.renderError : null}
                    remoteAllowed={props.remoteAllowed}
                    attachNote={props.attachNote}
                    attachBusy={props.attachBusy}
                    locked={locked}
                    demo={props.demo}
                    accountEmail={m.accountEmail}
                    onToggleStar={props.onToggleStar}
                    onToggleRead={props.onToggleRead}
                    onArchive={props.onArchive}
                    onAllowRemote={props.onAllowRemote}
                    onSaveAttachment={props.onSaveAttachment}
                  />
                ),
              )}
            </div>
            <p className="em-note">
              <small>
                {props.demo
                  ? "Star/read/archive are local-only in demo mode."
                  : "Star/read/archive sync to the server (IMAP write-through; POP3 is local-only, reconciled on next sync)."}
              </small>
            </p>
          </>
        )}
      </section>
    </div>
  );
}

/* ---------------- date group ---------------- */

interface RowEntry {
  kind: "msg" | "thread";
  m?: MessageEnvelope;
  t?: Thread;
}

function DateGroup({
  label,
  rows,
  open,
  onToggle,
  folder,
  currentId,
  picked,
  onTogglePick,
  onToggleStar,
  onArchive,
  onDelete,
}: {
  label: string;
  rows: RowEntry[];
  open: boolean;
  onToggle: () => void;
  folder: string;
  currentId?: string;
  picked: string[];
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  if (rows.length === 0) return null;
  return (
    <div className="em-date-group">
      <button type="button" className="em-group-head" aria-expanded={open} onClick={onToggle}>
        <span className={`em-disclosure${open ? " is-open" : ""}`} aria-hidden="true">
          <IconChevronRight size={10} />
        </span>
        {label}
      </button>
      {open &&
        rows.map((r) =>
          r.kind === "msg" && r.m ? (
            <MessageRow
              key={r.m.id}
              m={r.m}
              folder={folder}
              currentId={currentId}
              isPicked={picked.includes(r.m.id)}
              onTogglePick={onTogglePick}
              onToggleStar={onToggleStar}
              onArchive={onArchive}
              onDelete={onDelete}
            />
          ) : r.t ? (
            <ThreadRow
              key={r.t.key}
              thread={r.t}
              folder={folder}
              currentId={currentId}
              picked={picked}
              onTogglePick={onTogglePick}
              onToggleStar={onToggleStar}
              onArchive={onArchive}
              onDelete={onDelete}
            />
          ) : null,
        )}
    </div>
  );
}

/* ---------------- eM-style message row ---------------- */

/**
 * T-231 FTS hit row (kiwi_search_messages). Hits are not envelopes — no
 * unread/star/category state exists on SearchHit, so the row shows only
 * what the backend returned (sender, subject, snippet, date, paperclip)
 * and navigates to the owning `accountId:folderId` folder + message.
 * Hits lacking `accountId` (contract permits absence) can't resolve their
 * folder — they render inert rather than navigating somewhere wrong.
 */
function SearchHitRow({ hit }: { hit: SearchHit }) {
  const openable = hit.accountId !== "";
  const open = () => {
    if (!openable) return;
    navigate({
      name: "mail",
      folder: `${hit.accountId}:${hit.folderId}`,
      messageId: `${hit.accountId}:${hit.folderId}:${hit.uid}`,
    });
  };
  const dateIso = hit.dateUnix !== null ? new Date(hit.dateUnix * 1000).toISOString() : "";
  return (
    <article
      role="option"
      className="em-row"
      aria-selected={false}
      aria-label={`${hit.from}, ${hit.subject}`}
      aria-disabled={!openable}
      title={openable ? hit.subject : "Cannot open — the search hit lacks an account id"}
      onClick={open}
      onKeyDown={(e) => {
        if (e.key === "Enter") open();
      }}
      tabIndex={0}
    >
      <span className="em-dot" aria-hidden="true" />
      <span className="em-avatar" aria-hidden="true" style={{ background: avatarTint(hit.from) }}>
        {senderName(hit.from).slice(0, 1).toUpperCase() || "?"}
      </span>
      <span className="em-row-text">
        <span className="em-row-line em-row-top">
          <span className="em-row-sender" title={hit.from}>
            {senderName(hit.from)}
          </span>
          <time className="em-row-date" title={dateIso}>
            {formatDateShort(dateIso)}
          </time>
        </span>
        <span className="em-row-line">
          <span className="em-row-subject" title={hit.subject}>
            {hit.subject}
          </span>
          <span className="em-row-marks">
            {hit.hasAttachments && (
              <span title="Has attachments" aria-label="Has attachments">
                <IconPaperclip size={11} />
              </span>
            )}
          </span>
        </span>
        <span className="em-row-line em-row-sub">
          <span className="em-row-snippet" title={hit.snippet}>
            {hit.snippet}
          </span>
        </span>
      </span>
    </article>
  );
}

function RowShell({
  id,
  selected,
  unread,
  folder,
  navId,
  sender,
  date,
  subject,
  count,
  hasAttachments,
  category,
  snippet,
  checkbox,
  onPick,
  onToggleStar,
  starred,
  onArchive,
  onDelete,
  label,
}: {
  id: string;
  selected: boolean;
  unread: boolean;
  folder: string;
  navId: string;
  sender: string;
  date: string;
  subject: string;
  count: number;
  hasAttachments: boolean;
  category: MessageCategory;
  snippet: string;
  checkbox: ReactNode;
  starred: boolean;
  onPick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
  label: string;
}) {
  const [confirmDel, setConfirmDel] = useState(false);
  useEffect(() => setConfirmDel(false), [id]);
  const pill = CATEGORY_PILL[category ?? "primary"];
  return (
    <article
      id={id}
      role="option"
      className={`em-row${unread ? " is-unread" : ""}${selected ? " is-selected" : ""}`}
      aria-selected={selected}
      aria-label={label}
      onClick={(e) => {
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          onPick(navId, false);
          return;
        }
        if (e.shiftKey) {
          e.preventDefault();
          onPick(navId, true);
          return;
        }
        if ((e.target as HTMLElement).closest("button,input")) return;
        navigate({ name: "mail", folder, messageId: navId });
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") navigate({ name: "mail", folder, messageId: navId });
      }}
      tabIndex={0}
    >
      <span className={`em-dot${unread ? " is-unread" : ""}`} aria-hidden="true" />
      {checkbox}
      <span className="em-avatar" aria-hidden="true" style={{ background: avatarTint(sender) }}>
        {senderName(sender).slice(0, 1).toUpperCase() || "?"}
      </span>
      <span className="em-row-text">
        <span className="em-row-line em-row-top">
          <span className="em-row-sender" title={sender}>
            {sender}
          </span>
          <time className="em-row-date" title={date}>
            {formatDateShort(date)}
          </time>
        </span>
        <span className="em-row-line">
          <span className="em-row-subject" title={subject}>
            {subject}
          </span>
          <span className="em-row-marks">
            {hasAttachments && (
              <span title="Has attachments" aria-label="Has attachments">
                <IconPaperclip size={11} />
              </span>
            )}
            {count > 1 && (
              <span className="em-thread-badge" title={`${count} messages in this conversation`} aria-label={`${count} messages`}>
                {count}
                <IconChevronDown size={9} />
              </span>
            )}
          </span>
        </span>
        <span className="em-row-line em-row-sub">
          {pill && (
            <span className={`em-cat-pill ${pill.cls}`} aria-label={`Category: ${pill.label}`}>
              {pill.label}
            </span>
          )}
          <span className="em-row-snippet" title={snippet}>
            {snippet}
          </span>
        </span>
      </span>
      <span className="em-quick" role="toolbar" aria-label={`Quick actions for: ${subject}`}>
        <button
          type="button"
          className={`em-iconbtn${starred ? " is-starred" : ""}`}
          aria-pressed={starred}
          aria-label={starred ? `Unstar message: ${subject}` : `Star message: ${subject}`}
          title={starred ? "Unstar (s)" : "Star (s)"}
          onClick={(e) => {
            e.stopPropagation();
            onToggleStar(id);
          }}
        >
          <IconStar size={13} />
        </button>
        <button
          type="button"
          className="em-iconbtn"
          onClick={(e) => {
            e.stopPropagation();
            onArchive(id);
          }}
          title="Archive (e)"
          aria-label={`Archive message: ${subject}`}
        >
          <IconArchive size={13} />
        </button>
        {confirmDel ? (
          <>
            <button
              type="button"
              className="em-iconbtn"
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDel(false);
                onDelete(id);
              }}
              title="Confirm delete"
              aria-label={`Confirm delete: ${subject}`}
            >
              <IconCheck size={13} />
            </button>
            <button
              type="button"
              className="em-iconbtn"
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDel(false);
              }}
              title="Keep message"
              aria-label="Keep message"
            >
              <IconClose size={11} />
            </button>
          </>
        ) : (
          <button
            type="button"
            className="em-iconbtn"
            onClick={(e) => {
              e.stopPropagation();
              setConfirmDel(true);
            }}
            title="Delete…"
            aria-label={`Delete message: ${subject}`}
          >
            <IconTrash size={13} />
          </button>
        )}
      </span>
    </article>
  );
}

function MessageRow({
  m,
  folder,
  currentId,
  isPicked,
  onTogglePick,
  onToggleStar,
  onArchive,
  onDelete,
}: {
  m: MessageEnvelope;
  folder: string;
  currentId?: string;
  isPicked: boolean;
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <RowShell
      id={m.id}
      navId={m.id}
      selected={m.id === currentId}
      unread={m.unread}
      folder={folder}
      sender={m.from}
      date={m.date}
      subject={m.subject}
      count={1}
      hasAttachments={m.hasAttachments}
      category={m.category ?? "primary"}
      snippet={m.snippet}
      starred={m.starred}
      onPick={onTogglePick}
      onToggleStar={onToggleStar}
      onArchive={onArchive}
      onDelete={onDelete}
      label={`${m.unread ? "Unread" : "Read"} from ${m.from}: ${m.subject}. Account trust ${severityLabel(m.trust)}.${isPicked ? " Selected for bulk actions." : ""}`}
      checkbox={
        <input
          type="checkbox"
          className="em-row-check"
          data-checked={isPicked}
          checked={isPicked}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => {
            e.stopPropagation();
            onTogglePick(m.id, e.nativeEvent instanceof MouseEvent && e.nativeEvent.shiftKey);
          }}
          aria-label={`Select message from ${m.from}: ${m.subject}`}
        />
      }
    />
  );
}

function ThreadRow({
  thread,
  folder,
  currentId,
  picked,
  onTogglePick,
  onToggleStar,
  onArchive,
  onDelete,
}: {
  thread: Thread;
  folder: string;
  currentId?: string;
  picked: string[];
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const newest = thread.messages[thread.messages.length - 1];
  const allPicked = thread.messages.every((m) => picked.includes(m.id));
  const ids = thread.messages.map((m) => m.id);
  const toggleAll = () => {
    // Thread pick = every member id (bulk actions act on the whole thread).
    for (const id of ids) {
      if (allPicked === !picked.includes(id)) onTogglePick(id, false);
    }
  };
  return (
    <RowShell
      id={`thread-${thread.key.replace(/\W/g, "-")}`}
      navId={newest.id}
      selected={thread.messages.some((m) => m.id === currentId)}
      unread={thread.unreadCount > 0}
      folder={folder}
      sender={thread.participants.slice(0, 3).join(", ") + (thread.participants.length > 3 ? ` +${thread.participants.length - 3}` : "")}
      date={thread.latestDate}
      subject={thread.subject}
      count={thread.messages.length}
      hasAttachments={thread.messages.some((m) => m.hasAttachments)}
      category={newest.category ?? "primary"}
      snippet={newest.snippet}
      starred={thread.starredAny}
      onPick={(_id, _range) => toggleAll()}
      onToggleStar={() => onToggleStar(newest.id)}
      onArchive={() => onArchive(newest.id)}
      onDelete={() => onDelete(newest.id)}
      label={`Conversation: ${thread.subject}. ${thread.messages.length} messages, ${thread.unreadCount} unread.${allPicked ? " Selected for bulk actions." : ""}`}
      checkbox={
        <input
          type="checkbox"
          className="em-row-check"
          data-checked={allPicked}
          checked={allPicked}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => {
            e.stopPropagation();
            toggleAll();
          }}
          aria-label={`Select all ${thread.messages.length} messages in conversation ${thread.subject}`}
        />
      }
    />
  );
}

/* ---------------- reader: stacked message cards ---------------- */

function MessageCard({
  m,
  isSelected,
  folder,
  body,
  bodyLoading,
  bodyError,
  rendered,
  renderLoading,
  renderError,
  remoteAllowed,
  attachNote,
  attachBusy,
  locked,
  demo,
  accountEmail,
  onToggleStar,
  onToggleRead,
  onArchive,
  onAllowRemote,
  onSaveAttachment,
}: {
  m: MessageEnvelope;
  isSelected: boolean;
  folder: string;
  body: MessageBodyView | null;
  bodyLoading: boolean;
  bodyError: string | null;
  rendered: RenderedBodyView | null;
  renderLoading: boolean;
  renderError: string | null;
  remoteAllowed: boolean;
  attachNote: string | null;
  attachBusy: boolean;
  locked: boolean;
  demo: boolean;
  accountEmail: string;
  onToggleStar: (id: string) => void;
  onToggleRead: (id: string) => void;
  onArchive: (id: string, archived: boolean) => void;
  onAllowRemote: (allowed: boolean) => void;
  onSaveAttachment: (attachmentIndex: number, destPath: string) => void;
}) {
  // A selected card can collapse to its snippet (reference behavior);
  // selection change re-expands.
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => setCollapsed(false), [m.id, isSelected]);
  const expanded = isSelected && !collapsed;
  return (
    <article className={`em-card${expanded ? " is-open" : ""}`} aria-label={`Message from ${m.from}`}>
      <header className="em-card-head">
        <span className="em-avatar" aria-hidden="true" style={{ background: avatarTint(m.from) }}>
          {senderName(m.from).slice(0, 1).toUpperCase() || "?"}
        </span>
        <button
          type="button"
          className="em-card-sender"
          title={m.from}
          onClick={() => navigate({ name: "mail", folder, messageId: m.id })}
        >
          {senderName(m.from)}
        </button>
        <span className="em-card-tools">
          <time className="em-card-date" title={m.date}>
            {formatDateFull(m.date)}
          </time>
          <button
            type="button"
            className="em-iconbtn"
            onClick={() => navigate({ name: "compose" })}
            title="Reply (r)"
            aria-label={`Reply to ${m.from}`}
          >
            <IconReply size={13} />
          </button>
          <button
            type="button"
            className="em-iconbtn"
            aria-expanded={expanded}
            aria-label={expanded ? `Collapse message from ${m.from} to snippet` : `Expand message from ${m.from}`}
            title={expanded ? "Collapse to snippet" : "Expand"}
            onClick={() => {
              if (isSelected) setCollapsed((c) => !c);
              else navigate({ name: "mail", folder, messageId: m.id });
            }}
          >
            {expanded ? <IconChevronUp size={12} /> : <IconChevronDown size={12} />}
          </button>
        </span>
      </header>
      {expanded ? (
        <div className="em-card-body">
          <p className="em-card-to">
            To: <strong>{accountEmail}</strong>
            {m.unread && (
              <span className="em-cat-pill em-cat-news" title="Unread">
                Unread
              </span>
            )}
          </p>
          <UnsubscribeChip
            unsub={m.unsub}
            accountId={m.accountId}
            folderId={m.folderId}
            uid={m.uid}
            accountEmail={accountEmail}
            demo={demo}
          />
          {locked ? (
            <p role="note">Message body unavailable — mailbox is locked.</p>
          ) : bodyLoading ? (
            <div role="status" aria-label="Loading message body">
              <div className="kiwi-skeleton text" />
              <div className="kiwi-skeleton text" />
              <div className="kiwi-skeleton text" />
              <div className="kiwi-skeleton" />
            </div>
          ) : bodyError ? (
            <div className="kiwi-banner error" role="alert">
              <small>{bodyError}</small>
            </div>
          ) : body ? (
            <>
              <AttachmentList
                body={body}
                demo={demo}
                attachNote={attachNote}
                attachBusy={attachBusy}
                onSaveAttachment={onSaveAttachment}
              />
              <BodyPane
                body={body}
                rendered={rendered}
                renderLoading={renderLoading}
                renderError={renderError}
                remoteAllowed={remoteAllowed}
                demo={demo}
                onAllowRemote={onAllowRemote}
              />
            </>
          ) : (
            <p className="em-card-snippet">{m.snippet}</p>
          )}
          <div className="em-card-actions">
            <button type="button" className="ms-btn" onClick={() => navigate({ name: "compose" })} title="Reply (r)">
              <IconReply size={12} /> Reply
            </button>
            <button
              type="button"
              className="ms-btn"
              onClick={() => onToggleStar(m.id)}
              aria-pressed={m.starred}
              title="Star (s)"
            >
              <IconStar size={12} className={m.starred ? "em-starred" : undefined} /> {m.starred ? "Unstar" : "Star"}
            </button>
            <button type="button" className="ms-btn" onClick={() => onToggleRead(m.id)} title="Toggle read (u)">
              <IconMail size={12} /> Mark {m.unread ? "read" : "unread"}
            </button>
            <button type="button" className="ms-btn" onClick={() => onArchive(m.id, true)} title="Archive (e)">
              <IconArchive size={12} /> Archive
            </button>
          </div>
        </div>
      ) : (
        <p className="em-card-snippet">{m.snippet}</p>
      )}
    </article>
  );
}

/**
 * T-202 unsubscribe affordance (T-231 chip, T-234 execution, T-242 UI):
 * banner chip on messages carrying List-Unsubscribe endpoints. Dormant
 * (renders nothing) until the backend exposes the fields.
 *
 * Executes `kiwi_message_unsubscribe` in live mode:
 * - RFC 8058 one-click endpoint → the click IS the action (`http`,
 *   no consent flag needed — the backend enforces that rule).
 * - Plain https endpoint → a confirm step labels exactly what leaves
 *   the process, then calls `http` with `consent: true`.
 * - `mailto:` → always consent-gated: sends an email from the user's
 *   own address through the normal outbox (undo window applies).
 *
 * HTTPS links and mailto addresses are validated by parseUnsubscribe;
 * the webview never navigates to a remote URL, and copy-to-clipboard
 * remains as a fallback on every endpoint.
 */
function UnsubscribeChip({
  unsub,
  accountId,
  folderId,
  uid,
  accountEmail,
  demo,
}: {
  unsub: UnsubscribeInfo | undefined;
  accountId: string;
  folderId: number;
  uid: number;
  accountEmail: string;
  demo: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setOpen(false);
    setCopied(null);
    setResult(null);
    setError(null);
    setBusy(null);
  }, [unsub?.url, unsub?.mailto, accountId, folderId, uid]);
  if (!unsub || (!unsub.url && !unsub.mailto)) return null;
  const hostOf = (u: string): string => {
    try {
      return new URL(u).host;
    } catch {
      return u;
    }
  };
  const copy = async (text: string, what: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(`${what} copied to the clipboard.`);
    } catch {
      setCopied(`Copy failed — ${what.toLowerCase()}: ${text}`);
    }
  };
  const execute = async (action: "http" | "mailto", consent: boolean) => {
    setBusy(action);
    setError(null);
    try {
      const v = await api.messageUnsubscribe(accountId, folderId, uid, action, consent);
      setResult(
        v.action === "http"
          ? `Unsubscribe request sent — endpoint answered HTTP ${v.httpStatus ?? "?"}${
              (v.httpStatus ?? 0) >= 400 ? " (it may not have accepted it)" : ""
            }.`
          : `Unsubscribe email queued — undo from the outbox for a few seconds.`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="ms-unsub">
      {!open ? (
        <button
          type="button"
          className="ms-btn"
          onClick={() => setOpen(true)}
          title={unsub.oneClick ? "This sender offers one-click unsubscribe" : "This sender offers unsubscribe endpoints"}
        >
          Unsubscribe
        </button>
      ) : (
        <div className="ms-unsub-panel" role="group" aria-label="Unsubscribe options">
          {result ? (
            <>
              <p role="status" style={{ margin: "0 0 0.4rem" }}>
                <small>{result}</small>
              </p>
              <button type="button" className="ms-btn" onClick={() => setOpen(false)}>
                Done
              </button>
            </>
          ) : (
            <>
              <p style={{ margin: "0 0 0.4rem" }}>
                <small>
                  {demo
                    ? "Demo mode — endpoints are shown for copy; execution needs the live backend."
                    : unsub.oneClick
                      ? "One-click endpoint offered — the button sends the single RFC 8058 request. Nothing else is sent."
                      : "Sender endpoints below — nothing is sent until you pick one."}
                </small>
              </p>
              {unsub.url && (
                <p style={{ margin: "0 0 0.4rem" }}>
                  <small>
                    Endpoint ({hostOf(unsub.url)}):{" "}
                    {!demo && (
                      <button
                        type="button"
                        className="ms-btn"
                        disabled={busy !== null}
                        onClick={() => void execute("http", !unsub.oneClick)}
                      >
                        {busy === "http"
                          ? "Sending…"
                          : unsub.oneClick
                            ? "Unsubscribe now"
                            : "Send unsubscribe request"}
                      </button>
                    )}{" "}
                    <button
                      type="button"
                      className="ms-btn"
                      onClick={() => void copy(unsub.url as string, "Link")}
                    >
                      Copy link
                    </button>
                  </small>
                </p>
              )}
              {unsub.mailto && (
                <p style={{ margin: "0 0 0.4rem" }}>
                  <small>
                    Email <code>{unsub.mailto}</code> — sends from {accountEmail}:{" "}
                    {!demo && (
                      <button
                        type="button"
                        className="ms-btn"
                        disabled={busy !== null}
                        onClick={() => void execute("mailto", true)}
                      >
                        {busy === "mailto" ? "Sending…" : "Send unsubscribe email"}
                      </button>
                    )}{" "}
                    <button
                      type="button"
                      className="ms-btn"
                      onClick={() => void copy(unsub.mailto as string, "Address")}
                    >
                      Copy address
                    </button>
                  </small>
                </p>
              )}
              {copied && (
                <p role="status" style={{ margin: "0 0 0.4rem" }}>
                  <small>{copied}</small>
                </p>
              )}
              {error && (
                <p role="alert" style={{ margin: "0 0 0.4rem", color: "var(--kiwi-danger)" }}>
                  <small>{error}</small>
                </p>
              )}
              <button type="button" className="ms-btn" onClick={() => setOpen(false)}>
                Close
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function AttachmentList({
  body,
  demo,
  attachNote,
  attachBusy,
  onSaveAttachment,
}: {
  body: MessageBodyView;
  demo: boolean;
  attachNote: string | null;
  attachBusy: boolean;
  onSaveAttachment: (attachmentIndex: number, destPath: string) => void;
}) {
  const [destPaths, setDestPaths] = useState<Record<number, string>>({});
  // Reset per-message save state when the selection changes.
  useEffect(() => {
    setDestPaths({});
  }, [body.folderId, body.uid]);
  if (body.attachments.length === 0) return null;
  return (
    <div aria-label="Attachments" className="em-attach">
      {body.attachments.map((a, i) => (
        <p key={`${a.filename}-${i}`}>
          <small>
            <IconPaperclip size={11} /> {a.filename ?? "(unnamed attachment)"}{" "}
            <span style={{ color: "var(--kiwi-text-secondary)" }}>({a.contentType}, {a.size} B)</span>
          </small>
          {!demo && (
            <>
              <br />
              <label>
                <small>Save to: </small>
                <input
                  type="text"
                  value={destPaths[i] ?? a.filename ?? ""}
                  onChange={(e) => setDestPaths((m) => ({ ...m, [i]: e.target.value }))}
                  placeholder={a.filename ?? undefined}
                  style={{ width: "16rem" }}
                  aria-label={`Save destination for ${a.filename ?? "attachment"}`}
                />
              </label>{" "}
              <button type="button" disabled={attachBusy} onClick={() => onSaveAttachment(i, destPaths[i] ?? a.filename ?? "attachment")}>
                {attachBusy ? "Saving…" : "Save"}
              </button>
            </>
          )}
        </p>
      ))}
      {demo && (
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>Attachment download needs the backend — run the Tauri app.</small>
        </p>
      )}
      {attachNote && (
        <p role="status">
          <small>{attachNote}</small>
        </p>
      )}
    </div>
  );
}

function BodyPane({
  body,
  rendered,
  renderLoading,
  renderError,
  remoteAllowed,
  demo,
  onAllowRemote,
}: {
  body: MessageBodyView;
  rendered: RenderedBodyView | null;
  renderLoading: boolean;
  renderError: string | null;
  remoteAllowed: boolean;
  demo: boolean;
  onAllowRemote: (allowed: boolean) => void;
}) {
  const [showSource, setShowSource] = useState(false);
  return (
    <>
      {renderLoading && (
        <div role="status" aria-label="Rendering message">
          <small style={{ color: "var(--kiwi-text-secondary)" }}>Rendering HTML…</small>
        </div>
      )}
      {renderError && (
        <div className="kiwi-banner error" role="alert">
          <small>HTML render unavailable ({renderError}) — showing plaintext.</small>
        </div>
      )}
      {rendered?.html ? (
        <>
          <div
            className="kiwi-rendered-body"
            // Sanitized server-side by kiwi_render_body (ammonia strict
            // allowlist: no scripts/forms/iframes; remote images stripped
            // unless the per-account opt-in is on). Never raw htmlBody.
            dangerouslySetInnerHTML={{ __html: rendered.html }}
          />
          {(rendered.remoteImagesStripped > 0 || remoteAllowed) && !demo && (
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                {rendered.remoteImagesStripped > 0
                  ? `${rendered.remoteImagesStripped} remote image(s) blocked (tracking protection). `
                  : "Remote images are allowed for this account. "}
                <button type="button" onClick={() => onAllowRemote(!remoteAllowed)}>
                  {remoteAllowed ? "Block remote content" : "Allow remote content for this account"}
                </button>
              </small>
            </p>
          )}
          <p>
            <button type="button" onClick={() => setShowSource((s) => !s)} aria-expanded={showSource}>
              {showSource ? "Hide plaintext" : "Show plaintext"}
            </button>
          </p>
          {showSource && (
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>{body.textBody}</pre>
          )}
        </>
      ) : (
        <>
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>{body.textBody}</pre>
          {body.htmlBody && !rendered && !renderLoading && !demo && (
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>No HTML variant rendered for this message (text-only or unfetched).</small>
            </p>
          )}
          {body.htmlBody && demo && (
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>An HTML variant exists but is not rendered in demo mode.</small>
            </p>
          )}
        </>
      )}
    </>
  );
}

function BulkBar({
  count,
  inTrash,
  demo,
  onRead,
  onUnread,
  onArchive,
  onMove,
  onDelete,
  onSpam,
  onClear,
}: {
  count: number;
  inTrash: boolean;
  demo: boolean;
  onRead: () => void;
  onUnread: () => void;
  onArchive: () => void;
  onMove: (target: "archive" | "inbox") => void;
  onDelete: (permanent: boolean) => void;
  onSpam: () => void;
  onClear: () => void;
}) {
  const [confirming, setConfirming] = useState<null | "delete" | "spam">(null);
  const deleteLabel = inTrash ? "Delete permanently" : "Delete";
  return (
    <div className="kiwi-actionbar em-actionbar" role="toolbar" aria-label={`Bulk actions for ${count} selected messages`}>
      <strong>{count} selected</strong>
      <button type="button" onClick={onRead}>
        Mark read
      </button>
      <button type="button" onClick={onUnread}>
        Mark unread
      </button>
      <button type="button" onClick={onArchive}>
        Archive
      </button>
      <label>
        <span className="kiwi-sr-only">Move selected to folder</span>
        <select
          defaultValue=""
          onChange={(e) => {
            if (e.target.value === "archive" || e.target.value === "inbox") onMove(e.target.value);
            e.target.value = "";
          }}
          aria-label="Move selected messages to folder"
          title="Move targets supported by the backend: Archive and Inbox"
        >
          <option value="">Move to…</option>
          <option value="archive">Archive</option>
          <option value="inbox">Inbox</option>
        </select>
      </label>
      {confirming === "delete" ? (
        <>
          <button
            type="button"
            onClick={() => {
              setConfirming(null);
              onDelete(inTrash);
            }}
            title={inTrash ? "Expunges immediately — cannot be undone" : "Moves to Trash — recoverable until Trash is emptied"}
          >
            Confirm {inTrash ? "permanently delete" : "delete"} {count} message(s)
          </button>
          <button type="button" onClick={() => setConfirming(null)}>
            Keep
          </button>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setConfirming("delete")}
          title={demo ? "Demo: delete needs the backend" : inTrash ? `Permanently delete ${count} message(s)` : `Move ${count} message(s) to Trash`}
        >
          {deleteLabel}
        </button>
      )}
      {confirming === "spam" ? (
        <>
          <button type="button" onClick={() => { setConfirming(null); onSpam(); }}>
            Confirm mark {count} as spam
          </button>
          <button type="button" onClick={() => setConfirming(null)}>
            Keep
          </button>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setConfirming("spam")}
          title={demo ? "Demo: spam needs the backend" : `Move ${count} message(s) to the account Spam folder`}
        >
          Spam
        </button>
      )}
      <button type="button" onClick={onClear}>
        Clear
      </button>
    </div>
  );
}

function OutboxList({ outbox, onCancelSend }: { outbox: OutboxItem[]; onCancelSend: (queueId: string) => void }) {
  // Ticking clock for the undo-window countdown + scheduled-send times.
  // Ticks only while the outbox is mounted; static under reduced-motion
  // (the raw timestamps stay in the title attributes).
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    if (typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    const t = window.setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => window.clearInterval(t);
  }, []);
  if (outbox.length === 0) {
    return (
      <div className="kiwi-empty">
        <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
          <IconOutbox size={28} />
        </span>
        <strong>Outbox is empty</strong>
        <br />
        <small>Queued and scheduled sends will appear here.</small>
      </div>
    );
  }
  return (
    <div className="em-outbox" role="list" aria-label="Queued sends">
      {outbox.map((o) => {
        const undoLeft = Math.ceil(o.undoWindowUntilUnix - now);
        const sendsIn = Math.ceil(o.notBeforeUnix - now);
        const status =
          o.cancelable && undoLeft > 0
            ? `Undo open — ${undoLeft}s left`
            : sendsIn > 0
              ? `Scheduled — sends ${new Date(o.notBeforeUnix * 1000).toLocaleString()}`
              : o.attempts > 0
                ? `Dispatching… (attempt ${o.attempts})`
                : "Dispatching…";
        return (
          <article key={o.queueId} role="listitem" className="em-card em-outbox-card">
            <div>
              <strong>{o.subject || "(no subject)"}</strong>
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
              To {o.to.join(", ")} · attempts {o.attempts} ·{" "}
              <span title={`Undo window ends ${new Date(o.undoWindowUntilUnix * 1000).toLocaleString()}; not-before ${new Date(o.notBeforeUnix * 1000).toLocaleString()}`}>
                {status}
              </span>
            </div>
            <div style={{ marginTop: "0.3rem" }}>
              <button
                type="button"
                onClick={() => onCancelSend(o.queueId)}
                disabled={!o.cancelable}
                title={o.cancelable ? (undoLeft > 0 ? `Undo send (${undoLeft}s left)` : "Undo send") : "Undo window closed — message dispatching"}
              >
                {o.cancelable && undoLeft > 0 ? `Undo send (${undoLeft}s)` : "Undo send"}
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}
