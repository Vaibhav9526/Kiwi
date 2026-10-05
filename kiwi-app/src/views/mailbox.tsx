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
import type { CSSProperties, MouseEvent as ReactMouseEvent } from "react";
import type { AttachRiskView, FindingInfo, FolderView, MessageBodyView, MessageEnvelope, MessagePatch, MessageSourceView, OutboxItem, RenderedBodyView, SearchHit, Severity, SnoozePreset, UnsubscribeInfo } from "../kiwi";
import { severityLabel } from "../kiwi";
import { listen } from "@tauri-apps/api/event";
import { api, isTauri } from "../ipc";
import { loadPref, savePref } from "../prefs";
import { loadLocalBook, saveLocalBook, upsertLocal } from "../contacts";
import { navigate } from "../router";
import { requestCompose } from "./compose";
import { SecurityPill } from "../components/security";
import { PaneSplitter } from "../components/chrome";
import { ContextMenu } from "../components/contextmenu";
import type { CtxEntry } from "../components/contextmenu";
import { usePaneWidth } from "../state/panes";
import { buildThreads, displaySubject } from "../threading";
import type { Thread } from "../threading";
import {
  IconArchive,
  IconChevronDown,
  IconChevronRight,
  IconChevronUp,
  IconFilter,
  IconMail,
  IconOutbox,
  IconFile,
  IconPaperclip,
  IconPrint,
  IconReply,
  IconReplyAll,
  IconStar,
} from "../components/shell-icons";
// Mailspring thread-list row port (skin port — KIWI keeps its list
// container, selection, pick and date-group machinery; the row item layer
// is Mailspring's ListTabularItem + narrow `Item` column verbatim).
import { ListTabularRows } from "../ms/ms-list-tabular";
import { KIWI_ROW_COLUMNS, MS_ROW_HEIGHT, msRowEntry } from "../ms/ms-thread-row";
import type { MsRowEntry, MsRowViewCtx } from "../ms/ms-thread-row";
import { setThreadListPerspective } from "../ms/ms-thread";
import type { MsThread } from "../ms/ms-thread";

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
  /** T-289: real account count — drives the first-run "Add account" CTA
   *  instead of a misleading "no messages" empty state. */
  hasAccounts: boolean;
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
  onScheduleSend: (queueId: string, sendAtUnix: number) => void;
  onOutboxRefresh: () => void;
  /** T-299: per-account folder lists — the real Move-to/Copy-to submenu source. */
  folderLists: Record<string, FolderView[]>;
  onSnooze: (ids: string[], preset: SnoozePreset) => void;
  onMoveToFolder: (ids: string[], dstFolderId: number) => void;
  /** T-332: kiwi_copy_messages — local duplicate into dst, picked-aware. */
  onCopyToFolder: (ids: string[], dstFolderId: number) => void;
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
  const preFilterSelected = messages.find((m) => m.id === selectedId) ?? messages[0];

  // T-313 quick-filter chips — client-side view filtering over the rows
  // already fetched for this folder+tab. Chips AND-combine; `sender`
  // captures the selected row's From address when toggled on. Resets on
  // folder switch (folder-keyed state is wrong across folders — flags
  // survive but the sender address doesn't transfer meaningfully).
  type Chip = "unread" | "starred" | "attach" | "sender";
  const [chips, setChips] = useState<Set<Chip>>(new Set());
  const [senderFilter, setSenderFilter] = useState<string | null>(null);
  useEffect(() => {
    setChips(new Set());
    setSenderFilter(null);
  }, [folder]);
  const toggleChip = (c: Chip) => {
    setChips((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
    if (c === "sender") {
      setSenderFilter((prev) => (prev ? null : (preFilterSelected?.from ?? null)));
    }
  };
  const filtered = useMemo(() => {
    if (chips.size === 0) return messages;
    return messages.filter((m) => {
      if (chips.has("unread") && !m.unread) return false;
      if (chips.has("starred") && !m.starred) return false;
      if (chips.has("attach") && !m.hasAttachments) return false;
      if (chips.has("sender") && senderFilter && m.from !== senderFilter) return false;
      return true;
    });
  }, [messages, chips, senderFilter]);
  const selected = filtered.find((m) => m.id === selectedId) ?? filtered[0];

  // Bulk selection (T-162): explicit id list + range anchor. Cleared on
  // folder/tab change (ids are folder-scoped) and after move actions.
  const [picked, setPicked] = useState<string[]>([]);
  // Two-step row delete (was per-RowShell; now the ported rows are
  // memoized ListTabularItems, so the armed id is hoisted here).
  const [armedDel, setArmedDel] = useState<string | null>(null);
  const anchorRef = useRef<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const selectAllRef = useRef<HTMLInputElement | null>(null);
  // T-291: list⇄reader focus ping-pong — Enter opens the reader, Esc returns.
  const rowsRef = useRef<HTMLDivElement | null>(null);
  const readerRef = useRef<HTMLElement | null>(null);
  // T-293: resizable list column (persisted, clamped 280–600px).
  const listW = usePaneWidth("kiwi.pane.list", 320, 280, 600);
  useEffect(() => {
    setPicked([]);
    setArmedDel(null);
    anchorRef.current = null;
  }, [folder, catTab]);

  const togglePick = (id: string, range: boolean) => {
    if (range && anchorRef.current) {
      const a = filtered.findIndex((m) => m.id === anchorRef.current);
      const b = filtered.findIndex((m) => m.id === id);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        const span = filtered.slice(lo, hi + 1).map((m) => m.id);
        setPicked((prev) => Array.from(new Set([...prev, ...span])));
        return;
      }
    }
    anchorRef.current = id;
    setPicked((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const allPicked = filtered.length > 0 && picked.length >= filtered.length;
  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = picked.length > 0 && !allPicked;
    }
  }, [picked, allPicked]);

  const isTrash = folder === "trash" || (folder !== "outbox" && /trash|deleted|bin/i.test(folderLabel));
  /* ---- T-299: right-click menu on list rows. Right-click selects the row
   * when it isn't part of the multi-selection (eM/Thunderbird idiom); the
   * menu acts on the picked set if the row is picked, else the row's own
   * ids (thread rows pass every member). ---- */
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; ids: string[] } | null>(null);
  const openRowMenu = (e: ReactMouseEvent, ids: string[]) => {
    e.preventDefault();
    if (ids.length > 0 && !ids.some((id) => picked.includes(id))) {
      navigate({ name: "mail", folder, messageId: ids[ids.length - 1] });
    }
    setCtxMenu({ x: e.clientX, y: e.clientY, ids });
  };

  const ctxIds = ctxMenu ? (ctxMenu.ids.some((id) => picked.includes(id)) ? picked : ctxMenu.ids) : [];
  const ctxEnvs = ctxIds.map((id) => allMessages.find((m) => m.id === id)).filter((m): m is MessageEnvelope => !!m);
  const ctxSingle = ctxEnvs.length === 1 ? ctxEnvs[0] : null;
  const ctxAccount = ctxEnvs.length > 0 && ctxEnvs.every((m) => m.accountId === ctxEnvs[0].accountId) ? ctxEnvs[0].accountId : null;
  // T-332: shared destination list for Move-to AND Copy-to — same
  // construction rules (account-matched, current folder excluded).
  const ctxDstFolders = ctxAccount
    ? (props.folderLists[ctxAccount] ?? []).filter((f) => !(ctxSingle && ctxSingle.folderId === f.id))
    : [];
  const backendTip = "Needs the Tauri backend";
  const ctxEntries: CtxEntry[] = ctxMenu
    ? [
        { label: "Reply", icon: "reply", disabled: !ctxSingle, title: ctxSingle ? undefined : "Select a single message", onSelect: () => seedCompose("reply", ctxSingle!, ctxSingle!.id === selectedId ? props.body : null) },
        { label: "Reply All", icon: "reply-all", disabled: !ctxSingle, title: ctxSingle ? undefined : "Select a single message", onSelect: () => seedCompose("replyAll", ctxSingle!, ctxSingle!.id === selectedId ? props.body : null) },
        { label: "Forward", icon: "forward", disabled: !ctxSingle, title: ctxSingle ? undefined : "Select a single message", onSelect: () => seedCompose("forward", ctxSingle!, ctxSingle!.id === selectedId ? props.body : null) },
        "divider",
        ...(ctxSingle
          ? ([
              { label: ctxSingle.unread ? "Mark as read" : "Mark as unread", icon: ctxSingle.unread ? "mail-open" : "mail", onSelect: () => props.onToggleRead(ctxSingle.id) },
              { label: ctxSingle.starred ? "Remove star" : "Star", icon: "star", onSelect: () => props.onToggleStar(ctxSingle.id) },
            ] as CtxEntry[])
          : ([
              { label: `Mark ${ctxIds.length} as read`, icon: "mail-open", onSelect: () => props.onBulkPatch(ctxIds, { seen: true }, "Marked read") },
              { label: `Mark ${ctxIds.length} as unread`, icon: "mail", onSelect: () => props.onBulkPatch(ctxIds, { seen: false }, "Marked unread") },
              { label: `Star ${ctxIds.length}`, icon: "star", onSelect: () => props.onBulkPatch(ctxIds, { starred: true }, "Starred") },
              { label: `Unstar ${ctxIds.length}`, icon: "star", onSelect: () => props.onBulkPatch(ctxIds, { starred: false }, "Unstarred") },
            ] as CtxEntry[])),
        "divider",
        {
          label: "Snooze",
          icon: "snooze",
          disabled: props.demo,
          title: props.demo ? backendTip : undefined,
          submenu: [
            { label: "Later today", onSelect: () => props.onSnooze(ctxIds, "later_today") },
            { label: "Tomorrow", onSelect: () => props.onSnooze(ctxIds, "tomorrow") },
            { label: "Next week", onSelect: () => props.onSnooze(ctxIds, "next_week") },
          ],
        },
        {
          label: "Archive",
          icon: "archive",
          onSelect: () => (ctxSingle ? props.onArchive(ctxSingle.id, true) : props.onBulkPatch(ctxIds, { archived: true }, "Archived")),
        },
        {
          label: "Move to",
          icon: "folder",
          disabled: props.demo || ctxDstFolders.length === 0,
          title: props.demo ? backendTip : ctxDstFolders.length === 0 ? "No other folders on this account" : undefined,
          submenu: ctxDstFolders.map((f) => ({ label: f.name, onSelect: () => props.onMoveToFolder(ctxIds, f.id) })),
        },
        {
          label: "Copy to",
          icon: "folder",
          disabled: props.demo || ctxDstFolders.length === 0,
          title: props.demo
            ? backendTip
            : ctxDstFolders.length === 0
              ? "No other folders on this account"
              : "Duplicates into a local copy — never an IMAP server COPY",
          submenu: ctxDstFolders.map((f) => ({ label: f.name, onSelect: () => props.onCopyToFolder(ctxIds, f.id) })),
        },
        "divider",
        { label: "Mark as junk", icon: "flag", disabled: props.demo, title: props.demo ? backendTip : undefined, onSelect: () => props.onBulkSpam(ctxIds) },
        { label: isTrash ? "Delete permanently" : "Delete", icon: "trash", danger: true, onSelect: () => props.onBulkDelete(ctxIds, isTrash, isTrash ? "Deleted permanently" : "Moved to Trash") },
      ]
    : [];
  // T-284: the reader pill expands into the message's own evidence panel —
  // auth/link/attachment hints carried on the envelope, never the findings feed.
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [sourceOpen, setSourceOpen] = useState(false);
  useEffect(() => {
    setEvidenceOpen(false);
    setSourceOpen(false);
  }, [selected?.id]);
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
  const threads = useMemo(() => buildThreads(filtered), [filtered]);

  // Mailspring seam: the ported row components read the focused
  // perspective for sent/inbox timestamp choice and quick-action gating —
  // publish KIWI's current folder view here (per folder/account set).
  useEffect(() => {
    const accountIds = [...new Set(allMessages.map((m) => m.accountId))];
    setThreadListPerspective({
      isSent: () => folder === "sent",
      isInbox: () => folder === "inbox" || folder === "all-inboxes",
      accountIds,
      // Row quick actions stay visible everywhere (the trash action arms
      // the KIWI two-step delete; archive runs onArchive) — same as the
      // pre-port row buttons.
      canArchiveThreads: () => true,
      canMoveThreadsTo: () => true,
      categories: () => [],
      name: folderLabel,
    });
  }, [folder, folderLabel, allMessages]);
  const [threadMode, setThreadMode] = useState(() => loadPref("kiwi.threadMode", "threads"));
  useEffect(() => savePref("kiwi.threadMode", threadMode), [threadMode]);
  const [groupsOpen, setGroupsOpen] = useState<Record<string, boolean>>({});

  // Today / Older date groups over the (flat or threaded) row list.
  type RowEntry = { kind: "msg"; m: MessageEnvelope } | { kind: "thread"; t: Thread };
  const rows = useMemo<RowEntry[]>(() => {
    const flat: RowEntry[] =
      threadMode === "threads"
        ? threads.map((t) => ({ kind: "thread", t }))
        : filtered.map((m) => ({ kind: "msg", m }));
    return flat;
  }, [threadMode, threads, filtered]);
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
    if (!selected || filtered.length === 0) return;
    const i = filtered.findIndex((m) => m.id === selected.id);
    const next = filtered[(i + dir + filtered.length) % filtered.length];
    if (next) navigate({ name: "mail", folder, messageId: next.id });
  };

  const selectedThread = useMemo(
    () => (selected ? threads.find((t) => t.messages.some((m) => m.id === selected.id)) ?? null : null),
    [threads, selected],
  );

  return (
    <div className="em-mailbox ms-view-enter" style={{ "--kiwi-pane-list": `${listW.px}px` } as CSSProperties}>
      <section aria-label={`${folderLabel} message list`} className="em-list-col">
        <div className="em-list-head">
          <h1 ref={headingRef} tabIndex={-1} className="em-pane-title">
            {searching ? "Search results" : folderLabel}{" "}
            <small className="em-pane-sub">
              {searching
                ? `(${searchHits.length} hit(s) — “${props.searchQuery.trim()}”)`
                : `(${folder === "outbox" ? props.outbox.length : chips.size > 0 ? `${filtered.length} of ${messages.length} filtered` : `${messages.length} of ${allMessages.length}`})`}
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
                    setPicked(filtered.map((m) => m.id));
                    anchorRef.current = filtered[filtered.length - 1]?.id ?? null;
                  }
                }}
                aria-label={allPicked ? `Deselect all ${filtered.length} shown messages` : `Select all ${filtered.length} shown messages`}
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
        {folder !== "outbox" && !searching && allMessages.length > 0 && (
          <div className="em-filterbar" role="group" aria-label="Quick filters — narrow the loaded list">
            {(
              [
                { id: "unread", label: "Unread", count: messages.filter((m) => m.unread).length },
                { id: "starred", label: "Starred", count: messages.filter((m) => m.starred).length },
                { id: "attach", label: "Attachments", count: messages.filter((m) => m.hasAttachments).length },
              ] as { id: Chip; label: string; count: number }[]
            ).map((c) => (
              <button
                key={c.id}
                type="button"
                className={`em-chip${chips.has(c.id) ? " is-on" : ""}`}
                aria-pressed={chips.has(c.id)}
                onClick={() => toggleChip(c.id)}
              >
                {c.label} <span className="em-chip-n">{c.count}</span>
              </button>
            ))}
            <button
              type="button"
              className={`em-chip${chips.has("sender") ? " is-on" : ""}`}
              aria-pressed={chips.has("sender")}
              disabled={!preFilterSelected}
              title={
                preFilterSelected
                  ? chips.has("sender")
                    ? `Showing only mail from ${senderFilter}`
                    : `Show only mail from ${preFilterSelected.from}`
                  : "Select a message first — filters to its sender"
              }
              onClick={() => toggleChip("sender")}
            >
              From sender
            </button>
            {chips.size > 0 && (
              <button
                type="button"
                className="em-chip em-chip-clear"
                onClick={() => {
                  setChips(new Set());
                  setSenderFilter(null);
                }}
              >
                Clear
              </button>
            )}
            <span role="status" className="em-filterbar-status">
              {chips.size > 0 ? `${filtered.length} of ${messages.length} shown` : ""}
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
          <OutboxList outbox={props.outbox} onCancelSend={props.onCancelSend} onScheduleSend={props.onScheduleSend} />
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
            {filtered.length === 0 && !props.messagesLoading && !props.hasAccounts && !props.demo && (
              <div className="kiwi-empty">
                <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                  <IconMail size={28} />
                </span>
                <strong>No accounts yet</strong>
                <br />
                <small>Add a mail account to start — the wizard covers IMAP/POP3, autoconfig, and OAuth2 sign-in.</small>
                <br />
                <button type="button" className="ms-btn ms-btn-primary" style={{ marginTop: "0.5rem" }} onClick={() => navigate({ name: "setup" })}>
                  Add account…
                </button>
              </div>
            )}
            {filtered.length === 0 && !props.messagesLoading && (props.hasAccounts || props.demo) && (
              <div className="kiwi-empty">
                <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                  <IconMail size={28} />
                </span>
                {chips.size > 0 && allMessages.length > 0 ? (
                  <>
                    <strong>No matches</strong>
                    <br />
                    <small>Nothing in {folderLabel} passes the active filter chips.</small>
                    <br />
                    <button
                      type="button"
                      className="ms-btn"
                      style={{ marginTop: "0.5rem" }}
                      onClick={() => {
                        setChips(new Set());
                        setSenderFilter(null);
                      }}
                    >
                      Clear filters
                    </button>
                  </>
                ) : (
                  <>
                    <strong>Nothing here</strong>
                    <br />
                    <small>
                      {allMessages.length === 0
                        ? "No messages in this folder yet."
                        : `No ${catTab === "primary" ? "Primary" : "Other"} messages in the loaded list.`}
                    </small>
                  </>
                )}
              </div>
            )}
            <div
              className="em-rows thread-list"
              ref={rowsRef}
              role="listbox"
              aria-label="Messages. j/k or arrows move, Enter opens the reader, s stars, e archives, Delete deletes, r replies, u toggles read. Ctrl-click toggles selection, Shift-click range-selects."
              aria-multiselectable="true"
              aria-activedescendant={selected?.id}
              tabIndex={0}
              onKeyDown={(e) => {
                const t = e.target as HTMLElement | null;
                if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
                if (e.key === "ArrowDown" || e.key === "j") {
                  e.preventDefault();
                  stepSelection(1);
                } else if (e.key === "ArrowUp" || e.key === "k") {
                  e.preventDefault();
                  stepSelection(-1);
                } else if (e.key === "n") stepSelection(1);
                else if (e.key === "p") stepSelection(-1);
                else if (!selected) return;
                else if (e.key === "Enter") {
                  // Open = move keyboard focus into the reader pane (its
                  // own map takes over: Esc back, r/a/f composer).
                  e.preventDefault();
                  readerRef.current?.focus();
                } else if (e.key === "u") props.onToggleRead(selected.id);
                else if (e.key === "s") props.onToggleStar(selected.id);
                else if (e.key === "e") props.onArchive(selected.id, true);
                else if (e.key === "Delete") {
                  e.preventDefault();
                  props.onBulkDelete([selected.id], isTrash, isTrash ? "Deleted permanently" : "Moved to Trash");
                } else if (e.key === "r") requestCompose();
              }}
            >
              <DateGroup
                label="Today"
                rows={todayRows}
                open={groupsOpen["today"] ?? true}
                onToggle={() => setGroupsOpen((m) => ({ ...m, today: !(m["today"] ?? true) }))}
                folder={folder}
                draftsView={folder === "drafts"}
                currentId={selected?.id}
                picked={picked}
                armedDelId={armedDel}
                onTogglePick={togglePick}
                onToggleStar={props.onToggleStar}
                onArchive={(id) => props.onArchive(id, true)}
                onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
                onArmTrash={setArmedDel}
                onDisarmTrash={() => setArmedDel(null)}
                onRowContext={openRowMenu}
              />
              <DateGroup
                label="Older"
                rows={olderRows}
                open={groupsOpen["older"] ?? true}
                onToggle={() => setGroupsOpen((m) => ({ ...m, older: !(m["older"] ?? true) }))}
                folder={folder}
                draftsView={folder === "drafts"}
                currentId={selected?.id}
                picked={picked}
                armedDelId={armedDel}
                onTogglePick={togglePick}
                onToggleStar={props.onToggleStar}
                onArchive={(id) => props.onArchive(id, true)}
                onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
                onArmTrash={setArmedDel}
                onDisarmTrash={() => setArmedDel(null)}
                onRowContext={openRowMenu}
              />
            </div>
          </>
        )}
      </section>
      <PaneSplitter
        label="Message list width"
        value={listW.px}
        min={280}
        max={600}
        onResize={listW.set}
        onReset={listW.reset}
      />
      <section
        key={selected?.id ?? "none"}
        className="em-reader ms-ready"
        aria-label="Message reader. Esc returns to the list; r reply, a reply-all, f forward open the composer."
        tabIndex={0}
        ref={readerRef}
        onKeyDown={(e) => {
          const t = e.target as HTMLElement | null;
          const typing = !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
          if (typing) {
            // Esc inside a field blurs it rather than bouncing panes.
            if (e.key === "Escape") (t as HTMLElement).blur();
            return;
          }
          if (e.key === "Escape") {
            e.preventDefault();
            rowsRef.current?.focus();
          } else if (e.ctrlKey || e.metaKey || e.altKey) return;
          else if (!selected) return;
          else if (e.key === "r" || e.key === "a" || e.key === "f") {
            // Reply / reply-all / forward seed the composer via the
            // sessionStorage handoff (to/subject/quote — T-314).
            e.preventDefault();
            seedCompose(e.key === "r" ? "reply" : e.key === "a" ? "replyAll" : "forward", selected, selected.id === selectedId ? props.body : null);
          }
        }}
      >
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
                <button
                  type="button"
                  className="em-iconbtn"
                  onClick={() => setSourceOpen(true)}
                  disabled={!props.body}
                  title={
                    props.body
                      ? "View source — parsed headers + stored body parts (full RFC822 source needs a backend IPC — not exposed yet)"
                      : "View source — load the message body first (live mode only)"
                  }
                  aria-label="View message source"
                >
                  <IconFile size={14} />
                </button>
              </span>
            </div>
            <div className="em-reader-meta">
              <SecurityPill
                level={messageEvidenceLevel(selected) ?? selected.trust}
                summary={pillSummaryFor(selected)}
                onOpen={() => setEvidenceOpen((o) => !o)}
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
            {evidenceOpen && <MessageEvidence m={selected} />}
            {sourceOpen && props.body && (
              <SourceDialog body={props.body} accountId={selected.accountId} onClose={() => setSourceOpen(false)} />
            )}
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
                    threadMessages={selectedThread?.messages ?? [selected]}
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
      {ctxMenu && <ContextMenu x={ctxMenu.x} y={ctxMenu.y} entries={ctxEntries} onClose={() => setCtxMenu(null)} />}
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
  draftsView,
  currentId,
  picked,
  armedDelId,
  onTogglePick,
  onToggleStar,
  onArchive,
  onDelete,
  onArmTrash,
  onDisarmTrash,
  onRowContext,
}: {
  label: string;
  rows: RowEntry[];
  open: boolean;
  onToggle: () => void;
  folder: string;
  draftsView: boolean;
  currentId?: string;
  picked: string[];
  armedDelId: string | null;
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
  onArmTrash: (rowId: string) => void;
  onDisarmTrash: () => void;
  onRowContext: (e: ReactMouseEvent, ids: string[]) => void;
}) {
  if (rows.length === 0) return null;
  // View context for the ported row layer — KIWI callbacks/state stamped
  // onto each MsThread's `__kiwi` seam by msRowEntry.
  const ctx: MsRowViewCtx = {
    folder,
    draftsView,
    currentId,
    picked,
    armedDelId,
    onTogglePick,
    onToggleStar,
    onArchive,
    onDelete,
    onArmTrash,
    onDisarmTrash,
    onRowContext,
    // T-335: aggregate views (folder key has no `acct:id` colon shape)
    // tag each row with its OWN account — merged rows stay truthful.
    acctTagFor: (entry) => {
      if (folder.includes(":")) return undefined;
      if (entry.kind === "msg") {
        return { label: entry.m.accountEmail, color: avatarTint(entry.m.accountEmail) };
      }
      const accts = [...new Set(entry.t.messages.map((m) => m.accountId))];
      const emails = [...new Set(entry.t.messages.map((m) => m.accountEmail))];
      return accts.length === 1
        ? { label: emails[0], color: avatarTint(emails[0]) }
        : { label: `${accts.length} accounts`, color: "var(--kiwi-text-secondary, #666)" };
    },
    avatarFor: (seed) => ({
      initial: senderName(seed).slice(0, 1).toUpperCase() || "?",
      color: avatarTint(seed),
    }),
  };
  const rendered = open
    ? rows.flatMap((r, idx) => {
        const entry: MsRowEntry | null =
          r.kind === "msg" && r.m
            ? { kind: "msg", m: r.m }
            : r.kind === "thread" && r.t
              ? { kind: "thread", t: r.t }
              : null;
        if (!entry) return [];
        const { item, itemProps } = msRowEntry(entry, ctx);
        return [{ item, idx, itemProps }];
      })
    : [];
  return (
    <div className="em-date-group">
      <button type="button" className="em-group-head" aria-expanded={open} onClick={onToggle}>
        <span className={`em-disclosure${open ? " is-open" : ""}`} aria-hidden="true">
          <IconChevronRight size={10} />
        </span>
        {label}
      </button>
      {open && (
        <ListTabularRows
          rows={rendered}
          columns={KIWI_ROW_COLUMNS}
          itemHeight={MS_ROW_HEIGHT}
          innerStyles={{
            height: rendered.length * MS_ROW_HEIGHT,
            backgroundSize: `100% ${MS_ROW_HEIGHT}px`,
          }}
          onClick={(item: MsThread, e: ReactMouseEvent) => {
            const k = item.__kiwi;
            if (e.ctrlKey || e.metaKey) {
              e.preventDefault();
              k.onPick(false);
              return;
            }
            if (e.shiftKey) {
              e.preventDefault();
              k.onPick(true);
              return;
            }
            if ((e.target as HTMLElement).closest("button,input")) return;
            navigate({ name: "mail", folder, messageId: k.navId });
          }}
        />
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


/* ---------------- reader: stacked message cards ---------------- */

/** T-310: normalize an RFC822 Message-ID header for matching. */
/** T-314: one-shot compose handoff — the composer consumes `kiwi.replySeed`
 *  on mount (same pattern as the contacts `kiwi.composeTo` Write handoff).
 *  Quote attaches ONLY when `body` is provably this message's (callers pass
 *  null when it belongs to another envelope — never fabricate a quote).
 *  Storage denied → the composer still opens, just unseeded. */
export type ComposeSeedMode = "reply" | "replyAll" | "forward";
export function seedCompose(mode: ComposeSeedMode, m: MessageEnvelope, body: MessageBodyView | null): void {
  const addr = (s: string) => (s.match(/<([^>]+)>/)?.[1] ?? s).trim();
  const seed: { to: string[]; cc: string[]; subject: string; quote: string | null } = { to: [], cc: [], subject: "", quote: null };
  if (mode === "forward") {
    seed.subject = /^fwd?:/i.test(m.subject) ? m.subject : `Fwd: ${m.subject}`;
  } else {
    seed.to = [addr(m.from)];
    if (mode === "replyAll" && body) {
      const self = m.accountEmail.toLowerCase();
      const seen = new Set([addr(m.from).toLowerCase(), self]);
      for (const raw of [...body.to, ...body.cc]) {
        const a = addr(raw);
        const k = a.toLowerCase();
        if (a && !seen.has(k)) {
          seen.add(k);
          seed.cc.push(a);
        }
      }
    }
    seed.subject = /^re:/i.test(m.subject) ? m.subject : `Re: ${m.subject}`;
  }
  const text = body?.textBody;
  if (text) {
    const quoted = text
      .split(/\r?\n/)
      .map((l) => `> ${l}`)
      .join("\n");
    seed.quote = `On ${m.date}, ${m.from} wrote:\n${quoted}\n`;
  }
  try {
    window.sessionStorage.setItem("kiwi.replySeed", JSON.stringify(seed));
  } catch {
    // storage denied — composer opens blank, nothing lost.
  }
  requestCompose(); // T-343: opens the floating dock (or #/compose as fallback)
}

function normMsgId(s: string | null | undefined): string {
  return (s ?? "").trim().replace(/^<|>$/g, "").trim().toLowerCase();
}

function MessageCard({
  m,
  isSelected,
  folder,
  threadMessages,
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
  /** T-310: loaded thread members — for the in-reply-to jump resolution. */
  threadMessages: MessageEnvelope[];
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
            onClick={() => seedCompose("reply", m, body)}
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
          {/* T-310: in-reply-to jump — resolves the message's chain header
              against the loaded thread's real Message-IDs; nothing renders
              when the parent isn't in view. */}
          {(() => {
            const wanted = normMsgId(m.inReplyTo) || normMsgId(m.references?.[m.references.length - 1]);
            if (!wanted) return null;
            const parent = threadMessages.find((t) => normMsgId(t.messageId) === wanted && t.id !== m.id);
            if (!parent) return null;
            return (
              <p className="em-card-to" style={{ marginTop: 0 }}>
                <button
                  type="button"
                  className="em-quote-toggle"
                  onClick={() => navigate({ name: "mail", folder, messageId: parent.id })}
                  title={`Message-ID ${parent.messageId}`}
                >
                  ← In reply to {senderName(parent.from)}
                </button>
              </p>
            );
          })()}
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
                key={m.id}
                body={body}
                demo={demo}
                attachNote={attachNote}
                attachBusy={attachBusy}
                attachRisk={m.attachRisk ?? null}
                onSaveAttachment={onSaveAttachment}
              />
              <BodyPane
                body={body}
                rendered={rendered}
                renderLoading={renderLoading}
                renderError={renderError}
                remoteAllowed={remoteAllowed}
                demo={demo}
                accountId={m.accountId}
                folderId={m.folderId}
                uid={m.uid}
                onAllowRemote={onAllowRemote}
              />
            </>
          ) : (
            <p className="em-card-snippet">{m.snippet}</p>
          )}
          <div className="em-card-actions">
            <button type="button" className="ms-btn" onClick={() => seedCompose("reply", m, body)} title="Reply (r)">
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
  attachRisk,
  onSaveAttachment,
}: {
  body: MessageBodyView;
  demo: boolean;
  attachNote: string | null;
  attachBusy: boolean;
  /** T-254/T-284 message-level attachment evidence; null until evaluated. */
  attachRisk: AttachRiskView | null;
  onSaveAttachment: (attachmentIndex: number, destPath: string) => void;
}) {
  const [destPaths, setDestPaths] = useState<Record<number, string>>({});
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [sandboxNote, setSandboxNote] = useState<string | null>(null);
  // Reset per-message save state when the selection changes.
  useEffect(() => {
    setDestPaths({});
    setSandboxNote(null);
  }, [body.folderId, body.uid]);

  const openInSandbox = async (filename: string | null) => {
    if (!filename || demo || !isTauri()) return;
    setSandboxBusy(true);
    try {
      const s = await api.sandboxOpenAttachment(body.folderId, body.uid, filename);
      setSandboxNote(
        `Sandbox session ${s.sessionId} opened for ${s.target}.` +
          (s.evidenceReasons.length > 0 ? ` Evidence: ${s.evidenceReasons.join(", ")}.` : ""),
      );
    } catch (e) {
      setSandboxNote(`Sandbox open failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSandboxBusy(false);
    }
  };

  if (body.attachments.length === 0) return null;
  return (
    <div aria-label="Attachments" className="em-attach">
      {attachRisk && attachRisk.risk !== "clean" && (
        <p className={`kiwi-banner ${attachRisk.risk === "failed" ? "error" : "warn"}`} role="status">
          <small>
            Attachment evidence: {attachRisk.risk}
            {attachRisk.reasons.length > 0 ? ` — ${attachRisk.reasons.join(", ")}` : ""}. Detonate in the sandbox instead of saving.
          </small>
        </p>
      )}
      {body.attachments.map((a, i) => (
        <p key={`${a.filename}-${a.index}-${i}`}>
          <small>
            <IconPaperclip size={11} /> {a.filename ?? "(unnamed attachment)"}{" "}
            <span style={{ color: "var(--kiwi-text-secondary)" }}>
              ({a.contentType}, {a.size} B{!a.fetched ? ", downloaded on save" : ""})
            </span>
          </small>
          {!demo && (
            <>
              <br />
              <label>
                <small>Save to: </small>
                <input
                  type="text"
                  value={destPaths[a.index] ?? a.filename ?? ""}
                  onChange={(e) => setDestPaths((m) => ({ ...m, [a.index]: e.target.value }))}
                  placeholder={a.filename ?? undefined}
                  style={{ width: "16rem" }}
                  aria-label={`Save destination for ${a.filename ?? "attachment"}`}
                />
              </label>{" "}
              <button type="button" disabled={attachBusy} onClick={() => onSaveAttachment(a.index, destPaths[a.index] ?? a.filename ?? "attachment")}>
                {attachBusy ? "Saving…" : "Save"}
              </button>{" "}
              <button
                type="button"
                disabled={sandboxBusy || !a.filename}
                title="Detonate inside the isolated sandbox (kiwi_sandbox_open_attachment)"
                onClick={() => void openInSandbox(a.filename)}
              >
                {sandboxBusy ? "Opening…" : "Open in sandbox"}
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
      {sandboxNote && (
        <p role="status">
          <small>{sandboxNote}</small>
        </p>
      )}
    </div>
  );
}

/**
 * T-284: derive the reader pill's verdict from the message's own evidence
 * hints (T-232 auth, T-254 attachment, T-261 link). `null` when nothing has
 * been evaluated — the pill then falls back to account trust and says so.
 */
function messageEvidenceLevel(m: MessageEnvelope): Severity | null {
  const risks: string[] = [];
  if (m.auth) risks.push(m.auth.authRisk);
  if (m.linkRisk) risks.push(m.linkRisk.risk);
  if (m.attachRisk) risks.push(m.attachRisk.risk);
  if (risks.length === 0) return null;
  if (risks.includes("failed")) return "danger";
  if (risks.includes("noted")) return "warning";
  return "secure";
}

function pillSummaryFor(m: MessageEnvelope): string {
  if (messageEvidenceLevel(m) !== null) {
    return "Per-message evidence evaluated — activate for the auth/link/attachment detail.";
  }
  return `Account trust for ${m.accountEmail}. This message's auth/link/attachment evidence has not been evaluated yet (fetched bodies only) — activate for detail.`;
}

/** T-284: expandable per-message evidence detail under the reader pill. */
function MessageEvidence({ m }: { m: MessageEnvelope }) {
  const a = m.auth;
  const link = m.linkRisk;
  const att = m.attachRisk;
  if (!a && !link && !att) {
    return (
      <p className="em-note" role="status">
        <small>
          No per-message evidence yet — auth/link/attachment hints are evaluated when the body is fetched.{" "}
          Account trust: {severityLabel(m.trust)}.
        </small>
      </p>
    );
  }
  return (
    <div className="kiwi-banner" role="region" aria-label="Message security evidence" style={{ margin: "0.3rem 0" }}>
      {a && (
        <p style={{ margin: 0 }}>
          <small>
            <strong>Authentication:</strong> SPF {a.spf} · DKIM {a.dkim}
            {a.dkimDomain ? ` (${a.dkimDomain})` : ""} · DMARC {a.dmarc} (policy {a.dmarcPolicy})
            {a.discrepancy ? " — upstream/local verdict discrepancy" : ""}
            {a.upstream.untrustedRelay ? " — upstream auth via untrusted relay" : ""}
            {a.upstream.malformedHeaders > 0 ? ` — ${a.upstream.malformedHeaders} malformed upstream header(s)` : ""}
          </small>
        </p>
      )}
      {link && (
        <p style={{ margin: 0 }}>
          <small>
            <strong>Links:</strong> {link.risk}
            {link.reasons.length > 0 ? ` — ${link.reasons.join(", ")}` : ""}
          </small>
        </p>
      )}
      {att && (
        <p style={{ margin: 0 }}>
          <small>
            <strong>Attachments:</strong> {att.risk}
            {att.reasons.length > 0 ? ` — ${att.reasons.join(", ")}` : ""}
          </small>
        </p>
      )}
    </div>
  );
}

/**
 * T-292 "View source" — parsed headers + stored parts from the real
 * `kiwi_message_body` payload, plus (T-295) the verbatim RFC822 source via
 * `kiwi_message_source`, lazy-loaded on first open of the Raw tab. The raw
 * tab carries the backend's `truncated`/`bytes` honesty flags — never a
 * fabricated "full source".
 */
function SourceDialog({
  body,
  accountId,
  onClose,
}: {
  body: MessageBodyView;
  accountId: string;
  onClose: () => void;
}) {
  const [part, setPart] = useState<"html" | "text" | "raw">(body.htmlBody ? "html" : "text");
  const [raw, setRaw] = useState<MessageSourceView | null>(null);
  const [rawNote, setRawNote] = useState<string | null>(null);
  useEffect(() => {
    if (part !== "raw" || raw || rawNote) return;
    let cancelled = false;
    void (async () => {
      try {
        const v = await api.messageSource(accountId, body.folderId, body.uid);
        if (!cancelled) setRaw(v);
      } catch (e) {
        if (!cancelled)
          setRawNote(`Raw source unavailable: ${e instanceof Error ? e.message : String(e)}`);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [part, raw, rawNote, accountId, body.folderId, body.uid]);
  const headers: [string, string][] = [
    ["Subject", body.subject ?? "(no subject)"],
    ["From", body.from.join(", ") || "(unknown)"],
    ["To", body.to.join(", ") || "—"],
    ["Cc", body.cc.join(", ") || "—"],
    ["Date", body.dateUnix ? new Date(body.dateUnix * 1000).toLocaleString() : "—"],
    ["Message-ID", body.messageId ?? "—"],
    ["In-Reply-To", body.inReplyTo ?? "—"],
    ["References", body.references.join(" ") || "—"],
    ["Store coords", `folder ${body.folderId} · uid ${body.uid}`],
  ];
  const source = part === "html" ? body.htmlBody : body.textBody;
  return (
    <div className="kiwi-dialog-backdrop" role="presentation" onClick={onClose}>
      <div
        className="kiwi-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Message source"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          }
        }}
        style={{ maxWidth: "52rem", width: "92%" }}
      >
        <h1 style={{ marginTop: 0, fontSize: "1.1rem" }}>Message source</h1>
        <table style={{ borderCollapse: "collapse", width: "100%", marginBottom: "0.6rem" }}>
          <tbody>
            {headers.map(([k, v]) => (
              <tr key={k}>
                <td style={{ padding: "0.15rem 0.8rem 0.15rem 0", whiteSpace: "nowrap", verticalAlign: "top" }}>
                  <small>
                    <strong>{k}</strong>
                  </small>
                </td>
                <td style={{ padding: "0.15rem 0", wordBreak: "break-all" }}>
                  <small>{v}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p style={{ margin: "0 0 0.4rem" }}>
          <button
            type="button"
            disabled={!body.htmlBody}
            aria-pressed={part === "html"}
            onClick={() => setPart("html")}
            title={body.htmlBody ? "Stored text/html part" : "No HTML part stored"}
          >
            HTML part
          </button>{" "}
          <button
            type="button"
            disabled={!body.textBody}
            aria-pressed={part === "text"}
            onClick={() => setPart("text")}
            title={body.textBody ? "Stored text/plain part" : "No plaintext part stored"}
          >
            Plaintext part
          </button>{" "}
          <button
            type="button"
            aria-pressed={part === "raw"}
            onClick={() => setPart("raw")}
            title="Verbatim RFC822 bytes (kiwi_message_source, 8 MiB cap)"
          >
            Raw RFC822
          </button>
        </p>
        {part === "raw" ? (
          <>
            {raw && raw.truncated && (
              <p role="status">
                <small>
                  Truncated — showing first 8 MiB of {(raw.bytes / 1048576).toFixed(1)} MiB.
                </small>
              </p>
            )}
            {rawNote && (
              <p role="alert">
                <small>{rawNote}</small>
              </p>
            )}
            {!raw && !rawNote && (
              <p role="status">
                <small>Loading raw source…</small>
              </p>
            )}
            {raw && (
              <pre
                style={{
                  maxHeight: "18rem",
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  fontFamily: "monospace",
                  fontSize: "0.78rem",
                  padding: "0.5rem",
                  border: "1px solid var(--kiwi-border)",
                  borderRadius: "6px",
                  userSelect: "all",
                }}
              >
                {raw.source}
              </pre>
            )}
          </>
        ) : source ? (
          <pre
            style={{
              maxHeight: "18rem",
              overflow: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              fontFamily: "monospace",
              fontSize: "0.78rem",
              padding: "0.5rem",
              border: "1px solid var(--kiwi-border)",
              borderRadius: "6px",
              userSelect: "all",
            }}
          >
            {source}
          </pre>
        ) : (
          <p role="status">
            <small>No stored source for this part (body not yet fetched).</small>
          </p>
        )}
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>
            Parsed headers + stored body parts only — the full RFC822 wire source (verbatim MIME headers, all
            alternative parts) is not exposed by an IPC command yet. Contract gap filed under T-292.
          </small>
        </p>
        <button type="button" className="kiwi-btn-primary" onClick={onClose} autoFocus>
          Close (Esc)
        </button>
      </div>
    </div>
  );
}

/**
 * T-284 link policy gate state machine. Every click on a rendered-body anchor
 * goes through kiwi_link_click (message-scoped evidence) before anything
 * opens: allow → kiwi_open_external; requireConfirm/requireSandbox → an
 * explicit banner affordance; deny → blocked inline. Reasons are the bounded
 * deterministic codes only — never raw URL or body text.
 */
type LinkGate =
  | { phase: "checking"; url: string }
  | { phase: "confirm"; url: string; reasons: string[] }
  | { phase: "sandbox"; url: string; reasons: string[] }
  | { phase: "deny"; reasons: string[] }
  | { phase: "opened"; sessionId?: string; target?: string; reasons?: string[] }
  | { phase: "note" | "error"; text: string };

/** Matches the backend's sanitized_link_target: scheme://host/path only. */
function displayUrl(raw: string): string {
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 120);
  } catch {
    return "(unparseable link)";
  }
}

/**
 * T-310 — quoted-content split for text/plain bodies. Conservative: a
 * region only collapses when the quote marker is unambiguous — an
 * "On … wrote:" preamble or a `>`-prefixed run — AND the region runs to
 * end-of-message with at most a signature/`>` tail after it. Interleaved
 * quoting (a quote run followed by more real text) is left fully visible:
 * hiding it risks hiding real content.
 */
function splitQuotedText(text: string): { head: string; quoted: string | null; sig: string | null } {
  const lines = text.split("\n");
  const isQuote = (l: string) => /^>/.test(l.trim());
  const isPreamble = (l: string) => /^On .{1,300}wrote:?\s*$/im.test(l.trim());
  const isSigMark = (l: string) => /^--\s*$/.test(l);
  let qStart = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i] ?? "";
    if (isPreamble(l)) {
      // The preamble only counts when what follows is really quoted
      // material — at least one `>` line or nothing at all (bare trailer).
      const rest = lines.slice(i + 1);
      if (rest.some(isQuote) || rest.every((x) => x.trim() === "")) {
        qStart = i;
        break;
      }
      return { head: text, quoted: null, sig: null }; // stray "wrote:" text
    }
    if (isQuote(l)) {
      // Accept only a quote run that extends to EOM, tolerating blanks and
      // a trailing signature block — anything else interleaved means a
      // human mixed quote and reply; collapse nothing.
      let j = i;
      while (j < lines.length && (isQuote(lines[j] ?? "") || (lines[j] ?? "").trim() === "")) j++;
      const tail = lines.slice(j);
      const tailIsBlank = tail.every((x) => x.trim() === "");
      const tailIsSig = tail.length > 0 && isSigMark(tail[0] ?? "");
      const runLen = j - i;
      if (runLen >= 2 && (tailIsBlank || tailIsSig)) {
        qStart = i;
        break;
      }
      return { head: text, quoted: null, sig: null }; // ambiguous — collapse nothing
    }
  }
  if (qStart < 0) return { head: text, quoted: null, sig: null };
  const headLines = lines.slice(0, qStart);
  const quoted = lines.slice(qStart).join("\n").replace(/\n+$/, "");
  if (!headLines.join("\n").trim() || quoted.split("\n").length < 2) {
    return { head: text, quoted: null, sig: null };
  }
  // Signature: RFC 3676 "-- " delimiter inside the head only.
  let sigIdx = -1;
  for (let i = headLines.length - 1; i >= 0; i--) {
    if (/^--\s*$/.test(headLines[i] ?? "")) {
      sigIdx = i;
      break;
    }
  }
  if (sigIdx >= 0) {
    return {
      head: headLines.slice(0, sigIdx).join("\n").replace(/\n+$/, ""),
      sig: headLines.slice(sigIdx).join("\n"),
      quoted,
    };
  }
  return { head: headLines.join("\n"), quoted, sig: null };
}

/** Unambiguous quote containers in *already-sanitized* rendered HTML. */
const QUOTE_SEL = 'blockquote, .gmail_quote, [class*="gmail_quote"], .moz-cite-prefix, [type="cite"]';

function BodyPane({
  body,
  rendered,
  renderLoading,
  renderError,
  remoteAllowed,
  demo,
  accountId,
  folderId,
  uid,
  onAllowRemote,
}: {
  body: MessageBodyView;
  rendered: RenderedBodyView | null;
  renderLoading: boolean;
  renderError: string | null;
  remoteAllowed: boolean;
  demo: boolean;
  /** Message coordinates for the message-scoped kiwi_link_click verdict. */
  accountId: string;
  folderId: number;
  uid: number;
  onAllowRemote: (allowed: boolean) => void;
}) {
  const [showSource, setShowSource] = useState(false);
  const [gate, setGate] = useState<LinkGate | null>(null);
  useEffect(() => setGate(null), [accountId, folderId, uid]);

  // T-310: quote collapse. `quoteOpen` resets per message (toggle persists
  // for the open only — no pref). `quoteCount` = DOM nodes tagged in the
  // sanitized HTML; the text path uses `splitQuotedText`.
  const [quoteOpen, setQuoteOpen] = useState(false);
  const [quoteCount, setQuoteCount] = useState(0);
  const bodyRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setQuoteOpen(false);
  }, [accountId, folderId, uid]);
  useEffect(() => {
    const root = bodyRef.current;
    if (!root || !rendered?.html) {
      setQuoteCount(0);
      return;
    }
    // Top-level quote containers only (nested blockquotes ride their
    // ancestor). A preceding "On … wrote:" preamble element collapses with
    // its quote.
    const tops = [...root.querySelectorAll<HTMLElement>(QUOTE_SEL)].filter(
      (q) => !q.parentElement?.closest(QUOTE_SEL),
    );
    const targets: HTMLElement[] = [];
    for (const q of tops) {
      const prev = q.previousElementSibling;
      if (prev && /^On .{1,300}wrote:?\s*$/im.test((prev.textContent ?? "").trim())) {
        targets.push(prev as HTMLElement);
      }
      targets.push(q);
    }
    if (targets.length === 0) {
      setQuoteCount(0);
      return;
    }
    // Conservative: refuse to collapse when the quote is the ENTIRE body
    // (nothing would stay visible) — only collapse when real content
    // remains above/around it.
    const remainingText = [...root.children]
      .filter((el) => !targets.includes(el as HTMLElement))
      .map((el) => (el.textContent ?? "").trim())
      .join("");
    if (!remainingText) {
      setQuoteCount(0);
      return;
    }
    for (const t of targets) t.setAttribute("data-kiwi-quote", "");
    setQuoteCount(targets.length);
    return () => {
      for (const t of targets) t.removeAttribute("data-kiwi-quote");
    };
  }, [rendered?.html, accountId, folderId, uid]);

  const textParts = useMemo(
    () => splitQuotedText(body.textBody ?? ""),
    [body.textBody],
  );
  const textQuoted = textParts.quoted;

  const openExternal = async (url: string) => {
    try {
      await api.openExternal(url);
      setGate({ phase: "opened" });
    } catch (e) {
      setGate({ phase: "error", text: e instanceof Error ? e.message : String(e) });
    }
  };

  const openSandbox = async (url: string) => {
    setGate({ phase: "checking", url });
    try {
      const s = await api.sandboxOpenLink(url);
      setGate({ phase: "opened", sessionId: s.sessionId, target: s.target, reasons: s.evidenceReasons });
    } catch (e) {
      setGate({ phase: "error", text: e instanceof Error ? e.message : String(e) });
    }
  };

  const onBodyClick = (e: ReactMouseEvent<HTMLElement>) => {
    const a = (e.target as HTMLElement).closest("a[href]");
    if (!a) return;
    e.preventDefault();
    const href = a.getAttribute("href") ?? "";
    if (!href || href.startsWith("#")) return;
    if (demo || !isTauri()) {
      setGate({ phase: "note", text: "Link checks need the backend — run the Tauri app. Nothing was opened." });
      return;
    }
    void (async () => {
      setGate({ phase: "checking", url: href });
      try {
        const v = await api.linkClick(accountId, folderId, uid, href);
        if (v.action === "allow") await openExternal(href);
        else if (v.action === "requireConfirm") setGate({ phase: "confirm", url: href, reasons: v.reasons });
        else if (v.action === "requireSandbox") setGate({ phase: "sandbox", url: href, reasons: v.reasons });
        else setGate({ phase: "deny", reasons: v.reasons });
      } catch (err) {
        setGate({ phase: "error", text: err instanceof Error ? err.message : String(err) });
      }
    })();
  };
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
          {gate && (
            <div
              className={`kiwi-banner ${gate.phase === "deny" || gate.phase === "error" ? "error" : gate.phase === "confirm" || gate.phase === "sandbox" ? "warn" : ""}`}
              role={gate.phase === "deny" || gate.phase === "error" ? "alert" : "status"}
              aria-label="Link policy"
            >
              {gate.phase === "checking" && <small>Checking link safety…</small>}
              {gate.phase === "confirm" && (
                <>
                  <small>
                    Link needs confirmation — {displayUrl(gate.url)}
                    {gate.reasons.length > 0 ? ` — evidence: ${gate.reasons.join(", ")}` : ""}.
                  </small>{" "}
                  <button type="button" onClick={() => void openExternal(gate.url)}>Open anyway</button>{" "}
                  <button type="button" onClick={() => setGate(null)}>Cancel</button>
                </>
              )}
              {gate.phase === "sandbox" && (
                <>
                  <small>
                    Risky link — {displayUrl(gate.url)}
                    {gate.reasons.length > 0 ? ` — evidence: ${gate.reasons.join(", ")}` : ""}. Open isolated instead of your browser?
                  </small>{" "}
                  <button type="button" onClick={() => void openSandbox(gate.url)}>Open in sandbox</button>{" "}
                  <button type="button" onClick={() => setGate(null)}>Cancel</button>
                </>
              )}
              {gate.phase === "deny" && (
                <small>Link blocked{gate.reasons.length > 0 ? ` — evidence: ${gate.reasons.join(", ")}` : ""}. Nothing was opened.</small>
              )}
              {gate.phase === "opened" && (
                <small>
                  {gate.sessionId
                    ? `Opened in sandbox session ${gate.sessionId} — ${gate.target ?? ""}${gate.reasons && gate.reasons.length > 0 ? `. Evidence: ${gate.reasons.join(", ")}` : ""}.`
                    : "Opened in the system browser."}
                </small>
              )}
              {gate.phase === "note" && <small>{gate.text}</small>}
              {gate.phase === "error" && <small>Link check failed — {gate.text}. Nothing was opened.</small>}
            </div>
          )}
          {quoteCount > 0 && (
            <p style={{ margin: "0.2rem 0" }}>
              <button
                type="button"
                className="em-quote-toggle"
                onClick={() => setQuoteOpen((o) => !o)}
                aria-expanded={quoteOpen}
              >
                {quoteOpen ? "Hide quoted text" : `Show quoted text (${quoteCount})`}
              </button>
            </p>
          )}
          <div
            ref={bodyRef}
            className={`kiwi-rendered-body${!quoteOpen ? " em-quotes-collapsed" : ""}`}
            onClick={onBodyClick}
            // Sanitized server-side by kiwi_render_body (ammonia strict
            // allowlist: no scripts/forms/iframes; remote images stripped
            // unless the per-account opt-in is on). Never raw htmlBody.
            // Clicks are gated through kiwi_link_click before any open.
            // T-310: quote nodes are tagged with data-kiwi-quote by a
            // post-mount DOM pass (presentation only — sanitize untouched).
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
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>
            {textParts.head}
            {textParts.sig && <span className="em-sig">{`\n${textParts.sig}`}</span>}
          </pre>
          {textQuoted && (
            <>
              <p style={{ margin: "0.2rem 0" }}>
                <button
                  type="button"
                  className="em-quote-toggle"
                  onClick={() => setQuoteOpen((o) => !o)}
                  aria-expanded={quoteOpen}
                >
                  {quoteOpen ? "Hide quoted text" : "Show quoted text"}
                </button>
              </p>
              {quoteOpen && (
                <pre className="em-quote-region" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>
                  {textQuoted}
                </pre>
              )}
            </>
          )}
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

/** T-296 — relative send-time label ("in 12m"), absolute in the title attr. */
function relSendIn(secs: number): string {
  if (secs <= 0) return "due now";
  const m = Math.ceil(secs / 60);
  if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `in ${h}h ${m % 60}m` : `in ${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `in ${d}d ${h % 24}h` : `in ${d}d`;
}

/* Send state is derived from the real OutboxItem fields only. Contract gap
 * (T-296): the row carries no state enum / lastError / hold reason — a
 * "held" queue entry is only inferable as `attempts > 0 && notBefore`
 * pushed forward (retry backoff); there is no way to show WHY it failed.
 * Filed for a backend OutboxItem.state + lastError pair. */
function outboxState(o: OutboxItem, now: number): { chip: string; kind: "undo" | "scheduled" | "sending" | "retry" } {
  const undoLeft = Math.ceil(o.undoWindowUntilUnix - now);
  const sendsIn = Math.ceil(o.notBeforeUnix - now);
  if (o.cancelable && undoLeft > 0) return { chip: "Undo window", kind: "undo" };
  if (o.attempts > 0) {
    return sendsIn > 0
      ? { chip: `Retry — attempt ${o.attempts}`, kind: "retry" }
      : { chip: `Sending — attempt ${o.attempts}`, kind: "sending" };
  }
  return sendsIn > 0 ? { chip: "Scheduled", kind: "scheduled" } : { chip: "Sending now", kind: "sending" };
}

function OutboxList({
  outbox,
  onCancelSend,
  onScheduleSend,
}: {
  outbox: OutboxItem[];
  onCancelSend: (queueId: string) => void;
  onScheduleSend: (queueId: string, sendAtUnix: number) => void;
}) {
  // Ticking clock for the undo-window countdown + scheduled-send times.
  // Ticks only while the outbox is mounted; static under reduced-motion
  // (the raw timestamps stay in the title attributes).
  const [now, setNow] = useState(() => Date.now() / 1000);
  const [rescheduling, setRescheduling] = useState<string | null>(null);
  const [rescheduleAt, setRescheduleAt] = useState("");
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
        <strong>No scheduled sends</strong>
        <br />
        <small>Queued and scheduled sends will appear here.</small>
      </div>
    );
  }
  const commitReschedule = (queueId: string) => {
    const ms = new Date(rescheduleAt).getTime();
    if (Number.isNaN(ms)) return;
    onScheduleSend(queueId, Math.floor(ms / 1000));
    setRescheduling(null);
  };
  return (
    <div className="em-outbox" role="list" aria-label="Queued sends">
      {outbox.map((o) => {
        const undoLeft = Math.ceil(o.undoWindowUntilUnix - now);
        const sendsIn = Math.ceil(o.notBeforeUnix - now);
        const st = outboxState(o, now);
        const sendAtAbs = new Date(o.notBeforeUnix * 1000).toLocaleString();
        // Reschedule/Send-now only make sense while the item is still
        // queued (not-before pending or undo window open) — a row already
        // dispatching can't be re-timed.
        const queued = sendsIn > 0 || (o.cancelable && undoLeft > 0);
        return (
          <article key={o.queueId} role="listitem" className="em-card em-outbox-card">
            <div className="em-outbox-head">
              <strong>{o.subject || "(no subject)"}</strong>
              <span
                className={`em-outbox-state em-outbox-${st.kind}`}
                title={`not-before ${sendAtAbs} · undo window ends ${new Date(o.undoWindowUntilUnix * 1000).toLocaleString()}`}
              >
                {st.chip}
              </span>
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
              To {o.to.join(", ")} · sends{" "}
              <span title={sendAtAbs}>{relSendIn(sendsIn)}</span>
              {o.cancelable && undoLeft > 0 && <> · undo {undoLeft}s</>}
            </div>
            <div className="em-outbox-actions">
              <button
                type="button"
                onClick={() => onCancelSend(o.queueId)}
                disabled={!o.cancelable}
                title={o.cancelable ? (undoLeft > 0 ? `Undo send (${undoLeft}s left)` : "Undo send") : "Undo window closed — message dispatching"}
              >
                {o.cancelable && undoLeft > 0 ? `Undo send (${undoLeft}s)` : "Undo send"}
              </button>
              <button
                type="button"
                onClick={() => onScheduleSend(o.queueId, Math.floor(Date.now() / 1000))}
                disabled={!queued}
                title={queued ? "Send immediately (reschedules to now)" : "Already dispatching"}
              >
                Send now
              </button>
              {rescheduling === o.queueId ? (
                <span className="em-outbox-pick">
                  <input
                    type="datetime-local"
                    value={rescheduleAt}
                    min={new Date(Date.now() + 60_000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)}
                    onChange={(e) => setRescheduleAt(e.target.value)}
                    aria-label={`New send time for ${o.subject || "message"}`}
                    autoFocus
                  />
                  <button type="button" onClick={() => commitReschedule(o.queueId)} disabled={!rescheduleAt}>
                    Set
                  </button>
                  <button type="button" onClick={() => setRescheduling(null)}>
                    Cancel
                  </button>
                </span>
              ) : (
                <button
                  type="button"
                  disabled={!queued}
                  title={queued ? "Pick a new send time" : "Already dispatching"}
                  onClick={() => {
                    setRescheduling(o.queueId);
                    const d = new Date(Math.max(o.notBeforeUnix * 1000, Date.now() + 300_000));
                    setRescheduleAt(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                  }}
                >
                  Reschedule…
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}
