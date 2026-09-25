/**
 * Mailbox view (T-143, T-151, T-162, T-165): live folders/messages/body via
 * kiwi.ipc/1, sync, outbox with cancel/flush, per-account trust pills.
 * Star/read/archive go through kiwi_update_message in live mode (demo stays
 * local-only and says so); attachments save through
 * kiwi_download_attachment; HTML bodies render through kiwi_render_body
 * (server-side ammonia sanitizer, remote images blocked unless the
 * per-account opt-in is on). List keys (T-153): j/k/arrows/n/p move ·
 * s star · e archive · r reply · u read/unread. Bulk selection (T-162):
 * hover checkbox, Ctrl/Cmd-click toggle, Shift-click range, header
 * select-all; the action bar runs one bulk pass per action (flags/archive
 * via kiwi_update_message, delete via kiwi_delete_messages with count
 * confirms, spam via kiwi_move_messages to the account Spam folder,
 * empty-trash from Trash folders). Demo explains itself per action. Conversations (T-165): subject-normalized
 * threads (In-Reply-To/References aren't in list views) with collapsible
 * groups, unread badges, Threads/List toggle, reader thread strip.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { FindingInfo, MessageBodyView, MessageEnvelope, MessagePatch, OutboxItem, RenderedBodyView, UnsubscribeInfo } from "../kiwi";
import { CATEGORY_TABS, severityGlyph, severityLabel } from "../kiwi";
import type { MessageCategory } from "../kiwi";
import { listen } from "@tauri-apps/api/event";
import { api, isTauri } from "../ipc";
import { loadPref, savePref } from "../prefs";
import { loadLocalBook, saveLocalBook, upsertLocal } from "../contacts";
import { navigate } from "../router";
import { SecurityPill } from "../components/security";
import { buildThreads } from "../threading";
import type { Thread } from "../threading";

const listStyle: CSSProperties = { overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.3rem" };

function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** Short timestamp for single-line rows: time today, date otherwise. */
function formatDateShort(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString([], { month: "short", day: "numeric" });
  return d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

export interface MailboxProps {
  folder: string;
  folderLabel: string;
  messages: MessageEnvelope[];
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
  // F2 category tabs (T-231): the backend classifies per message
  // (`MessageView.category`); tabs filter the loaded list with counts.
  // No `list_messages_by_category` command exists, so scoping is the
  // loaded list — labeled on the tabs.
  const [catTab, setCatTab] = useState<MessageCategory>("primary");
  const messages = useMemo(
    () => allMessages.filter((m) => (m.category ?? "primary") === catTab),
    [allMessages, catTab],
  );
  const catCounts = useMemo(() => {
    const counts: Record<MessageCategory, number> = { primary: 0, newsletters: 0, social: 0, notifications: 0, other: 0 };
    for (const m of allMessages) counts[(m.category ?? "primary") as MessageCategory] += 1;
    return counts;
  }, [allMessages]);
  const selected = messages.find((m) => m.id === selectedId) ?? messages[0];

  // Bulk selection (T-162): explicit id list + range anchor. Cleared on
  // folder change (ids are folder-scoped) and after move actions (rows gone).
  const [picked, setPicked] = useState<string[]>([]);
  const anchorRef = useRef<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const selectAllRef = useRef<HTMLInputElement | null>(null);
  // Mailspring idiom: stacked rows when the list column is under ~540px.
  const listColRef = useRef<HTMLElement | null>(null);
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const el = listColRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 0;
      setNarrow(w > 0 && w < 540);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
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

  const unreadIds = messages.filter((m) => m.unread).map((m) => m.id);
  const isTrash = folder !== "outbox" && /trash|deleted|bin/i.test(folderLabel);
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const [contactNote, setContactNote] = useState<string | null>(null);
  useEffect(() => {
    setConfirmEmpty(false);
  }, [folder]);
  useEffect(() => {
    setContactNote(null);
  }, [selectedId]);

  /** Add the sender to contacts (T-173): server first, labeled local book
    * fallback. Display name guessed from `Name <addr>` shape; editable in
    * the Contacts view. */
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
    try {
      await api.createContact(input);
      setContactNote(`Saved ${address} to contacts.`);
    } catch {
      saveLocalBook(upsertLocal(loadLocalBook(), input));
      setContactNote(`Saved ${address} locally — contacts IPC not in the backend yet.`);
    }
  };

  // Conversation threads (T-165): grouped from the visible list, newest
  // activity first. Single-message threads render as plain rows.
  const threads = useMemo(() => buildThreads(messages), [messages]);
  const [threadMode, setThreadMode] = useState(() => loadPref("kiwi.threadMode", "threads"));
  useEffect(() => savePref("kiwi.threadMode", threadMode), [threadMode]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const toggleThread = (key: string) => setExpanded((m) => ({ ...m, [key]: !m[key] }));

  /** Run a bulk pass, then clear selection + return focus to the heading when rows moved. */
  const runBulk = (ids: string[], patch: MessagePatch, label: string, clearsRows: boolean) => {
    props.onBulkPatch(ids, patch, label);
    if (clearsRows) {
      setPicked([]);
      anchorRef.current = null;
      // The action bar unmounts — move focus somewhere stable.
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

  return (
    <div className="ms-mailbox ms-view-enter">
      <section aria-label={`${folderLabel} message list`} className={`ms-list-col${narrow ? " ms-narrow" : ""}`} ref={listColRef}>
        <div className="ms-list-header">
          <h1 ref={headingRef} tabIndex={-1} style={{ fontSize: "1.1rem", margin: 0 }}>
            {folderLabel} <small style={{ color: "var(--kiwi-ms-text-secondary)" }}>({folder === "outbox" ? props.outbox.length : `${messages.length} of ${allMessages.length}`})</small>
          </h1>
          {folder !== "outbox" ? (
            <>
              <button type="button" className="ms-btn" onClick={props.onSync} disabled={props.syncing} aria-label="Sync now" title="Sync now (F5)">
                {props.syncing ? (
                  <span className="ms-spinner" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                ) : (
                  "⟳ Sync"
                )}
              </button>
              <label style={{ display: "inline-flex", alignItems: "center", gap: "0.25rem", fontSize: "0.85rem" }}>
                <input
                  ref={selectAllRef}
                  type="checkbox"
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
                All
              </label>
              <button
                type="button"
                role="switch"
                aria-checked={threadMode === "threads"}
                className="ms-switch"
                onClick={() => setThreadMode(threadMode === "threads" ? "list" : "threads")}
                title="Group messages into conversations by subject"
              >
                <span className="ms-switch-track" aria-hidden="true">
                  <span className="ms-switch-knob" />
                </span>
                Threads
              </button>
              <button
                type="button"
                className="ms-btn"
                onClick={() => runBulk(unreadIds, { seen: true }, "Marked read", false)}
                disabled={unreadIds.length === 0}
                title={unreadIds.length === 0 ? "Nothing unread" : `Mark ${unreadIds.length} unread message(s) read`}
              >
                Mark all read{unreadIds.length > 0 ? ` (${unreadIds.length})` : ""}
              </button>
              {isTrash && (
                confirmEmpty ? (
                  <>
                    <button
                      type="button"
                      onClick={() => {
                        setConfirmEmpty(false);
                        props.onEmptyTrash();
                        setPicked([]);
                        anchorRef.current = null;
                      }}
                    >
                      Confirm empty {messages.length} message(s)
                    </button>
                    <button type="button" onClick={() => setConfirmEmpty(false)}>
                      Keep
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="ms-btn"
                    onClick={() => setConfirmEmpty(true)}
                    disabled={messages.length === 0}
                    title={
                      messages.length === 0
                        ? "Trash is empty"
                        : `Permanently delete ${messages.length} message(s) in Trash`
                    }
                  >
                    Empty trash
                  </button>
                )
              )}
            </>
          ) : (
            <button type="button" className="ms-btn" onClick={props.onFlushOutbox} aria-label="Send all queued mail now">
              Send all now
            </button>
          )}
        </div>
        {folder !== "outbox" && (
          <div
            className="ms-tabs ms-cat-tabs"
            role="tablist"
            aria-label="Inbox categories (loaded messages)"
            onKeyDown={(e) => {
              const tabs = Array.from(
                (e.currentTarget as HTMLElement).querySelectorAll<HTMLElement>('[role="tab"]'),
              );
              const i = tabs.indexOf(e.target as HTMLElement);
              if (i < 0) return;
              let n: number | null = null;
              if (e.key === "ArrowRight" || e.key === "ArrowDown") n = (i + 1) % tabs.length;
              else if (e.key === "ArrowLeft" || e.key === "ArrowUp") n = (i - 1 + tabs.length) % tabs.length;
              else if (e.key === "Home") n = 0;
              else if (e.key === "End") n = tabs.length - 1;
              if (n !== null) {
                e.preventDefault();
                setCatTab(CATEGORY_TABS[n].slug);
                tabs[n]?.focus();
              }
            }}
          >
            {CATEGORY_TABS.map((t) => (
              <button
                key={t.slug}
                type="button"
                role="tab"
                aria-selected={catTab === t.slug}
                className="ms-tab"
                tabIndex={catTab === t.slug ? 0 : -1}
                title={`${catCounts[t.slug]} of the loaded messages`}
                onClick={() => setCatTab(t.slug)}
              >
                {t.label} <span className="ms-badge" aria-hidden="true">{catCounts[t.slug]}</span>
              </button>
            ))}
          </div>
        )}
        {picked.length > 0 && folder !== "outbox" && (
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
          <p role="status">
            <small>{props.syncNote}</small>
          </p>
        )}
        {folder === "outbox" ? (
          <OutboxList outbox={props.outbox} onCancelSend={props.onCancelSend} />
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
                <span className="kiwi-empty-icon" aria-hidden="true">✉</span>
                <strong>Nothing here</strong>
                <br />
                <small>
                  {allMessages.length === 0
                    ? "No messages in this folder yet."
                    : `No ${CATEGORY_TABS.find((t) => t.slug === catTab)?.label ?? catTab} messages in the loaded list.`}
                </small>
              </div>
            )}
            <div
              style={listStyle}
              className="ms-rows"
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
              {threadMode === "threads"
                ? threads.map((t) =>
                    t.messages.length === 1 ? (
                      <MessageRow
                        key={t.key}
                        m={t.messages[0]}
                        folder={folder}
                        currentId={selected?.id}
                        isPicked={picked.includes(t.messages[0].id)}
                        onTogglePick={togglePick}
                        onToggleStar={props.onToggleStar}
                        onArchive={(id) => props.onArchive(id, true)}
                        onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
                      />
                    ) : (
                      <ThreadGroup
                        key={t.key}
                        thread={t}
                        folder={folder}
                        currentId={selected?.id}
                        isExpanded={expanded[t.key] === true}
                        onToggleExpand={() => toggleThread(t.key)}
                        isPicked={(id) => picked.includes(id)}
                        allPicked={t.messages.every((m) => picked.includes(m.id))}
                        onToggleThread={() => {
                          const ids = t.messages.map((m) => m.id);
                          if (ids.every((id) => picked.includes(id))) {
                            setPicked((prev) => prev.filter((id) => !ids.includes(id)));
                          } else {
                            setPicked((prev) => Array.from(new Set([...prev, ...ids])));
                            anchorRef.current = ids[ids.length - 1];
                          }
                        }}
                        onTogglePick={togglePick}
                        onToggleStar={props.onToggleStar}
                        onArchive={(id) => props.onArchive(id, true)}
                        onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
                      />
                    ),
                  )
                : messages.map((m) => (
                    <MessageRow
                      key={m.id}
                      m={m}
                      folder={folder}
                      currentId={selected?.id}
                      isPicked={picked.includes(m.id)}
                      onTogglePick={togglePick}
                      onToggleStar={props.onToggleStar}
                      onArchive={(id) => props.onArchive(id, true)}
                      onDelete={(id) => props.onBulkDelete([id], false, "Deleted message")}
                    />
                  ))}
            </div>
          </>
        )}
      </section>
      <section
        key={selected?.id ?? "none"}
        className="kiwi-reader ms-reader ms-ready"
        aria-label="Message reader"
        tabIndex={0}
      >
        {!selected && folder !== "outbox" && <p>Select a message to read.</p>}
        {folder === "outbox" && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>Queued sends live here. Undo works while the grace window is open; “Send all now” skips remaining grace.</small>
          </p>
        )}
        {selected && folder !== "outbox" && (
          <>
            <ThreadStrip
              threads={threads}
              selectedId={selected.id}
              folder={folder}
              expanded={expanded[selectedThreadKey(threads, selected.id)] === true}
              onToggleExpand={() => toggleThread(selectedThreadKey(threads, selected.id))}
            />
            <div className="ms-reader-bar" role="toolbar" aria-label="Message actions">
              <button type="button" className="ms-btn" onClick={() => navigate({ name: "compose" })} title="Reply (r)">
                Reply
              </button>
              <button
                type="button"
                className="ms-btn"
                onClick={() => props.onToggleStar(selected.id)}
                aria-pressed={selected.starred}
                title="Star (s)"
              >
                {selected.starred ? "★ Unstar" : "☆ Star"}
              </button>
              <button type="button" className="ms-btn" onClick={() => props.onToggleRead(selected.id)} title="Toggle read (u)">
                Mark {selected.unread ? "read" : "unread"}
              </button>
              <button type="button" className="ms-btn" onClick={() => props.onArchive(selected.id, true)} title="Archive (e)">
                Archive
              </button>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
              <h2 style={{ margin: 0 }}>{selected.subject}</h2>
              <SecurityPill
                level={selected.trust}
                summary={`Account trust for ${selected.accountEmail}. Per-message session attribution is not yet exposed by the backend.`}
                onOpen={() => props.onOpenFinding(0)}
              />
            </div>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              From {selected.from} · To {selected.accountEmail} · {formatDate(selected.date)}{" "}
              <button type="button" onClick={() => void addSenderToContacts()} title="Save the sender to contacts">
                <small>Add to contacts</small>
              </button>
            </p>
            {contactNote && (
              <p role="status">
                <small>{contactNote}</small>
              </p>
            )}
            <UnsubscribeChip unsub={selected.unsub} />
            {locked ? (
              <p role="note">Message body unavailable — mailbox is locked.</p>
            ) : props.bodyLoading ? (
              <div role="status" aria-label="Loading message body">
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton" />
              </div>
            ) : props.bodyError ? (
              <div className="kiwi-banner error" role="alert">
                <small>{props.bodyError}</small>
              </div>
            ) : props.body ? (
              <>
                <AttachmentList
                  body={props.body}
                  demo={props.demo}
                  attachNote={props.attachNote}
                  attachBusy={props.attachBusy}
                  onSaveAttachment={props.onSaveAttachment}
                />
                <BodyPane
                  body={props.body}
                  rendered={props.rendered}
                  renderLoading={props.renderLoading}
                  renderError={props.renderError}
                  remoteAllowed={props.remoteAllowed}
                  demo={props.demo}
                  onAllowRemote={props.onAllowRemote}
                />
              </>
            ) : (
              <p>{selected.snippet}</p>
            )}
            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              <button type="button" className="ms-btn" disabled={findings.length === 0} onClick={() => props.onOpenFinding(0)}>
                Security details ({findings.length})
              </button>
            </div>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
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

/**
 * T-202 unsubscribe affordance (T-231): banner chip on messages carrying
 * List-Unsubscribe endpoints. Dormant (renders nothing) until the backend
 * exposes the fields. HTTPS links and mailto addresses are validated by
 * parseUnsubscribe; actions are confirm-gated and copy-based — the webview
 * never navigates to a remote URL and nothing is sent without consent.
 * One-click POST/open via shell integration is flagged as follow-up.
 */
function UnsubscribeChip({ unsub }: { unsub: UnsubscribeInfo | undefined }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  useEffect(() => {
    setOpen(false);
    setCopied(null);
  }, [unsub?.url, unsub?.mailto]);
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
  return (
    <div className="ms-unsub">
      {!open ? (
        <button
          type="button"
          className="ms-btn"
          onClick={() => setOpen(true)}
          title="This sender offers one-click unsubscribe"
        >
          Unsubscribe
        </button>
      ) : (
        <div className="ms-unsub-panel" role="group" aria-label="Unsubscribe options">
          <p style={{ margin: "0 0 0.4rem" }}>
            <small>
              {unsub.oneClick
                ? "One-click endpoint offered — until shell integration lands, copy it instead. Nothing is sent automatically."
                : "Sender endpoints below — copy to use. Nothing is sent automatically."}
            </small>
          </p>
          {unsub.url && (
            <p style={{ margin: "0 0 0.4rem" }}>
              <small>
                Link ({hostOf(unsub.url)}):{" "}
                <button type="button" className="ms-btn" onClick={() => void copy(unsub.url as string, "Link")}>
                  Copy link
                </button>
              </small>
            </p>
          )}
          {unsub.mailto && (
            <p style={{ margin: "0 0 0.4rem" }}>
              <small>
                Email (<code>{unsub.mailto}</code>):{" "}
                <button type="button" className="ms-btn" onClick={() => void copy(unsub.mailto as string, "Address")}>
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
          <button type="button" className="ms-btn" onClick={() => setOpen(false)}>
            Close
          </button>
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
    <div aria-label="Attachments">
      {body.attachments.map((a, i) => (
        <p key={`${a.filename}-${i}`}>
          <small>
            📎 {a.filename} <span style={{ color: "var(--kiwi-text-secondary)" }}>({a.contentType}, {a.size} B)</span>
          </small>
          {!demo && (
            <>
              <br />
              <label>
                <small>Save to: </small>
                <input
                  type="text"
                  value={destPaths[i] ?? a.filename}
                  onChange={(e) => setDestPaths((m) => ({ ...m, [i]: e.target.value }))}
                  placeholder={a.filename}
                  style={{ width: "16rem" }}
                  aria-label={`Save destination for ${a.filename}`}
                />
              </label>{" "}
              <button type="button" disabled={attachBusy} onClick={() => onSaveAttachment(i, destPaths[i] ?? a.filename)}>
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
  // Row-level delete confirms inline (two-step, like BulkBar) — never fires blind.
  const [confirmDel, setConfirmDel] = useState(false);
  useEffect(() => setConfirmDel(false), [m.id]);
  return (
    <article
      id={m.id}
      role="option"
      className={`ms-row${m.unread ? " is-unread" : ""}`}
      aria-selected={m.id === currentId}
      aria-label={`${m.unread ? "Unread" : "Read"} from ${m.from}: ${m.subject}. Account trust ${severityLabel(m.trust)}.${isPicked ? " Selected for bulk actions." : ""}`}
      onClick={(e) => {
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          onTogglePick(m.id, false);
        } else if (e.shiftKey) {
          e.preventDefault();
          onTogglePick(m.id, true);
        } else if ((e.target as HTMLElement).closest("button")) {
          // Quick-action buttons handle themselves.
        } else {
          navigate({ name: "mail", folder, messageId: m.id });
        }
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") navigate({ name: "mail", folder, messageId: m.id });
      }}
      tabIndex={0}
    >
      <input
        type="checkbox"
        className="ms-row-check"
        data-checked={isPicked}
        checked={isPicked}
        onClick={(e) => e.stopPropagation()}
        onChange={(e) => {
          e.stopPropagation();
          onTogglePick(m.id, e.nativeEvent instanceof MouseEvent && e.nativeEvent.shiftKey);
        }}
        aria-label={`Select message from ${m.from}: ${m.subject}`}
      />
      <button
        type="button"
        className="ms-star"
        aria-pressed={m.starred}
        aria-label={m.starred ? `Unstar message: ${m.subject}` : `Star message: ${m.subject}`}
        title={m.starred ? "Unstar (s)" : "Star (s)"}
        onClick={(e) => {
          e.stopPropagation();
          onToggleStar(m.id);
        }}
      >
        {m.starred ? "★" : "☆"}
      </button>
      <span className="ms-row-participants" title={m.from}>
        {m.from}
      </span>
      <span className="ms-row-main" title={`${m.subject} — ${m.snippet}`}>
        <span className="ms-row-subject">
          {m.unread && (
            <span className="ms-unread-dot" aria-hidden="true">
              ●
            </span>
          )}
          {m.subject}
        </span>
        <span className="ms-row-snippet">
          <span aria-hidden="true" title={`Account trust: ${severityLabel(m.trust)}`}>
            [{severityGlyph(m.trust)}]
          </span>{" "}
          {m.snippet}
        </span>
      </span>
      <span className="ms-row-date" title={m.date}>
        {formatDateShort(m.date)}
      </span>
      <span className="ms-quick-actions" role="toolbar" aria-label={`Quick actions for: ${m.subject}`}>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onArchive(m.id);
          }}
          title="Archive (e)"
        >
          📦
        </button>
        {confirmDel ? (
          <>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDel(false);
                onDelete(m.id);
              }}
              title="Confirm delete"
            >
              ✓
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDel(false);
              }}
              title="Keep message"
            >
              ✕
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setConfirmDel(true);
            }}
            title="Delete…"
          >
            🗑
          </button>
        )}
      </span>
    </article>
  );
}

function ThreadGroup({
  thread,
  folder,
  currentId,
  isExpanded,
  onToggleExpand,
  isPicked,
  allPicked,
  onToggleThread,
  onTogglePick,
  onToggleStar,
  onArchive,
  onDelete,
}: {
  thread: Thread;
  folder: string;
  currentId?: string;
  isExpanded: boolean;
  onToggleExpand: () => void;
  isPicked: (id: string) => boolean;
  allPicked: boolean;
  onToggleThread: () => void;
  onTogglePick: (id: string, range: boolean) => void;
  onToggleStar: (id: string) => void;
  onArchive: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const newest = thread.messages[thread.messages.length - 1];
  return (
    <div className="kiwi-thread" role="group" aria-label={`Conversation: ${thread.subject}, ${thread.messages.length} messages`}>
      <article
        role="option"
        className="ms-thread-head"
        aria-selected={thread.messages.some((m) => m.id === currentId)}
        aria-expanded={isExpanded}
        aria-label={`Conversation: ${thread.subject}. ${thread.messages.length} messages, ${thread.unreadCount} unread. ${isExpanded ? "Expanded." : "Collapsed."} Press Enter to ${isExpanded ? "collapse" : "expand"}.`}
        onClick={(e) => {
          if ((e.target as HTMLElement).tagName === "INPUT") return;
          onToggleExpand();
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.target as HTMLElement).tagName !== "INPUT") onToggleExpand();
        }}
        tabIndex={0}
      >
        <div style={{ display: "flex", justifyContent: "space-between", gap: "0.4rem", alignItems: "center" }}>
          <span style={{ display: "flex", alignItems: "center", gap: "0.35rem", minWidth: 0 }}>
            <input
              type="checkbox"
              className="ms-row-check"
              data-checked={allPicked}
              checked={allPicked}
              onClick={(e) => e.stopPropagation()}
              onChange={(e) => {
                e.stopPropagation();
                onToggleThread();
              }}
              aria-label={`Select all ${thread.messages.length} messages in conversation ${thread.subject}`}
            />
            <span aria-hidden="true" className="ms-disclosure" style={{ flex: "none" }}>{isExpanded ? "▾" : "▸"}</span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              <strong>{thread.subject}</strong>
            </span>
          </span>
          <span style={{ display: "flex", gap: "0.3rem", alignItems: "center", flex: "none" }}>
            {thread.unreadCount > 0 && (
              <span className="kiwi-pill warning" title={`${thread.unreadCount} unread in this conversation`}>
                ● {thread.unreadCount} unread
              </span>
            )}
            <span className="kiwi-pill unknown" title={`${thread.messages.length} messages`}>
              {thread.messages.length} msgs
            </span>
            <span title={thread.latestDate} style={{ color: "var(--kiwi-text-secondary)", fontSize: "0.8rem" }}>
              {formatDate(thread.latestDate)}
            </span>
          </span>
        </div>
        <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
          {thread.participants.slice(0, 3).join(", ")}
          {thread.participants.length > 3 && ` +${thread.participants.length - 3} more`} · {newest.snippet}
        </div>
      </article>
      {isExpanded && (
        <div className="ms-thread-kids ms-thread-expand">
          {thread.messages.map((m) => (
            <MessageRow
              key={m.id}
              m={m}
              folder={folder}
              currentId={currentId}
              isPicked={isPicked(m.id)}
              onTogglePick={onTogglePick}
              onToggleStar={onToggleStar}
              onArchive={onArchive}
              onDelete={onDelete}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function selectedThreadKey(threads: Thread[], selectedId: string): string {
  return threads.find((t) => t.messages.some((m) => m.id === selectedId))?.key ?? "";
}

function ThreadStrip({
  threads,
  selectedId,
  folder,
  expanded,
  onToggleExpand,
}: {
  threads: Thread[];
  selectedId: string;
  folder: string;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const thread = threads.find((t) => t.messages.some((m) => m.id === selectedId));
  if (!thread || thread.messages.length < 2) return null;
  return (
    <div className="kiwi-thread-strip" style={{ marginBottom: "0.6rem" }}>
      <button
        type="button"
        onClick={onToggleExpand}
        aria-expanded={expanded}
        aria-label={`${expanded ? "Collapse" : "Expand"} conversation ${thread.subject}, ${thread.messages.length} messages, ${thread.unreadCount} unread`}
      >
        {expanded ? "▾" : "▸"} Thread: {thread.subject} ({thread.messages.length}
        {thread.unreadCount > 0 && `, ${thread.unreadCount} unread`})
      </button>
      {expanded && (
        <ol style={{ listStyle: "none", margin: "0.4rem 0 0", padding: 0, display: "flex", flexDirection: "column", gap: "0.25rem" }}>
          {thread.messages.map((m) => (
            <li key={m.id}>
              <button
                type="button"
                onClick={() => navigate({ name: "mail", folder, messageId: m.id })}
                aria-current={m.id === selectedId ? "true" : undefined}
                style={{ fontWeight: m.id === selectedId ? 700 : 400, textAlign: "left", width: "100%" }}
                aria-label={`${m.id === selectedId ? "Current message" : "Open message"} from ${m.from}, ${formatDate(m.date)}${m.unread ? ", unread" : ""}`}
              >
                {m.unread && <span aria-hidden="true">● </span>}
                {m.from} · {formatDate(m.date)}
              </button>
            </li>
          ))}
        </ol>
      )}
    </div>
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
    <div className="kiwi-actionbar" role="toolbar" aria-label={`Bulk actions for ${count} selected messages`}>
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
        <span className="kiwi-empty-icon" aria-hidden="true">📤</span>
        <strong>Outbox is empty</strong>
        <br />
        <small>Queued and scheduled sends will appear here.</small>
      </div>
    );
  }
  return (
    <div style={listStyle} role="list" aria-label="Queued sends">
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
          <article key={o.queueId} role="listitem" style={{ border: "1px solid var(--kiwi-border)", borderRadius: "8px", padding: "0.5rem 0.6rem" }}>
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
