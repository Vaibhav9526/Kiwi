/**
 * App shell chrome (T-267 eM-idiom rebuild): titlebar (hamburger + centered
 * search pill + window-side cluster), toolbar row (icon+label+chevron
 * split buttons — +New orange primary), 4-pane body (folder pane with
 * Mail/Favorites smart folders + per-account sections, list, reader,
 * collapsible Agenda rail) and the bottom icon status strip.
 * Mailspring-idiom tokens/motion stay the animation vocabulary; every prop
 * and navigation target from the prior chrome is preserved.
 * All glyphs are stub stroke icons — TODO(icon) swap to components/icons (T-268).
 */
import { useEffect, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import type { Severity, SnoozePreset, TrustState } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { Icon, SEVERITY_ICON } from "./icons/index";
import { navigate } from "../router";
import { loadPref, savePref } from "../prefs";
import { usePaneWidth } from "../state/panes";
import { useTheme } from "../themes";
import {
  IconArchive,
  IconBolt,
  IconCheck,
  IconChevronDown,
  IconChevronRight,
  IconCollapseRight,
  IconCommand,
  IconContacts,
  IconDrafts,
  IconFlag,
  IconFolder,
  IconForward,
  IconHelp,
  IconInbox,
  IconJunk,
  IconLock,
  IconMail,
  IconMenu,
  IconMore,
  IconOutbox,
  IconPlus,
  IconRefresh,
  IconReply,
  IconReplyAll,
  IconSearch,
  IconSent,
  IconSettings,
  IconSnooze,
  IconStar,
  IconTasks,
  IconTrash,
  IconUnread,
  IconUnreplied,
  IconUser,
} from "./shell-icons";

export function TrustChip({ trust, locked }: TrustState) {
  if (locked) {
    return (
      <span className="kiwi-pill locked" role="status">
        <IconLock size={11} /> KIWI: Locked
      </span>
    );
  }
  return (
    <button
      type="button"
      className={`kiwi-pill ${trust}`}
      aria-label={`KIWI trust: ${severityLabel(trust)}. Activate to open the Security view.`}
      onClick={() => navigate({ name: "security" })}
      title={trust === "unknown" ? "No connection data yet" : `Trust: ${severityLabel(trust)}`}
    >
      {severityGlyph(trust)} KIWI: {severityLabel(trust)}
    </button>
  );
}

/* ---------------- shared dropdown menu ---------------- */

export interface MenuItem {
  label: string;
  hint?: string;
  disabled?: boolean;
  run: () => void;
}
/** `null` renders a separator. */
export type MenuEntry = MenuItem | { section: string } | null;

function useDismissable(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);
  return ref;
}

export function DropMenu({ entries, label, onClose }: { entries: MenuEntry[]; label: string; onClose: () => void }) {
  return (
    <ul className="em-menu ms-pop" role="menu" aria-label={label}>
      {entries.map((it, i) =>
        it === null ? (
          <li key={i} className="em-menu-sep" role="separator" />
        ) : "section" in it ? (
          <li key={i} className="em-menu-section" role="presentation">
            {it.section}
          </li>
        ) : (
          <li key={`${it.label}-${i}`} role="none">
            <button
              type="button"
              role="menuitem"
              disabled={it.disabled}
              onClick={() => {
                onClose();
                it.run();
              }}
            >
              {it.label}
              {it.hint && <span className="em-menu-hint">{it.hint}</span>}
            </button>
          </li>
        ),
      )}
    </ul>
  );
}

/* ---------------- titlebar: hamburger + centered search ---------------- */

function HamburgerMenu({
  onSync,
  onLock,
  onOpenShortcuts,
}: {
  onSync: () => void;
  onLock: () => void;
  onOpenShortcuts: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useDismissable(open, () => setOpen(false));
  const entries: MenuEntry[] = [
    { section: "File" },
    { label: "New message", hint: "Ctrl+N", run: () => navigate({ name: "compose" }) },
    { label: "Get new messages", hint: "F5", run: onSync },
    { label: "Add account…", run: () => navigate({ name: "setup" }) },
    { label: "Lock mailbox now", run: onLock },
    null,
    { section: "Go" },
    { label: "Mail", run: () => navigate({ name: "mail", folder: "all-inboxes" }) },
    { label: "Search", run: () => navigate({ name: "search" }) },
    { label: "Contacts", run: () => navigate({ name: "contacts" }) },
    { label: "Mail filters", run: () => navigate({ name: "filters" }) },
    { label: "Security Center", run: () => navigate({ name: "security" }) },
    { label: "Settings", run: () => navigate({ name: "settings" }) },
    null,
    { section: "Help" },
    { label: "Keyboard shortcuts", hint: "?", run: onOpenShortcuts },
  ];
  return (
    <div className="em-menu-wrap" ref={ref}>
      <button
        type="button"
        className="em-iconbtn"
        aria-label="Application menu"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <IconMenu size={16} />
      </button>
      {open && <DropMenu entries={entries} label="Application menu" onClose={() => setOpen(false)} />}
    </div>
  );
}

export interface TopBarProps {
  trust: TrustState;
  demo: boolean;
  query: string;
  onQuery: (q: string) => void;
  onOpenPalette: () => void;
  onOpenShortcuts: () => void;
  onSubmitSearch: () => void;
  onSync: () => void;
  onLock: () => void;
  syncing?: boolean;
  /** T-267 toolbar wiring — actions on the selected message. */
  hasSelection: boolean;
  inTrash: boolean;
  onReply: () => void;
  onReplyAll: () => void;
  onForward: () => void;
  onMarkRead: (read: boolean) => void;
  onMarkStarred: (starred: boolean) => void;
  onMarkAllRead: () => void;
  onMarkJunk: (junk: boolean) => void;
  onArchive: (archived: boolean) => void;
  onSnooze: (preset: SnoozePreset) => void;
  onUnsnooze: () => void;
  onDelete: (permanent: boolean) => void;
  onSecurityDetails: () => void;
  onEmptyTrash: () => void;
  onReloadList: () => void;
}

/** Split toolbar button — primary click + chevron dropdown (icon+label+chevron each). */
function ToolBtn({
  icon,
  label,
  onClick,
  menu,
  disabled,
  primary,
}: {
  icon: ReactNode;
  label: string;
  onClick: () => void;
  menu?: MenuEntry[];
  disabled?: boolean;
  primary?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useDismissable(open, () => setOpen(false));
  const cls = `em-tool${primary ? " em-tool-primary" : ""}`;
  if (!menu) {
    return (
      <button type="button" className={cls} onClick={onClick} disabled={disabled} title={label}>
        {icon}
        <span className="em-tool-label">{label}</span>
      </button>
    );
  }
  return (
    <div className="em-menu-wrap" ref={ref}>
      <span className={cls + (disabled ? " is-disabled" : "")}>
        <button type="button" className="em-tool-main" onClick={onClick} disabled={disabled} title={label}>
          {icon}
          <span className="em-tool-label">{label}</span>
        </button>
        <button
          type="button"
          className="em-tool-caret"
          aria-label={`${label} options`}
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          <IconChevronDown size={10} />
        </button>
      </span>
      {open && <DropMenu entries={menu} label={`${label} options`} onClose={() => setOpen(false)} />}
    </div>
  );
}

export function TopBar(props: TopBarProps) {
  const { trust, demo, query, onQuery, onSubmitSearch, onSync, syncing } = props;
  // T-275: theme self-serves from useTheme() — the select lists every
  // registered theme package (stock + sideloaded), not just the trio.
  const { theme, resolvedTheme, themes, setTheme } = useTheme();
  const sel = props.hasSelection;
  const composeActions: MenuEntry[] = [
    { label: "Reply", run: props.onReply, disabled: !sel },
    { label: "Reply all", run: props.onReplyAll, disabled: !sel },
    { label: "Forward", run: props.onForward, disabled: !sel },
  ];
  return (
    <header className="em-chrome">
      <div className="em-titlebar">
        <HamburgerMenu onSync={onSync} onLock={props.onLock} onOpenShortcuts={props.onOpenShortcuts} />
        <div className="em-search" role="search">
          <IconSearch size={13} className="em-search-icon" />
          <label className="kiwi-sr-only" htmlFor="kiwi-search">
            Search mail
          </label>
          <input
            id="kiwi-search"
            type="search"
            placeholder="Search (type ? for help)"
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                onSubmitSearch();
              }
            }}
          />
        </div>
        <div className="em-titlebar-right">
          {demo && (
            <span className="em-demo-pill" title="Backend unreachable — showing local demo data">
              demo data
            </span>
          )}
          <label className="em-theme-label">
            Theme{" "}
            <select value={theme} onChange={(e) => setTheme(e.target.value)} aria-label="Color theme">
              <option value="system">System ({resolvedTheme})</option>
              {themes.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="em-iconbtn" onClick={props.onOpenPalette} aria-label="Open command palette" title="Commands (Ctrl+K)">
            <IconCommand size={15} />
          </button>
          <button type="button" className="em-iconbtn" onClick={props.onOpenShortcuts} aria-label="Show keyboard shortcuts" title="Shortcuts (?)">
            <IconHelp size={15} />
          </button>
          <TrustChip {...trust} />
        </div>
      </div>
      <div className="em-toolbar" role="toolbar" aria-label="Mail toolbar">
        <ToolBtn
          icon={<IconPlus size={13} />}
          label="New"
          primary
          onClick={() => navigate({ name: "compose" })}
          menu={[
            { label: "New message", hint: "Ctrl+N", run: () => navigate({ name: "compose" }) },
            { label: "New contact", run: () => navigate({ name: "contacts" }) },
            { label: "New task", run: () => window.dispatchEvent(new CustomEvent("kiwi-agenda-new")) },
          ]}
        />
        <ToolBtn
          icon={<IconRefresh size={13} />}
          label="Refresh"
          onClick={onSync}
          disabled={!!syncing}
          menu={[
            { label: "Sync now", hint: "F5", run: onSync },
            { label: "Reload folder list", run: props.onReloadList },
          ]}
        />
        <ToolBtn icon={<IconReply size={13} />} label="Reply" disabled={!sel} onClick={props.onReply} menu={composeActions} />
        <ToolBtn icon={<IconReplyAll size={13} />} label="Reply All" disabled={!sel} onClick={props.onReplyAll} menu={composeActions} />
        <ToolBtn icon={<IconForward size={13} />} label="Forward" disabled={!sel} onClick={props.onForward} menu={composeActions} />
        <ToolBtn
          icon={<IconFlag size={13} />}
          label="Mark"
          disabled={!sel}
          onClick={() => props.onMarkRead(true)}
          menu={[
            { label: "Mark as read", run: () => props.onMarkRead(true), disabled: !sel },
            { label: "Mark as unread", run: () => props.onMarkRead(false), disabled: !sel },
            { label: "Star", run: () => props.onMarkStarred(true), disabled: !sel },
            { label: "Unstar", run: () => props.onMarkStarred(false), disabled: !sel },
            null,
            { label: "Mark as junk", run: () => props.onMarkJunk(true), disabled: !sel },
            { label: "Mark as not junk", run: () => props.onMarkJunk(false), disabled: !sel },
            null,
            { label: "Mark all read", run: props.onMarkAllRead },
          ]}
        />
        <ToolBtn
          icon={<IconArchive size={13} />}
          label="Archive"
          disabled={!sel}
          onClick={() => props.onArchive(true)}
          menu={[
            { label: "Archive", run: () => props.onArchive(true), disabled: !sel },
            { label: "Move to Inbox", run: () => props.onArchive(false), disabled: !sel },
          ]}
        />
        <ToolBtn
          icon={<IconSnooze size={13} />}
          label="Snooze"
          disabled={!sel}
          onClick={() => props.onSnooze("tomorrow")}
          menu={[
            { label: "Later today", run: () => props.onSnooze("later_today"), disabled: !sel },
            { label: "Tomorrow", run: () => props.onSnooze("tomorrow"), disabled: !sel },
            { label: "Next week", run: () => props.onSnooze("next_week"), disabled: !sel },
            null,
            { label: "Unsnooze", run: props.onUnsnooze, disabled: !sel },
          ]}
        />
        <ToolBtn
          icon={<IconBolt size={13} />}
          label="Quick Actions"
          onClick={() => undefined}
          menu={[
            { label: "Mark all read", run: props.onMarkAllRead },
            { label: "Security details", run: props.onSecurityDetails, disabled: !sel },
            props.inTrash ? { label: "Empty trash", run: props.onEmptyTrash } : null,
            null,
            { label: "Lock mailbox now", run: props.onLock },
          ]}
        />
        <ToolBtn
          icon={<IconTrash size={13} />}
          label="Delete"
          disabled={!sel}
          onClick={() => props.onDelete(props.inTrash)}
          menu={[
            { label: "Move to Trash", run: () => props.onDelete(false), disabled: !sel },
            { label: "Delete permanently", run: () => props.onDelete(true), disabled: !sel },
          ]}
        />
      </div>
    </header>
  );
}

/* ---------------- folder pane ---------------- */

export interface FolderSection {
  id: string;
  email: string;
  displayName: string;
  color: string;
  trust: Severity;
  muted: boolean;
  unread: number;
  items: { id: string; label: string; unread: number }[];
}

const SMART_ICONS: Record<string, (p: { size?: number }) => ReactNode> = {
  "all-inboxes": (p) => <IconInbox {...p} />,
  outbox: (p) => <IconOutbox {...p} />,
  sent: (p) => <IconSent {...p} />,
  trash: (p) => <IconTrash {...p} />,
  drafts: (p) => <IconDrafts {...p} />,
  junk: (p) => <IconJunk {...p} />,
  unread: (p) => <IconUnread {...p} />,
  flagged: (p) => <IconFlag {...p} />,
  unreplied: (p) => <IconUnreplied {...p} />,
  snoozed: (p) => <IconSnooze {...p} />,
};

/** Folder-name → outline icon (live folders arrive as free names). */
function folderIcon(label: string): ReactNode {
  if (/inbox/i.test(label)) return <IconInbox size={13} />;
  if (/sent/i.test(label)) return <IconSent size={13} />;
  if (/trash|deleted|bin/i.test(label)) return <IconTrash size={13} />;
  if (/draft/i.test(label)) return <IconDrafts size={13} />;
  if (/junk|spam/i.test(label)) return <IconJunk size={13} />;
  if (/archive/i.test(label)) return <IconArchive size={13} />;
  if (/outbox/i.test(label)) return <IconOutbox size={13} />;
  return <IconFolder size={13} />;
}

function FolderRow({
  id,
  label,
  count,
  icon,
  active,
  indent,
}: {
  id: string;
  label: string;
  count: number;
  icon: ReactNode;
  active: boolean;
  indent?: boolean;
}) {
  return (
    <button
      type="button"
      role="treeitem"
      className="em-tree-item"
      aria-selected={active}
      aria-label={`${label}${count > 0 ? `, ${count} unread` : ""}`}
      onClick={() => navigate({ name: "mail", folder: id })}
    >
      {indent && <span className="em-tree-indent" aria-hidden="true" />}
      <span className="em-tree-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="em-tree-label">{label}</span>
      {count > 0 && (
        <span className="em-tree-count" aria-hidden="true">
          {count}
        </span>
      )}
    </button>
  );
}

export function FolderPane({
  smartFolders,
  smartUnread,
  accountSections,
  activeFolder,
  outboxCount,
  foldersError,
  demo,
}: {
  smartFolders: { id: string; label: string }[];
  smartUnread: Record<string, number>;
  accountSections: FolderSection[];
  activeFolder: string;
  outboxCount: number;
  foldersError?: string | null;
  demo?: boolean;
}) {
  const [favOpen, setFavOpen] = useState(true);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  return (
    <nav className="em-folders" aria-label="Accounts and folders">
      <h1 className="em-pane-title">Mail</h1>
      <button type="button" className="em-group-head" aria-expanded={favOpen} onClick={() => setFavOpen((o) => !o)}>
        <span className={`em-disclosure${favOpen ? " is-open" : ""}`} aria-hidden="true">
          <IconChevronRight size={11} />
        </span>
        <IconStar size={13} />
        Favorites
      </button>
      {favOpen && (
        <div role="tree" aria-label="Favorites" className="em-group">
          {smartFolders.map((f) => (
            <FolderRow
              key={f.id}
              id={f.id}
              label={f.label}
              icon={(SMART_ICONS[f.id] ?? (() => <IconFolder size={13} />))({ size: 13 })}
              count={f.id === "outbox" ? outboxCount : (smartUnread[f.id] ?? 0)}
              active={activeFolder === f.id}
              indent
            />
          ))}
        </div>
      )}
      {foldersError && (
        <p className="em-folders-error" role="alert">
          <Icon name="alert-triangle" size={11} /> <small>{foldersError}</small>
        </p>
      )}
      {accountSections.length === 0 && !demo && !foldersError && (
        <div className="em-folders-empty">
          <small>No accounts yet.</small>
          <button type="button" className="em-security-link" onClick={() => navigate({ name: "setup" })}>
            Add account →
          </button>
        </div>
      )}
      <div role="tree" aria-label="Accounts" className="em-accounts">
        {accountSections.map((s) => {
          const expanded = open[s.id] ?? true;
          return (
            <div key={s.id} className="em-account-group">
              <button
                type="button"
                className="em-group-head em-account-head"
                aria-expanded={expanded}
                onClick={() => setOpen((m) => ({ ...m, [s.id]: !expanded }))}
                title={s.muted ? `${s.email} (muted — unread excluded from counts)` : s.email}
              >
                <span className={`em-disclosure${expanded ? " is-open" : ""}`} aria-hidden="true">
                  <IconChevronRight size={11} />
                </span>
                <span className="em-avatar" aria-hidden="true" style={{ background: s.color }}>
                  {(s.displayName || s.email || "?").slice(0, 1).toUpperCase()}
                </span>
                <span className="em-tree-label">{s.email}</span>
                {s.unread > 0 && (
                  <span className="em-tree-count" aria-hidden="true">
                    {s.unread}
                  </span>
                )}
              </button>
              {expanded &&
                s.items.map((f) => (
                  <FolderRow
                    key={f.id}
                    id={f.id}
                    label={f.label}
                    icon={folderIcon(f.label)}
                    count={f.unread}
                    active={activeFolder === f.id}
                    indent
                  />
                ))}
            </div>
          );
        })}
      </div>
    </nav>
  );
}

/* ---------------- agenda rail (collapsible right rail, local GTD) ---------------- */

interface AgendaTask {
  id: string;
  title: string;
  done: boolean;
  flag: boolean;
  due: "none" | "today" | "tomorrow";
  time?: string;
}

const AGENDA_SEED: AgendaTask[] = [
  { id: "seed-1", title: "Pair authenticator device", done: false, flag: true, due: "none" },
  { id: "seed-2", title: "Review security report", done: false, flag: false, due: "today", time: "5:00 PM" },
  { id: "seed-3", title: "Try the agenda rail", done: false, flag: false, due: "tomorrow" },
];

const DUE_GROUPS: { key: AgendaTask["due"]; label: string }[] = [
  { key: "none", label: "No Date" },
  { key: "today", label: "Today" },
  { key: "tomorrow", label: "Tomorrow" },
];

/**
 * T-283 rail security summary — REAL data only. Every optional row renders
 * only when a value with a real source is supplied; absent source = no row
 * (honest absence, never mocked). `demo` tags fixture-derived numbers.
 */
export interface AgendaSecurity {
  trust: TrustState;
  lockReason?: string | null;
  /** Open findings count (kiwi_security_findings; fixture count in demo). */
  findings?: number | null;
  /** Unread across inboxes — real `unseen` sum (live) / demo set. */
  unread?: number | null;
  /** Live has no store-wide flagged/unreplied aggregate — pass null. */
  flagged?: number | null;
  unreplied?: number | null;
  /** Active paired devices (kiwi_list_devices); null in demo/none loaded. */
  activeDevices?: number | null;
  demo?: boolean;
}

function SecuritySummaryCard({ security }: { security: AgendaSecurity }) {
  const { trust } = security;
  const sev: Severity = trust.locked ? "danger" : trust.trust;
  const rows: { icon: Parameters<typeof Icon>[0]["name"]; label: string; value: string | number }[] = [];
  if (security.findings != null) rows.push({ icon: "alert-triangle", label: "Open findings", value: security.findings });
  if (security.unread != null) rows.push({ icon: "unreplied", label: "Unread", value: security.unread });
  if (security.flagged != null) rows.push({ icon: "flag", label: "Flagged", value: security.flagged });
  if (security.unreplied != null) rows.push({ icon: "mail-open", label: "Unreplied", value: security.unreplied });
  if (security.activeDevices != null)
    rows.push({ icon: "device", label: "Active devices", value: security.activeDevices });
  return (
    <section className="em-security-card" aria-label="Security summary">
      <div className="em-security-head">
        <Icon name={SEVERITY_ICON[sev]} size={13} />
        <strong>{trust.locked ? "Locked" : severityLabel(sev)}</strong>
        {trust.score !== null && <small className="em-security-score">{trust.score}/100</small>}
        {security.demo && (
          <small className="em-security-demo" title="Fixture data — no backend">
            demo
          </small>
        )}
      </div>
      {trust.locked && security.lockReason && <p className="em-security-reason">{security.lockReason}</p>}
      {rows.length > 0 && (
        <ul className="em-security-rows">
          {rows.map((r) => (
            <li key={r.label}>
              <Icon name={r.icon} size={11} />
              <span>{r.label}</span>
              <strong>{r.value}</strong>
            </li>
          ))}
        </ul>
      )}
      {/* Gap (honest absence): pending sandbox-open sessions have no list
          IPC yet — the row appears once a real source exists. */}
      <button type="button" className="em-security-link" onClick={() => navigate({ name: "security" })}>
        Security Center →
      </button>
    </section>
  );
}

export function AgendaRail({ security }: { security?: AgendaSecurity }) {
  const [collapsed, setCollapsed] = useState(() => loadPref<boolean>("kiwi.rail", false) === true);
  const [tasks, setTasks] = useState<AgendaTask[]>(() => {
    const v = loadPref<AgendaTask[]>("kiwi.agenda", AGENDA_SEED);
    return Array.isArray(v) ? v : AGENDA_SEED;
  });
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState("");
  const [groupOpen, setGroupOpen] = useState<Record<string, boolean>>({});
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => savePref("kiwi.rail", collapsed), [collapsed]);
  useEffect(() => savePref("kiwi.agenda", tasks), [tasks]);
  useEffect(() => {
    const onNew = () => {
      setCollapsed(false);
      setAdding(true);
      window.setTimeout(() => inputRef.current?.focus(), 0);
    };
    const onToggle = () => setCollapsed((c) => !c);
    window.addEventListener("kiwi-agenda-new", onNew);
    window.addEventListener("kiwi-rail-toggle", onToggle);
    return () => {
      window.removeEventListener("kiwi-agenda-new", onNew);
      window.removeEventListener("kiwi-rail-toggle", onToggle);
    };
  }, []);
  useEffect(() => {
    if (adding) inputRef.current?.focus();
  }, [adding]);

  const addTask = () => {
    const title = draft.trim();
    if (title) {
      setTasks((t) => [{ id: `t-${Date.now().toString(36)}`, title, done: false, flag: false, due: "none" }, ...t]);
    }
    setDraft("");
    setAdding(false);
  };

  const patchTask = (id: string, patch: Partial<AgendaTask>) =>
    setTasks((list) => list.map((t) => (t.id === id ? { ...t, ...patch } : t)));

  if (collapsed) {
    return (
      <aside className="em-rail em-rail-collapsed" aria-label="Agenda (collapsed)">
        <button
          type="button"
          className="em-iconbtn"
          onClick={() => setCollapsed(false)}
          aria-expanded={false}
          title="Expand agenda rail"
        >
          <IconCollapseRight size={14} className="em-flip" />
        </button>
      </aside>
    );
  }

  return (
    <aside className="em-rail" aria-label="Agenda">
      <div className="em-rail-head">
        <h2 className="em-pane-title">Agenda</h2>
        <button
          type="button"
          className="em-iconbtn"
          onClick={() => setCollapsed(true)}
          aria-expanded={true}
          title="Collapse agenda rail"
        >
          <IconCollapseRight size={14} />
        </button>
      </div>
      {adding ? (
        <div className="em-agenda-add">
          <input
            ref={inputRef}
            type="text"
            value={draft}
            placeholder="Task title"
            aria-label="New task title"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") addTask();
              else if (e.key === "Escape") {
                setDraft("");
                setAdding(false);
              }
            }}
          />
          <button type="button" className="em-iconbtn" onClick={addTask} aria-label="Add task">
            <IconPlus size={12} />
          </button>
        </div>
      ) : (
        <button type="button" className="em-add-task" onClick={() => setAdding(true)}>
          Add new task
        </button>
      )}
      {security && <SecuritySummaryCard security={security} />}
      {DUE_GROUPS.map((g) => {
        const items = tasks.filter((t) => t.due === g.key);
        const expanded = groupOpen[g.key] ?? true;
        return (
          <section key={g.key} className="em-agenda-group">
            <button
              type="button"
              className="em-group-head"
              aria-expanded={expanded}
              onClick={() => setGroupOpen((m) => ({ ...m, [g.key]: !expanded }))}
            >
              <span className={`em-disclosure${expanded ? " is-open" : ""}`} aria-hidden="true">
                <IconChevronRight size={11} />
              </span>
              {g.label}
            </button>
            {expanded && (
              <ul className="em-agenda-list">
                {items.length === 0 && (
                  <li className="em-agenda-empty">
                    <small>No tasks</small>
                  </li>
                )}
                {items.map((t) => (
                  <li key={t.id} className="em-agenda-item">
                    <button
                      type="button"
                      className={`em-check${t.done ? " is-done" : ""}`}
                      role="checkbox"
                      aria-checked={t.done}
                      aria-label={`Mark "${t.title}" ${t.done ? "not done" : "done"}`}
                      onClick={() => patchTask(t.id, { done: !t.done })}
                    >
                      {t.done && <IconCheck size={10} />}
                    </button>
                    {g.key !== "none" && (
                      <span className="em-tree-icon" aria-hidden="true">
                        <IconTasks size={12} />
                      </span>
                    )}
                    <span className={`em-agenda-title${t.done ? " is-done" : ""}`}>
                      {t.title}
                      {t.time && <small className="em-agenda-time"> ({t.time})</small>}
                    </span>
                    <button
                      type="button"
                      className={`em-iconbtn em-flag${t.flag ? " is-flagged" : ""}`}
                      aria-pressed={t.flag}
                      aria-label={`${t.flag ? "Unflag" : "Flag"} "${t.title}"`}
                      onClick={() => patchTask(t.id, { flag: !t.flag })}
                    >
                      <IconFlag size={11} />
                    </button>
                    <button
                      type="button"
                      className="em-iconbtn em-agenda-del"
                      aria-label={`Remove "${t.title}"`}
                      onClick={() => setTasks((list) => list.filter((x) => x.id !== t.id))}
                    >
                      <IconTrash size={11} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </aside>
  );
}

/* ---------------- status strip ---------------- */

export function StatusStrip({
  children,
  pendingApprovals,
}: {
  children: ReactNode;
  pendingApprovals: number;
}) {
  const [open, setOpen] = useState(false);
  const ref = useDismissable(open, () => setOpen(false));
  return (
    <footer className="em-statusbar">
      <div className="em-status-icons" role="toolbar" aria-label="Modules">
        <button
          type="button"
          className="em-iconbtn is-active"
          aria-label="Mail"
          aria-current="page"
          onClick={() => navigate({ name: "mail", folder: "all-inboxes" })}
        >
          <IconMail size={15} />
        </button>
        <button type="button" className="em-iconbtn" aria-label="Contacts" onClick={() => navigate({ name: "contacts" })}>
          <IconContacts size={15} />
        </button>
        <div className="em-menu-wrap" ref={ref}>
          <button
            type="button"
            className="em-iconbtn"
            aria-label="More modules"
            aria-haspopup="menu"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
          >
            <IconMore size={15} />
          </button>
          {open && (
            <DropMenu
              label="More modules"
              onClose={() => setOpen(false)}
              entries={[
                { label: "Search", run: () => navigate({ name: "search" }) },
                {
                  label: `Security Center${pendingApprovals > 0 ? ` (${pendingApprovals} pending)` : ""}`,
                  run: () => navigate({ name: "security" }),
                },
                { label: "Mail filters", run: () => navigate({ name: "filters" }) },
                { label: "Settings", run: () => navigate({ name: "settings" }) },
                null,
                { label: "Add account…", run: () => navigate({ name: "setup" }) },
              ]}
            />
          )}
        </div>
      </div>
      <div className="em-status-text">{children}</div>
      <div className="em-status-icons em-status-right" role="toolbar" aria-label="Panels">
        <button type="button" className="em-iconbtn" aria-label="Contacts" onClick={() => navigate({ name: "contacts" })}>
          <IconUser size={14} />
        </button>
        <button
          type="button"
          className="em-iconbtn is-active"
          aria-label="Agenda rail"
          onClick={() => window.dispatchEvent(new CustomEvent("kiwi-rail-toggle"))}
          title="Toggle agenda rail"
        >
          <IconTasks size={14} />
        </button>
        <button
          type="button"
          className="em-iconbtn"
          aria-label="Mail"
          onClick={() => navigate({ name: "mail", folder: "all-inboxes" })}
        >
          <IconMail size={14} />
        </button>
        <button type="button" className="em-iconbtn" aria-label="Settings" onClick={() => navigate({ name: "settings" })}>
          <IconSettings size={14} />
        </button>
      </div>
    </footer>
  );
}

/* ---------------- shell ---------------- */

/* ---------------- pane splitter (T-293: pointer + keyboard resize) ---------------- */

export function PaneSplitter({
  label,
  value,
  min,
  max,
  invert,
  onResize,
  onReset,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  /** Rail splitter grows leftward (drag left = wider). */
  invert?: boolean;
  onResize: (px: number) => void;
  onReset: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const start = useRef<{ x: number; w: number } | null>(null);
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      className={`em-splitter${dragging ? " is-drag" : ""}`}
      title={`${label} — drag to resize, ←→ keys (10px, Shift 25px), double-click resets`}
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture(e.pointerId);
        start.current = { x: e.clientX, w: value };
        setDragging(true);
      }}
      onPointerMove={(e) => {
        if (!start.current) return;
        onResize(start.current.w + (invert ? -1 : 1) * (e.clientX - start.current.x));
      }}
      onPointerUp={(e) => {
        if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
        start.current = null;
        setDragging(false);
      }}
      onPointerCancel={() => {
        start.current = null;
        setDragging(false);
      }}
      onDoubleClick={onReset}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 25 : 10;
        if (e.key === "ArrowLeft") {
          e.preventDefault();
          onResize(value + (invert ? step : -step));
        } else if (e.key === "ArrowRight") {
          e.preventDefault();
          onResize(value + (invert ? -step : step));
        } else if (e.key === "Home") {
          e.preventDefault();
          onResize(min);
        } else if (e.key === "End") {
          e.preventDefault();
          onResize(max);
        } else if (e.key === "Enter") {
          e.preventDefault();
          onReset();
        }
      }}
    />
  );
}

export function AppShell({
  sidebar,
  children,
  rail,
  status,
}: {
  sidebar: ReactNode;
  children: ReactNode;
  rail: ReactNode;
  status: ReactNode;
}) {
  const folders = usePaneWidth("kiwi.pane.folders", 216, 180, 400);
  const railW = usePaneWidth("kiwi.pane.rail", 232, 180, 480);
  return (
    <>
      <div
        className="em-main"
        style={
          {
            "--kiwi-pane-folders": `${folders.px}px`,
            "--kiwi-pane-rail": `${railW.px}px`,
          } as CSSProperties
        }
      >
        {sidebar}
        <PaneSplitter
          label="Folders pane width"
          value={folders.px}
          min={180}
          max={400}
          onResize={folders.set}
          onReset={folders.reset}
        />
        <div className="em-center">{children}</div>
        {rail && (
          <div className="em-rail-wrap">
            <PaneSplitter
              label="Agenda rail width"
              value={railW.px}
              min={180}
              max={480}
              invert
              onResize={railW.set}
              onReset={railW.reset}
            />
            {rail}
          </div>
        )}
      </div>
      {status}
    </>
  );
}
