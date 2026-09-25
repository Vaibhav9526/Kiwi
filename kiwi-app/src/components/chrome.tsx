/**
 * App shell chrome (T-112 → T-191 Mailspring idiom): desktop MenuBar,
 * unified TopBar toolbar, Sidebar (folder tree + accounts + unread badges),
 * AppShell layout. Surfaces KIWI-UI-013/014/015/002.
 * Reskin/layout only — every prop and navigation target is preserved.
 */
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { AccountInfo, TrustState } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { navigate } from "../router";

export function TrustChip({ trust, locked }: TrustState) {
  if (locked) {
    return (
      <span className="kiwi-pill locked" role="status">
        🔒 KIWI: Locked
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

interface MenuEntry {
  label: string;
  hint?: string;
  run: () => void;
}

/** Desktop menu bar — every item reuses an existing route/action. */
function MenuBar({
  demo,
  onSync,
  onLock,
  onOpenShortcuts,
}: {
  demo: boolean;
  onSync: () => void;
  onLock: () => void;
  onOpenShortcuts: () => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const barRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (barRef.current && !barRef.current.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(null);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open ]);

  const menus: { name: string; items: MenuEntry[] }[] = [
    {
      name: "File",
      items: [
        { label: "New message", hint: "Ctrl+N", run: () => navigate({ name: "compose" }) },
        { label: "Get new messages", hint: "F5", run: onSync },
        { label: "Add account…", run: () => navigate({ name: "setup" }) },
        { label: "Lock mailbox now", run: onLock },
      ],
    },
    {
      name: "Go",
      items: [
        { label: "Mail", run: () => navigate({ name: "mail", folder: "all-inboxes" }) },
        { label: "Search", run: () => navigate({ name: "search" }) },
        { label: "Contacts", run: () => navigate({ name: "contacts" }) },
        { label: "Mail filters", run: () => navigate({ name: "filters" }) },
        { label: "Security Center", run: () => navigate({ name: "security" }) },
        { label: "Settings", run: () => navigate({ name: "settings" }) },
      ],
    },
    {
      name: "Help",
      items: [{ label: "Keyboard shortcuts", hint: "?", run: onOpenShortcuts }],
    },
  ];
  void demo;

  return (
    <div className="ms-menubar" role="menubar" aria-label="Application menus" ref={barRef}>
      {menus.map((m) => (
        <div className="ms-menu-wrap" key={m.name}>
          <button
            type="button"
            className="ms-menu-button"
            role="menuitem"
            aria-haspopup="menu"
            aria-expanded={open === m.name}
            onClick={() => setOpen((o) => (o === m.name ? null : m.name))}
            onMouseEnter={() => {
              if (open !== null) setOpen(m.name);
            }}
          >
            {m.name}
          </button>
          {open === m.name && (
            <ul className="ms-menu-list ms-pop" role="menu" aria-label={m.name}>
              {m.items.map((it) => (
                <li key={it.label} role="none">
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setOpen(null);
                      it.run();
                    }}
                  >
                    {it.label}
                    {it.hint && <span className="ms-menu-hint">{it.hint}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

interface TopBarProps {
  trust: TrustState;
  demo: boolean;
  query: string;
  onQuery: (q: string) => void;
  theme: string;
  onTheme: (t: string) => void;
  onOpenPalette: () => void;
  onOpenShortcuts: () => void;
  onSubmitSearch: () => void;
  onSync: () => void;
  onLock: () => void;
  syncing?: boolean;
}

export function TopBar({
  trust,
  demo,
  query,
  onQuery,
  theme,
  onTheme,
  onOpenPalette,
  onOpenShortcuts,
  onSubmitSearch,
  onSync,
  onLock,
  syncing,
}: TopBarProps) {
  return (
    <header className="ms-chrome">
      <MenuBar demo={demo} onSync={onSync} onLock={onLock} onOpenShortcuts={onOpenShortcuts} />
      <div className="ms-toolbar" role="toolbar" aria-label="Mail toolbar">
        <button type="button" className="ms-brand" aria-label="KIWI home" onClick={() => navigate({ name: "mail", folder: "all-inboxes" })}>
          KIWI
        </button>
        <button type="button" className="ms-btn" onClick={onSync} disabled={!!syncing} title="Get new messages (F5)">
          {syncing ? (
            <span className="ms-spinner" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
          ) : (
            "⇅ Get"
          )}
        </button>
        <button type="button" className="ms-btn ms-btn-primary" onClick={() => navigate({ name: "compose" })} title="Write a new message (Ctrl+N)">
          ✎ Write
        </button>
        <div role="search">
          <label className="kiwi-sr-only" htmlFor="kiwi-search">
            Search mail
          </label>
          <input
            id="kiwi-search"
            type="search"
            placeholder="Search mail (/) — Enter for results"
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
        <button type="button" className="ms-btn" onClick={onOpenPalette} aria-label="Open command palette" title="Commands (Ctrl+K)">
          ⌘
        </button>
        <button type="button" className="ms-btn" onClick={onOpenShortcuts} aria-label="Show keyboard shortcuts" title="Shortcuts (?)">
          ?
        </button>
        {demo && (
          <span className="ms-demo-pill" title="Backend unreachable — showing local demo data">
            demo data
          </span>
        )}
        <label style={{ fontSize: "0.8rem", color: "var(--kiwi-ms-text-secondary)" }}>
          Theme{" "}
          <select value={theme} onChange={(e) => onTheme(e.target.value)} aria-label="Color theme">
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
        <TrustChip {...trust} />
      </div>
    </header>
  );
}

interface SidebarProps {
  folders: { id: string; label: string }[];
  accounts: AccountInfo[];
  activeFolder: string;
  unreadByFolder: Record<string, number>;
}

/** Inbox-class folders get the filled alt badge; everything else is outline. */
function isAltBadge(id: string, label: string): boolean {
  return /inbox|unread|starred|important/i.test(`${id} ${label}`);
}

export function Sidebar({ folders, accounts, activeFolder, unreadByFolder }: SidebarProps) {
  const [accountsOpen, setAccountsOpen] = useState(true);
  return (
    <nav className="ms-sidebar" aria-label="Accounts and folders">
      <div className="ms-section-label" id="ms-mailboxes-head">
        Mailboxes
      </div>
      <div role="tree" aria-labelledby="ms-mailboxes-head">
        {folders.map((f) => {
          const active = activeFolder === f.id;
          const unread = unreadByFolder[f.id] ?? 0;
          return (
            <button
              key={f.id}
              type="button"
              role="treeitem"
              className="ms-tree-item"
              aria-selected={active}
              aria-label={`${f.label}${unread > 0 ? `, ${unread} unread` : ""}`}
              onClick={() => navigate({ name: "mail", folder: f.id })}
            >
              <span className="ms-tree-label">{f.label}</span>
              {unread > 0 && (
                <span className={`ms-badge${isAltBadge(f.id, f.label) ? " ms-badge-alt" : ""}`} aria-hidden="true">
                  {unread}
                </span>
              )}
            </button>
          );
        })}
      </div>
      <button
        type="button"
        className="ms-section-head"
        aria-expanded={accountsOpen}
        aria-controls="ms-accounts-list"
        onClick={() => setAccountsOpen((o) => !o)}
      >
        <span className="ms-disclosure" aria-hidden="true">
          {accountsOpen ? "▾" : "▸"}
        </span>
        Accounts
      </button>
      {accountsOpen && (
        <ul id="ms-accounts-list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {accounts.map((a) => (
            <li key={a.id} className="ms-account">
              <span className="ms-account-bar" aria-hidden="true" style={{ background: a.color }} />
              <span className="ms-account-meta">
                {a.displayName}{" "}
                {a.muted && (
                  <span className="kiwi-pill unknown" title="Muted — unread excluded from counts">
                    muted
                  </span>
                )}
                <br />
                <small>
                  {a.email} · {a.muted ? "muted" : `${a.unread} unread`} · trust {severityLabel(a.trust).toLowerCase()}
                </small>
              </span>
            </li>
          ))}
        </ul>
      )}
      <div className="ms-nav">
        <button type="button" className="ms-btn ms-btn-primary ms-nav-btn" onClick={() => navigate({ name: "compose" })}>
          ✎ Compose
        </button>
        <button type="button" className="ms-btn ms-nav-btn" onClick={() => navigate({ name: "contacts" })}>
          👥 Contacts
        </button>
        <button type="button" className="ms-btn ms-nav-btn" onClick={() => navigate({ name: "filters" })}>
          🔀 Filters
        </button>
        <button type="button" className="ms-btn ms-nav-btn" onClick={() => navigate({ name: "security" })}>
          🛡 Security
        </button>
        <button type="button" className="ms-btn ms-nav-btn" onClick={() => navigate({ name: "settings" })}>
          ⚙ Settings
        </button>
      </div>
    </nav>
  );
}

export function AppShell({ sidebar, children, status }: { sidebar: ReactNode; children: ReactNode; status: ReactNode }) {
  return (
    <>
      <div className="ms-main">
        {sidebar}
        <div className="ms-content">{children}</div>
      </div>
      <footer className="ms-statusbar">{status}</footer>
    </>
  );
}
