/**
 * App shell chrome (T-112): TopBar, Sidebar (folder tree + accounts),
 * AppShell layout. Surfaces KIWI-UI-013/014/015/002.
 */
import type { CSSProperties, ReactNode } from "react";
import type { AccountInfo, TrustState } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { navigate } from "../router";

const layout: CSSProperties = { display: "grid", gridTemplateRows: "auto 1fr auto", height: "100vh" };
const main: CSSProperties = { display: "grid", gridTemplateColumns: "240px 1fr", minHeight: 0 };
const sidebarStyle: CSSProperties = {
  background: "var(--kiwi-sidebar)",
  borderRight: "1px solid var(--kiwi-border)",
  padding: "0.6rem",
  overflowY: "auto",
};
const contentStyle: CSSProperties = { minWidth: 0, minHeight: 0, overflow: "auto", padding: "0.8rem" };
const topbarStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "0.6rem",
  padding: "0.5rem 0.8rem",
  background: "var(--kiwi-surface)",
  borderBottom: "1px solid var(--kiwi-border)",
};
const statusbarStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "0.6rem",
  padding: "0.3rem 0.8rem",
  background: "var(--kiwi-surface)",
  borderTop: "1px solid var(--kiwi-border)",
  fontSize: "0.8rem",
  color: "var(--kiwi-text-secondary)",
};

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
}

export function TopBar({ trust, demo, query, onQuery, theme, onTheme, onOpenPalette, onOpenShortcuts, onSubmitSearch }: TopBarProps) {
  return (
    <header style={topbarStyle}>
      <strong aria-label="KIWI home" className="kiwi-brand">
        KIWI
      </strong>
      <div role="search" style={{ flex: 1, display: "flex", gap: "0.4rem" }}>
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
          style={{ flex: 1, maxWidth: "28rem" }}
        />
      </div>
      <button type="button" onClick={onOpenPalette} aria-label="Open command palette" title="Commands (Ctrl+K)">
        ⌘ Commands
      </button>
      <button type="button" onClick={onOpenShortcuts} aria-label="Show keyboard shortcuts" title="Shortcuts (?)">
        ?
      </button>
      {demo && (
        <span className="kiwi-pill unknown" title="Backend unreachable — showing local demo data">
          ? demo data
        </span>
      )}
      <label style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
        Theme{" "}
        <select value={theme} onChange={(e) => onTheme(e.target.value)} aria-label="Color theme">
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
      <TrustChip {...trust} />
    </header>
  );
}

interface SidebarProps {
  folders: { id: string; label: string }[];
  accounts: AccountInfo[];
  activeFolder: string;
  unreadByFolder: Record<string, number>;
}

export function Sidebar({ folders, accounts, activeFolder, unreadByFolder }: SidebarProps) {
  return (
    <nav style={sidebarStyle} aria-label="Accounts and folders">
      <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }} role="tree" aria-label="Folders">
        {folders.map((f) => {
          const active = activeFolder === f.id;
          const unread = unreadByFolder[f.id] ?? 0;
          return (
            <button
              key={f.id}
              type="button"
              role="treeitem"
              className="kiwi-tree-item"
              aria-selected={active}
              aria-label={`${f.label}${unread > 0 ? `, ${unread} unread` : ""}`}
              onClick={() => navigate({ name: "mail", folder: f.id })}
            >
              {f.label}
              {unread > 0 && <span aria-hidden="true"> ({unread})</span>}
            </button>
          );
        })}
      </div>
      <h2 className="kiwi-section-label">Accounts</h2>
      <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
        {accounts.map((a) => (
          <li key={a.id} className="kiwi-account">
            <span
              aria-hidden="true"
              style={{ width: "0.6rem", height: "0.6rem", borderRadius: "50%", background: a.color }}
            />
            <span>
              {a.displayName}{" "}
              {a.muted && (
                <span className="kiwi-pill unknown" title="Muted — unread excluded from counts">
                  muted
                </span>
              )}
              <br />
              <small style={{ color: "var(--kiwi-text-secondary)" }}>
                {a.email} · {a.muted ? "muted" : `${a.unread} unread`} · trust {severityLabel(a.trust).toLowerCase()}
              </small>
            </span>
          </li>
        ))}
      </ul>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", marginTop: "0.8rem" }}>
        <button type="button" className="kiwi-nav-btn kiwi-btn-primary" onClick={() => navigate({ name: "compose" })}>
          ✎ Compose
        </button>
        <button type="button" className="kiwi-nav-btn" onClick={() => navigate({ name: "contacts" })}>
          👥 Contacts
        </button>
        <button type="button" className="kiwi-nav-btn" onClick={() => navigate({ name: "security" })}>
          🛡 Security
        </button>
        <button type="button" className="kiwi-nav-btn" onClick={() => navigate({ name: "settings" })}>
          ⚙ Settings
        </button>
      </div>
    </nav>
  );
}

export function AppShell({ sidebar, children, status }: { sidebar: ReactNode; children: ReactNode; status: ReactNode }) {
  return (
    <div style={layout}>
      <main style={main}>
        {sidebar}
        <div style={contentStyle}>{children}</div>
      </main>
      <footer style={statusbarStyle}>{status}</footer>
    </div>
  );
}
