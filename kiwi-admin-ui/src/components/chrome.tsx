/**
 * Admin shell chrome (T-134): nav layout, actor/role switcher, backend mode
 * badge, shared loading/error/empty states, confirm dialog. S-11 rules:
 * destructive actions confirm naming the target; RBAC-denied controls render
 * disabled with the required permission named (mock mode pre-checks, live
 * mode surfaces the server's 403).
 */
import type { CSSProperties, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";
import type { ActorRole } from "../api";
import { ApiError } from "../api";
import { navigate, type RouteName } from "../router";

const layout: CSSProperties = { display: "grid", gridTemplateRows: "auto 1fr", height: "100vh" };
const main: CSSProperties = { display: "grid", gridTemplateColumns: "220px 1fr", minHeight: 0 };
const sidebarStyle: CSSProperties = {
  background: "var(--kiwi-sidebar)", borderRight: "1px solid var(--kiwi-border)",
  padding: "0.6rem", overflowY: "auto",
};
const contentStyle: CSSProperties = { minWidth: 0, overflowY: "auto", padding: "0.9rem", maxWidth: "60rem" };
const topbarStyle: CSSProperties = {
  display: "flex", alignItems: "center", gap: "0.6rem", padding: "0.5rem 0.8rem",
  background: "var(--kiwi-surface)", borderBottom: "1px solid var(--kiwi-border)", flexWrap: "wrap",
};

const NAV: { name: RouteName; label: string }[] = [
  { name: "orgs", label: "Organizations" },
  { name: "users", label: "Users & roles" },
  { name: "policies", label: "Policies" },
  { name: "mailflow", label: "Mail flow" },
  { name: "audit", label: "Audit log" },
];

export function TopBar({
  mode, baseUrl, role, onRole, onBaseUrl, orgId, onOrgId,
}: {
  mode: "live" | "demo";
  baseUrl: string;
  role: ActorRole;
  onRole: (r: ActorRole) => void;
  onBaseUrl: (u: string) => void;
  orgId: string;
  onOrgId: (id: string) => void;
}) {
  return (
    <header style={topbarStyle}>
      <strong style={{ color: "var(--kiwi-brand-ink)" }}>KIWI Admin</strong>
      <span className={`kiwi-pill ${mode === "live" ? "secure" : "unknown"}`} title={mode === "live" ? `Connected to ${baseUrl}` : "Service unreachable — local demo data"}>
        {mode === "live" ? "● live" : "? demo"}
      </span>
      <label style={{ fontSize: "0.8rem" }}>
        Service{" "}
        <input type="text" value={baseUrl} onChange={(e) => onBaseUrl(e.target.value)} style={{ width: "14rem" }} aria-label="Admin service base URL" />
      </label>
      <label style={{ fontSize: "0.8rem" }}>
        Role{" "}
        <select value={role} onChange={(e) => onRole(e.target.value as ActorRole)} aria-label="Acting role (demo enforcement / live header)">
          <option value="org_admin">org_admin</option>
          <option value="security_admin">security_admin</option>
          <option value="viewer">viewer</option>
        </select>
      </label>
      <label style={{ fontSize: "0.8rem" }}>
        Org{" "}
        <input type="text" value={orgId} onChange={(e) => onOrgId(e.target.value)} placeholder="org id" style={{ width: "12rem" }} aria-label="Current organization id" />
      </label>
    </header>
  );
}

export function Shell({ route, children }: { route: RouteName; children: ReactNode }) {
  return (
    <div style={main}>
      <nav style={sidebarStyle} aria-label="Admin sections">
        {NAV.map((n) => (
          <button
            key={n.name}
            type="button"
            aria-current={route === n.name ? "page" : undefined}
            onClick={() => navigate({ name: n.name })}
            style={{ display: "block", width: "100%", textAlign: "left", marginBottom: "0.25rem", fontWeight: route === n.name ? 700 : 400 }}
          >
            {n.label}
          </button>
        ))}
        <p style={{ fontSize: "0.75rem", color: "var(--kiwi-text-secondary)" }}>
          Localhost console. Policy verdicts are advisory — gateway enforcement is out of scope (contract §5.3).
        </p>
      </nav>
      <div style={contentStyle}>{children}</div>
    </div>
  );
}

export function Page({ children }: { children: ReactNode }) {
  return <div style={layout}>{children}</div>;
}

export function Loading({ what }: { what: string }) {
  return (
    <p role="status">
      <small>Loading {what}…</small>
    </p>
  );
}

export function LoadError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const code = error instanceof ApiError ? error.code : "unknown";
  return (
    <div className="kiwi-banner error" role="alert">
      <strong>Failed to load</strong> ({code}): {error instanceof Error ? error.message : String(error)}{" "}
      <button type="button" onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}

export function Empty({ hint }: { hint: string }) {
  return (
    <p style={{ color: "var(--kiwi-text-secondary)" }}>
      <small>{hint}</small>
    </p>
  );
}

/** useAsync — loading/error/data lifecycle for view fetches. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): { data: T | null; error: unknown; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

export function ConfirmDialog({
  title, body, confirmLabel, onConfirm, onCancel,
}: {
  title: string;
  body: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => cancelRef.current?.focus(), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);
  return (
    <div className="kiwi-dialog-backdrop" onClick={onCancel}>
      <div className="kiwi-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" onClick={(e) => e.stopPropagation()}>
        <h2 id="confirm-title">{title}</h2>
        <p>{body}</p>
        <div style={{ display: "flex", gap: "0.4rem" }}>
          <button type="button" onClick={onConfirm}>
            {confirmLabel}
          </button>
          <button type="button" onClick={onCancel} ref={cancelRef}>
            Cancel (Esc)
          </button>
        </div>
      </div>
    </div>
  );
}
