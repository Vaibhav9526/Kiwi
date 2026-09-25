/**
 * Security event center (T-143, T-164): live events + retained findings via
 * kiwi.ipc/1 (kiwi_security_findings/events; finding dialog joins
 * kiwi_finding_detail), session-detail dialog, JSON report export. Demo mode
 * renders the T-112 fixtures, badged.
 */
import { useEffect, useState } from "react";
import type { FindingInfo, SecurityEventRow, SecuritySessionView, Severity } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { api } from "../ipc";

function pretty(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function SecurityCenterView({
  events,
  findings,
  demo,
  onOpenFinding,
}: {
  events: SecurityEventRow[];
  findings: FindingInfo[];
  demo: boolean;
  onOpenFinding: (index: number) => void;
}) {
  const [accountFilter, setAccountFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"" | Severity>("");
  // T-260: the typed SessionView (ipc.md §3). `null` is a real state — an
  // unrecognized/malformed envelope — and the view below says so rather than
  // rendering a blank or half-parsed card.
  const [session, setSession] = useState<SecuritySessionView | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSession(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [session]);

  const filtered = events.filter(
    (e) =>
      (!accountFilter || e.accountEmail.includes(accountFilter)) &&
      (!severityFilter || e.severity === severityFilter),
  );

  const download = (filename: string, obj: unknown) => {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const openSession = async (detailRef: string) => {
    const id = detailRef.startsWith("session:") ? detailRef.slice("session:".length) : detailRef;
    if (!id) return;
    setSessionError(null);
    try {
      const detail = await api.sessionDetail(id);
      // T-260: a null detail means the envelope didn't match the §3 shape.
      // Say so — silence would read as "the session is fine".
      if (!detail) {
        setSession(null);
        setSessionError("Session detail was not in the expected format.");
        return;
      }
      setSession(detail);
    } catch (e) {
      setSessionError(e instanceof Error ? e.message : String(e));
    }
  };

  const exportReport = async () => {
    setReportError(null);
    try {
      download("kiwi-security-report.json", await api.securityReport());
    } catch (e) {
      setReportError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section aria-label="KIWI Security event center" className="ms-prefs ms-view-enter">
      <h1>Security</h1>
      {demo && (
        <p>
          <span className="ms-badge">? demo events</span>
        </p>
      )}
      <h2>Findings ({findings.length})</h2>
      {findings.length === 0 && (
        <p style={{ color: "var(--kiwi-ms-text-secondary)" }}>
          <small>No retained findings.</small>
        </p>
      )}
      <ul className="ms-findings-list">
        {findings.map((f, i) => (
          <li key={f.id} className="ms-finding-row">
            <span className={`kiwi-pill ${f.severity}`}>
              {severityGlyph(f.severity)} {severityLabel(f.severity)}
            </span>{" "}
            <span className="ms-finding-title" title={f.title}>
              {f.title}
            </span>{" "}
            <button type="button" className="ms-btn" onClick={() => onOpenFinding(i)}>
              Details
            </button>
          </li>
        ))}
      </ul>
      <h2>Events</h2>
      <div className="ms-filterbar">
        <label>
          Account filter:{" "}
          <input type="text" value={accountFilter} onChange={(e) => setAccountFilter(e.target.value)} placeholder="account substring" />
        </label>
        <label>
          Severity:{" "}
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as "" | Severity)}>
            <option value="">All</option>
            <option value="secure">Secure</option>
            <option value="warning">Warning</option>
            <option value="danger">Danger</option>
            <option value="unknown">Unknown</option>
          </select>
        </label>
        {!demo && (
          <button type="button" className="ms-btn" onClick={() => void exportReport()}>
            Security report (JSON)
          </button>
        )}
        {demo && (
          <button
            type="button"
            className="ms-btn"
            onClick={() => download("kiwi-security-events.json", { exported_at: new Date().toISOString(), events: filtered })}
          >
            Export JSON
          </button>
        )}
      </div>
      <p style={{ color: "var(--kiwi-ms-text-secondary)" }}>
        <small>Endpoint posture — devices, signals, org binding — lives in Settings → Identity.</small>
      </p>
      {reportError && (
        <p role="alert">
          <small>{reportError}</small>
        </p>
      )}
      {sessionError && (
        <p role="alert">
          <small>{sessionError}</small>
        </p>
      )}
      <p role="status">
        <small>{filtered.length} events shown.</small>
      </p>
      <table className="ms-table">
        <caption className="kiwi-sr-only">Security events</caption>
        <thead>
          <tr>
            {["Time", "Account", "Category", "Severity", "Summary", "Detail"].map((h) => (
              <th key={h} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.map((e) => (
            <tr key={e.id}>
              <td>{e.ts}</td>
              <td>{e.accountEmail}</td>
              <td>{e.category}</td>
              <td>
                <span className={`kiwi-pill ${e.severity}`}>
                  {severityGlyph(e.severity)} {severityLabel(e.severity)}
                </span>
              </td>
              <td>{e.summary}</td>
              <td>
                {e.detailRef ? (
                  <button type="button" className="ms-btn" onClick={() => void openSession(e.detailRef)}>
                    Session
                  </button>
                ) : (
                  "—"
                )}
              </td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={6}>No security events for this filter.</td>
            </tr>
          )}
        </tbody>
      </table>
      {session && (
        <div className="kiwi-dialog-backdrop" onClick={() => setSession(null)}>
          <div
            className="kiwi-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="session-title"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "720px" }}
          >
            <h2 id="session-title">Session detail</h2>
            <pre className="kiwi-evidence" tabIndex={0}>
              {pretty(session)}
            </pre>
            <button type="button" onClick={() => setSession(null)}>
              Close (Esc)
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
