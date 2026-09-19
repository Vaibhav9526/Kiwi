/**
 * Security event center (T-112): filterable event table + JSON export.
 * Surface KIWI-UI-010. Real events arrive from kiwi-core/kiwi-forensics;
 * Export downloads the (demo) rows as JSON — forensic format per T-107/T-109.
 */
import { useState } from "react";
import type { SecurityEventRow, Severity } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";

export function SecurityCenterView({ events, demo }: { events: SecurityEventRow[]; demo: boolean }) {
  const [accountFilter, setAccountFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"" | Severity>("");

  const filtered = events.filter(
    (e) =>
      (!accountFilter || e.accountEmail.includes(accountFilter)) &&
      (!severityFilter || e.severity === severityFilter),
  );

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), events: filtered }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "kiwi-security-events.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section aria-label="KIWI Security event center">
      <h1>Security</h1>
      {demo && (
        <p>
          <span className="kiwi-pill unknown">? demo events</span>
        </p>
      )}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.6rem", flexWrap: "wrap" }}>
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
        <button type="button" onClick={exportJson}>
          Export JSON
        </button>
      </div>
      <p role="status">
        <small>{filtered.length} events shown.</small>
      </p>
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <caption className="kiwi-sr-only">Security events</caption>
        <thead>
          <tr>
            {["Time", "Account", "Category", "Severity", "Summary"].map((h) => (
              <th key={h} scope="col" style={{ textAlign: "left", borderBottom: "1px solid var(--kiwi-border)", padding: "0.3rem" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.map((e) => (
            <tr key={e.id}>
              <td style={{ padding: "0.3rem" }}>{e.ts}</td>
              <td style={{ padding: "0.3rem" }}>{e.accountEmail}</td>
              <td style={{ padding: "0.3rem" }}>{e.category}</td>
              <td style={{ padding: "0.3rem" }}>
                <span className={`kiwi-pill ${e.severity}`}>
                  {severityGlyph(e.severity)} {severityLabel(e.severity)}
                </span>
              </td>
              <td style={{ padding: "0.3rem" }}>{e.summary}</td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={5}>No security events for this filter.</td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
