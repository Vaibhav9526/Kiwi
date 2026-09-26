/**
 * Security event center (T-143, T-164): live events + retained findings via
 * kiwi.ipc/1 (kiwi_security_findings/events; finding dialog joins
 * kiwi_finding_detail), session-detail dialog, JSON report export. Demo mode
 * renders the T-112 fixtures, badged.
 */
import { Fragment, useEffect, useState } from "react";
import type { AuditEventView, FindingInfo, SecurityEventRow, SecuritySessionView, Severity } from "../kiwi";
import { AUDIT_CORRUPT_MESSAGE, severityGlyph, severityLabel } from "../kiwi";
import { api, BackendUnavailableError, IpcError } from "../ipc";

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
  // T-323: app-audit trail (audit.jsonl — mbox import/export, device, rules,
  // account mutations). Read IPC kiwi_audit_events (T-324) is queued, not yet
  // registered → until it lands the section shows the honest pending state;
  // the moment it registers the same code renders real rows.
  const AUDIT_PAGE = 200;
  const [audit, setAudit] = useState<AuditEventView[]>([]);
  const [auditState, setAuditState] = useState<"idle" | "loading" | "pending" | "ready" | "error">("idle");
  const [auditErr, setAuditErr] = useState<string | null>(null);
  const [auditDone, setAuditDone] = useState(false); // older page returned empty
  const [auditExpanded, setAuditExpanded] = useState<number | null>(null);
  const [auditCopy, setAuditCopy] = useState<string | null>(null);
  // T-331: chain health. `corrupt` is a PERSISTENT security state, not a
  // transient load failure — it must not clear on a successful reload, and it
  // must not be a toast (a security signal has to stay on screen until the
  // user dismisses or the backend reports a verified chain again).
  const [auditIntegrity, setAuditIntegrity] = useState<"ok" | "corrupt" | "unknown" | null>(null);

  const loadAudit = async (beforeUnix?: number) => {
    setAuditState("loading");
    setAuditErr(null);
    try {
      const rows = await api.auditEvents(beforeUnix, AUDIT_PAGE);
      setAudit((prev) => (beforeUnix === undefined ? rows : [...prev, ...rows]));
      if (beforeUnix === undefined) setAuditDone(false);
      if (rows.length < AUDIT_PAGE) setAuditDone(true);
      setAuditState("ready");
    } catch (e) {
      // Not-yet-registered command = pending, not failure.
      const msg = e instanceof Error ? e.message : String(e);
      if (e instanceof BackendUnavailableError || /unknown command|not found|unregistered|not implemented/i.test(msg)) {
        setAuditState("pending");
      } else if (e instanceof IpcError && e.code === "audit-corrupt") {
        // T-331: a failed verification is the headline, not a retry-able
        // error string. Rows below are untrustworthy — don't render them as
        // if they were evidence.
        setAuditIntegrity("corrupt");
        setAuditState("error");
        setAuditErr(AUDIT_CORRUPT_MESSAGE);
      } else {
        setAuditState("error");
        setAuditErr(msg);
      }
    }
  };

  // T-331 + T-338: probe chain health. Cheap (no rows), ungated, and it is the
  // only way corruption becomes visible before the rows are requested. The
  // verdict is backend-owned — the renderer never guesses.
  const probeIntegrity = async (): Promise<"ok" | "corrupt" | "unknown"> => {
    try {
      const v = await api.auditIntegrity();
      setAuditIntegrity(v.state);
      return v.state;
    } catch {
      setAuditIntegrity("unknown");
      return "unknown";
    }
  };

  // "Re-check" on the corrupt banner: a real re-verification — if the chain
  // now verifies, reload the rows that were withheld as evidence.
  const recheckIntegrity = async () => {
    const s = await probeIntegrity();
    if (s === "ok") void loadAudit();
  };

  useEffect(() => {
    if (demo) {
      setAuditIntegrity("unknown");
      return;
    }
    void probeIntegrity();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo]);

  useEffect(() => {
    if (demo) {
      setAuditState("pending"); // demo never fabricates an audit trail
      return;
    }
    void loadAudit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo]);

  const auditCsv = (rows: AuditEventView[]) =>
    [
      "event,at_iso,actor,subject_id,detail_json",
      ...rows.map((r) =>
        [r.event, new Date(r.atUnix * 1000).toISOString(), r.actor, r.subjectId ?? "", r.detailJson ?? ""]
          .map((c) => `"${String(c).replaceAll('"', '""')}"`)
          .join(","),
      ),
    ].join("\n");

  const copyAudit = async (fmt: "json" | "csv") => {
    if (!audit.length || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(fmt === "json" ? JSON.stringify(audit, null, 2) : auditCsv(audit));
      setAuditCopy(`${audit.length} loaded rows copied as ${fmt.toUpperCase()}.`);
    } catch {
      setAuditCopy("Clipboard unavailable — copy failed.");
    }
  };

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
    <section aria-label="KIWI Security event center" className="em-security ms-view-enter">
      <h1 className="em-view-title">
        Security{" "}
        {demo && <span className="ms-badge">? demo events</span>}
      </h1>
      <div className="ms-pane">
        <h2 className="ms-pane-title">Findings ({findings.length})</h2>
        {findings.length === 0 ? (
          <p className="em-pane-desc">No retained findings.</p>
        ) : (
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
        )}
      </div>
      <div className="ms-pane">
        <h2 className="ms-pane-title">Events</h2>
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
      </div>
      <div className="ms-pane">
        <h2 className="ms-pane-title">App audit log</h2>
        <p className="em-pane-desc">
          <small>
            Action trail (audit.jsonl) — imports, exports, device and account mutations. Distinct from the
            transport-security events above: these rows record what the app DID, not what the wire showed.
            Ids and counts only — the trail never carries paths, subjects, or bodies.
          </small>
        </p>
      {auditState === "pending" && (
        <div className="kiwi-banner" role="status">
          <small>
            Audit-log read IPC (<code>kiwi_audit_events</code>) is backend-pending (T-324 — queued). Actions
            are already being recorded; this panel renders them the moment the read command lands.
            {demo && " Demo mode never fabricates an audit trail."}
          </small>
        </div>
      )}
      {/*
        T-338: the probe verdict surfaces alongside the rows in every readable
        state — verified says so, unreadable says the rows are unverified.
        Both come from kiwi_audit_integrity alone; nothing is assumed.
      */}
      {!demo && auditIntegrity === "ok" && (
        <p role="status" style={{ color: "var(--kiwi-ms-text-secondary)" }}>
          <small>Chain integrity: verified (kiwi_audit_integrity).</small>
        </p>
      )}
      {!demo && auditIntegrity === "unknown" && auditState === "ready" && (
        <p role="status" style={{ color: "var(--kiwi-ms-text-secondary)" }}>
          <small>Chain integrity: could not be verified — rows shown are unverified.</small>
        </p>
      )}
      {/*
        T-331: the persistent security state. Deliberately NOT a toast and NOT
        dismissible-by-time: `audit-corrupt` means the log can no longer prove
        what the app did, and that claim has to keep standing on screen.
      */}
      {auditIntegrity === "corrupt" && (
        <div className="kiwi-banner error" role="alert" data-audit-integrity="corrupt">
          <strong>Audit integrity failure.</strong> {AUDIT_CORRUPT_MESSAGE}.{" "}
          <button type="button" className="ms-btn" onClick={() => void recheckIntegrity()}>
            Re-check
          </button>
          <br />
          <small>
            The rows below are unverified and must not be treated as evidence. Do not clear the log — it
            is the only record of what this app did. <code>kiwi_security_status</code> carries the same
            verdict as <code>auditOk</code>.
          </small>
        </div>
      )}
      {auditState === "error" && auditIntegrity !== "corrupt" && (
        <div className="kiwi-banner error" role="alert">
          <small>Audit log failed to load: {auditErr}</small>{" "}
          <button type="button" className="ms-btn" onClick={() => void loadAudit()}>
            Retry
          </button>
        </div>
      )}
      {auditState === "loading" && audit.length === 0 && (
        <p role="status">
          <small>Loading audit log…</small>
        </p>
      )}
      {audit.length > 0 && auditIntegrity !== "corrupt" && (
        <>
          <div className="ms-filterbar">
            <button type="button" className="ms-btn" onClick={() => void loadAudit()} disabled={auditState === "loading"}>
              Refresh
            </button>
            <button type="button" className="ms-btn" onClick={() => void copyAudit("json")}>
              Copy JSON
            </button>
            <button type="button" className="ms-btn" onClick={() => void copyAudit("csv")}>
              Copy CSV
            </button>
            <small style={{ color: "var(--kiwi-ms-text-secondary)" }}>
              copies the {audit.length} loaded rows — a full-file download needs the backend
            </small>
          </div>
          {auditCopy && (
            <p role="status">
              <small>{auditCopy}</small>
            </p>
          )}
          <table className="ms-table">
            <caption className="kiwi-sr-only">App audit trail</caption>
            <thead>
              <tr>
                {["Time", "Event", "Actor", "Subject", "Detail"].map((h) => (
                  <th key={h} scope="col">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((r, i) => (
                <Fragment key={i}>
                  <tr>
                    <td>{new Date(r.atUnix * 1000).toLocaleString()}</td>
                    <td>
                      <code>{r.event}</code>
                    </td>
                    <td>{r.actor}</td>
                    <td>{r.subjectId ?? "—"}</td>
                    <td>
                      {r.detailJson ? (
                        <button
                          type="button"
                          className="ms-btn"
                          aria-expanded={auditExpanded === i}
                          onClick={() => setAuditExpanded(auditExpanded === i ? null : i)}
                        >
                          Detail
                        </button>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                  {auditExpanded === i && r.detailJson && (
                    <tr>
                      <td colSpan={5}>
                        <pre className="kiwi-evidence" tabIndex={0}>
                          {(() => {
                            try {
                              return JSON.stringify(JSON.parse(r.detailJson), null, 2);
                            } catch {
                              return r.detailJson;
                            }
                          })()}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {!auditDone && (
            <p>
              <button
                type="button"
                className="ms-btn"
                disabled={auditState === "loading"}
                onClick={() => void loadAudit(audit[audit.length - 1]?.atUnix)}
              >
                {auditState === "loading" ? "Loading…" : "Load older"}
              </button>
            </p>
          )}
        </>
      )}
      {auditState === "ready" && audit.length === 0 && auditIntegrity !== "corrupt" && (
        <p>
          <small>No audit events recorded yet.</small>
        </p>
      )}
      </div>
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
