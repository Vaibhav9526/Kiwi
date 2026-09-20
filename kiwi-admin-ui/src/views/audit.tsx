/**
 * Audit view (T-134): entry table + chain verification panel.
 */
import { useState } from "react";
import type { AdminApi } from "../api";
import { LoadError, Loading, useAsync } from "../components/chrome";

export function AuditView({ api }: { api: AdminApi }) {
  const { data, error, loading, reload } = useAsync(() => api.queryAudit({ limit: 100 }), [api]);
  const [verify, setVerify] = useState<{ valid: boolean; checked: number; error: string | null } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const runVerify = async () => {
    setVerifying(true);
    setVerifyError(null);
    try {
      setVerify(await api.verifyAudit(10000));
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : String(e));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <section aria-label="Audit log">
      <h1>Audit log <small style={{ color: "var(--kiwi-text-secondary)" }}>append-only, hash-chained</small></h1>
      <div className="kiwi-card">
        <h2>Chain verification</h2>
        <p>
          <button type="button" onClick={runVerify} disabled={verifying}>
            {verifying ? "Verifying…" : "Verify chain"}
          </button>
        </p>
        {verifyError && <p role="alert"><small>{verifyError}</small></p>}
        {verify && (
          <p role="status">
            {verify.valid ? (
              <span className="kiwi-pill allow">✓ valid ({verify.checked} checked)</span>
            ) : (
              <span className="kiwi-pill block">✕ {verify.error}</span>
            )}
          </p>
        )}
      </div>
      {loading && <Loading what="audit entries" />}
      {error ? <LoadError error={error} onRetry={reload} /> : null}
      {!loading && !error && (
        <table>
          <caption className="kiwi-sr-only">Audit entries, newest first</caption>
          <thead>
            <tr>
              <th scope="col">Seq</th><th scope="col">Actor</th><th scope="col">Action</th>
              <th scope="col">Outcome</th><th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((r) => (
              <tr key={r.seq}>
                <td>{r.seq}</td>
                <td><small>{r.actor_subject ?? "—"}</small></td>
                <td><code>{r.action}</code></td>
                <td>
                  <span className={`kiwi-pill ${r.outcome === "allowed" ? "allow" : r.outcome === "denied" ? "denied" : "unknown"}`}>
                    {r.outcome}
                  </span>
                </td>
                <td><small>{r.details ?? ""}</small></td>
              </tr>
            ))}
            {(data ?? []).length === 0 && (
              <tr><td colSpan={5}>No audit entries yet.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
