/**
 * Mail-flow view (T-134): filterable metadata table (no bodies by design)
 * + minimal send-attempt ingest form bound to the current org.
 */
import { useState } from "react";
import type { AdminApi } from "../api";
import { Empty, LoadError, Loading, useAsync } from "../components/chrome";

export function MailflowView({ api, orgId }: { api: AdminApi; orgId: string }) {
  const [domain, setDomain] = useState("");
  const [appliedDomain, setAppliedDomain] = useState("");
  const { data, error, loading, reload } = useAsync(
    () => api.queryMailflow({ org: orgId || undefined, recipientDomain: appliedDomain || undefined, limit: 100 }),
    [api, orgId, appliedDomain],
  );
  const [sender, setSender] = useState("");
  const [recipient, setRecipient] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const ingest = async () => {
    setFormError(null);
    try {
      await api.ingestMailflow({
        direction: "outbound",
        sender: sender.trim(),
        recipient: recipient.trim(),
        ts: Math.floor(Date.now() / 1000),
        message_id: null,
        tls_version: null,
        security_status: "unknown",
        policy_verdict: "unknown",
        org_id: orgId || null,
      });
      setSender("");
      setRecipient("");
      reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section aria-label="Mail flow">
      <h1>Mail flow <small style={{ color: "var(--kiwi-text-secondary)" }}>metadata only — never bodies</small></h1>
      <p>
        <label>Recipient domain filter:{" "}
          <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="partner.example" />
        </label>{" "}
        <button type="button" onClick={() => setAppliedDomain(domain.trim())}>Apply</button>
      </p>
      {loading && <Loading what="mail-flow events" />}
      {error ? <LoadError error={error} onRetry={reload} /> : null}
      {!loading && !error && (
        <table>
          <caption className="kiwi-sr-only">Mail-flow metadata events</caption>
          <thead>
            <tr>
              <th scope="col">Time</th><th scope="col">Dir</th><th scope="col">Sender</th>
              <th scope="col">Recipient</th><th scope="col">TLS</th><th scope="col">Verdict</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((e) => (
              <tr key={e.id}>
                <td><small>{new Date(e.ts * 1000).toLocaleString()}</small></td>
                <td>{e.direction}</td>
                <td><small>{e.sender}</small></td>
                <td><small>{e.recipient}</small></td>
                <td>{e.tls_version ?? "—"}</td>
                <td><span className={`kiwi-pill ${e.policy_verdict}`}>{e.policy_verdict}</span></td>
              </tr>
            ))}
            {(data ?? []).length === 0 && (
              <tr><td colSpan={6}>No mail-flow events for this filter.</td></tr>
            )}
          </tbody>
        </table>
      )}
      <div className="kiwi-card">
        <h2>Record send attempt (outbound)</h2>
        <p>
          <label>Sender: <input type="text" value={sender} onChange={(e) => setSender(e.target.value)} /></label>{" "}
          <label>Recipient: <input type="text" value={recipient} onChange={(e) => setRecipient(e.target.value)} /></label>{" "}
          <button type="button" onClick={ingest} disabled={!sender.trim() || !recipient.trim() || !orgId}>
            Record
          </button>
        </p>
        {!orgId && <Empty hint="Set a current org id — outbound events require it (contract §6)." />}
        {formError && <p role="alert"><small>{formError}</small></p>}
      </div>
    </section>
  );
}
