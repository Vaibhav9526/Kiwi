/**
 * Policies view (T-134): list cards, create form, single + outbound-bridge
 * evaluation testers rendering per-recipient verdicts (KIWI-UI-007 data).
 */
import { useState } from "react";
import type { AdminApi, OutboundEvaluation } from "../api";
import { Empty, LoadError, Loading, useAsync } from "../components/chrome";

export function PoliciesView({ api, orgId }: { api: AdminApi; orgId: string }) {
  const { data, error, loading, reload } = useAsync(() => (orgId ? api.listPolicies(orgId) : Promise.resolve([])), [api, orgId]);
  const [name, setName] = useState("default-outbound");
  const [minTls, setMinTls] = useState("tls1.2");
  const [ext, setExt] = useState<"allow" | "warn" | "block">("warn");
  const [rules, setRules] = useState("partner.example=allow");
  const [formError, setFormError] = useState<string | null>(null);
  const [sender, setSender] = useState("alice@example.test");
  const [recipients, setRecipients] = useState("b@partner.example, c@stranger.test");
  const [tls, setTls] = useState("tls1.3");
  const [result, setResult] = useState<OutboundEvaluation | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  if (!orgId) return <Empty hint="Set a current org id in the header to manage policies." />;
  if (loading) return <Loading what="policies" />;
  if (error) return <LoadError error={error} onRetry={reload} />;

  const create = async () => {
    setFormError(null);
    try {
      const domain_rules: { domain: string; action: "allow" | "block" }[] = rules
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => {
          const [domain, action] = s.split("=").map((x) => x.trim());
          if (!domain || (action !== "allow" && action !== "block")) throw new Error(`bad rule '${s}' — use domain=allow|block`);
          const act: "allow" | "block" = action;
          return { domain, action: act };
        });
      await api.createPolicy(orgId, { name: name.trim(), enabled: true, min_tls: minTls, external_recipients: ext, domain_rules });
      setName("");
      reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    }
  };

  const evaluate = async () => {
    setEvalError(null);
    setResult(null);
    try {
      const out = await api.evaluateOutbound(orgId, {
        sender: sender.trim(),
        recipients: recipients.split(",").map((s) => s.trim()).filter(Boolean),
        tlsVersion: tls.trim() || null,
      });
      setResult(out);
    } catch (e) {
      setEvalError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section aria-label="Policies">
      <h1>Policies</h1>
      {(data ?? []).map((p) => (
        <div className="kiwi-card" key={p.id}>
          <h2>
            {p.name} <small style={{ color: "var(--kiwi-text-secondary)" }}>{p.id}</small>
          </h2>
          <p>
            <small>
              {p.enabled ? "enabled" : "disabled"} · min TLS {p.min_tls ?? "none"} · external: {p.external_recipients}
            </small>
          </p>
          <ul>
            {p.domain_rules.map((r) => (
              <li key={r.domain}>
                <code>{r.domain}</code> → <span className={`kiwi-pill ${r.action === "block" ? "block" : "allow"}`}>{r.action}</span>
              </li>
            ))}
            {p.domain_rules.length === 0 && <li><small>No domain rules.</small></li>}
          </ul>
        </div>
      ))}
      {(data ?? []).length === 0 && <Empty hint="No policies yet — create one below." />}
      <div className="kiwi-card">
        <h2>Create policy</h2>
        <p>
          <label>Name: <input type="text" value={name} onChange={(e) => setName(e.target.value)} /></label>{" "}
          <label>Min TLS:{" "}
            <select value={minTls} onChange={(e) => setMinTls(e.target.value)}>
              <option value="tls1.0">TLS 1.0</option>
              <option value="tls1.1">TLS 1.1</option>
              <option value="tls1.2">TLS 1.2</option>
              <option value="tls1.3">TLS 1.3</option>
            </select>
          </label>{" "}
          <label>External:{" "}
            <select value={ext} onChange={(e) => setExt(e.target.value as "allow" | "warn" | "block")}>
              <option value="allow">allow</option>
              <option value="warn">warn</option>
              <option value="block">block</option>
            </select>
          </label>
        </p>
        <p>
          <label>Domain rules (domain=allow|block, comma-separated):{" "}
            <input type="text" value={rules} onChange={(e) => setRules(e.target.value)} style={{ width: "70%" }} />
          </label>
        </p>
        <p>
          <button type="button" onClick={create} disabled={!name.trim()}>Create policy</button>
        </p>
        {formError && <p role="alert"><small>{formError}</small></p>}
      </div>
      <div className="kiwi-card">
        <h2>Outbound evaluation tester (§10 bridge)</h2>
        <p>
          <label>Sender: <input type="text" value={sender} onChange={(e) => setSender(e.target.value)} /></label>{" "}
          <label>Observed TLS: <input type="text" value={tls} onChange={(e) => setTls(e.target.value)} style={{ width: "7rem" }} /></label>
        </p>
        <p>
          <label>Recipients (comma-separated):{" "}
            <input type="text" value={recipients} onChange={(e) => setRecipients(e.target.value)} style={{ width: "70%" }} />
          </label>{" "}
          <button type="button" onClick={evaluate}>Evaluate</button>
        </p>
        {evalError && <p role="alert"><small>{evalError}</small></p>}
        {result && (
          <>
            <p>Overall: <span className={`kiwi-pill ${result.overall}`}>{result.overall}</span></p>
            <table>
              <caption className="kiwi-sr-only">Per-recipient verdicts</caption>
              <thead><tr><th scope="col">Recipient</th><th scope="col">Verdict</th><th scope="col">Reasons</th></tr></thead>
              <tbody>
                {result.results.map((r) => (
                  <tr key={r.recipient}>
                    <td><code>{r.recipient}</code></td>
                    <td><span className={`kiwi-pill ${r.verdict}`}>{r.verdict}</span></td>
                    <td><small>{r.reasons.map((x) => x.detail ? `${x.code} (${x.detail})` : x.code).join("; ")}</small></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  );
}
