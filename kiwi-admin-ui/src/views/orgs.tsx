/**
 * Organizations view (T-134). v1.3 has no org-listing endpoint, so this view
 * is honest about it: create form (returns the new id) + current-org picker.
 */
import { useState } from "react";
import type { AdminApi } from "../api";
import { ApiError } from "../api";

export function OrgsView({ api, orgId, onOrgId }: { api: AdminApi; orgId: string; onOrgId: (id: string) => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const org = await api.createOrg(name.trim());
      setCreated(org.id);
      onOrgId(org.id);
      setName("");
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-label="Organizations">
      <h1>Organizations</h1>
      <div className="kiwi-card">
        <h2>Create organization</h2>
        <p>
          <label>
            Name: <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="acme.test" />{" "}
            <button type="button" onClick={create} disabled={!name.trim() || busy}>
              {busy ? "Creating…" : "Create"}
            </button>
          </label>
        </p>
        {error && (
          <p role="alert">
            <small>{error}</small>
          </p>
        )}
        {created && (
          <p role="status">
            <small>
              Created <code>{created}</code> — set as current org.
            </small>
          </p>
        )}
      </div>
      <div className="kiwi-card">
        <h2>Current organization</h2>
        <p>
          <code>{orgId || "(none — enter an org id in the header)"}</code>
        </p>
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>
            Org enumeration has no endpoint in contract v1.3 — paste an id created here or elsewhere. A list
            endpoint is tracked follow-up work.
          </small>
        </p>
      </div>
    </section>
  );
}
