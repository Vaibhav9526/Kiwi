/**
 * Users & roles view (T-134): table, invite form, per-row role grant
 * (confirm dialog naming the target), device revoke by id (confirm).
 * No device enumeration endpoint exists in v1.3 — revoke takes an id.
 */
import { useState } from "react";
import type { ActorRole, AdminApi } from "../api";
import { ConfirmDialog, Empty, LoadError, Loading, useAsync } from "../components/chrome";

export function UsersView({ api, orgId }: { api: AdminApi; orgId: string }) {
  const { data, error, loading, reload } = useAsync(() => (orgId ? api.listUsers(orgId) : Promise.resolve([])), [api, orgId]);
  const [email, setEmail] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [grant, setGrant] = useState<{ userId: string; email: string; role: ActorRole } | null>(null);
  const [deviceId, setDeviceId] = useState("");
  const [revoking, setRevoking] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  if (!orgId) return <Empty hint="Set a current org id in the header to manage users." />;
  if (loading) return <Loading what="users" />;
  if (error) return <LoadError error={error} onRetry={reload} />;

  const invite = async () => {
    setFormError(null);
    try {
      await api.createUser(orgId, email.trim());
      setEmail("");
      setNotice(`Invited ${email.trim()}.`);
      reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    }
  };

  const doGrant = async () => {
    if (!grant) return;
    try {
      await api.grantRole(orgId, grant.userId, grant.role);
      setNotice(`Granted ${grant.role} to ${grant.email}.`);
      reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    } finally {
      setGrant(null);
    }
  };

  const doRevoke = async () => {
    setRevoking(true);
    try {
      await api.revokeDevice(deviceId.trim());
      setNotice(`Revoked device ${deviceId.trim()}.`);
      setDeviceId("");
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevoking(false);
      setConfirmRevoke(false);
    }
  };

  return (
    <section aria-label="Users and roles">
      <h1>Users &amp; roles</h1>
      {notice && (
        <p role="status">
          <small>{notice}</small>
        </p>
      )}
      <div className="kiwi-card">
        <h2>Invite user</h2>
        <p>
          <label>
            Email: <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="bob@acme.test" />{" "}
            <button type="button" onClick={invite} disabled={!email.trim()}>
              Invite
            </button>
          </label>
        </p>
      </div>
      <table>
        <caption className="kiwi-sr-only">Organization users</caption>
        <thead>
          <tr>
            <th scope="col">Email</th>
            <th scope="col">Roles</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((u) => (
            <tr key={u.id}>
              <td>{u.email}</td>
              <td>{u.roles.length ? u.roles.join(", ") : "—"}</td>
              <td>
                <label>
                  <span className="kiwi-sr-only">Grant role to {u.email}</span>
                  <select
                    defaultValue=""
                    onChange={(e) => {
                      if (e.target.value) setGrant({ userId: u.id, email: u.email, role: e.target.value as ActorRole });
                      e.target.value = "";
                    }}
                    aria-label={`Grant role to ${u.email}`}
                  >
                    <option value="">Grant role…</option>
                    <option value="org_admin">org_admin</option>
                    <option value="security_admin">security_admin</option>
                    <option value="viewer">viewer</option>
                  </select>
                </label>
              </td>
            </tr>
          ))}
          {(data ?? []).length === 0 && (
            <tr>
              <td colSpan={3}>No users yet — invite the first one above.</td>
            </tr>
          )}
        </tbody>
      </table>
      <div className="kiwi-card">
        <h2>Revoke device</h2>
        <p>
          <label>
            Device id: <input type="text" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="dev-…" />{" "}
            <button type="button" onClick={() => setConfirmRevoke(true)} disabled={!deviceId.trim() || revoking}>
              Revoke…
            </button>
          </label>
        </p>
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>Device enumeration has no endpoint in v1.3 — revocation takes an explicit id and confirms.</small>
        </p>
      </div>
      {formError && (
        <div className="kiwi-banner error" role="alert">
          {formError}
        </div>
      )}
      {grant && (
        <ConfirmDialog
          title="Grant role"
          body={`Grant ${grant.role} to ${grant.email}?`}
          confirmLabel={`Grant ${grant.role}`}
          onConfirm={doGrant}
          onCancel={() => setGrant(null)}
        />
      )}
      {confirmRevoke && (
        <ConfirmDialog
          title="Revoke device"
          body={`Revoke device ${deviceId.trim()}? Enrolled clients stop trusting it immediately.`}
          confirmLabel="Revoke device"
          onConfirm={doRevoke}
          onCancel={() => setConfirmRevoke(false)}
        />
      )}
    </section>
  );
}
