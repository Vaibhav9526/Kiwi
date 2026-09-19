/**
 * KIWI admin console root (T-134). Probes the service /healthz: live mode
 * talks REST (contract v1.3), unreachable service falls back to the demo
 * adapter — always badged, never silent. Prefs (base URL, org) persist in
 * localStorage; role is session state.
 */
import { useEffect, useMemo, useState } from "react";
import type { ActorRole, AdminApi } from "./api";
import { HttpAdminApi } from "./api";
import { MockAdminApi } from "./mock";
import { useRoute } from "./router";
import { Page, Shell, TopBar } from "./components/chrome";
import { OrgsView } from "./views/orgs";
import { UsersView } from "./views/users";
import { PoliciesView } from "./views/policies";
import { MailflowView } from "./views/mailflow";
import { AuditView } from "./views/audit";

const DEFAULT_BASE = "http://127.0.0.1:8471";

function load(key: string, fallback: string): string {
  try {
    return window.localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Private mode — prefs simply don't persist.
  }
}

export default function App() {
  const route = useRoute();
  const [baseUrl, setBaseUrl] = useState(() => load("kiwi-admin.baseUrl", DEFAULT_BASE));
  const [role, setRole] = useState<ActorRole>("org_admin");
  const [orgId, setOrgId] = useState(() => load("kiwi-admin.orgId", ""));
  const [live, setLive] = useState(false);

  useEffect(() => save("kiwi-admin.baseUrl", baseUrl), [baseUrl]);
  useEffect(() => save("kiwi-admin.orgId", orgId), [orgId]);

  // Probe the service; any failure → demo mode (badged in the header).
  useEffect(() => {
    let cancelled = false;
    const probe = new HttpAdminApi(baseUrl, { subject: "probe", roles: ["viewer"], orgId: null });
    probe
      .health()
      .then(() => {
        if (!cancelled) setLive(true);
      })
      .catch(() => {
        if (!cancelled) setLive(false);
      });
    return () => {
      cancelled = true;
    };
  }, [baseUrl]);

  const api: AdminApi = useMemo(
    () =>
      live
        ? new HttpAdminApi(baseUrl, { subject: "admin-console", roles: [role], orgId: orgId || null })
        : new MockAdminApi(role),
    [live, baseUrl, role, orgId],
  );

  return (
    <Page>
      <TopBar
        mode={live ? "live" : "demo"}
        baseUrl={baseUrl}
        role={role}
        onRole={setRole}
        onBaseUrl={(u) => {
          setBaseUrl(u);
          setLive(false);
        }}
        orgId={orgId}
        onOrgId={setOrgId}
      />
      <Shell route={route.name}>
        {route.name === "orgs" && <OrgsView api={api} orgId={orgId} onOrgId={setOrgId} />}
        {route.name === "users" && <UsersView api={api} orgId={orgId} />}
        {route.name === "policies" && <PoliciesView api={api} orgId={orgId} />}
        {route.name === "mailflow" && <MailflowView api={api} orgId={orgId} />}
        {route.name === "audit" && <AuditView api={api} />}
      </Shell>
    </Page>
  );
}
