/**
 * Settings (T-143): prefs sections unchanged; Accounts, devices, org
 * binding, and endpoint signals are live via kiwi.ipc/1. Secrets (passwords)
 * never appear here — kiwi_add_account consumes them once at setup.
 */
import { useEffect, useState } from "react";
import { loadPref, savePref } from "../prefs";
import { api, IpcError } from "../ipc";
import type { AccountView, DeviceView, VerifyResult } from "../kiwi";
import { navigate } from "../router";

const SECTIONS = ["General", "Accounts", "KIWI Security", "Templates", "Notifications", "Privacy", "Advanced"] as const;
type Section = (typeof SECTIONS)[number];

function errText(e: unknown): string {
  return e instanceof IpcError ? `${e.code}: ${e.message}` : e instanceof Error ? e.message : String(e);
}

export function SettingsView({
  mode,
  accounts,
  orgBinding,
  onAccountsChanged,
  onStatusChanged,
  onOrgChanged,
  onLock,
}: {
  mode: "live" | "demo";
  accounts: AccountView[];
  orgBinding: { orgId: string; baseUrl: string } | null;
  onAccountsChanged: () => void;
  onStatusChanged: () => void;
  onOrgChanged: () => void;
  onLock: () => void;
}) {
  const [section, setSection] = useState<Section>("General");
  const [themeDefault, setThemeDefault] = useState(() => loadPref("kiwi.theme", "dark"));
  const [grace, setGrace] = useState(() => loadPref("kiwi.grace", "10"));
  const [minTls, setMinTls] = useState(() => loadPref("kiwi.minTls", "tls1.2"));
  const [templates, setTemplates] = useState<string[]>(() => loadPref("kiwi.templates", ["Status update", "Meeting request"]));
  const [newTemplate, setNewTemplate] = useState("");
  const [devices, setDevices] = useState<DeviceView[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, VerifyResult[]>>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [bindOrgId, setBindOrgId] = useState("");
  const [bindUrl, setBindUrl] = useState("");
  const [signals, setSignals] = useState<Record<string, unknown> | null>(null);

  useEffect(() => savePref("kiwi.theme", themeDefault), [themeDefault]);
  useEffect(() => savePref("kiwi.grace", grace), [grace]);
  useEffect(() => savePref("kiwi.minTls", minTls), [minTls]);
  useEffect(() => savePref("kiwi.templates", templates), [templates]);

  const loadDevices = async () => {
    if (mode !== "live") return;
    setDevicesError(null);
    try {
      setDevices(await api.listDevices());
    } catch (e) {
      setDevicesError(errText(e));
    }
  };

  useEffect(() => {
    if (section === "KIWI Security") void loadDevices();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [section, mode]);

  const testAccount = async (id: string) => {
    setActionError(null);
    try {
      const results = await api.testAccount(id);
      setTestResults((m) => ({ ...m, [id]: results }));
    } catch (e) {
      setActionError(errText(e));
    }
  };

  const removeAccount = async (id: string) => {
    setActionError(null);
    try {
      await api.removeAccount(id);
      setConfirmRemove(null);
      onAccountsChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  const revokeDevice = async (id: string) => {
    setActionError(null);
    try {
      await api.revokeDevice(id);
      setConfirmRevoke(null);
      await loadDevices();
      onStatusChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  const setBinding = async () => {
    setActionError(null);
    try {
      await api.setOrgBinding(bindOrgId.trim() || null, bindUrl.trim() || null);
      setBindOrgId("");
      setBindUrl("");
      onOrgChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  const clearBinding = async () => {
    setActionError(null);
    try {
      await api.setOrgBinding(null, null);
      onOrgChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  const collectSignals = async () => {
    setActionError(null);
    try {
      setSignals(await api.collectEndpointSignals());
      onStatusChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "0.8rem" }}>
      <nav aria-label="Settings sections">
        {SECTIONS.map((s) => (
          <button
            key={s}
            type="button"
            aria-current={s === section ? "page" : undefined}
            onClick={() => setSection(s)}
            style={{ display: "block", width: "100%", textAlign: "left", marginBottom: "0.25rem", fontWeight: s === section ? 700 : 400 }}
          >
            {s}
          </button>
        ))}
      </nav>
      <section aria-label={`${section} settings`}>
        <h1>{section}</h1>
        {actionError && (
          <div className="kiwi-banner error" role="alert">
            <small>{actionError}</small>
          </div>
        )}

        {section === "General" && (
          <>
            <p>
              <label>
                Theme:{" "}
                <select value={themeDefault} onChange={(e) => setThemeDefault(e.target.value)}>
                  <option value="system">System</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Undo-send grace window:{" "}
                <select value={grace} onChange={(e) => setGrace(e.target.value)}>
                  <option value="5">5 seconds</option>
                  <option value="10">10 seconds</option>
                  <option value="20">20 seconds</option>
                  <option value="30">30 seconds</option>
                </select>
              </label>
            </p>
          </>
        )}

        {section === "Accounts" && (
          <>
            {mode === "demo" && (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>Demo mode — account management needs the backend. Run the Tauri app for live accounts.</small>
              </p>
            )}
            {accounts.map((a) => (
              <div className="kiwi-card" key={a.id}>
                <h2>
                  {a.displayName} <small style={{ color: "var(--kiwi-text-secondary)" }}>{a.email}</small>
                </h2>
                <p>
                  <small>
                    {a.incomingProtocol.toUpperCase()} {a.incoming.host}:{a.incoming.port} ({a.incoming.security}) · SMTP{" "}
                    {a.outgoing.host}:{a.outgoing.port} ({a.outgoing.security}) · {a.unreadCount} unread
                  </small>
                </p>
                <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <button type="button" onClick={() => void testAccount(a.id)}>
                    Test connection
                  </button>
                  {confirmRemove === a.id ? (
                    <>
                      <button type="button" onClick={() => void removeAccount(a.id)}>
                        Confirm remove {a.email}
                      </button>
                      <button type="button" onClick={() => setConfirmRemove(null)}>
                        Keep
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setConfirmRemove(a.id)}>
                      Remove…
                    </button>
                  )}
                </div>
                {(testResults[a.id] ?? []).map((r, i) => (
                  <p key={i}>
                    <small>
                      Verify {i === 0 ? "incoming" : "outgoing"}: {r.ok ? "✓ ok" : "✕ failed"} —{" "}
                      {r.steps.map((s) => `${s.stage}:${s.ok ? "ok" : "FAIL"}`).join(", ")}
                    </small>
                  </p>
                ))}
              </div>
            ))}
            <p>
              <button type="button" onClick={() => navigate({ name: "setup" })}>
                Add account…
              </button>
            </p>
          </>
        )}

        {section === "KIWI Security" && (
          <>
            <p>
              <label>
                Minimum TLS version (display default):{" "}
                <select value={minTls} onChange={(e) => setMinTls(e.target.value)}>
                  <option value="tls1.0">TLS 1.0</option>
                  <option value="tls1.1">TLS 1.1</option>
                  <option value="tls1.2">TLS 1.2 (recommended)</option>
                  <option value="tls1.3">TLS 1.3</option>
                </select>
              </label>
            </p>
            <p>
              <button type="button" onClick={onLock} disabled={mode !== "live"}>
                Lock now
              </button>{" "}
              <button type="button" onClick={() => void collectSignals()} disabled={mode !== "live"}>
                Collect endpoint signals
              </button>
            </p>
            {signals && (
              <pre className="kiwi-evidence" tabIndex={0}>
                {JSON.stringify(signals, null, 2)}
              </pre>
            )}
            <h2>Devices</h2>
            {devicesError && (
              <p role="alert">
                <small>{devicesError}</small>
              </p>
            )}
            {devices.length === 0 && (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>
                  {mode === "live"
                    ? "No devices registered. Pairing completes on the authenticator (Phase 4 flow)."
                    : "Device management needs the backend."}
                </small>
              </p>
            )}
            <ul>
              {devices.map((d) => (
                <li key={d.deviceId}>
                  {d.label} <small>({d.deviceId}, {d.algorithm}, {d.status})</small>{" "}
                  {confirmRevoke === d.deviceId ? (
                    <>
                      <button type="button" onClick={() => void revokeDevice(d.deviceId)}>
                        Confirm revoke
                      </button>{" "}
                      <button type="button" onClick={() => setConfirmRevoke(null)}>
                        Keep
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setConfirmRevoke(d.deviceId)} disabled={d.status === "revoked"}>
                      Revoke…
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <h2>Organization binding</h2>
            <p>
              <small>
                Current: {orgBinding ? `${orgBinding.orgId} @ ${orgBinding.baseUrl}` : "none"}
              </small>
            </p>
            <p>
              <label>
                Org id: <input type="text" value={bindOrgId} onChange={(e) => setBindOrgId(e.target.value)} />
              </label>{" "}
              <label>
                Base URL:{" "}
                <input
                  type="text"
                  value={bindUrl}
                  onChange={(e) => setBindUrl(e.target.value)}
                  placeholder="http://127.0.0.1:8471"
                  style={{ width: "14rem" }}
                />
              </label>{" "}
              <button type="button" onClick={() => void setBinding()} disabled={mode !== "live"}>
                Bind
              </button>{" "}
              <button type="button" onClick={() => void clearBinding()} disabled={mode !== "live" || !orgBinding}>
                Clear
              </button>
            </p>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>Loopback URLs only — the backend rejects anything else.</small>
            </p>
          </>
        )}

        {section === "Templates" && (
          <>
            <ul>
              {templates.map((t) => (
                <li key={t}>
                  {t}{" "}
                  <button type="button" onClick={() => setTemplates((x) => x.filter((y) => y !== t))} aria-label={`Delete template ${t}`}>
                    Delete
                  </button>
                </li>
              ))}
            </ul>
            <p>
              <label>
                New template: <input type="text" value={newTemplate} onChange={(e) => setNewTemplate(e.target.value)} />{" "}
                <button
                  type="button"
                  disabled={!newTemplate.trim()}
                  onClick={() => {
                    setTemplates((x) => [...x, newTemplate.trim()]);
                    setNewTemplate("");
                  }}
                >
                  Add
                </button>
              </label>
            </p>
          </>
        )}

        {section === "Privacy" && (
          <p>
            Remote content: blocked by default. Read receipts and link tracking are <strong>off</strong> and stay off
            pending owner sign-off (ARCHITECTURE.md §4).
          </p>
        )}

        {(section === "Notifications" || section === "Advanced") && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>Scaffold placeholder — backend preferences arrive with a future settings command.</small>
          </p>
        )}
      </section>
    </div>
  );
}
