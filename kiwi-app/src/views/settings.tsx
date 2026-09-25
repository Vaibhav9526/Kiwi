/**
 * Settings (T-143…T-167): prefs sections; Accounts (per-account pane:
 * test/remove/reconfigure/set-default, re-probe, sync frequency, signature),
 * devices, org binding, endpoint signals, Appearance (theme/accent/density),
 * Notifications (toasts/sound/mute), Privacy (remote-content + receipts),
 * Advanced. Live prefs sync through the kiwi_prefs_* key/value store
 * (T-175/T-237) with localStorage fallback (T-167). Secrets never appear here.
 */
import { useEffect, useRef, useState } from "react";
import type { ComponentProps } from "react";
import { accountPref, applyPrefsBag, applyUiPrefs, collectPrefs, loadMuted, loadPref, savePref } from "../prefs";
import { api, BackendUnavailableError, IpcError } from "../ipc";
import type { AccountView, DeviceView, OAuth2StatusView, VerifyResult } from "../kiwi";
import { OAuth2SignIn, oauth2ProviderLabel } from "../components/oauth2";
import { navigate } from "../router";
import { EDIT_HANDOFF_KEY, localAutoconfigGuess } from "./setup";
import { FiltersView } from "./filters";
import { IntegrationsView } from "./integrations";
import { SHORTCUT_ROWS } from "../components/shortcuts";
import { Icon } from "../components/icons/index";
import { ThemePicker, useTheme } from "../themes";

// T-191 tabbed preferences (Mailspring idiom): the eight legacy sections
// fold into seven tabs — General (general + notifications + privacy +
// advanced), Accounts, Identity (KIWI Security), Appearance (appearance +
// templates), Shortcuts, Mail Rules (embedded filters), Integrations
// (temp mail + deliverability, T-242).
const SECTIONS = ["General", "Accounts", "Identity", "Appearance", "Shortcuts", "Mail Rules", "Integrations"] as const;
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
  filters,
}: {
  mode: "live" | "demo";
  accounts: AccountView[];
  orgBinding: { orgId: string; baseUrl: string } | null;
  onAccountsChanged: () => void;
  onStatusChanged: () => void;
  onOrgChanged: () => void;
  onLock: () => void;
  /** Mail Rules tab embeds the filters surface (same props as the route). */
  filters?: ComponentProps<typeof FiltersView>;
}) {
  const [section, setSection] = useState<Section>("General");
  // T-275: theme is owned by useTheme() — the ThemePicker (Appearance tab)
  // and TopBar select write through it; backend bag merges dispatch
  // kiwi-theme via applyPrefsBag, so no manual pref re-read is needed.
  const { theme: themeDefault } = useTheme();
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
  const [poll, setPoll] = useState(() => loadPref("kiwi.poll", "manual"));
  const [remoteState, setRemoteState] = useState<Record<string, boolean>>({});
  const [remoteBusy, setRemoteBusy] = useState<string | null>(null);
  const [draftCount, setDraftCount] = useState(0);
  // OAuth2 posture per account (T-243): `kiwi_oauth2_status` drives the
  // needs-refresh badge + inline re-auth on Accounts cards.
  const [oauth2Status, setOauth2Status] = useState<Record<string, OAuth2StatusView | null>>({});
  const [reauthFor, setReauthFor] = useState<string | null>(null);
  const [defaultId, setDefaultId] = useState(() => loadPref("kiwi.defaultAccount", ""));
  const [accent, setAccent] = useState(() => loadPref("kiwi.accent", "standard"));
  const [density, setDensity] = useState(() => loadPref("kiwi.density", "comfortable"));
  const [toasts, setToasts] = useState(() => loadPref("kiwi.toasts", "on"));
  const [sound, setSound] = useState(() => loadPref("kiwi.sound", "off"));
  const [mutedIds, setMutedIds] = useState<string[]>(() => loadMuted());
  const [syncFreq, setSyncFreq] = useState<Record<string, string>>({});
  const [signatures, setSignatures] = useState<Record<string, string>>({});
  const [probeBusy, setProbeBusy] = useState<string | null>(null);
  const [probeNote, setProbeNote] = useState<Record<string, string>>({});
  const [prefsSync, setPrefsSync] = useState<"local" | "synced" | "unavailable">("local");
  const pushTimer = useRef<number | null>(null);

  useEffect(() => savePref("kiwi.grace", grace), [grace]);
  useEffect(() => savePref("kiwi.minTls", minTls), [minTls]);
  useEffect(() => savePref("kiwi.templates", templates), [templates]);
  useEffect(() => savePref("kiwi.poll", poll), [poll]);
  useEffect(() => savePref("kiwi.defaultAccount", defaultId), [defaultId]);
  useEffect(() => {
    savePref("kiwi.accent", accent);
    applyUiPrefs();
  }, [accent]);
  useEffect(() => {
    savePref("kiwi.density", density);
    applyUiPrefs();
  }, [density]);
  useEffect(() => savePref("kiwi.toasts", toasts), [toasts]);
  useEffect(() => savePref("kiwi.sound", sound), [sound]);
  useEffect(() => savePref("kiwi.muted", mutedIds), [mutedIds]);

  // Backend prefs push (T-167/T-237): best-effort, debounced; any failure
  // leaves the badge at "unavailable" while localStorage stays the truth.
  const schedulePush = () => {
    if (mode !== "live") {
      setPrefsSync("local");
      return;
    }
    if (pushTimer.current !== null) window.clearTimeout(pushTimer.current);
    pushTimer.current = window.setTimeout(() => {
      void (async () => {
        try {
          await api.setPrefs(collectPrefs());
          setPrefsSync("synced");
        } catch {
          setPrefsSync("unavailable");
        }
      })();
    }, 600);
  };
  useEffect(() => schedulePush(), [themeDefault, grace, minTls, templates, poll, defaultId, accent, density, toasts, sound, mutedIds, syncFreq, signatures, mode]);
  useEffect(() => () => {
    if (pushTimer.current !== null) window.clearTimeout(pushTimer.current);
  }, []);

  // Backend prefs pull (T-167): backend bag wins where present, then state
  // re-reads from storage. Silent when the commands are absent.
  useEffect(() => {
    if (mode !== "live") return;
    void (async () => {
      try {
        const bag = await api.getPrefs();
        applyPrefsBag(bag);
        // theme state re-syncs via the kiwi-theme event applyPrefsBag emits.
        setGrace(loadPref("kiwi.grace", "10"));
        setMinTls(loadPref("kiwi.minTls", "tls1.2"));
        setTemplates(loadPref("kiwi.templates", ["Status update", "Meeting request"]));
        setPoll(loadPref("kiwi.poll", "manual"));
        setDefaultId(loadPref("kiwi.defaultAccount", ""));
        setAccent(loadPref("kiwi.accent", "standard"));
        setDensity(loadPref("kiwi.density", "comfortable"));
        setToasts(loadPref("kiwi.toasts", "on"));
        setSound(loadPref("kiwi.sound", "off"));
        setMutedIds(loadMuted());
        setPrefsSync("synced");
      } catch (e) {
        if (!(e instanceof BackendUnavailableError)) setActionError(errText(e));
        setPrefsSync("unavailable");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  // Per-account prefs hydrate from storage as accounts arrive.
  useEffect(() => {
    setSyncFreq((m) => {
      const n = { ...m };
      for (const a of accounts) if (!(a.id in n)) n[a.id] = loadPref(accountPref("kiwi.syncFreq", a.id), "manual");
      return n;
    });
    setSignatures((m) => {
      const n = { ...m };
      for (const a of accounts) if (!(a.id in n)) n[a.id] = loadPref(accountPref("kiwi.signature", a.id), "");
      return n;
    });
  }, [accounts]);

  // OAuth2 posture per account (T-243): non-secret grant posture only —
  // authMethod/needsRefresh/credentialPresent. Failures leave null (no
  // badge rendered); the command is absent in demo mode.
  useEffect(() => {
    if (mode !== "live") return;
    let alive = true;
    void (async () => {
      const rows = await Promise.all(
        accounts.map(async (a) => {
          try {
            return [a.id, await api.oauth2Status(a.id)] as const;
          } catch {
            return [a.id, null] as const;
          }
        }),
      );
      if (alive) setOauth2Status(Object.fromEntries(rows));
    })();
    return () => {
      alive = false;
    };
  }, [accounts, mode]);

  const refreshOauth2Status = async (accountId: string) => {
    try {
      const st = await api.oauth2Status(accountId);
      setOauth2Status((m) => ({ ...m, [accountId]: st }));
    } catch {
      // Posture refresh is best-effort; the badge simply stays.
    }
  };

  /** Provider id fallback when status omits it — host-derived. */
  const oauth2ProviderFor = (a: AccountView): string => {
    const h = a.incoming.host.toLowerCase();
    if (h.includes("office365") || h.includes("outlook")) return "microsoft";
    return "google";
  };
  useEffect(() => {
    for (const [id, v] of Object.entries(syncFreq)) savePref(accountPref("kiwi.syncFreq", id), v);
  }, [syncFreq]);
  useEffect(() => {
    for (const [id, v] of Object.entries(signatures)) savePref(accountPref("kiwi.signature", id), v);
  }, [signatures]);

  /** Server re-probe (T-167): discovery chain for this address, staged as a
    * reconfigure handoff for review — never applied blindly. */
  const reprobeAccount = async (a: AccountView) => {
    setActionError(null);
    setProbeBusy(a.id);
    try {
      let found = null;
      let source = "local-guess";
      try {
        found = await api.lookupAutoconfig(a.email);
        if (found) source = found.source;
      } catch {
        found = null;
      }
      const guess = found ?? localAutoconfigGuess(a.email);
      if (!guess) {
        setProbeNote((m) => ({ ...m, [a.id]: "Discovery found nothing — edit servers in the wizard manually." }));
        return;
      }
      window.localStorage.setItem(
        EDIT_HANDOFF_KEY,
        JSON.stringify({
          email: a.email,
          displayName: a.displayName,
          protocol: guess.protocol,
          inHost: guess.inHost,
          inPort: guess.inPort,
          inSec: guess.inSec,
          outHost: guess.outHost,
          outPort: guess.outPort,
          outSec: guess.outSec,
          username: guess.username || a.username,
        }),
      );
      setProbeNote((m) => ({
        ...m,
        [a.id]: `Probed from ${source}. Staged for review — open the wizard to verify before saving.`,
      }));
    } catch (e) {
      setActionError(errText(e));
    } finally {
      setProbeBusy(null);
    }
  };

  const toggleMute = (id: string) => {
    setMutedIds((ids) => (ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]));
  };

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
    if (section === "Identity") void loadDevices();
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
      if (defaultId === id) setDefaultId("");
      onAccountsChanged();
    } catch (e) {
      setActionError(errText(e));
    }
  };

  /** Reconfigure: hand server fields (never secrets) to the wizard, which
    * prefills for verify + add. No edit command exists in kiwi.ipc/1, so
    * saving creates a new entry and the old one is removed afterwards. */
  const reconfigureAccount = (a: AccountView) => {
    setActionError(null);
    try {
      window.localStorage.setItem(
        EDIT_HANDOFF_KEY,
        JSON.stringify({
          email: a.email,
          displayName: a.displayName,
          protocol: a.incomingProtocol,
          inHost: a.incoming.host,
          inPort: a.incoming.port,
          inSec: a.incoming.security,
          outHost: a.outgoing.host,
          outPort: a.outgoing.port,
          outSec: a.outgoing.security,
          username: a.username,
        }),
      );
      navigate({ name: "setup" });
    } catch {
      setActionError("Could not stage the reconfigure handoff (storage unavailable).");
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

  const toggleRemote = async (id: string, allowed: boolean) => {
    setActionError(null);
    setRemoteBusy(id);
    try {
      const v = await api.setRemoteContent(id, allowed);
      setRemoteState((m) => ({ ...m, [v.accountId]: v.remoteContentAllowed }));
    } catch (e) {
      setActionError(errText(e));
    } finally {
      setRemoteBusy(null);
    }
  };

  const countDrafts = () => {
    try {
      let n = 0;
      for (let i = 0; i < window.localStorage.length; i++) {
        if (window.localStorage.key(i)?.startsWith("kiwi.draft.")) n++;
      }
      setDraftCount(n);
    } catch {
      setDraftCount(0);
    }
  };

  useEffect(() => {
    if (section === "General") countDrafts();
  }, [section]);

  const clearDrafts = () => {
    try {
      const doomed: string[] = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const k = window.localStorage.key(i);
        if (k?.startsWith("kiwi.draft.")) doomed.push(k);
      }
      for (const k of doomed) window.localStorage.removeItem(k);
    } catch {
      // Best-effort — the count below says what remains.
    }
    countDrafts();
  };

  return (
    <div className="ms-prefs ms-view-enter">
      <div
        className="ms-tabs"
        role="tablist"
        aria-label="Preferences"
        onKeyDown={(e) => {
          const tabs = Array.from(
            (e.currentTarget as HTMLElement).querySelectorAll<HTMLElement>('[role="tab"]'),
          );
          const i = tabs.indexOf(e.target as HTMLElement);
          if (i < 0) return;
          let n: number | null = null;
          if (e.key === "ArrowRight" || e.key === "ArrowDown") n = (i + 1) % tabs.length;
          else if (e.key === "ArrowLeft" || e.key === "ArrowUp") n = (i - 1 + tabs.length) % tabs.length;
          else if (e.key === "Home") n = 0;
          else if (e.key === "End") n = tabs.length - 1;
          if (n !== null) {
            e.preventDefault();
            setSection(SECTIONS[n]);
            tabs[n]?.focus();
          }
        }}
      >
        {SECTIONS.map((s) => (
          <button
            key={s}
            type="button"
            role="tab"
            aria-selected={s === section}
            className="ms-tab"
            tabIndex={s === section ? 0 : -1}
            onClick={() => setSection(s)}
          >
            {s}
          </button>
        ))}
      </div>
      <section aria-label={`${section} settings`} role="tabpanel">
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
                Undo-send grace window:{" "}
                <select value={grace} onChange={(e) => setGrace(e.target.value)}>
                  <option value="5">5 seconds</option>
                  <option value="10">10 seconds</option>
                  <option value="20">20 seconds</option>
                  <option value="30">30 seconds</option>
                </select>
              </label>
            </p>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                Prefs store: {mode === "live" ? (prefsSync === "synced" ? "backend + this device" : prefsSync === "unavailable" ? "this device (backend prefs IPC absent)" : "this device") : "this device (demo)"}.
              </small>
            </p>
          </>
        )}

        {section === "Appearance" && (
          <>
            {/* T-268 picker (T-275 landed): stock + sideloaded theme packages,
                System option, instant apply via data-theme on root. */}
            <ThemePicker />
            <p>
              <label>
                Accent intensity:{" "}
                <select value={accent} onChange={(e) => setAccent(e.target.value)}>
                  <option value="subtle">Subtle (flat brand)</option>
                  <option value="standard">Standard</option>
                  <option value="vivid">Vivid (strong glow)</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Density:{" "}
                <select value={density} onChange={(e) => setDensity(e.target.value)}>
                  <option value="comfortable">Comfortable</option>
                  <option value="compact">Compact</option>
                </select>
              </label>
            </p>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>Applies instantly on this device; the theme switcher in the top bar changes the live session.</small>
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
                  {a.displayName} <small style={{ color: "var(--kiwi-text-secondary)" }}>{a.email}</small>{" "}
                  {defaultId === a.id && (
                    <span className="kiwi-pill secure" title="Default sending account">
                      <Icon name="check" size={10} /> default
                    </span>
                  )}
                  {mutedIds.includes(a.id) && (
                    <span className="kiwi-pill unknown" title="Muted — unread excluded from counts">
                      muted
                    </span>
                  )}
                  {(() => {
                    const st = oauth2Status[a.id];
                    if (!st || st.authMethod !== "xoauth2") return null;
                    const stale = !st.credentialPresent || st.needsRefresh === true;
                    return (
                      <span
                        className={`kiwi-pill ${stale ? "warning" : "secure"}`}
                        title={`OAuth2 grant posture (kiwi_oauth2_status) — token material stays in the OS credential store.${st.credentialPresent === false ? " No credential stored at the account's key." : ""}${st.needsRefresh === true ? " Token is at/past its refresh window." : ""}`}
                      >
                        OAuth2{st.provider ? ` · ${oauth2ProviderLabel(st.provider)}` : ""}
                        {stale ? " — re-auth needed" : ""}
                      </span>
                    );
                  })()}
                </h2>
                <p>
                  <small>
                    {a.incomingProtocol.toUpperCase()} {a.incoming.host}:{a.incoming.port} ({a.incoming.security}) · SMTP{" "}
                    {a.outgoing.host}:{a.outgoing.port} ({a.outgoing.security}) · {a.unreadCount} unread
                  </small>
                </p>
                <p style={{ color: "var(--kiwi-text-secondary)" }}>
                  <small>
                    Display name “{a.displayName}” is backend-owned — rename via Reconfigure… below (no rename
                    command in kiwi.ipc/1; saving creates a new entry, then remove this one).
                  </small>
                </p>
                {(() => {
                  const st = oauth2Status[a.id];
                  if (!st || st.authMethod !== "xoauth2") return null;
                  const stale = !st.credentialPresent || st.needsRefresh === true;
                  if (reauthFor === a.id) {
                    const provider = st.provider ?? oauth2ProviderFor(a);
                    return (
                      <OAuth2SignIn
                        provider={provider}
                        email={st.email ?? a.email}
                        buttonLabel={`Sign in with ${oauth2ProviderLabel(provider)} again`}
                        onDone={() => {
                          // Completing the grant re-wrote the token at the
                          // same credential-store key — no re-add needed.
                          setReauthFor(null);
                          void refreshOauth2Status(a.id);
                        }}
                        onCancel={() => setReauthFor(null)}
                      />
                    );
                  }
                  if (!stale) return null;
                  return (
                    <p>
                      <button type="button" onClick={() => setReauthFor(a.id)}>
                        Re-authorize {st.provider ? oauth2ProviderLabel(st.provider) : "OAuth2"} sign-in
                      </button>
                    </p>
                  );
                })()}
                <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <button type="button" onClick={() => void testAccount(a.id)}>
                    Test connection
                  </button>
                  <button
                    type="button"
                    onClick={() => void reprobeAccount(a)}
                    disabled={probeBusy === a.id}
                    title="Re-run autoconfig discovery for this address, staged for review"
                  >
                    {probeBusy === a.id ? "Probing…" : "Re-probe servers"}
                  </button>
                  <button type="button" onClick={() => reconfigureAccount(a)} disabled={mode !== "live"}>
                    Reconfigure…
                  </button>
                  {defaultId === a.id ? (
                    <button type="button" onClick={() => setDefaultId("")}>
                      Clear default
                    </button>
                  ) : (
                    <button type="button" onClick={() => setDefaultId(a.id)}>
                      Set as default
                    </button>
                  )}
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
                      Verify {i === 0 ? "incoming" : "outgoing"}: <Icon name={r.ok ? "check" : "close"} size={10} /> {r.ok ? "ok" : "failed"} —{" "}
                      {r.steps.map((s) => `${s.stage}:${s.ok ? "ok" : "FAIL"}`).join(", ")}
                    </small>
                  </p>
                ))}
                {probeNote[a.id] && (
                  <div className="kiwi-banner warn" role="status">
                    <small>
                      {probeNote[a.id]}{" "}
                      <button type="button" onClick={() => navigate({ name: "setup" })}>
                        Review in wizard
                      </button>
                    </small>
                  </div>
                )}
                <p>
                  <label>
                    Sync frequency:{" "}
                    <select
                      value={syncFreq[a.id] ?? "manual"}
                      onChange={(e) => setSyncFreq((m) => ({ ...m, [a.id]: e.target.value }))}
                      aria-label={`Sync frequency for ${a.email}`}
                    >
                      <option value="manual">Manual only</option>
                      <option value="5">Every 5 minutes</option>
                      <option value="15">Every 15 minutes</option>
                      <option value="60">Hourly</option>
                    </select>
                  </label>{" "}
                  <small style={{ color: "var(--kiwi-text-secondary)" }}>
                    Stored for the future background scheduler; today sync is manual (Sync button).
                  </small>
                </p>
                <p>
                  <label>
                    Mute this account{" "}
                    <input type="checkbox" checked={mutedIds.includes(a.id)} onChange={() => toggleMute(a.id)} aria-label={`Mute ${a.email}`} />
                  </label>{" "}
                  <small style={{ color: "var(--kiwi-text-secondary)" }}>
                    Hides unread from counts and tags the sidebar entry. Mail still syncs.
                  </small>
                </p>
                <p>
                  <label htmlFor={`sig-${a.id}`}>Signature</label>
                  <br />
                  <textarea
                    id={`sig-${a.id}`}
                    rows={3}
                    value={signatures[a.id] ?? ""}
                    onChange={(e) => setSignatures((m) => ({ ...m, [a.id]: e.target.value }))}
                    placeholder="—&#10;Sent from KIWI"
                    style={{ width: "100%", maxWidth: "30rem" }}
                  />
                </p>
              </div>
            ))}
            <p>
              <button type="button" onClick={() => navigate({ name: "setup" })}>
                Add account…
              </button>
            </p>
          </>
        )}

        {section === "Identity" && (
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
                  {d.label}{" "}
                  <small>
                    ({d.deviceId}, {d.algorithm}, {d.status}, fp …{d.keyFingerprintTail}
                    {d.revokedUnix != null && `, revoked ${new Date(d.revokedUnix * 1000).toLocaleDateString()}`})
                  </small>{" "}
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

        {section === "Appearance" && (
          <>
            <h2>Templates</h2>
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

        {section === "General" && (
          <>
            <h2>Privacy</h2>
            <p>
              <small>
                Default for every account: <strong>blocked</strong> (backend-enforced; tracking surface). Opt in
                per account below — audited server-side.
              </small>
            </p>
            <p>
              <small>
                Read receipts: <strong>stripped, always</strong> — the client never sends them and renders no
                tracking pixels (remote content stays blocked). Link tracking stays off pending owner sign-off
                (ARCHITECTURE.md §4).
              </small>
            </p>
            <h2>Remote content per account</h2>
            {mode === "demo" ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>Demo mode — toggling needs the backend. Run the Tauri app for live settings.</small>
              </p>
            ) : accounts.length === 0 ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>No accounts yet — add one to manage remote content.</small>
              </p>
            ) : (
              <ul>
                {accounts.map((a) => {
                  const state = remoteState[a.id];
                  return (
                    <li key={a.id}>
                      {a.displayName} <small>({a.email})</small> —{" "}
                      <small>
                        {state === undefined ? "currently blocked (backend default; unchanged this session)" : state ? "allowed" : "blocked"}
                      </small>{" "}
                      <button
                        type="button"
                        disabled={remoteBusy === a.id}
                        onClick={() => void toggleRemote(a.id, !(state ?? false))}
                      >
                        {remoteBusy === a.id ? "Saving…" : state ? "Block" : "Allow"}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                Applies to rendered HTML bodies (kiwi_set_remote_content, audited server-side). Remote images are a
                tracking surface — allow only for senders you trust.
              </small>
            </p>
          </>
        )}

        {section === "General" && (
          <>
            <h2>Notifications</h2>
            <p>
              <label>
                Toast popups:{" "}
                <select value={toasts} onChange={(e) => setToasts(e.target.value)}>
                  <option value="on">On (send/sync/policy events)</option>
                  <option value="off">Off (in-view status only)</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Sound:{" "}
                <select value={sound} onChange={(e) => setSound(e.target.value)}>
                  <option value="off">Off</option>
                  <option value="on">On (short blip per popup)</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Background sync:{" "}
                <select value={poll} onChange={(e) => setPoll(e.target.value)}>
                  <option value="manual">Manual only</option>
                  <option value="1">Every minute</option>
                  <option value="5">Every 5 minutes</option>
                  <option value="15">Every 15 minutes</option>
                </select>
              </label>
            </p>
            <h2>Per-account mute</h2>
            {accounts.length === 0 ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>No accounts yet.</small>
              </p>
            ) : (
              <ul>
                {accounts.map((a) => (
                  <li key={a.id}>
                    <label>
                      <input
                        type="checkbox"
                        checked={mutedIds.includes(a.id)}
                        onChange={() => toggleMute(a.id)}
                        aria-label={`Mute ${a.email}`}
                      />{" "}
                      {a.displayName} <small>({a.email})</small>
                    </label>
                  </li>
                ))}
              </ul>
            )}
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                Muted accounts keep syncing but hide unread from counts and tag the sidebar. Toast/sound
                preferences are this-device-only until the backend prefs IPC lands.
              </small>
            </p>
          </>
        )}

        {section === "General" && (
          <>
            <h2>Advanced</h2>
            <p>
              <small>
                Contract: <code>kiwi.ipc/1</code> · local prefs under <code>kiwi.*</code> keys in this device's
                localStorage (never credentials or message bodies — drafts only).
              </small>
            </p>
            <p>
              <small>
                Autosaved drafts on this device: <strong>{draftCount}</strong>{" "}
                <button type="button" onClick={clearDrafts} disabled={draftCount === 0}>
                  Clear all drafts
                </button>
              </small>
            </p>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>Backend data (accounts, mail store, outbox) lives in the app data dir — managed by the backend, not here.</small>
            </p>
          </>
        )}

        {section === "Shortcuts" && (
          <>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                List shortcuts (j/k/s/e/r/u) are inactive while typing in a text field — press Esc first. The full
                overlay opens with <code>?</code>, the palette with <code>Ctrl+K</code>.
              </small>
            </p>
            <table style={{ borderCollapse: "collapse", width: "100%" }}>
              <tbody>
                {SHORTCUT_ROWS.map(([keys, what]) => (
                  <tr key={keys}>
                    <td style={{ padding: "0.3rem 0.6rem 0.3rem 0", whiteSpace: "nowrap" }}>
                      <code>{keys}</code>
                    </td>
                    <td style={{ padding: "0.3rem 0" }}>{what}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {section === "Mail Rules" && (
          <>
            {filters ? (
              <FiltersView {...filters} />
            ) : (
              <p>
                <small>
                  Mail rules need the mailbox context —{" "}
                  <button type="button" onClick={() => navigate({ name: "filters" })}>
                    open the Filters view
                  </button>
                  .
                </small>
              </p>
            )}
          </>
        )}

        {section === "Integrations" && <IntegrationsView accounts={accounts} mode={mode} />}
      </section>
    </div>
  );
}
