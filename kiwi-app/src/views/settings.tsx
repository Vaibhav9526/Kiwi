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
import type { AccountView, AppInfoView, DeviceView, FolderView, MboxExportView, MboxImportView, OAuth2StatusView, StorageStatsView, VerifyResult } from "../kiwi";
import { APP_LICENSE, APP_NAME, APP_VERSION } from "../version";
import { OAuth2SignIn, oauth2ProviderLabel } from "../components/oauth2";
import { navigate } from "../router";
import { EDIT_HANDOFF_KEY, localAutoconfigGuess } from "./setup";
import { FiltersView } from "./filters";
import { IntegrationsView } from "./integrations";
import { RulesView } from "./rules";
import { TemplatesManager } from "./templates";
import { DEMO_ACCOUNTS } from "../mock";
import { SHORTCUT_ROWS } from "../components/shortcuts";
import { Icon, isIconName } from "../components/icons/index";
import { PairQrFlow } from "../components/pair";
import { ThemePicker, useTheme } from "../themes";
import { emitToPlugin, installPlugin, removePlugin, setPluginEnabled, useInstalledPlugins, usePluginPanes } from "../plugins";

// T-191 tabbed preferences (Mailspring idiom): the eight legacy sections
// fold into seven tabs — General (general + notifications + privacy +
// advanced), Accounts, Identity (KIWI Security), Appearance (appearance +
// templates), Shortcuts, Mail Rules (embedded filters), Integrations
// (temp mail + deliverability, T-242). T-315 appends About.
const SECTIONS = ["General", "Accounts", "Identity", "Appearance", "Shortcuts", "Mail Rules", "Integrations", "Plugins", "About"] as const;
type Section = (typeof SECTIONS)[number];

function errText(e: unknown): string {
  return e instanceof IpcError ? `${e.code}: ${e.message}` : e instanceof Error ? e.message : String(e);
}

/** Human byte size (T-333) — binary units, one decimal above 1 KiB. */
function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KiB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MiB`;
  return `${(b / 1073741824).toFixed(1)} GiB`;
}

export function SettingsView({
  mode,
  accounts,
  appInfo,
  orgBinding,
  onAccountsChanged,
  onStatusChanged,
  onOrgChanged,
  onLock,
  filters,
  folderLists,
}: {
  mode: "live" | "demo";
  accounts: AccountView[];
  /** Backend self-report (kiwi_app_info) — null in demo/unavailable. */
  appInfo?: AppInfoView | null;
  orgBinding: { orgId: string; baseUrl: string } | null;
  onAccountsChanged: () => void;
  onStatusChanged: () => void;
  onOrgChanged: () => void;
  onLock: () => void;
  /** Mail Rules tab embeds the filters surface (same props as the route). */
  filters?: ComponentProps<typeof FiltersView>;
  /** Real folder list per account — the rules editor's move-folder picker. */
  folderLists?: Record<string, FolderView[]>;
}) {
  const [section, setSection] = useState<Section>("General");
  // T-275: theme is owned by useTheme() — the ThemePicker (Appearance tab)
  // and TopBar select write through it; backend bag merges dispatch
  // kiwi-theme via applyPrefsBag, so no manual pref re-read is needed.
  const { theme: themeDefault } = useTheme();
  // T-280: plugin surface — installed records + registered panes (live via
  // the kiwi-plugins-changed / pane-store subscriptions).
  const installedPlugins = useInstalledPlugins();
  const pluginPanes = usePluginPanes();
  const [grace, setGrace] = useState(() => loadPref("kiwi.grace", "10"));
  const [minTls, setMinTls] = useState(() => loadPref("kiwi.minTls", "tls1.2"));
  const [devices, setDevices] = useState<DeviceView[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [pairOpen, setPairOpen] = useState(false);
  /** This desktop's own device id (SecurityStatusView.deviceId) — marks the
   *  "this device" row when the local endpoint is registered (T-308). */
  const [localDeviceId, setLocalDeviceId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, VerifyResult[]>>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [pluginErrs, setPluginErrs] = useState<string[]>([]);
  const pluginFileRef = useRef<HTMLInputElement>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [bindOrgId, setBindOrgId] = useState("");
  const [bindUrl, setBindUrl] = useState("");
  const [signals, setSignals] = useState<Record<string, unknown> | null>(null);
  const [poll, setPoll] = useState(() => loadPref("kiwi.poll", "manual"));
  const [remoteState, setRemoteState] = useState<Record<string, boolean>>({});
  const [remoteBusy, setRemoteBusy] = useState<string | null>(null);
  const [draftCount, setDraftCount] = useState(0);
  // T-318: mbox import (kiwi_import_mbox) + export (kiwi_mailbox_export_mbox)
  // — path inputs match the existing destPath idiom (no dialog plugin in
  // this shell). Results render verbatim counts; failures surface inline.
  const [importFor, setImportFor] = useState<string | null>(null);
  const [importPath, setImportPath] = useState("");
  const [importFolder, setImportFolder] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [importResult, setImportResult] = useState<MboxImportView | null>(null);
  const [exportSel, setExportSel] = useState(""); // "accountId:folderId"
  const [exportPath, setExportPath] = useState("");
  const [exportBusy, setExportBusy] = useState(false);
  const [exportResult, setExportResult] = useState<MboxExportView | null>(null);
  // T-333: storage diagnostics (kiwi_storage_stats/compact, ipc.md §8) —
  // About tab. null stats = not loaded; demo never fetches (no backend).
  const [storage, setStorage] = useState<StorageStatsView | null>(null);
  const [storageLoading, setStorageLoading] = useState(false);
  const [storageErr, setStorageErr] = useState<string | null>(null);
  const [compactConfirm, setCompactConfirm] = useState(false);
  const [compactBusy, setCompactBusy] = useState(false);
  const [compactNote, setCompactNote] = useState<string | null>(null);
  const [compactErr, setCompactErr] = useState<string | null>(null);
  // OAuth2 posture per account (T-243): `kiwi_oauth2_status` drives the
  // needs-refresh badge + inline re-auth on Accounts cards.
  const [oauth2Status, setOauth2Status] = useState<Record<string, OAuth2StatusView | null>>({});
  const [reauthFor, setReauthFor] = useState<string | null>(null);
  const [defaultId, setDefaultId] = useState(() => loadPref("kiwi.defaultAccount", ""));
  const [accent, setAccent] = useState(() => loadPref("kiwi.accent", "standard"));
  const [density, setDensity] = useState(() => loadPref("kiwi.density", "comfortable"));
  const [toasts, setToasts] = useState(() => loadPref("kiwi.toasts", "on"));
  const [sound, setSound] = useState(() => loadPref("kiwi.sound", "off"));
  const [osNotify, setOsNotify] = useState(() => loadPref("kiwi.notify", "on"));
  const [mutedIds, setMutedIds] = useState<string[]>(() => loadMuted());
  const [syncFreq, setSyncFreq] = useState<Record<string, string>>({});
  const [signatures, setSignatures] = useState<Record<string, string>>({});
  const [probeBusy, setProbeBusy] = useState<string | null>(null);
  const [probeNote, setProbeNote] = useState<Record<string, string>>({});
  const [prefsSync, setPrefsSync] = useState<"local" | "synced" | "unavailable">("local");
  const pushTimer = useRef<number | null>(null);

  useEffect(() => savePref("kiwi.grace", grace), [grace]);
  useEffect(() => savePref("kiwi.minTls", minTls), [minTls]);
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
  useEffect(() => savePref("kiwi.notify", osNotify), [osNotify]);
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
  useEffect(() => schedulePush(), [themeDefault, grace, minTls, poll, defaultId, accent, density, toasts, sound, osNotify, mutedIds, syncFreq, signatures, mode]);
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
        setPoll(loadPref("kiwi.poll", "manual"));
        setDefaultId(loadPref("kiwi.defaultAccount", ""));
        setAccent(loadPref("kiwi.accent", "standard"));
        setDensity(loadPref("kiwi.density", "comfortable"));
        setToasts(loadPref("kiwi.toasts", "on"));
        setSound(loadPref("kiwi.sound", "off"));
        setOsNotify(loadPref("kiwi.notify", "on"));
        setMutedIds(loadMuted());
        setPrefsSync("synced");
      } catch (e) {
        if (!(e instanceof BackendUnavailableError)) setActionError(errText(e));
        setPrefsSync("unavailable");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  // T-333: storage stats load when the About section is shown (live only).
  useEffect(() => {
    if (section !== "About" || mode !== "live") {
      setStorage(null);
      setStorageErr(null);
      return;
    }
    let cancelled = false;
    setStorageLoading(true);
    void api
      .storageStats()
      .then((s) => {
        if (!cancelled) setStorage(s);
      })
      .catch((e) => {
        if (!cancelled) setStorageErr(errText(e));
      })
      .finally(() => {
        if (!cancelled) setStorageLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [section, mode]);

  const runCompact = async () => {
    setCompactBusy(true);
    setCompactErr(null);
    setCompactNote(null);
    try {
      const r = await api.storageCompact();
      const fmt = (b: number | null) => (b === null ? "unmeasurable" : fmtBytes(b));
      setCompactNote(`Compacted — ${fmt(r.beforeDbBytes)} → ${fmt(r.afterDbBytes)}.`);
      // Refresh stats so the dl shows the post-VACUUM size.
      void api.storageStats().then(setStorage).catch(() => {});
    } catch (e) {
      setCompactErr(errText(e));
    } finally {
      setCompactBusy(false);
      setCompactConfirm(false);
    }
  };

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
      const [rows, status] = await Promise.all([api.listDevices(), api.securityStatus()]);
      setDevices(rows);
      setLocalDeviceId(status.deviceId);
    } catch (e) {
      setDevicesError(errText(e));
    }
  };

  /**
   * T-307 sideload install: read every picked package file as text
   * (webkitRelativePath carries the folder layout; the top-level dir name is
   * stripped so `manifest.json` lands at the package root). Registry-side
   * validation (manifest schema, capability names, safe paths) returns
   * readable errors which surface verbatim in the banner — no silent fails.
   */
  const installPluginFiles = async (files: FileList | null, input: HTMLInputElement) => {
    if (!files || files.length === 0) return;
    // FileList is live — snapshot the File objects BEFORE clearing the input,
    // or input.value="" empties the list and silently drops the pick.
    const picked = Array.from(files);
    input.value = ""; // allow re-picking the same folder
    const errs: string[] = [];
    const map: Record<string, string> = {};
    const MAX_FILES = 64;
    const MAX_BYTES = 512 * 1024;
    if (picked.length > MAX_FILES) errs.push(`package has ${picked.length} files — max ${MAX_FILES}`);
    for (const f of picked.slice(0, MAX_FILES)) {
      const rel = (f.webkitRelativePath || f.name).split("/").slice(1).join("/") || f.name;
      if (f.size > MAX_BYTES) {
        errs.push(`"${rel}" is ${Math.ceil(f.size / 1024)}KB — max 512KB`);
        continue;
      }
      try {
        map[rel] = await f.text();
      } catch {
        errs.push(`couldn't read "${rel}"`);
      }
    }
    if (errs.length === 0 && !("manifest.json" in map)) {
      errs.push("no manifest.json at the package root — pick the plugin folder itself");
    }
    if (errs.length === 0) {
      const r = installPlugin(map["manifest.json"], map);
      if (!r.ok) errs.push(...(r.errors ?? ["install failed"]));
    }
    setPluginErrs(errs);
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

  /** T-318 import: client rejects non-.mbox picks before the IPC (the
   * backend's own "no `From ` separator" check is the authoritative one);
   * the result card shows the returned counts verbatim. */
  const runImport = async (accountId: string) => {
    setActionError(null);
    setImportResult(null);
    const path = importPath.trim();
    if (!path) {
      setActionError("Enter the .mbox file path first.");
      return;
    }
    if (!/\.mbox$/i.test(path)) {
      setActionError("Not an .mbox file — pick a Berkeley-mbox file whose name ends in .mbox.");
      return;
    }
    setImportBusy(true);
    try {
      setImportResult(await api.importMbox(accountId, path, importFolder.trim() || undefined));
    } catch (e) {
      setActionError(errText(e));
    } finally {
      setImportBusy(false);
    }
  };

  /** T-318 export: folder select holds "accountId:folderId"; dest path is a
   * typed input (same idiom as attachment download — no dialog plugin).
   * `.mbox` is appended when missing so the produced file matches the name
   * shown in the result line. */
  const runExport = async () => {
    setActionError(null);
    setExportResult(null);
    const folderId = Number(exportSel.split(":")[1]);
    let path = exportPath.trim();
    if (!Number.isFinite(folderId) || folderId <= 0) {
      setActionError("Pick a folder to export.");
      return;
    }
    if (!path) {
      setActionError("Enter a destination path for the .mbox file.");
      return;
    }
    if (!/\.mbox$/i.test(path)) path = `${path}.mbox`;
    setExportBusy(true);
    try {
      const r = await api.mailboxExportMbox(folderId, path);
      setExportPath(path); // result line echoes the real destination used
      setExportResult(r);
    } catch (e) {
      setActionError(errText(e));
    } finally {
      setExportBusy(false);
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
                {importFor === a.id ? (
                  <div className="kiwi-banner" role="group" aria-label={`Import mbox into ${a.email}`}>
                    <p style={{ marginTop: 0 }}>
                      <label htmlFor={`mbox-path-${a.id}`}>Import .mbox file</label>
                      <br />
                      <input
                        id={`mbox-path-${a.id}`}
                        type="text"
                        value={importPath}
                        onChange={(e) => setImportPath(e.target.value)}
                        placeholder="C:\\…\\archive.mbox"
                        style={{ width: "100%", maxWidth: "26rem" }}
                        disabled={importBusy}
                      />
                    </p>
                    <p>
                      <label htmlFor={`mbox-folder-${a.id}`}>Target folder</label>
                      <br />
                      <input
                        id={`mbox-folder-${a.id}`}
                        type="text"
                        value={importFolder}
                        onChange={(e) => setImportFolder(e.target.value)}
                        placeholder="Import"
                        style={{ width: "12rem" }}
                        disabled={importBusy}
                      />{" "}
                      <small style={{ color: "var(--kiwi-text-secondary)" }}>
                        empty = the local “Import” folder
                      </small>
                    </p>
                    <p>
                      <button type="button" onClick={() => void runImport(a.id)} disabled={importBusy}>
                        {importBusy ? "Importing…" : "Import"}
                      </button>{" "}
                      <button
                        type="button"
                        disabled={importBusy}
                        onClick={() => {
                          setImportFor(null);
                          setImportResult(null);
                          setActionError(null);
                        }}
                      >
                        Cancel
                      </button>{" "}
                      {importBusy && (
                        <small style={{ color: "var(--kiwi-text-secondary)" }}>
                          kiwi_import_mbox — parsing and ingesting members…
                        </small>
                      )}
                    </p>
                    {importResult && (
                      <p role="status" style={{ marginBottom: 0 }}>
                        <small>
                          <Icon name="check" size={10} /> Imported <b>{importResult.imported}</b> of{" "}
                          {importResult.messagesFound} members into “{importResult.folder}”
                          {importResult.skippedDuplicates > 0 && <> · {importResult.skippedDuplicates} duplicates skipped</>}
                          {importResult.skippedExpunged > 0 && <> · {importResult.skippedExpunged} expunged skipped</>}
                          {importResult.failed > 0 && <> · {importResult.failed} failed</>}
                          {importResult.ruleFailures > 0 && <> · {importResult.ruleFailures} rule failures</>}
                          {importResult.truncated && <> · <b>truncated</b> — member cap hit, file not fully read</>}
                          {importResult.imported === 0 &&
                            importResult.skippedDuplicates === 0 &&
                            importResult.skippedExpunged === 0 &&
                            importResult.failed === 0 && <> — nothing to import</>}
                          {importResult.issues.slice(0, 5).map((iss) => (
                            <span key={iss.index} style={{ display: "block" }}>
                              · member {iss.index}: {iss.detail}
                            </span>
                          ))}
                          {importResult.issues.length > 5 && (
                            <span style={{ display: "block" }}>· +{importResult.issues.length - 5} more issues</span>
                          )}
                        </small>
                      </p>
                    )}
                  </div>
                ) : (
                  <p>
                    <button
                      type="button"
                      disabled={mode !== "live"}
                      title={mode !== "live" ? "Import needs the backend — demo mode has no mailbox store" : undefined}
                      onClick={() => {
                        setImportFor(a.id);
                        setImportPath("");
                        setImportFolder("");
                        setImportResult(null);
                        setActionError(null);
                      }}
                    >
                      Import .mbox…
                    </button>{" "}
                    <small style={{ color: "var(--kiwi-text-secondary)" }}>
                      Berkeley mbox → this account (kiwi_import_mbox)
                    </small>
                  </p>
                )}
              </div>
            ))}
            {mode === "live" && accounts.length === 0 ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>No accounts yet — add one before importing or exporting mail.</small>
              </p>
            ) : (
              <div className="kiwi-card">
                <h2>
                  Export folder <small style={{ color: "var(--kiwi-text-secondary)" }}>mbox</small>
                </h2>
                {mode !== "live" ? (
                  <p style={{ color: "var(--kiwi-text-secondary)" }}>
                    <small>Export needs the backend — demo mode has no real folder store.</small>
                  </p>
                ) : (
                  <>
                    <p>
                      <label htmlFor="export-folder">Folder</label>
                      <br />
                      <select id="export-folder" value={exportSel} onChange={(e) => setExportSel(e.target.value)} disabled={exportBusy}>
                        <option value="">Choose a folder…</option>
                        {accounts.flatMap((a) =>
                          (folderLists?.[a.id] ?? []).map((f) => (
                            <option key={`${a.id}:${f.id}`} value={`${a.id}:${f.id}`}>
                              {a.email} — {f.name}
                              {f.exists === 0 ? " (empty)" : ` (${f.exists})`}
                            </option>
                          )),
                        )}
                      </select>{" "}
                      {Object.values(folderLists ?? {}).every((l) => l.length === 0) && (
                        <small style={{ color: "var(--kiwi-text-secondary)" }}>folder list empty — sync first</small>
                      )}
                    </p>
                    <p>
                      <label htmlFor="export-path">Destination</label>
                      <br />
                      <input
                        id="export-path"
                        type="text"
                        value={exportPath}
                        onChange={(e) => setExportPath(e.target.value)}
                        placeholder="C:\\…\\folder.mbox"
                        style={{ width: "100%", maxWidth: "26rem" }}
                        disabled={exportBusy}
                      />{" "}
                      <small style={{ color: "var(--kiwi-text-secondary)" }}>
                        .mbox appended if missing; written atomically
                      </small>
                    </p>
                    <p>
                      <button type="button" onClick={() => void runExport()} disabled={exportBusy || !exportSel}>
                        {exportBusy ? "Exporting…" : "Export to mbox"}
                      </button>{" "}
                      {exportBusy && (
                        <small style={{ color: "var(--kiwi-text-secondary)" }}>
                          kiwi_mailbox_export_mbox — streaming bodies to disk…
                        </small>
                      )}
                    </p>
                    {exportResult && (
                      <div className={`kiwi-banner ${exportResult.partial ? "warn" : ""}`} role="status">
                        <small>
                          <Icon name={exportResult.partial ? "alert-triangle" : "check"} size={10} /> Exported{" "}
                          <b>{exportResult.exported}</b>
                          {exportResult.skipped > 0 && <> · {exportResult.skipped} skipped (body unavailable)</>} ·{" "}
                          {exportResult.bytes.toLocaleString()} B → {exportPath.trim() || "destination"}
                          {exportResult.truncated && <> · <b>truncated</b> at the member cap</>}
                          {exportResult.partial && !exportResult.truncated && exportResult.skipped === 0 && <> · partial</>}
                          {exportResult.exported === 0 && exportResult.skipped === 0 && <> — folder was empty</>}
                        </small>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
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
            {devices.length === 0 && !pairOpen && (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>
                  {mode === "live"
                    ? "No paired devices."
                    : "Device management needs the backend."}
                </small>
              </p>
            )}
            {/* T-303: real pairing — begin issues a backend-owned ticket and
                renders its qrPayload as a scannable QR; pair_status polls to
                claimed/expired (§9d). Demo keeps an honest disabled state. */}
            {pairOpen ? (
              <div className="em-card" style={{ padding: "0.8rem", marginBottom: "0.6rem" }}>
                <PairQrFlow
                  onClaimed={() => {
                    void loadDevices();
                  }}
                />
                <p style={{ textAlign: "center", margin: "0.5rem 0 0" }}>
                  <button type="button" className="ms-btn" onClick={() => setPairOpen(false)}>
                    Close
                  </button>
                </p>
              </div>
            ) : (
              <p>
                <button
                  type="button"
                  className="ms-btn"
                  onClick={() => setPairOpen(true)}
                  disabled={mode !== "live"}
                  title={mode !== "live" ? "Device pairing needs the Tauri backend" : undefined}
                >
                  Pair new device…
                </button>
              </p>
            )}
            {/* T-308: rows project the real §9d.5 DeviceView — fingerprint
                (full dash-grouped, display-only) + keystoreRef presence +
                paired/last-seen/revoked timestamps; "this device" marks the
                local endpoint when its id appears. Nothing invented. */}
            <ul>
              {devices.map((d) => (
                <li key={d.deviceId}>
                  {d.label}{" "}
                  {d.deviceId === localDeviceId && (
                    <span className="ms-badge ms-badge-alt" title="This desktop's own device record">
                      this device
                    </span>
                  )}{" "}
                  <span
                    className={`ms-badge${d.status === "revoked" ? "" : " ms-badge-alt"}`}
                    title={
                      d.status === "revoked"
                        ? "Revoked — terminal; cannot satisfy challenges"
                        : `Status: ${d.status}`
                    }
                  >
                    {d.status}
                  </span>
                  <br />
                  <small style={{ color: "var(--kiwi-text-secondary)" }}>
                    {d.deviceId} · {d.algorithm} · paired{" "}
                    {new Date(d.registeredUnix * 1000).toLocaleDateString()} · last seen{" "}
                    {new Date(d.lastSeenUnix * 1000).toLocaleDateString()}
                    {d.revokedUnix != null &&
                      ` · revoked ${new Date(d.revokedUnix * 1000).toLocaleDateString()}`}
                    {" · keystore: "}
                    {d.keystoreRef ?? "none"}
                  </small>
                  <br />
                  <small>
                    fingerprint <code title="SHA-256 of the public key — display only, never a trust input">{d.fingerprint}</code>
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
                    <button
                      type="button"
                      onClick={() => setConfirmRevoke(d.deviceId)}
                      disabled={d.status === "revoked"}
                      title={d.status === "revoked" ? "Already revoked" : undefined}
                    >
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
            <h2>Message templates</h2>
            <TemplatesManager live={mode === "live"} />
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
                OS notifications:{" "}
                <select value={osNotify} onChange={(e) => setOsNotify(e.target.value)}>
                  <option value="on">On (new-mail ding per synced folder)</option>
                  <option value="off">Off (no OS popups)</option>
                </select>
              </label>
              {mode !== "live" && (
                <>
                  {" "}
                  <small style={{ color: "var(--kiwi-text-secondary)" }}>
                    — this build has no OS-notification channel; the pref still saves and the desktop
                    app honors it
                  </small>
                </>
              )}
            </p>
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
                Muted accounts keep syncing but hide unread from counts and tag the sidebar — and a
                muted account never raises an OS notification. OS-notification, toast, and sound
                preferences sync through the backend prefs store.
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
            {/* T-281: server-side ruleset (kiwi_rules_*) — authoritative
                management surface. The localFilters block below is the
                older prefs-backed draft engine, kept separate. */}
            <RulesView demo={mode === "demo"} accounts={accounts} folderLists={folderLists ?? {}} />
            <hr style={{ border: 0, borderTop: "1px solid var(--kiwi-border)", margin: "1rem 0" }} />
            <h3>
              Draft filters{" "}
              <small style={{ color: "var(--kiwi-text-secondary)", fontWeight: "normal" }}>
                — local prefs engine (kiwi.filterRules), run-on-list only
              </small>
            </h3>
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

        {section === "Plugins" && (
          <>
            {/* T-307: sideload install — the folder picker feeds every package
                file into installPlugin (manifest validation + capability gate
                rejections surface verbatim in the error banner). */}
            <p>
              <button
                type="button"
                className="ms-btn"
                onClick={() => pluginFileRef.current?.click()}
                title="Pick a plugin folder containing manifest.json — sideloaded plugins run as trusted code (see src/plugins/GETTING-STARTED.md)"
              >
                <Icon name="puzzle" size={13} /> Install plugin…
              </button>{" "}
              <small style={{ color: "var(--kiwi-text-secondary)" }}>
                Sideload-only alpha — plugins run as trusted code in a Worker (no DOM/localStorage).
              </small>
            </p>
            <input
              ref={pluginFileRef}
              type="file"
              // @ts-expect-error webkitdirectory is non-standard but supported by WebView2/WKWebView/Chromium
              webkitdirectory=""
              multiple
              style={{ display: "none" }}
              aria-label="Plugin package folder"
              onChange={(e) => void installPluginFiles(e.target.files, e.target)}
            />
            {pluginErrs.length > 0 && (
              <div className="kiwi-banner error" role="alert">
                <small>
                  Plugin not installed:
                  <ul style={{ margin: "0.2rem 0 0", paddingLeft: "1.1rem" }}>
                    {pluginErrs.map((e) => (
                      <li key={e}>{e}</li>
                    ))}
                  </ul>
                </small>
              </div>
            )}
            {installedPlugins.length === 0 ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>
                  No plugins installed. Sideload-only v1 — see <code>src/plugins/GETTING-STARTED.md</code>.
                </small>
              </p>
            ) : (
              installedPlugins.map((p) => (
                <div className="kiwi-card" key={p.manifest.id}>
                  <h2>
                    {p.manifest.name ?? p.manifest.id}{" "}
                    <small style={{ color: "var(--kiwi-text-secondary)" }}>
                      v{p.manifest.version} · {p.manifest.id}
                    </small>
                  </h2>
                  <p>
                    {p.manifest.permissions.length === 0 ? (
                      <small style={{ color: "var(--kiwi-text-secondary)" }}>no capabilities declared</small>
                    ) : (
                      p.manifest.permissions.map((cap) => (
                        <span key={cap} className="ms-badge" style={{ marginRight: "0.3rem" }} title={`Declared capability: ${cap}`}>
                          {cap}
                        </span>
                      ))
                    )}
                  </p>
                  <p>
                    <label>
                      <input
                        type="checkbox"
                        checked={p.enabled}
                        onChange={(e) => setPluginEnabled(p.manifest.id, e.target.checked)}
                      />{" "}
                      Enabled
                    </label>{" "}
                    <button type="button" className="ms-btn" onClick={() => removePlugin(p.manifest.id)}>
                      Remove
                    </button>
                  </p>
                </div>
              ))
            )}
            {pluginPanes.length > 0 && (
              <>
                <h2>Plugin panes</h2>
                {pluginPanes.map((pane) => (
                  <PluginPaneCard key={`${pane.pluginId}/${pane.paneId}`} pane={pane} />
                ))}
              </>
            )}
          </>
        )}

        {section === "About" && (
          <>
            {/* T-315 — every stat comes from a real source: APP_VERSION is
                the build manifest version (src/version.ts), appInfo rows are
                kiwi_app_info (live only), accounts/plugins are real stores.
                Nothing is estimated — a stat with no source is omitted. */}
            <div className="kiwi-card" style={{ marginBottom: "0.8rem" }}>
              <h2 style={{ marginTop: 0 }}>
                {APP_NAME} Mail <small style={{ fontWeight: "normal" }}>v{APP_VERSION}</small>
              </h2>
              <p style={{ color: "var(--kiwi-text-secondary)", marginTop: 0 }}>
                <small>Security-first desktop mail — evidence-first trust model.</small>
              </p>
            </div>

            <h2>Diagnostics</h2>
            <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "0.25rem 1rem", marginTop: 0 }}>
              <dt>App version</dt>
              <dd style={{ margin: 0 }}><code>{APP_VERSION}</code> (build manifest)</dd>
              <dt>Accounts</dt>
              {/* Demo's sidebar accounts come from DEMO_ACCOUNTS (mock.ts) —
                  the live IPC list is empty there; count the source the UI
                  actually renders, never a number that disagrees on screen. */}
              <dd style={{ margin: 0 }}>
                {mode === "demo" ? `${DEMO_ACCOUNTS.length} (demo fixtures)` : accounts.length}
              </dd>
              <dt>Plugins installed</dt>
              <dd style={{ margin: 0 }}>{installedPlugins.length}</dd>
              {appInfo && (
                <>
                  <dt>Backend</dt>
                  <dd style={{ margin: 0 }}><code>{appInfo.version}</code> · IPC <code>{appInfo.contractVersion}</code></dd>
                  <dt>Security sessions observed</dt>
                  <dd style={{ margin: 0 }}>{appInfo.sessionsObserved}</dd>
                  <dt>This device</dt>
                  <dd style={{ margin: 0 }}><code>{appInfo.deviceId}</code></dd>
                  {appInfo.org && (
                    <>
                      <dt>Organization</dt>
                      <dd style={{ margin: 0 }}>{appInfo.org.orgId} — {appInfo.org.baseUrl}</dd>
                    </>
                  )}
                </>
              )}
            </dl>
            {!appInfo && (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>
                  Backend stats unavailable{mode === "demo" ? " in demo mode" : ""} — backend
                  version, sessions, and device id appear when a backend answers
                  <code> kiwi_app_info</code>. Profile dir is omitted: no IPC exposes it, and an
                  estimate is not shown.
                </small>
              </p>
            )}

            {/* T-333: real storage measurements via kiwi_storage_stats (§8).
                Every value is measured backend-side — null renders as
                "unmeasurable", 0 renders as 0; integrityCheck shows SQLite's
                own verdict and a non-"ok" result is a danger row, not a pass. */}
            <h2>Storage</h2>
            {mode !== "live" ? (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                <small>Storage diagnostics need the backend — demo mode has no store to measure.</small>
              </p>
            ) : storageLoading && !storage ? (
              <p role="status">
                <small>Measuring local storage…</small>
              </p>
            ) : storageErr ? (
              <div className="kiwi-banner error" role="alert">
                <small>Storage stats failed to load: {storageErr}</small>
              </div>
            ) : storage ? (
              <>
                <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "0.25rem 1rem", marginTop: 0 }}>
                  <dt>Database size</dt>
                  <dd style={{ margin: 0 }}>
                    {storage.dbBytes === null ? (
                      <em>unmeasurable — no mail.db on disk</em>
                    ) : (
                      <>{fmtBytes(storage.dbBytes)} <small style={{ color: "var(--kiwi-text-secondary)" }}>({storage.dbBytes.toLocaleString()} B)</small></>
                    )}
                  </dd>
                  <dt>Messages stored</dt>
                  <dd style={{ margin: 0 }}>{storage.messageCount.toLocaleString()}</dd>
                  <dt>Folders</dt>
                  <dd style={{ margin: 0 }}>{storage.folderCount}</dd>
                  <dt>Attachment payloads</dt>
                  <dd style={{ margin: 0 }}>
                    {storage.attachmentBytes === null ? (
                      <em>unmeasurable</em>
                    ) : (
                      <>{fmtBytes(storage.attachmentBytes)} <small style={{ color: "var(--kiwi-text-secondary)" }}>(persisted tree; parts inside stored bodies excluded)</small></>
                    )}
                  </dd>
                  <dt>Audit records</dt>
                  <dd style={{ margin: 0 }}>{storage.auditCount.toLocaleString()}</dd>
                  <dt>Schema version</dt>
                  <dd style={{ margin: 0 }}><code>{storage.schemaVersion}</code></dd>
                  <dt>Integrity check</dt>
                  <dd style={{ margin: 0 }}>
                    {storage.integrityCheck === "ok" ? (
                      <span className="kiwi-pill secure"><Icon name="check" size={10} /> ok</span>
                    ) : (
                      <span className="kiwi-pill danger">
                        <Icon name="alert-triangle" size={10} /> {storage.integrityCheck}
                      </span>
                    )}
                  </dd>
                </dl>
                {compactConfirm ? (
                  <div className="kiwi-banner warn" role="alertdialog" aria-label="Confirm database compaction">
                    <p style={{ marginTop: 0 }}>
                      <small>
                        <b>Compact the database?</b> Rebuilds mail.db (VACUUM) — mail is paused for
                        writing while it runs; a sync in progress refuses it. Audited as
                        storage-compact-requested/compacted.
                      </small>
                    </p>
                    <p style={{ marginBottom: 0 }}>
                      <button type="button" onClick={() => void runCompact()} disabled={compactBusy}>
                        {compactBusy ? "Compacting…" : "Compact now"}
                      </button>{" "}
                      <button type="button" onClick={() => setCompactConfirm(false)} disabled={compactBusy}>
                        Cancel
                      </button>
                    </p>
                  </div>
                ) : (
                  <p>
                    <button type="button" onClick={() => { setCompactConfirm(true); setCompactErr(null); setCompactNote(null); }}>
                      Compact database…
                    </button>{" "}
                    <small style={{ color: "var(--kiwi-text-secondary)" }}>
                      reclaim free pages — before/after sizes shown from real measurement
                    </small>
                  </p>
                )}
                {compactNote && (
                  <p role="status">
                    <small><Icon name="check" size={10} /> {compactNote}</small>
                  </p>
                )}
                {compactErr && (
                  <div className="kiwi-banner error" role="alert">
                    <small>Compact failed: {compactErr}</small>
                  </div>
                )}
              </>
            ) : null}

            <h2>Keyboard shortcuts</h2>
            <p style={{ color: "var(--kiwi-text-secondary)", marginTop: 0 }}>
              <small>The same map as the <code>?</code> overlay and the Shortcuts tab — one source.</small>
            </p>
            <table style={{ borderCollapse: "collapse", width: "100%" }} aria-label="Keyboard shortcuts">
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

            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>
                {APP_NAME} contributors · {APP_LICENSE} — see <code>LICENSE</code>.
              </small>
            </p>
          </>
        )}
      </section>
    </div>
  );
}

/**
 * Plugin-supplied Settings pane (T-280). Mount notifies the plugin via the
 * bridge (`pane.mount`); the plugin pushes body markup back through
 * `settings.renderPane`. ALPHA: markup renders verbatim — plugins are
 * trusted code (THREAT-MODEL RR-11); CSP still blocks inline script.
 */
function PluginPaneCard({ pane }: { pane: import("../plugins").PluginPane }) {
  useEffect(() => {
    emitToPlugin(pane.pluginId, "pane.mount", { paneId: pane.paneId });
    return () => emitToPlugin(pane.pluginId, "pane.unmount", { paneId: pane.paneId });
  }, [pane.pluginId, pane.paneId]);
  const icon = pane.icon && isIconName(pane.icon) ? pane.icon : "puzzle";
  return (
    <div className="kiwi-card kiwi-plugin-pane" data-plugin={pane.pluginId} data-pane={pane.paneId}>
      <h2>
        <Icon name={icon} size={14} /> {pane.title}{" "}
        <small style={{ color: "var(--kiwi-text-secondary)" }}>by {pane.pluginName}</small>
      </h2>
      {pane.body ? (
        <div className="kiwi-plugin-pane-body" dangerouslySetInnerHTML={{ __html: pane.body }} />
      ) : (
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>Pane registered — plugin will render content on mount.</small>
        </p>
      )}
    </div>
  );
}
