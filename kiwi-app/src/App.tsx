/**
 * KIWI root (T-143): live backend orchestration over kiwi.ipc/1 with labeled
 * demo fallback outside the Tauri webview. The renderer owns NO security
 * verdicts — trust/lock/findings/policy outcomes all come from the backend;
 * star/read flags stay local-only (no flag command in kiwi.ipc/1).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, BackendUnavailableError, IpcError } from "./ipc";
import { loadPref, savePref } from "./prefs";
import {
  DEMO_ACCOUNTS,
  DEMO_EVENTS,
  DEMO_FINDINGS,
  DEMO_FOLDERS,
  DEMO_MESSAGES,
} from "./mock";
import { navigate, useRoute } from "./router";
import type {
  AccountInfo,
  AccountView,
  AppInfoView,
  ChallengeView,
  DeviceView,
  FindingInfo,
  FolderView,
  MessageBodyView,
  MessageEnvelope,
  MessageView,
  OutboxItem,
  SecurityEventRow,
  Severity,
  TrustState,
} from "./kiwi";
import {
  eventToRow,
  findingToInfo,
  toTrustState,
  trustTokenToSeverity,
  unixToIso,
} from "./kiwi";
import { AppShell, Sidebar, TopBar } from "./components/chrome";
import { AuthenticatorDialog, FindingDialog, LockOverlay } from "./components/security";
import type { AuthStatus } from "./components/security";
import { MailboxView } from "./views/mailbox";
import { ComposeView } from "./views/compose";
import { SetupWizardView } from "./views/setup";
import { SettingsView } from "./views/settings";
import { SecurityCenterView } from "./views/security-center";

function applyTheme(theme: string) {
  const root = document.documentElement;
  if (theme === "system") {
    const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.setAttribute("data-theme", dark ? "dark" : "light");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

const DEMO_TRUST: TrustState = { trust: "unknown", locked: false, state: "unknown", score: null, requiredAction: "none" };

function toEnvelope(
  accountId: string,
  accountEmail: string,
  folderKey: string,
  folderId: number,
  m: MessageView,
  trust: Severity,
  overrides: Record<string, { starred?: boolean; unread?: boolean }>,
): MessageEnvelope {
  const id = `${accountId}:${folderId}:${m.uid}`;
  const ov = overrides[id];
  const flags = Array.isArray(m.flags) ? m.flags : [];
  return {
    id,
    accountId,
    accountEmail,
    folder: folderKey,
    folderId,
    uid: m.uid,
    from: m.fromAddr || "(unknown)",
    subject: m.subject || "(no subject)",
    date: unixToIso(m.dateUnix),
    unread: ov?.unread ?? !flags.includes("\\Seen"),
    starred: ov?.starred ?? flags.includes("\\Flagged"),
    hasAttachments: m.hasAttachments === true,
    trust,
    snippet: m.snippet || "",
  };
}

export default function App() {
  const route = useRoute();
  const [theme, setTheme] = useState(() => loadPref<string>("kiwi.theme", "dark"));
  const [mode, setMode] = useState<"live" | "demo">("demo");
  const [backendNote, setBackendNote] = useState("probing backend…");
  const [appInfo, setAppInfo] = useState<AppInfoView | null>(null);
  const [accountsRaw, setAccountsRaw] = useState<AccountView[]>([]);
  const [trust, setTrust] = useState<TrustState>(DEMO_TRUST);
  const [devices, setDevices] = useState<DeviceView[]>([]);
  const [folderLists, setFolderLists] = useState<Record<string, FolderView[]>>({});
  const [foldersError, setFoldersError] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageEnvelope[]>([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [body, setBody] = useState<MessageBodyView | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);
  const [bodyError, setBodyError] = useState<string | null>(null);
  const [findings, setFindings] = useState<FindingInfo[]>(DEMO_FINDINGS);
  const [events, setEvents] = useState<SecurityEventRow[]>(DEMO_EVENTS);
  const [outbox, setOutbox] = useState<OutboxItem[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [flagOverrides, setFlagOverrides] = useState<Record<string, { starred?: boolean; unread?: boolean }>>({});
  const [query, setQuery] = useState("");
  const [findingIndex, setFindingIndex] = useState<number | null>(null);
  const [authOpen, setAuthOpen] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus>("waiting");
  const [authExpiry, setAuthExpiry] = useState<number | null>(null);
  const [authSeconds, setAuthSeconds] = useState(120);
  const [challenge, setChallenge] = useState<ChallengeView | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [lockReason, setLockReason] = useState("Trust reduced — verify with your authenticator to unlock.");

  const demo = mode === "demo";

  useEffect(() => applyTheme(theme), [theme]);
  useEffect(() => savePref("kiwi.theme", theme), [theme]);

  /* ---------- probe ---------- */

  const refreshStatus = useCallback(async () => {
    try {
      setTrust(toTrustState(await api.securityStatus()));
    } catch (e) {
      if (!(e instanceof BackendUnavailableError)) {
        setBackendNote(e instanceof Error ? e.message : String(e));
      }
    }
  }, []);

  const refreshAccounts = useCallback(async () => {
    const acc = await api.listAccounts();
    setAccountsRaw(acc);
    try {
      setDevices(await api.listDevices());
    } catch {
      setDevices([]);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const pong = await api.ping();
        const [info, status, acc] = await Promise.all([api.appInfo(), api.securityStatus(), api.listAccounts()]);
        if (cancelled) return;
        setMode("live");
        setAppInfo(info);
        setTrust(toTrustState(status));
        setAccountsRaw(acc);
        try {
          setDevices(await api.listDevices());
        } catch {
          setDevices([]);
        }
        const contract = typeof info.contractVersion === "string" ? info.contractVersion : "kiwi.ipc/1";
        setBackendNote(`${pong} · ${contract} · ${acc.length} account(s)`);
      } catch (e) {
        if (cancelled) return;
        setMode("demo");
        setBackendNote(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Recompute trust periodically so the lock overlay tracks the backend.
  useEffect(() => {
    if (demo) return;
    const t = window.setInterval(() => void refreshStatus(), 15000);
    return () => window.clearInterval(t);
  }, [demo, refreshStatus]);

  // Ctrl+K focuses search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        document.getElementById("kiwi-search")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* ---------- derived account/folder model ---------- */

  const emailById = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of accountsRaw) m.set(a.id, a.email);
    return m;
  }, [accountsRaw]);

  const accounts: AccountInfo[] = useMemo(() => {
    if (demo) return DEMO_ACCOUNTS;
    return accountsRaw.map((a, i) => ({
      id: a.id,
      email: a.email,
      displayName: a.displayName || a.email,
      trust: trustTokenToSeverity(a.trustToken),
      unread: typeof a.unreadCount === "number" ? a.unreadCount : 0,
      color: typeof a.color === "string" && a.color ? a.color : ["#2563eb", "#7a5b00", "#b23a22"][i % 3],
    }));
  }, [demo, accountsRaw]);

  const folders = useMemo(() => {
    if (demo) return [...DEMO_FOLDERS, { id: "outbox", label: "Outbox" }];
    const list = [
      { id: "all-inboxes", label: "All Inboxes" },
      { id: "outbox", label: "Outbox" },
    ];
    for (const a of accountsRaw) {
      for (const f of folderLists[a.id] ?? []) {
        list.push({ id: `${a.id}:${f.id}`, label: `${a.displayName || a.email} / ${f.name}` });
      }
    }
    return list;
  }, [demo, accountsRaw, folderLists]);

  const folderLabel = useMemo(() => {
    const id = route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes";
    return folders.find((f) => f.id === id)?.label ?? "All Inboxes";
  }, [folders, route]);

  const unreadByFolder = useMemo(() => {
    if (demo) {
      const counts: Record<string, number> = { "all-inboxes": 0 };
      for (const m of DEMO_MESSAGES) {
        if (!m.unread) continue;
        counts["all-inboxes"] = (counts["all-inboxes"] ?? 0) + 1;
        counts[m.folder] = (counts[m.folder] ?? 0) + 1;
      }
      return counts;
    }
    const counts: Record<string, number> = { "all-inboxes": 0 };
    for (const a of accountsRaw) {
      for (const f of folderLists[a.id] ?? []) {
        const key = `${a.id}:${f.id}`;
        counts[key] = f.unseen ?? 0;
        counts["all-inboxes"] = (counts["all-inboxes"] ?? 0) + (f.unseen ?? 0);
      }
    }
    return counts;
  }, [demo, accountsRaw, folderLists]);

  /* ---------- live loaders ---------- */

  const loadFolders = useCallback(async () => {
    if (demo) return;
    setFoldersError(null);
    try {
      const entries = await Promise.all(
        accountsRaw.map(async (a) => {
          try {
            return [a.id, await api.listFolders(a.id)] as const;
          } catch (e) {
            if (e instanceof IpcError && e.code === "locked") throw e;
            return [a.id, [] as FolderView[]] as const;
          }
        }),
      );
      const next: Record<string, FolderView[]> = {};
      for (const [id, list] of entries) next[id] = list;
      setFolderLists(next);
    } catch (e) {
      setFoldersError(e instanceof Error ? e.message : String(e));
    }
  }, [demo, accountsRaw]);

  useEffect(() => {
    if (demo || accountsRaw.length === 0) return;
    void loadFolders();
  }, [demo, accountsRaw, loadFolders]);

  const folderKey = route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes";

  useEffect(() => {
    if (demo) return;
    if (trust.locked) {
      setMessages([]);
      setMessagesError(null);
      return;
    }
    let cancelled = false;
    setMessagesLoading(true);
    setMessagesError(null);
    (async () => {
      try {
        const collected: MessageEnvelope[] = [];
        const fetchOne = async (accountId: string, folderId: number, key: string) => {
          const email = emailById.get(accountId) ?? accountId;
          const acct = accountsRaw.find((a) => a.id === accountId);
          const t = trustTokenToSeverity(acct?.trustToken);
          const list = await api.listMessages(accountId, folderId, 50);
          for (const m of list) collected.push(toEnvelope(accountId, email, key, folderId, m, t, flagOverrides));
        };
        if (folderKey === "all-inboxes") {
          await Promise.all(
            accountsRaw.map(async (a) => {
              const fl = folderLists[a.id] ?? [];
              const inbox = fl.find((f) => f.name.toUpperCase() === "INBOX") ?? fl[0];
              if (inbox) await fetchOne(a.id, inbox.id, "all-inboxes");
            }),
          );
          collected.sort((x, y) => (y.date < x.date ? -1 : y.date > x.date ? 1 : 0));
        } else if (folderKey !== "outbox") {
          const sep = folderKey.lastIndexOf(":");
          if (sep > 0) {
            await fetchOne(folderKey.slice(0, sep), Number(folderKey.slice(sep + 1)), folderKey);
          }
        }
        if (!cancelled) setMessages(collected);
      } catch (e) {
        if (!cancelled) {
          if (e instanceof IpcError && e.code === "locked") {
            setMessages([]);
          } else {
            setMessagesError(e instanceof Error ? e.message : String(e));
          }
        }
      } finally {
        if (!cancelled) setMessagesLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo, trust.locked, folderKey, accountsRaw, folderLists, emailById]);

  const selectedId = route.name === "mail" ? route.messageId : undefined;

  useEffect(() => {
    if (demo || !selectedId || trust.locked) {
      setBody(null);
      setBodyError(null);
      return;
    }
    const parts = selectedId.split(":");
    if (parts.length !== 3) return;
    const [accountId, folderIdRaw, uidRaw] = parts as [string, string, string];
    let cancelled = false;
    setBodyLoading(true);
    setBodyError(null);
    (async () => {
      try {
        const b = await api.getMessage(accountId, Number(folderIdRaw), Number(uidRaw));
        if (!cancelled) setBody(b);
      } catch (e) {
        if (!cancelled) setBodyError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setBodyLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [demo, selectedId, trust.locked]);

  const loadSecurity = useCallback(async () => {
    if (demo) return;
    try {
      const [f, e] = await Promise.all([api.securityFindings(), api.securityEvents(100)]);
      setFindings(f.map((x, i) => findingToInfo(x as never, i)));
      setEvents(e.map((x) => eventToRow(x as never, (id) => (id ? (emailById.get(id) ?? id) : "—"))));
    } catch {
      // Security panels keep last-known values; errors surface in-view on demand.
    }
  }, [demo, emailById]);

  useEffect(() => {
    if (demo) return;
    void loadSecurity();
  }, [demo, loadSecurity, route.name]);

  const refreshOutbox = useCallback(async () => {
    if (demo) return;
    try {
      setOutbox(await api.listOutbox());
    } catch {
      setOutbox([]);
    }
  }, [demo]);

  useEffect(() => {
    if (demo || folderKey !== "outbox") return;
    void refreshOutbox();
  }, [demo, folderKey, refreshOutbox]);

  /* ---------- actions ---------- */

  const toggleStar = useCallback((id: string) => {
    setFlagOverrides((m) => {
      const cur = m[id]?.starred;
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id)?.starred ?? false;
      return { ...m, [id]: { ...m[id], starred: cur ?? !base } };
    });
  }, [demo, messages]);

  const toggleRead = useCallback((id: string) => {
    setFlagOverrides((m) => {
      const cur = m[id]?.unread;
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id)?.unread ?? false;
      return { ...m, [id]: { ...m[id], unread: cur ?? !base } };
    });
  }, [demo, messages]);

  const visibleMessages = useMemo(() => {
    const base = demo
      ? folderKey === "all-inboxes"
        ? DEMO_MESSAGES
        : DEMO_MESSAGES.filter((m) => m.folder === folderKey)
      : messages;
    const withOverrides = demo
      ? base
      : base.map((m) => {
          const ov = flagOverrides[m.id];
          return ov ? { ...m, starred: ov.starred ?? m.starred, unread: ov.unread ?? m.unread } : m;
        });
    const withDemoOverrides = demo
      ? withOverrides.map((m) => {
          const ov = flagOverrides[m.id];
          return ov ? { ...m, starred: ov.starred ?? m.starred, unread: ov.unread ?? m.unread } : m;
        })
      : withOverrides;
    const q = query.trim().toLowerCase();
    if (!q) return withDemoOverrides;
    return withDemoOverrides.filter(
      (m) => m.from.toLowerCase().includes(q) || m.subject.toLowerCase().includes(q) || m.snippet.toLowerCase().includes(q),
    );
  }, [demo, folderKey, messages, flagOverrides, query]);

  const doSync = useCallback(async () => {
    if (demo) return;
    setSyncing(true);
    setSyncNote(null);
    try {
      let added = 0;
      for (const a of accountsRaw) {
        const reports = await api.syncAccount(a.id);
        for (const r of reports) {
          const n = r["newMessages"];
          if (typeof n === "number") added += n;
        }
      }
      setSyncNote(`Sync complete — ${added} new message(s).`);
      await Promise.all([loadFolders(), loadSecurity(), refreshStatus()]);
    } catch (e) {
      setSyncNote(e instanceof Error ? `Sync failed: ${e.message}` : String(e));
    } finally {
      setSyncing(false);
    }
  }, [demo, accountsRaw, loadFolders, loadSecurity, refreshStatus]);

  const doFlushOutbox = useCallback(async () => {
    try {
      const r = await api.flushOutbox();
      setSyncNote(`Send-all: ${r.sent} sent, ${r.failed} failed, ${r.held} held.`);
      await refreshOutbox();
    } catch (e) {
      setSyncNote(e instanceof Error ? `Send-all failed: ${e.message}` : String(e));
    }
  }, [refreshOutbox]);

  const doCancelSend = useCallback(
    async (queueId: string) => {
      try {
        await api.cancelSend(queueId);
      } catch (e) {
        setSyncNote(e instanceof Error ? `Undo failed: ${e.message}` : String(e));
      }
      await refreshOutbox();
    },
    [refreshOutbox],
  );

  const doLock = useCallback(async () => {
    if (demo) return;
    try {
      setTrust(toTrustState(await api.lock()));
    } catch (e) {
      setBackendNote(e instanceof Error ? e.message : String(e));
    }
  }, [demo]);

  /* ---------- challenge flow ---------- */

  const startVerify = useCallback(async () => {
    if (demo) {
      setAuthStatus("waiting");
      setAuthSeconds(120);
      setAuthOpen(true);
      return;
    }
    setVerifying(true);
    try {
      const active = devices.find((d) => d.status === "active") ?? devices[0];
      if (!active) {
        setLockReason("No authenticator device registered — pair one in Settings → KIWI Security.");
        return;
      }
      const chal = await api.requestChallenge(active.deviceId, "unlock");
      setChallenge(chal);
      const secs = Math.max(1, chal.expiresUnix - Math.floor(Date.now() / 1000));
      setAuthSeconds(secs);
      setAuthExpiry(chal.expiresUnix);
      setAuthStatus("waiting");
      setAuthOpen(true);
    } catch (e) {
      setLockReason(e instanceof Error ? `Challenge failed: ${e.message}` : String(e));
    } finally {
      setVerifying(false);
    }
  }, [demo, devices]);

  // Live: poll trust while the challenge dialog is open; approve on unlock.
  useEffect(() => {
    if (demo || !authOpen || !challenge || authStatus !== "waiting") return;
    const t = window.setInterval(() => {
      void (async () => {
        try {
          const s = toTrustState(await api.securityStatus());
          setTrust(s);
          if (!s.locked) {
            setAuthStatus("approved");
            window.setTimeout(() => {
              setAuthOpen(false);
              setChallenge(null);
            }, 900);
          } else if (Math.floor(Date.now() / 1000) >= (authExpiry ?? 0)) {
            setAuthStatus("expired");
          }
        } catch {
          // Keep waiting; transport blips must not kill the dialog.
        }
      })();
    }, 3000);
    return () => window.clearInterval(t);
  }, [demo, authOpen, challenge, authStatus, authExpiry]);

  // Countdown display.
  useEffect(() => {
    if (!authOpen || authStatus !== "waiting") return;
    if (authSeconds <= 0) {
      setAuthStatus("expired");
      return;
    }
    const t = window.setTimeout(() => setAuthSeconds((s) => s - 1), 1000);
    return () => window.clearTimeout(t);
  }, [authOpen, authStatus, authSeconds]);

  // Demo: auto-approve after 6s (labeled).
  useEffect(() => {
    if (!authOpen || !demo || authStatus !== "waiting") return;
    const t = window.setTimeout(() => setAuthStatus("approved"), 6000);
    return () => window.clearTimeout(t);
  }, [authOpen, demo, authStatus]);

  useEffect(() => {
    if (authStatus === "approved" && authOpen && demo) {
      const t = window.setTimeout(() => {
        setAuthOpen(false);
        setTrust({ ...DEMO_TRUST });
      }, 900);
      return () => window.clearTimeout(t);
    }
  }, [authStatus, authOpen, demo]);

  const activeDevice = devices.find((d) => d.status === "active") ?? devices[0];

  return (
    <>
      <TopBar trust={trust} demo={demo} query={query} onQuery={setQuery} theme={theme} onTheme={setTheme} />
      <AppShell
        sidebar={
          <Sidebar
            folders={folders}
            accounts={accounts}
            activeFolder={route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes"}
            unreadByFolder={unreadByFolder}
          />
        }
        status={
          <>
            <span>{backendNote}</span>
            {appInfo && (
              <span>
                · v{appInfo.version} · {appInfo.sessionsObserved} session(s) observed
                {trust.score !== null && <> · score {trust.score}</>}
                {trust.requiredAction !== "none" && <> · action: {trust.requiredAction}</>}
              </span>
            )}
            {foldersError && <span> · folders: {foldersError}</span>}
            {demo && <span> · demo mode — run the Tauri backend for live data</span>}
            <button type="button" onClick={() => navigate({ name: "setup" })}>
              Add account
            </button>
          </>
        }
      >
        {route.name === "mail" && (
          <MailboxView
            folder={folderKey}
            folderLabel={folderLabel}
            messages={visibleMessages}
            messagesLoading={messagesLoading}
            messagesError={messagesError}
            selectedId={selectedId}
            body={body}
            bodyLoading={bodyLoading}
            bodyError={bodyError}
            findings={findings}
            locked={trust.locked}
            syncing={syncing}
            syncNote={syncNote}
            outbox={outbox}
            onOpenFinding={(i) => setFindingIndex(i)}
            onToggleStar={toggleStar}
            onToggleRead={toggleRead}
            onSync={() => void doSync()}
            onFlushOutbox={() => void doFlushOutbox()}
            onCancelSend={(q) => void doCancelSend(q)}
            onOutboxRefresh={() => void refreshOutbox()}
          />
        )}
        {route.name === "compose" && (
          <ComposeView
            mode={mode}
            accounts={accountsRaw.map((a) => ({ id: a.id, email: a.email, displayName: a.displayName || a.email }))}
            onSent={() => {
              void refreshOutbox();
              void refreshStatus();
            }}
          />
        )}
        {route.name === "setup" && (
          <SetupWizardView
            mode={mode}
            onAdded={() => {
              void (async () => {
                await refreshAccounts();
              })();
            }}
          />
        )}
        {route.name === "settings" && (
          <SettingsView
            mode={mode}
            accounts={accountsRaw}
            orgBinding={appInfo?.org ?? null}
            onAccountsChanged={() => void refreshAccounts()}
            onStatusChanged={() => void refreshStatus()}
            onOrgChanged={() => {
              void (async () => {
                try {
                  setAppInfo(await api.appInfo());
                } catch {
                  // keep last-known binding
                }
              })();
            }}
            onLock={() => void doLock()}
          />
        )}
        {route.name === "security" && (
          <SecurityCenterView events={events} findings={findings} demo={demo} onOpenFinding={(i) => setFindingIndex(i)} />
        )}
      </AppShell>

      {findingIndex !== null && findings[findingIndex] && (
        <FindingDialog
          finding={findings[findingIndex]}
          position={findingIndex + 1}
          total={findings.length}
          onClose={() => setFindingIndex(null)}
          onPrev={() => setFindingIndex((i) => (i === null ? i : Math.max(0, i - 1)))}
          onNext={() => setFindingIndex((i) => (i === null ? i : Math.min(findings.length - 1, i + 1)))}
        />
      )}

      {trust.locked && (
        <LockOverlay
          reason={demo ? `${lockReason} (Demo: auto-approves.)` : lockReason}
          busy={verifying}
          onVerify={() => void startVerify()}
          onRetry={() => {
              if (demo) {
                setTrust({ ...DEMO_TRUST });
                setLockReason("Trust reduced — verify with your authenticator to unlock.");
              } else {
                void refreshStatus();
              }
            }}
        />
      )}

      {authOpen && (
        <AuthenticatorDialog
          eventLabel={challenge ? `Unlock mailbox (${challenge.event})` : "Unlock mailbox"}
          deviceName={demo ? "Demo authenticator" : (activeDevice?.label ?? "authenticator")}
          fpTail={demo ? "9F3A" : (activeDevice?.deviceId ?? "").slice(-4) || "—"}
          secondsLeft={authSeconds}
          status={authStatus}
          detail={challenge && !demo ? challenge.challengeId : undefined}
          onCancel={() => {
            setAuthOpen(false);
            setChallenge(null);
            setVerifying(false);
          }}
        />
      )}
    </>
  );
}
