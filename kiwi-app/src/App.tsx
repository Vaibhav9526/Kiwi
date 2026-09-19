/**
 * KIWI root (T-112): theme, backend probe with demo fallback, hash routes,
 * lock overlay + authenticator + finding dialog orchestration, Ctrl+K.
 * Real data replaces DEMO_* as kiwi-mail/kiwi-core IPC lands (ui-surfaces §5).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./ipc";
import { loadPref, savePref } from "./prefs";
import { DEMO_ACCOUNTS, DEMO_EVENTS, DEMO_FINDINGS, DEMO_FOLDERS, DEMO_MESSAGES } from "./mock";
import { navigate, useRoute } from "./router";
import type { AccountInfo, MessageEnvelope, TrustState } from "./kiwi";
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

export default function App() {
  const route = useRoute();
  const [theme, setTheme] = useState(() => loadPref<string>("kiwi.theme", "system"));
  const [accounts, setAccounts] = useState<AccountInfo[]>(DEMO_ACCOUNTS);
  const [messages, setMessages] = useState<MessageEnvelope[]>(DEMO_MESSAGES);
  const [trust, setTrust] = useState<TrustState>({ trust: "unknown", locked: false });
  const [demo, setDemo] = useState(true);
  const [backendNote, setBackendNote] = useState("probing backend…");
  const [query, setQuery] = useState("");
  const [findingIndex, setFindingIndex] = useState<number | null>(null);
  const [authOpen, setAuthOpen] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus>("waiting");
  const [authSeconds, setAuthSeconds] = useState(120);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => applyTheme(theme), [theme]);
  useEffect(() => savePref("kiwi.theme", theme), [theme]);

  const toggleStar = useCallback((id: string) => {
    setMessages((ms) => ms.map((m) => (m.id === id ? { ...m, starred: !m.starred } : m)));
  }, []);

  const toggleRead = useCallback((id: string) => {
    setMessages((ms) => ms.map((m) => (m.id === id ? { ...m, unread: !m.unread } : m)));
  }, []);

  // Backend probe: ping + accounts + trust; any failure → demo mode.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const pong = await api.ping();
        const [acc, status] = await Promise.all([api.listAccounts(), api.securityStatus()]);
        if (cancelled) return;
        setDemo(false);
        setBackendNote(`backend: ${pong}`);
        if (acc.length > 0) setAccounts(acc);
        setTrust(status);
      } catch (e) {
        if (cancelled) return;
        setDemo(true);
        setBackendNote(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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

  // Authenticator countdown; demo mode auto-approves after 6s (labeled).
  useEffect(() => {
    if (!authOpen || authStatus !== "waiting") return;
    if (authSeconds <= 0) {
      setAuthStatus("expired");
      return;
    }
    const t = window.setTimeout(() => setAuthSeconds((s) => s - 1), 1000);
    return () => window.clearTimeout(t);
  }, [authOpen, authStatus, authSeconds]);

  useEffect(() => {
    if (!authOpen || !demo || authStatus !== "waiting") return;
    const t = window.setTimeout(() => setAuthStatus("approved"), 6000);
    return () => window.clearTimeout(t);
  }, [authOpen, demo, authStatus]);

  useEffect(() => {
    if (authStatus === "approved" && authOpen) {
      const t = window.setTimeout(() => {
        setAuthOpen(false);
        setTrust((tr) => ({ ...tr, locked: false }));
        setVerifying(false);
      }, 900);
      return () => window.clearTimeout(t);
    }
  }, [authStatus, authOpen]);

  const startVerify = useCallback(() => {
    setAuthStatus("waiting");
    setAuthSeconds(120);
    setAuthOpen(true);
    setVerifying(true);
  }, []);

  const visibleMessages = useMemo(() => {
    const folder = route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes";
    const inFolder = folder === "all-inboxes" ? messages : messages.filter((m) => m.folder === folder);
    const q = query.trim().toLowerCase();
    if (!q) return inFolder;
    return inFolder.filter(
      (m) => m.from.toLowerCase().includes(q) || m.subject.toLowerCase().includes(q) || m.snippet.toLowerCase().includes(q),
    );
  }, [messages, route, query]);

  const unreadByFolder = useMemo(() => {
    const counts: Record<string, number> = { "all-inboxes": 0 };
    for (const m of messages) {
      if (!m.unread) continue;
      counts["all-inboxes"] = (counts["all-inboxes"] ?? 0) + 1;
      counts[m.folder] = (counts[m.folder] ?? 0) + 1;
    }
    return counts;
  }, [messages]);

  const folderLabel = DEMO_FOLDERS.find((f) => f.id === (route.name === "mail" ? route.folder : undefined))?.label ?? "All Inboxes";

  return (
    <>
      <TopBar trust={trust} demo={demo} query={query} onQuery={setQuery} theme={theme} onTheme={setTheme} />
      <AppShell
        sidebar={
          <Sidebar
            accounts={accounts}
            activeFolder={route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes"}
            unreadByFolder={unreadByFolder}
          />
        }
        status={
          <>
            <span>{backendNote}</span>
            {demo && <span> · demo mode — connect the Tauri backend for live data</span>}
            <button type="button" onClick={() => navigate({ name: "setup" })}>
              Add account
            </button>
          </>
        }
      >
        {route.name === "mail" && (
          <MailboxView
            folder={route.folder ?? "all-inboxes"}
            folderLabel={folderLabel}
            messages={visibleMessages}
            selectedId={route.messageId}
            findings={DEMO_FINDINGS}
            locked={trust.locked}
            onOpenFinding={(i) => setFindingIndex(i)}
            onToggleStar={toggleStar}
            onToggleRead={toggleRead}
          />
        )}
        {route.name === "compose" && <ComposeView />}
        {route.name === "setup" && <SetupWizardView />}
        {route.name === "settings" && <SettingsView />}
        {route.name === "security" && <SecurityCenterView events={DEMO_EVENTS} demo={demo} />}
      </AppShell>

      {findingIndex !== null && DEMO_FINDINGS[findingIndex] && (
        <FindingDialog
          finding={DEMO_FINDINGS[findingIndex]}
          position={findingIndex + 1}
          total={DEMO_FINDINGS.length}
          onClose={() => setFindingIndex(null)}
          onPrev={() => setFindingIndex((i) => (i === null ? i : Math.max(0, i - 1)))}
          onNext={() => setFindingIndex((i) => (i === null ? i : Math.min(DEMO_FINDINGS.length - 1, i + 1)))}
        />
      )}

      {trust.locked && (
        <LockOverlay
          reason="Trust reduced — verify with your authenticator to unlock. (Demo: auto-approves.)"
          busy={verifying}
          onVerify={startVerify}
          onRetry={() => setTrust({ trust: "unknown", locked: false })}
        />
      )}

      {authOpen && (
        <AuthenticatorDialog
          eventLabel="Unlock mailbox"
          deviceName="Demo authenticator"
          fpTail="9F3A"
          secondsLeft={authSeconds}
          status={authStatus}
          onCancel={() => {
            setAuthOpen(false);
            setVerifying(false);
          }}
        />
      )}
    </>
  );
}
