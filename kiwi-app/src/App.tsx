/**
 * KIWI root (T-143, T-151, T-182): live backend orchestration over kiwi.ipc/1
 * with labeled demo fallback outside the Tauri webview. State lives in
 * `src/state/` hooks (useToasts, useSession, useAccountModel); this file owns
 * the mail-changed listener and mailbox state inline (T-284: the dead
 * useMailbox hook was deleted — see docs/agents/agent-24-status.md) and keeps
 * theme/route/query/palette wiring plus view composition. The renderer owns
 * NO security verdicts — every verdict comes from the backend.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, IpcError, isTauri, onMailChanged } from "./ipc";
import { applyUiPrefs } from "./prefs";
import { useTheme } from "./themes";
import { broadcastPluginEvent, usePluginRuntime } from "./plugins";
import { useToasts } from "./state/toasts";
import { DEMO_TRUST, useSession } from "./state/session";
import { useAccountModel } from "./state/accounts";
import {
  DEMO_EVENTS,
  DEMO_FINDINGS,
  DEMO_MESSAGES,
} from "./mock";
import { navigate, useRoute } from "./router";
import type {
  AttachmentSavedView,
  ChallengeView,
  FindingDetailView,
  FindingInfo,
  FolderView,
  MessageBodyView,
  MessageEnvelope,
  MessagePatch,
  MessageView,
  OutboxItem,
  RemoteContentView,
  RenderedBodyView,
  SearchHit,
  SecurityEventRow,
  Severity,
  SnoozePreset,
} from "./kiwi";
import {
  eventToRow,
  findingToInfo,
  normalizeCategory,
  parseUnsubscribe,
  toTrustState,
  trustTokenToSeverity,
  unixToIso,
} from "./kiwi";
import { AgendaRail, AppShell, FolderPane, StatusStrip, TopBar } from "./components/chrome";
import { Icon } from "./components/icons/index";
import { AuthenticatorDialog, FindingDialog, LockOverlay } from "./components/security";
import type { AuthStatus } from "./components/security";
import { CommandPalette } from "./components/palette";
import type { PaletteAction } from "./components/palette";
import { ShortcutsHelp } from "./components/shortcuts";
import { ToastStack } from "./components/toasts";
import { MailboxView } from "./views/mailbox";
import { ComposeView } from "./views/compose";
import { SetupWizardView } from "./views/setup";
import { SettingsView } from "./views/settings";
import { SecurityCenterView } from "./views/security-center";
import { SearchView } from "./views/search";
import type { SearchResultRow } from "./views/search";
import { ContactsView } from "./views/contacts";
import { FiltersView } from "./views/filters";


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
    answered: flags.includes("\\Answered") ? true : undefined,
    hasAttachments: m.hasAttachments === true,
    trust,
    snippet: m.snippet || "",
    category: normalizeCategory(m.category),
    unsub: parseUnsubscribe(m),
    // T-284: carry per-message evidence hints so the reader pill reflects
    // this message's auth/link/attachment evaluation, not just session trust.
    auth: m.auth ?? null,
    attachRisk: m.attachRisk ?? null,
    linkRisk: m.linkRisk ?? null,
  };
}

export default function App() {
  const route = useRoute();
  // T-275: theme is owned by useTheme() (src/themes) — persists kiwi.theme,
  // applies resolved data-theme, accepts installed-package ids, and follows
  // the legacy kiwi-theme event so Settings/TopBar stay in sync.
  const { theme, setTheme } = useTheme();
  const { toasts, notify, dismissToast } = useToasts();
  const {
    mode,
    demo,
    backendNote,
    appInfo,
    setAppInfo,
    accountsRaw,
    trust,
    setTrust,
    devices,
    refreshStatus,
    refreshAccounts,
    doLock,
  } = useSession(notify);
  // T-280: host the enabled sideloaded plugins — notify.show → toast sink,
  // settings-page → Settings→Plugins panes; every bridge call is lock-gated.
  usePluginRuntime(notify, trust.locked);
  const [folderLists, setFolderLists] = useState<Record<string, FolderView[]>>({});
  const [foldersError, setFoldersError] = useState<string | null>(null);
  const { emailById, folders, folderLabel, filtersListLabel, smartFolders, accountSections, smartUnread } = useAccountModel(
    demo,
    accountsRaw,
    folderLists,
    route,
  );
  const [messages, setMessages] = useState<MessageEnvelope[]>([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [body, setBody] = useState<MessageBodyView | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);
  const [bodyError, setBodyError] = useState<string | null>(null);
  const [rendered, setRendered] = useState<RenderedBodyView | null>(null);
  const [renderLoading, setRenderLoading] = useState(false);
  const [renderError, setRenderError] = useState<string | null>(null);
  const [remoteContent, setRemoteContent] = useState<Record<string, boolean>>({});
  const [attachNote, setAttachNote] = useState<string | null>(null);
  const [attachBusy, setAttachBusy] = useState(false);
  const [mailboxRev, setMailboxRev] = useState(0);
  const [findings, setFindings] = useState<FindingInfo[]>(DEMO_FINDINGS);
  const [events, setEvents] = useState<SecurityEventRow[]>(DEMO_EVENTS);
  const [outbox, setOutbox] = useState<OutboxItem[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [flagOverrides, setFlagOverrides] = useState<Record<string, { starred?: boolean; unread?: boolean }>>({});
  const [query, setQuery] = useState("");
  const [searchHits, setSearchHits] = useState<SearchHit[] | null>(null);
  const [searchBusy, setSearchBusy] = useState(false);
  const [searchNote, setSearchNote] = useState<string | null>(null);
  const [findingIndex, setFindingIndex] = useState<number | null>(null);
  const [findingDetail, setFindingDetail] = useState<FindingDetailView | null>(null);
  const [findingDetailError, setFindingDetailError] = useState<string | null>(null);
  const [authOpen, setAuthOpen] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus>("waiting");
  const [authExpiry, setAuthExpiry] = useState<number | null>(null);
  const [authSeconds, setAuthSeconds] = useState(120);
  const [challenge, setChallenge] = useState<ChallengeView | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [lockReason, setLockReason] = useState("Trust reduced — verify with your authenticator to unlock.");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  // UI prefs (accent/density) apply from storage on mount; data-theme is
  // applied by useTheme (above) — installed theme ids resolve via registry.
  useEffect(() => applyUiPrefs(), []);

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

  // Live sync → refresh (kiwi://mail-changed, IPC-16/T-271). The worker
  // emits one event per changed pass — a sync bursts per folder — so
  // events debounce ~300 ms into ONE list reload + folder-count refresh,
  // and `newMessages` accumulate into a single summary toast. App-level
  // so it refreshes whichever folder/route is mounted.
  useEffect(() => {
    if (demo || !isTauri()) return;
    let unlisten: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let pendingNew = 0;
    onMailChanged((ev) => {
      if (typeof ev.newMessages === "number" && ev.newMessages > 0) {
        pendingNew += ev.newMessages;
      }
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = undefined;
        const n = pendingNew;
        pendingNew = 0;
        setMailboxRev((r) => r + 1);
        void loadFolders();
        if (n > 0) notify("info", `${n} new message${n === 1 ? "" : "s"} arrived.`);
        // T-280: fan the same debounced signal out to plugin hosts.
        broadcastPluginEvent("mail-changed", { added: n });
      }, 300);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      if (timer) clearTimeout(timer);
      unlisten?.();
    };
  }, [demo, loadFolders, notify]);

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
        // T-267 smart folders (eM Favorites): aggregates resolve here;
        // flag-based smart rows (unread/flagged/unreplied) load every
        // account INBOX and narrow client-side in baseMessages.
        const SMART_FOLDER_RE: Record<string, RegExp> = {
          sent: /sent/i,
          trash: /trash|deleted|bin/i,
          drafts: /draft/i,
          junk: /junk|spam/i,
        };
        const INBOX_SMART = new Set(["unread", "flagged", "unreplied"]);
        if (folderKey === "all-inboxes" || INBOX_SMART.has(folderKey)) {
          await Promise.all(
            accountsRaw.map(async (a) => {
              const fl = folderLists[a.id] ?? [];
              const inbox = fl.find((f) => f.name.toUpperCase() === "INBOX") ?? fl[0];
              if (inbox) await fetchOne(a.id, inbox.id, "all-inboxes");
            }),
          );
          collected.sort((x, y) => (y.date < x.date ? -1 : y.date > x.date ? 1 : 0));
        } else if (folderKey === "snoozed") {
          // Parked rows (kiwi_list_snoozed, T-255) — account-wide sweep.
          await Promise.all(
            accountsRaw.map(async (a) => {
              const email = emailById.get(a.id) ?? a.id;
              const t = trustTokenToSeverity(a.trustToken);
              const parked = await api.listSnoozed(a.id, 100);
              for (const m of parked) {
                collected.push({
                  id: `${a.id}:${m.folderId}:${m.uid}`,
                  accountId: a.id,
                  accountEmail: email,
                  folder: "snoozed",
                  folderId: m.folderId,
                  uid: m.uid,
                  from: m.fromAddr || "(unknown)",
                  subject: m.subject || "(no subject)",
                  date: m.dateUnix != null ? unixToIso(m.dateUnix) : "",
                  unread: false,
                  starred: false,
                  hasAttachments: false,
                  trust: t,
                  snippet: m.snoozedUntil ? `Snoozed until ${new Date(m.snoozedUntil * 1000).toLocaleString()}` : "",
                  category: "primary",
                  unsub: { url: null, mailto: null, oneClick: false },
                });
              }
            }),
          );
          collected.sort((x, y) => (y.date < x.date ? -1 : y.date > x.date ? 1 : 0));
        } else if (SMART_FOLDER_RE[folderKey]) {
          // Sent/Trash/Drafts/Junk Email: every matching folder on every account.
          const re = SMART_FOLDER_RE[folderKey];
          await Promise.all(
            accountsRaw.map(async (a) => {
              for (const f of (folderLists[a.id] ?? []).filter((f) => re.test(f.name))) {
                await fetchOne(a.id, f.id, folderKey);
              }
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
  }, [demo, trust.locked, folderKey, accountsRaw, folderLists, emailById, mailboxRev]);

  // T-231: titlebar search pill → real FTS (kiwi_search_messages), debounced
  // 300 ms. Live-only — demo keeps its labeled client-side filter, and a
  // backend failure surfaces as a list-pane banner, never fabricated rows.
  // `searchHits` stays null while inactive so the mailbox can distinguish
  // "not searching" from "searched, zero hits".
  const searchActive = !demo && !trust.locked && route.name === "mail" && query.trim() !== "";
  useEffect(() => {
    if (!searchActive) {
      setSearchHits(null);
      setSearchBusy(false);
      setSearchNote(null);
      return;
    }
    let cancelled = false;
    setSearchBusy(true);
    const t = window.setTimeout(() => {
      void (async () => {
        try {
          const hits = await api.searchMessages(query.trim(), 50);
          if (!cancelled) {
            setSearchHits(hits);
            setSearchNote(null);
          }
        } catch (e) {
          if (!cancelled) {
            setSearchHits([]);
            setSearchNote(`Search failed: ${e instanceof Error ? e.message : String(e)}`);
          }
        } finally {
          if (!cancelled) setSearchBusy(false);
        }
      })();
    }, 300);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [searchActive, query]);

  const selectedId = route.name === "mail" ? route.messageId : undefined;

  useEffect(() => {
    if (demo || !selectedId || trust.locked) {
      setBody(null);
      setBodyError(null);
      setRendered(null);
      setRenderError(null);
      setAttachNote(null);
      return;
    }
    const parts = selectedId.split(":");
    if (parts.length !== 3) return;
    const [accountId, folderIdRaw, uidRaw] = parts as [string, string, string];
    const folderId = Number(folderIdRaw);
    const uid = Number(uidRaw);
    let cancelled = false;
    setBodyLoading(true);
    setBodyError(null);
    setRenderLoading(true);
    setRenderError(null);
    setRendered(null);
    setAttachNote(null);
    (async () => {
      try {
        const b = await api.getMessage(accountId, folderId, uid);
        if (!cancelled) setBody(b);
      } catch (e) {
        if (!cancelled) setBodyError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setBodyLoading(false);
      }
      // Sanitized HTML render (T-146) — server-side ammonia allowlist.
      // Failure here never hides the plaintext body above.
      try {
        const r = await api.renderBody(accountId, folderId, uid);
        if (cancelled) return;
        setRendered(r);
        if (typeof r.remoteContentAllowed === "boolean") {
          setRemoteContent((m) => ({ ...m, [accountId]: r.remoteContentAllowed }));
        }
      } catch (e) {
        if (!cancelled) setRenderError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setRenderLoading(false);
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

  /**
   * Finding dialog data (T-164): the list-mapped FindingInfo renders
   * immediately; live mode then joins the full record (session + signals +
   * siblings) via kiwi_finding_detail. Backend ids are stable `rule|…`
   * keys — `finding-N` fallbacks have no backend key and skip the fetch.
   * Demo keeps fixtures only.
   */
  const openFinding = useCallback(
    (i: number) => {
      setFindingIndex(i);
      setFindingDetail(null);
      setFindingDetailError(null);
      if (demo) return;
      const rawId = findings[i]?.id;
      if (!rawId || rawId.startsWith("finding-")) return;
      void (async () => {
        try {
          setFindingDetail(await api.findingDetail(rawId));
        } catch (e) {
          setFindingDetailError(e instanceof Error ? e.message : String(e));
        }
      })();
    },
    [demo, findings],
  );

  const closeFinding = useCallback(() => {
    setFindingIndex(null);
    setFindingDetail(null);
    setFindingDetailError(null);
  }, []);

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

  const setLocalOverride = useCallback((id: string, patch: { starred?: boolean; unread?: boolean }) => {
    setFlagOverrides((m) => ({ ...m, [id]: { ...m[id], ...patch } }));
  }, []);

  const applyPatch = useCallback(
    async (id: string, patch: MessagePatch) => {
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id);
      if (!base) return;
      if (demo) {
        // Demo fixtures have no backend — local-only, labeled in-view.
        if (patch.starred !== undefined) setLocalOverride(id, { starred: patch.starred });
        if (patch.seen !== undefined) setLocalOverride(id, { unread: !patch.seen });
        return;
      }
      try {
        const v = await api.updateMessage(base.accountId, base.folderId, base.uid, patch);
        const has = (name: string) => v.flags.some((f) => f.toLowerCase() === name.toLowerCase());
        setLocalOverride(id, { starred: has("\\Flagged"), unread: !has("\\Seen") });
        if (v.movedToFolderId !== null && v.movedToFolderId !== undefined) {
          const msg = patch.archived
            ? "Message archived — moved to the Archive folder."
            : "Message unarchived — moved back to INBOX.";
          setSyncNote(msg);
          notify("ok", msg);
          // Reload the list: the row now lives in another folder.
          setMailboxRev((n) => n + 1);
          await loadFolders();
        }
      } catch (e) {
        // Offline / gated failure: keep a local override so the UI stays
        // usable, and say so — the next sync reconciles with the server.
        if (patch.starred !== undefined) setLocalOverride(id, { starred: patch.starred });
        if (patch.seen !== undefined) setLocalOverride(id, { unread: !patch.seen });
        const msg =
          e instanceof Error
            ? `Flag update failed (${e.message}) — kept locally, reconciles on next sync.`
            : String(e);
        setSyncNote(msg);
        notify("warn", msg);
      }
    },
    [demo, messages, setLocalOverride, loadFolders, notify],
  );

  const toggleStar = useCallback(
    (id: string) => {
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id);
      const cur = flagOverrides[id]?.starred ?? base?.starred ?? false;
      void applyPatch(id, { starred: !cur });
    },
    [demo, messages, flagOverrides],
  );

  const toggleRead = useCallback(
    (id: string) => {
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id);
      const cur = flagOverrides[id]?.unread ?? base?.unread ?? false;
      void applyPatch(id, { seen: cur });
    },
    [demo, messages, flagOverrides],
  );

  const archiveMessage = useCallback(
    (id: string, archived: boolean) => {
      void applyPatch(id, { archived });
    },
    [applyPatch],
  );

  /**
   * Bulk flag/archive over N messages (T-162): one sequential pass, one
   * summary toast. Per-message overrides update from each backend verdict;
   * any move triggers a single list reload. Demo applies seen/starred
   * locally (archive has no local meaning — stated, not faked).
   */
  const bulkPatch = useCallback(
    async (ids: string[], patch: MessagePatch, actionLabel: string) => {
      const pool = demo ? DEMO_MESSAGES : messages;
      if (demo) {
        if (patch.seen !== undefined || patch.starred !== undefined) {
          setFlagOverrides((m) => {
            const next = { ...m };
            for (const id of ids) {
              next[id] = {
                ...next[id],
                ...(patch.seen !== undefined ? { unread: !patch.seen } : {}),
                ...(patch.starred !== undefined ? { starred: patch.starred } : {}),
              };
            }
            return next;
          });
          notify("info", `Demo: ${actionLabel} — ${ids.length} message(s), local only.`);
        } else {
          notify("info", "Demo mode — archiving needs the Tauri backend.");
        }
        return;
      }
      let ok = 0;
      let fail = 0;
      let moved = false;
      for (const id of ids) {
        const base = pool.find((x) => x.id === id);
        if (!base) {
          fail++;
          continue;
        }
        try {
          const v = await api.updateMessage(base.accountId, base.folderId, base.uid, patch);
          const has = (name: string) => v.flags.some((f) => f.toLowerCase() === name.toLowerCase());
          setLocalOverride(id, { starred: has("\\Flagged"), unread: !has("\\Seen") });
          if (v.movedToFolderId !== null && v.movedToFolderId !== undefined) moved = true;
          ok++;
        } catch {
          fail++;
        }
      }
      if (moved) {
        setMailboxRev((n) => n + 1);
        await loadFolders();
      }
      const summary =
        fail === 0
          ? `${actionLabel} — ${ok} message(s).`
          : `${actionLabel} — ${ok} ok, ${fail} failed (kept locally, reconcile on sync).`;
      setSyncNote(summary);
      notify(fail === 0 ? "ok" : "warn", summary);
    },
    [demo, messages, setLocalOverride, loadFolders, notify],
  );

  /** Group envelope ids by (accountId, folderId) — delete/move are folder-scoped. */
  const groupByFolder = useCallback(
    (ids: string[]) => {
      const pool = demo ? DEMO_MESSAGES : messages;
      const groups = new Map<string, { accountId: string; folderId: number; uids: number[] }>();
      let missing = 0;
      for (const id of ids) {
        const base = pool.find((x) => x.id === id);
        if (!base) {
          missing++;
          continue;
        }
        const key = `${base.accountId}\n${base.folderId}`;
        const g = groups.get(key);
        if (g) g.uids.push(base.uid);
        else groups.set(key, { accountId: base.accountId, folderId: base.folderId, uids: [base.uid] });
      }
      return { groups: [...groups.values()], missing };
    },
    [demo, messages],
  );

  const reloadMail = useCallback(async () => {
    setMailboxRev((n) => n + 1);
    await loadFolders();
  }, [loadFolders]);

  /**
   * Bulk delete (T-163): soft→Trash by default, permanent from Trash or
   * when asked (backend decides Trash-source too). Chunked at 400 uids
   * (backend bound is 500). One summary toast; rows always reload.
   */
  const bulkDelete = useCallback(
    async (ids: string[], permanent: boolean, actionLabel: string) => {
      if (demo || ids.length === 0) {
        if (ids.length === 0) return;
        notify("info", "Demo mode — delete needs the Tauri backend.");
        return;
      }
      const { groups, missing } = groupByFolder(ids);
      let trashed = 0;
      let destroyed = 0;
      let fail = 0;
      fail += missing;
      for (const g of groups) {
        for (let i = 0; i < g.uids.length; i += 400) {
          try {
            const r = await api.deleteMessages(g.accountId, g.folderId, g.uids.slice(i, i + 400), permanent);
            trashed += r.movedToTrash;
            destroyed += r.deleted;
          } catch {
            fail += g.uids.slice(i, i + 400).length;
          }
        }
      }
      await reloadMail();
      const bits: string[] = [];
      if (trashed > 0) bits.push(`${trashed} → Trash`);
      if (destroyed > 0) bits.push(`${destroyed} permanently deleted`);
      const summary =
        fail === 0 ? `${actionLabel} — ${bits.join(", ") || "nothing deleted"}.` : `${actionLabel} — ${bits.join(", ") || "nothing deleted"}, ${fail} failed.`;
      setSyncNote(summary);
      notify(fail === 0 ? "ok" : "warn", summary);
    },
    [demo, groupByFolder, reloadMail, notify],
  );

  /**
   * Bulk spam (T-163): move to the account's Spam/Junk folder via
   * kiwi_move_messages (same-account only — enforced server-side too).
   * Accounts without a known Spam folder are skipped and named.
   */
  const bulkSpam = useCallback(
    async (ids: string[]) => {
      if (demo || ids.length === 0) {
        if (ids.length === 0) return;
        notify("info", "Demo mode — spam needs the Tauri backend.");
        return;
      }
      const { groups, missing } = groupByFolder(ids);
      let moved = 0;
      let fail = missing;
      const noSpam: string[] = [];
      for (const g of groups) {
        const spam = (folderLists[g.accountId] ?? []).find((f) => /spam|junk/i.test(f.name));
        if (!spam) {
          fail += g.uids.length;
          noSpam.push(g.accountId);
          continue;
        }
        if (spam.id === g.folderId) {
          moved += g.uids.length; // already there — counts as done
          continue;
        }
        for (let i = 0; i < g.uids.length; i += 400) {
          try {
            const r = await api.moveMessages(g.accountId, g.folderId, spam.id, g.uids.slice(i, i + 400));
            moved += r.moved;
          } catch {
            fail += g.uids.slice(i, i + 400).length;
          }
        }
      }
      await reloadMail();
      let summary = fail === 0 ? `Marked spam — ${moved} message(s).` : `Marked spam — ${moved} moved, ${fail} failed.`;
      if (noSpam.length > 0) summary += ` No Spam folder on: ${[...new Set(noSpam)].join(", ")} (sync first).`;
      setSyncNote(summary);
      notify(fail === 0 ? "ok" : "warn", summary);
    },
    [demo, groupByFolder, folderLists, reloadMail, notify],
  );

  const selectedEnvelope = useMemo(
    () => (demo ? DEMO_MESSAGES : messages).find((m) => m.id === selectedId) ?? null,
    [demo, messages, selectedId],
  );

  /**
   * Toolbar snooze (T-267 → kiwi_message_snooze, T-255): parks the
   * selected envelope until the preset deadline; list reloads so the
   * parked row drops out of the folder view.
   */
  const snoozeSelected = useCallback(
    async (preset: SnoozePreset) => {
      const s = selectedEnvelope;
      if (!s) return;
      if (demo) {
        notify("info", "Demo mode — snooze needs the Tauri backend.");
        return;
      }
      try {
        const v = await api.snoozeMessages(s.accountId, [{ folderId: s.folderId, uid: s.uid }], { preset });
        notify("ok", `Snoozed ${v.snoozed} message(s) until ${new Date(v.untilUnix * 1000).toLocaleString()}.`);
        await reloadMail();
      } catch (e) {
        const msg = `Snooze failed: ${e instanceof Error ? e.message : e}`;
        setSyncNote(msg);
        notify("error", msg);
      }
    },
    [demo, selectedEnvelope, reloadMail, notify],
  );

  const unsnoozeSelected = useCallback(async () => {
    const s = selectedEnvelope;
    if (!s) return;
    if (demo) {
      notify("info", "Demo mode — unsnooze needs the Tauri backend.");
      return;
    }
    try {
      const v = await api.unsnoozeMessages(s.accountId, [{ folderId: s.folderId, uid: s.uid }]);
      notify("ok", `Unsnoozed ${v.unsnoozed} message(s).`);
      await reloadMail();
    } catch (e) {
      const msg = `Unsnooze failed: ${e instanceof Error ? e.message : e}`;
      setSyncNote(msg);
      notify("error", msg);
    }
  }, [demo, selectedEnvelope, reloadMail, notify]);

  /**
   * Toolbar junk toggle (kiwi_message_set_junk, T-263): `junk` sets the
   * flag + moves to the account Junk folder; `false` clears/returns to
   * INBOX. Moves remap uids — always reload the list after.
   */
  const setJunkSelected = useCallback(
    async (junk: boolean) => {
      const s = selectedEnvelope;
      if (!s) return;
      if (demo) {
        notify("info", "Demo mode — junk marking needs the Tauri backend.");
        return;
      }
      try {
        const v = await api.setJunk(s.accountId, [{ folderId: s.folderId, uid: s.uid }], junk);
        notify("ok", junk ? `Marked junk — ${v.moved} moved to Junk.` : `Un-junked — ${v.moved} moved back to INBOX.`);
        await reloadMail();
      } catch (e) {
        const msg = `Junk update failed: ${e instanceof Error ? e.message : e}`;
        setSyncNote(msg);
        notify("error", msg);
      }
    },
    [demo, selectedEnvelope, reloadMail, notify],
  );
  const setAllowRemote = useCallback(
    async (allowed: boolean) => {
      if (demo || !selectedEnvelope) return;
      setRenderError(null);
      try {
        const v: RemoteContentView = await api.setRemoteContent(selectedEnvelope.accountId, allowed);
        setRemoteContent((m) => ({ ...m, [v.accountId]: v.remoteContentAllowed }));
        // Re-render so the stripped/allowed image set updates immediately.
        const r: RenderedBodyView = await api.renderBody(
          selectedEnvelope.accountId,
          selectedEnvelope.folderId,
          selectedEnvelope.uid,
        );
        setRendered(r);
      } catch (e) {
        setRenderError(e instanceof Error ? e.message : String(e));
      }
    },
    [demo, selectedEnvelope],
  );

  const saveAttachment = useCallback(
    async (attachmentIndex: number, destPath: string) => {
      if (demo || !selectedEnvelope) return;
      const dest = destPath.trim();
      if (!dest) {
        setAttachNote("Choose a destination path first.");
        return;
      }
      setAttachBusy(true);
      setAttachNote(null);
      try {
        const saved: AttachmentSavedView = await api.downloadAttachment(
          selectedEnvelope.accountId,
          selectedEnvelope.folderId,
          selectedEnvelope.uid,
          attachmentIndex,
          dest,
        );
        setAttachNote(`Saved ${saved.filename} (${saved.size} B) → ${saved.path}.`);
        notify("ok", `Attachment saved: ${saved.filename}.`);
      } catch (e) {
        const msg = e instanceof Error ? `Save failed: ${e.message}` : String(e);
        setAttachNote(msg);
        notify("error", msg);
      } finally {
        setAttachBusy(false);
      }
    },
    [demo, selectedEnvelope, notify],
  );

  /** Flag/star overrides applied, query NOT applied — feeds mailbox + search. */
  const baseMessages = useMemo(() => {
    // T-267 smart-folder predicates. Demo slugs map onto DEMO_MESSAGES
    // folders; live aggregate folders (sent/trash/drafts/junk/snoozed)
    // are already scoped by the loader, so only flag-based smarts and
    // the demo `acct:slug` section ids need client predicates.
    const SMART_PRED: Record<string, (m: MessageEnvelope) => boolean> = {
      unread: (m) => m.unread,
      flagged: (m) => m.starred,
      unreplied: (m) => m.answered !== true,
      snoozed: (m) => m.folder === "snoozed",
      sent: (m) => m.folder === "sent",
      trash: (m) => m.folder === "trash",
      drafts: (m) => m.folder === "drafts",
      junk: (m) => m.folder === "spam" || m.folder === "junk",
    };
    let base: MessageEnvelope[];
    if (demo) {
      if (folderKey === "all-inboxes") base = DEMO_MESSAGES;
      else if (SMART_PRED[folderKey]) base = DEMO_MESSAGES.filter(SMART_PRED[folderKey]);
      else {
        // Per-account section id `accId:slug` (demo) or `accId:folderId` (live).
        const sep = folderKey.lastIndexOf(":");
        base = sep > 0
          ? DEMO_MESSAGES.filter((m) => m.accountId === folderKey.slice(0, sep) && m.folder === folderKey.slice(sep + 1))
          : DEMO_MESSAGES.filter((m) => m.folder === folderKey);
      }
    } else {
      base = messages;
      const pred = SMART_PRED[folderKey];
      // Loader-scoped keys (sent/trash/…/snoozed/acct:id) carry matching
      // `folder`/`folderId` already — re-filtering would wrongly narrow
      // e.g. a live "sent" row's folder key. Only narrow the INBOX-loaded
      // smart rows and demo-shaped folders.
      if (pred && ["unread", "flagged", "unreplied"].includes(folderKey)) base = base.filter(pred);
    }
    const withOverrides = demo
      ? base
      : base.map((m) => {
          const ov = flagOverrides[m.id];
          return ov ? { ...m, starred: ov.starred ?? m.starred, unread: ov.unread ?? m.unread } : m;
        });
    if (demo) {
      return withOverrides.map((m) => {
        const ov = flagOverrides[m.id];
        return ov ? { ...m, starred: ov.starred ?? m.starred, unread: ov.unread ?? m.unread } : m;
      });
    }
    return withOverrides;
  }, [demo, folderKey, messages, flagOverrides]);

  const visibleMessages = useMemo(() => {
    // T-231: live mode delegates search to kiwi_search_messages (hit rows
    // render in the list pane); the substring filter is the demo path only.
    const q = query.trim().toLowerCase();
    if (!q || !demo) return baseMessages;
    return baseMessages.filter(
      (m) => m.from.toLowerCase().includes(q) || m.subject.toLowerCase().includes(q) || m.snippet.toLowerCase().includes(q),
    );
  }, [baseMessages, query, demo]);

  const doSync = useCallback(async () => {
    if (demo) {
      notify("info", "Demo mode — sync needs the Tauri backend.");
      return;
    }
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
      const msg = `Sync complete — ${added} new message(s).`;
      setSyncNote(msg);
      notify("ok", msg);
      await Promise.all([loadFolders(), loadSecurity(), refreshStatus()]);
    } catch (e) {
      const msg = e instanceof Error ? `Sync failed: ${e.message}` : String(e);
      setSyncNote(msg);
      notify("error", msg);
    } finally {
      setSyncing(false);
    }
  }, [demo, accountsRaw, loadFolders, loadSecurity, refreshStatus, notify]);

  // Global keys (T-153 + T-191 TB map): Ctrl+K palette; `/` search; `?`
  // shortcuts; Ctrl+N compose; F5 sync. Single-letter keys never fire
  // while typing in a text field.
  useEffect(() => {
    const isTyping = (t: EventTarget | null) => {
      const el = t as HTMLElement | null;
      return !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
    };
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      // TB map (T-191): Ctrl+N composes — never hijack a text field.
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
        if (!isTyping(e.target)) {
          e.preventDefault();
          navigate({ name: "compose" });
        }
        return;
      }
      // TB map (T-191): F5 syncs now.
      if (e.key === "F5") {
        e.preventDefault();
        void doSync();
        return;
      }
      if (isTyping(e.target) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "/") {
        e.preventDefault();
        document.getElementById("kiwi-search")?.focus();
      } else if (e.key === "?") {
        e.preventDefault();
        setHelpOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [doSync]);

  const doFlushOutbox = useCallback(async () => {
    if (demo) {
      notify("info", "Demo mode — the outbox needs the Tauri backend.");
      return;
    }
    try {
      const r = await api.flushOutbox();
      const msg = `Send-all: ${r.sent} sent, ${r.failed} failed, ${r.held} held.`;
      setSyncNote(msg);
      notify(r.failed > 0 || r.held > 0 ? "warn" : "ok", msg);
      await refreshOutbox();
    } catch (e) {
      const msg = e instanceof Error ? `Send-all failed: ${e.message}` : String(e);
      setSyncNote(msg);
      notify("error", msg);
    }
  }, [demo, refreshOutbox, notify]);

  const doCancelSend = useCallback(
    async (queueId: string) => {
      try {
        const r = await api.cancelSend(queueId);
        notify("info", r.cancelled ? "Send undone — back to draft." : "Undo window already closed — message dispatching.");
      } catch (e) {
        const msg = e instanceof Error ? `Undo failed: ${e.message}` : String(e);
        setSyncNote(msg);
        notify("error", msg);
      }
      await refreshOutbox();
    },
    [refreshOutbox, notify],
  );

  /* ---------- command palette actions (T-153) ---------- */

  const cycleTheme = useCallback(() => {
    const next = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
    setTheme(next);
    notify("info", `Theme: ${next}.`);
  }, [theme, setTheme, notify]);

  const paletteActions: PaletteAction[] = useMemo(() => {
    const list: PaletteAction[] = [
      { id: "compose", label: "Compose new message", hint: "r", run: () => navigate({ name: "compose" }) },
      {
        id: "search",
        label: "Focus message search",
        hint: "/",
        run: () => document.getElementById("kiwi-search")?.focus(),
      },
      { id: "theme", label: `Toggle theme (now ${theme})`, hint: "light/dark/system", run: cycleTheme },
      { id: "security", label: "Open Security Center", run: () => navigate({ name: "security" }) },
      { id: "contacts", label: "Open Contacts", run: () => navigate({ name: "contacts" }) },
      { id: "filters", label: "Open mail filters", run: () => navigate({ name: "filters" }) },
      { id: "settings", label: "Open Settings", run: () => navigate({ name: "settings" }) },
      { id: "shortcuts", label: "Show keyboard shortcuts", hint: "?", run: () => setHelpOpen(true) },
    ];
    for (const f of folders) {
      list.push({
        id: `goto-${f.id}`,
        label: `Go to ${f.label}`,
        hint: "folder",
        run: () => navigate({ name: "mail", folder: f.id }),
      });
    }
    list.push(
      demo
        ? {
            id: "sync",
            label: "Sync now (demo — needs backend)",
            hint: "live only",
            run: () => notify("info", "Demo mode — sync needs the Tauri backend."),
          }
        : { id: "sync", label: "Sync now", run: () => void doSync() },
      demo
        ? {
            id: "lock",
            label: "Lock now (demo — needs backend)",
            hint: "live only",
            run: () => notify("info", "Demo mode — locking needs the Tauri backend."),
          }
        : { id: "lock", label: "Lock mailbox now", run: () => void doLock() },
    );
    return list;
  }, [folders, theme, cycleTheme, demo, doSync, doLock, notify]);

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
      const chal = await api.unlockChallenge(active.deviceId);
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
      <TopBar
        trust={trust}
        demo={demo}
        query={query}
        onQuery={setQuery}
        onOpenPalette={() => setPaletteOpen(true)}
        onOpenShortcuts={() => setHelpOpen(true)}
        onSubmitSearch={() => navigate({ name: "search" })}
        onSync={() => void doSync()}
        onLock={() => void doLock()}
        syncing={syncing}
        hasSelection={!!selectedEnvelope}
        inTrash={folderKey === "trash" || /trash|deleted|bin/i.test(folderLabel)}
        onReply={() => navigate({ name: "compose" })}
        onReplyAll={() => navigate({ name: "compose" })}
        onForward={() => navigate({ name: "compose" })}
        onMarkRead={(read) => {
          if (selectedEnvelope) void bulkPatch([selectedEnvelope.id], { seen: read }, read ? "Marked read" : "Marked unread");
        }}
        onMarkStarred={(starred) => {
          if (selectedEnvelope) void bulkPatch([selectedEnvelope.id], { starred }, starred ? "Starred" : "Unstarred");
        }}
        onMarkAllRead={() => {
          const ids = baseMessages.filter((m) => m.unread).map((m) => m.id);
          if (ids.length > 0) void bulkPatch(ids, { seen: true }, "Marked all read");
          else notify("info", "Nothing unread in this list.");
        }}
        onMarkJunk={(junk) => void setJunkSelected(junk)}
        onArchive={(archived) => {
          if (selectedEnvelope) archiveMessage(selectedEnvelope.id, archived);
        }}
        onSnooze={(preset) => void snoozeSelected(preset)}
        onUnsnooze={() => void unsnoozeSelected()}
        onDelete={(permanent) => {
          if (selectedEnvelope) void bulkDelete([selectedEnvelope.id], permanent, permanent ? "Deleted permanently" : "Deleted");
        }}
        onSecurityDetails={() => openFinding(0)}
        onEmptyTrash={() => void bulkDelete(visibleMessages.map((m) => m.id), false, "Emptied trash")}
        onReloadList={() => void reloadMail()}
      />
      <AppShell
        sidebar={
          <FolderPane
            smartFolders={smartFolders}
            smartUnread={smartUnread}
            accountSections={accountSections}
            activeFolder={route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes"}
            outboxCount={outbox.length}
            foldersError={foldersError}
            demo={demo}
          />
        }
        rail={
          route.name === "mail" ? (
            <AgendaRail
              security={{
                trust,
                lockReason: trust.locked ? lockReason : null,
                // Real sources only: unread is a real `unseen` sum in both
                // modes; flagged/unreplied have no live store-wide aggregate
                // (accounts.ts) → omitted live, shown from demo data in demo.
                findings: findings.length,
                unread: smartUnread["unread"] ?? null,
                flagged: demo ? (smartUnread["flagged"] ?? null) : null,
                unreplied: demo ? (smartUnread["unreplied"] ?? null) : null,
                activeDevices: demo ? null : devices.filter((d) => d.status === "active").length,
                demo,
              }}
            />
          ) : null
        }
        status={
          <StatusStrip pendingApprovals={authOpen && authStatus === "waiting" ? 1 : 0}>
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
          </StatusStrip>
        }
      >
        {route.name === "mail" && (
          <MailboxView
            folder={folderKey}
            folderLabel={folderLabel}
            messages={visibleMessages}
            searchQuery={query}
            searchResults={searchActive ? (searchHits ?? []) : null}
            searchBusy={searchActive && searchBusy}
            searchNote={searchNote}
            messagesLoading={messagesLoading}
            messagesError={messagesError}
            selectedId={selectedId}
            body={body}
            bodyLoading={bodyLoading}
            bodyError={bodyError}
            rendered={rendered}
            renderLoading={renderLoading}
            renderError={renderError}
            remoteAllowed={
              selectedEnvelope ? (remoteContent[selectedEnvelope.accountId] ?? rendered?.remoteContentAllowed ?? false) : false
            }
            attachNote={attachNote}
            attachBusy={attachBusy}
            findings={findings}
            locked={trust.locked}
            hasAccounts={accountsRaw.length > 0}
            demo={demo}
            syncing={syncing}
            syncNote={syncNote}
            outbox={outbox}
            onOpenFinding={openFinding}
            onToggleStar={toggleStar}
            onToggleRead={toggleRead}
            onArchive={archiveMessage}
            onBulkPatch={(ids, patch, label) => void bulkPatch(ids, patch, label)}
            onBulkDelete={(ids, permanent, label) => void bulkDelete(ids, permanent, label)}
            onBulkSpam={(ids) => void bulkSpam(ids)}
            onEmptyTrash={() => void bulkDelete(visibleMessages.map((m) => m.id), false, "Emptied trash")}
            onAllowRemote={(allowed) => void setAllowRemote(allowed)}
            onSaveAttachment={(index, destPath) => void saveAttachment(index, destPath)}
            onSync={() => void doSync()}
            onFlushOutbox={() => void doFlushOutbox()}
            onCancelSend={(q) => void doCancelSend(q)}
            onOutboxRefresh={() => void refreshOutbox()}
          />
        )}
        {route.name === "compose" && (
          <div
            className="ms-composer-backdrop"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) navigate({ name: "mail", folder: folderKey });
            }}
          >
            <div
              className="ms-composer-modal"
              role="dialog"
              aria-modal="true"
              aria-label="Compose message"
              onKeyDown={(e) => {
                // Esc closes — but never steal it from text fields
                // (recipient autocomplete + textarea need it first).
                if (e.key === "Escape") {
                  const t = e.target as HTMLElement | null;
                  const tag = t?.tagName;
                  if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT" && !t?.isContentEditable) {
                    e.stopPropagation();
                    navigate({ name: "mail", folder: folderKey });
                  }
                }
              }}
            >
              <div className="ms-composer-head">
                <span style={{ flex: 1 }} />
                <button
                  type="button"
                  className="ms-btn"
                  onClick={() => navigate({ name: "mail", folder: folderKey })}
                  aria-label="Close composer (draft autosaves locally)"
                  title="Close composer (draft autosaves locally)"
                >
                  <Icon name="close" size={12} />
                </button>
              </div>
              <ComposeView
                mode={mode}
                accounts={accountsRaw.map((a) => ({ id: a.id, email: a.email, displayName: a.displayName || a.email }))}
                onSent={() => {
                  void refreshOutbox();
                  void refreshStatus();
                }}
                onNotify={notify}
              />
            </div>
          </div>
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
            folderLists={folderLists}
            filters={{
              demo,
              accounts: accountsRaw.map((a) => ({ id: a.id, email: a.email, displayName: a.displayName || a.email })),
              messages: baseMessages,
              listLabel: filtersListLabel,
              onBulkPatch: (ids, patch, label) => void bulkPatch(ids, patch, label),
              onBulkDelete: (ids, permanent, label) => void bulkDelete(ids, permanent, label),
              onNotify: notify,
            }}
          />
        )}
        {route.name === "security" && (
          <SecurityCenterView events={events} findings={findings} demo={demo} onOpenFinding={openFinding} />
        )}
        {route.name === "contacts" && <ContactsView demo={demo} onNotify={notify} />}
        {route.name === "filters" && (
          <FiltersView
            demo={demo}
            accounts={accountsRaw.map((a) => ({ id: a.id, email: a.email, displayName: a.displayName || a.email }))}
            messages={baseMessages}
            listLabel={filtersListLabel}
            onBulkPatch={(ids, patch, label) => void bulkPatch(ids, patch, label)}
            onBulkDelete={(ids, permanent, label) => void bulkDelete(ids, permanent, label)}
            onNotify={notify}
          />
        )}
        {route.name === "search" && (
          <SearchView
            query={query}
            onQuery={setQuery}
            demo={demo}
            messages={baseMessages}
            emailOf={(accountId) => emailById.get(accountId) ?? accountId}
            onOpenHit={(r: SearchResultRow) =>
              navigate({
                name: "mail",
                folder: `${r.accountId}:${r.folderId}`,
                messageId: `${r.accountId}:${r.folderId}:${r.uid}`,
              })
            }
          />
        )}
      </AppShell>

      {findingIndex !== null && findings[findingIndex] && (
        <FindingDialog
          finding={findings[findingIndex]}
          position={findingIndex + 1}
          total={findings.length}
          detail={findingDetail}
          detailError={findingDetailError}
          onClose={closeFinding}
          onPrev={() => openFinding(Math.max(0, (findingIndex ?? 0) - 1))}
          onNext={() => openFinding(Math.min(findings.length - 1, (findingIndex ?? 0) + 1))}
        />
      )}

      {trust.locked && (
        <LockOverlay
          reason={demo ? `${lockReason} (Demo: auto-approves.)` : lockReason}
          busy={verifying}
          trustLines={[
            `Trust state: ${trust.state}`,
            `Score: ${trust.score === null ? "—" : trust.score}`,
            `Required action: ${trust.requiredAction}`,
          ]}
          deviceLabel={demo ? "Demo authenticator" : (activeDevice?.label ?? null)}
          fpTail={demo ? "9F3A" : ((activeDevice?.deviceId ?? "").slice(-4) || null)}
          challengeId={demo ? null : (challenge?.challengeId ?? null)}
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

      <CommandPalette
        open={paletteOpen}
        query={query}
        onQuery={(q) => {
          setQuery(q);
          navigate({ name: "search" });
        }}
        actions={paletteActions}
        onClose={() => setPaletteOpen(false)}
      />
      <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} />
      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </>
  );
}
