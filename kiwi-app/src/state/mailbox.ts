/**
 * Mailbox data + actions (T-182, extracted from App.tsx verbatim): folder
 * loading, message list, body + sanitized render, remote-content opt-in,
 * attachment save, flag/star/archive/bulk/delete/spam actions, sync. Feeds
 * MailboxView, SearchView and FiltersView. Zero functional change.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { api, IpcError } from "../ipc";
import { DEMO_MESSAGES } from "../mock";
import { normalizeCategory, parseUnsubscribe, trustTokenToSeverity, unixToIso } from "../kiwi";
import type {
  AccountView,
  AttachmentSavedView,
  FolderView,
  MessageBodyView,
  MessageEnvelope,
  MessagePatch,
  MessageView,
  RemoteContentView,
  RenderedBodyView,
  Severity,
} from "../kiwi";
import type { Route } from "../router";
import type { NotifyFn } from "./toasts";

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
    category: normalizeCategory(m.category),
    unsub: parseUnsubscribe(m),
  };
}

export interface MailboxDeps {
  demo: boolean;
  accountsRaw: AccountView[];
  emailById: Map<string, string>;
  trustLocked: boolean;
  route: Route;
  query: string;
  folderLists: Record<string, FolderView[]>;
  setFolderLists: Dispatch<SetStateAction<Record<string, FolderView[]>>>;
  notify: NotifyFn;
  ext: {
    loadSecurity: () => Promise<void>;
    refreshStatus: () => Promise<void>;
  };
}

export function useMailbox({
  demo,
  accountsRaw,
  emailById,
  trustLocked,
  route,
  query,
  folderLists,
  setFolderLists,
  notify,
  ext,
}: MailboxDeps) {
  const [foldersError, setFoldersError] = useState<string | null>(null);
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
  const [syncing, setSyncing] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [flagOverrides, setFlagOverrides] = useState<Record<string, { starred?: boolean; unread?: boolean }>>({});

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
  }, [demo, accountsRaw, setFolderLists]);

  useEffect(() => {
    if (demo || accountsRaw.length === 0) return;
    void loadFolders();
  }, [demo, accountsRaw, loadFolders]);

  const folderKey = route.name === "mail" ? (route.folder ?? "all-inboxes") : "all-inboxes";

  useEffect(() => {
    if (demo) return;
    if (trustLocked) {
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
  }, [demo, trustLocked, folderKey, accountsRaw, folderLists, emailById, mailboxRev]);

  const selectedId = route.name === "mail" ? route.messageId : undefined;

  useEffect(() => {
    if (demo || !selectedId || trustLocked) {
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
  }, [demo, selectedId, trustLocked]);

  const setLocalOverride = useCallback((id: string, patch: { starred?: boolean; unread?: boolean }) => {
    setFlagOverrides((m) => ({ ...m, [id]: { ...m[id], ...patch } }));
  }, []);

  const reloadMail = useCallback(async () => {
    setMailboxRev((n) => n + 1);
    await loadFolders();
  }, [loadFolders]);

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
          await reloadMail();
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
    [demo, messages, setLocalOverride, reloadMail, notify],
  );

  const toggleStar = useCallback(
    (id: string) => {
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id);
      const cur = flagOverrides[id]?.starred ?? base?.starred ?? false;
      void applyPatch(id, { starred: !cur });
    },
    [demo, messages, flagOverrides, applyPatch],
  );

  const toggleRead = useCallback(
    (id: string) => {
      const base = (demo ? DEMO_MESSAGES : messages).find((x) => x.id === id);
      const cur = flagOverrides[id]?.unread ?? base?.unread ?? false;
      void applyPatch(id, { seen: cur });
    },
    [demo, messages, flagOverrides, applyPatch],
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
      if (moved) await reloadMail();
      const summary =
        fail === 0
          ? `${actionLabel} — ${ok} message(s).`
          : `${actionLabel} — ${ok} ok, ${fail} failed (kept locally, reconcile on sync).`;
      setSyncNote(summary);
      notify(fail === 0 ? "ok" : "warn", summary);
    },
    [demo, messages, setLocalOverride, reloadMail, notify],
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
    if (demo) {
      return withOverrides.map((m) => {
        const ov = flagOverrides[m.id];
        return ov ? { ...m, starred: ov.starred ?? m.starred, unread: ov.unread ?? m.unread } : m;
      });
    }
    return withOverrides;
  }, [demo, folderKey, messages, flagOverrides]);

  const visibleMessages = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return baseMessages;
    return baseMessages.filter(
      (m) => m.from.toLowerCase().includes(q) || m.subject.toLowerCase().includes(q) || m.snippet.toLowerCase().includes(q),
    );
  }, [baseMessages, query]);

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
      await Promise.all([loadFolders(), ext.loadSecurity(), ext.refreshStatus()]);
    } catch (e) {
      const msg = e instanceof Error ? `Sync failed: ${e.message}` : String(e);
      setSyncNote(msg);
      notify("error", msg);
    } finally {
      setSyncing(false);
    }
  }, [demo, accountsRaw, loadFolders, ext, notify]);

  return {
    folderKey,
    foldersError,
    selectedId,
    selectedEnvelope,
    messages,
    messagesLoading,
    messagesError,
    body,
    bodyLoading,
    bodyError,
    rendered,
    renderLoading,
    renderError,
    remoteContent,
    attachNote,
    attachBusy,
    syncing,
    syncNote,
    baseMessages,
    visibleMessages,
    loadFolders,
    reloadMail,
    toggleStar,
    toggleRead,
    archiveMessage,
    bulkPatch,
    bulkDelete,
    bulkSpam,
    setAllowRemote,
    saveAttachment,
    doSync,
  };
}
