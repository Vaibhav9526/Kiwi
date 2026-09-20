/**
 * Derived account/folder model (T-182, extracted from App.tsx verbatim):
 * muted set, email index, sidebar accounts, folder list + labels, unread
 * counts (muted excluded). Zero functional change — only relocated.
 */

import { useMemo } from "react";
import { DEMO_ACCOUNTS, DEMO_FOLDERS, DEMO_MESSAGES } from "../mock";
import { loadMuted } from "../prefs";
import { trustTokenToSeverity } from "../kiwi";
import type { AccountInfo, AccountView, FolderView } from "../kiwi";
import type { Route } from "../router";

export function useAccountModel(
  demo: boolean,
  accountsRaw: AccountView[],
  folderLists: Record<string, FolderView[]>,
  route: Route,
) {
  // Muted accounts (T-167): re-read when accounts or routes change so the
  // Settings toggle takes effect on return without a reload.
  const muted = useMemo(() => loadMuted(), [accountsRaw, route.name]);

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
      muted: muted.includes(a.id),
    }));
  }, [demo, accountsRaw, muted]);

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

  /** Filters-view run scope label (baseMessages follows the mail route). */
  const filtersListLabel = route.name === "mail" ? folderLabel : "last loaded list";

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
      if (muted.includes(a.id)) continue;
      for (const f of folderLists[a.id] ?? []) {
        const key = `${a.id}:${f.id}`;
        counts[key] = f.unseen ?? 0;
        counts["all-inboxes"] = (counts["all-inboxes"] ?? 0) + (f.unseen ?? 0);
      }
    }
    return counts;
  }, [demo, accountsRaw, folderLists, muted]);

  return { muted, emailById, accounts, folders, folderLabel, filtersListLabel, unreadByFolder };
}
