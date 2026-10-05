/**
 * Derived account/folder model (T-182, extracted from App.tsx verbatim):
 * muted set, email index, sidebar accounts, folder list + labels, unread
 * counts (muted excluded). T-267 extends it with the eM-idiom folder
 * model: Favorites smart-folder rows (All Inboxes / Outbox / Sent /
 * Trash / Drafts / Junk Email / Unread / Flagged / Unreplied / Snoozed)
 * and per-account expandable sections with real `unseen` counts.
 */

import { useMemo } from "react";
import { DEMO_ACCOUNTS, DEMO_MESSAGES } from "../mock";
import { loadMuted } from "../prefs";
import { trustTokenToSeverity } from "../kiwi";
import type { AccountInfo, AccountView, FolderView, Severity } from "../kiwi";
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

  /* ---------- T-267 eM folder model ---------- */

  /**
   * Global smart folders (Favorites section). Ids double as mail-route
   * folder keys — the App loader resolves each:
   * - `all-inboxes` + `unread`/`flagged`/`unreplied`: every account INBOX
   *   (smart filters narrow the loaded set client-side).
   * - `outbox`: the send queue (not a folder).
   * - `sent`/`trash`/`drafts`/`junk`: every account folder whose name
   *   matches the class regex — aggregate cross-account like eM Client.
   * - `snoozed`: kiwi_list_snoozed across accounts (parked rows).
   */
  const smartFolders: { id: string; label: string }[] = useMemo(() => {
    const base = [
      { id: "all-inboxes", label: "All Inboxes" },
      { id: "outbox", label: "Outbox" },
      { id: "sent", label: "Sent" },
      { id: "trash", label: "Trash" },
      { id: "drafts", label: "Drafts" },
      { id: "junk", label: "Junk Email" },
      { id: "unread", label: "Unread" },
      { id: "flagged", label: "Flagged" },
      { id: "unreplied", label: "Unreplied" },
      { id: "snoozed", label: "Snoozed" },
    ];
    // T-335 honesty rules for the unified view: a single-account "All
    // Inboxes" would just duplicate that account's Inbox row — hidden.
    // Likewise once every account's folder list has loaded AND every
    // inbox reports 0 rows, the row hides rather than promise content it
    // can't show; it reappears when a sync lands mail. While any list is
    // still loading the row stays (unknown ≠ empty).
    if (accounts.length < 2) return base.filter((f) => f.id !== "all-inboxes");
    if (!demo && accounts.every((a) => Array.isArray(folderLists[a.id]))) {
      const total = accounts.reduce((n, a) => {
        const fl = folderLists[a.id] ?? [];
        const inbox = fl.find((f) => f.name.toUpperCase() === "INBOX") ?? fl[0];
        return n + (inbox?.exists ?? 0);
      }, 0);
      if (total === 0) return base.filter((f) => f.id !== "all-inboxes");
    }
    return base;
  }, [accounts, folderLists, demo]);

  /** Per-account expandable sections. Demo children reuse the `acct:slug`
   * key shape (demo loader parses accountId + folder slug); live children
   * are the real `accountId:folderId` keys. */
  const accountSections = useMemo(() => {
    const demoFolderUnread = (accountId: string, slug: string) =>
      DEMO_MESSAGES.filter((m) => m.unread && m.accountId === accountId && m.folder === slug).length;
    return accounts.map((a) => ({
      id: a.id,
      email: a.email,
      displayName: a.displayName,
      color: a.color,
      trust: a.trust as Severity,
      muted: a.muted === true,
      unread: a.unread,
      items: demo
        ? [
            { id: `${a.id}:inbox`, label: "Inbox", unread: demoFolderUnread(a.id, "inbox") },
            { id: `${a.id}:sent`, label: "Sent", unread: demoFolderUnread(a.id, "sent") },
            { id: `${a.id}:trash`, label: "Trash", unread: demoFolderUnread(a.id, "trash") },
            { id: `${a.id}:drafts`, label: "Drafts", unread: demoFolderUnread(a.id, "drafts") },
            { id: `${a.id}:spam`, label: "Spam", unread: demoFolderUnread(a.id, "spam") },
          ]
        : (folderLists[a.id] ?? []).map((f) => ({
            id: `${a.id}:${f.id}`,
            label: f.name,
            unread: a.muted ? 0 : (f.unseen ?? 0),
            // T-322: folder-management gates — local-only CRUD, delete
            // needs empty+leaf (contract §kiwi_folder_*). Demo items lack
            // these fields → ops stay disabled there anyway.
            folderId: f.id,
            origin: f.origin,
            parentId: f.parentId,
            exists: f.exists,
          })),
    }));
  }, [demo, accounts, folderLists]);

  /** Right-aligned counts on the Favorites rows — real `unseen` sums where
   * a folder class backs the row; 0 (→ badge hidden) when no aggregate
   * exists yet (flagged/unreplied/snoozed have no store-wide count). */
  const smartUnread = useMemo(() => {
    const counts: Record<string, number> = {};
    if (demo) {
      const unreadAll = DEMO_MESSAGES.filter((m) => m.unread).length;
      const perFolder = (slug: string) => DEMO_MESSAGES.filter((m) => m.unread && m.folder === slug).length;
      counts["all-inboxes"] = perFolder("inbox");
      counts["outbox"] = 0;
      counts["sent"] = perFolder("sent");
      counts["trash"] = perFolder("trash");
      counts["drafts"] = perFolder("drafts");
      counts["junk"] = perFolder("spam");
      counts["unread"] = unreadAll;
      counts["flagged"] = DEMO_MESSAGES.filter((m) => m.starred).length;
      counts["unreplied"] = DEMO_MESSAGES.filter((m) => m.folder === "inbox" && m.answered !== true).length;
      counts["snoozed"] = perFolder("snoozed");
      return counts;
    }
    const sumMatch = (re: RegExp) => {
      let n = 0;
      for (const a of accountsRaw) {
        if (muted.includes(a.id)) continue;
        for (const f of folderLists[a.id] ?? []) if (re.test(f.name)) n += f.unseen ?? 0;
      }
      return n;
    };
    counts["all-inboxes"] = sumMatch(/inbox/i);
    counts["outbox"] = 0;
    counts["sent"] = sumMatch(/sent/i);
    counts["trash"] = sumMatch(/trash|deleted|bin/i);
    counts["drafts"] = sumMatch(/draft/i);
    counts["junk"] = sumMatch(/junk|spam/i);
    counts["unread"] = counts["all-inboxes"];
    counts["flagged"] = 0;
    counts["unreplied"] = 0;
    counts["snoozed"] = 0;
    return counts;
  }, [demo, accountsRaw, folderLists, muted]);

  const folders = useMemo(() => {
    const list = [...smartFolders];
    for (const s of accountSections) {
      for (const f of s.items) list.push({ id: f.id, label: `${s.displayName || s.email} / ${f.label}` });
    }
    return list;
  }, [smartFolders, accountSections]);

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

  return { muted, emailById, accounts, folders, folderLabel, filtersListLabel, unreadByFolder, smartFolders, accountSections, smartUnread };
}
