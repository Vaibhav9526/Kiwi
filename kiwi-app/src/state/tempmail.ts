/**
 * Shared disposable-inbox state (T-342). Temp mail used to live entirely
 * inside Settings → Integrations; the inbox is now a first-class sidebar
 * view, so the session state lives in ONE hook instance owned by App and
 * drilled to the three consumers (sidebar badge/quick-action, the
 * Disposable Inbox view, the Integrations management card) — no double
 * polling, no divergent copies of the same backend session.
 *
 * Polling: one resync poll on mount (a live session can survive view
 * remounts — sessions die only with the app), then a 45 s interval while a
 * mailbox exists. `not-found` = no session — honest empty, never an error.
 * Every response carries `publicInboxNotice` verbatim; the latest wins.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, BackendUnavailableError, IpcError } from "../ipc";
import type {
  TempMailboxView,
  TempMessageSummaryView,
  TempMessageView,
} from "../kiwi";
import { PUBLIC_INBOX_NOTICE } from "../kiwi";

export const TEMPMAIL_POLL_MS = 45_000;
/** GuerrillaMail age-out documented in ipc.md §9e.1 — an estimate, labeled as such. */
export const TEMPMAIL_TTL_SECS = 60 * 60;

export function tempmailErr(e: unknown): string {
  return e instanceof IpcError
    ? `${e.code}: ${e.message}`
    : e instanceof BackendUnavailableError
      ? "Backend unavailable — disposable inboxes need the live KIWI backend."
      : e instanceof Error
        ? e.message
        : String(e);
}

export interface TempMail {
  mailbox: TempMailboxView | null;
  messages: TempMessageSummaryView[];
  unread: number;
  notice: string;
  busy: string | null;
  error: string | null;
  flash: string | null;
  /** Seconds the provider's documented age-out was pushed back by `extend` (once, +1h). */
  extraSecs: number;
  /** Provider age-out estimate (created + 60min + extend) — a VIEW renders
   *  the live countdown; null when the backend didn't send createdUnix. */
  expiresAtUnix: number | null;
  create: (localPart?: string) => Promise<boolean>;
  refresh: () => Promise<void>;
  fetchMessage: (mailId: string) => Promise<TempMessageView | null>;
  extend: () => Promise<void>;
  discard: () => Promise<void>;
}

export function useTempMail(live: boolean): TempMail {
  const [mailbox, setMailbox] = useState<TempMailboxView | null>(null);
  const [messages, setMessages] = useState<TempMessageSummaryView[]>([]);
  const [notice, setNotice] = useState(PUBLIC_INBOX_NOTICE);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const [extraSecs, setExtraSecs] = useState(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const poll = useCallback(async () => {
    try {
      const p = await api.integrationsTempmailPoll();
      if (!mounted.current) return;
      setNotice(p.publicInboxNotice);
      setMessages(p.messages);
      if (p.address) {
        setMailbox((prev) => (prev ? { ...prev, address: p.address! } : { address: p.address!, publicInboxNotice: p.publicInboxNotice }));
      }
    } catch (e) {
      // `not-found` means no live session — the honest empty state, not an
      // error. Anything else surfaces so a degraded provider is visible.
      if (mounted.current && !(e instanceof IpcError && e.code === "not-found")) setError(tempmailErr(e));
    }
  }, []);

  // Resync on mount; then a light interval while a mailbox is live.
  useEffect(() => {
    if (!live) return;
    void poll();
  }, [live, poll]);
  useEffect(() => {
    if (!live || !mailbox) return;
    const t = window.setInterval(() => void poll(), TEMPMAIL_POLL_MS);
    return () => window.clearInterval(t);
  }, [live, mailbox, poll]);

  const run = useCallback(async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setError(null);
    setFlash(null);
    try {
      await fn();
    } catch (e) {
      if (mounted.current) setError(tempmailErr(e));
    } finally {
      if (mounted.current) setBusy(null);
    }
  }, []);

  const create = useCallback(
    async (localPart?: string) => {
      let ok = false;
      await run("create", async () => {
        const v = await api.integrationsTempmailCreate(localPart);
        if (!mounted.current) return;
        setMailbox(v);
        setNotice(v.publicInboxNotice);
        setExtraSecs(0);
        const p = await api.integrationsTempmailPoll();
        if (!mounted.current) return;
        setMessages(p.messages);
        ok = true;
      });
      return ok;
    },
    [run],
  );

  const refresh = useCallback(async () => {
    await run("poll", poll);
  }, [run, poll]);

  const fetchMessage = useCallback(
    async (mailId: string) => {
      try {
        const m = await api.integrationsTempmailFetch(mailId);
        if (!mounted.current) return null;
        setNotice(m.publicInboxNotice);
        setMessages((list) => list.map((s) => (s.mailId === mailId ? { ...s, read: true } : s)));
        return m;
      } catch (e) {
        if (mounted.current) setError(tempmailErr(e));
        return null;
      }
    },
    [],
  );

  const extend = useCallback(async () => {
    await run("extend", async () => {
      const v = await api.integrationsTempmailExtend();
      if (!mounted.current) return;
      setNotice(v.publicInboxNotice);
      if (v.extended) setExtraSecs(TEMPMAIL_TTL_SECS);
      if (v.addressCreatedUnix) {
        setMailbox((prev) => (prev ? { ...prev, addressCreatedUnix: v.addressCreatedUnix } : prev));
      }
      setFlash(v.extended ? "Session extended." : v.expired ? "Session already expired server-side." : "Not extended.");
    });
  }, [run]);

  const discard = useCallback(async () => {
    await run("discard", async () => {
      const v = await api.integrationsTempmailDiscard();
      if (!mounted.current) return;
      setNotice(v.publicInboxNotice);
      setMailbox(null);
      setMessages([]);
      setExtraSecs(0);
      setFlash(
        v.discarded
          ? v.remoteForgotten
            ? "Address discarded; the remote session was forgotten too."
            : "Address discarded locally; the remote inbox may still exist briefly."
          : "Nothing to discard.",
      );
    });
  }, [run]);

  const created = mailbox?.addressCreatedUnix;
  const expiresAtUnix = created != null ? created + TEMPMAIL_TTL_SECS + extraSecs : null;

  return {
    mailbox,
    messages,
    unread: messages.filter((m) => !m.read).length,
    notice,
    busy,
    error,
    flash,
    extraSecs,
    expiresAtUnix,
    create,
    refresh,
    fetchMessage,
    extend,
    discard,
  };
}
