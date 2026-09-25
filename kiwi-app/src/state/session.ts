/**
 * Backend session (T-182, extracted from App.tsx verbatim): probe on mount
 * (live vs demo), trust state + 15 s re-poll, accounts/devices refresh,
 * administrative lock. Zero functional change — only relocated.
 */

import { useCallback, useEffect, useState } from "react";
import { api, BackendUnavailableError } from "../ipc";
import { toTrustState } from "../kiwi";
import type { AccountView, AppInfoView, DeviceView, TrustState } from "../kiwi";
import type { NotifyFn } from "./toasts";

export const DEMO_TRUST: TrustState = { trust: "unknown", locked: false, state: "unknown", score: null, requiredAction: "none" };

export function useSession(notify: NotifyFn) {
  const [mode, setMode] = useState<"live" | "demo">("demo");
  const [backendNote, setBackendNote] = useState("probing backend…");
  const [appInfo, setAppInfo] = useState<AppInfoView | null>(null);
  const [accountsRaw, setAccountsRaw] = useState<AccountView[]>([]);
  const [trust, setTrust] = useState<TrustState>(DEMO_TRUST);
  const [devices, setDevices] = useState<DeviceView[]>([]);

  const demo = mode === "demo";

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

  const doLock = useCallback(async () => {
    if (demo) return;
    try {
      setTrust(toTrustState(await api.lock()));
      notify("info", "Mailbox locked.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setBackendNote(msg);
      notify("error", msg);
    }
  }, [demo, notify]);

  return {
    mode,
    demo,
    backendNote,
    setBackendNote,
    appInfo,
    setAppInfo,
    accountsRaw,
    trust,
    setTrust,
    devices,
    refreshStatus,
    refreshAccounts,
    doLock,
  };
}
