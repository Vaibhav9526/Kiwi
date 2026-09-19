/**
 * Typed Tauri IPC layer (T-143) — one wrapper per command in
 * docs/contracts/ipc.md (`kiwi.ipc/1`). Command names/args are the contract
 * with src-tauri/src/lib.rs (Agent 7 owns the backend; frontend never edits
 * it). No business logic here — transport + error normalization only.
 *
 * Error model: transport problems (not in a webview, IPC failure) throw
 * BackendUnavailableError → views fall back to labeled demo data. Backend
 * verdicts (including `locked`) arrive as {code, message} and throw IpcError
 * → views render error/lock states, never demo data as real.
 */
import { invoke } from "@tauri-apps/api/core";
import type {
  AccountView,
  AppInfoView,
  ChallengeView,
  DeviceView,
  FolderView,
  MessageBodyView,
  MessageView,
  OutboxItem,
  SecurityStatusView,
  VerifyResult,
} from "./kiwi";

export class BackendUnavailableError extends Error {
  constructor(command: string, cause?: unknown) {
    super(`KIWI backend unavailable for '${command}'${cause ? `: ${cause instanceof Error ? cause.message : String(cause)}` : ""}`);
    this.name = "BackendUnavailableError";
  }
}

/** Backend verdict — see ipc.md §11 error codes. */
export class IpcError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "IpcError";
  }
}

/** True inside the Tauri webview; false in a plain browser (vite dev). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function asIpcError(value: unknown): IpcError | null {
  if (typeof value === "object" && value !== null) {
    const r = value as Record<string, unknown>;
    if (typeof r["code"] === "string" && typeof r["message"] === "string") {
      return new IpcError(r["code"], r["message"]);
    }
  }
  if (typeof value === "string" && value.length > 0 && value.length < 300) {
    return new IpcError("internal", value);
  }
  return null;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) throw new BackendUnavailableError(command, "not in Tauri webview");
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    throw asIpcError(err) ?? new BackendUnavailableError(command, err);
  }
}

function asArray<T>(raw: unknown): T[] {
  return Array.isArray(raw) ? (raw as T[]) : [];
}

/* ---------------- system / lock path (exempt) ---------------- */

export const api = {
  ping(): Promise<string> {
    return call<string>("kiwi_ping");
  },
  appInfo(): Promise<AppInfoView> {
    return call<AppInfoView>("kiwi_app_info");
  },
  securityStatus(): Promise<SecurityStatusView> {
    return call<SecurityStatusView>("kiwi_security_status");
  },
  lock(): Promise<SecurityStatusView> {
    return call<SecurityStatusView>("kiwi_lock");
  },
  requestChallenge(deviceId: string, event: "unlock" | "device-pairing" | "recovery" | "elevated-action"): Promise<ChallengeView> {
    return call<ChallengeView>("kiwi_request_challenge", { deviceId, event });
  },
  submitChallenge(response: {
    challengeId: string;
    deviceId: string;
    sessionId: string;
    event: string;
    signatureB64: string;
  }): Promise<SecurityStatusView> {
    // Called only by flows holding a real authenticator signature — the UI
    // never signs. Exposed for completeness; unused by current views.
    return call<SecurityStatusView>("kiwi_submit_challenge", { response });
  },

  /* ---------------- accounts (gated) ---------------- */

  async listAccounts(): Promise<AccountView[]> {
    return asArray<AccountView>(await call<unknown>("kiwi_list_accounts"));
  },
  addAccount(account: Record<string, unknown>): Promise<AccountView> {
    return call<AccountView>("kiwi_add_account", { account });
  },
  removeAccount(accountId: string): Promise<{ removed: boolean }> {
    return call<{ removed: boolean }>("kiwi_remove_account", { accountId });
  },
  testAccount(accountId: string): Promise<VerifyResult[]> {
    return call<VerifyResult[]>("kiwi_test_account", { accountId });
  },
  verifyServer(input: Record<string, unknown>): Promise<VerifyResult> {
    return call<VerifyResult>("kiwi_verify_server", { input });
  },

  /* ---------------- mail read (gated) ---------------- */

  async listFolders(accountId: string): Promise<FolderView[]> {
    return asArray<FolderView>(await call<unknown>("kiwi_list_folders", { accountId }));
  },
  async listMessages(accountId: string, folderId: number, limit?: number): Promise<MessageView[]> {
    return asArray<MessageView>(await call<unknown>("kiwi_list_messages", { accountId, folderId, limit }));
  },
  getMessage(accountId: string, folderId: number, uid: number): Promise<MessageBodyView> {
    return call<MessageBodyView>("kiwi_get_message", { accountId, folderId, uid });
  },
  syncAccount(accountId: string, folders?: string[]): Promise<Record<string, unknown>[]> {
    return call<Record<string, unknown>[]>("kiwi_sync_account", { accountId, folders });
  },

  /* ---------------- send / outbox (gated) ---------------- */

  sendMessage(
    accountId: string,
    message: Record<string, unknown>,
    options?: { sendAtUnix?: number | null; undoGraceSecs?: number | null },
  ): Promise<{ queueId: string; notBeforeUnix: number; undoWindowUntilUnix: number }> {
    return call("kiwi_send_message", { accountId, message, options });
  },
  cancelSend(queueId: string): Promise<{ cancelled: boolean }> {
    return call<{ cancelled: boolean }>("kiwi_cancel_send", { queueId });
  },
  async listOutbox(): Promise<OutboxItem[]> {
    return asArray<OutboxItem>(await call<unknown>("kiwi_list_outbox"));
  },
  flushOutbox(): Promise<{ sent: number; failed: number; held: number }> {
    return call("kiwi_flush_outbox");
  },

  /* ---------------- security data (gated) ---------------- */

  async securityFindings(accountId?: string): Promise<Record<string, unknown>[]> {
    return asArray<Record<string, unknown>>(await call<unknown>("kiwi_security_findings", { accountId }));
  },
  async securityEvents(limit?: number): Promise<Record<string, unknown>[]> {
    return asArray<Record<string, unknown>>(await call<unknown>("kiwi_security_events", { limit }));
  },
  sessionDetail(sessionId: string): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_session_detail", { sessionId });
  },
  securityReport(accountId?: string): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_security_report", { accountId });
  },

  /* ---------------- devices / org binding (gated) ---------------- */

  registerDevice(input: { label: string; algorithm: string; publicKeyB64: string; keystoreRef?: string | null }): Promise<DeviceView> {
    return call<DeviceView>("kiwi_register_device", { input });
  },
  async listDevices(): Promise<DeviceView[]> {
    return asArray<DeviceView>(await call<unknown>("kiwi_list_devices"));
  },
  revokeDevice(deviceId: string): Promise<SecurityStatusView> {
    return call<SecurityStatusView>("kiwi_revoke_device", { deviceId });
  },
  setOrgBinding(orgId: string | null, baseUrl: string | null): Promise<{ orgId: string; baseUrl: string } | null> {
    return call("kiwi_set_org_binding", { orgId, baseUrl });
  },

  /* ---------------- endpoint signals (exempt) ---------------- */

  collectEndpointSignals(): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_collect_endpoint_signals");
  },
};
