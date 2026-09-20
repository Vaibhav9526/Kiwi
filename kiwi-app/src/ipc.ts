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
  AttachmentSavedView,
  AutoconfigSuggestion,
  ChallengeView,
  ContactInput,
  ContactView,
  DeleteResultView,
  DeviceView,
  FindingDetailView,
  FolderView,
  MessageBodyView,
  MessagePatch,
  MessageUpdateView,
  MessageView,
  MoveResultView,
  OutboxItem,
  RemoteContentView,
  RenderedBodyView,
  SearchHit,
  SecurityStatusView,
  VerifyResult,
} from "./kiwi";
import { parseAutoconfigSuggestion, parseContact, parseSearchHit } from "./kiwi";

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

  /* ---------------- autoconfig (gated, T-156) ---------------- */

  /**
   * Discovery chain for an email address (ISPDB → autoconfig XML →
   * MX heuristics → manual). `kiwi_lookup_autoconfig` does not exist in the
   * backend yet (T-135 IPC pending) — until it lands this throws
   * BackendUnavailableError and the wizard falls back to its labeled local
   * stub. Same wrapper either way, so no view changes on land.
   */
  async lookupAutoconfig(email: string): Promise<AutoconfigSuggestion | null> {
    const raw = await call<unknown>("kiwi_lookup_autoconfig", { email });
    return parseAutoconfigSuggestion(raw);
  },

  /* ---------------- search (gated, T-160) ---------------- */

  /**
   * Full-mailbox search (Agent 8's pending command). Until the backend
   * lands it this throws BackendUnavailableError and callers fall back to
   * labeled client-side filtering of already-loaded messages. Same wrapper
   * either way, so no view changes on land.
   */
  async searchMessages(query: string, limit?: number): Promise<SearchHit[]> {
    const raw = await call<unknown>("kiwi_search_messages", { query, limit });
    if (!Array.isArray(raw)) return [];
    const out: SearchHit[] = [];
    raw.forEach((item, i) => {
      const hit = parseSearchHit(item, i);
      if (hit) out.push(hit);
    });
    return out;
  },

  /* ---------------- backend prefs (T-167, pending) ---------------- */

  /**
   * Backend preference bag. Neither command exists yet — until they land
   * both throw BackendUnavailableError and the UI runs on localStorage
   * (source of truth offline; backend wins on load-merge once present).
   * Same wrappers either way, so no view changes on land.
   */
  getPrefs(): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_get_prefs");
  },
  setPrefs(prefs: Record<string, unknown>): Promise<{ saved: number }> {
    return call<{ saved: number }>("kiwi_set_prefs", { prefs });
  },

  /* ---------------- contacts (gated, T-173, pending backend) ---------------- */

  /**
   * Address book per docs/contracts/contacts.md §3 (`kiwi.contacts/1`).
   * No backend command exists yet (Agent 7) — until they land every call
   * throws BackendUnavailableError and views use the labeled localStorage
   * book instead. Same wrappers either way, so no view changes on land.
   */
  async listContacts(limit?: number, offset?: number): Promise<ContactView[]> {
    const raw = await call<unknown>("kiwi_list_contacts", { limit, offset });
    if (!Array.isArray(raw)) return [];
    const out: ContactView[] = [];
    for (const item of raw) {
      const c = parseContact(item);
      if (c) out.push(c);
    }
    return out;
  },
  async searchContacts(query: string, limit?: number): Promise<ContactView[]> {
    const raw = await call<unknown>("kiwi_search_contacts", { query, limit });
    if (!Array.isArray(raw)) return [];
    const out: ContactView[] = [];
    for (const item of raw) {
      const c = parseContact(item);
      if (c) out.push(c);
    }
    return out;
  },
  getContact(contactId: string): Promise<ContactView | null> {
    return call<ContactView | null>("kiwi_get_contact", { contactId });
  },
  createContact(contact: ContactInput): Promise<ContactView> {
    return call<ContactView>("kiwi_create_contact", { contact });
  },
  updateContact(contactId: string, contact: ContactInput): Promise<ContactView> {
    return call<ContactView>("kiwi_update_contact", { contactId, contact });
  },
  deleteContact(contactId: string): Promise<{ removed: boolean }> {
    return call<{ removed: boolean }>("kiwi_delete_contact", { contactId });
  },
  async contactsByEmail(address: string): Promise<ContactView | null> {
    const raw = await call<unknown>("kiwi_contacts_by_email", { address });
    if (raw === null) return null;
    return parseContact(raw);
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

  /* ---------------- message actions (gated, T-146) ---------------- */

  updateMessage(accountId: string, folderId: number, uid: number, patch: MessagePatch): Promise<MessageUpdateView> {
    return call<MessageUpdateView>("kiwi_update_message", { accountId, folderId, uid, patch });
  },
  downloadAttachment(
    accountId: string,
    folderId: number,
    uid: number,
    attachmentIndex: number,
    destPath: string,
  ): Promise<AttachmentSavedView> {
    return call<AttachmentSavedView>("kiwi_download_attachment", {
      accountId,
      folderId,
      uid,
      attachmentIndex,
      destPath,
    });
  },
  renderBody(accountId: string, folderId: number, uid: number): Promise<RenderedBodyView> {
    return call<RenderedBodyView>("kiwi_render_body", { accountId, folderId, uid });
  },
  setRemoteContent(accountId: string, allowed: boolean): Promise<RemoteContentView> {
    return call<RemoteContentView>("kiwi_set_remote_content", { accountId, allowed });
  },

  /* ---------------- delete / move (gated, T-163) ---------------- */

  deleteMessages(
    accountId: string,
    folderId: number,
    uids: number[],
    permanent?: boolean,
  ): Promise<DeleteResultView> {
    return call<DeleteResultView>("kiwi_delete_messages", { accountId, folderId, uids, permanent });
  },
  moveMessages(
    accountId: string,
    srcFolderId: number,
    dstFolderId: number,
    uids: number[],
  ): Promise<MoveResultView> {
    return call<MoveResultView>("kiwi_move_messages", { accountId, srcFolderId, dstFolderId, uids });
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
  findingDetail(findingId: string): Promise<FindingDetailView> {
    return call<FindingDetailView>("kiwi_finding_detail", { findingId });
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
