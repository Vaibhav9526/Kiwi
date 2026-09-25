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
import { listen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccountView,
  AppInfoView,
  AttachmentSavedView,
  AuditEventView,
  AuditIntegrityView,
  AutoconfigSuggestion,
  ChallengeView,
  ContactInput,
  ContactView,
  CopyResultView,
  DeleteResultView,
  DeliverabilityBeginView,
  DeliverabilityReportView,
  DeliverabilitySendView,
  DeliverabilityStatusView,
  DeviceView,
  FindingDetailView,
  ForensicsExportView,
  FolderView,
  MailChangedEvent,
  LinkClickVerdict,
  MboxExportView,
  MboxImportView,
  MessageBodyView,
  MessagePatch,
  MessageRef,
  MessageSourceView,
  MessageUpdateView,
  MessageView,
  MoveResultView,
  OAuth2BeginView,
  OAuth2PollView,
  OAuth2StatusView,
  OutboxItem,
  PairBeginView,
  PairStatusView,
  Pop3PolicyView,
  RemoteContentView,
  RenderedBodyView,
  RuleHitView,
  RulePreviewView,
  RulesApplyView,
  RuleView,
  SearchHit,
  SecuritySessionView,
  SandboxOpenView,
  SandboxSessionsView,
  SecurityStatusView,
  SendReceipt,
  SetJunkView,
  SnoozePreset,
  SnoozeResultView,
  SnoozedMessageView,
  StorageCompactView,
  StorageStatsView,
  SyncStatusView,
  TagCountView,
  RenderedTemplateView,
  TemplateInput,
  TemplateView,
  TempDiscardView,
  TempExtendView,
  TempMailboxView,
  TempMessageView,
  TempPollView,
  UnsnoozeResultView,
  UnsubscribeAction,
  UnsubscribeResultView,
  VCardExportView,
  VCardImportView,
  VerifyResult,
} from "./kiwi";
import { parseAutoconfigSuggestion, parseContact, parseOAuth2Begin, parseOAuth2Poll, parseOAuth2Status, parseSandboxSessions, parseSearchHit, parseSecuritySession } from "./kiwi";
import {
  decodeDeliverabilityBeginView,
  decodeDeliverabilityReportView,
  decodeDeliverabilitySendView,
  decodeDeliverabilityStatusView,
  decodeTempDiscardView,
  decodeTempExtendView,
  decodeTempMailboxView,
  decodeTempMessageView,
  decodeTempPollView,
} from "./integrations";

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
    public readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = "IpcError";
  }
}

/** True inside the Tauri webview; false in a plain browser (vite dev). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function retryAfterMs(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return undefined;
  return Math.min(value, 60 * 60 * 1000);
}

function asIpcError(value: unknown): IpcError | null {
  if (typeof value === "object" && value !== null) {
    const r = value as Record<string, unknown>;
    if (typeof r["code"] === "string" && typeof r["message"] === "string") {
      const hint = retryAfterMs(r["retryAfterMs"] ?? r["retry_after_ms"]);
      return new IpcError(r["code"], r["message"], hint);
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

function decoded<T>(value: T | null, command: string): T {
  if (value === null) throw new IpcError("malformed-response", `malformed integration response for ${command}`);
  return value;
}

function asArray<T>(raw: unknown): T[] {
  return Array.isArray(raw) ? (raw as T[]) : [];
}

/* ---------------- events ---------------- */

/**
 * Subscribe to `kiwi://mail-changed` (ipc.md §6 event; emitted by the
 * sync worker after a pass that changed stored mail). Caller owns
 * debouncing/refresh policy; the returned unlisten detaches.
 * Non-Tauri contexts reject with BackendUnavailableError.
 */
export function onMailChanged(handler: (ev: MailChangedEvent) => void): Promise<UnlistenFn> {
  if (!isTauri()) {
    return Promise.reject(new BackendUnavailableError("kiwi://mail-changed", "not in Tauri webview"));
  }
  return listen<MailChangedEvent>("kiwi://mail-changed", (e) => handler(e.payload));
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
  /** Canonical §9d unlock path — backend fixes `event:"unlock"` and owns
   *  challenge id / nonce / session / TTL; renderer supplies only deviceId. */
  unlockChallenge(deviceId: string): Promise<ChallengeView> {
    return call<ChallengeView>("unlock_challenge", { deviceId });
  },
  /** Compat alias (kiwi_request_challenge) — for non-unlock challenge
   *  events. Still backed by PairEngine. */
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
   * MX heuristics → manual). Invokes `kiwi_discover_account`, the
   * contract-ratified command name (ipc.md §5; `kiwi_lookup_autoconfig`
   * is a registered alias for stale wrappers — T-230). The backend
   * returns a DiscoveryOutcomeView; the parser unwraps `suggestion`.
   * When the backend is absent this throws BackendUnavailableError and
   * the wizard falls back to its labeled local stub / manual entry.
   */
  async lookupAutoconfig(email: string): Promise<AutoconfigSuggestion | null> {
    const raw = await call<unknown>("kiwi_discover_account", { email });
    return parseAutoconfigSuggestion(raw);
  },

  /* ---------------- oauth2 acquisition (gated, T-230/243) ---------------- */

  /**
   * `kiwi_oauth2_begin(provider, email?)` → the ticket plus whatever the
   * user must see: `userCode` + `verificationUri` (device_code) or
   * `authorizeUrl` to open in the system browser (loopback_code).
   * `oauth2-not-configured` lands here as an IpcError when the deployment
   * ships no client id for the provider.
   */
  async oauth2Begin(provider: string, email?: string): Promise<OAuth2BeginView | null> {
    const raw = await call<unknown>("kiwi_oauth2_begin", { provider, email });
    return parseOAuth2Begin(raw);
  },
  /**
   * `kiwi_oauth2_poll(ticketId)` → pending / complete / error. Terminal
   * failures come back as `status:"error"` with a §9f `errorCode`;
   * transient transport failures throw IpcError (the grant stays alive).
   */
  async oauth2Poll(ticketId: string): Promise<OAuth2PollView | null> {
    const raw = await call<unknown>("kiwi_oauth2_poll", { ticketId });
    return parseOAuth2Poll(raw);
  },
  /** `kiwi_oauth2_cancel(ticketId)` — abandon a grant the user walked away from. */
  async oauth2Cancel(ticketId: string): Promise<boolean> {
    const raw = await call<unknown>("kiwi_oauth2_cancel", { ticketId });
    return typeof raw === "object" && raw !== null && (raw as Record<string, unknown>)["cancelled"] === true;
  },
  /**
   * `kiwi_oauth2_status(accountId)` → auth posture for the accounts view
   * (`authMethod`, `needsRefresh`, `credentialPresent`) — no token
   * material ever crosses this boundary.
   */
  async oauth2Status(accountId: string): Promise<OAuth2StatusView | null> {
    const raw = await call<unknown>("kiwi_oauth2_status", { accountId });
    return parseOAuth2Status(raw);
  },
  /**
   * `kiwi_open_external(url, sourceUrl?)` — HTTPS system-browser handoff.
   * Message-link callers pass sourceUrl; T-273 then enforces fresh risk and
   * refuses failed links with sandbox-required.
   */
  openExternal(url: string, sourceUrl?: string): Promise<void> {
    return call<void>("kiwi_open_external", { url, sourceUrl });
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

  /* ---------------- backend prefs (T-167; commands landed T-175) ---------------- */

  /**
   * Backend preference bag over the ipc.md §9c key/value store
   * (`kiwi_prefs_*`, global scope). `getPrefs` folds the `{key, value}[]`
   * list rows into a bag; `setPrefs` pushes each entry through the
   * per-key `kiwi_prefs_set` — the first rejection aborts the push so
   * callers see a failed sync rather than a partial one. When the backend
   * is absent both throw BackendUnavailableError and the UI runs on
   * localStorage (source of truth offline; backend wins on load-merge).
   */
  async getPrefs(): Promise<Record<string, unknown>> {
    const rows = asArray<{ key: string; value: unknown }>(
      await call<unknown>("kiwi_prefs_list"),
    );
    const bag: Record<string, unknown> = {};
    for (const row of rows) {
      if (row && typeof row.key === "string") bag[row.key] = row.value;
    }
    return bag;
  },
  async setPrefs(prefs: Record<string, unknown>): Promise<{ saved: number }> {
    let saved = 0;
    for (const [key, value] of Object.entries(prefs)) {
      await call<unknown>("kiwi_prefs_set", { key, value });
      saved += 1;
    }
    return { saved };
  },
  /**
   * Single pref read — `null` = unset (ipc.md §9c). `getPrefs` covers the
   * bag; this is for one-key lookups that should not list the store.
   */
  prefsGet(key: string, accountId?: string): Promise<unknown> {
    return call<unknown>("kiwi_prefs_get", { key, accountId });
  },

  /* ---------------- contacts (gated, T-173, pending backend) ---------------- */

  /**
   * Address book per docs/contracts/contacts.md §3 (`kiwi.contacts/1`).
   * When the backend is absent each call throws BackendUnavailableError
   * and views use the labeled localStorage book instead.
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
  async contactsByTag(tag: string, limit?: number): Promise<ContactView[]> {
    const raw = await call<unknown>("kiwi_contacts_by_tag", { tag, limit });
    if (!Array.isArray(raw)) return [];
    const out: ContactView[] = [];
    for (const item of raw) {
      const c = parseContact(item);
      if (c) out.push(c);
    }
    return out;
  },
  contactTags(): Promise<TagCountView[]> {
    return call<TagCountView[]>("kiwi_contact_tags");
  },
  importVcards(vcardText: string): Promise<VCardImportView> {
    // Wire arg is `vcardText` (Rust `vcard_text` → Tauri camelCase).
    return call<VCardImportView>("kiwi_import_vcards", { vcardText });
  },
  exportVcards(contactIds?: string[]): Promise<VCardExportView> {
    return call<VCardExportView>("kiwi_export_vcards", { contactIds });
  },

  /* ---------------- mail read (gated) ---------------- */

  async listFolders(accountId: string): Promise<FolderView[]> {
    return asArray<FolderView>(await call<unknown>("kiwi_list_folders", { accountId }));
  },
  /** T-319: local store folder only; no IMAP server CREATE is implied. */
  createFolder(accountId: string, name: string, parentId?: number | null): Promise<FolderView> {
    return call<FolderView>("kiwi_folder_create", { accountId, parentId: parentId ?? null, name });
  },
  renameFolder(accountId: string, folderId: number, newName: string): Promise<FolderView> {
    return call<FolderView>("kiwi_folder_rename", { accountId, folderId, newName });
  },
  deleteFolder(accountId: string, folderId: number): Promise<{ folderId: number }> {
    return call<{ folderId: number }>("kiwi_folder_delete", { accountId, folderId });
  },
  async listMessages(accountId: string, folderId: number, limit?: number): Promise<MessageView[]> {
    return asArray<MessageView>(await call<unknown>("kiwi_list_messages", { accountId, folderId, limit }));
  },
  getMessage(accountId: string, folderId: number, uid: number): Promise<MessageBodyView> {
    return call<MessageBodyView>("kiwi_get_message", { accountId, folderId, uid });
  },
  /** T-295: verbatim RFC822 source (lossy UTF-8, 8 MiB cap). Absent → typed
   * `not-found`, never an empty string. */
  messageSource(accountId: string, folderId: number, uid: number): Promise<MessageSourceView> {
    return call<MessageSourceView>("kiwi_message_source", { accountId, folderId, uid });
  },
  syncAccount(accountId: string, folders?: string[]): Promise<Record<string, unknown>[]> {
    return call<Record<string, unknown>[]>("kiwi_sync_account", { accountId, folders });
  },
  /** Per-account sync rows; omit `accountId` for every configured account. */
  syncStatus(accountId?: string): Promise<SyncStatusView[]> {
    return call<SyncStatusView[]>("kiwi_sync_status", { accountId });
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
  /** T-295: per-account POP3 deletion policy — `true` DELEs after ingest
   * (default keep-on-server). POP3 accounts only. */
  setPop3Policy(accountId: string, deleteAfterDownload: boolean): Promise<Pop3PolicyView> {
    return call<Pop3PolicyView>("kiwi_set_pop3_policy", { accountId, deleteAfterDownload });
  },
  /** T-309: import a Berkeley-mbox file into an account folder (default the
   * local `Import` folder). Report counts are honest — duplicates/expunged/
   * failed members are skipped and counted, never silently dropped. */
  importMbox(accountId: string, path: string, folder?: string): Promise<MboxImportView> {
    return call<MboxImportView>("kiwi_import_mbox", { accountId, path, folder });
  },
  /**
   * `kiwi_mailbox_export_mbox` (T-316) — mirror of the importer. Lock-gated,
   * atomic write (`.kiwi-part` + rename), honest `partial`/`skipped`/`bytes`.
   * Contract: docs/contracts/ipc.md §6j.
   */
  mailboxExportMbox(folderId: number, destPath: string): Promise<MboxExportView> {
    return call<MboxExportView>("kiwi_mailbox_export_mbox", { folderId, destPath });
  },
  linkClick(accountId: string, folderId: number, uid: number, url: string): Promise<LinkClickVerdict> {
    return call<LinkClickVerdict>("kiwi_link_click", { accountId, folderId, uid, url });
  },
  sandboxOpenLink(url: string): Promise<SandboxOpenView> {
    return call<SandboxOpenView>("kiwi_sandbox_open_link", { url });
  },
  sandboxOpenAttachment(folderId: number, uid: number, filename: string): Promise<SandboxOpenView> {
    return call<SandboxOpenView>("kiwi_sandbox_open_attachment", { folderId, uid, filename });
  },
  /**
   * T-300: bounded record of completed sandbox opens, newest first — the
   * Agenda security card's pending-sessions row. Resolves to `{sessions: []}`
   * when nothing has been opened (absence is not an error).
   */
  async sandboxSessions(): Promise<SandboxSessionsView> {
    const raw = await call<unknown>("kiwi_sandbox_sessions", {});
    return parseSandboxSessions(raw) ?? { sessions: [] };
  },

  /**
   * Execute the message's stored unsubscribe offer (T-234, F3).
   * `action="http"` POSTs the advertised https URL (one-click endpoints
   * get the RFC 8058 body; plain URLs need `consent: true`).
   * `action="mailto"` enqueues via the normal outbox — ALWAYS needs
   * `consent: true`. `consent-required` is thrown when the flag is
   * missing where required.
   */
  messageUnsubscribe(
    accountId: string,
    folderId: number,
    uid: number,
    action: UnsubscribeAction,
    consent?: boolean,
  ): Promise<UnsubscribeResultView> {
    return call<UnsubscribeResultView>("kiwi_message_unsubscribe", {
      accountId,
      folderId,
      uid,
      action,
      consent,
    });
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
  /**
   * Local duplicate of `uids` into `dstFolderId` under fresh local uids —
   * the Copy-to sibling of move (T-325). NOT a server-side IMAP COPY: a
   * copy of a synced-folder message is a local-only row. Smart/system
   * destinations are refused.
   */
  copyMessages(
    accountId: string,
    srcFolderId: number,
    dstFolderId: number,
    uids: number[],
  ): Promise<CopyResultView> {
    return call<CopyResultView>("kiwi_copy_messages", { accountId, srcFolderId, dstFolderId, uids });
  },

  /* ---------------- snooze (gated, T-255) ---------------- */

  /**
   * Park messages locally until a deadline — never a server-side move;
   * parked rows leave folder lists and return at the sync-pass sweep.
   * Deadline is exactly one of `untilUnix` | `preset`.
   */
  snoozeMessages(
    accountId: string,
    refs: MessageRef[],
    deadline: { untilUnix?: number; preset?: SnoozePreset },
  ): Promise<SnoozeResultView> {
    return call<SnoozeResultView>("kiwi_message_snooze", { accountId, refs, ...deadline });
  },
  unsnoozeMessages(accountId: string, refs: MessageRef[]): Promise<UnsnoozeResultView> {
    return call<UnsnoozeResultView>("kiwi_message_unsnooze", { accountId, refs });
  },
  /** Account-wide parked mail, soonest-due first (the Snoozed view). */
  async listSnoozed(accountId: string, limit?: number): Promise<SnoozedMessageView[]> {
    return asArray<SnoozedMessageView>(await call<unknown>("kiwi_list_snoozed", { accountId, limit }));
  },

  /* ---------------- junk (gated, T-263) ---------------- */

  /**
   * Mark refs junk (`\Junk` flag + move to the account's Junk folder) or
   * un-junk them (clear flag; Junk-folder rows return to INBOX). IMAP
   * writes through immediately; POP3 is local-only. Refs may span
   * folders; every folderId must belong to `accountId`.
   */
  setJunk(accountId: string, refs: MessageRef[], junk: boolean): Promise<SetJunkView> {
    return call<SetJunkView>("kiwi_message_set_junk", { accountId, refs, junk });
  },

  /* ---------------- inbox rules (gated, T-233/T-244) ---------------- */

  /**
   * Stored rules: `accountId` scopes to that account's rules PLUS the
   * global ones; omit for globals only.
   */
  async rulesList(accountId?: string): Promise<RuleView[]> {
    return asArray<RuleView>(await call<unknown>("kiwi_rules_list", { accountId }));
  },
  /**
   * Create-or-replace a rule — `rule.id` is caller-assigned. The backend
   * re-runs `Rule::validate` (renderer input is untrusted): malformed
   * specs throw `invalid-input`, a foreign `accountId` throws
   * `not-found`.
   */
  rulesUpsert(rule: RuleView): Promise<RuleView> {
    return call<RuleView>("kiwi_rules_upsert", { rule });
  },
  rulesDelete(ruleId: string): Promise<{ removed: boolean }> {
    return call<{ removed: boolean }>("kiwi_rules_delete", { ruleId });
  },
  /**
   * Re-run the enabled ruleset over stored messages (Trash never
   * scanned). Deliberate re-run — ingest-time application is automatic.
   */
  rulesApplyNow(accountId: string): Promise<RulesApplyView> {
    return call<RulesApplyView>("kiwi_rules_apply_now", { accountId });
  },
  /** Matched-rule audit trail, newest first (limit default 100). */
  async rulesHits(accountId: string, limit?: number): Promise<RuleHitView[]> {
    return asArray<RuleHitView>(await call<unknown>("kiwi_rules_hits", { accountId, limit }));
  },
  /**
   * "Test this rule" dry-run — evaluates the candidate ALONE against the
   * newest `limit` stored messages; never executes actions, never writes
   * hits or watermarks (limit default 50, clamp 1–200).
   */
  rulesPreview(accountId: string, rule: RuleView, limit?: number): Promise<RulePreviewView> {
    return call<RulePreviewView>("kiwi_rules_preview", { accountId, rule, limit });
  },

  /* ---------------- message templates (gated, T-288) ---------------- */

  /** Stored templates, name-then-id order (ipc.md §6i). */
  async templatesList(): Promise<TemplateView[]> {
    return asArray<TemplateView>(await call<unknown>("kiwi_templates_list"));
  },
  /**
   * Create a template — the store assigns `tpl-N` and timestamps;
   * caller supplies content only. The `tpl-` prefix is reserved.
   */
  templatesCreate(template: TemplateInput): Promise<TemplateView> {
    return call<TemplateView>("kiwi_templates_create", { template });
  },
  /**
   * Full replace by `template.id`, not a merge — `createdUnix` is
   * preserved. Absent id throws `not-found`.
   */
  templatesUpdate(template: TemplateView): Promise<TemplateView> {
    return call<TemplateView>("kiwi_templates_update", { template });
  },
  /** Idempotent — `removed: false` is a normal answer, not an error. */
  templatesDelete(templateId: string): Promise<{ removed: boolean }> {
    return call<{ removed: boolean }>("kiwi_templates_delete", { templateId });
  },
  /**
   * Server-side `{{var}}` substitution — returns ready-to-use fields
   * plus `missingVars` (well-formed placeholders with no value, left
   * verbatim in the text). Vars bounds: ≤64 entries, ≤4 KiB values.
   */
  templatesRender(
    templateId: string,
    vars?: Record<string, string>,
  ): Promise<RenderedTemplateView> {
    return call<RenderedTemplateView>("kiwi_templates_render", { templateId, vars });
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
  /** Reschedule a queued send (unix seconds); returns the updated receipt. */
  scheduleSend(queueId: string, sendAtUnix: number): Promise<SendReceipt> {
    return call<SendReceipt>("kiwi_schedule_send", { queueId, sendAtUnix });
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
  /**
   * T-323/T-324: real app-audit rows from audit.jsonl — NOT transport
   * sessions. Newest first; beforeUnix is an exclusive keyset cursor.
   */
  async auditEvents(beforeUnix?: number, limit?: number): Promise<AuditEventView[]> {
    return asArray<AuditEventView>(await call<unknown>("kiwi_audit_events", { beforeUnix, limit }));
  },
  /**
   * T-330/T-333: storage diagnostics + compact. Stats are real measurements
   * (null = unmeasurable, never estimated); compact runs VACUUM and refuses
   * `sync-in-flight` with a retry hint — callers show that message verbatim.
   */
  storageStats(): Promise<StorageStatsView> {
    return call<StorageStatsView>("kiwi_storage_stats");
  },
  storageCompact(): Promise<StorageCompactView> {
    return call<StorageCompactView>("kiwi_storage_compact");
  },
  /**
   * T-331: audit-chain health without reading rows. Ungated, so a security
   * strip can poll it. An unrecognized/absent field degrades to `unknown`
   * (never `ok`) — fail-closed display.
   */
  async auditIntegrity(): Promise<AuditIntegrityView> {
    const raw = await call<unknown>("kiwi_audit_integrity");
    const rec = (raw ?? {}) as Record<string, unknown>;
    const state = rec["state"];
    const auditOk = rec["auditOk"];
    if (state === "ok" || state === "corrupt" || state === "unknown") {
      return { state, auditOk: typeof auditOk === "boolean" ? auditOk : state === "unknown" ? null : state === "ok" };
    }
    return { state: "unknown", auditOk: null };
  },
  /**
   * T-320: save one session's deterministic forensic report to `destPath` as a
   * self-verifying artifact (SHA-256 of its own canonical bytes embedded in
   * the file). The written file round-trips through
   * `kiwi_forensics::report::ExportEnvelope::verify_bytes` — no external
   * trust store needed.
   */
  forensicsExport(sessionId: string, destPath: string): Promise<ForensicsExportView> {
    return call<ForensicsExportView>("kiwi_forensics_export", { sessionId, destPath });
  },

  /**
   * T-260: typed `SecuritySessionView` (ipc.md §3 canonical shape) with
   * safe-render normalization — an unrecognized enum token degrades to its
   * honest unknown form instead of rendering verbatim. A malformed envelope
   * surfaces as `null` so the view can say so rather than show a blank card.
   */
  async sessionDetail(sessionId: string): Promise<SecuritySessionView | null> {
    return parseSecuritySession(await call<unknown>("kiwi_session_detail", { sessionId }));
  },
  findingDetail(findingId: string): Promise<FindingDetailView> {
    return call<FindingDetailView>("kiwi_finding_detail", { findingId });
  },
  securityReport(accountId?: string): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_security_report", { accountId });
  },

  /* ---------------- pairing flow (ipc.md §9d) ----------------
   * Canonical commands; `pair_begin`/`pair_status` are exempt from the lock
   * gate only while a backend-owned pairing flow is live — the renderer
   * cannot activate one. */

  /** Begin device pairing — backend owns the ticket/expiry/endpoint. */
  pairBegin(deviceLabel: string): Promise<PairBeginView> {
    return call<PairBeginView>("pair_begin", { deviceLabel });
  },
  /** Poll a ticket — read-only; never consumes. */
  pairStatus(ticket: string): Promise<PairStatusView> {
    return call<PairStatusView>("pair_status", { ticket });
  },

  /* ---------------- devices / org binding (gated) ---------------- */

  /** Compat registration seam (kiwi_register_device) — pending until a
   *  device-pairing challenge verifies. */
  registerDevice(input: { label: string; algorithm: string; publicKeyB64: string; keystoreRef?: string | null }): Promise<DeviceView> {
    return call<DeviceView>("kiwi_register_device", { input });
  },
  async listDevices(): Promise<DeviceView[]> {
    return asArray<DeviceView>(await call<unknown>("device_list"));
  },
  revokeDevice(deviceId: string): Promise<SecurityStatusView> {
    return call<SecurityStatusView>("device_revoke", { deviceId });
  },
  setOrgBinding(orgId: string | null, baseUrl: string | null): Promise<{ orgId: string; baseUrl: string } | null> {
    return call("kiwi_set_org_binding", { orgId, baseUrl });
  },

  /* ---------------- integrations (gated, T-227, ipc.md §9e) ---------------- */

  /**
   * Disposable public inbox (GuerrillaMail). Every response carries
   * `publicInboxNotice` — display it; the inbox is PUBLIC, anyone who
   * knows the address can read its mail. One session at a time; create
   * replaces, discard clears.
   */
  async integrationsTempmailCreate(localPart?: string): Promise<TempMailboxView> {
    const raw = await call<unknown>("kiwi_integrations_tempmail_create", { localPart });
    return decoded(decodeTempMailboxView(raw), "kiwi_integrations_tempmail_create");
  },
  async integrationsTempmailPoll(): Promise<TempPollView> {
    const raw = await call<unknown>("kiwi_integrations_tempmail_poll");
    return decoded(decodeTempPollView(raw), "kiwi_integrations_tempmail_poll");
  },
  /** Fetched message — `html` arrives pre-sanitized (remote resources
   * always stripped for a public inbox); raw MIME never crosses IPC. */
  async integrationsTempmailFetch(mailId: string): Promise<TempMessageView> {
    const raw = await call<unknown>("kiwi_integrations_tempmail_fetch", { mailId });
    return decoded(decodeTempMessageView(raw), "kiwi_integrations_tempmail_fetch");
  },
  async integrationsTempmailDiscard(): Promise<TempDiscardView> {
    const raw = await call<unknown>("kiwi_integrations_tempmail_discard");
    return decoded(decodeTempDiscardView(raw), "kiwi_integrations_tempmail_discard");
  },
  async integrationsTempmailExtend(): Promise<TempExtendView> {
    const raw = await call<unknown>("kiwi_integrations_tempmail_extend");
    return decoded(decodeTempExtendView(raw), "kiwi_integrations_tempmail_extend");
  },

  /**
   * Outbound deliverability test (email-spam-tester). `begin` reserves a
   * single-use address and returns a single-use `consentToken`; `send`
   * consumes it — the backend enforces consent (`consent-required` on
   * missing/wrong/replayed token). Recipients in `message` are ignored;
   * the sole recipient is the reserved address.
   */
  async integrationsDeliverabilityBegin(): Promise<DeliverabilityBeginView> {
    const raw = await call<unknown>("kiwi_integrations_deliverability_begin");
    return decoded(decodeDeliverabilityBeginView(raw), "kiwi_integrations_deliverability_begin");
  },
  async integrationsDeliverabilitySend(
    testId: string,
    consentToken: string,
    accountId: string,
    message: Record<string, unknown>,
  ): Promise<DeliverabilitySendView> {
    const raw = await call<unknown>("kiwi_integrations_deliverability_send", {
      testId,
      consentToken,
      accountId,
      message,
    });
    return decoded(decodeDeliverabilitySendView(raw), "kiwi_integrations_deliverability_send");
  },
  async integrationsDeliverabilityStatus(testId: string): Promise<DeliverabilityStatusView> {
    const raw = await call<unknown>("kiwi_integrations_deliverability_status", { testId });
    return decoded(decodeDeliverabilityStatusView(raw), "kiwi_integrations_deliverability_status");
  },
  async integrationsDeliverabilityReport(testId: string): Promise<DeliverabilityReportView> {
    const raw = await call<unknown>("kiwi_integrations_deliverability_report", { testId });
    return decoded(decodeDeliverabilityReportView(raw), "kiwi_integrations_deliverability_report");
  },

  /* ---------------- endpoint signals (exempt) ---------------- */

  collectEndpointSignals(): Promise<Record<string, unknown>> {
    return call<Record<string, unknown>>("kiwi_collect_endpoint_signals");
  },
};
