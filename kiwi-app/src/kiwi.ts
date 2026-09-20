/**
 * Shared frontend types (T-112 scaffold, T-143 IPC binding).
 * Backend-owned verdicts arrive via ipc.ts; shapes mirror
 * docs/contracts/ipc.md (`kiwi.ipc/1`, camelCase wire) with tolerant
 * parsing — the renderer never crashes on missing fields, it renders
 * unknown/stale instead (fail-closed display, ui-spec §11).
 */

export type Severity = "secure" | "warning" | "danger" | "unknown";

/** UI trust projection of SecurityStatusView (see toTrustState). */
export interface TrustState {
  trust: Severity;
  locked: boolean;
  /** Raw backend state for labels (trusted|degraded|locked|unknown). */
  state: string;
  /** 0–100, null when unreported. */
  score: number | null;
  requiredAction: string;
}

export interface AccountInfo {
  id: string;
  email: string;
  displayName: string;
  trust: Severity;
  unread: number;
  /** Sidebar color-dot, hex. */
  color: string;
  /** Per-account mute (T-167): unread excluded from counts, tagged in UI. */
  muted?: boolean;
}

export interface MessageEnvelope {
  /** `${accountId}:${folderId}:${uid}` — stable across folders. */
  id: string;
  accountId: string;
  accountEmail: string;
  folder: string;
  folderId: number;
  uid: number;
  from: string;
  subject: string;
  /** ISO timestamp. */
  date: string;
  unread: boolean;
  starred: boolean;
  hasAttachments: boolean;
  trust: Severity;
  snippet: string;
}

export interface FindingInfo {
  id: string;
  severity: "warning" | "danger";
  title: string;
  session: string;
  evidence: string;
  impact: string;
  remediation: string[];
  engineVersion: string;
}

export interface SecurityEventRow {
  id: string;
  ts: string;
  accountEmail: string;
  category: string;
  severity: Severity;
  summary: string;
  detailRef: string;
}

export type PolicyBannerVerdict = "none" | "warn" | "block";

/* ---------------- backend views (kiwi.ipc/1, tolerant) ---------------- */

export interface AppInfoView {
  version: string;
  contractVersion: string;
  deviceId: string;
  org: { orgId: string; baseUrl: string } | null;
  accountCount: number;
  sessionsObserved: number;
}

export interface SignalView {
  kind: string;
  severity: string;
  penalty: number;
  evidenceRef: string;
}

export interface SecurityStatusView {
  state: string;
  score: number | null;
  locked: boolean;
  requiredAction: string;
  signals: SignalView[];
  endpointSignals: string[];
  knownDevices: number;
}

export interface AccountView {
  id: string;
  displayName: string;
  email: string;
  incomingProtocol: string;
  incoming: { host: string; port: number; security: string };
  outgoing: { host: string; port: number; security: string };
  username: string;
  unreadCount: number;
  trustToken: string;
  color: string;
}

export interface FolderView {
  id: number;
  name: string;
  exists: number;
  unseen: number;
  uidValidity: number;
}

export interface MessageView {
  id: number;
  folderId: number;
  uid: number;
  messageId: string | null;
  subject: string;
  fromAddr: string;
  toAddrs: string;
  dateUnix: number;
  size: number;
  flags: string[];
  hasAttachments: boolean;
  snippet: string;
}

export interface MessageAttachmentView {
  filename: string;
  contentType: string;
  size: number;
}

export interface MessagePatch {
  seen?: boolean;
  starred?: boolean;
  archived?: boolean;
}

export interface MessageUpdateView {
  folderId: number;
  uid: number;
  flags: string[];
  movedToFolderId: number | null;
}

export interface AttachmentSavedView {
  path: string;
  filename: string;
  contentType: string;
  size: number;
}

export interface RenderedBodyView {
  html: string | null;
  remoteContentAllowed: boolean;
  remoteImagesStripped: number;
}

export interface RemoteContentView {
  accountId: string;
  remoteContentAllowed: boolean;
}

/** `kiwi_delete_messages` result (T-163) — counts tell which path ran. */
export interface DeleteResultView {
  folderId: number;
  movedToTrash: number;
  deleted: number;
  trashFolderId: number | null;
}

/** `kiwi_move_messages` result (T-163). */
export interface MoveResultView {
  srcFolderId: number;
  dstFolderId: number;
  moved: number;
}

/**
 * `kiwi_finding_detail` result (T-164) — full finding + joined session.
 * Parsed tolerantly: the finding object passes through verbatim.
 */
export interface FindingDetailView {
  finding: BackendFinding & Record<string, unknown>;
  session: Record<string, unknown> | null;
  signals: SignalView[];
  siblingFindingIds: string[];
}

/**
 * Address-book contact (T-173) — camelCase wire view of
 * `kiwi.contacts/1` (see docs/contracts/contacts.md §2). Parsed
 * tolerantly; the renderer shows unknown/stale, never crashes.
 */
export interface ContactEmailView {
  address: string;
  label: string | null;
}

export interface ContactPhoneView {
  number: string;
  label: string | null;
}

export interface ContactView {
  id: string;
  displayName: string;
  givenName: string | null;
  familyName: string | null;
  org: string | null;
  title: string | null;
  notes: string | null;
  tags: string[];
  emails: ContactEmailView[];
  phones: ContactPhoneView[];
  createdUnix: number | null;
  updatedUnix: number | null;
}

/** Writable subset (ContactInput): everything minus store-owned fields. */
export interface ContactInput {
  displayName: string;
  givenName?: string | null;
  familyName?: string | null;
  org?: string | null;
  title?: string | null;
  notes?: string | null;
  tags: string[];
  emails: { address: string; label?: string | null }[];
  phones: { number: string; label?: string | null }[];
}

function contactStr(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function contactOptStr(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

/** Tolerant parse of one ContactView; null when it has no identity. */
export function parseContact(raw: unknown): ContactView | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const id = contactStr(r["id"]);
  const displayName = contactStr(r["displayName"] ?? r["display_name"]);
  const emailsRaw = Array.isArray(r["emails"]) ? r["emails"] : [];
  const emails: ContactEmailView[] = [];
  for (const e of emailsRaw) {
    if (typeof e !== "object" || e === null) continue;
    const er = e as Record<string, unknown>;
    const address = contactStr(er["address"]).trim();
    if (!address) continue;
    emails.push({ address, label: contactOptStr(er["label"]) });
  }
  if (!id && !displayName && emails.length === 0) return null;
  const phonesRaw = Array.isArray(r["phones"]) ? r["phones"] : [];
  const phones: ContactPhoneView[] = [];
  for (const p of phonesRaw) {
    if (typeof p !== "object" || p === null) continue;
    const pr = p as Record<string, unknown>;
    const number = contactStr(pr["number"]).trim();
    if (!number) continue;
    phones.push({ number, label: contactOptStr(pr["label"]) });
  }
  const tagsRaw = Array.isArray(r["tags"]) ? r["tags"] : [];
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  return {
    id,
    displayName: displayName || (emails[0]?.address ?? ""),
    givenName: contactOptStr(r["givenName"] ?? r["given_name"]),
    familyName: contactOptStr(r["familyName"] ?? r["family_name"]),
    org: contactOptStr(r["org"]),
    title: contactOptStr(r["title"]),
    notes: contactOptStr(r["notes"]),
    tags: tagsRaw.filter((t): t is string => typeof t === "string"),
    emails,
    phones,
    createdUnix: num(r["createdUnix"] ?? r["created_unix"]),
    updatedUnix: num(r["updatedUnix"] ?? r["updated_unix"]),
  };
}

/** Row label: display name, else primary email (mirrors the crate). */
export function contactLabel(c: ContactView): string {
  return c.displayName || c.emails[0]?.address || "(unnamed)";
}

/** Primary email (first address) or empty string. */
export function contactPrimaryEmail(c: ContactView): string {
  return c.emails[0]?.address ?? "";
}

/**
 * Server search hit (T-160) — `kiwi_search_messages` is Agent 8's pending
 * command; shape mirrors MessageView so local envelopes convert cleanly.
 * Every field is optional on the wire; the view renders unknown/stale.
 */
export interface SearchHit {
  accountId: string;
  folderId: number;
  uid: number;
  subject: string;
  from: string;
  snippet: string;
  dateUnix: number | null;
  hasAttachments: boolean;
}

/** Tolerant parse of one `kiwi_search_messages` hit; null when unusable. */
export function parseSearchHit(raw: unknown, index: number): SearchHit | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const str = (v: unknown, fb = "") => (typeof v === "string" ? v : fb);
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const folderId = num(r["folderId"]);
  const uid = num(r["uid"]);
  if (!str(r["accountId"]) || folderId === null || uid === null) return null;
  void index;
  return {
    accountId: str(r["accountId"]),
    folderId,
    uid,
    subject: str(r["subject"], "(no subject)"),
    from: str(r["fromAddr"]) || str(r["from"], "(unknown)"),
    snippet: str(r["snippet"]),
    dateUnix: num(r["dateUnix"]),
    hasAttachments: r["hasAttachments"] === true,
  };
}

/**
 * Autoconfig suggestion (T-156) — mirrors `kiwi-autoconfig`'s
 * `AccountSuggestion` (`kiwi.autoconfig/1`) flattened for the wizard.
 * `source` is one of ispdb | autoconfig_host | well_known | mx_heuristic |
 * manual | local-guess (frontend stub until the IPC lands).
 */
export interface AutoconfigSuggestion {
  source: string;
  protocol: "imap" | "pop3";
  inHost: string;
  inPort: number;
  inSec: string;
  outHost: string;
  outPort: number;
  outSec: string;
  username: string;
  authKind: string;
}

function secToken(v: unknown): string {
  const t = typeof v === "string" ? v.toLowerCase().replace(/[_-]/g, "") : "";
  if (t === "tls" || t === "implicittls" || t === "ssl") return "tls";
  if (t === "starttls" || t === "stls") return "starttls";
  return "tls";
}

/** Tolerant parse of a future `kiwi_lookup_autoconfig` response; null when unusable. */
export function parseAutoconfigSuggestion(raw: unknown): AutoconfigSuggestion | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const num = (v: unknown, fb: number) => (typeof v === "number" && Number.isSafeInteger(v) && v > 0 && v < 65536 ? v : fb);
  // Accept both the flat wizard shape and the nested Rust
  // AccountSuggestion shape ({ incoming: { kind, host, port, … }, … }).
  const inc = (r["incoming"] ?? {}) as Record<string, unknown>;
  const out = (r["outgoing"] ?? {}) as Record<string, unknown>;
  const pick = (flat: unknown, nested: unknown, fb: string) => str(flat) || str(nested) || fb;
  const inHost = pick(r["inHost"], inc["host"], "");
  const outHost = pick(r["outHost"], out["host"], "");
  if (!inHost || !outHost) return null;
  const protoRaw = (str(r["protocol"]) || str(inc["kind"])).toLowerCase();
  return {
    source: str(r["source"]) || "manual",
    protocol: protoRaw === "pop3" ? "pop3" : "imap",
    inHost,
    inPort: num(r["inPort"] ?? inc["port"], 993),
    inSec: secToken(r["inSec"] ?? inc["security"]),
    outHost,
    outPort: num(r["outPort"] ?? out["port"], 465),
    outSec: secToken(r["outSec"] ?? out["security"]),
    username: str(r["username"]) || str(inc["username"]),
    authKind: str(r["authKind"]) || str(inc["auth"]) || "password",
  };
}

export interface MessageBodyView {
  folderId: number;
  uid: number;
  messageId: string | null;
  subject: string;
  from: string[];
  to: string[];
  cc: string[];
  dateUnix: number;
  textBody: string;
  htmlBody: string | null;
  attachments: MessageAttachmentView[];
  bodyPresent: boolean;
}

/** kiwi.forensics/1 finding — exact fields vary; parsed tolerantly. */
export interface BackendFinding {
  id?: unknown;
  title?: unknown;
  summary?: unknown;
  severity?: unknown;
  sessionRef?: unknown;
  session?: unknown;
  evidence?: unknown;
  impact?: unknown;
  remediation?: unknown;
  engineVersion?: unknown;
}

export interface BackendEventRow {
  id?: unknown;
  tsUnix?: unknown;
  accountId?: unknown;
  category?: unknown;
  severity?: unknown;
  summary?: unknown;
  detailRef?: unknown;
}

export interface ChallengeView {
  challengeId: string;
  deviceId: string;
  sessionId: string;
  event: string;
  nonceB64: string;
  canonicalBytesB64: string;
  issuedUnix: number;
  expiresUnix: number;
}

export interface DeviceView {
  deviceId: string;
  label: string;
  algorithm: string;
  status: string;
  registeredUnix: number;
  lastSeenUnix: number;
}

export interface OutboxItem {
  queueId: string;
  accountId: string;
  from: string;
  to: string[];
  subject: string;
  notBeforeUnix: number;
  undoWindowUntilUnix: number;
  attempts: number;
  cancelable: boolean;
}

export interface VerifyStep {
  stage: string;
  ok: boolean;
  detail: string;
}

export interface VerifyResult {
  ok: boolean;
  steps: VerifyStep[];
  session: Record<string, unknown> | null;
  findings: BackendFinding[];
  trust: SecurityStatusView;
}

/* ---------------- mappers (backend → UI, never throw) ---------------- */

export function severityLabel(s: Severity): string {
  switch (s) {
    case "secure":
      return "Secure";
    case "warning":
      return "Warning";
    case "danger":
      return "Danger";
    case "unknown":
      return "Unknown";
  }
}

/** Glyph differs per severity so meaning is never color-only. */
export function severityGlyph(s: Severity): string {
  switch (s) {
    case "secure":
      return "✓";
    case "warning":
      return "!";
    case "danger":
      return "✕";
    case "unknown":
      return "?";
  }
}

export function toTrustState(raw: unknown): TrustState {
  const fallback: TrustState = { trust: "unknown", locked: false, state: "unknown", score: null, requiredAction: "none" };
  if (typeof raw !== "object" || raw === null) return fallback;
  const r = raw as Record<string, unknown>;
  const state = typeof r["state"] === "string" ? r["state"] : "unknown";
  const locked = r["locked"] === true || state === "locked";
  return {
    trust: locked ? "danger" : state === "trusted" ? "secure" : state === "degraded" ? "warning" : "unknown",
    locked,
    state,
    score: typeof r["score"] === "number" ? r["score"] : null,
    requiredAction: typeof r["requiredAction"] === "string" ? r["requiredAction"] : "none",
  };
}

/** Backend account trustToken → UI severity. */
export function trustTokenToSeverity(token: unknown): Severity {
  if (token === "trusted") return "secure";
  if (token === "degraded" || token === "warning") return "warning";
  if (token === "locked") return "danger";
  return "unknown";
}

/** Backend event severity (info|low|medium|high|critical) → UI severity. */
export function eventSeverityToSeverity(s: unknown): Severity {
  if (s === "high" || s === "critical") return "danger";
  if (s === "medium" || s === "low") return "warning";
  return "unknown";
}

export function unixToIso(tsUnix: unknown): string {
  if (typeof tsUnix !== "number" || !Number.isFinite(tsUnix)) return "";
  try {
    return new Date(tsUnix * 1000).toISOString();
  } catch {
    return "";
  }
}

function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

export function findingToInfo(f: BackendFinding, index: number): FindingInfo {
  const sev = str(f.severity).toLowerCase();
  return {
    id: str(f.id, `finding-${index}`),
    severity: sev === "critical" || sev === "high" ? "danger" : "warning",
    title: str(f.title, str(f.summary, "Security finding")),
    session: str(f.session, str(f.sessionRef, "—")),
    evidence: typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence ?? null, null, 2),
    impact: str(f.impact, "See remediation guidance."),
    remediation: Array.isArray(f.remediation) ? f.remediation.map((s) => String(s)) : [],
    engineVersion: str(f.engineVersion, "kiwi.forensics/1"),
  };
}

export function eventToRow(e: BackendEventRow, accountEmail: (id: string | null) => string): SecurityEventRow {
  const id = str(e.id, "event");
  return {
    id,
    ts: unixToIso(e.tsUnix),
    accountEmail: accountEmail(typeof e.accountId === "string" ? e.accountId : null),
    category: str(e.category, "event"),
    severity: eventSeverityToSeverity(e.severity),
    summary: str(e.summary, id),
    detailRef: str(e.detailRef, ""),
  };
}
