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
