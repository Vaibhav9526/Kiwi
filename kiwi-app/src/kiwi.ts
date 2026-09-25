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
  /** F2 inbox tab (backend `MessageView.category` slug; unknown → primary). */
  category: MessageCategory;
  /** T-202 unsubscribe endpoints (dormant until the backend classifies). */
  unsub: UnsubscribeInfo;
}

/** F2 inbox tabs — slugs match kiwi-mail `Category::as_str` (stable API). */
export type MessageCategory = "primary" | "newsletters" | "social" | "notifications" | "other";

export const CATEGORY_TABS: { slug: MessageCategory; label: string }[] = [
  { slug: "primary", label: "Primary" },
  { slug: "newsletters", label: "Newsletters" },
  { slug: "social", label: "Social" },
  { slug: "notifications", label: "Notifications" },
  { slug: "other", label: "Other" },
];

/** Unknown/empty slugs fall back to Primary (mirrors `from_slug` callers). */
export function normalizeCategory(v: unknown): MessageCategory {
  const s = typeof v === "string" ? v.trim().toLowerCase() : "";
  return s === "newsletters" || s === "social" || s === "notifications" || s === "other" ? s : "primary";
}

/** T-202 unsubscribe endpoints (tolerant; absent until the backend exposes them). */
export interface UnsubscribeInfo {
  url: string | null;
  mailto: string | null;
  oneClick: boolean;
}

function cleanStr(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

/** HTTPS-only: list-unsubscribe URLs must never be http/javascript/data. */
export function parseUnsubscribe(raw: unknown): UnsubscribeInfo {
  const out: UnsubscribeInfo = { url: null, mailto: null, oneClick: false };
  if (typeof raw !== "object" || raw === null) return out;
  const r = raw as Record<string, unknown>;
  const url = cleanStr(r["unsubscribe_url"]);
  if (url) {
    try {
      const u = new URL(url);
      if (u.protocol === "https:") out.url = u.toString();
    } catch {
      // Unusable — stays null, chip stays hidden.
    }
  }
  const mailto = cleanStr(r["unsubscribe_mailto"]);
  if (mailto) {
    const addr = mailto.toLowerCase().startsWith("mailto:") ? mailto.slice("mailto:".length) : mailto;
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr.split("?")[0] ?? "")) out.mailto = addr;
  }
  out.oneClick = r["unsubscribe_one_click"] === true;
  return out;
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
  trust: string;
  state: string;
  score: number | null;
  locked: boolean;
  requiredAction: string;
  signals: SignalView[];
  sessionsObserved: number;
  deviceId: string;
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
  /** F2 tab slug (primary/…); absent on old rows → normalizeCategory. */
  category?: unknown;
  /** T-202 endpoints; absent until the backend exposes them. */
  unsubscribe_url?: unknown;
  unsubscribe_mailto?: unknown;
  unsubscribe_one_click?: unknown;
  /**
   * T-232 Authentication-Results. Absent until the body has been fetched and
   * evaluated — "not evaluated" is deliberately distinct from a `none`
   * verdict, so the security pill must render unknown rather than safe.
   */
  auth?: AuthResultsView | null;
}

/**
 * SPF/DKIM/DMARC verdicts (T-232). Vocabulary is `kiwi.mailauth/1`:
 * `pass` | `fail` | `softfail` | `neutral` | `none` | `temperror` | `permerror`.
 *
 * SECURITY.md rules 1–2: `none` means no record was published and `temperror`
 * means the check could not complete. Both are *absence of evidence* — never
 * render them as a pass, and never as a finding.
 */
export type AuthRisk = "clean" | "noted" | "failed";

export interface AuthResultsView {
  /** Bounded deterministic hint for the frontend pill; never a finding. */
  authRisk: AuthRisk;
  spf: string;
  dkim: string;
  dmarc: string;
  dmarcPolicy: string;
  dkimDomain?: string | null;
  headerValue?: string | null;
  evidence?: unknown;
  /** Upstream MTA evidence; untrustedRelay is a provenance limitation. */
  upstream: UpstreamAuthView;
  /** Exact pass/fail contradiction evidence flag — never a finding by itself. */
  discrepancy: boolean;
}

export interface UpstreamAuthVerdictView {
  authservId: string;
  verdict: string;
}

export interface AuthVerdictComparisonView {
  method: "spf" | "dkim" | "dmarc";
  upstreamVerdict: string;
  localVerdict: string;
  discrepancy: boolean;
}

export interface UpstreamAuthView {
  present: boolean;
  untrustedRelay: boolean;
  malformedHeaders: number;
  authservIds: string[];
  spf: UpstreamAuthVerdictView[];
  dkim: UpstreamAuthVerdictView[];
  dmarc: UpstreamAuthVerdictView[];
  /** Evidence rows carrying both upstream and local verdicts. */
  comparisons: AuthVerdictComparisonView[];
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

/** `kiwi_message_unsubscribe` action selector (T-234). */
export type UnsubscribeAction = "http" | "mailto";

/**
 * `kiwi_message_unsubscribe` result. `executed` means the request left
 * the process (http: a response was received; mailto: queued). For http,
 * `httpStatus` <400 means the endpoint accepted the unsubscribe.
 */
export interface UnsubscribeResultView {
  action: UnsubscribeAction;
  executed: boolean;
  httpStatus: number | null;
  queueId: string | null;
  undoWindowUntilUnix: number | null;
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
  // accountId may be absent until the IPC contract lands (folder→account
  // resolution is server-side) — the row still lists; opening resolves then.
  if (folderId === null || uid === null) return null;
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
  /**
   * ipc.md §5 `suggestion.oauth2` — present iff the suggestion is XOAUTH2
   * on a shipped-provider host (IMAP only). `provider` feeds
   * `kiwi_oauth2_begin`; `grant` tells the wizard which UX to render.
   */
  oauth2?: { provider: string; grant: string };
}

function secToken(v: unknown): string {
  const t = typeof v === "string" ? v.toLowerCase().replace(/[_-]/g, "") : "";
  if (t === "tls" || t === "implicittls" || t === "ssl") return "tls";
  if (t === "starttls" || t === "stls") return "starttls";
  return "tls";
}

/** Tolerant parse of a `kiwi_discover_account` response (ipc.md §5); null when unusable. */
export function parseAutoconfigSuggestion(raw: unknown): AutoconfigSuggestion | null {
  if (typeof raw !== "object" || raw === null) return null;
  const envelope = raw as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const num = (v: unknown, fb: number) => (typeof v === "number" && Number.isSafeInteger(v) && v > 0 && v < 65536 ? v : fb);
  // The wire shape is a DiscoveryOutcomeView — the suggestion lives under
  // `suggestion`. Accept that envelope, a bare suggestion, or the flat
  // wizard stub shape.
  const nested =
    typeof envelope["suggestion"] === "object" && envelope["suggestion"] !== null
      ? (envelope["suggestion"] as Record<string, unknown>)
      : null;
  const r = nested ?? envelope;
  const inc = (r["incoming"] ?? {}) as Record<string, unknown>;
  const out = (r["outgoing"] ?? {}) as Record<string, unknown>;
  const pick = (flat: unknown, nestedV: unknown, fb: string) => str(flat) || str(nestedV) || fb;
  const inHost = pick(r["inHost"], inc["host"], "");
  const outHost = pick(r["outHost"], out["host"], "");
  if (!inHost || !outHost) return null;
  const protoRaw = (str(r["protocol"]) || str(inc["kind"])).toLowerCase();
  const oauthRaw = r["oauth2"];
  const oauth2 =
    typeof oauthRaw === "object" && oauthRaw !== null
      ? (() => {
          const o = oauthRaw as Record<string, unknown>;
          const provider = str(o["provider"]);
          const grant = str(o["grant"]);
          return provider && grant ? { provider, grant } : undefined;
        })()
      : undefined;
  return {
    source: str(envelope["source"]) || str(r["source"]) || "manual",
    protocol: protoRaw === "pop3" ? "pop3" : "imap",
    inHost,
    inPort: num(r["inPort"] ?? inc["port"], 993),
    inSec: secToken(r["inSec"] ?? inc["security"]),
    outHost,
    outPort: num(r["outPort"] ?? out["port"], 465),
    outSec: secToken(r["outSec"] ?? out["security"]),
    username: str(r["username"]) || str(inc["username"]),
    authKind: str(r["authKind"]) || str(inc["auth"]) || "password",
    oauth2,
  };
}

// ---------------------------------------------------------------------------
// OAuth2 acquisition views (ipc.md §9f; kiwi.oauth2/1) — no token material
// ever crosses IPC: ticket ids, credential-key names, and posture only.
// ---------------------------------------------------------------------------

export type OAuth2GrantKind = "loopback_code" | "device_code" | string;

/** `kiwi_oauth2_begin` result — the ticket plus whatever the user must see. */
export interface OAuth2BeginView {
  ticketId: string;
  kind: OAuth2GrantKind;
  authorizeUrl?: string;
  userCode?: string;
  verificationUri?: string;
  verificationUriComplete?: string;
  expiresAtUnix?: number;
  pollIntervalSecs?: number;
}

/** `kiwi_oauth2_poll` result — terminal failures arrive as `status:"error"`. */
export interface OAuth2PollView {
  status: "pending" | "complete" | "error";
  ticketId: string;
  retryAfterSecs?: number;
  provider?: string;
  email?: string;
  credentialKey?: string;
  errorCode?: string;
  errorMessage?: string;
}

/** `kiwi_oauth2_status` result — stored-account grant posture, no secrets. */
export interface OAuth2StatusView {
  accountId: string;
  authMethod: string;
  provider?: string;
  email?: string;
  credentialPresent: boolean;
  expiresAtUnix?: number;
  needsRefresh?: boolean;
  hasRefreshToken?: boolean;
}

const optStr = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const optNum = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

export function parseOAuth2Begin(raw: unknown): OAuth2BeginView | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const ticketId = optStr(r["ticketId"]);
  const kind = optStr(r["kind"]);
  if (!ticketId || !kind) return null;
  return {
    ticketId,
    kind,
    authorizeUrl: optStr(r["authorizeUrl"]),
    userCode: optStr(r["userCode"]),
    verificationUri: optStr(r["verificationUri"]),
    verificationUriComplete: optStr(r["verificationUriComplete"]),
    expiresAtUnix: optNum(r["expiresAtUnix"]),
    pollIntervalSecs: optNum(r["pollIntervalSecs"]),
  };
}

export function parseOAuth2Poll(raw: unknown): OAuth2PollView | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const status = optStr(r["status"]);
  const ticketId = optStr(r["ticketId"]);
  if (!ticketId || (status !== "pending" && status !== "complete" && status !== "error")) return null;
  return {
    status,
    ticketId,
    retryAfterSecs: optNum(r["retryAfterSecs"]),
    provider: optStr(r["provider"]),
    email: optStr(r["email"]),
    credentialKey: optStr(r["credentialKey"]),
    errorCode: optStr(r["errorCode"]),
    errorMessage: optStr(r["errorMessage"]),
  };
}

export function parseOAuth2Status(raw: unknown): OAuth2StatusView | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const accountId = optStr(r["accountId"]);
  const authMethod = optStr(r["authMethod"]);
  if (!accountId || !authMethod) return null;
  return {
    accountId,
    authMethod,
    provider: optStr(r["provider"]),
    email: optStr(r["email"]),
    credentialPresent: r["credentialPresent"] === true,
    expiresAtUnix: optNum(r["expiresAtUnix"]),
    needsRefresh: r["needsRefresh"] === true ? true : r["needsRefresh"] === false ? false : undefined,
    hasRefreshToken:
      r["hasRefreshToken"] === true ? true : r["hasRefreshToken"] === false ? false : undefined,
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

/* ---------------- integrations (T-227, ipc.md §9e) ---------------- */

/**
 * The public-inbox disclosure, verbatim from
 * `kiwi-integrations::tempmail::PUBLIC_INBOX_NOTICE`. Shown BEFORE the
 * user enables a temp inbox — the backend also echoes it on every
 * temp-mail response (`publicInboxNotice`), which the UI renders as
 * received (never paraphrased).
 */
export const PUBLIC_INBOX_NOTICE =
  "Temporary inboxes are PUBLIC: anyone who knows the address can read its mail, and messages pass through a third-party server. Never receive personal or sensitive mail here.";

/** Every temp-mail response carries the mandated public-inbox disclosure. */
export interface PublicInboxNotice {
  publicInboxNotice: string;
}

export interface TempMailboxView extends PublicInboxNotice {
  address: string;
  addressCreatedUnix?: number;
}

export interface TempMessageSummaryView {
  mailId: string;
  from: string;
  subject: string;
  excerpt: string;
  timestampUnix?: number;
  date: string;
  read: boolean;
}

export interface TempPollView extends PublicInboxNotice {
  messages: TempMessageSummaryView[];
  totalNew: number;
  address?: string;
}

/** Fetched temp message — html is pre-sanitized backend-side, remote
 * resources always stripped; raw MIME never crosses IPC. */
export interface TempMessageView extends PublicInboxNotice {
  mailId: string;
  from: string;
  subject: string;
  date: string;
  contentType?: string;
  html?: string;
  text?: string;
  remoteImagesStripped: number;
}

export interface TempDiscardView extends PublicInboxNotice {
  discarded: boolean;
  remoteForgotten: boolean;
}

export interface TempExtendView extends PublicInboxNotice {
  extended: boolean;
  expired: boolean;
  addressCreatedUnix?: number;
}

export interface DeliverabilityBeginView {
  testId: string;
  address: string;
  expiresAtUnix?: number;
  expiresAtRaw?: string;
  /** Single-use consent capability — hand back verbatim to send. */
  consentToken: string;
  consentNotice: string;
}

export interface DeliverabilitySendView {
  testId: string;
  queueId: string;
  notBeforeUnix: number;
}

export interface DeliverabilityStatusView {
  testId: string;
  /** "pending" | "received" | "analyzing" | "checks_ready" | "failed" | unknown string */
  analysisStatus: string;
  checksDone: number;
  checksTotal: number;
  ready: boolean;
  sent: boolean;
}

export interface DeliverabilityCitationView {
  kind: string;
  title: string;
  url: string;
}

export interface DeliverabilityCheckView {
  id: string;
  category: string;
  categoryRaw: string;
  status: string;
  title: string;
  summary: string;
  citations: DeliverabilityCitationView[];
}

export interface DeliverabilityCategoryTally {
  pass: number;
  warn: number;
  fail: number;
  skip: number;
  other: number;
}

export interface DeliverabilityReportView {
  testId: string;
  scoreOursMilli?: number;
  scoreCompatMilli?: number;
  complete: boolean;
  reportUrl?: string;
  subscores: Record<string, number>;
  tallies: Record<string, DeliverabilityCategoryTally>;
  checks: DeliverabilityCheckView[];
  /** ids of failed `auth` checks — the gate set. */
  authFailureIds: string[];
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
