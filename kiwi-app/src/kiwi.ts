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
  /**
   * T-331: backend-owned audit-chain verdict carried on the security status
   * payload. `true` verified, `false` failed verification, `null`/absent =
   * not checked. `null` is honest absence and renders as nothing at all —
   * never as a reassuring tick.
   */
  auditOk?: boolean | null;
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
  /** RFC822 Message-ID + reply chain (T-310) — resolved against the loaded
   *  thread for the in-reply-to jump; null/[] = unknown. */
  messageId?: string | null;
  inReplyTo?: string | null;
  references?: string[];
  /**
   * T-267 "Unreplied" smart folder: `true` when the envelope carries the
   * IMAP `\Answered` flag. `undefined` = unknown (demo fixtures, backends
   * that don't report flags) — the smart filter treats unknown as
   * unreplied, matching eM Client's pessimistic count.
   */
  answered?: boolean;
  /** T-202 unsubscribe endpoints (dormant until the backend classifies). */
  unsub: UnsubscribeInfo;
  /**
   * T-284 per-message evidence hints (T-232 auth / T-254 attach / T-261 link).
   * All three are `undefined`/`null` until the body has been fetched and
   * evaluated — "not evaluated" is deliberately distinct from clean.
   */
  auth?: AuthResultsView | null;
  attachRisk?: AttachRiskView | null;
  linkRisk?: LinkRiskView | null;
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
  const url = cleanStr(r["unsubscribeUrl"]) ?? cleanStr(r["unsubscribe_url"]);
  if (url) {
    try {
      const u = new URL(url);
      if (u.protocol === "https:") out.url = u.toString();
    } catch {
      // Unusable — stays null, chip stays hidden.
    }
  }
  const mailto = cleanStr(r["unsubscribeMailto"]) ?? cleanStr(r["unsubscribe_mailto"]);
  if (mailto) {
    const addr = mailto.toLowerCase().startsWith("mailto:") ? mailto.slice("mailto:".length) : mailto;
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr.split("?")[0] ?? "")) out.mailto = addr;
  }
  out.oneClick = r["unsubscribeOneClick"] === true || r["unsubscribe_one_click"] === true;
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
  /**
   * T-345: whether a tray icon actually exists. `false`/`undefined` on
   * platforms without a tray surface — the close-to-tray pref is then
   * inert and settings must say so rather than let the toggle pretend.
   */
  trayAvailable?: boolean;
  /**
   * KIWI_DEV_PLAINTEXT=1 is set: loopback plaintext auth/transport tolerated
   * for mail fixtures. Rendered as a visible DEV chip; never defaults on.
   */
  devPlaintext?: boolean;
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
  /**
   * T-331: backend-owned audit-chain integrity. `true` verified, `false`
   * failed verification, `null`/absent = not checked yet — honest absence,
   * which must never render as "fine".
   */
  auditOk?: boolean | null;
}

/**
 * T-331 `kiwi_audit_integrity` — the cheap health probe (no row payloads).
 * `state` is the honest tri-state the UI words from; `auditOk` mirrors it
 * (`null` = unknown). A tampered chain is a *state*, not an exception: the
 * backend already emitted `audit-corrupt` with no renderer handling it, so the
 * failure was invisible.
 */
export interface AuditIntegrityView {
  state: "ok" | "corrupt" | "unknown";
  auditOk: boolean | null;
}

/** The one honest sentence for a failed chain verification (T-331). */
export const AUDIT_CORRUPT_MESSAGE =
  "audit log failed integrity verification — possible corruption or tampering";

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
  accountId: string;
  /** null for a root local folder; local children only. */
  parentId: number | null;
  name: string;
  /** Real store row: remote (sync), local (user-managed), or system. */
  origin: "remote" | "local" | "system";
  /** null until a sync has selected the folder. */
  uidValidity: number | null;
  uidNext: number | null;
  highestUid: number;
  /** Total stored rows (T-264) — includes snoozed/parked mail. */
  exists: number;
  /** Rows without \Seen — the unread badge source. Parked mail counts. */
  unseen: number;
}

export interface MessageView {
  id: number;
  folderId: number;
  uid: number;
  messageId: string | null;
  subject: string | null;
  fromAddr: string | null;
  toAddrs: string | null;
  dateUnix: number | null;
  size: number | null;
  flags: string[];
  unread: boolean;
  starred: boolean;
  hasAttachments: boolean;
  snippet: string | null;
  /** Whether the full body is already stored locally. */
  bodyStored: boolean;
  /** T-169 header-chain threading; null/[] means "unknown". */
  inReplyTo: string | null;
  references: string[];
  /** F2 tab slug (primary/…); absent on old rows → normalizeCategory. */
  category?: unknown;
  /** T-202 endpoints (camelCase wire keys; null until the sender advertises). */
  unsubscribeUrl?: string | null;
  unsubscribeMailto?: string | null;
  unsubscribeOneClick?: boolean;
  unsubscribeRequiresConsent?: boolean;
  /**
   * T-232 Authentication-Results. Absent until the body has been fetched and
   * evaluated — "not evaluated" is deliberately distinct from a `none`
   * verdict, so the security pill must render unknown rather than safe.
   */
  auth?: AuthResultsView | null;
  /** Bounded attachment evidence hint (T-254); absent until body parse. */
  attachRisk?: AttachRiskView | null;
  /** Bounded URL evidence hint (T-261); absent until body parse. */
  linkRisk?: LinkRiskView | null;
}

/**
 * `kiwi://mail-changed` event payload (ipc.md §6; T-157 emitter, T-271
 * consumer). `folder`/`folderId` are null on the connect-time full pass;
 * `reason` is "sync" | "idle" | "poll".
 */
export interface MailChangedEvent {
  accountId: string;
  folder: string | null;
  folderId: number | null;
  reason: string;
  newMessages: number;
  flagUpdates: number;
  expunged: number;
  atUnix: number;
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
export type AttachRisk = "clean" | "noted" | "failed";

export type AttachRiskReason =
  | "dangerousExtension"
  | "doubleExtension"
  | "dangerousContentType"
  | "macroEnabledOffice"
  | "vbaProjectContainer"
  | "archiveNotInspectable"
  | "encryptedOrOpaqueContainer"
  | "unicodeConfusable";

export interface AttachRiskView {
  risk: AttachRisk;
  reasons: AttachRiskReason[];
}

export type LinkRisk = "clean" | "noted" | "failed";
export type LinkRiskReason =
  | "ipLiteralHost"
  | "displayDomainMismatch"
  | "insecureHttp"
  | "knownShortener"
  | "excessiveSubdomains"
  | "excessiveHyphens"
  | "punycodeHost"
  | "unicodeHost"
  | "credentialsInUrl";

/* ---------------- security session vocabulary (T-260) ---------------- */

/**
 * Session-view enum tokens (docs/contracts/security-session.md §2/§3).
 * These are the *session-view* spellings, deliberately distinct from the
 * forensics FSV-1 serde tags (`tls13`, `hostname_mismatch`, `x_o_auth2`).
 */
export type SessionTransport = "plaintext" | "starttls" | "tls";
export type SessionTlsVersion = "ssl3" | "tls1.0" | "tls1.1" | "tls1.2" | "tls1.3" | "unknown";
export type SessionKeyExchange =
  | "x25519" | "secp256r1" | "secp384r1" | "secp521r1"
  | "ffdhe2048" | "ffdhe3072" | "ffdhe4096"
  | "static" | "unknown" | `other:${string}`;
export type ChainValidationToken =
  | "valid" | "invalid" | "untrusted" | "expired" | "hostname-mismatch" | "unknown";
/**
 * Provenance. `live-client` supersedes the pre-pivot `thunderbird-hook`.
 * `unknown` is the safe-render form for a token this build doesn't know — it
 * is NOT "clean" or any real provenance; it means the value was not recognized.
 */
export type SessionSourceToken =
  | "live-client" | "forensic-pcap" | "test-fixture" | "unknown";

/** `kiwi_forensics_export` receipt (T-320) — a self-verifying artifact. */
export interface ForensicsExportView {
  /** The user-chosen destination written (the user already knows it). */
  path: string;
  /** Size of the whole artifact on disk (envelope + report). */
  bytes: number;
  /** Lowercase hex SHA-256 of the canonical report payload, as embedded. */
  sha256: string;
  reportContractVersion: string;
  /** Findings carried in the exported report (a count, never the list). */
  findings: number;
  generatedAtUnix: number;
}

/** `kiwi_session_detail` result — T-269 canonical shape (ipc.md §3). */
export interface SecuritySessionView {
  schemaVersion: number;
  sessionId: string;
  accountId: string | null;
  deviceId: string | null;
  protocol: "smtp" | "imap" | "pop3";
  serverHost: string;
  serverPort: number;
  transport: SessionTransport;
  tlsVersion: SessionTlsVersion | null;
  keyExchangeGroup: SessionKeyExchange | null;
  certChain: { presentedLen: number; validation: ChainValidationToken } | null;
  starttlsOffered: boolean | null;
  starttlsUsed: boolean;
  authMechanism: string;
  authSucceeded: boolean | null;
  establishedUnix: number;
  source: SessionSourceToken;
}

/**
 * Safe-render parser for a session view. An unrecognized enum token degrades
 * to its honest unknown form rather than being displayed verbatim or crashing
 * a view: a future backend spelling must render as "unknown"/absent, never as
 * a confident-looking wrong value.
 */
export function parseSecuritySession(raw: unknown): SecuritySessionView | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
  const oneOf = <T extends string>(v: unknown, allowed: readonly T[], fallback: T): T =>
    typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : fallback;

  const sessionId = str(r["sessionId"]);
  const serverHost = str(r["serverHost"]);
  if (!sessionId || !serverHost) return null;

  const chain = r["certChain"] as Record<string, unknown> | null | undefined;
  const certChain =
    chain && typeof chain === "object"
      ? {
          presentedLen: num(chain["presentedLen"]) ?? 0,
          validation: oneOf<ChainValidationToken>(
            chain["validation"],
            ["valid", "invalid", "untrusted", "expired", "hostname-mismatch", "unknown"],
            "unknown",
          ),
        }
      : null;

  return {
    schemaVersion: num(r["schemaVersion"]) ?? 1,
    sessionId,
    accountId: typeof r["accountId"] === "string" ? r["accountId"] : null,
    deviceId: typeof r["deviceId"] === "string" ? r["deviceId"] : null,
    protocol: oneOf(r["protocol"], ["smtp", "imap", "pop3"] as const, "imap"),
    serverHost,
    serverPort: num(r["serverPort"]) ?? 0,
    transport: oneOf<SessionTransport>(r["transport"], ["plaintext", "starttls", "tls"], "plaintext"),
    tlsVersion:
      r["tlsVersion"] === null || r["tlsVersion"] === undefined
        ? null
        : oneOf<SessionTlsVersion>(
            r["tlsVersion"],
            ["ssl3", "tls1.0", "tls1.1", "tls1.2", "tls1.3", "unknown"],
            "unknown",
          ),
    keyExchangeGroup:
      typeof r["keyExchangeGroup"] === "string" && r["keyExchangeGroup"]
        ? (r["keyExchangeGroup"] as SessionKeyExchange)
        : null,
    certChain,
    starttlsOffered: typeof r["starttlsOffered"] === "boolean" ? r["starttlsOffered"] : null,
    starttlsUsed: r["starttlsUsed"] === true,
    // Open vocabulary: `other:<name>` is a server-supplied token, so a new
    // mechanism must still render rather than be discarded.
    authMechanism: str(r["authMechanism"]) ?? "unknown",
    authSucceeded: typeof r["authSucceeded"] === "boolean" ? r["authSucceeded"] : null,
    establishedUnix: num(r["establishedUnix"]) ?? 0,
    source: oneOf<SessionSourceToken>(
      r["source"],
      ["live-client", "forensic-pcap", "test-fixture", "unknown"],
      "unknown",
    ),
  };
}

export interface LinkRiskView {
  risk: LinkRisk;
  reasons: LinkRiskReason[];
}

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
  /**
   * Ordinal among the message's attachments — the `attachmentIndex`
   * `downloadAttachment` resolves (T-339).
   */
  index: number;
  /** `null` when the MIME part carries no filename — never empty string. */
  filename: string | null;
  contentType: string;
  /**
   * Decoded size for complete bodies; for a deferred part this is the
   * BODYSTRUCTURE *wire* octet count (encoded body — the decoded payload
   * is smaller). 0 when unknown.
   */
  size: number;
  /**
   * `false` marks a deferred part (T-339): saving it triggers a live
   * `BODY.PEEK` fetch. Always `true` on fully-stored bodies.
   */
  fetched: boolean;
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

export type LinkClickAction = "allow" | "requireConfirm" | "requireSandbox" | "deny";

export interface LinkClickVerdict {
  action: LinkClickAction;
  /** Bounded deterministic evidence reason codes; never URL/body text. */
  reasons: string[];
}

export interface SandboxOpenView {
  sessionId: string;
  /** Sanitized URL or attachment coordinate; never raw attachment bytes. */
  target: string;
  /** Stable link/attachment risk reason codes carried into the session. */
  evidenceReasons: string[];
  report: Record<string, unknown> & { evidenceReasons?: string[] };
}

/** One recorded sandbox open (T-300) — an honest, bounded session row. */
export interface SandboxSessionView {
  sessionId: string;
  kind: "link" | "attachment";
  /**
   * Sanitized display target: a URL with userinfo/query/fragment removed for
   * links, or the `attachment:f<folderId>/u<uid>` coordinate for attachments.
   * Never a host path, filename, or payload.
   */
  target: string;
  /**
   * `clean | noted | failed`, or `null` when no stored message evidence
   * matched the target — absent evidence, never a fabricated "clean".
   */
  riskVerdict: "clean" | "noted" | "failed" | null;
  /** Bounded stable evidence reason codes; never the matched target text. */
  evidenceReasons: string[];
  openedAtUnix: number;
  /**
   * `completed` — every T-266 open tears down before it is recorded, so there
   * is no live guest. Reserved for a future live-session provider.
   */
  state: "completed";
  /** `null` for a torn-down session; a future live provider may populate it. */
  expiresAtUnix: number | null;
}

/**
 * `kiwi_sandbox_sessions` receipt — newest first, bounded. `sessions` is
 * `[]` when nothing has been opened; absence is never an error.
 */
export interface SandboxSessionsView {
  sessions: SandboxSessionView[];
}

/**
 * Tolerant parser for `kiwi_sandbox_sessions` (T-300). The renderer never
 * trusts the row shape: unknown or corrupt sessions are dropped rather than
 * rendered, and a malformed envelope collapses to `null` so the wrapper can
 * report an honest empty list. `riskVerdict` must be a known value — an
 * unrecognized verdict is treated as absent evidence, never as "clean".
 */
export function parseSandboxSessions(raw: unknown): SandboxSessionsView | null {
  const optNum = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
  const optStr = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  const verdict = (v: unknown): "clean" | "noted" | "failed" | null =>
    v === "clean" || v === "noted" || v === "failed" ? v : null;
  if (typeof raw !== "object" || raw === null) return null;
  const sessions = (raw as Record<string, unknown>)["sessions"];
  if (!Array.isArray(sessions)) return null;
  const out: SandboxSessionView[] = [];
  for (const entry of sessions) {
    if (typeof entry !== "object" || entry === null) continue;
    const r = entry as Record<string, unknown>;
    const sessionId = optStr(r["sessionId"]);
    const kind = r["kind"] === "link" || r["kind"] === "attachment" ? r["kind"] : null;
    const target = optStr(r["target"]);
    const openedAtUnix = optNum(r["openedAtUnix"]);
    // `state` is a forward-compatible vocabulary; a torn-down session is the
    // only honest value today, so anything else is dropped, not guessed.
    if (!sessionId || !kind || !target || openedAtUnix === undefined) continue;
    if (r["state"] !== "completed") continue;
    const reasons = r["evidenceReasons"];
    out.push({
      sessionId,
      kind,
      target,
      riskVerdict: verdict(r["riskVerdict"]),
      evidenceReasons: Array.isArray(reasons) ? reasons.filter((x): x is string => typeof x === "string") : [],
      openedAtUnix,
      state: "completed",
      expiresAtUnix: optNum(r["expiresAtUnix"]) ?? null,
    });
  }
  return { sessions: out };
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

/**
 * `kiwi_message_source` (T-295) — verbatim RFC822 for "view source".
 * `source` is lossy-decoded UTF-8 capped at 8 MiB; `truncated` marks the
 * cap fired and `bytes` is the stored total ("first 8 MiB of N").
 */
export interface MessageSourceView {
  folderId: number;
  uid: number;
  source: string;
  bytes: number;
  truncated: boolean;
}

/**
 * `kiwi_set_pop3_policy` (T-295) — per-account POP3 server-side deletion.
 * Default `false` keeps drops on the server; `true` sends DELE per ingest.
 */
export interface Pop3PolicyView {
  accountId: string;
  deleteAfterDownload: boolean;
}

/**
 * `kiwi_import_mbox` (T-309) — per-member failure inside an mbox import.
 * `index` is the 1-based `From ` member ordinal (0 marks a file-level note);
 * `detail` is bounded and never contains a body fragment or a filename.
 */
export interface MboxImportIssueView {
  index: number;
  detail: string;
}

/**
 * `kiwi_import_mbox` report. Counts sum to the members processed
 * (`min(messagesFound, MAX_MBOX_MESSAGES)`); `truncated` marks members left
 * unprocessed past the cap. `ruleFailures` counts ingest-rule errors on
 * imported rows only — the members still landed.
 */
export interface MboxImportView {
  accountId: string;
  folder: string;
  folderId: number;
  messagesFound: number;
  imported: number;
  skippedDuplicates: number;
  skippedExpunged: number;
  failed: number;
  truncated: boolean;
  ruleFailures: number;
  issues: MboxImportIssueView[];
}

/**
 * `kiwi_mailbox_export_mbox` report (T-316). `exported` counts members
 * written to the file; `skipped` counts rows whose RFC822 body could not
 * be obtained (omitted, never synthesized); `partial` flips whenever the
 * file doesn't carry every row. Write is atomic (`.kiwi-part` + rename).
 */
export interface MboxExportView {
  accountId: string;
  folder: string;
  folderId: number;
  exported: number;
  skipped: number;
  bytes: number;
  partial: boolean;
  truncated: boolean;
}

/**
 * `kiwi_audit_events` row (T-323/T-324). One real append-only JSONL record:
 * `action` → `event`, `ts_unix` → `atUnix`, verbatim `detail` →
 * `detailJson` (often plain text). The persisted schema has no actor or
 * subject column, so both are explicit nulls — never synthesized.
 */
export interface AuditEventView {
  event: string;
  atUnix: number;
  /** Real JSONL has no actor/subject columns; absence is explicit null. */
  actor: string | null;
  subjectId?: string | null;
  detailJson?: string | null;
}

/**
 * `kiwi_storage_stats` snapshot (T-330, ipc.md §8). Every field is a real
 * measurement or explicit `null` — `0` and `null` are different facts:
 * `dbBytes`/`attachmentBytes` null = unmeasurable, never an estimate.
 * `integrityCheck` is SQLite's own PRAGMA result — only `"ok"` is a pass.
 */
export interface StorageStatsView {
  dbBytes: number | null;
  messageCount: number;
  folderCount: number;
  attachmentBytes: number | null;
  auditCount: number;
  schemaVersion: number;
  integrityCheck: string;
}

/**
 * `kiwi_storage_compact` receipt (T-330) — real mail.db length measured
 * immediately before/after the VACUUM. `after > before` is possible and
 * honest. Audited twice backend-side (`-requested` then `-compacted`).
 */
export interface StorageCompactView {
  beforeDbBytes: number | null;
  afterDbBytes: number | null;
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
  /** `null` when nothing moved (hard delete / empty selection). */
  trashFolderId: number | null;
  /** src uid → Trash uid for moved messages (uids are folder-scoped). */
  uidMap: Record<string, number>;
}

/** `kiwi_move_messages` result (T-163). */
export interface MoveResultView {
  srcFolderId: number;
  dstFolderId: number;
  moved: number;
  /** src uid → dst uid for moved messages (uids are folder-scoped). */
  uidMap: Record<string, number>;
}

/**
 * `kiwi_copy_messages` result (T-325). Store-level duplicate only —
 * never a server-side IMAP COPY; a copy of a synced-folder message is a
 * local row the next reconcile treats as new (gap filed: real IMAP COPY
 * belongs in the sync layer).
 */
export interface CopyResultView {
  srcFolderId: number;
  dstFolderId: number;
  copied: number;
  /** src uid → fresh local dst uid. */
  uidMap: Record<string, number>;
}

/**
 * One `{folderId, uid}` message coordinate — snooze/unsnooze refs (T-255).
 * Unlike `folderId + uids[]` commands, snooze refs may span folders (the
 * Snoozed view is account-wide).
 */
export interface MessageRef {
  folderId: number;
  uid: number;
}

/**
 * `kiwi_message_snooze` deadline preset — resolved server-side to a fixed
 * offset so every client agrees (see docs/contracts/ipc.md §6e). Pass
 * `preset` XOR `untilUnix`.
 */
export type SnoozePreset = "later_today" | "tomorrow" | "next_week";

/** `kiwi_message_snooze` result. */
export interface SnoozeResultView {
  snoozed: number;
  untilUnix: number;
}

/** `kiwi_message_unsnooze` result. */
export interface UnsnoozeResultView {
  unsnoozed: number;
}

/**
 * One parked message (`kiwi_list_snoozed`, T-255). The row still lives in
 * `folder` — snooze hides it from folder lists, it is never moved.
 * `snoozedFromFolderId` is where it was parked (survives moves).
 */
export interface SnoozedMessageView {
  folderId: number;
  uid: number;
  folder: string;
  snoozedFromFolderId: number;
  snoozedUntil: number;
  snoozedAt: number;
  subject: string | null;
  fromAddr: string | null;
  messageId: string | null;
  dateUnix: number | null;
}

/**
 * One relocated ref from `kiwi_message_set_junk` (T-263) — moves remap
 * uids and refs may span folders, so each leg records its source.
 */
export interface SetJunkMoveView {
  fromFolderId: number;
  fromUid: number;
  /** Fresh uid in the destination folder (uids are folder-scoped). */
  toUid: number;
}

/**
 * `kiwi_message_set_junk` result. `targetFolderId` is the Junk folder
 * when `junk` and INBOX when un-junking out of Junk; `null` when the
 * call only flipped flags (already-in-Junk / un-junk elsewhere).
 */
export interface SetJunkView {
  junk: boolean;
  flagged: number;
  moved: number;
  targetFolderId: number | null;
  moves: SetJunkMoveView[];
}

/* ---------------- inbox rules DSL (T-228/T-233/T-244) ---------------- */

/** Field comparison operator — `domain` is a post-`@` dot-boundary suffix. */
export type RuleMatchOp = "contains" | "is" | "ends_with" | "domain";

/**
 * Predicate tree — `{"kind": "…"}` serde shape from the backend's
 * rules DSL (docs/contracts/ipc.md §6d). `sender`/`recipient` match the
 * email address only, never the display name.
 */
export type RulePredicate =
  | { kind: "sender" | "recipient" | "subject" | "attachment_name"; op: RuleMatchOp; value: string }
  | { kind: "header"; name: string; op: RuleMatchOp; value: string }
  | { kind: "body_contains"; value: string }
  | { kind: "all" | "any"; children: RulePredicate[] }
  | { kind: "not"; child: RulePredicate }
  | { kind: "always" };

/**
 * `{"do": "…"}` actions — folder dispositions (`move`/`archive`/`delete`)
 * relocate the message (first wins); `delete` is Trash semantics, never
 * a hard expunge.
 */
export type RuleAction =
  | { do: "move"; folder: string }
  | { do: "archive" | "delete" | "mark_read" | "star" };

/**
 * A rule as the renderer sees it — one shape serves both directions:
 * `kiwi_rules_list` emits it, `kiwi_rules_upsert` consumes it (ids are
 * caller-assigned — upsert is create-or-replace). `accountId` absent/
 * null = applies to every account; `isBlock` marks the block-list class
 * (evaluated before regular rules, terminal on match, verdict = Trash).
 */
export interface RuleView {
  id: string;
  accountId?: string | null;
  name: string;
  enabled: boolean;
  position: number;
  isBlock: boolean;
  when: RulePredicate;
  then: RuleAction[];
  /** Store-owned cumulative sync-time apply failures; badge broken rules when > 0. */
  failureCount: number;
  /** Most recent bounded diagnostic, or null before any failure. */
  lastError: string | null;
  /** Unix seconds of the most recent failure, or null. */
  lastFailureUnix: number | null;
}

/** One audit row — which rule fired on which stored message, when. */
export interface RuleHitView {
  folderId: number;
  uid: number;
  ruleId: string;
  messageId: string | null;
  appliedUnix: number;
}

/** `kiwi_rules_apply_now` receipt — the re-run's aggregate effect. */
export interface RulesApplyView {
  scanned: number;
  matched: number;
  moved: number;
  /** Block-list verdicts applied (each trashed the message). */
  blocked: number;
  flagsChanged: number;
  /** Messages skipped — no parseable body stored yet. */
  skippedNoBody: number;
}

/** One candidate-rule match in `kiwi_rules_preview`. */
export interface PreviewHitView {
  folderId: number;
  uid: number;
  /** Folder name (not id) — this is a display list. */
  folder: string;
  subject: string | null;
  messageId: string | null;
  /** True predicate leaves with stable AST paths; no body/header values. */
  conditionHits: PreviewConditionHitView[];
}

export interface PreviewConditionHitView {
  path: string;
  kind: "sender" | "recipient" | "subject" | "header" | "body_contains" | "attachment_name" | "always";
}

/**
 * `kiwi_rules_preview` receipt — a pure read: nothing was moved,
 * flagged, hit-logged, or watermarked. `matched` = `hits.length`.
 */
export interface RulePreviewView {
  scanned: number;
  skippedNoBody: number;
  matched: number;
  hits: PreviewHitView[];
}

/* ---------------- message templates (gated, T-288, ipc.md §6i) ------- */

/**
 * Stored composer template — a flat named list (content, not policy;
 * no account scoping). Stored rows keep `{{name}}` placeholders
 * verbatim; substitution happens only via `templatesRender`.
 */
export interface TemplateView {
  /** `tpl-N`, assigned by the store on create. */
  id: string;
  name: string;
  /** Subject line; `{{var}}` placeholders allowed, resolved at render. */
  subject: string;
  /** Plain-text body — always present (may be empty). */
  bodyText: string;
  /** Optional HTML body — omitted (not null) when absent. */
  bodyHtml?: string;
  createdUnix: number;
  updatedUnix: number;
}

/** `kiwi_templates_create` payload — id/timestamps are store-assigned. */
export interface TemplateInput {
  name: string;
  subject?: string;
  bodyText?: string;
  bodyHtml?: string;
}

/**
 * `kiwi_templates_render` result — fields with `{{var}}` resolved
 * (single non-recursive pass; unknown names left verbatim) plus the
 * well-formed placeholders that had no supplied value.
 */
export interface RenderedTemplateView {
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  /** Sorted, deduped placeholder names with no supplied value — flag these. */
  missingVars: string[];
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

/** `kiwi_contact_tags` row — `{tag, count}`, most-used first (contacts.md §5.2). */
export interface TagCountView {
  tag: string;
  count: number;
}

/** `kiwi_import_vcards` issue row — one per card that failed to import. */
export interface ImportIssueView {
  cardIndex: number;
  detail: string;
}

/** `kiwi_import_vcards` result (contacts.md §5.2): imported contacts + issues. */
export interface VCardImportView {
  contacts: ContactView[];
  issues: ImportIssueView[];
}

/** `kiwi_export_vcards` result — a single concatenated vCard payload. */
export interface VCardExportView {
  vcard: string;
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
  subject: string | null;
  from: string[];
  to: string[];
  cc: string[];
  dateUnix: number | null;
  /** `null` = no text/plain alternative or body not yet parsed. */
  textBody: string | null;
  htmlBody: string | null;
  attachments: MessageAttachmentView[];
  bodyPresent: boolean;
  inReplyTo: string | null;
  references: string[];
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
  /** Last 8 hex of SHA-256 over the raw public key — display only. */
  keyFingerprintTail: string;
  /** Full lowercase-hex SHA-256 fingerprint of the public key. */
  fingerprint: string;
  /** Credential-store key reference, when the device key is held backend-side. */
  keystoreRef: string | null;
  /** Revocation timestamp; `null` while the device is live (§9d.6). */
  revokedUnix: number | null;
}

/* ---------------- pairing flow (ipc.md §9d) ---------------- */

/** `pair_begin` — the backend owns the ticket + expiry; the renderer only
 *  displays `qrPayload` for the phone to claim. */
export interface PairBeginView {
  ticket: string;
  expiresUnix: number;
  qrPayload: string;
}

/** `pair_status` — read-only ticket poll; never consumes (§9d.4). */
export interface PairStatusView {
  state: "awaiting-phone" | "claimed" | "expired";
  device: DeviceView | null;
  expiresUnix: number;
}

/**
 * `kiwi_schedule_send`/`kiwi_send_message` receipt — queue identity plus
 * dispatch/undo deadlines (unix seconds).
 */
export interface SendReceipt {
  queueId: string;
  /** Earliest dispatch time (unix seconds). */
  notBeforeUnix: number;
  /** Undo-send cancel deadline (unix seconds). */
  undoWindowUntilUnix: number;
}

/** `kiwi_sync_status` row — one per configured account (ipc.md §6). */
export interface SyncStatusView {
  accountId: string;
  /** "pending" | "connecting" | "syncing" | "idle" | "polling" |
   *  "backoff" | "paused-locked" | "stopped" */
  state: string;
  lastSyncUnix: number | null;
  lastError: string | null;
  nextRetryUnix: number | null;
  foldersSynced: number;
  newMessages: number;
  attempts: number;
}

export interface OutboxItem {
  queueId: string;
  /** Always set by kiwi_list_outbox today; `null` = unbound queue row. */
  accountId: string | null;
  from: string;
  to: string[];
  subject: string;
  notBeforeUnix: number;
  undoWindowUntilUnix: number;
  attempts: number;
  cancelable: boolean;
  /**
   * Lifecycle state (T-298, ipc.md §7). The list only ever emits
   * `queued` (attempts==0 — incl. send-later/undo-grace) and `held`
   * (attempts>0 — a prior attempt failed, retry pending). `sending` is
   * a sub-second transient; `sent`/`cancelled` drop the row — observe
   * terminal transitions via the kiwi://outbox event, not the list.
   */
  state: "queued" | "sending" | "held" | "cancelled" | "sent";
  /** Sanitized `code: message` of the last failed attempt; `null` until the first. */
  lastError: string | null;
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
  consentConsumed: boolean;
  enqueued: boolean;
  singleAttempt: boolean;
}

export interface DeliverabilityStatusView {
  testId: string;
  /** "pending" | "received" | "analyzing" | "checks_ready" | unknown string. `failed` is an error, never a status. */
  analysisStatus: string;
  checksDone: number;
  checksTotal: number;
  ready: boolean;
  sent: boolean;
  consentConsumed: boolean;
  retryAfterMs?: number;
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
  authFailureIds: string[];
  authGate: "pass" | "fail" | "unknown";
  checksTruncated: boolean;
  evidenceComplete: boolean;
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
    // T-331: only a real boolean counts; anything else stays null = unchecked.
    auditOk: typeof r["auditOk"] === "boolean" ? r["auditOk"] : null,
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
