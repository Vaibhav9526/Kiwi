/**
 * Mail-flow emitter helpers (T-109). Pure builders that shape client-side
 * send/receive facts into the wire-shape MailflowEvent payloads defined in
 * docs/contracts/admin-api.md §6. Output is validated again by
 * parseMailflowIngest on ingest — these builders never bypass validation.
 * Metadata only: there is no body/subject/content field anywhere here.
 */
import { emailDomain, TLS_VERSION_ALIASES } from "../types.js";
import { SECURITY_STATUSES } from "./model.js";
import type { PolicyVerdict } from "./model.js";
import { RequestValidationError, assertInt, assertNonEmptyString } from "../util/validate.js";

export interface MailflowWireEvent {
  id: string;
  org_id: string | null;
  direction: "inbound" | "outbound";
  sender: string;
  recipient: string;
  ts: number;
  message_id: string | null;
  tls_version: string | null;
  security_status: string;
  policy_verdict: PolicyVerdict;
}

function normalizeTlsVersion(raw: unknown, field: string): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") throw new RequestValidationError(field, "expected string");
  const normalized = TLS_VERSION_ALIASES[raw.trim().toLowerCase()];
  if (!normalized) throw new RequestValidationError(field, `unrecognized TLS version '${raw}'`);
  return normalized;
}

function normalizeSecurityStatus(raw: unknown): string {
  return typeof raw === "string" && (SECURITY_STATUSES as readonly string[]).includes(raw) ? raw : "unknown";
}

function normalizePolicyVerdict(raw: unknown): PolicyVerdict {
  return raw === "allow" || raw === "warn" || raw === "block" ? raw : "unknown";
}

function normalizeMessageId(raw: unknown): string | null {
  if (raw === undefined || raw === null) return null;
  return assertNonEmptyString(raw, "messageId", 998);
}

export interface SendAttemptFacts {
  orgId: string;
  sender: string;
  /** One entry per recipient, verdict from PolicyService.evaluateOutbound (T-108). */
  perRecipient: { recipient: string; policyVerdict: unknown }[];
  tlsVersion: unknown;
  securityStatus?: unknown;
  messageId?: unknown;
  /** Message time, Unix seconds. */
  ts: unknown;
}

/**
 * Build one outbound event per recipient for a send attempt. Call AFTER the
 * policy bridge verdict is known and AFTER the SMTP result is known — the
 * caller records the attempt regardless of send success (policy_verdict is
 * advisory; delivery outcome is not stored in v1).
 */
export function buildSendAttemptEvents(facts: SendAttemptFacts, generateId: () => string): MailflowWireEvent[] {
  const sender = assertNonEmptyString(facts.sender, "sender", 254);
  if (!Array.isArray(facts.perRecipient) || facts.perRecipient.length === 0) {
    throw new RequestValidationError("perRecipient", "expected non-empty array");
  }
  const ts = assertInt(facts.ts, "ts");
  const tlsVersion = normalizeTlsVersion(facts.tlsVersion, "tlsVersion");
  const securityStatus = normalizeSecurityStatus(facts.securityStatus);
  const messageId = normalizeMessageId(facts.messageId);
  return facts.perRecipient.map((entry) => {
    if (typeof entry !== "object" || entry === null) throw new RequestValidationError("perRecipient[]", "expected object");
    const recipient = assertNonEmptyString((entry as { recipient: unknown }).recipient, "recipient", 254);
    if (emailDomain(recipient) === null) throw new RequestValidationError("recipient", "missing domain part");
    return {
      id: generateId(),
      org_id: facts.orgId,
      direction: "outbound" as const,
      sender,
      recipient,
      ts,
      message_id: messageId,
      tls_version: tlsVersion,
      security_status: securityStatus,
      policy_verdict: normalizePolicyVerdict((entry as { policyVerdict: unknown }).policyVerdict),
    };
  });
}

export interface ReceivedFacts {
  orgId: string | null;
  sender: string;
  recipient: string;
  tlsVersion: unknown;
  securityStatus?: unknown;
  messageId?: unknown;
  ts: unknown;
}

/** Build one inbound event for a received message (post-sync, per message). */
export function buildReceivedEvent(facts: ReceivedFacts, generateId: () => string): MailflowWireEvent {
  const sender = assertNonEmptyString(facts.sender, "sender", 254);
  const recipient = assertNonEmptyString(facts.recipient, "recipient", 254);
  return {
    id: generateId(),
    org_id: facts.orgId,
    direction: "inbound" as const,
    sender,
    recipient,
    ts: assertInt(facts.ts, "ts"),
    message_id: normalizeMessageId(facts.messageId),
    tls_version: normalizeTlsVersion(facts.tlsVersion, "tlsVersion"),
    security_status: normalizeSecurityStatus(facts.securityStatus),
    policy_verdict: "unknown",
  };
}
