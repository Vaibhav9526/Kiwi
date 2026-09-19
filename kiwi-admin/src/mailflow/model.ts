/** Mail-flow metadata model — metadata only, never message bodies (prompt.md §6 Agent 4). */
import { emailDomain, TLS_VERSION_ALIASES } from "../types.js";
import { assertNonEmptyString, assertIdentifier, isRecord } from "../util/validate.js";
import { RequestValidationError } from "../util/validate.js";

export type MailDirection = "inbound" | "outbound";

export type PolicyVerdict = "allow" | "warn" | "block" | "unknown";

export const SECURITY_STATUSES: readonly string[] = [
  "clean",
  "warn",
  "suspicious",
  "tls-mismatch",
  "unknown",
] as const;

export interface MailflowEvent {
  id: string;
  org_id: string | null;
  direction: MailDirection;
  sender: string;
  recipient: string;
  ts: number;
  message_id: string | null;
  tls_version: string | null;
  security_status: string;
  policy_verdict: PolicyVerdict;
  received_at: number;
}

export interface MailflowIngest {
  id: string;
  orgId: string | null;
  direction: MailDirection;
  sender: string;
  recipient: string;
  ts: number;
  messageId: string | null;
  tlsVersion: string | null;
  securityStatus: string;
  policyVerdict: PolicyVerdict;
}

/** Validate an untrusted ingest payload into a strict MailflowIngest. */
export function parseMailflowIngest(raw: unknown, generateId: () => string): MailflowIngest {
  if (!isRecord(raw)) throw new RequestValidationError("body", "expected object");
  const direction = raw["direction"];
  if (direction !== "inbound" && direction !== "outbound") {
    throw new RequestValidationError("direction", "must be 'inbound' or 'outbound'");
  }
  const sender = assertNonEmptyString(raw["sender"], "sender", 254);
  const recipient = assertNonEmptyString(raw["recipient"], "recipient", 254);
  const rawTs = raw["ts"];
  if (typeof rawTs !== "number" || !Number.isSafeInteger(rawTs)) {
    throw new RequestValidationError("ts", "expected integer");
  }
  const orgId = raw["org_id"] === undefined || raw["org_id"] === null ? null : assertIdentifier(raw["org_id"], "org_id");
  const messageId = raw["message_id"] === undefined || raw["message_id"] === null ? null : assertNonEmptyString(raw["message_id"], "message_id", 998);
  const securityStatus = typeof raw["security_status"] === "string" && SECURITY_STATUSES.includes(raw["security_status"])
    ? raw["security_status"]
    : "unknown";
  const policyVerdict = raw["policy_verdict"];
  const verdict: PolicyVerdict =
    policyVerdict === "allow" || policyVerdict === "warn" || policyVerdict === "block" ? policyVerdict : "unknown";

  let tlsVersion: string | null = null;
  const rawTls = raw["tls_version"];
  if (typeof rawTls === "string") {
    const normalized = TLS_VERSION_ALIASES[rawTls.trim().toLowerCase()];
    if (normalized) tlsVersion = normalized;
    else throw new RequestValidationError("tls_version", `unrecognized TLS version '${rawTls}'`);
  }

  if (orgId === null && direction === "outbound") {
    throw new RequestValidationError("org_id", "required for outbound events");
  }

  return {
    id: generateId(),
    orgId,
    direction,
    sender,
    recipient,
    ts: rawTs,
    messageId,
    tlsVersion,
    securityStatus,
    policyVerdict: verdict,
  };
}

export function recipientDomainOf(event: MailflowIngest | MailflowEvent): string | null {
  return emailDomain(event.recipient);
}
