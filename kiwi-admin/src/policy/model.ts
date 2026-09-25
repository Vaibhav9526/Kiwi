/** Policy model — deterministic, no AI (SECURITY.md rule 1). */
import type { ExternalRecipientBehavior, RecipientDomainAction } from "../types.js";

export type PolicyVerdict = "allow" | "warn" | "block";

export interface PolicyReason {
  code: string;
  detail?: string;
}

export interface PolicyDefinition {
  id: string;
  enabled: boolean;
  /** Minimum acceptable TLS version label (TLS_VERSION_ALIASES key), or null for no floor. */
  minTls: string | null;
  externalRecipients: ExternalRecipientBehavior;
  /** Recipient-domain rules; precedence documented in admin-api.md §5.2. */
  domainRules: { domain: string; action: RecipientDomainAction }[];
}

/**
 * §5.1 wire shape — the snake_case contract object returned by
 * `GET /orgs/{org}/policies`. Distinct from the internal camelCase
 * `PolicyDefinition` the evaluator consumes (T-259/ADM-T250-01): the list
 * endpoint had been serializing the internal shape, dropping `name`/`org_id`
 * and casing fields wrong.
 */
export interface PolicyObject {
  id: string;
  org_id: string;
  name: string;
  enabled: boolean;
  min_tls: string | null;
  external_recipients: ExternalRecipientBehavior;
  domain_rules: { domain: string; action: RecipientDomainAction }[];
}

export interface PolicyInput {
  direction: "inbound" | "outbound";
  sender: string;
  recipient: string;
  /** Canonical TLS label or null when unknown/not observed. */
  tlsVersion: string | null;
}

export interface PolicyDecision {
  verdict: PolicyVerdict;
  reasons: PolicyReason[];
  /**
   * Canonical field name `policyId` (T-259/ADM-T250-12): the single-evaluate
   * response and the §10 outbound bridge now use one name. Null when no
   * enabled policy produced the verdict (`no-policy-enabled`).
   */
  policyId: string | null;
}

/** Stable reason codes (docs/contracts/admin-api.md §5.3). */
export const REASON_CODES = {
  RECIPIENT_UNPARSEABLE: "recipient-unparseable",
  RECIPIENT_DOMAIN_BLOCKED: "recipient-domain-blocked",
  RECIPIENT_DOMAIN_ALLOWED: "recipient-domain-allowed",
  EXTERNAL_RECIPIENT: "external-recipient",
  TLS_BELOW_MINIMUM: "tls-below-minimum",
  TLS_UNVERIFIED: "tls-unverified",
  NO_POLICY_ENABLED: "no-policy-enabled",
} as const;

export function decide(decision: Omit<PolicyDecision, "verdict"> & { reasons: PolicyReason[] }): PolicyDecision {
  const hasBlock = decision.reasons.some((r) => r.code === REASON_CODES.RECIPIENT_DOMAIN_BLOCKED || r.code === REASON_CODES.RECIPIENT_UNPARSEABLE || r.code === REASON_CODES.TLS_BELOW_MINIMUM);
  const hasWarn = decision.reasons.some((r) => r.code === REASON_CODES.EXTERNAL_RECIPIENT || r.code === REASON_CODES.TLS_UNVERIFIED);
  const verdict: PolicyVerdict = hasBlock ? "block" : hasWarn ? "warn" : "allow";
  return { ...decision, verdict };
}
