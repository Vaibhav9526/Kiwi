/**
 * Deterministic policy evaluator (task T-004). Pure functions: no I/O, no AI,
 * no clocks. Same input → same verdict, always (SECURITY.md rule 1).
 *
 * Evaluation order for outbound messages:
 *   1. recipient domain parseability
 *   2. explicit block rules
 *   3. explicit allow rules (suppresses external-recipient warn)
 *   4. external-recipient behavior (warn|block|allow)
 *   5. min-TLS floor on observed transport TLS
 * Verdict severity: block > warn > allow.
 */
import { emailDomain, normalizeDomain, TLS_VERSION_ORDER } from "../types.js";
import type { PolicyDefinition, PolicyInput, PolicyDecision, PolicyReason } from "./model.js";
import { REASON_CODES, decide } from "./model.js";

function isExternalDomain(domain: string, policy: PolicyDefinition): boolean {
  // "External" means: not covered by an explicit allow rule for this org's
  // own namespace. In this scaffold the org's managed domains are represented
  // by the allow-rules set; a fuller model links org→domains (Phase 6).
  return !policy.domainRules.some(
    (r) => r.action === "allow" && normalizeDomain(r.domain) === domain,
  );
}

function tlsRank(label: string | null): number {
  if (label === null) return -1;
  const idx = TLS_VERSION_ORDER.indexOf(label);
  return idx;
}

export function evaluatePolicy(policy: PolicyDefinition, input: PolicyInput): PolicyDecision {
  const reasons: PolicyReason[] = [];

  if (!policy.enabled) {
    return decide({ reasons: [{ code: REASON_CODES.NO_POLICY_ENABLED }], policyId: policy.id });
  }

  const recipientDomain = emailDomain(input.recipient);
  if (recipientDomain === null || !recipientDomain.includes(".")) {
    reasons.push({ code: REASON_CODES.RECIPIENT_UNPARSEABLE, detail: input.recipient });
    return decide({ reasons, policyId: policy.id });
  }

  const normalizedRecipient = normalizeDomain(recipientDomain);

  const blocked = policy.domainRules.find(
    (r) => r.action === "block" && normalizeDomain(r.domain) === normalizedRecipient,
  );
  if (blocked) {
    reasons.push({ code: REASON_CODES.RECIPIENT_DOMAIN_BLOCKED, detail: normalizedRecipient });
    return decide({ reasons, policyId: policy.id });
  }

  const allowed = policy.domainRules.find(
    (r) => r.action === "allow" && normalizeDomain(r.domain) === normalizedRecipient,
  );

  if (input.direction === "outbound") {
    if (!allowed && policy.externalRecipients === "block") {
      reasons.push({ code: REASON_CODES.RECIPIENT_DOMAIN_BLOCKED, detail: `${normalizedRecipient} (external-recipient=block)` });
      return decide({ reasons, policyId: policy.id });
    }
    if (!allowed && policy.externalRecipients === "warn") {
      reasons.push({ code: REASON_CODES.EXTERNAL_RECIPIENT, detail: normalizedRecipient });
    }
  }

  // min-TLS: applies to the observed transport TLS version of the connection
  // carrying this message. Unknown TLS never blocks (it is unverified, not
  // measured weak) — it warns only when external-recipient also warns? No:
  // keep orthogonal — TLS_UNVERIFIED alone yields warn.
  if (input.direction === "outbound" && policy.minTls !== null) {
    const observedRank = tlsRank(input.tlsVersion);
    const minRank = tlsRank(policy.minTls);
    if (observedRank < 0) {
      reasons.push({ code: REASON_CODES.TLS_UNVERIFIED, detail: "no TLS version observed" });
    } else if (minRank >= 0 && observedRank < minRank) {
      reasons.push({ code: REASON_CODES.TLS_BELOW_MINIMUM, detail: `observed ${input.tlsVersion} < required ${policy.minTls}` });
    }
  }

  if (allowed) {
    reasons.push({ code: REASON_CODES.RECIPIENT_DOMAIN_ALLOWED, detail: normalizedRecipient });
  }

  return decide({ reasons, policyId: policy.id });
}
