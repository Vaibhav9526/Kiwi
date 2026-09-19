/**
 * Services — RBAC-enforced, audited operations over the repositories.
 * The REST layer (docs/contracts/admin-api.md) will sit on top of these.
 */
import { randomUUID } from "node:crypto";
import { requirePermission, AuthorizationDeniedError } from "../rbac/rbac.js";
import type { Actor, Permission } from "../rbac/rbac.js";
import type { OrgRole } from "../types.js";
import { TLS_VERSION_ALIASES } from "../types.js";
import { evaluatePolicy } from "./evaluator.js";
import type { PolicyDefinition, PolicyInput, PolicyDecision, PolicyReason } from "./model.js";
import { REASON_CODES } from "./model.js";
import { assertNonEmptyString, assertIdentifier, RequestValidationError } from "../util/validate.js";
import type { RecipientDomainAction, ExternalRecipientBehavior } from "../types.js";

export interface ExternalPolicyInput {
  name: string;
  enabled: boolean;
  minTls: string | null;
  externalRecipients: ExternalRecipientBehavior;
  domainRules: { domain: string; action: RecipientDomainAction }[];
}

export interface ServiceContainerLike {
  auditWrap<T>(actor: Actor, orgId: string | null, action: string, resource: string | null, work: () => T, permission?: Permission): T;
}

export class OrgService {
  constructor(
    private readonly repos: { orgs: import("../db/interfaces.js").OrgRepository },
    private readonly ctx: ServiceContainerLike,
  ) {}

  createOrg(actor: Actor, name: string, now: number): { id: string; name: string; created_at: number } {
    const id = `org-${randomUUID()}`;
    return this.ctx.auditWrap(actor, null, "org.create", id, () =>
      this.repos.orgs.createOrg(id, assertNonEmptyString(name, "name", 200), now),
    );
  }

  createUser(actor: Actor, orgId: string, email: string, now: number): { id: string; org_id: string; email: string; created_at: number } {
    const id = `user-${randomUUID()}`;
    return this.ctx.auditWrap(
      actor,
      orgId,
      "user.create",
      id,
      () => this.repos.orgs.createUser(id, assertIdentifier(orgId, "orgId"), assertNonEmptyString(email, "email", 254), now),
      "user.invite",
    );
  }

  grantRole(actor: Actor, userId: string, orgId: string, role: OrgRole, now: number): void {
    this.ctx.auditWrap(
      actor,
      orgId,
      "user.role.grant",
      userId,
      () => this.repos.orgs.grantRole(assertIdentifier(userId, "userId"), orgId, role, now),
      "user.role.grant",
    );
  }

  createDevice(
    actor: Actor,
    orgId: string,
    label: string,
    now: number,
  ): { id: string; org_id: string; label: string; revoked: number; created_at: number } {
    const id = `dev-${randomUUID()}`;
    return this.ctx.auditWrap(
      actor,
      orgId,
      "device.create",
      id,
      () => this.repos.orgs.createDevice(id, orgId, assertNonEmptyString(label, "label", 200), now),
      "device.revoke",
    );
  }

  revokeDevice(actor: Actor, deviceId: string, now: number): void {
    this.ctx.auditWrap(
      actor,
      null,
      "device.revoke",
      deviceId,
      () => this.repos.orgs.revokeDevice(assertIdentifier(deviceId, "deviceId"), now),
      "device.revoke",
    );
  }

  listDomains(actor: Actor, orgId: string): { domain: string; verified: number }[] {
    requirePermission(actor, "org.read", orgId);
    return this.repos.orgs.listDomains(orgId);
  }

  /** T-134: org user listing with roles (read-only, RBAC-gated, unaudited like other reads). */
  listUsers(actor: Actor, orgId: string): { id: string; email: string; roles: OrgRole[]; created_at: number }[] {
    requirePermission(actor, "user.read", orgId);
    const oid = assertIdentifier(orgId, "orgId");
    return this.repos.orgs.listUsers(oid).map((u) => ({
      id: u.id,
      email: u.email,
      roles: this.repos.orgs.listRoles(u.id),
      created_at: u.created_at,
    }));
  }
}

export class PolicyService {
  constructor(
    private readonly repos: { policies: import("../db/interfaces.js").PolicyRuleRepository },
    private readonly ctx: ServiceContainerLike,
  ) {}

  createPolicy(actor: Actor, orgId: string, name: string, input: ExternalPolicyInput): { id: string } {
    const id = `pol-${randomUUID()}`;
    return this.ctx.auditWrap(
      actor,
      orgId,
      "policy.create",
      id,
      () => {
        this.repos.policies.createPolicy(
          id,
          orgId,
          assertNonEmptyString(name, "name", 200),
          input.enabled,
          input.minTls,
          input.externalRecipients,
          Date.now(),
        );
        for (const rule of input.domainRules) {
          this.repos.policies.addDomainRule(id, assertNonEmptyString(rule.domain, "domain", 253), rule.action);
        }
        return { id };
      },
      "policy.write",
    );
  }

  getPolicyDefinition(id: string): PolicyDefinition | undefined {
    const row = this.repos.policies.getPolicy(id);
    if (!row) return undefined;
    return {
      id: row.id,
      enabled: row.enabled === 1,
      minTls: row.min_tls,
      externalRecipients: row.external_recipients,
      domainRules: this.repos.policies.listDomainRules(id),
    };
  }

  evaluate(id: string, input: PolicyInput): PolicyDecision {
    const definition = this.getPolicyDefinition(id);
    if (!definition) throw new Error(`policy '${id}' not found`);
    return evaluatePolicy(definition, input);
  }

  /** T-134: full policy definitions of an org (read-only, RBAC-gated). */
  listPolicies(actor: Actor, orgId: string): PolicyDefinition[] {
    requirePermission(actor, "policy.read", orgId);
    const oid = assertIdentifier(orgId, "orgId");
    return this.repos.policies.listPoliciesForOrg(oid).map((row) => ({
      id: row.id,
      enabled: row.enabled === 1,
      minTls: row.min_tls,
      externalRecipients: row.external_recipients,
      domainRules: this.repos.policies.listDomainRules(row.id),
    }));
  }

  /**
   * T-108 send-path entry point. Validates untrusted caller input, loads the
   * org's policies, and delegates to the pure evaluateOutboundForOrg core.
   * Requires `policy.read` on the org; allowed AND denied checks are audited.
   */
  evaluateOutbound(
    actor: Actor,
    orgId: string,
    raw: { sender: unknown; recipients: unknown; tlsVersion: unknown },
  ): OutboundEvaluation {
    return this.ctx.auditWrap(
      actor,
      orgId,
      "policy.evaluate_outbound",
      orgId,
      () => {
        const oid = assertIdentifier(orgId, "orgId");
        const sender = assertNonEmptyString(raw.sender, "sender", 254);
        if (!Array.isArray(raw.recipients) || raw.recipients.length === 0) {
          throw new RequestValidationError("recipients", "expected non-empty array");
        }
        if (raw.recipients.length > MAX_BRIDGE_RECIPIENTS) {
          throw new RequestValidationError("recipients", `exceeds ${MAX_BRIDGE_RECIPIENTS} entries`);
        }
        const recipients = raw.recipients.map((r) => assertNonEmptyString(r, "recipients[]", 254));
        let tlsVersion: string | null = null;
        if (raw.tlsVersion !== undefined && raw.tlsVersion !== null) {
          if (typeof raw.tlsVersion !== "string") throw new RequestValidationError("tlsVersion", "expected string");
          const normalized = TLS_VERSION_ALIASES[raw.tlsVersion.trim().toLowerCase()];
          if (!normalized) throw new RequestValidationError("tlsVersion", "unrecognized TLS version");
          tlsVersion = normalized;
        }
        const definitions: PolicyDefinition[] = this.repos.policies.listPoliciesForOrg(oid).map((row) => ({
          id: row.id,
          enabled: row.enabled === 1,
          minTls: row.min_tls,
          externalRecipients: row.external_recipients,
          domainRules: this.repos.policies.listDomainRules(row.id),
        }));
        return evaluateOutboundForOrg(oid, definitions, sender, recipients, tlsVersion);
      },
      "policy.read",
    );
  }
}

export interface OutboundRecipientResult {
  recipient: string;
  verdict: "allow" | "warn" | "block";
  reasons: PolicyReason[];
  /** Worst-policy id, or null when the org has no enabled policy. */
  policyId: string | null;
}

export interface OutboundEvaluation {
  orgId: string;
  /** Worst verdict across recipients — the send path blocks when ANY is block. */
  overall: "allow" | "warn" | "block";
  results: OutboundRecipientResult[];
}

const VERDICT_RANK = { allow: 0, warn: 1, block: 2 } as const;

/**
 * T-108 send-path bridge. Evaluates an outbound send attempt against ALL
 * enabled policies of the org (worst verdict wins per recipient) and returns
 * per-recipient results for the composer banner (KIWI-UI-007) plus an overall
 * send/no-send verdict for kiwi-mail's send path. Pure core — no I/O, no AI.
 *
 * Advisory only — see admin-api.md §5.3 honest-enforcement limitation.
 */
export function evaluateOutboundForOrg(
  orgId: string,
  policies: PolicyDefinition[],
  sender: string,
  recipients: string[],
  tlsVersion: string | null,
): OutboundEvaluation {
  const enabled = policies.filter((p) => p.enabled);
  const results: OutboundRecipientResult[] = recipients.map((recipient) => {
    if (enabled.length === 0) {
      return { recipient, verdict: "allow", reasons: [{ code: REASON_CODES.NO_POLICY_ENABLED }], policyId: null };
    }
    const decisions = enabled.map((p) => evaluatePolicy(p, { direction: "outbound", sender, recipient, tlsVersion }));
    let worst = decisions[0]!;
    for (const d of decisions) {
      if (VERDICT_RANK[d.verdict] > VERDICT_RANK[worst.verdict]) worst = d;
    }
    return {
      recipient,
      verdict: worst.verdict,
      reasons: worst.reasons,
      policyId: worst.evaluatedPolicyId,
    };
  });
  let overall: OutboundEvaluation["overall"] = "allow";
  for (const r of results) {
    if (VERDICT_RANK[r.verdict] > VERDICT_RANK[overall]) overall = r.verdict;
  }
  return { orgId, overall, results };
}

/** Max recipients per send-path evaluation (bounded untrusted input). */
const MAX_BRIDGE_RECIPIENTS = 256;
