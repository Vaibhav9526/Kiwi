/**
 * Services — RBAC-enforced, audited operations over the repositories.
 * The REST layer (docs/contracts/admin-api.md) will sit on top of these.
 */
import { randomUUID } from "node:crypto";
import { requirePermission, AuthorizationDeniedError } from "../rbac/rbac.js";
import type { Actor, Permission } from "../rbac/rbac.js";
import type { OrgRole } from "../types.js";
import { evaluatePolicy } from "./evaluator.js";
import type { PolicyDefinition, PolicyInput, PolicyDecision } from "./model.js";
import { assertNonEmptyString, assertIdentifier } from "../util/validate.js";
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
}
