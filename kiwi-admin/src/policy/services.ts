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
import { assertNonEmptyString, assertIdentifier, RequestValidationError, NotFoundError } from "../util/validate.js";
import type { MaybePromise } from "../db/interfaces.js";
import type { RecipientDomainAction, ExternalRecipientBehavior } from "../types.js";

export interface ExternalPolicyInput {
  name: string;
  enabled: boolean;
  minTls: string | null;
  externalRecipients: ExternalRecipientBehavior;
  domainRules: { domain: string; action: RecipientDomainAction }[];
}

export interface ServiceContainerLike {
  auditWrap<T>(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    work: () => MaybePromise<T>,
    permission?: Permission,
  ): Promise<T>;
  /** Denial-only append for read endpoints that must audit a refused
    * authorization but never a successful read (§14.3 — auditWrap would
    * also stamp the allowed side). */
  auditAppend(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    outcome: import("../audit/model.js").AuditOutcome,
    requestId: string | null,
    details: Record<string, unknown>,
    ts: number,
  ): Promise<unknown>;
}

export class OrgService {
  constructor(
    private readonly repos: { orgs: import("../db/interfaces.js").OrgRepository },
    private readonly ctx: ServiceContainerLike,
  ) {}

  async createOrg(actor: Actor, name: string, now: number): Promise<{ id: string; name: string; created_at: number }> {
    const id = `org-${randomUUID()}`;
    return this.ctx.auditWrap(
      actor,
      null,
      "org.create",
      id,
      () => this.repos.orgs.createOrg(id, assertNonEmptyString(name, "name", 200), now),
      "org.create",
    );
  }

  async createUser(
    actor: Actor,
    orgId: string,
    email: string,
    now: number,
  ): Promise<{ id: string; org_id: string; email: string; created_at: number }> {
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

  async grantRole(actor: Actor, userId: string, orgId: string, role: OrgRole, now: number): Promise<void> {
    const uid = assertIdentifier(userId, "userId");
    const oid = assertIdentifier(orgId, "orgId");
    // Membership check (T-193/M6): the grant targets (user, org) jointly —
    // a user from another org (or nobody at all) is a 404, never a
    // cross-org role row and never a constraint-name 500.
    const user = await this.repos.orgs.getUser(uid);
    if (!user || user.org_id !== oid) throw new NotFoundError(`user '${uid}' in org '${oid}'`);
    await this.ctx.auditWrap(
      actor,
      oid,
      "user.role.grant",
      uid,
      () => this.repos.orgs.grantRole(uid, oid, role, now),
      "user.role.grant",
    );
  }

  async createDevice(
    actor: Actor,
    orgId: string,
    label: string,
    now: number,
  ): Promise<{ id: string; org_id: string; label: string; revoked: number; created_at: number }> {
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

  async revokeDevice(actor: Actor, deviceId: string, now: number): Promise<void> {
    // Scoped revocation (T-193/H3): resolve the device's owning org first
    // so the permission check — and the audit row — target that org. A
    // revocation aimed at another org's device is denied, not executed.
    const did = assertIdentifier(deviceId, "deviceId");
    const device = await this.repos.orgs.getDevice(did);
    if (!device) throw new NotFoundError(`device '${did}'`);
    await this.ctx.auditWrap(
      actor,
      device.org_id,
      "device.revoke",
      did,
      () => this.repos.orgs.revokeDevice(did, now),
      "device.revoke",
    );
  }

  async listDomains(actor: Actor, orgId: string): Promise<{ domain: string; verified: number }[]> {
    requirePermission(actor, "org.read", orgId);
    return this.repos.orgs.listDomains(orgId);
  }

  async listUsers(actor: Actor, orgId: string, limit = 50): Promise<{ id: string; email: string; roles: OrgRole[]; created_at: number }[]> {
    requirePermission(actor, "user.read", orgId);
    const oid = assertIdentifier(orgId, "orgId");
    // Bounded + batched (T-193/M7): one roles query for the page, not one
    // per user; the page itself is capped like every other listing.
    const bounded = Math.min(Math.max(Math.floor(limit), 1), 500);
    const users = (await this.repos.orgs.listUsers(oid)).slice(0, bounded);
    const roleRows = users.length > 0 ? await this.repos.orgs.listRolesForUsers(users.map((u) => u.id)) : [];
    const byUser = new Map<string, OrgRole[]>();
    for (const row of roleRows) {
      const list = byUser.get(row.user_id) ?? [];
      list.push(row.role);
      byUser.set(row.user_id, list);
    }
    return users.map((u) => ({ id: u.id, email: u.email, roles: byUser.get(u.id) ?? [], created_at: u.created_at }));
  }

  /**
   * §14 device inventory (T-253): org-scoped, bounded, total order.
   * Authorization denial is audited via a denial-only append (a successful
   * read stays unaudited, consistent with listUsers/listPolicies). Fails
   * closed for a null-org actor — `device.read` on the real path org only.
   */
  async listDevices(
    actor: Actor,
    orgId: string,
    limit = 50,
  ): Promise<{ id: string; org_id: string; label: string; revoked: number; revoked_at: number | null; created_at: number }[]> {
    const oid = assertIdentifier(orgId, "orgId");
    try {
      requirePermission(actor, "device.read", oid);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        // Fixed denial row (§14.3): no device data in details. If this
        // append fails the error propagates as a sanitized 500 — the
        // inventory is not returned on a failed denial append.
        await this.ctx.auditAppend(actor, oid, "device.list", oid, "denied", null, { permission: "device.read" }, Date.now());
      }
      throw err;
    }
    const bounded = Math.min(Math.max(Math.floor(limit), 1), 500);
    const rows = await this.repos.orgs.listDevices(oid, bounded);
    for (const r of rows) {
      // §14.1 invariant: revoked=1 requires revoked_at, revoked=0 forbids
      // it. Legacy inconsistent rows must not be silently normalized.
      if ((r.revoked === 1) !== (r.revoked_at !== null)) {
        throw new Error(`device '${r.id}' has inconsistent revocation state`);
      }
    }
    return rows;
  }
}

/** Max domain rules per policy (T-193/M3): beside MAX_BRIDGE_RECIPIENTS. */
const MAX_POLICY_DOMAIN_RULES = 256;

export class PolicyService {
  constructor(
    private readonly repos: { policies: import("../db/interfaces.js").PolicyRuleRepository },
    private readonly ctx: ServiceContainerLike,
  ) {}

  async createPolicy(actor: Actor, orgId: string, name: string, input: ExternalPolicyInput): Promise<{ id: string }> {
    const id = `pol-${randomUUID()}`;
    return this.ctx.auditWrap(
      actor,
      orgId,
      "policy.create",
      id,
      async () => {
        // Validate the whole rule set BEFORE writing anything (T-193/M3):
        // an unchecked duplicate domain used to fail mid-loop on the
        // primary key, leaving earlier rules committed — a policy that was
        // neither requested nor nothing. Length is capped beside
        // MAX_BRIDGE_RECIPIENTS. Validation lives INSIDE the audited work
        // (not before auditWrap) so a rejected rule set leaves an `error`
        // row instead of no trace at all.
        if (input.domainRules.length > MAX_POLICY_DOMAIN_RULES) {
          throw new RequestValidationError("domainRules", `exceeds ${MAX_POLICY_DOMAIN_RULES} entries`);
        }
        const seen = new Set<string>();
        const rules = input.domainRules.map((rule) => {
          const domain = assertNonEmptyString(rule.domain, "domain", 253);
          if (rule.action !== "allow" && rule.action !== "block") {
            throw new RequestValidationError("domainRules[].action", "must be allow|block");
          }
          const key = domain.toLowerCase();
          if (seen.has(key)) throw new RequestValidationError("domainRules[]", `duplicate domain '${domain}'`);
          seen.add(key);
          return { domain, action: rule.action };
        });
        const policyName = assertNonEmptyString(name, "name", 200);
        await this.repos.policies.createPolicyWithRules(
          id,
          orgId,
          policyName,
          input.enabled,
          input.minTls,
          input.externalRecipients,
          Date.now(),
          rules,
        );
        return { id };
      },
      "policy.write",
    );
  }

  async getPolicyDefinition(id: string): Promise<PolicyDefinition | undefined> {
    const row = await this.repos.policies.getPolicy(id);
    if (!row) return undefined;
    return {
      id: row.id,
      enabled: row.enabled === 1,
      minTls: row.min_tls,
      externalRecipients: row.external_recipients,
      domainRules: await this.repos.policies.listDomainRules(id),
    };
  }

  async evaluate(actor: Actor, id: string, input: PolicyInput): Promise<PolicyDecision> {
    // Authenticated + audited evaluation (T-193/H1): resolve the owning org
    // first so the permission check — and the audit row — target it. The
    // policy id alone was previously sufficient scope for anyone on loopback.
    const row = await this.repos.policies.getPolicy(id);
    if (!row) throw new NotFoundError(`policy '${id}'`);
    return this.ctx.auditWrap(actor, row.org_id, "policy.evaluate", id, async () => {
      const definition = await this.getPolicyDefinition(id);
      if (!definition) throw new NotFoundError(`policy '${id}'`);
      return evaluatePolicy(definition, input);
    }, "policy.read");
  }

  /** T-134: full policy definitions of an org (read-only, RBAC-gated). */
  async listPolicies(actor: Actor, orgId: string, limit = 50): Promise<PolicyDefinition[]> {
    requirePermission(actor, "policy.read", orgId);
    const oid = assertIdentifier(orgId, "orgId");
    // Bounded + batched (T-193/M7): one domain-rules query for the page.
    const bounded = Math.min(Math.max(Math.floor(limit), 1), 500);
    const rows = (await this.repos.policies.listPoliciesForOrg(oid)).slice(0, bounded);
    const ruleRows =
      rows.length > 0 ? await this.repos.policies.listDomainRulesForPolicies(rows.map((r) => r.id)) : [];
    const byPolicy = new Map<string, { domain: string; action: RecipientDomainAction }[]>();
    for (const rule of ruleRows) {
      const list = byPolicy.get(rule.policy_id) ?? [];
      list.push({ domain: rule.domain, action: rule.action });
      byPolicy.set(rule.policy_id, list);
    }
    return rows.map((row) => ({
      id: row.id,
      enabled: row.enabled === 1,
      minTls: row.min_tls,
      externalRecipients: row.external_recipients,
      domainRules: byPolicy.get(row.id) ?? [],
    }));
  }

  /**
   * T-108 send-path entry point. Validates untrusted caller input, loads the
   * org's policies, and delegates to the pure evaluateOutboundForOrg core.
   * Requires `policy.read` on the org; allowed AND denied checks are audited.
   */
  async evaluateOutbound(
    actor: Actor,
    orgId: string,
    raw: { sender: unknown; recipients: unknown; tlsVersion: unknown },
  ): Promise<OutboundEvaluation> {
    return this.ctx.auditWrap(
      actor,
      orgId,
      "policy.evaluate_outbound",
      orgId,
      async () => {
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
        const rows = await this.repos.policies.listPoliciesForOrg(oid);
        const definitions: PolicyDefinition[] = [];
        for (const row of rows) {
          definitions.push({
            id: row.id,
            enabled: row.enabled === 1,
            minTls: row.min_tls,
            externalRecipients: row.external_recipients,
            domainRules: await this.repos.policies.listDomainRules(row.id),
          });
        }
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
