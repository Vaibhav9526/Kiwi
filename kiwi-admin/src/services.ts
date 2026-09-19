/**
 * ServiceContainer — composition root wiring repositories + services over
 * one SQLite file (ADR-003). Every mutating/scoped operation takes an Actor,
 * checks RBAC first, and records an audit entry (allowed or denied) —
 * SECURITY.md rule 11.
 */
import { openDb } from "./db/driver.js";
import type { Db } from "./db/interfaces.js";
import { ensureMigrated } from "./db/migrations.js";
import { SqliteOrgRepository, SqlitePolicyRuleRepository } from "./db/sqlite-org.js";
import { SqliteMailflowRepository, SqliteAuditRepository } from "./db/sqlite-mailflow.js";
import type { OrgRepository, PolicyRuleRepository, MailflowRepository, AuditRepository } from "./db/interfaces.js";
import { AuthorizationDeniedError, requirePermission } from "./rbac/rbac.js";
import type { Actor, Permission } from "./rbac/rbac.js";
import { OrgService, PolicyService } from "./policy/services.js";
import { MailflowService, AuditService } from "./mailflow/services.js";
import type { AuditOutcome } from "./audit/model.js";

export { OrgService, PolicyService, MailflowService, AuditService };

export interface ServiceContainer {
  readonly db: Db;
  readonly orgs: OrgService;
  readonly policies: PolicyService;
  readonly mailflow: MailflowService;
  readonly audit: AuditService;
  auditAppend(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    outcome: AuditOutcome,
    requestId: string | null,
    details: Record<string, unknown>,
    ts: number,
  ): { seq: number; entry_hash: string };
  auditWrap<T>(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    work: () => T,
    permission?: Permission,
  ): T;
  close(): void;
}

class KiwiServiceContainer implements ServiceContainer {
  readonly db: Db;
  readonly orgs: OrgService;
  readonly policies: PolicyService;
  readonly mailflow: MailflowService;
  readonly audit: AuditService;
  private readonly auditRepo: AuditRepository;

  constructor(dbPath: string) {
    this.db = openDb(dbPath);
    ensureMigrated(this.db);
    const orgRepo: OrgRepository = new SqliteOrgRepository(this.db);
    const policyRepo: PolicyRuleRepository = new SqlitePolicyRuleRepository(this.db);
    const mailflowRepo: MailflowRepository = new SqliteMailflowRepository(this.db);
    this.auditRepo = new SqliteAuditRepository(this.db);
    this.audit = new AuditService({ audit: this.auditRepo });
    this.orgs = new OrgService({ orgs: orgRepo }, this);
    this.policies = new PolicyService({ policies: policyRepo }, this);
    this.mailflow = new MailflowService({ mailflow: mailflowRepo }, this);
  }

  auditAppend(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    outcome: AuditOutcome,
    requestId: string | null,
    details: Record<string, unknown>,
    ts: number,
  ): { seq: number; entry_hash: string } {
    return this.audit.append(
      { actor: { subject: actor.subject, roles: actor.roles }, orgId, action, resource, outcome, requestId, details },
      ts,
    );
  }

  auditWrap<T>(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    work: () => T,
    permission: Permission = "org.read",
  ): T {
    try {
      requirePermission(actor, permission, orgId);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        this.auditAppend(actor, orgId, action, resource, "denied", null, { permission }, Date.now());
      }
      throw err;
    }
    const result = work();
    this.auditAppend(actor, orgId, action, resource, "allowed", null, {}, Date.now());
    return result;
  }

  close(): void {
    (this.db as unknown as { close?: () => void }).close?.();
  }
}

export function createServiceContainer(dbPath: string): ServiceContainer {
  return new KiwiServiceContainer(dbPath);
}
