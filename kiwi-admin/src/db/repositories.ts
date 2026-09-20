/**
 * SQLite Drizzle repositories — implement `db/interfaces.ts` with the Drizzle
 * query builder. Return shapes are IDENTICAL to the retired raw-SQL layer
 * (callers/services/tests unchanged). Boolean-ish columns stay 0/1 integers.
 */
import { and, asc, desc, eq, gte, like, lte } from "drizzle-orm";
import * as s from "./schema.sqlite.js";
import type { SqliteDrizzle } from "./sqlite.js";
import type {
  AuditRepository,
  MailflowRepository,
  OrgRepository,
  PolicyRuleRepository,
} from "./interfaces.js";
import type { ExternalRecipientBehavior, OrgRole, RecipientDomainAction } from "../types.js";
import type { MailflowIngest } from "../mailflow/model.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";

export class DrizzleOrgRepository implements OrgRepository {
  constructor(private readonly db: SqliteDrizzle) {}

  createOrg(id: string, name: string, now: number): { id: string; name: string; created_at: number } {
    this.db.insert(s.orgs).values({ id, name, createdAt: now }).run();
    return { id, name, created_at: now };
  }

  getOrg(id: string): { id: string; name: string; created_at: number } | undefined {
    const row = this.db.select().from(s.orgs).where(eq(s.orgs.id, id)).get();
    return row ? { id: row.id, name: row.name, created_at: row.createdAt } : undefined;
  }

  addDomain(
    orgId: string,
    domain: string,
    now: number,
  ): { org_id: string; domain: string; verified: number; created_at: number } {
    this.db.insert(s.domains).values({ orgId, domain, verified: 0, createdAt: now }).onConflictDoNothing().run();
    return { org_id: orgId, domain, verified: 0, created_at: now };
  }

  listDomains(orgId: string): { domain: string; verified: number }[] {
    return this.db
      .select({ domain: s.domains.domain, verified: s.domains.verified })
      .from(s.domains)
      .where(eq(s.domains.orgId, orgId))
      .orderBy(s.domains.domain)
      .all();
  }

  createUser(
    id: string,
    orgId: string,
    email: string,
    now: number,
  ): { id: string; org_id: string; email: string; created_at: number } {
    this.db.insert(s.users).values({ id, orgId, email, createdAt: now }).run();
    return { id, org_id: orgId, email, created_at: now };
  }

  getUser(id: string): { id: string; org_id: string; email: string; created_at: number } | undefined {
    const row = this.db.select().from(s.users).where(eq(s.users.id, id)).get();
    return row ? { id: row.id, org_id: row.orgId, email: row.email, created_at: row.createdAt } : undefined;
  }

  listUsers(orgId: string): { id: string; org_id: string; email: string; created_at: number }[] {
    return this.db
      .select()
      .from(s.users)
      .where(eq(s.users.orgId, orgId))
      .orderBy(s.users.email)
      .all()
      .map((row) => ({ id: row.id, org_id: row.orgId, email: row.email, created_at: row.createdAt }));
  }

  grantRole(userId: string, orgId: string, role: OrgRole, now: number): void {
    this.db
      .insert(s.userOrgRoles)
      .values({ userId, orgId, role, grantedAt: now })
      .onConflictDoUpdate({
        target: [s.userOrgRoles.userId, s.userOrgRoles.orgId],
        set: { role, grantedAt: now },
      })
      .run();
  }

  listRoles(userId: string): OrgRole[] {
    return this.db
      .select({ role: s.userOrgRoles.role })
      .from(s.userOrgRoles)
      .where(eq(s.userOrgRoles.userId, userId))
      .all()
      .map((r) => r.role as OrgRole);
  }

  createDevice(
    id: string,
    orgId: string,
    label: string,
    now: number,
  ): { id: string; org_id: string; label: string; revoked: number; created_at: number } {
    this.db.insert(s.devices).values({ id, orgId, label, revoked: 0, createdAt: now }).run();
    return { id, org_id: orgId, label, revoked: 0, created_at: now };
  }

  getDevice(
    id: string,
  ): { id: string; org_id: string; label: string; revoked: number; created_at: number } | undefined {
    const row = this.db.select().from(s.devices).where(eq(s.devices.id, id)).get();
    return row ? { id: row.id, org_id: row.orgId, label: row.label, revoked: row.revoked, created_at: row.createdAt } : undefined;
  }

  revokeDevice(id: string, now: number): void {
    this.db.update(s.devices).set({ revoked: 1, revokedAt: now }).where(eq(s.devices.id, id)).run();
  }
}

export class DrizzlePolicyRuleRepository implements PolicyRuleRepository {
  constructor(private readonly db: SqliteDrizzle) {}

  createPolicy(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
  ): void {
    this.db
      .insert(s.policies)
      .values({ id, orgId, name, enabled: enabled ? 1 : 0, minTls, externalRecipients, createdAt: now, updatedAt: now })
      .run();
  }

  getPolicy(id: string): {
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  } | undefined {
    const row = this.db.select().from(s.policies).where(eq(s.policies.id, id)).get();
    return row
      ? {
          id: row.id,
          org_id: row.orgId,
          name: row.name,
          enabled: row.enabled,
          min_tls: row.minTls,
          external_recipients: row.externalRecipients as ExternalRecipientBehavior,
        }
      : undefined;
  }

  addDomainRule(policyId: string, domain: string, action: RecipientDomainAction): void {
    this.db
      .insert(s.policyDomainRules)
      .values({ policyId, domain, action })
      .onConflictDoUpdate({
        target: [s.policyDomainRules.policyId, s.policyDomainRules.domain],
        set: { action },
      })
      .run();
  }

  listDomainRules(policyId: string): { domain: string; action: RecipientDomainAction }[] {
    return this.db
      .select({ domain: s.policyDomainRules.domain, action: s.policyDomainRules.action })
      .from(s.policyDomainRules)
      .where(eq(s.policyDomainRules.policyId, policyId))
      .orderBy(s.policyDomainRules.domain)
      .all()
      .map((r) => ({ domain: r.domain, action: r.action as RecipientDomainAction }));
  }

  listPoliciesForOrg(orgId: string): {
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  }[] {
    return this.db
      .select()
      .from(s.policies)
      .where(eq(s.policies.orgId, orgId))
      .orderBy(s.policies.id)
      .all()
      .map((row) => ({
        id: row.id,
        org_id: row.orgId,
        name: row.name,
        enabled: row.enabled,
        min_tls: row.minTls,
        external_recipients: row.externalRecipients as ExternalRecipientBehavior,
      }));
  }
}

export class DrizzleMailflowRepository implements MailflowRepository {
  constructor(private readonly db: SqliteDrizzle) {}

  ingest(event: MailflowIngest): { id: string } {
    this.db
      .insert(s.mailflowEvents)
      .values({
        id: event.id,
        orgId: event.orgId,
        direction: event.direction,
        sender: event.sender,
        recipient: event.recipient,
        ts: event.ts,
        messageId: event.messageId,
        tlsVersion: event.tlsVersion,
        securityStatus: event.securityStatus,
        policyVerdict: event.policyVerdict,
        receivedAt: Date.now(),
      })
      .run();
    return { id: event.id };
  }

  query(filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number }): {
    id: string;
    org_id: string | null;
    direction: "inbound" | "outbound";
    sender: string;
    recipient: string;
    ts: number;
    message_id: string | null;
    tls_version: string | null;
    security_status: string;
    policy_verdict: "allow" | "warn" | "block" | "unknown";
    received_at: number;
  }[] {
    const conditions = [];
    if (filter.orgId) conditions.push(eq(s.mailflowEvents.orgId, filter.orgId));
    if (filter.recipientDomain) conditions.push(like(s.mailflowEvents.recipient, `%@${filter.recipientDomain}`));
    if (typeof filter.sinceTs === "number") conditions.push(gte(s.mailflowEvents.ts, filter.sinceTs));
    if (typeof filter.untilTs === "number") conditions.push(lte(s.mailflowEvents.ts, filter.untilTs));
    const rows = this.db
      .select()
      .from(s.mailflowEvents)
      .where(conditions.length ? and(...conditions) : undefined)
      .orderBy(desc(s.mailflowEvents.ts), desc(s.mailflowEvents.id))
      .limit(Math.min(filter.limit, 1000))
      .all();
    return rows.map((r) => ({
      id: r.id,
      org_id: r.orgId,
      direction: r.direction as "inbound" | "outbound",
      sender: r.sender,
      recipient: r.recipient,
      ts: r.ts,
      message_id: r.messageId,
      tls_version: r.tlsVersion,
      security_status: r.securityStatus,
      policy_verdict: r.policyVerdict as "allow" | "warn" | "block" | "unknown",
      received_at: r.receivedAt,
    }));
  }
}

export class DrizzleAuditRepository implements AuditRepository {
  constructor(private readonly db: SqliteDrizzle) {}

  append(input: AuditEventInput, prevHash: string, entryHash: string, seq: number, ts: number): AuditRecord {
    this.db
      .insert(s.auditLog)
      .values({
        seq,
        ts,
        actorSubject: input.actor.subject,
        actorRoles: JSON.stringify(input.actor.roles),
        orgId: input.orgId,
        action: input.action,
        resource: input.resource,
        outcome: input.outcome,
        requestId: input.requestId,
        details: JSON.stringify(input.details),
        prevHash,
        entryHash,
      })
      .run();
    return {
      seq,
      ts,
      actor_subject: input.actor.subject,
      actor_roles: JSON.stringify(input.actor.roles),
      org_id: input.orgId,
      action: input.action,
      resource: input.resource,
      outcome: input.outcome,
      request_id: input.requestId,
      details: JSON.stringify(input.details),
      prev_hash: prevHash,
      entry_hash: entryHash,
    };
  }

  readAt(seq: number): AuditRecord | undefined {
    const row = this.db.select().from(s.auditLog).where(eq(s.auditLog.seq, seq)).get();
    return row ? toAuditRecord(row) : undefined;
  }

  last(): AuditRecord | undefined {
    const row = this.db.select().from(s.auditLog).orderBy(desc(s.auditLog.seq)).limit(1).get();
    return row ? toAuditRecord(row) : undefined;
  }

  range(since: number, until: number, limit: number, orgId?: string | null): AuditRecord[] {
    // Org filtering happens in SQL, not after the fact — see the interface
    // note: a post-filter would let `limit` truncate the window first.
    const conditions = [gte(s.auditLog.ts, since), lte(s.auditLog.ts, until)];
    if (orgId) conditions.push(eq(s.auditLog.orgId, orgId));
    return this.db
      .select()
      .from(s.auditLog)
      .where(and(...conditions))
      .orderBy(asc(s.auditLog.seq))
      .limit(limit)
      .all()
      .map(toAuditRecord);
  }
}

type AuditRow = typeof s.auditLog.$inferSelect;

function toAuditRecord(r: AuditRow): AuditRecord {
  return {
    seq: r.seq,
    ts: r.ts,
    actor_subject: r.actorSubject,
    actor_roles: r.actorRoles,
    org_id: r.orgId,
    action: r.action,
    resource: r.resource,
    outcome: r.outcome as AuditRecord["outcome"],
    request_id: r.requestId,
    details: r.details,
    prev_hash: r.prevHash,
    entry_hash: r.entryHash,
  };
}
