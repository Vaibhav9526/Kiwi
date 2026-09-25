/**
 * PostgreSQL Drizzle repositories — async mirrors of `db/interfaces.ts`
 * (node-postgres is inherently async; see AsyncInterface). Same method names
 * and return shapes; PG-native booleans are mapped to the interface's 0/1
 * numbers at the boundary. Exercised live when DATABASE_URL is set (Agent 6
 * T-131 compose); otherwise covered by artifact + shape tests.
 */
import { and, asc, desc, eq, gte, inArray, lte, sql } from "drizzle-orm";
import * as p from "./schema.pg.js";
import type { PgDrizzle } from "./pg.js";
import type {
  AsyncInterface,
  AuditRepository,
  MailflowRepository,
  OrgRepository,
  PolicyRuleRepository,
} from "./interfaces.js";
import type { ExternalRecipientBehavior, OrgRole, RecipientDomainAction } from "../types.js";
import type { MailflowIngest, MailflowEvent } from "../mailflow/model.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";
import { canonicalEventJson, computeEntryHash } from "../audit/chain.js";
import { ConflictError } from "../util/validate.js";

/**
 * Escape a caller-supplied value for LIKE (T-193/L1) — see the SQLite
 * mirror for the rationale. Paired with an explicit `ESCAPE '\'` clause.
 */
export function escapeLikePattern(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

/**
 * True for Postgres unique-violation failures (SQLSTATE 23505).
 *
 * Drizzle wraps the driver failure in a `DrizzleQueryError` whose own
 * message is only "Failed query: ..." — the SQLSTATE and the
 * "duplicate key" text live on `cause`. A previous revision inspected only
 * the wrapper, so every duplicate email on Postgres surfaced as a 500 with
 * a correlation id instead of the contracted 409 `conflict` (T-193/M5).
 */
export function isUniqueViolation(err: unknown): boolean {
  let cur: unknown = err;
  for (let depth = 0; cur !== null && typeof cur === "object" && depth < 3; depth++) {
    const code = (cur as { code?: unknown }).code;
    if (code === "23505") return true;
    if (cur instanceof Error && /duplicate key value/i.test(cur.message)) return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
}

const bit = (b: boolean): number => (b ? 1 : 0);

export class PgOrgRepository implements AsyncInterface<OrgRepository> {
  constructor(private readonly db: PgDrizzle) {}

  async createOrg(id: string, name: string, now: number): Promise<{ id: string; name: string; created_at: number }> {
    await this.db.insert(p.orgs).values({ id, name, createdAt: now });
    return { id, name, created_at: now };
  }

  async getOrg(id: string): Promise<{ id: string; name: string; created_at: number } | undefined> {
    const rows = await this.db.select().from(p.orgs).where(eq(p.orgs.id, id)).limit(1);
    const row = rows[0];
    return row ? { id: row.id, name: row.name, created_at: row.createdAt } : undefined;
  }

  async addDomain(
    orgId: string,
    domain: string,
    now: number,
  ): Promise<{ org_id: string; domain: string; verified: number; created_at: number }> {
    await this.db.insert(p.domains).values({ orgId, domain, verified: false, createdAt: now }).onConflictDoNothing();
    return { org_id: orgId, domain, verified: 0, created_at: now };
  }

  async listDomains(orgId: string): Promise<{ domain: string; verified: number }[]> {
    const rows = await this.db
      .select({ domain: p.domains.domain, verified: p.domains.verified })
      .from(p.domains)
      .where(eq(p.domains.orgId, orgId))
      .orderBy(p.domains.domain);
    return rows.map((r) => ({ domain: r.domain, verified: bit(r.verified) }));
  }

  async createUser(
    id: string,
    orgId: string,
    email: string,
    now: number,
  ): Promise<{ id: string; org_id: string; email: string; created_at: number }> {
    // Duplicate email → typed 409 (T-193/M5), mirroring the SQLite side.
    try {
      await this.db.insert(p.users).values({ id, orgId, email, createdAt: now });
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError("email", "address already registered in this org");
      throw err;
    }
    return { id, org_id: orgId, email, created_at: now };
  }

  async getUser(id: string): Promise<{ id: string; org_id: string; email: string; created_at: number } | undefined> {
    const rows = await this.db.select().from(p.users).where(eq(p.users.id, id)).limit(1);
    const row = rows[0];
    return row ? { id: row.id, org_id: row.orgId, email: row.email, created_at: row.createdAt } : undefined;
  }

  async listUsers(orgId: string): Promise<{ id: string; org_id: string; email: string; created_at: number }[]> {
    const rows = await this.db.select().from(p.users).where(eq(p.users.orgId, orgId)).orderBy(p.users.email);
    return rows.map((row) => ({ id: row.id, org_id: row.orgId, email: row.email, created_at: row.createdAt }));
  }

  async grantRole(userId: string, orgId: string, role: OrgRole, now: number): Promise<void> {
    await this.db
      .insert(p.userOrgRoles)
      .values({ userId, orgId, role, grantedAt: now })
      .onConflictDoUpdate({
        target: [p.userOrgRoles.userId, p.userOrgRoles.orgId],
        set: { role, grantedAt: now },
      });
  }

  async listRoles(userId: string): Promise<OrgRole[]> {
    const rows = await this.db
      .select({ role: p.userOrgRoles.role })
      .from(p.userOrgRoles)
      .where(eq(p.userOrgRoles.userId, userId));
    return rows.map((r) => r.role as OrgRole);
  }

  async listRolesForUsers(userIds: string[]): Promise<{ user_id: string; role: OrgRole }[]> {
    if (userIds.length === 0) return [];
    const rows = await this.db
      .select({ user_id: p.userOrgRoles.userId, role: p.userOrgRoles.role })
      .from(p.userOrgRoles)
      .where(inArray(p.userOrgRoles.userId, userIds));
    return rows.map((r) => ({ user_id: r.user_id, role: r.role as OrgRole }));
  }

  async createDevice(
    id: string,
    orgId: string,
    label: string,
    now: number,
  ): Promise<{ id: string; org_id: string; label: string; revoked: number; created_at: number }> {
    await this.db.insert(p.devices).values({ id, orgId, label, revoked: false, createdAt: now });
    return { id, org_id: orgId, label, revoked: 0, created_at: now };
  }

  async getDevice(
    id: string,
  ): Promise<{ id: string; org_id: string; label: string; revoked: number; created_at: number } | undefined> {
    const rows = await this.db.select().from(p.devices).where(eq(p.devices.id, id)).limit(1);
    const row = rows[0];
    return row
      ? { id: row.id, org_id: row.orgId, label: row.label, revoked: bit(row.revoked), created_at: row.createdAt }
      : undefined;
  }

  async listDevices(
    orgId: string,
    limit: number,
  ): Promise<{ id: string; org_id: string; label: string; revoked: number; revoked_at: number | null; created_at: number }[]> {
    const rows = await this.db
      .select()
      .from(p.devices)
      .where(eq(p.devices.orgId, orgId))
      .orderBy(asc(p.devices.createdAt), asc(p.devices.id))
      .limit(limit);
    return rows.map((row) => ({
      id: row.id,
      org_id: row.orgId,
      label: row.label,
      revoked: bit(row.revoked),
      revoked_at: row.revokedAt,
      created_at: row.createdAt,
    }));
  }

  async revokeDevice(id: string, now: number): Promise<void> {
    await this.db.update(p.devices).set({ revoked: true, revokedAt: now }).where(eq(p.devices.id, id));
  }
}

export class PgPolicyRuleRepository implements AsyncInterface<PolicyRuleRepository> {
  constructor(private readonly db: PgDrizzle) {}

  async createPolicy(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
  ): Promise<void> {
    await this.db
      .insert(p.policies)
      .values({ id, orgId, name, enabled, minTls, externalRecipients, createdAt: now, updatedAt: now });
  }

  async getPolicy(id: string): Promise<{
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  } | undefined> {
    const rows = await this.db.select().from(p.policies).where(eq(p.policies.id, id)).limit(1);
    const row = rows[0];
    return row
      ? {
          id: row.id,
          org_id: row.orgId,
          name: row.name,
          enabled: bit(row.enabled),
          min_tls: row.minTls,
          external_recipients: row.externalRecipients as ExternalRecipientBehavior,
        }
      : undefined;
  }

  async addDomainRule(policyId: string, domain: string, action: RecipientDomainAction): Promise<void> {
    await this.db
      .insert(p.policyDomainRules)
      .values({ policyId, domain, action })
      .onConflictDoUpdate({
        target: [p.policyDomainRules.policyId, p.policyDomainRules.domain],
        set: { action },
      });
  }

  async listDomainRules(policyId: string): Promise<{ domain: string; action: RecipientDomainAction }[]> {
    const rows = await this.db
      .select({ domain: p.policyDomainRules.domain, action: p.policyDomainRules.action })
      .from(p.policyDomainRules)
      .where(eq(p.policyDomainRules.policyId, policyId))
      .orderBy(p.policyDomainRules.domain);
    return rows.map((r) => ({ domain: r.domain, action: r.action as RecipientDomainAction }));
  }

  async listDomainRulesForPolicies(
    policyIds: string[],
  ): Promise<{ policy_id: string; domain: string; action: RecipientDomainAction }[]> {
    if (policyIds.length === 0) return [];
    const rows = await this.db
      .select({
        policy_id: p.policyDomainRules.policyId,
        domain: p.policyDomainRules.domain,
        action: p.policyDomainRules.action,
      })
      .from(p.policyDomainRules)
      .where(inArray(p.policyDomainRules.policyId, policyIds))
      .orderBy(p.policyDomainRules.domain);
    return rows.map((r) => ({
      policy_id: r.policy_id,
      domain: r.domain,
      action: r.action as RecipientDomainAction,
    }));
  }

  async createPolicyWithRules(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
    rules: { domain: string; action: RecipientDomainAction }[],
  ): Promise<void> {
    // One transaction (T-193/M3), mirroring the SQLite side.
    await this.db.transaction(async (tx) => {
      await tx
        .insert(p.policies)
        .values({ id, orgId, name, enabled, minTls, externalRecipients, createdAt: now, updatedAt: now });
      for (const rule of rules) {
        await tx.insert(p.policyDomainRules).values({ policyId: id, domain: rule.domain, action: rule.action });
      }
    });
  }

  async listPoliciesForOrg(orgId: string): Promise<{
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  }[]> {
    const rows = await this.db.select().from(p.policies).where(eq(p.policies.orgId, orgId)).orderBy(p.policies.id);
    return rows.map((row) => ({
      id: row.id,
      org_id: row.orgId,
      name: row.name,
      enabled: bit(row.enabled),
      min_tls: row.minTls,
      external_recipients: row.externalRecipients as ExternalRecipientBehavior,
    }));
  }
}

export class PgMailflowRepository implements AsyncInterface<MailflowRepository> {
  constructor(private readonly db: PgDrizzle) {}

  async ingest(event: MailflowIngest): Promise<{ id: string }> {
    await this.db.insert(p.mailflowEvents).values({
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
    });
    return { id: event.id };
  }

  async query(filter: {
    orgId?: string;
    recipientDomain?: string;
    sinceTs?: number;
    untilTs?: number;
    limit: number;
  }): Promise<MailflowEvent[]> {
    const conditions = [];
    if (filter.orgId) conditions.push(eq(p.mailflowEvents.orgId, filter.orgId));
    if (filter.recipientDomain) conditions.push(sql`${p.mailflowEvents.recipient} LIKE ${`%@${escapeLikePattern(filter.recipientDomain)}`} ESCAPE '\\'`);
    if (typeof filter.sinceTs === "number") conditions.push(gte(p.mailflowEvents.ts, filter.sinceTs));
    if (typeof filter.untilTs === "number") conditions.push(lte(p.mailflowEvents.ts, filter.untilTs));
    const rows = await this.db
      .select()
      .from(p.mailflowEvents)
      .where(conditions.length ? and(...conditions) : undefined)
      .orderBy(desc(p.mailflowEvents.ts), desc(p.mailflowEvents.id))
      .limit(Math.min(filter.limit, 1000));
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

export class PgAuditRepository implements AsyncInterface<AuditRepository> {
  constructor(private readonly db: PgDrizzle) {}

  async appendChained(input: AuditEventInput, ts: number): Promise<AuditRecord> {
    // Atomic chained append (T-193/H6): the tail read, `seq` assignment,
    // hash computation, and insert all happen INSIDE one transaction behind
    // a transaction-scoped advisory lock. A previous revision read the tail
    // in the service layer and only locked the insert, so two processes
    // could still compute the same `seq` and collide on the primary key —
    // the lock serializes nothing unless the read it protects is inside it.
    // Gapless by construction (a nextval/serial sequence would leave holes
    // on rollback and break the contiguity `verify()` relies on); the lock
    // releases with the transaction, so a crashed holder cannot wedge the log.
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('kiwi_audit_seq'))`);
      const lastRows = await tx.select().from(p.auditLog).orderBy(desc(p.auditLog.seq)).limit(1);
      const last = lastRows[0];
      const prevHash = last?.entryHash ?? "genesis";
      const seq = (last?.seq ?? 0) + 1;
      const entryHash = computeEntryHash(canonicalEventJson(input), prevHash);
      await tx.insert(p.auditLog).values({
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
      });
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
    });
  }

  async append(input: AuditEventInput, prevHash: string, entryHash: string, seq: number, ts: number): Promise<AuditRecord> {
    // Low-level primitive for tests that hand-construct chains (explicit
    // seq). Production appends go through appendChained above — calling this
    // with a client-computed `seq` under concurrency reintroduces H6.
    await this.db.insert(p.auditLog).values({
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
    });
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

  async readAt(seq: number): Promise<AuditRecord | undefined> {
    const rows = await this.db.select().from(p.auditLog).where(eq(p.auditLog.seq, seq)).limit(1);
    const row = rows[0];
    return row ? toAuditRecord(row) : undefined;
  }

  async last(): Promise<AuditRecord | undefined> {
    const rows = await this.db.select().from(p.auditLog).orderBy(desc(p.auditLog.seq)).limit(1);
    const row = rows[0];
    return row ? toAuditRecord(row) : undefined;
  }

  async range(since: number, until: number, limit: number, orgId?: string | null): Promise<AuditRecord[]> {
    // Org filtering happens in SQL, not after the fact — see the interface
    // note: a post-filter would let `limit` truncate the window first.
    const conditions = [gte(p.auditLog.ts, since), lte(p.auditLog.ts, until)];
    if (orgId) conditions.push(eq(p.auditLog.orgId, orgId));
    const rows = await this.db
      .select()
      .from(p.auditLog)
      .where(and(...conditions))
      .orderBy(asc(p.auditLog.seq))
      .limit(limit);
    return rows.map(toAuditRecord);
  }
}

type PgAuditRow = typeof p.auditLog.$inferSelect;

function toAuditRecord(r: PgAuditRow): AuditRecord {
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
