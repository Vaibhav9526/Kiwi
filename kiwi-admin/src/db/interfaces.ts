/**
 * Repository interfaces (ADR-003: Postgres can substitute SQLite later, so
 * all persistence goes through these interfaces, never raw SQL at call sites).
 */
import type { OrgRole, RecipientDomainAction, ExternalRecipientBehavior } from "../types.js";
import type { MailflowEvent, MailflowIngest } from "../mailflow/model.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";

export interface OrgRepository {
  createOrg(id: string, name: string, now: number): { id: string; name: string; created_at: number };
  getOrg(id: string): { id: string; name: string; created_at: number } | undefined;
  addDomain(orgId: string, domain: string, now: number): { org_id: string; domain: string; verified: number; created_at: number };
  listDomains(orgId: string): { domain: string; verified: number }[];
  createUser(id: string, orgId: string, email: string, now: number): { id: string; org_id: string; email: string; created_at: number };
  getUser(id: string): { id: string; org_id: string; email: string; created_at: number } | undefined;
  grantRole(userId: string, orgId: string, role: OrgRole, now: number): void;
  listRoles(userId: string): OrgRole[];
  createDevice(id: string, orgId: string, label: string, now: number): { id: string; org_id: string; label: string; revoked: number; created_at: number };
  getDevice(id: string): { id: string; org_id: string; label: string; revoked: number; created_at: number } | undefined;
  revokeDevice(id: string, now: number): void;
}

export interface PolicyRuleRepository {
  createPolicy(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
  ): void;
  getPolicy(id: string): {
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  } | undefined;
  addDomainRule(policyId: string, domain: string, action: RecipientDomainAction): void;
  listDomainRules(policyId: string): { domain: string; action: RecipientDomainAction }[];
  /** All policies of an org (T-108 send-path bridge evaluates the enabled ones). */
  listPoliciesForOrg(orgId: string): {
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  }[];
}

export interface MailflowRepository {
  ingest(event: MailflowIngest): { id: string };
  query(filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number }): MailflowEvent[];
}

export interface AuditRepository {
  append(input: AuditEventInput, prevHash: string, entryHash: string, seq: number, ts: number): AuditRecord;
  readAt(seq: number): AuditRecord | undefined;
  last(): AuditRecord | undefined;
  range(since: number, until: number, limit: number): AuditRecord[];
}

/** Supertype over the concrete driver (see db/driver.ts). */
export type SqlParam = null | number | bigint | string | boolean;

export interface Db {
  exec(sql: string): void;
  run(sql: string, ...params: SqlParam[]): void;
  one(sql: string, ...params: SqlParam[]): unknown;
  all(sql: string, ...params: SqlParam[]): unknown[];
}
