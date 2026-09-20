/**
 * Repository interfaces (ADR-003: Postgres can substitute SQLite later, so
 * all persistence goes through these interfaces, never raw SQL at call sites).
 */
import type { OrgRole, RecipientDomainAction, ExternalRecipientBehavior } from "../types.js";
import type { MailflowEvent, MailflowIngest } from "../mailflow/model.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";

/**
 * A value that may arrive synchronously or as a Promise.
 *
 * This is the ONE place the sync/async split is expressed. better-sqlite3
 * resolves synchronously; node-postgres cannot (see AsyncInterface below).
 * Repository methods return this union and the service layer awaits them —
 * `await` on a non-Promise is a no-op, so a single service implementation
 * serves both dialects. The pure cores (policy evaluator, audit chain,
 * validation, RBAC) stay synchronous; nothing else gained async.
 */
export type MaybePromise<T> = T | Promise<T>;

export interface OrgRepository {
  createOrg(id: string, name: string, now: number): MaybePromise<{ id: string; name: string; created_at: number }>;
  getOrg(id: string): MaybePromise<{ id: string; name: string; created_at: number } | undefined>;
  addDomain(orgId: string, domain: string, now: number): MaybePromise<{ org_id: string; domain: string; verified: number; created_at: number }>;
  listDomains(orgId: string): MaybePromise<{ domain: string; verified: number }[]>;
  createUser(id: string, orgId: string, email: string, now: number): MaybePromise<{ id: string; org_id: string; email: string; created_at: number }>;
  getUser(id: string): MaybePromise<{ id: string; org_id: string; email: string; created_at: number } | undefined>;
  /** Users of an org, ordered by email (T-134 admin UI listing). */
  listUsers(orgId: string): MaybePromise<{ id: string; org_id: string; email: string; created_at: number }[]>;
  grantRole(userId: string, orgId: string, role: OrgRole, now: number): MaybePromise<void>;
  listRoles(userId: string): MaybePromise<OrgRole[]>;
  /** Batched role lookup for a user page (T-193/M7): one query, not N. */
  listRolesForUsers(userIds: string[]): MaybePromise<{ user_id: string; role: OrgRole }[]>;
  createDevice(id: string, orgId: string, label: string, now: number): MaybePromise<{ id: string; org_id: string; label: string; revoked: number; created_at: number }>;
  getDevice(id: string): MaybePromise<{ id: string; org_id: string; label: string; revoked: number; created_at: number } | undefined>;
  revokeDevice(id: string, now: number): MaybePromise<void>;
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
  ): MaybePromise<void>;
  getPolicy(id: string): MaybePromise<{
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  } | undefined>;
  addDomainRule(policyId: string, domain: string, action: RecipientDomainAction): MaybePromise<void>;
  listDomainRules(policyId: string): MaybePromise<{ domain: string; action: RecipientDomainAction }[]>;
  /** Batched domain-rule lookup for a policy page (T-193/M7). */
  listDomainRulesForPolicies(policyIds: string[]): MaybePromise<{ policy_id: string; domain: string; action: RecipientDomainAction }[]>;
  /**
   * Atomic policy + rules insert (T-193/M3): the whole set commits or
   * nothing does — callers pre-validate, the transaction guarantees it.
   */
  createPolicyWithRules(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
    rules: { domain: string; action: RecipientDomainAction }[],
  ): MaybePromise<void>;
  /** All policies of an org (T-108 send-path bridge evaluates the enabled ones). */
  listPoliciesForOrg(orgId: string): MaybePromise<{
    id: string;
    org_id: string;
    name: string;
    enabled: number;
    min_tls: string | null;
    external_recipients: ExternalRecipientBehavior;
  }[]>;
}

export interface MailflowRepository {
  ingest(event: MailflowIngest): MaybePromise<{ id: string }>;
  query(filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number }): MaybePromise<MailflowEvent[]>;
}

export interface AuditRepository {
  append(input: AuditEventInput, prevHash: string, entryHash: string, seq: number, ts: number): MaybePromise<AuditRecord>;
  readAt(seq: number): MaybePromise<AuditRecord | undefined>;
  last(): MaybePromise<AuditRecord | undefined>;
  /**
   * Rows in `[since, until]` ordered by seq ascending, capped at `limit`.
   *
   * `orgId` narrows to one org's entries. Omit it (or pass null) for the FULL
   * chain — `AuditService.verify` depends on that, because a hash chain can
   * only be validated over every row. Filtering must happen in the query, not
   * after it: a post-filter would let `limit` silently truncate a window and
   * break the contiguity property verify() relies on.
   */
  range(since: number, until: number, limit: number, orgId?: string | null): MaybePromise<AuditRecord[]>;
}

/** Supertype over the concrete driver (see db/sqlite.ts). */
export type SqlParam = null | number | bigint | string | boolean;

export interface Db {
  exec(sql: string): void;
  run(sql: string, ...params: SqlParam[]): void;
  one(sql: string, ...params: SqlParam[]): unknown;
  all(sql: string, ...params: SqlParam[]): unknown[];
}

/**
 * Fully-async mirror of a repository interface, for the PostgreSQL runtime
 * (node-postgres is inherently async). Same method names, same shapes — every
 * method returns a Promise. The interfaces above declare `MaybePromise<T>`, so
 * an `AsyncInterface<T>` implementation is also a valid `T`; this alias stays
 * as the explicit statement of intent for the PG repositories.
 */
export type AsyncInterface<T> = {
  [K in keyof T]: T[K] extends (...args: infer A) => infer R ? (...args: A) => Promise<Awaited<R>> : never;
};
