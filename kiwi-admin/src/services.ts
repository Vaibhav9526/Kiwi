/**
 * ServiceContainer — composition root wiring repositories + services.
 *
 * TWO dialects, ONE service layer. The dialect is chosen by DATABASE_URL:
 * present -> PostgreSQL (ADR-006, the compose configuration), absent -> SQLite
 * (ADR-003, the local-first runtime). `db/interfaces.ts` declares repository
 * methods as `MaybePromise<T>` and this layer awaits them, so there is a single
 * implementation of every service and every route for both drivers.
 *
 * Every mutating/scoped operation takes an Actor, checks RBAC first, and
 * records an audit entry (allowed or denied) — SECURITY.md rule 11.
 */
import { openSqlite, migrateSqlite } from "./db/sqlite.js";
import { openPg, migratePg } from "./db/pg.js";
import type { Db, MaybePromise } from "./db/interfaces.js";
import {
  DrizzleOrgRepository,
  DrizzlePolicyRuleRepository,
  DrizzleMailflowRepository,
  DrizzleAuditRepository,
} from "./db/repositories.js";
import {
  PgOrgRepository,
  PgPolicyRuleRepository,
  PgMailflowRepository,
  PgAuditRepository,
} from "./db/repositories.pg.js";
import type { OrgRepository, PolicyRuleRepository, MailflowRepository, AuditRepository } from "./db/interfaces.js";
import { AuthorizationDeniedError, requirePermission } from "./rbac/rbac.js";
import type { Actor, Permission } from "./rbac/rbac.js";
import { OrgService, PolicyService } from "./policy/services.js";
import { MailflowService, AuditService } from "./mailflow/services.js";
import type { AuditOutcome } from "./audit/model.js";

export { OrgService, PolicyService, MailflowService, AuditService };

/** The driver this container opened. */
export type Dialect = "sqlite" | "postgres";

export interface ServiceContainer {
  readonly dialect: Dialect;
  /**
   * Synchronous SQL facade, for tests and dialect introspection. SQLite only:
   * node-postgres has no synchronous query path, so this is null on Postgres.
   */
  readonly db: Db | null;
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
  ): Promise<{ seq: number; entry_hash: string }>;
  auditWrap<T>(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    work: () => MaybePromise<T>,
    permission?: Permission,
  ): Promise<T>;
  close(): Promise<void>;
}

interface Repositories {
  orgs: OrgRepository;
  policies: PolicyRuleRepository;
  mailflow: MailflowRepository;
  audit: AuditRepository;
}

/** Everything that differs between the two drivers. */
interface Wiring {
  dialect: Dialect;
  repos: Repositories;
  db: Db | null;
  close(): Promise<void> | void;
}

class KiwiServiceContainer implements ServiceContainer {
  readonly dialect: Dialect;
  readonly db: Db | null;
  readonly orgs: OrgService;
  readonly policies: PolicyService;
  readonly mailflow: MailflowService;
  readonly audit: AuditService;
  private readonly wiring: Wiring;

  constructor(wiring: Wiring) {
    this.wiring = wiring;
    this.dialect = wiring.dialect;
    this.db = wiring.db;
    this.audit = new AuditService({ audit: wiring.repos.audit });
    this.orgs = new OrgService({ orgs: wiring.repos.orgs }, this);
    this.policies = new PolicyService({ policies: wiring.repos.policies, orgs: wiring.repos.orgs }, this);
    this.mailflow = new MailflowService({ mailflow: wiring.repos.mailflow }, this);
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
  ): Promise<{ seq: number; entry_hash: string }> {
    return this.audit.append(
      { actor: { subject: actor.subject, roles: actor.roles }, orgId, action, resource, outcome, requestId, details },
      ts,
    );
  }

  async auditWrap<T>(
    actor: Actor,
    orgId: string | null,
    action: string,
    resource: string | null,
    work: () => MaybePromise<T>,
    permission: Permission = "org.read",
  ): Promise<T> {
    try {
      requirePermission(actor, permission, orgId);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        await this.auditAppend(actor, orgId, action, resource, "denied", null, { permission }, Date.now());
      }
      throw err;
    }
    // Error outcome (T-193/M3): a `work()` throw previously propagated with
    // no trace, so a half-applied mutation was invisible. The `error` row
    // records it; the original error still propagates to the caller.
    // (The append itself is best-effort here — it must never mask `err`.)
    try {
      const result = await work();
      await this.auditAppend(actor, orgId, action, resource, "allowed", null, {}, Date.now());
      return result;
    } catch (err) {
      try {
        await this.auditAppend(actor, orgId, action, resource, "error", null, {}, Date.now());
      } catch {
        // fall through to the original error below
      }
      throw err;
    }
  }

  async close(): Promise<void> {
    await this.wiring.close();
  }
}

/** Opens the container on SQLite (local-first runtime, ADR-003). */
export function createSqliteServiceContainer(dbPath = "kiwi-admin.db"): ServiceContainer {
  const conn = openSqlite(dbPath);
  migrateSqlite(conn.db);
  return new KiwiServiceContainer({
    dialect: "sqlite",
    db: conn.facade,
    repos: {
      orgs: new DrizzleOrgRepository(conn.db),
      policies: new DrizzlePolicyRuleRepository(conn.db),
      mailflow: new DrizzleMailflowRepository(conn.db),
      audit: new DrizzleAuditRepository(conn.db),
    },
    close: () => conn.raw.close(),
  });
}

/**
 * Opens the container on PostgreSQL (ADR-006) and applies pending Drizzle
 * migrations before anything is served. The connection string is always
 * caller-supplied (env `DATABASE_URL`) — never hardcoded, never logged.
 */
export async function createPgServiceContainer(databaseUrl: string): Promise<ServiceContainer> {
  const conn = openPg(databaseUrl);
  try {
    await migratePg(conn.db);
  } catch (err) {
    // Do not leak a half-open pool when the schema could not be brought up.
    await conn.pool.end();
    throw err;
  }
  return new KiwiServiceContainer({
    dialect: "postgres",
    db: null,
    repos: {
      orgs: new PgOrgRepository(conn.db),
      policies: new PgPolicyRuleRepository(conn.db),
      mailflow: new PgMailflowRepository(conn.db),
      audit: new PgAuditRepository(conn.db),
    },
    close: () => conn.pool.end(),
  });
}

/**
 * The `| undefined` on both fields is deliberate, not redundant: `tsconfig`
 * sets `exactOptionalPropertyTypes`, under which an ABSENT property and one
 * explicitly set to `undefined` are different types. Callers forward these
 * from their own optional parameters (`startServer({ dbPath: opts.dbPath })`),
 * and forwarding means passing `undefined` explicitly — which is exactly what
 * "follow the environment" means here. Removing it breaks `npm run typecheck`.
 */
export interface ServiceContainerOptions {
  /** SQLite file path. Ignored when the Postgres dialect is selected. */
  dbPath?: string | undefined;
  /**
   * Explicit dialect override. `null` forces SQLite; omitted (or `undefined`)
   * follows the environment. Compose sets DATABASE_URL, so the containerized
   * service is Postgres-backed; a bare dev shell has no DATABASE_URL and stays
   * on SQLite.
   */
  databaseUrl?: string | null | undefined;
}

/**
 * The one entry point. Pass a string for an explicit SQLite file (the form the
 * tests use — an explicit path is a dialect decision, so it never consults the
 * environment), or an options object to let DATABASE_URL choose.
 */
export async function createServiceContainer(options: ServiceContainerOptions | string = {}): Promise<ServiceContainer> {
  if (typeof options === "string") return createSqliteServiceContainer(options);
  const url =
    options.databaseUrl === undefined ? (process.env["DATABASE_URL"] ?? "").trim() : (options.databaseUrl ?? "").trim();
  return url ? createPgServiceContainer(url) : createSqliteServiceContainer(options.dbPath ?? "kiwi-admin.db");
}
