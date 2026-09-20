/**
 * T-130 migration tests: Drizzle Kit artifacts apply cleanly, are idempotent,
 * and carry the audit append-only guard in both dialects. PG live round-trip
 * runs only with DATABASE_URL (Agent 6 T-131 compose); otherwise PG is
 * covered by artifact assertions + compile-time interface conformance.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { openSqlite, migrateSqlite } from "../src/db/sqlite.js";
import { openPg, migratePg } from "../src/db/pg.js";
import {
  PgOrgRepository,
  PgPolicyRuleRepository,
  PgMailflowRepository,
  PgAuditRepository,
} from "../src/db/repositories.pg.js";
import type {
  AsyncInterface,
  AuditRepository,
  MailflowRepository,
  OrgRepository,
  PolicyRuleRepository,
} from "../src/db/interfaces.js";
import { makeTempDbPath } from "./helpers/db.js";

// Compile-time: PG repositories conform to the async mirror of the preserved
// sync interfaces. A drift breaks `npm run typecheck`, not production.
type _OrgConforms = PgOrgRepository extends AsyncInterface<OrgRepository> ? true : false;
type _PolicyConforms = PgPolicyRuleRepository extends AsyncInterface<PolicyRuleRepository> ? true : false;
type _MailflowConforms = PgMailflowRepository extends AsyncInterface<MailflowRepository> ? true : false;
type _AuditConforms = PgAuditRepository extends AsyncInterface<AuditRepository> ? true : false;
const _conformance: [_OrgConforms, _PolicyConforms, _MailflowConforms, _AuditConforms] = [true, true, true, true];
void _conformance;

const EXPECTED_TABLES = [
  "orgs",
  "domains",
  "users",
  "user_org_roles",
  "devices",
  "policies",
  "policy_domain_rules",
  "mailflow_events",
  "audit_log",
];

function migrationSql(dialect: "pg" | "sqlite", prefix: "0000" | "0001"): string {
  const dir = join(process.cwd(), "drizzle", dialect);
  const file = readdirSync(dir).find((f) => f.startsWith(prefix) && f.endsWith(".sql"));
  expect(file, `${dialect} ${prefix} migration exists`).toBeTruthy();
  return readFileSync(join(dir, file ?? ""), "utf8");
}

describe("sqlite Drizzle migrations", () => {
  it("creates all tables + triggers on a fresh file and re-migrates cleanly", () => {
    const conn = openSqlite(makeTempDbPath());
    try {
      migrateSqlite(conn.db);
      const tables = conn.facade.all("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name") as {
        name: string;
      }[];
      for (const t of EXPECTED_TABLES) {
        expect(tables.map((r) => r.name)).toContain(t);
      }
      const triggers = conn.facade.all(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log' ORDER BY name",
      ) as { name: string }[];
      expect(triggers.map((t) => t.name)).toEqual(["audit_log_no_delete", "audit_log_no_update"]);
      // Idempotent: second run applies nothing and throws nothing.
      migrateSqlite(conn.db);
      const journal = conn.facade.all("SELECT hash FROM __drizzle_migrations") as { hash: string }[];
      expect(journal.length).toBe(2);
    } finally {
      conn.raw.close();
    }
  });

  it("enforces foreign keys at the storage layer", () => {
    const conn = openSqlite(makeTempDbPath());
    try {
      migrateSqlite(conn.db);
      const pragma = conn.facade.one("PRAGMA foreign_keys") as { foreign_keys: number };
      expect(pragma.foreign_keys).toBe(1);
    } finally {
      conn.raw.close();
    }
  });
});

describe("migration artifacts (both dialects)", () => {
  it("pg 0000 creates the full contract schema with constraints + indexes", () => {
    const sql = migrationSql("pg", "0000");
    for (const t of EXPECTED_TABLES) {
      expect(sql).toContain(`CREATE TABLE "${t}"`);
    }
    expect(sql).toContain("idx_mailflow_org_ts");
    expect(sql).toContain("idx_mailflow_recipient");
    expect(sql.toLowerCase()).toContain("on delete cascade");
    expect(sql).toContain("org_admin");
  });

  it("pg 0001 installs the plpgsql append-only guard", () => {
    const sql = migrationSql("pg", "0001");
    expect(sql).toContain("audit_log_reject_write");
    expect(sql).toContain("CREATE TRIGGER audit_log_no_update");
    expect(sql).toContain("CREATE TRIGGER audit_log_no_delete");
  });

  it("sqlite 0001 installs the abort triggers", () => {
    const sql = migrationSql("sqlite", "0001");
    expect(sql).toContain("RAISE(ABORT");
    expect(sql).toContain("audit_log_no_update");
    expect(sql).toContain("audit_log_no_delete");
  });
});

const LIVE_PG = process.env["DATABASE_URL"] ?? "";

describe.skipIf(!LIVE_PG)("pg live round-trip (DATABASE_URL)", () => {
  it("migrates, enforces guards, and round-trips core entities", async () => {
    const { pool, db } = openPg(LIVE_PG);
    try {
      await migratePg(db);
      const orgs = new PgOrgRepository(db);
      const org = await orgs.createOrg(`org-live-${Date.now()}`, "live.test", 1000);
      expect((await orgs.getOrg(org.id))?.name).toBe("live.test");

      const policies = new PgPolicyRuleRepository(db);
      await policies.createPolicy("pol-live", org.id, "live", true, "tls1.2", "warn", 1001);
      await policies.addDomainRule("pol-live", "partner.example", "allow");
      expect(await policies.listPoliciesForOrg(org.id)).toHaveLength(1);

      const audit = new PgAuditRepository(db);
      await audit.append(
        { actor: { subject: "live@test", roles: ["org_admin"] }, orgId: org.id, action: "test.live", resource: null, outcome: "allowed", requestId: null, details: {} },
        "genesis",
        "entry-live",
        1,
        1002,
      );
      // Guard trigger fires on raw UPDATE.
      await expect(pool.query("UPDATE audit_log SET action = 'evil' WHERE seq = 1")).rejects.toThrow(/append-only/);
    } finally {
      await pool.end();
    }
  });
});
