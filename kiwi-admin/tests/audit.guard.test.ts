/** Audit append-only DB guard (v2 migration) + idempotent restarts. */
import { describe, it, expect } from "vitest";
import type { Actor } from "../src/rbac/rbac.js";
import { createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import type { Db } from "../src/db/interfaces.js";
import { makeTempDbPath } from "./helpers/db.js";

const admin: Actor = { subject: "guard-admin@acme.test", roles: ["org_admin"], orgId: null };
const auditor: Actor = { subject: "auditor@acme.test", roles: ["viewer"], orgId: null };

/**
 * The raw SQL facade exists only on the SQLite dialect (node-postgres has no
 * synchronous query path). This suite drives UPDATE/DELETE straight at the
 * file, so it is SQLite-only by construction.
 */
function sql(container: ServiceContainer): Db {
  if (!container.db) throw new Error("this suite requires the SQLite dialect");
  return container.db;
}

async function openSeeded(dbPath: string): Promise<{ container: ServiceContainer; orgId: string }> {
  const container = await createServiceContainer(dbPath);
  const orgId = (await container.orgs.createOrg(admin, "guard-acme.test", 5000)).id;
  return { container, orgId };
}

describe("audit_log append-only triggers", () => {
  it("rejects UPDATE and DELETE at the storage layer", async () => {
    const { container } = await openSeeded(makeTempDbPath());
    try {
      expect(() => sql(container).run("UPDATE audit_log SET action = 'evil' WHERE seq = 1")).toThrow(/append-only/);
      expect(() => sql(container).run("DELETE FROM audit_log WHERE seq = 1")).toThrow(/append-only/);
      // Guard did not disturb legitimate reads/verification.
      expect((await container.audit.verify(auditor, { limit: 100 })).valid).toBe(true);
      const row = sql(container).one("SELECT action FROM audit_log WHERE seq = 1") as { action: string };
      expect(row.action).toBe("org.create");
    } finally {
      await container.close();
    }
  });

  it("registers both triggers in sqlite_master", async () => {
    const { container } = await openSeeded(makeTempDbPath());
    try {
      const triggers = sql(container).all(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log' ORDER BY name",
      ) as { name: string }[];
      expect(triggers.map((t) => t.name)).toEqual(["audit_log_no_delete", "audit_log_no_update"]);
    } finally {
      await container.close();
    }
  });

  it("verify flags a seq gap (simulated privileged-row insertion)", async () => {
    const { container } = await openSeeded(makeTempDbPath());
    try {
      sql(container).run(
        "INSERT INTO audit_log (seq, ts, action, outcome, prev_hash, entry_hash) VALUES (999, 5001, 'evil', 'allowed', 'x', 'y')",
      );
      const result = await container.audit.verify(auditor, { limit: 100 });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("non-contiguous");
    } finally {
      await container.close();
    }
  });
});

describe("restart-safe migrations", () => {
  it("reopening the same database file works and keeps data", async () => {
    const dbPath = makeTempDbPath();
    const first = await openSeeded(dbPath);
    await first.container.close();

    const second = await openSeeded(dbPath);
    try {
      // Prior audit history survived the restart.
      expect((await second.container.audit.verify(auditor, { limit: 100 })).valid).toBe(true);
      const history = await second.container.audit.query(auditor, { limit: 100 });
      expect(history.some((r) => r.action === "org.create")).toBe(true);
      // New writes work after restart.
      await second.container.orgs.createOrg(admin, "second.test", 5100);
      expect((await second.container.audit.verify(auditor, { limit: 100 })).valid).toBe(true);
      // Drizzle journal tracks both migrations (0000 schema + 0001 triggers).
      const journal = sql(second.container).all("SELECT hash FROM __drizzle_migrations ORDER BY created_at") as {
        hash: string;
      }[];
      expect(journal.length).toBeGreaterThanOrEqual(2);
    } finally {
      await second.container.close();
    }
  });
});
