/** Audit append-only DB guard (v2 migration) + idempotent restarts. */
import { describe, it, expect } from "vitest";
import type { Actor } from "../src/rbac/rbac.js";
import { createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import { makeTempDbPath } from "./helpers/db.js";

const admin: Actor = { subject: "guard-admin@acme.test", roles: ["org_admin"], orgId: null };

function openSeeded(dbPath: string): { container: ServiceContainer; orgId: string } {
  const container = createServiceContainer(dbPath);
  const orgId = container.orgs.createOrg(admin, "guard-acme.test", 5000).id;
  return { container, orgId };
}

describe("audit_log append-only triggers", () => {
  it("rejects UPDATE and DELETE at the storage layer", () => {
    const { container } = openSeeded(makeTempDbPath());
    try {
      expect(() => container.db.run("UPDATE audit_log SET action = 'evil' WHERE seq = 1")).toThrow(/append-only/);
      expect(() => container.db.run("DELETE FROM audit_log WHERE seq = 1")).toThrow(/append-only/);
      // Guard did not disturb legitimate reads/verification.
      expect(container.audit.verify({ limit: 100 }).valid).toBe(true);
      const row = container.db.one("SELECT action FROM audit_log WHERE seq = 1") as { action: string };
      expect(row.action).toBe("org.create");
    } finally {
      container.close();
    }
  });

  it("registers both triggers in sqlite_master", () => {
    const { container } = openSeeded(makeTempDbPath());
    try {
      const triggers = container.db.all(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log' ORDER BY name",
      ) as { name: string }[];
      expect(triggers.map((t) => t.name)).toEqual(["audit_log_no_delete", "audit_log_no_update"]);
    } finally {
      container.close();
    }
  });

  it("verify flags a seq gap (simulated privileged-row insertion)", () => {
    const { container } = openSeeded(makeTempDbPath());
    try {
      container.db.run(
        "INSERT INTO audit_log (seq, ts, action, outcome, prev_hash, entry_hash) VALUES (999, 5001, 'evil', 'allowed', 'x', 'y')",
      );
      const result = container.audit.verify({ limit: 100 });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("non-contiguous");
    } finally {
      container.close();
    }
  });
});

describe("restart-safe migrations", () => {
  it("reopening the same database file works and keeps data", () => {
    const dbPath = makeTempDbPath();
    const first = openSeeded(dbPath);
    first.container.close();

    const second = openSeeded(dbPath);
    try {
      // Prior audit history survived the restart.
      expect(second.container.audit.verify({ limit: 100 }).valid).toBe(true);
      expect(second.container.audit.query({ limit: 100 }).some((r) => r.action === "org.create")).toBe(true);
      // New writes work after restart.
      second.container.orgs.createOrg(admin, "second.test", 5100);
      expect(second.container.audit.verify({ limit: 100 }).valid).toBe(true);
      // Drizzle journal tracks both migrations (0000 schema + 0001 triggers).
      const journal = second.container.db.all("SELECT hash FROM __drizzle_migrations ORDER BY created_at") as {
        hash: string;
      }[];
      expect(journal.length).toBeGreaterThanOrEqual(2);
    } finally {
      second.container.close();
    }
  });
});
