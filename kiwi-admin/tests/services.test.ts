import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { parseAuditEventInput } from "../src/audit/model.js";
import { AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { ConflictError, NotFoundError, RequestValidationError } from "../src/util/validate.js";
import { escapeLikePattern } from "../src/db/repositories.js";
import { OrgService, PolicyService, MailflowService, AuditService, createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import { makeTempDbPath } from "./helpers/db.js";

let container: ServiceContainer;
let orgId: string;

const admin: Actor = { subject: "admin@acme.test", roles: ["org_admin"], orgId: null };
const viewer: Actor = { subject: "view@acme.test", roles: ["viewer"], orgId: null };
/** Reads the audit log. `audit.read` is a permission now, so reads need an actor. */
const auditor: Actor = { subject: "auditor@acme.test", roles: ["viewer"], orgId: null };

beforeAll(async () => {
  // The string form pins the SQLite dialect regardless of the ambient
  // DATABASE_URL, which keeps the unit suite hermetic.
  container = await createServiceContainer(makeTempDbPath());
  // Platform-level admin (orgId null) bootstraps the org; later actors bind
  // to the real generated org id.
  orgId = (await container.orgs.createOrg(admin, "acme.test", 900)).id;
});

afterAll(async () => {
  await container.close();
});

describe("OrgService — audit + RBAC wiring", () => {
  it("creates users, roles, devices with audit trail", async () => {
    const actor: Actor = { ...admin, orgId };
    const user = await container.orgs.createUser(actor, orgId, "bob@acme.test", 1010);
    await container.orgs.grantRole(actor, user.id, orgId, "security_admin", 1020);
    const dev = await container.orgs.createDevice(actor, orgId, "laptop-1", 1030);
    await container.orgs.revokeDevice(actor, dev.id, 1040);

    const records = await container.audit.query(auditor, { limit: 50 });
    const actions = records.map((r) => r.action);
    for (const a of ["org.create", "user.create", "user.role.grant", "device.create", "device.revoke"]) {
      expect(actions).toContain(a);
    }
    expect(records.every((r) => r.actor_subject === "admin@acme.test")).toBe(true);
    expect(records.every((r) => r.outcome === "allowed")).toBe(true);
  });

  it("denies + audits a policy write by a viewer", async () => {
    const actor: Actor = { ...viewer, orgId };
    await expect(
      container.policies.createPolicy(actor, orgId, "p1", {
        name: "block-evil",
        enabled: true,
        minTls: "tls1.2",
        externalRecipients: "warn",
        domainRules: [{ domain: "evil.example", action: "block" }],
      }),
    ).rejects.toThrow(AuthorizationDeniedError);

    const denied = (await container.audit.query(auditor, { limit: 50 })).filter((r) => r.outcome === "denied");
    expect(denied).toHaveLength(1);
    expect(denied[0]?.details).toContain("policy.write");
    expect((await container.audit.verify(auditor, { limit: 100 })).valid).toBe(true);
  });
});

describe("PolicyService — evaluation determinism", () => {
  it("evaluates deterministically through the service facade", async () => {
    const writer: Actor = { ...admin, orgId };
    const p = await container.policies.createPolicy(writer, orgId, "p2", {
      name: "default-outbound",
      enabled: true,
      minTls: "tls1.2",
      externalRecipients: "warn",
      domainRules: [
        { domain: "partner.example", action: "allow" },
        { domain: "evil.example", action: "block" },
      ],
    });
    const input = {
      direction: "outbound" as const,
      sender: "alice@acme.test",
      recipient: "stranger@unknown.test",
      tlsVersion: "tls1.3",
    };
    const first = await container.policies.evaluate(writer, p.id, input);
    expect(first).toEqual(await container.policies.evaluate(writer, p.id, input));
    expect(first.verdict).toBe("warn");
  });
});

describe("MailflowService — metadata-only ingest + queries", () => {
  it("ingests and queries mailflow events with RBAC enforcement", async () => {
    const actor: Actor = { ...admin, orgId: "orgId" };
    await container.mailflow.ingest(actor, {
      direction: "outbound",
      sender: "alice@acme.test",
      recipient: "bob@partner.example",
      ts: 2000,
      message_id: "<m1@acme.test>",
      tls_version: "tls1.3",
      security_status: "clean",
      policy_verdict: "allow",
      org_id: "orgId",
    });

    const page = await container.mailflow.query(actor, { orgId: "orgId", limit: 10 });
    expect(page.items.length).toBeGreaterThanOrEqual(1);
    const ev = page.items[0]!;
    expect(ev.recipient).toBe("bob@partner.example");
    expect(Object.keys(ev)).not.toContain("body");

    const readOnly: Actor = { ...viewer, orgId: "orgId" };
    await expect(
      container.mailflow.ingest(readOnly, {
        direction: "inbound",
        sender: "x@other.test",
        recipient: "bob@acme.test",
        ts: 2010,
        message_id: null,
        tls_version: null,
        security_status: "clean",
        policy_verdict: "allow",
        org_id: "orgId",
      }),
    ).rejects.toThrow(AuthorizationDeniedError);
    // Order-robust: the shared container accumulates rows across describes
    // (H1 now audits evaluations too), so assert presence, not position.
    const denied = (await container.audit.query(auditor, { limit: 100 })).filter((r) => r.outcome === "denied");
    expect(denied.some((r) => r.action === "mailflow.ingest")).toBe(true);
  });
});

describe("List methods (T-134 admin UI reads)", () => {
  it("lists org users with roles and org policies with rules", async () => {
    const actor: Actor = { ...admin, orgId };
    const u1 = await container.orgs.createUser(actor, orgId, "carol@acme.test", 4000);
    const u2 = await container.orgs.createUser(actor, orgId, "dave@acme.test", 4010);
    await container.orgs.grantRole(actor, u1.id, orgId, "viewer", 4020);

    const users = await container.orgs.listUsers(actor, orgId);
    const emails = users.map((u) => u.email);
    expect(emails).toContain("carol@acme.test");
    expect(emails).toContain("dave@acme.test");
    expect(users.find((u) => u.email === "carol@acme.test")?.roles).toEqual(["viewer"]);
    expect(users.find((u) => u.email === "dave@acme.test")?.roles).toEqual([]);
    expect(users).toEqual([...users].sort((a, b) => a.email.localeCompare(b.email)));

    const policies = await container.policies.listPolicies(actor, orgId);
    expect(policies.length).toBeGreaterThanOrEqual(1);
    // §5.1 wire shape (T-259/ADM-T250-01): the full snake_case PolicyObject —
    // org_id + name + snake_case fields, not the internal camelCase def.
    expect(policies[0]).toMatchObject({ org_id: orgId });
    for (const key of ["id", "org_id", "name", "enabled", "min_tls", "external_recipients", "domain_rules"]) {
      expect(policies[0]).toHaveProperty(key);
    }
  });

  it("denies cross-org listing", async () => {
    const other = (await container.orgs.createOrg(admin, "list-other.test", 4100)).id;
    const cross: Actor = { ...viewer, orgId };
    await expect(container.orgs.listUsers(cross, other)).rejects.toThrow(AuthorizationDeniedError);
    await expect(container.policies.listPolicies(cross, other)).rejects.toThrow(AuthorizationDeniedError);
  });
});

describe("AuditService", () => {
  it("verifies the whole chain", async () => {
    const v = await container.audit.verify(auditor, { limit: 200 });
    expect(v.valid).toBe(true);
    expect(v.checked).toBeGreaterThan(0);
  });

  it("parses untrusted event payloads strictly", () => {
    expect(() => parseAuditEventInput({ action: "" })).toThrow();
  });

  it("manual append keeps chain valid", async () => {
    const actor: Actor = { ...admin, orgId: "orgId" };
    const rec = await container.auditAppend(
      actor,
      "orgId",
      "test.manual",
      null,
      "allowed",
      null,
      { note: "integration probe" },
      3000,
    );
    expect(rec.seq).toBeGreaterThan(0);
    expect((await container.audit.verify(auditor, { limit: 500 })).valid).toBe(true);
  });

  it("requires audit.read to read or verify the log", async () => {
    // No roles at all — the fail-closed actor shape — must be refused.
    const anonymous: Actor = { subject: "nobody", roles: [], orgId: null };
    await expect(container.audit.query(anonymous, { limit: 10 })).rejects.toThrow(AuthorizationDeniedError);
    await expect(container.audit.verify(anonymous, { limit: 10 })).rejects.toThrow(AuthorizationDeniedError);
  });
});
