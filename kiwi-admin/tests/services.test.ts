import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { parseAuditEventInput } from "../src/audit/model.js";
import { AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { OrgService, PolicyService, MailflowService, AuditService, createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import { makeTempDbPath } from "./helpers/db.js";

let container: ServiceContainer;
let orgId: string;

const admin: Actor = { subject: "admin@acme.test", roles: ["org_admin"], orgId: null };
const viewer: Actor = { subject: "view@acme.test", roles: ["viewer"], orgId: null };

beforeAll(() => {
  container = createServiceContainer(makeTempDbPath());
  // Platform-level admin (orgId null) bootstraps the org; later actors bind
  // to the real generated org id.
  orgId = container.orgs.createOrg(admin, "acme.test", 900).id;
});

afterAll(() => {
  container.close();
});

describe("OrgService — audit + RBAC wiring", () => {
  it("creates users, roles, devices with audit trail", () => {
    const actor: Actor = { ...admin, orgId };
    const user = container.orgs.createUser(actor, orgId, "bob@acme.test", 1010);
    container.orgs.grantRole(actor, user.id, orgId, "security_admin", 1020);
    const dev = container.orgs.createDevice(actor, orgId, "laptop-1", 1030);
    container.orgs.revokeDevice(actor, dev.id, 1040);

    const records = container.audit.query({ limit: 50 });
    const actions = records.map((r) => r.action);
    for (const a of ["org.create", "user.create", "user.role.grant", "device.create", "device.revoke"]) {
      expect(actions).toContain(a);
    }
    expect(records.every((r) => r.actor_subject === "admin@acme.test")).toBe(true);
    expect(records.every((r) => r.outcome === "allowed")).toBe(true);
  });

  it("denies + audits a policy write by a viewer", () => {
    const actor: Actor = { ...viewer, orgId };
    const denyFn = () =>
      container.policies.createPolicy(actor, orgId, "p1", {
        name: "block-evil",
        enabled: true,
        minTls: "tls1.2",
        externalRecipients: "warn",
        domainRules: [{ domain: "evil.example", action: "block" }],
      });
    expect(denyFn).toThrow(AuthorizationDeniedError);

    const denied = container.audit.query({ limit: 50 }).filter((r) => r.outcome === "denied");
    expect(denied).toHaveLength(1);
    expect(denied[0]?.details).toContain("policy.write");
    expect(container.audit.verify({ limit: 100 }).valid).toBe(true);
  });
});

describe("PolicyService — evaluation determinism", () => {
  it("evaluates deterministically through the service facade", () => {
    const writer: Actor = { ...admin, orgId };
    const p = container.policies.createPolicy(writer, orgId, "p2", {
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
    expect(container.policies.evaluate(p.id, input)).toEqual(container.policies.evaluate(p.id, input));
    expect(container.policies.evaluate(p.id, input).verdict).toBe("warn");
  });
});

describe("MailflowService — metadata-only ingest + queries", () => {
  it("ingests and queries mailflow events with RBAC enforcement", () => {
    const actor: Actor = { ...admin, orgId: "orgId" };
    container.mailflow.ingest(actor, {
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

    const page = container.mailflow.query(actor, { orgId: "orgId", limit: 10 });
    expect(page.items.length).toBeGreaterThanOrEqual(1);
    const ev = page.items[0]!;
    expect(ev.recipient).toBe("bob@partner.example");
    expect(Object.keys(ev)).not.toContain("body");

    const readOnly: Actor = { ...viewer, orgId: "orgId" };
    const denyFn = () =>
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
      });
    expect(denyFn).toThrow(AuthorizationDeniedError);
    const lastDenied = container.audit.query({ limit: 10 }).filter((r) => r.outcome === "denied").at(-1);
    expect(lastDenied?.action).toBe("mailflow.ingest");
  });
});

describe("List methods (T-134 admin UI reads)", () => {
  it("lists org users with roles and org policies with rules", () => {
    const actor: Actor = { ...admin, orgId };
    const u1 = container.orgs.createUser(actor, orgId, "carol@acme.test", 4000);
    const u2 = container.orgs.createUser(actor, orgId, "dave@acme.test", 4010);
    container.orgs.grantRole(actor, u1.id, orgId, "viewer", 4020);

    const users = container.orgs.listUsers(actor, orgId);
    const emails = users.map((u) => u.email);
    expect(emails).toContain("carol@acme.test");
    expect(emails).toContain("dave@acme.test");
    expect(users.find((u) => u.email === "carol@acme.test")?.roles).toEqual(["viewer"]);
    expect(users.find((u) => u.email === "dave@acme.test")?.roles).toEqual([]);
    expect(users).toEqual([...users].sort((a, b) => a.email.localeCompare(b.email)));

    const policies = container.policies.listPolicies(actor, orgId);
    expect(policies.length).toBeGreaterThanOrEqual(1);
    expect(policies[0]).toHaveProperty("domainRules");
  });

  it("denies cross-org listing", () => {
    const other = container.orgs.createOrg(admin, "list-other.test", 4100).id;
    const cross: Actor = { ...viewer, orgId };
    expect(() => container.orgs.listUsers(cross, other)).toThrow(AuthorizationDeniedError);
    expect(() => container.policies.listPolicies(cross, other)).toThrow(AuthorizationDeniedError);
  });
});

describe("AuditService", () => {
  it("verifies the whole chain", () => {
    const v = container.audit.verify({ limit: 200 });
    expect(v.valid).toBe(true);
    expect(v.checked).toBeGreaterThan(0);
  });

  it("parses untrusted event payloads strictly", () => {
    expect(() => parseAuditEventInput({ action: "" })).toThrow();
  });

  it("manual append keeps chain valid", () => {
    const actor: Actor = { ...admin, orgId: "orgId" };
    const rec = container.auditAppend(
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
    expect(container.audit.verify({ limit: 500 }).valid).toBe(true);
  });
});

