/** T-108 send-path bridge tests: org-scoped worst-wins evaluation. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import { evaluateOutboundForOrg } from "../src/policy/services.js";
import { makeTempDbPath } from "./helpers/db.js";

let container: ServiceContainer;
let orgId: string;

const admin: Actor = { subject: "bridge-admin@acme.test", roles: ["org_admin"], orgId: null };
const auditor: Actor = { subject: "auditor@acme.test", roles: ["viewer"], orgId: null };

beforeAll(async () => {
  container = await createServiceContainer(makeTempDbPath());
  orgId = (await container.orgs.createOrg(admin, "bridge-acme.test", 1000)).id;
  const writer: Actor = { ...admin, orgId };
  await container.policies.createPolicy(writer, orgId, "default-outbound", {
    name: "default-outbound",
    enabled: true,
    minTls: "tls1.2",
    externalRecipients: "warn",
    domainRules: [
      { domain: "partner.example", action: "allow" },
      { domain: "evil.example", action: "block" },
    ],
  });
});

afterAll(async () => {
  await container.close();
});

describe("PolicyService.evaluateOutbound — send-path bridge", () => {
  it("returns per-recipient verdicts with worst-wins overall", async () => {
    const actor: Actor = { ...admin, orgId };
    const out = await container.policies.evaluateOutbound(actor, orgId, {
      sender: "alice@bridge-acme.test",
      recipients: ["friend@partner.example", "stranger@unknown.test", "bad@evil.example"],
      tlsVersion: "tls1.3",
    });
    expect(out.orgId).toBe(orgId);
    expect(out.results.map((r) => [r.recipient, r.verdict])).toEqual([
      ["friend@partner.example", "allow"],
      ["stranger@unknown.test", "warn"],
      ["bad@evil.example", "block"],
    ]);
    expect(out.overall).toBe("block");
    expect(out.results.every((r) => typeof r.policyId === "string")).toBe(true);
  });

  it("blocks below-minimum observed TLS and accepts version aliases", async () => {
    const actor: Actor = { ...admin, orgId };
    const out = await container.policies.evaluateOutbound(actor, orgId, {
      sender: "alice@bridge-acme.test",
      recipients: ["friend@partner.example"],
      tlsVersion: "TLS1_0",
    });
    expect(out.overall).toBe("block");
    expect(out.results[0]?.reasons.map((r) => r.code)).toContain("tls-below-minimum");
  });

  it("allows when the org has no enabled policies (reason recorded)", async () => {
    const other = (await container.orgs.createOrg(admin, "nopolicy.test", 1100)).id;
    const actor: Actor = { ...admin, orgId: other };
    const out = await container.policies.evaluateOutbound(actor, other, {
      sender: "a@nopolicy.test",
      recipients: ["b@elsewhere.test"],
      tlsVersion: null,
    });
    expect(out.overall).toBe("allow");
    expect(out.results[0]?.reasons.map((r) => r.code)).toContain("no-policy-enabled");
    expect(out.results[0]?.policyId).toBeNull();
  });

  it("denies cross-org evaluation and audits the denial", async () => {
    const other = (await container.orgs.createOrg(admin, "other.test", 1200)).id;
    const crossActor: Actor = { subject: "x@bridge-acme.test", roles: ["viewer"], orgId };
    await expect(
      container.policies.evaluateOutbound(crossActor, other, {
        sender: "a@other.test",
        recipients: ["b@other.test"],
        tlsVersion: null,
      }),
    ).rejects.toThrow(AuthorizationDeniedError);
    const denied = (await container.audit.query(auditor, { limit: 100 })).filter((r) => r.outcome === "denied");
    expect(denied.some((r) => r.action === "policy.evaluate_outbound")).toBe(true);
  });

  it("rejects malformed bridge input", async () => {
    const actor: Actor = { ...admin, orgId };
    await expect(
      container.policies.evaluateOutbound(actor, orgId, { sender: "a@b.test", recipients: [], tlsVersion: null }),
    ).rejects.toThrow(/recipients/);
    await expect(
      container.policies.evaluateOutbound(actor, orgId, {
        sender: "a@b.test",
        recipients: ["b@c.test"],
        tlsVersion: "TLS9.9",
      }),
    ).rejects.toThrow(/tlsVersion/);
    await expect(
      container.policies.evaluateOutbound(actor, orgId, {
        sender: "a@b.test",
        recipients: new Array(257).fill("b@c.test"),
        tlsVersion: null,
      }),
    ).rejects.toThrow(/exceeds 256/);
  });

  it("pure core is deterministic", async () => {
    const actor: Actor = { ...admin, orgId };
    const bridge = await container.policies.evaluateOutbound(actor, orgId, {
      sender: "a@bridge-acme.test",
      recipients: ["b@evil.example"],
      tlsVersion: "tls1.3",
    });
    const def = await container.policies.getPolicyDefinition(bridge.results[0]?.policyId ?? "");
    expect(def).toBeDefined();
    const a = evaluateOutboundForOrg(orgId, def ? [def] : [], "a@bridge-acme.test", ["b@evil.example"], "tls1.3");
    const b = evaluateOutboundForOrg(orgId, def ? [def] : [], "a@bridge-acme.test", ["b@evil.example"], "tls1.3");
    expect(a).toEqual(b);
    expect(a.overall).toBe("block");
  });
});
