
import { describe, it, expect } from "vitest";
import { AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { ConflictError, NotFoundError, RequestValidationError } from "../src/util/validate.js";
import { escapeLikePattern } from "../src/db/repositories.js";
import { createServiceContainer } from "../src/services.js";
import { makeTempDbPath } from "./helpers/db.js";

/**
 * T-193 regression tests for the admin-review-1 findings. Each test names
 * the finding it pins; the e2e suite (infra/e2e/test_admin_e2e.py) covers
 * the same properties over HTTP.
 */
describe("T-193/H1 evaluate is authenticated and audited", () => {
  const admin: Actor = { subject: "h1-admin", roles: ["org_admin"], orgId: null };

  it("viewer and cross-org evaluations are denied and audited; owner allowed", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const a = (await container.orgs.createOrg(admin, "h1c.test", 102)).id;
    const b = (await container.orgs.createOrg(admin, "h1d.test", 103)).id;
    const p = (
      await container.policies.createPolicy({ ...admin, orgId: a }, a, "h1x", {
        name: "h1x",
        enabled: true,
        minTls: null,
        externalRecipients: "warn",
        domainRules: [],
      })
    ).id;
    const input = { direction: "outbound" as const, sender: "a@t", recipient: "b@t", tlsVersion: null };
    await expect(container.policies.evaluate({ subject: "v", roles: ["viewer"], orgId: a }, p.id, input)).rejects.toThrow(
      AuthorizationDeniedError,
    );
    await expect(container.policies.evaluate({ ...admin, orgId: b }, p.id, input)).rejects.toThrow(
      AuthorizationDeniedError,
    );
    const denied = (await container.audit.query(admin, { limit: 100 })).filter(
      (r) => r.outcome === "denied" && r.action === "policy.evaluate",
    );
    expect(denied.length).toBeGreaterThanOrEqual(2);
    const ok = await container.policies.evaluate({ ...admin, orgId: a }, p.id, input);
    expect(ok).toBeTruthy();
    const allowed = (await container.audit.query(admin, { limit: 100 })).filter(
      (r) => r.outcome === "allowed" && r.action === "policy.evaluate",
    );
    expect(allowed.length).toBeGreaterThanOrEqual(1);
    await container.close();
  });
});

describe("T-193/H3+H5 scoped revocation and org creation", () => {
  it("cross-org revoke denied, own-org revoke works, unknown device 404s", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const admin: Actor = { subject: "h3", roles: ["org_admin"], orgId: null };
    const a = (await container.orgs.createOrg(admin, "h3a.test", 110)).id;
    const b = (await container.orgs.createOrg(admin, "h3b.test", 111)).id;
    const dev = await container.orgs.createDevice({ ...admin, orgId: a }, a, "laptop", 112);
    await expect(container.orgs.revokeDevice({ ...admin, orgId: b }, dev.id, 113)).rejects.toThrow(
      AuthorizationDeniedError,
    );
    await container.orgs.revokeDevice({ ...admin, orgId: a }, dev.id, 114);
    await expect(container.orgs.revokeDevice({ ...admin, orgId: a }, "dev-nope", 115)).rejects.toThrow(NotFoundError);
    await container.close();
  });

  it("createOrg requires org.create (viewer denied)", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    await expect(
      container.orgs.createOrg({ subject: "v", roles: ["viewer"], orgId: null }, "nope.test", 120),
    ).rejects.toThrow(AuthorizationDeniedError);
    const created = await container.orgs.createOrg(
      { subject: "p", roles: ["org_admin"], orgId: null },
      "platform.test",
      121,
    );
    expect(created.id.startsWith("org-")).toBe(true);
    await container.close();
  });
});

describe("T-193/H8 verify floor", () => {
  it("refuses non-positive limits instead of attesting nothing", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const auditor: Actor = { subject: "a", roles: ["viewer"], orgId: null };
    await expect(container.audit.verify(auditor, { limit: 0 })).rejects.toThrow(RequestValidationError);
    await expect(container.audit.verify(auditor, { limit: -5 })).rejects.toThrow(RequestValidationError);
    await container.close();
  });
});

describe("T-193/M3 atomic createPolicy with caps and error audit", () => {
  it("rejects duplicates and overlong rule sets without partial writes", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const admin: Actor = { subject: "m3", roles: ["org_admin"], orgId: null };
    const org = (await container.orgs.createOrg(admin, "m3.test", 130)).id;
    const writer: Actor = { ...admin, orgId: org };
    const before = (await container.policies.listPolicies(writer, org)).length;
    await expect(
      container.policies.createPolicy(writer, org, "dup", {
        name: "dup",
        enabled: true,
        minTls: null,
        externalRecipients: "warn",
        domainRules: [
          { domain: "a.test", action: "allow" },
          { domain: "A.TEST", action: "block" },
        ],
      }),
    ).rejects.toThrow(RequestValidationError);
    const big = Array.from({ length: 257 }, (_, i) => ({ domain: `d${i}.test`, action: "allow" as const }));
    await expect(
      container.policies.createPolicy(writer, org, "big", {
        name: "big",
        enabled: true,
        minTls: null,
        externalRecipients: "warn",
        domainRules: big,
      }),
    ).rejects.toThrow(RequestValidationError);
    const after = (await container.policies.listPolicies(writer, org)).length;
    expect(after).toBe(before);
    const errors = (await container.audit.query(admin, { limit: 200 })).filter(
      (r) => r.outcome === "error" && r.action === "policy.create",
    );
    expect(errors.length).toBeGreaterThanOrEqual(2);
    await container.close();
  });
});

describe("T-193/M5+M6 conflict and membership", () => {
  it("duplicate email is a 409-class error; outsider grant is 404", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const admin: Actor = { subject: "m56", roles: ["org_admin"], orgId: null };
    const a = (await container.orgs.createOrg(admin, "m56a.test", 140)).id;
    const b = (await container.orgs.createOrg(admin, "m56b.test", 141)).id;
    const writer: Actor = { ...admin, orgId: a };
    await container.orgs.createUser(writer, a, "dup@acme.test", 142);
    await expect(container.orgs.createUser(writer, a, "dup@acme.test", 143)).rejects.toThrow(ConflictError);
    const outsider = await container.orgs.createUser(writer, a, "out@acme.test", 144);
    await expect(container.orgs.grantRole(writer, outsider.id, b, "viewer", 145)).rejects.toThrow(NotFoundError);
    await expect(container.orgs.grantRole(writer, "user-nope", a, "viewer", 146)).rejects.toThrow(NotFoundError);
    await container.close();
  });
});

describe("T-193/M7 bounded listings", () => {
  it("listUsers honors the limit", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const admin: Actor = { subject: "m7", roles: ["org_admin"], orgId: null };
    const org = (await container.orgs.createOrg(admin, "m7.test", 150)).id;
    const writer: Actor = { ...admin, orgId: org };
    await container.orgs.createUser(writer, org, "one@acme.test", 151);
    await container.orgs.createUser(writer, org, "two@acme.test", 152);
    expect((await container.orgs.listUsers(writer, org, 1)).length).toBeLessThanOrEqual(1);
    expect((await container.orgs.listUsers(writer, org)).length).toBeGreaterThanOrEqual(2);
    await container.close();
  });
});

describe("T-193/H6 concurrent appends stay contiguous", () => {
  it("20 parallel appends serialize without loss or gaps", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        container.audit.append(
          {
            actor: { subject: "h6", roles: ["org_admin"] },
            orgId: null,
            action: "h6.probe",
            resource: null,
            outcome: "allowed",
            requestId: null,
            details: { i },
          },
          1600 + i,
        ),
      ),
    );
    const seqs = results.map((r) => r.seq).sort((a, b) => a - b);
    expect(seqs).toHaveLength(20);
    for (let k = 1; k < seqs.length; k++) expect(seqs[k]! - seqs[k - 1]!).toBe(1);
    expect(await container.audit.verify({ subject: "h6v", roles: ["viewer"], orgId: null }, { limit: 100 })).toMatchObject({
      valid: true,
    });
    await container.close();
  });
});

describe("T-193/L1 LIKE metacharacters are escaped", () => {
  it("escapeLikePattern neutralizes %, _, and backslash", () => {
    expect(escapeLikePattern("%a_b\\c")).toBe("\\%a\\_b\\\\c");
    expect(escapeLikePattern("plain.example")).toBe("plain.example");
  });

  it("recipientDomain % and _ match literally (no widening)", async () => {
    const container = await createServiceContainer(makeTempDbPath());
    const admin: Actor = { subject: "l1", roles: ["org_admin"], orgId: null };
    const org = (await container.orgs.createOrg(admin, "l1.test", 170)).id;
    const writer: Actor = { ...admin, orgId: org };
    await container.mailflow.ingest(writer, {
      direction: "outbound",
      sender: "a@t",
      recipient: "plain@x.test",
      ts: 1710,
      message_id: null,
      tls_version: null,
      security_status: "clean",
      policy_verdict: "allow",
      org_id: org,
    });
    expect((await container.mailflow.query(writer, { orgId: org, recipientDomain: "%", limit: 10 })).items).toEqual([]);
    expect((await container.mailflow.query(writer, { orgId: org, recipientDomain: "_", limit: 10 })).items).toEqual([]);
    expect(
      (await container.mailflow.query(writer, { orgId: org, recipientDomain: "x.test", limit: 10 })).items,
    ).toHaveLength(1);
    await container.close();
  });
});
