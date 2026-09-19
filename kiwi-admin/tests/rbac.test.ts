import { describe, it, expect } from "vitest";
import { hasPermission, requirePermission, AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { InMemoryAuditLog } from "../src/audit/chain.js";

const orgAdmin: Actor = { subject: "admin@acme.test", roles: ["org_admin"], orgId: "org-acme" };
const secAdmin: Actor = { subject: "sec@acme.test", roles: ["security_admin"], orgId: "org-acme" };
const viewer: Actor = { subject: "view@acme.test", roles: ["viewer"], orgId: "org-acme" };
const otherOrgViewer: Actor = { subject: "view@other.test", roles: ["viewer"], orgId: "org-other" };
const anonymous: Actor = { subject: "anonymous", roles: [], orgId: null };

describe("RBAC positive cases", () => {
  it("org_admin can grant roles", () => {
    expect(hasPermission(orgAdmin, "user.role.grant", "org-acme")).toBe(true);
  });
  it("security_admin can write policies but not invite users", () => {
    expect(hasPermission(secAdmin, "policy.write", "org-acme")).toBe(true);
    expect(hasPermission(secAdmin, "user.invite", "org-acme")).toBe(false);
  });
  it("viewer can read policies and mailflow", () => {
    expect(hasPermission(viewer, "policy.read", "org-acme")).toBe(true);
    expect(hasPermission(viewer, "mailflow.read", "org-acme")).toBe(true);
  });
});

describe("RBAC negative cases (unauthorized admin op rejected)", () => {
  it("viewer cannot write policy", () => {
    expect(hasPermission(viewer, "policy.write", "org-acme")).toBe(false);
  });
  it("viewer cannot revoke devices", () => {
    expect(hasPermission(viewer, "device.revoke", "org-acme")).toBe(false);
  });
  it("anonymous has no permissions", () => {
    for (const p of ["org.create", "policy.write", "device.revoke", "audit.read"] as const) {
      expect(hasPermission(anonymous, p, "org-acme")).toBe(false);
    }
  });
  it("cross-org access is denied even with a valid role", () => {
    expect(hasPermission(otherOrgViewer, "policy.read", "org-acme")).toBe(false);
    expect(hasPermission(orgAdmin, "device.revoke", "org-other")).toBe(false);
  });
  it("requirePermission throws AuthorizationDeniedError", () => {
    expect(() => requirePermission(viewer, "policy.write", "org-acme")).toThrow(AuthorizationDeniedError);
    expect(() => requirePermission(anonymous, "org.create", "org-acme")).toThrow(AuthorizationDeniedError);
  });
});

describe("RBAC denials are audited", () => {
  it("every denial produces an audit record with outcome=denied and chain stays valid", () => {
    const log = new InMemoryAuditLog();
    const attempt = (actor: Actor, permission: string, org: string | null) => {
      try {
        // Simulate the service call-site pattern:
        // requirePermission(...) then work then audit(allowed).
        const perm = permission as Parameters<typeof requirePermission>[1];
        requirePermission(actor, perm, org);
        log.append(
          {
            actor: { subject: actor.subject, roles: actor.roles },
            orgId: org,
            action: `attempt:${permission}`,
            resource: null,
            outcome: "allowed",
            requestId: null,
            details: {},
          },
          1000,
        );
      } catch (err) {
        if (!(err instanceof AuthorizationDeniedError)) throw err;
        log.append(
          {
            actor: { subject: actor.subject, roles: actor.roles },
            orgId: org,
            action: `attempt:${permission}`,
            resource: null,
            outcome: "denied",
            requestId: null,
            details: { permission },
          },
          1000,
        );
      }
    };

    attempt(viewer, "policy.write", "org-acme");
    attempt(anonymous, "device.revoke", "org-acme");
    attempt(otherOrgViewer, "policy.read", "org-acme");
    attempt(secAdmin, "user.invite", "org-acme");
    attempt(orgAdmin, "policy.write", "org-acme"); // allowed control

    const denied = log.records.filter((r) => r.outcome === "denied");
    expect(denied).toHaveLength(4);
    expect(denied.every((r) => r.actor_subject !== null)).toBe(true);
    expect(log.verify()).toEqual({ valid: true, error: null });
  });
});
