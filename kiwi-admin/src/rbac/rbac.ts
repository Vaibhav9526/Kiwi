/**
 * RBAC permission model (docs/contracts/admin-api.md §3.2).
 * Roles: org_admin > security_admin > viewer. Enforcement is centralized:
 * service call sites call requirePermission() before doing work and every
 * denial is audited (SECURITY.md rule 11).
 */
import type { OrgRole } from "../types.js";

export const PERMISSIONS = [
  "org.read",
  "org.create",
  "org.update",
  "user.read",
  "user.invite",
  "user.role.grant",
  "device.read",
  "device.revoke",
  /**
   * Device enrollment capability (T-259/ADM-T250-15): `createDevice` used to
   * be gated on `device.revoke`, which lied about what was being authorized.
   * `device.create` names the real act; the route remains unimplemented, so
   * this binds the service-only path today.
   */
  "device.create",
  "policy.read",
  "policy.write",
  "mailflow.read",
  "mailflow.ingest",
  "audit.read",
  /**
   * T-179: exporting the audit log. Separate from `audit.read` — every role
   * may read the log, but producing a signed, off-box copy (the evidence
   * artifact) is an export-capable act. Org admins hold it org-scoped
   * (`GET /orgs/{org}/audit/export`); the GLOBAL export additionally requires
   * the distinct `system-admin` platform role (admin-api.md §13, T-259).
   */
  "audit.export",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const ROLE_PERMISSIONS: Record<OrgRole, ReadonlySet<Permission>> = {
  org_admin: new Set<Permission>([
    "org.read",
    "org.create",
    "org.update",
    "user.read",
    "user.invite",
    "user.role.grant",
    "device.read",
    "device.revoke",
    "device.create",
    "policy.read",
    "policy.write",
    "mailflow.read",
    "mailflow.ingest",
    "audit.read",
    "audit.export",
  ]),
  security_admin: new Set<Permission>([
    "org.read",
    "user.read",
    "device.read",
    "device.revoke",
    "device.create",
    "policy.read",
    "policy.write",
    "mailflow.read",
    "audit.read",
  ]),
  viewer: new Set<Permission>(["org.read", "user.read", "device.read", "policy.read", "mailflow.read", "audit.read"]),
  /**
   * Platform role (admin-api.md §13, T-259): the ONLY identity that may take
   * a signed export of the whole audit chain off-box. It deliberately holds
   * no org-scoped permission — `hasPermission` denies any non-null target for
   * its null-org actor, so it cannot read a single org's data; its one
   * capability is the global export. It is also never grantable into
   * `user_org_roles` (see GRANTABLE_ORG_ROLES) — it arrives only via the
   * header-actor scaffold until real platform auth lands (§12.2).
   */
  "system-admin": new Set<Permission>(["audit.export"]),
};

export interface Actor {
  subject: string;
  roles: OrgRole[];
  /** Org the actor's session is bound to; null = no org context (platform level). */
  orgId: string | null;
}

export class AuthorizationDeniedError extends Error {
  constructor(
    public readonly subject: string,
    public readonly permission: Permission,
    public readonly orgId: string | null,
  ) {
    super(`actor '${subject}' lacks permission '${permission}'${orgId ? ` in org '${orgId}'` : ""}`);
    this.name = "AuthorizationDeniedError";
  }
}

export function hasPermission(actor: Actor, permission: Permission, targetOrgId: string | null): boolean {
  return actor.roles.some((role) => {
    const set = ROLE_PERMISSIONS[role];
    if (!set) return false;
    if (!set.has(permission)) return false;
    // Org scoping (T-193/H2, fail-closed): an actor with roles in one org
    // cannot exercise org-scoped permissions against another org — and an
    // actor with NO org binding holds NO org scope at all. A null-org actor
    // previously satisfied every org-scoped check (global reach by omitting
    // a header); now any non-null target denies it. Platform-level actions
    // pass a null target and check the role only (bootstrap, audit export).
    if (targetOrgId !== null && targetOrgId !== actor.orgId) return false;
    return true;
  });
}

export function requirePermission(actor: Actor, permission: Permission, targetOrgId: string | null): void {
  if (!hasPermission(actor, permission, targetOrgId)) {
    throw new AuthorizationDeniedError(actor.subject, permission, targetOrgId);
  }
}
