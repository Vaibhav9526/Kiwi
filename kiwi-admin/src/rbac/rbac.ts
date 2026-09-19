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
  "policy.read",
  "policy.write",
  "mailflow.read",
  "mailflow.ingest",
  "audit.read",
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
    "policy.read",
    "policy.write",
    "mailflow.read",
    "mailflow.ingest",
    "audit.read",
  ]),
  security_admin: new Set<Permission>([
    "org.read",
    "user.read",
    "device.read",
    "device.revoke",
    "policy.read",
    "policy.write",
    "mailflow.read",
    "audit.read",
  ]),
  viewer: new Set<Permission>(["org.read", "user.read", "device.read", "policy.read", "mailflow.read", "audit.read"]),
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
    // Org scoping: an actor with roles in one org cannot exercise org-scoped
    // permissions against another org. Platform-level (orgId null) actors
    // must hold the permission with no org binding (local-first single-org
    // scaffold: roles granted with orgId === actor.orgId count).
    if (targetOrgId !== null && actor.orgId !== null && targetOrgId !== actor.orgId) return false;
    return true;
  });
}

export function requirePermission(actor: Actor, permission: Permission, targetOrgId: string | null): void {
  if (!hasPermission(actor, permission, targetOrgId)) {
    throw new AuthorizationDeniedError(actor.subject, permission, targetOrgId);
  }
}
