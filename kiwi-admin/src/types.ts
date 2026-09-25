/** Shared KIWI admin types. Wire-shape names follow docs/contracts/admin-api.md (v1). */

export type OrgRole = "org_admin" | "security_admin" | "viewer" | "system-admin";

/**
 * Every role an actor's headers may claim. `system-admin` (admin-api.md §13)
 * is a platform role: it exists so the global audit export can be gated on a
 * distinct identity rather than the org-wide `audit.export` grant.
 */
export const ALL_ORG_ROLES: readonly OrgRole[] = [
  "org_admin",
  "security_admin",
  "viewer",
  "system-admin",
] as const;

/**
 * Roles that may be granted into `user_org_roles` (the org-scoped role
 * table's CHECK allows only these). `system-admin` is a platform identity,
 * never an org membership — `grantRole` must reject it or the row write
 * fails a constraint as a 500.
 */
export const GRANTABLE_ORG_ROLES: readonly OrgRole[] = [
  "org_admin",
  "security_admin",
  "viewer",
] as const;

export type RecipientDomainAction = "allow" | "block";

export type ExternalRecipientBehavior = "allow" | "warn" | "block";

/** TLS versions ordered weakest to strongest for deterministic comparisons. */
export const TLS_VERSION_ORDER: readonly string[] = [
  "ssl3",
  "tls1.0",
  "tls1.1",
  "tls1.2",
  "tls1.3",
] as const;

/** Strings accepted as TLS version input (case-insensitive). */
export const TLS_VERSION_ALIASES: Readonly<Record<string, string>> = {
  ssl3: "ssl3",
  tls1_0: "tls1.0",
  tls1: "tls1.0",
  "tls1.0": "tls1.0",
  tls1_1: "tls1.1",
  "tls1.1": "tls1.1",
  tls1_2: "tls1.2",
  "tls1.2": "tls1.2",
  tls1_3: "tls1.3",
  "tls1.3": "tls1.3",
};

/** Canonically normalize a domain: lowercase, trim, strip one trailing dot. */
export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.+$/, "");
}

/**
 * Extract the domain part of an email address (everything after the last "@").
 * Returns null when the input does not contain an "@". Pure helper — no
 * validation beyond that; callers decide policy.
 */
export function emailDomain(address: string): string | null {
  const trimmed = address.trim();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1) return null;
  const domain = trimmed.slice(at + 1);
  return domain.length === 0 ? null : domain;
}

/** True when the given string is a plausible domain label sequence. */
export function isPlausibleDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
  if (normalized.length === 0 || normalized.length > 253) return false;
  const labels = normalized.split(".");
  if (labels.length < 2) return false;
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label),
  );
}
