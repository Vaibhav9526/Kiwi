/** Org/policy repositories — SQLite implementations of db/interfaces.ts. */
import type { Db } from "./interfaces.js";
import type {
  OrgRepository,
  PolicyRuleRepository,
} from "./interfaces.js";
import type { OrgRole, RecipientDomainAction, ExternalRecipientBehavior } from "../types.js";

interface OrgRow {
  id: string;
  name: string;
  created_at: number;
}
interface DomainRow {
  org_id: string;
  domain: string;
  verified: number;
  created_at: number;
}
interface UserRow {
  id: string;
  org_id: string;
  email: string;
  created_at: number;
}
interface DeviceRow {
  id: string;
  org_id: string;
  label: string;
  revoked: number;
  created_at: number;
}
interface PolicyRow {
  id: string;
  org_id: string;
  name: string;
  enabled: number;
  min_tls: string | null;
  external_recipients: ExternalRecipientBehavior;
}

export class SqliteOrgRepository implements OrgRepository {
  constructor(private readonly db: Db) {}

  createOrg(id: string, name: string, now: number): OrgRow {
    this.db.run("INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)", id, name, now);
    return { id, name, created_at: now };
  }

  getOrg(id: string): OrgRow | undefined {
    return this.db.one("SELECT id, name, created_at FROM orgs WHERE id = ?", id) as OrgRow | undefined;
  }

  addDomain(orgId: string, domain: string, now: number): { org_id: string; domain: string; verified: number; created_at: number } {
    this.db.run(
      "INSERT INTO domains (org_id, domain, verified, created_at) VALUES (?, ?, 0, ?) ON CONFLICT(org_id, domain) DO NOTHING",
      orgId,
      domain,
      now,
    );
    return { org_id: orgId, domain, verified: 0, created_at: now };
  }

  listDomains(orgId: string): { domain: string; verified: number }[] {
    return this.db.all("SELECT domain, verified FROM domains WHERE org_id = ? ORDER BY domain", orgId) as {
      domain: string;
      verified: number;
    }[];
  }

  createUser(id: string, orgId: string, email: string, now: number): UserRow {
    this.db.run("INSERT INTO users (id, org_id, email, created_at) VALUES (?, ?, ?, ?)", id, orgId, email, now);
    return { id, org_id: orgId, email, created_at: now };
  }

  getUser(id: string): UserRow | undefined {
    return this.db.one("SELECT id, org_id, email, created_at FROM users WHERE id = ?", id) as UserRow | undefined;
  }

  grantRole(userId: string, orgId: string, role: OrgRole, now: number): void {
    this.db.run(
      "INSERT INTO user_org_roles (user_id, org_id, role, granted_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, org_id) DO UPDATE SET role = excluded.role",
      userId,
      orgId,
      role,
      now,
    );
  }

  listRoles(userId: string): OrgRole[] {
    return (this.db.all("SELECT role FROM user_org_roles WHERE user_id = ?", userId) as { role: OrgRole }[]).map(
      (r) => r.role,
    );
  }

  createDevice(id: string, orgId: string, label: string, now: number): DeviceRow {
    this.db.run("INSERT INTO devices (id, org_id, label, created_at) VALUES (?, ?, ?, ?)", id, orgId, label, now);
    return { id, org_id: orgId, label, revoked: 0, created_at: now };
  }

  getDevice(id: string): DeviceRow | undefined {
    return this.db.one("SELECT id, org_id, label, revoked, created_at FROM devices WHERE id = ?", id) as DeviceRow | undefined;
  }

  revokeDevice(id: string, now: number): void {
    this.db.run("UPDATE devices SET revoked = 1, revoked_at = ? WHERE id = ?", now, id);
  }
}

export class SqlitePolicyRuleRepository implements PolicyRuleRepository {
  constructor(private readonly db: Db) {}

  createPolicy(
    id: string,
    orgId: string,
    name: string,
    enabled: boolean,
    minTls: string | null,
    externalRecipients: ExternalRecipientBehavior,
    now: number,
  ): void {
    this.db.run(
      "INSERT INTO policies (id, org_id, name, enabled, min_tls, external_recipients, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      id,
      orgId,
      name,
      enabled ? 1 : 0,
      minTls,
      externalRecipients,
      now,
      now,
    );
  }

  getPolicy(id: string): PolicyRow | undefined {
    return this.db.one(
      "SELECT id, org_id, name, enabled, min_tls, external_recipients FROM policies WHERE id = ?",
      id,
    ) as PolicyRow | undefined;
  }

  addDomainRule(policyId: string, domain: string, action: RecipientDomainAction): void {
    this.db.run(
      "INSERT INTO policy_domain_rules (policy_id, domain, action) VALUES (?, ?, ?) ON CONFLICT(policy_id, domain) DO UPDATE SET action = excluded.action",
      policyId,
      domain,
      action,
    );
  }

  listDomainRules(policyId: string): { domain: string; action: RecipientDomainAction }[] {
    return this.db.all("SELECT domain, action FROM policy_domain_rules WHERE policy_id = ? ORDER BY domain", policyId) as {
      domain: string;
      action: RecipientDomainAction;
    }[];
  }
}
