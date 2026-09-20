/**
 * Drizzle schema — PostgreSQL dialect (PRIMARY per ADR-006).
 * Source of truth for service/organization data. Mirrors
 * docs/contracts/admin-api.md §4 exactly; any change here requires a new
 * Drizzle Kit migration (`npm run db:generate`) + Lead contract review.
 *
 * Conventions: snake_case columns (match the v1 SQLite DDL); Unix-second
 * integers for timestamps (bigint — no 2038 overflow); roles/behaviors as
 * TEXT + CHECK (not native enums — new values must not require ALTER TYPE).
 * No secrets in any column by design (SECURITY.md rules 5–6).
 */
import { relations, sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  index,
  pgTable,
  primaryKey,
  text,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const orgs = pgTable("orgs", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  createdAt: bigint("created_at", { mode: "number" }).notNull(),
});

export const domains = pgTable(
  "domains",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    verified: boolean("verified").notNull().default(false),
    createdAt: bigint("created_at", { mode: "number" }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.domain] })],
);

export const users = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    orgId: text("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    createdAt: bigint("created_at", { mode: "number" }).notNull(),
  },
  (t) => [uniqueIndex("idx_users_org_email").on(t.orgId, t.email)],
);

export const userOrgRoles = pgTable(
  "user_org_roles",
  {
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    orgId: text("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    grantedAt: bigint("granted_at", { mode: "number" }).notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.orgId] }),
    check("user_org_roles_role_check", sql`${t.role} IN ('org_admin','security_admin','viewer')`),
  ],
);

export const devices = pgTable("devices", {
  id: text("id").primaryKey(),
  orgId: text("org_id")
    .notNull()
    .references(() => orgs.id, { onDelete: "cascade" }),
  label: text("label").notNull(),
  revoked: boolean("revoked").notNull().default(false),
  revokedAt: bigint("revoked_at", { mode: "number" }),
  createdAt: bigint("created_at", { mode: "number" }).notNull(),
});

export const policies = pgTable("policies", {
  id: text("id").primaryKey(),
  orgId: text("org_id")
    .notNull()
    .references(() => orgs.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  minTls: text("min_tls"),
  externalRecipients: text("external_recipients").notNull().default("allow"),
  createdAt: bigint("created_at", { mode: "number" }).notNull(),
  updatedAt: bigint("updated_at", { mode: "number" }).notNull(),
}, (t) => [
  check("policies_external_recipients_check", sql`${t.externalRecipients} IN ('allow','warn','block')`),
]);

export const policyDomainRules = pgTable(
  "policy_domain_rules",
  {
    policyId: text("policy_id")
      .notNull()
      .references(() => policies.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    action: text("action").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.policyId, t.domain] }),
    check("policy_domain_rules_action_check", sql`${t.action} IN ('allow','block')`),
  ],
);

export const mailflowEvents = pgTable(
  "mailflow_events",
  {
    id: text("id").primaryKey(),
    orgId: text("org_id"),
    direction: text("direction").notNull(),
    sender: text("sender").notNull(),
    recipient: text("recipient").notNull(),
    ts: bigint("ts", { mode: "number" }).notNull(),
    messageId: text("message_id"),
    tlsVersion: text("tls_version"),
    securityStatus: text("security_status").notNull().default("unknown"),
    policyVerdict: text("policy_verdict").notNull().default("unknown"),
    receivedAt: bigint("received_at", { mode: "number" }).notNull(),
  },
  (t) => [
    index("idx_mailflow_org_ts").on(t.orgId, t.ts),
    index("idx_mailflow_recipient").on(t.recipient),
    check("mailflow_direction_check", sql`${t.direction} IN ('inbound','outbound')`),
    check(
      "mailflow_policy_verdict_check",
      sql`${t.policyVerdict} IN ('allow','warn','block','unknown')`,
    ),
  ],
);

export const auditLog = pgTable(
  "audit_log",
  {
    // App-assigned contiguous sequence (services own seq = last+1); no DB
    // sequence, so replicas/restores cannot silently renumber history.
    seq: bigint("seq", { mode: "number" }).primaryKey(),
    ts: bigint("ts", { mode: "number" }).notNull(),
    actorSubject: text("actor_subject"),
    actorRoles: text("actor_roles"),
    orgId: text("org_id"),
    action: text("action").notNull(),
    resource: text("resource"),
    outcome: text("outcome").notNull(),
    requestId: text("request_id"),
    details: text("details"),
    prevHash: text("prev_hash").notNull(),
    entryHash: text("entry_hash").notNull(),
  },
  (t) => [check("audit_outcome_check", sql`${t.outcome} IN ('allowed','denied','error')`)],
);

// Typed relations (swappable PG/SQLite behind repository interfaces).
export const orgsRelations = relations(orgs, ({ many }) => ({
  domains: many(domains),
  users: many(users),
  devices: many(devices),
  policies: many(policies),
}));

export const domainsRelations = relations(domains, ({ one }) => ({
  org: one(orgs, { fields: [domains.orgId], references: [orgs.id] }),
}));

export const usersRelations = relations(users, ({ one, many }) => ({
  org: one(orgs, { fields: [users.orgId], references: [orgs.id] }),
  roles: many(userOrgRoles),
}));

export const userOrgRolesRelations = relations(userOrgRoles, ({ one }) => ({
  user: one(users, { fields: [userOrgRoles.userId], references: [users.id] }),
  org: one(orgs, { fields: [userOrgRoles.orgId], references: [orgs.id] }),
}));

export const devicesRelations = relations(devices, ({ one }) => ({
  org: one(orgs, { fields: [devices.orgId], references: [orgs.id] }),
}));

export const policiesRelations = relations(policies, ({ one, many }) => ({
  org: one(orgs, { fields: [policies.orgId], references: [orgs.id] }),
  domainRules: many(policyDomainRules),
}));

export const policyDomainRulesRelations = relations(policyDomainRules, ({ one }) => ({
  policy: one(policies, { fields: [policyDomainRules.policyId], references: [policies.id] }),
}));
