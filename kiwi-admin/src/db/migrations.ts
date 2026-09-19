/**
 * Sequential schema migrations. Each entry runs once, inside a transaction,
 * in order; applied versions are recorded in schema_migrations.
 *
 * Table set (v1 org model — docs/contracts/admin-api.md §4):
 *   orgs, domains, users, user_org_roles, devices, policies, mailflow_events,
 *   audit_log.
 * v2 adds the audit append-only guard (DB triggers — admin-api.md §7):
 *   audit_log rejects UPDATE and DELETE at the storage layer.
 */
export interface Migration {
  version: number;
  name: string;
  up: string;
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "org-model-v1",
    up: `
      CREATE TABLE IF NOT EXISTS orgs (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS domains (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        domain      TEXT NOT NULL,
        verified    INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL,
        PRIMARY KEY (org_id, domain)
      );

      CREATE TABLE IF NOT EXISTS users (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        email       TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        UNIQUE (org_id, email)
      );

      CREATE TABLE IF NOT EXISTS user_org_roles (
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        role        TEXT NOT NULL CHECK (role IN ('org_admin','security_admin','viewer')),
        granted_at  INTEGER NOT NULL,
        PRIMARY KEY (user_id, org_id)
      );

      CREATE TABLE IF NOT EXISTS devices (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        label       TEXT NOT NULL,
        revoked     INTEGER NOT NULL DEFAULT 0,
        revoked_at  INTEGER,
        created_at  INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS policies (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        min_tls     TEXT,
        external_recipients TEXT NOT NULL DEFAULT 'allow'
          CHECK (external_recipients IN ('allow','warn','block')),
        created_at  INTEGER NOT NULL,
        updated_at  INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS policy_domain_rules (
        policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
        domain      TEXT NOT NULL,
        action      TEXT NOT NULL CHECK (action IN ('allow','block')),
        PRIMARY KEY (policy_id, domain)
      );

      CREATE TABLE IF NOT EXISTS mailflow_events (
        id          TEXT PRIMARY KEY,
        org_id      TEXT,
        direction   TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
        sender      TEXT NOT NULL,
        recipient   TEXT NOT NULL,
        ts          INTEGER NOT NULL,
        message_id  TEXT,
        tls_version TEXT,
        security_status TEXT NOT NULL DEFAULT 'unknown',
        policy_verdict  TEXT NOT NULL DEFAULT 'unknown'
          CHECK (policy_verdict IN ('allow','warn','block','unknown')),
        received_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_mailflow_org_ts   ON mailflow_events (org_id, ts);
      CREATE INDEX IF NOT EXISTS idx_mailflow_recipient ON mailflow_events (recipient);

      CREATE TABLE IF NOT EXISTS audit_log (
        seq            INTEGER PRIMARY KEY AUTOINCREMENT,
        ts             INTEGER NOT NULL,
        actor_subject  TEXT,
        actor_roles    TEXT,
        org_id         TEXT,
        action         TEXT NOT NULL,
        resource       TEXT,
        outcome        TEXT NOT NULL CHECK (outcome IN ('allowed','denied','error')),
        request_id     TEXT,
        details        TEXT,
        prev_hash      TEXT NOT NULL,
        entry_hash     TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS schema_migrations (
        version     INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        applied_at  INTEGER NOT NULL
      );
    `,
  },
  {
    version: 2,
    name: "audit-append-only-guard",
    up: `
      -- DB-level append-only guard for audit_log (admin-api.md §7).
      -- Blocks UPDATE and DELETE from ANY connection, including raw SQL from
      -- this process. Honest limit: a file-write holder can DROP TRIGGER first,
      -- so hash-chain verification on read remains the detection layer.
      CREATE TRIGGER IF NOT EXISTS audit_log_no_update
      BEFORE UPDATE ON audit_log
      BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
      END;

      CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
      BEFORE DELETE ON audit_log
      BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
      END;
    `,
  },
];

export function ensureMigrated(driver: {
  exec: (sql: string) => void;
  one: (sql: string, ...params: (null | number | bigint | string | boolean)[]) => unknown;
}): void {
  driver.exec("BEGIN");
  try {
    driver.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)",
    );
    for (const migration of MIGRATIONS) {
      // Idempotent: skip versions already applied so reopening an existing
      // database file (app restart) works instead of throwing on re-INSERT.
      const applied = driver.one("SELECT version FROM schema_migrations WHERE version = ?", migration.version) as
        | { version: number }
        | undefined;
      if (applied) continue;
      driver.exec(
        `INSERT INTO schema_migrations (version, name, applied_at) VALUES (${migration.version}, '${migration.name.replace(/'/g, "''")}', 0)`,
      );
      driver.exec(migration.up);
      driver.exec(`UPDATE schema_migrations SET applied_at = 1 WHERE version = ${migration.version}`);
    }
    driver.exec("COMMIT");
  } catch (err) {
    driver.exec("ROLLBACK");
    throw err;
  }
}
