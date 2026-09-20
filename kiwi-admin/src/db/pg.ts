/**
 * PostgreSQL connection + Drizzle binding (PRIMARY service dialect, ADR-006).
 * The connection string is ALWAYS caller-supplied (env `DATABASE_URL` from the
 * compose/test harness — Agent 6 T-131). No credentials in code, logs, or
 * migrations (SECURITY.md rules 5–6). Migrations in `drizzle/pg/`.
 */
import { Pool } from "pg";
import { fileURLToPath } from "node:url";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import * as schema from "./schema.pg.js";

export type PgDrizzle = NodePgDatabase<typeof schema>;

export interface PgConnection {
  pool: Pool;
  db: PgDrizzle;
}

export function openPg(connectionString: string): PgConnection {
  if (!connectionString) throw new Error("openPg: connection string required (provide DATABASE_URL from the environment)");
  const pool = new Pool({ connectionString });
  const db = drizzle(pool, { schema });
  return { pool, db };
}

/** Applies pending Drizzle migrations; idempotent (journal-tracked). */
export async function migratePg(db: PgDrizzle): Promise<void> {
  await migrate(db, {
    migrationsFolder: fileURLToPath(new URL("../../drizzle/pg", import.meta.url)),
  });
}
