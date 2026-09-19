/**
 * SQLite connection + Drizzle binding (tests + local-first runtime).
 * better-sqlite3 (synchronous, zero-copy rows) + WAL + FK enforcement.
 * Migrations in `drizzle/sqlite/` applied via Drizzle's migrator.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import * as schema from "./schema.sqlite.js";
import type { Db, SqlParam } from "./interfaces.js";

const require = createRequire(import.meta.url);
// CJS driver loaded without esModuleInterop (see tsconfig — NodeNext).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const Database = require("better-sqlite3") as new (file: string) => {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: (string | number | bigint | null)[]): void;
    get(...params: (string | number | bigint | null)[]): unknown;
    all(...params: (string | number | bigint | null)[]): unknown[];
  };
  close(): void;
};

export type SqliteDrizzle = BetterSQLite3Database<typeof schema>;

export interface SqliteConnection {
  raw: { close(): void };
  db: SqliteDrizzle;
  /** Legacy facade (ServiceContainer.db + tests) over the same connection. */
  facade: Db;
}

function toSupported(p: SqlParam): string | number | bigint | null {
  return typeof p === "boolean" ? (p ? 1 : 0) : p;
}

export function openSqlite(file: string): SqliteConnection {
  const raw = new Database(file);
  raw.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  const db = drizzle(raw, { schema });
  const facade: Db = {
    exec: (sql) => raw.exec(sql),
    run: (sql, ...params) => {
      raw.prepare(sql).run(...params.map(toSupported));
    },
    one: (sql, ...params) => raw.prepare(sql).get(...params.map(toSupported)),
    all: (sql, ...params) => raw.prepare(sql).all(...params.map(toSupported)),
  };
  return { raw, db, facade };
}

/** Applies pending Drizzle migrations; idempotent (journal-tracked). */
export function migrateSqlite(db: SqliteDrizzle): void {
  migrate(db, {
    migrationsFolder: fileURLToPath(new URL("../../drizzle/sqlite", import.meta.url)),
  });
}
