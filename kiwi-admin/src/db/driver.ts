import { DatabaseSync } from "node:sqlite";
import type { Db, SqlParam } from "./interfaces.js";

export { DatabaseSync };
export type { Db, SqlParam };

/**
 * Open a SQLite file (or ":memory:") and return the dialect-neutral Db
 * facade used by all repositories. `ensureMigrated` must be called before
 * repositories are used (done by ServiceContainer).
 */
export function openDb(file: string): Db {
  const sqlite = new DatabaseSync(file);
  sqlite.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  const toSupported = (p: SqlParam): string | number | bigint | null =>
    typeof p === "boolean" ? (p ? 1 : 0) : (p as string | number | bigint | null);
  return {
    exec: (sql) => sqlite.exec(sql),
    run: (sql, ...params) => {
      sqlite.prepare(sql).run(...params.map(toSupported));
    },
    one: (sql, ...params) => sqlite.prepare(sql).get(...params.map(toSupported)),
    all: (sql, ...params) => sqlite.prepare(sql).all(...params.map(toSupported)),
  };
}
