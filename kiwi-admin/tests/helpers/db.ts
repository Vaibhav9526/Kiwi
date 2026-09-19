import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach } from "vitest";

let dir: string | null = null;

export function makeTempDbPath(): string {
  dir = mkdtempSync(join(tmpdir(), "kiwi-admin-test-"));
  return join(dir, "kiwi-admin.db");
}

beforeEach(() => {
  // no-op hook kept so suites can rely on consistent vitest lifecycle
});

afterAll(() => {
  if (dir) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
});

export function openMemoryDb(): DatabaseSync {
  return new DatabaseSync(":memory:");
}
