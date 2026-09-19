import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";

let dir: string | null = null;

export function makeTempDbPath(): string {
  dir = mkdtempSync(join(tmpdir(), "kiwi-admin-test-"));
  return join(dir, "kiwi-admin.db");
}

afterAll(() => {
  if (dir) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
});

