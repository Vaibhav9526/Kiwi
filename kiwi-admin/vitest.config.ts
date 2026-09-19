import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // node:sqlite emits an experimental warning on some Node versions; keep output clean.
    onConsoleLog(_log, type) {
      if (type === "stderr" && _log.includes("ExperimentalWarning")) return false;
      return undefined;
    },
  },
});
