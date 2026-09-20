import { defineConfig } from "drizzle-kit";

/** Primary dialect: PostgreSQL (service/org data). */
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.pg.ts",
  out: "./drizzle/pg",
  strict: true,
  verbose: true,
});
