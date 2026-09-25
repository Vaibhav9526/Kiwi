/**
 * T-179 audit export tests: NDJSON layout, the signed trailer, and the
 * org_admin-only permission.
 *
 * The point of an export is that someone who does not trust this service can
 * check it, so these tests recompute the HMAC exactly as an outside verifier
 * would rather than asserting the signature is merely present.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHmac } from "node:crypto";
import { InMemoryAuditLog } from "../src/audit/chain.js";
import {
  buildAuditExport,
  auditExportKeyId,
  AUDIT_EXPORT_VERSION,
  ORG_AUDIT_EXPORT_VERSION,
  type AuditExportChainState,
  type AuditExportHeader,
  type AuditExportSignature,
} from "../src/audit/export.js";
import { AuthorizationDeniedError } from "../src/rbac/rbac.js";
import type { Actor } from "../src/rbac/rbac.js";
import { createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import type { AuditEventInput } from "../src/audit/model.js";
import { makeTempDbPath } from "./helpers/db.js";

const KEY = "test-export-key-not-a-real-secret";

const event = (overrides: Partial<AuditEventInput> = {}): AuditEventInput => ({
  actor: { subject: "admin@acme.test", roles: ["org_admin"] },
  orgId: "org-acme",
  action: "policy.update",
  resource: "policy-123",
  outcome: "allowed",
  requestId: "req-1",
  details: { enabled: true },
  ...overrides,
});

/** Parse NDJSON into objects, dropping the trailing-newline empty element. */
function parseLines(ndjson: string): unknown[] {
  return ndjson
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as unknown);
}

/** Everything the signature is supposed to cover: all lines but the last. */
function signedBodyOf(ndjson: string): string {
  return ndjson.split("\n").filter((l) => l.length > 0).slice(0, -1).join("\n");
}

function hmac(body: string, key = KEY): string {
  return createHmac("sha256", key).update(body).digest("hex");
}

function seedLog(count = 2): InMemoryAuditLog {
  const log = new InMemoryAuditLog();
  for (let i = 0; i < count; i += 1) log.append(event({ requestId: `r${i + 1}` }), 1000 + i * 10);
  return log;
}

describe("buildAuditExport — NDJSON layout", () => {
  it("emits header, one line per record, chain state, then the signature", () => {
    const log = seedLog(2);
    const out = buildAuditExport(log.records, { now: 7777, key: KEY });
    const parsed = parseLines(out.ndjson);

    expect(parsed).toHaveLength(5); // header + 2 records + chain_state + signature
    const header = parsed[0] as AuditExportHeader;
    expect(header.type).toBe("header");
    expect(header.version).toBe(AUDIT_EXPORT_VERSION);
    expect(header.exported_at).toBe(7777);
    expect(header.rows).toBe(2);
    expect(header.first_seq).toBe(1);
    expect(header.last_seq).toBe(2);

    // The record lines are the records themselves, chain fields included —
    // that is what makes the export independently re-verifiable.
    const first = parsed[1] as Record<string, unknown>;
    expect(first["seq"]).toBe(1);
    expect(first["prev_hash"]).toBe("genesis");
    expect(typeof first["entry_hash"]).toBe("string");
    expect(first["action"]).toBe("policy.update");

    const state = parsed[3] as AuditExportChainState;
    expect(state.type).toBe("chain_state");
    expect(state.valid).toBe(true);
    expect(state.error).toBeNull();
    expect(state.checked).toBe(2);
    expect(state.head_hash).toBe((parsed[2] as Record<string, unknown>)["entry_hash"]);

    expect((parsed[4] as AuditExportSignature).type).toBe("signature");
    // Exactly one trailing newline: NDJSON, no trailing blank line.
    expect(out.ndjson.endsWith("\n")).toBe(true);
    expect(out.ndjson.endsWith("\n\n")).toBe(false);
  });

  it("terminates every line, and is byte-stable for identical inputs", () => {
    const log = seedLog(3);
    const a = buildAuditExport(log.records, { now: 42, key: KEY });
    const b = buildAuditExport(log.records, { now: 42, key: KEY });
    expect(a.ndjson).toBe(b.ndjson);
    expect(a.ndjson.split("\n").filter((l) => l !== "")).toHaveLength(6);
  });
});

describe("buildAuditExport — signature", () => {
  it("is an HMAC-SHA256 a third party can recompute from the export alone", () => {
    const out = buildAuditExport(seedLog(2).records, { now: 7777, key: KEY });
    const sig = out.signature;
    expect(sig.alg).toBe("hmac-sha256");
    expect(sig.signed).toBe(true);
    expect(sig.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(sig.signature).toBe(hmac(signedBodyOf(out.ndjson)));
    // Covers every line before it, and says so.
    expect(sig.covers_through).toBe(4);
  });

  it("covers the chain-state line, so the integrity claim cannot be edited", () => {
    const out = buildAuditExport(seedLog(2).records, { now: 7777, key: KEY });
    const body = signedBodyOf(out.ndjson);
    expect(body).toContain('"valid":true');
    // Flip the claim the way a tamperer would; the published signature stops matching.
    const flipped = body.replace('"valid":true', '"valid":false');
    expect(flipped).not.toBe(body);
    expect(hmac(flipped)).not.toBe(out.signature.signature);
  });

  it("covers the header, so the export timestamp cannot be edited", () => {
    const out = buildAuditExport(seedLog(2).records, { now: 7777, key: KEY });
    const body = signedBodyOf(out.ndjson);
    expect(hmac(body.replace('"exported_at":7777', '"exported_at":1'))).not.toBe(out.signature.signature);
  });

  it("reports a wrong key as a mismatch rather than passing", () => {
    const out = buildAuditExport(seedLog(2).records, { now: 1, key: KEY });
    expect(hmac(signedBodyOf(out.ndjson), "some-other-key")).not.toBe(out.signature.signature);
  });

  it("publishes a key fingerprint, never the key", () => {
    const out = buildAuditExport(seedLog(1).records, { now: 1, key: KEY });
    const id = auditExportKeyId(KEY);
    expect(out.signature.key_id).toBe(id);
    expect(id).toMatch(/^[0-9a-f]{16}$/);
    expect(out.signature.key_id).not.toContain(KEY);
    expect(out.ndjson).not.toContain(KEY);
    // Distinct keys fingerprint differently.
    expect(auditExportKeyId("another-key")).not.toBe(id);
  });

  it("is honest when unsigned: no key yields signed:false, never a placeholder", () => {
    for (const key of [null, "", "   "]) {
      const out = buildAuditExport(seedLog(2).records, { now: 5, key });
      const parsed = parseLines(out.ndjson);
      const sig = parsed[parsed.length - 1] as AuditExportSignature;
      expect(sig.type).toBe("signature");
      expect(sig.signed).toBe(false);
      expect(sig.alg).toBe("none");
      expect(sig.signature).toBeNull();
      expect(sig.key_id).toBeNull();
      expect(sig.covers_through).toBeNull();
      // Still a complete, well-formed export.
      expect(parsed).toHaveLength(5);
      expect((parsed[3] as AuditExportChainState).valid).toBe(true);
    }
  });
});

describe("buildAuditExport — chain state is reported, not assumed", () => {
  it("flags a tampered record instead of hiding it", () => {
    const log = seedLog(3);
    // Rewrite a historical action the way the tamper probe does.
    (log.records[0] as { action: string }).action = "policy.delete";
    const out = buildAuditExport(log.records, { now: 1, key: KEY });

    expect(out.chainState.valid).toBe(false);
    expect(out.chainState.error).toContain("chain broken at seq 1");
    expect(out.chainState.checked).toBe(0); // nothing verified before the bad row
    // The rows are still exported — the reader re-derives the same verdict.
    expect(out.rows).toBe(3);
    // chain_state sits at index rows+1 (header, then one line per record).
    const parsed = parseLines(out.ndjson);
    expect((parsed[out.rows + 1] as AuditExportChainState).valid).toBe(false);
    expect((parsed[parsed.length - 1] as AuditExportSignature).type).toBe("signature");
  });

  it("flags a seq gap as non-contiguous", () => {
    const log = seedLog(3);
    const withGap = log.records.filter((r) => r.seq !== 2);
    const out = buildAuditExport(withGap, { now: 1, key: KEY });
    expect(out.chainState.valid).toBe(false);
    expect(out.chainState.error).toContain("non-contiguous");
  });

  it("handles an empty log without inventing rows", () => {
    const out = buildAuditExport([], { now: 9, key: KEY });
    const parsed = parseLines(out.ndjson);
    expect(parsed).toHaveLength(3); // header + chain_state + signature
    expect((parsed[0] as AuditExportHeader).rows).toBe(0);
    expect((parsed[0] as AuditExportHeader).first_seq).toBeNull();
    const state = parsed[1] as AuditExportChainState;
    expect(state.valid).toBe(true);
    expect(state.checked).toBe(0);
    expect(state.head_hash).toBe("genesis");
  });
});

describe("AuditService.export — access control", () => {
  let container: ServiceContainer;
  let orgId: string;
  // §13 (T-188/T-259): the GLOBAL export is the distinct platform role
  // `system-admin`; org_admin keeps `audit.export` only org-scoped now.
  const sysadmin: Actor = { subject: "export-admin@acme.test", roles: ["system-admin"], orgId: null };
  const admin: Actor = { subject: "export-admin@acme.test", roles: ["org_admin"], orgId: null };
  const secAdmin: Actor = { subject: "export-sec@acme.test", roles: ["security_admin"], orgId: null };
  const viewer: Actor = { subject: "export-view@acme.test", roles: ["viewer"], orgId: null };

  beforeAll(async () => {
    container = await createServiceContainer(makeTempDbPath());
    // org_admin seeds the org — system-admin deliberately holds ONLY
    // `audit.export` (minimal platform role), never `org.create`/`audit.read`.
    orgId = (await container.orgs.createOrg(admin, "export-acme.test", 900)).id;
  });

  afterAll(async () => {
    await container.close();
  });

  it("lets system-admin export the whole chain, signed", async () => {
    // Read the log BEFORE exporting: the export appends its own audit row, so
    // a post-export read would be one row ahead of the snapshot. (The
    // org-agnostic read is the unbound org_admin's — system-admin has no
    // audit.read by design.)
    const all = await container.audit.query(admin, { limit: 1000 });
    const out = await container.audit.export(sysadmin, { now: 1234, key: KEY });
    expect(out.rows).toBeGreaterThan(0);
    expect(out.chainState.valid).toBe(true);
    expect(out.signature.signed).toBe(true);
    expect(out.signature.signature).toBe(hmac(signedBodyOf(out.ndjson)));
    expect(out.header.exported_at).toBe(1234);
    expect(out.header.first_seq).toBe(1);
    // It is the FULL chain: last_seq is the highest seq that existed.
    expect(out.header.last_seq).toBe(all[all.length - 1]?.seq);
  });

  it("refuses org_admin, security_admin and viewer — only system-admin may export globally", async () => {
    // The distinction this test exists for: audit.read is broad, audit.export
    // is narrower, and the GLOBAL export is narrower still — org_admin holds
    // audit.export org-scoped but must NOT satisfy the global route (§13).
    for (const actor of [admin, secAdmin, viewer]) {
      await expect(container.audit.export({ ...actor, orgId }, { now: 1, key: KEY })).rejects.toThrow(
        AuthorizationDeniedError,
      );
      await expect(container.audit.export(actor, { now: 1, key: KEY })).rejects.toThrow(AuthorizationDeniedError);
    }
  });

  it("audits a refused global export (ADM-T250-06)", async () => {
    // §13.4: denial rows for export — read back via the platform audit.read.
    const r = await apiAuditDenied(container, admin);
    const denial = r.filter(
      (row) => row.action === "audit.export" && row.outcome === "denied" && row.org_id === null,
    );
    expect(denial.length).toBeGreaterThan(0);
  });

  it("refuses a role-less actor", async () => {
    const anonymous: Actor = { subject: "nobody", roles: [], orgId: null };
    await expect(container.audit.export(anonymous, { now: 1, key: KEY })).rejects.toThrow(AuthorizationDeniedError);
  });

  it("records the export itself in the log it exported from", async () => {
    // An export takes a signed copy of the whole log off-box, so it must leave
    // a trace. It is appended after the snapshot, so the artifact covers the
    // chain as it stood immediately before its own record.
    const before = await container.audit.verify(admin, { limit: 1000 });
    const out = await container.audit.export(sysadmin, { now: 99, key: KEY });
    expect(out.header.last_seq).toBe(before.checked);
    expect(out.rows).toBe(before.checked);

    const after = await container.audit.query(admin, { limit: 1000 });
    expect(after).toHaveLength(before.checked + 1);
    const last = after[after.length - 1];
    expect(last?.action).toBe("audit.export");
    expect(last?.outcome).toBe("allowed");
    // The record names the key by fingerprint only.
    expect(last?.details).not.toContain(KEY);
    expect(last?.details).toContain(auditExportKeyId(KEY));
  });
});

/** Trigger a denied global export, then return the log rows (platform read). */
async function apiAuditDenied(container: ServiceContainer, reader: Actor) {
  const denied: Actor = { subject: "denied-admin", roles: ["org_admin"], orgId: null };
  await expect(container.audit.export(denied, { now: 1, key: KEY })).rejects.toThrow(AuthorizationDeniedError);
  return container.audit.query(reader, { limit: 1000 });
}

describe("AuditService.exportOrg — org-scoped export (T-259/ADM-T250-07)", () => {
  let container: ServiceContainer;
  let orgA: string;
  let orgB: string;
  const bootstrap: Actor = { subject: "seed", roles: ["org_admin"], orgId: null };
  const adminA: Actor = { subject: "admin-a@test", roles: ["org_admin"], orgId: "" };
  const reader: Actor = { subject: "reader@test", roles: ["org_admin"], orgId: null };

  beforeAll(async () => {
    container = await createServiceContainer(makeTempDbPath());
    orgA = (await container.orgs.createOrg(bootstrap, "exp-org-a.test", 900)).id;
    orgB = (await container.orgs.createOrg(bootstrap, "exp-org-b.test", 901)).id;
    adminA.orgId = orgA;
    // Seed org-scoped rows in BOTH orgs so the slice is provably filtered.
    await container.orgs.createUser({ ...bootstrap, orgId: orgA }, orgA, "a@exp-org-a.test", 1000);
    await container.orgs.createUser({ ...bootstrap, orgId: orgB }, orgB, "b@exp-org-b.test", 1001);
  });

  afterAll(async () => {
    await container.close();
  });

  it("returns only the path org's rows, signed, with an honest scope_state", async () => {
    const out = await container.audit.exportOrg(adminA, orgA, { now: 555, key: KEY });
    const lines = parseLines(out.ndjson);
    const header = lines[0] as {
      type: string; version: string; scope: string; org_id: string; exported_at: number; rows: number;
    };
    expect(header.type).toBe("header");
    expect(header.version).toBe(ORG_AUDIT_EXPORT_VERSION);
    expect(header.scope).toBe("org");
    expect(header.org_id).toBe(orgA);
    expect(header.exported_at).toBe(555);

    // Every record line belongs to orgA — orgB's rows never appear.
    const records = lines.slice(1, -2) as { org_id: string | null }[];
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((r) => r.org_id === orgA)).toBe(true);
    expect(records.some((r) => r.org_id === orgB)).toBe(false);

    // The trailer is scope_state — it claims NO chain verdict, explicitly.
    const scope = lines[lines.length - 2] as { type: string; org_id: string; chain_claim: string };
    expect(scope.type).toBe("scope_state");
    expect(scope.org_id).toBe(orgA);
    expect(scope.chain_claim).toBe("none");
    expect(JSON.stringify(lines)).not.toContain('"chain_state"');

    // Signed over header + records + scope_state, like the global artifact.
    const sig = lines[lines.length - 1] as { type: string; alg: string; signed: boolean; signature: string };
    expect(sig.type).toBe("signature");
    expect(sig.alg).toBe("hmac-sha256");
    expect(sig.signature).toBe(hmac(signedBodyOf(out.ndjson)));
    expect(out.ndjson).not.toContain(KEY);
  });

  it("records the export with org_id = the path org (§13.4)", async () => {
    const out = await container.audit.exportOrg(adminA, orgA, { now: 556, key: KEY });
    const all = await container.audit.query(reader, { limit: 1000 });
    const last = all[all.length - 1];
    expect(last?.action).toBe("audit.export");
    expect(last?.outcome).toBe("allowed");
    expect(last?.org_id).toBe(orgA); // never a null/global row (§13.4)
    expect(last?.details).toContain('"scope":"org"');
    // Snapshot-first: the artifact's last row precedes its own self-audit row.
    expect(out.header.last_seq).not.toBeNull();
    expect(last?.seq).toBeGreaterThan(out.header.last_seq as number);
  });

  it("denies org_admin a foreign org and audits the denial", async () => {
    await expect(container.audit.exportOrg(adminA, orgB, { now: 1, key: KEY })).rejects.toThrow(
      AuthorizationDeniedError,
    );
    const all = await container.audit.query(reader, { limit: 1000 });
    const denial = all.filter((r) => r.action === "audit.export" && r.outcome === "denied" && r.org_id === orgB);
    expect(denial.length).toBeGreaterThan(0);
  });

  it("denies the unbound system-admin on the org route (its surface is global)", async () => {
    const sysadmin: Actor = { subject: "sys", roles: ["system-admin"], orgId: null };
    await expect(container.audit.exportOrg(sysadmin, orgA, { now: 1, key: KEY })).rejects.toThrow(
      AuthorizationDeniedError,
    );
  });
});
