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
  const admin: Actor = { subject: "export-admin@acme.test", roles: ["org_admin"], orgId: null };
  const secAdmin: Actor = { subject: "export-sec@acme.test", roles: ["security_admin"], orgId: null };
  const viewer: Actor = { subject: "export-view@acme.test", roles: ["viewer"], orgId: null };

  beforeAll(async () => {
    container = await createServiceContainer(makeTempDbPath());
    orgId = (await container.orgs.createOrg(admin, "export-acme.test", 900)).id;
  });

  afterAll(async () => {
    await container.close();
  });

  it("lets org_admin export the whole chain, signed", async () => {
    // Read the log BEFORE exporting: the export appends its own audit row, so
    // a post-export read would be one row ahead of the snapshot.
    const all = await container.audit.query(admin, { limit: 1000 });
    const out = await container.audit.export({ ...admin, orgId }, { now: 1234, key: KEY });
    expect(out.rows).toBeGreaterThan(0);
    expect(out.chainState.valid).toBe(true);
    expect(out.signature.signed).toBe(true);
    expect(out.signature.signature).toBe(hmac(signedBodyOf(out.ndjson)));
    expect(out.header.exported_at).toBe(1234);
    expect(out.header.first_seq).toBe(1);
    // It is the FULL chain: last_seq is the highest seq that existed.
    expect(out.header.last_seq).toBe(all[all.length - 1]?.seq);
  });

  it("refuses security_admin and viewer even though both hold audit.read", async () => {
    // The distinction this test exists for: audit.read is broad, audit.export
    // is org_admin only.
    for (const actor of [secAdmin, viewer]) {
      await expect(container.audit.export({ ...actor, orgId }, { now: 1, key: KEY })).rejects.toThrow(
        AuthorizationDeniedError,
      );
      await expect(container.audit.export(actor, { now: 1, key: KEY })).rejects.toThrow(AuthorizationDeniedError);
    }
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
    const out = await container.audit.export({ ...admin, orgId }, { now: 99, key: KEY });
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
