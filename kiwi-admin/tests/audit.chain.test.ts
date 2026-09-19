import { describe, it, expect } from "vitest";
import { InMemoryAuditLog, auditReplay, computeEntryHash, canonicalEventJson } from "../src/audit/chain.js";
import { parseAuditEventInput } from "../src/audit/model.js";
import type { AuditEventInput } from "../src/audit/model.js";

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

describe("audit chain integrity", () => {
  it("chains entries: each prev_hash equals previous entry_hash", () => {
    const log = new InMemoryAuditLog();
    const a = log.append(event({ requestId: "r1" }), 1000);
    const b = log.append(event({ requestId: "r2" }), 1010);
    const c = log.append(event({ requestId: "r3" }), 1020);
    expect(a.prev_hash).toBe("genesis");
    expect(b.prev_hash).toBe(a.entry_hash);
    expect(c.prev_hash).toBe(b.entry_hash);
    expect(log.verify()).toEqual({ valid: true, error: null });
  });

  it("detects tampering with a historical field", () => {
    const log = new InMemoryAuditLog();
    log.append(event(), 1000);
    log.append(event(), 1010);
    // simulate in-place tamper of the first record's action
    (log.records[0] as { action: string }).action = "policy.delete";
    const result = log.verify();
    expect(result.valid).toBe(false);
    expect(result.error).toContain("chain broken at seq 1");
  });

  it("detects deletion of a middle record via replay", () => {
    const log = new InMemoryAuditLog();
    log.append(event(), 1000);
    log.append(event(), 1010);
    log.append(event(), 1020);
    const mutated = log.records.filter((r) => r.seq !== 2);
    const result = auditReplay(mutated);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("chain broken at seq 3");
  });

  it("entry_hash is SHA-256 over canonical event JSON + prev_hash", () => {
    const input = event();
    const json = canonicalEventJson(input);
    const hash = computeEntryHash(json, "genesis");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    // determinism
    expect(computeEntryHash(json, "genesis")).toBe(hash);
  });

  it("parseAuditEventInput validates untrusted payloads", () => {
    expect(() => parseAuditEventInput(null)).toThrow();
    expect(() => parseAuditEventInput({ action: "" })).toThrow();
    const ok = parseAuditEventInput({ action: "org.create", actor: { subject: "u1", roles: ["viewer"] } });
    expect(ok.action).toBe("org.create");
    expect(ok.actor.subject).toBe("u1");
    expect(ok.outcome).toBe("allowed"); // default
    // unknown role strings are dropped, not fatal
    const roles = parseAuditEventInput({ action: "x", actor: { subject: "u1", roles: ["bogus", "viewer"] } });
    expect(roles.actor.roles).toEqual(["viewer"]);
  });
});
