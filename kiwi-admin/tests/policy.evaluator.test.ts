import { describe, it, expect } from "vitest";
import { evaluatePolicy } from "../src/policy/evaluator.js";
import type { PolicyDefinition, PolicyInput } from "../src/policy/model.js";

const basePolicy: PolicyDefinition = {
  id: "pol-1",
  enabled: true,
  minTls: "tls1.2",
  externalRecipients: "warn",
  domainRules: [
    { domain: "Partner.Example", action: "allow" },
    { domain: "evil.example", action: "block" },
  ],
};

const outbound = (overrides: Partial<PolicyInput> = {}): PolicyInput => ({
  direction: "outbound",
  sender: "alice@acme.test",
  recipient: "bob@partner.example",
  tlsVersion: "tls1.3",
  ...overrides,
});

describe("policy evaluator — recipient domains", () => {
  it("allows a recipient on an explicit allow rule (case-insensitive domain match)", () => {
    const d = evaluatePolicy(basePolicy, outbound({ recipient: "Bob@PARTNER.example" }));
    expect(d.verdict).toBe("allow");
    expect(d.reasons.map((r) => r.code)).toContain("recipient-domain-allowed");
  });

  it("blocks a recipient on an explicit block rule, even with good TLS", () => {
    const d = evaluatePolicy(basePolicy, outbound({ recipient: "x@evil.example" }));
    expect(d.verdict).toBe("block");
    expect(d.reasons.map((r) => r.code)).toContain("recipient-domain-blocked");
  });

  it("blocks an unparseable recipient deterministically", () => {
    const d = evaluatePolicy(basePolicy, outbound({ recipient: "not-an-address" }));
    expect(d.verdict).toBe("block");
    expect(d.reasons.map((r) => r.code)).toContain("recipient-unparseable");
  });

  it("warns on external recipients when policy behavior is warn", () => {
    const d = evaluatePolicy(basePolicy, outbound({ recipient: "stranger@unknown.test" }));
    expect(d.verdict).toBe("warn");
    expect(d.reasons.map((r) => r.code)).toContain("external-recipient");
  });

  it("blocks external recipients when policy behavior is block", () => {
    const d = evaluatePolicy({ ...basePolicy, externalRecipients: "block" }, outbound({ recipient: "stranger@unknown.test" }));
    expect(d.verdict).toBe("block");
  });

  it("external allow behavior yields plain allow", () => {
    const d = evaluatePolicy(
      { ...basePolicy, externalRecipients: "allow" },
      outbound({ recipient: "stranger@unknown.test", tlsVersion: "tls1.2" }),
    );
    expect(d.verdict).toBe("allow");
  });
});

describe("policy evaluator — min TLS", () => {
  it("blocks below minimum TLS (tls1.0 < tls1.2)", () => {
    const d = evaluatePolicy(basePolicy, outbound({ tlsVersion: "tls1.0" }));
    expect(d.verdict).toBe("block");
    expect(d.reasons.map((r) => r.code)).toContain("tls-below-minimum");
  });

  it("blocks ssl3 below minimum", () => {
    const d = evaluatePolicy(basePolicy, outbound({ tlsVersion: "ssl3" }));
    expect(d.verdict).toBe("block");
  });

  it("warns (does not block) when TLS version is unverified/unknown", () => {
    const d = evaluatePolicy(basePolicy, outbound({ tlsVersion: null }));
    expect(d.verdict).toBe("warn");
    expect(d.reasons.map((r) => r.code)).toContain("tls-unverified");
  });

  it("accepts the exact minimum version", () => {
    const d = evaluatePolicy(basePolicy, outbound({ tlsVersion: "tls1.2" }));
    expect(d.verdict).toBe("allow");
  });

  it("does not apply min-TLS to inbound direction", () => {
    const d = evaluatePolicy(basePolicy, { ...outbound({ tlsVersion: "tls1.0" }), direction: "inbound" });
    expect(d.verdict).toBe("allow");
  });
});

describe("policy evaluator — disabled policy & determinism", () => {
  it("disabled policy yields allow with no-policy-enabled reason", () => {
    const d = evaluatePolicy({ ...basePolicy, enabled: false }, outbound({ recipient: "x@evil.example" }));
    expect(d.verdict).toBe("allow");
    expect(d.reasons.map((r) => r.code)).toContain("no-policy-enabled");
  });

  it("is deterministic: same input → identical decision object", () => {
    const input = outbound({ recipient: "mixed@Evil.EXAMPLE", tlsVersion: "tls1.1" });
    expect(evaluatePolicy(basePolicy, input)).toEqual(evaluatePolicy(basePolicy, input));
  });
});
