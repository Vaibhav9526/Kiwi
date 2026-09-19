/** T-109 mail-flow emitter tests: client-fact → wire-shape builders. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Actor } from "../src/rbac/rbac.js";
import { createServiceContainer } from "../src/services.js";
import type { ServiceContainer } from "../src/services.js";
import { buildSendAttemptEvents, buildReceivedEvent } from "../src/mailflow/emitter.js";
import { parseMailflowIngest } from "../src/mailflow/model.js";
import { makeTempDbPath } from "./helpers/db.js";

let container: ServiceContainer;
let orgId: string;

const admin: Actor = { subject: "emitter-admin@acme.test", roles: ["org_admin"], orgId: null };
const idGen = (() => {
  let n = 0;
  return () => `evt-test-${++n}`;
})();

beforeAll(() => {
  container = createServiceContainer(makeTempDbPath());
  orgId = container.orgs.createOrg(admin, "emitter-acme.test", 2000).id;
});

afterAll(() => {
  container.close();
});

describe("buildSendAttemptEvents", () => {
  it("expands one event per recipient with bridge verdicts", () => {
    const events = buildSendAttemptEvents(
      {
        orgId,
        sender: "alice@emitter-acme.test",
        perRecipient: [
          { recipient: "friend@partner.example", policyVerdict: "allow" },
          { recipient: "bad@evil.example", policyVerdict: "block" },
        ],
        tlsVersion: "tls1.3",
        securityStatus: "clean",
        messageId: "<m1@emitter-acme.test>",
        ts: 2100,
      },
      idGen,
    );
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ direction: "outbound", org_id: orgId, policy_verdict: "allow" });
    expect(events[1]).toMatchObject({ policy_verdict: "block" });
    // Every built event must survive strict ingest parsing (round-trip proof).
    for (const e of events) {
      expect(() => parseMailflowIngest(e, idGen)).not.toThrow();
    }
  });

  it("carries no body/subject/content field by construction", () => {
    const [e] = buildSendAttemptEvents(
      {
        orgId,
        sender: "a@emitter-acme.test",
        perRecipient: [{ recipient: "b@x.test", policyVerdict: "warn" }],
        tlsVersion: null,
        ts: 2110,
      },
      idGen,
    );
    expect(Object.keys(e ?? {})).not.toContain("body");
    expect(Object.keys(e ?? {})).not.toContain("subject");
    expect(Object.keys(e ?? {})).not.toContain("content");
  });

  it("defaults unknown verdict/status instead of failing", () => {
    const [e] = buildSendAttemptEvents(
      {
        orgId,
        sender: "a@emitter-acme.test",
        perRecipient: [{ recipient: "b@x.test", policyVerdict: "bogus" }],
        tlsVersion: null,
        securityStatus: "bogus",
        ts: 2120,
      },
      idGen,
    );
    expect(e?.policy_verdict).toBe("unknown");
    expect(e?.security_status).toBe("unknown");
  });

  it("rejects domain-less recipients and bad TLS labels", () => {
    expect(() =>
      buildSendAttemptEvents(
        { orgId, sender: "a@b.test", perRecipient: [{ recipient: "not-an-address", policyVerdict: "allow" }], tlsVersion: null, ts: 1 },
        idGen,
      ),
    ).toThrow(/recipient/);
    expect(() =>
      buildSendAttemptEvents(
        { orgId, sender: "a@b.test", perRecipient: [{ recipient: "b@c.test", policyVerdict: "allow" }], tlsVersion: "TLS9", ts: 1 },
        idGen,
      ),
    ).toThrow(/tlsVersion/);
  });

  it("emitter output ingests end-to-end through the service", () => {
    const actor: Actor = { ...admin, orgId };
    const events = buildSendAttemptEvents(
      {
        orgId,
        sender: "alice@emitter-acme.test",
        perRecipient: [{ recipient: "friend@partner.example", policyVerdict: "allow" }],
        tlsVersion: "tls1.3",
        ts: 2130,
      },
      idGen,
    );
    for (const e of events) {
      const res = container.mailflow.ingest(actor, {
        direction: e.direction,
        sender: e.sender,
        recipient: e.recipient,
        ts: e.ts,
        message_id: e.message_id,
        tls_version: e.tls_version,
        security_status: e.security_status,
        policy_verdict: e.policy_verdict,
        org_id: e.org_id,
      });
      expect(res.id).toBeTruthy();
    }
    expect(container.mailflow.query(actor, { orgId, limit: 10 }).items.length).toBeGreaterThanOrEqual(1);
  });
});

describe("buildReceivedEvent", () => {
  it("builds inbound events with nullable org", () => {
    const e = buildReceivedEvent(
      {
        orgId: null,
        sender: "x@other.test",
        recipient: "alice@emitter-acme.test",
        tlsVersion: "tls1.2",
        ts: 2140,
      },
      idGen,
    );
    expect(e.direction).toBe("inbound");
    expect(e.org_id).toBeNull();
    expect(e.policy_verdict).toBe("unknown");
    expect(() => parseMailflowIngest(e, idGen)).not.toThrow();
  });
});
