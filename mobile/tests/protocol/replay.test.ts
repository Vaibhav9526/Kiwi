/**
 * Replay-ledger evidence (T-136 contract §4.3, §6.4).
 */
import { describe, it, expect } from "vitest";

import { ReplayLedger, FixedClock } from "../../src/protocol/replay";
import { validChallenge } from "../helpers/protocol";

describe("ReplayLedger", () => {
  it("records one answer per challenge id (approve)", () => {
    const ledger = new ReplayLedger(new FixedClock(100));
    const c = validChallenge();
    expect(ledger.record(c.challenge_id, "approve")).toBe(true);
    expect(ledger.record(c.challenge_id, "approve")).toBe(false);
    expect(ledger.record(c.challenge_id, "deny")).toBe(false);
    expect(ledger.isConsumed(c.challenge_id)).toBe(true);
  });

  it("a deny also consumes the id (§6.3/§6.4)", () => {
    const ledger = new ReplayLedger(new FixedClock(100));
    const c = validChallenge();
    expect(ledger.record(c.challenge_id, "deny")).toBe(true);
    expect(ledger.isConsumed(c.challenge_id)).toBe(true);
  });

  it("expiry check uses the injected clock", () => {
    const clock = new FixedClock(100);
    const ledger = new ReplayLedger(clock);
    const c = validChallenge(); // expires = issued + 120
    expect(ledger.isExpired(c)).toBe(false);
    clock.unix = c.expires_unix;
    expect(ledger.isExpired(c)).toBe(true);
  });

  it("prunes only old entries", () => {
    const clock = new FixedClock(100);
    const ledger = new ReplayLedger(clock);
    ledger.record("a", "deny");
    clock.unix = 100 + 3601; // past the 1-hour prune window
    ledger.record("b", "deny");
    expect(ledger.prune(3600)).toBe(1);
    expect(ledger.isConsumed("a")).toBe(false);
    expect(ledger.isConsumed("b")).toBe(true);
  });

  it("is bounded at 256 entries (fail closed, never unbounded)", () => {
    const ledger = new ReplayLedger(new FixedClock(1));
    for (let i = 0; i < ReplayLedger.MAX_ENTRIES; i++) {
      expect(ledger.record(`c${i}`, "deny")).toBe(true);
    }
    expect(ledger.record("overflow", "deny")).toBe(false);
    expect(ledger.size).toBe(ReplayLedger.MAX_ENTRIES);
    expect(ledger.isConsumed("overflow")).toBe(false);
  });
});
