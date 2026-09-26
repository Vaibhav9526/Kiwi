/**
 * Decision-history evidence (T-194): what the History screen renders.
 */
import { describe, it, expect } from 'vitest';

import { DecisionHistory } from '../../src/protocol/history';
import { FixedClock } from '../../src/protocol/replay';

function entry(id: string, decision: 'approve' | 'deny' | 'expired' = 'deny') {
  return { challengeId: id, event: 'unlock' as const, sessionId: 'boot-test-0001', decision };
}

describe('DecisionHistory', () => {
  it('records one entry per challenge id, first outcome wins', () => {
    const history = new DecisionHistory(new FixedClock(100));
    expect(history.record(entry('c1', 'approve'))).toBe(true);
    expect(history.record(entry('c1', 'deny'))).toBe(false);
    const rows = history.entries();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.decision).toBe('approve');
    expect(rows[0]?.atUnix).toBe(100);
    expect(rows[0]?.delivery).toBe('not-queued');
  });

  it('returns newest first (screen order)', () => {
    const history = new DecisionHistory(new FixedClock(100));
    history.record(entry('old'));
    history.record(entry('new', 'approve'));
    expect(history.entries().map((e) => e.challengeId)).toEqual(['new', 'old']);
  });

  it('marks delivery once the queue has tried the item', () => {
    const history = new DecisionHistory(new FixedClock(100));
    history.record(entry('c1'));
    expect(history.markDelivery('c1', 'delivered')).toBe(true);
    expect(history.entries()[0]?.delivery).toBe('delivered');
    expect(history.markDelivery('missing', 'delivered')).toBe(false);
  });

  it('is bounded — oldest entries evict at capacity', () => {
    const history = new DecisionHistory(new FixedClock(1), 3);
    history.record(entry('a'));
    history.record(entry('b'));
    history.record(entry('c'));
    history.record(entry('d'));
    expect(history.size).toBe(3);
    expect(history.entries().map((e) => e.challengeId)).toEqual(['d', 'c', 'b']);
  });

  it('clears on unpair', () => {
    const history = new DecisionHistory(new FixedClock(1));
    history.record(entry('a'));
    history.clear();
    expect(history.size).toBe(0);
    expect(history.entries()).toEqual([]);
  });
});
