/**
 * Sign-then-queue delivery evidence (T-136 contract §7).
 */
import { describe, it, expect } from 'vitest';

import { ChallengeQueue, type QueueTransport } from '../../src/protocol/queue';
import { FixedClock } from '../../src/protocol/replay';
import { validChallenge, fakeSignature } from '../helpers/protocol';
import { buildChallengeResponseData } from '../../src/protocol/canonical';

function offlineTransport(): QueueTransport {
  return { postResponse: async () => ({ kind: 'offline', reason: 'no link' }) };
}

function approveResponse(): { resp: ReturnType<typeof buildChallengeResponseData>; decision: 'approve' } {
  return { resp: buildChallengeResponseData(validChallenge(), 'approve', fakeSignature()), decision: 'approve' };
}

describe('ChallengeQueue (sign-then-queue)', () => {
  it('queues an approve and delivers it in FIFO order', async () => {
    const clock = new FixedClock(100);
    const delivered: string[] = [];
    const transport: QueueTransport = {
      postResponse: async (resp) => {
        delivered.push(resp.challenge_id);
        return { kind: 'delivered', requestId: 'r1' };
      },
    };
    const queue = new ChallengeQueue(transport, clock);
    const { resp, decision } = approveResponse();
    expect(queue.enqueue(validChallenge(), resp, decision)).toEqual({ ok: true });
    expect(queue.size).toBe(1);
    const outcome = await queue.tick();
    expect(outcome).toEqual({ delivered: [validChallenge().challenge_id], offline: [], skipped: 0 });
    expect(queue.size).toBe(0);
    expect(delivered).toEqual([validChallenge().challenge_id]);
  });

  it('holds the item on offline and never drops the signed approval', async () => {
    const clock = new FixedClock(100);
    const queue = new ChallengeQueue(offlineTransport(), clock);
    const { resp, decision } = approveResponse();
    queue.enqueue(validChallenge(), resp, decision);
    const outcome = await queue.tick();
    expect(outcome.offline).toEqual([validChallenge().challenge_id]);
    expect(queue.size).toBe(1); // still queued for retry
  });

  it('throttles re-delivery attempts (min 10 s)', async () => {
    const clock = new FixedClock(100);
    const queue = new ChallengeQueue(offlineTransport(), clock);
    const { resp, decision } = approveResponse();
    queue.enqueue(validChallenge(), resp, decision);
    const first = await queue.deliver(validChallenge().challenge_id);
    expect(first.kind).toBe('offline');
    const second = await queue.deliver(validChallenge().challenge_id);
    expect(second).toEqual({ kind: 'skipped', reason: 'throttled' });
    clock.unix = 111; // past the 10 s window
    const third = await queue.deliver(validChallenge().challenge_id);
    expect(third.kind).toBe('offline');
  });

  it('dedupes per challenge id and bounds the backlog', () => {
    const clock = new FixedClock(100);
    const queue = new ChallengeQueue(offlineTransport(), clock, { maxBacklog: 2 });
    const { resp, decision } = approveResponse();
    expect(queue.enqueue(validChallenge(), resp, decision)).toEqual({ ok: true });
    expect(queue.enqueue(validChallenge(), resp, decision)).toEqual({ ok: false, reason: 'duplicate' });
    const c2 = { ...validChallenge(), challenge_id: 'chg-test-0002' };
    const c3 = { ...validChallenge(), challenge_id: 'chg-test-0003' };
    const r2 = buildChallengeResponseData(c2, 'deny', null);
    expect(queue.enqueue(c2, r2, 'deny')).toEqual({ ok: true });
    const r3 = buildChallengeResponseData(c3, 'deny', null);
    expect(queue.enqueue(c3, r3, 'deny')).toEqual({ ok: false, reason: 'backlog-full' });
    expect(queue.size).toBe(2);
    queue.clear();
    expect(queue.size).toBe(0);
  });

  it('unknown ids skip cleanly', async () => {
    const queue = new ChallengeQueue(offlineTransport(), new FixedClock(1));
    expect(await queue.deliver('nope')).toEqual({ kind: 'skipped', reason: 'not queued' });
  });
});
