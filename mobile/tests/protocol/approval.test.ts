/**
 * Approval-service evidence (T-194; contract §6.1, §6.3, §7).
 *
 * The ordered gate runs at review AND at the tap; expiry is a timeout, not
 * a denial; a keystore refusal never consumes the challenge; deny is
 * unsigned. Fixtures are synthetic (SECURITY.md rule 6).
 */
import { describe, it, expect } from 'vitest';

import { ApprovalService } from '../../src/protocol/approval';
import { ReplayLedger, FixedClock } from '../../src/protocol/replay';
import { ChallengeQueue, type QueueTransport } from '../../src/protocol/queue';
import { DecisionHistory } from '../../src/protocol/history';
import { SoftHsmKeystore } from '../../src/keystore/soft-hsm';
import { UnavailableKeystore } from '../../src/keystore/keystore';
import type { DeviceKeystore } from '../../src/keystore/keystore';
import type { PairedIdentity } from '../../src/protocol/types';
import { validChallenge, ISSUED, EXPIRES } from '../helpers/protocol';

function offlineTransport(): QueueTransport {
  return { postResponse: async () => ({ kind: 'offline', reason: 'test transport' }) };
}

interface Rig {
  clock: FixedClock;
  ledger: ReplayLedger;
  queue: ChallengeQueue;
  history: DecisionHistory;
  service: ApprovalService;
  identity: PairedIdentity;
}

async function rigWith(keystore: DeviceKeystore, keystoreRef: string): Promise<Rig> {
  const clock = new FixedClock(ISSUED + 1);
  const ledger = new ReplayLedger(clock);
  const queue = new ChallengeQueue(offlineTransport(), clock);
  const history = new DecisionHistory(clock);
  const service = new ApprovalService({ ledger, queue, history, keystore, clock });
  const identity: PairedIdentity = {
    deviceId: 'dev-test-0001',
    deviceLabel: 'Test phone',
    desktopEndpoint: 'wss://127.0.0.1:49310/pair',
    desktopKeyB64: 'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    keystoreRef,
    publicKeyB64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    pairedUnix: ISSUED,
  };
  return { clock, ledger, queue, history, service, identity };
}

async function pairedRig(): Promise<Rig> {
  const keystore = SoftHsmKeystore.createTestOnly();
  const handle = await keystore.generateKey('kiwi-auth-test');
  return rigWith(keystore, handle.keystoreRef);
}

describe('review (gate order)', () => {
  it('accepts a well-formed, bound, live challenge', async () => {
    const rig = await pairedRig();
    const res = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(res.ok).toBe(true);
    if (res.ok) {expect(res.reviewed.challenge.challenge_id).toBe('chg-test-0001');}
  });

  it('rejects malformed JSON before anything else (AUTH-14 bound entry)', async () => {
    const rig = await pairedRig();
    expect(rig.service.review('not json', rig.identity).ok).toBe(false);
    const huge = `{"schema_version":1,${'x'.repeat(5000)}}`;
    const res = rig.service.review(huge, rig.identity);
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('malformed');}
  });

  it('fails closed without a paired identity (AUTH-6)', async () => {
    const rig = await pairedRig();
    const res = rig.service.review(JSON.stringify(validChallenge()), null);
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('no-identity');}
  });

  it('rejects challenges addressed to another device (binding)', async () => {
    const rig = await pairedRig();
    const foreign = { ...validChallenge(), device_id: 'dev-other' };
    const res = rig.service.review(JSON.stringify(foreign), rig.identity);
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('wrong-device');}
  });

  it('records expiry as `expired`, never as a denial (AUTH-11)', async () => {
    const rig = await pairedRig();
    rig.clock.unix = EXPIRES;
    const res = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('expired');}
    expect(rig.history.entries()[0]?.decision).toBe('expired');
    expect(rig.ledger.isConsumed('chg-test-0001')).toBe(true);
    expect(rig.queue.size).toBe(0); // no response was built for a timeout
  });
});

describe('decide (tap-time transaction)', () => {
  it('approve: signs, records, queues, and flushes to the transport', async () => {
    const rig = await pairedRig();
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const res = await rig.service.decide(review.reviewed, rig.identity, 'approve');
    expect(res.ok).toBe(true);
    if (res.ok && res.decision === 'approve') {
      expect(res.signatureB64.length).toBeGreaterThan(0);
      expect(Buffer.from(res.signatureB64, 'base64')).toHaveLength(64);
      expect(res.queued).toEqual({ ok: true });
    }
    expect(rig.ledger.isConsumed('chg-test-0001')).toBe(true);
    expect(rig.history.entries()[0]).toMatchObject({ decision: 'approve', delivery: 'not-queued' });
    expect(rig.queue.size).toBe(1);
    const flushed = await rig.service.flush();
    expect(flushed.offline).toEqual(['chg-test-0001']);
    expect(rig.history.entries()[0]?.delivery).toBe('offline');
  });

  it('re-runs the clock gate at the tap (AUTH-7): expired between review and tap', async () => {
    const rig = await pairedRig();
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    rig.clock.unix = EXPIRES; // time passes while the sheet is open
    const res = await rig.service.decide(review.reviewed, rig.identity, 'approve');
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('expired');}
    expect(rig.history.entries()[0]?.decision).toBe('expired');
    expect(rig.queue.size).toBe(0); // nothing was signed or queued
  });

  it('re-runs binding at the tap: device swapped after review', async () => {
    const rig = await pairedRig();
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const swapped = { ...rig.identity, deviceId: 'dev-other' };
    const res = await rig.service.decide(review.reviewed, swapped, 'approve');
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('wrong-device');}
  });

  it('keystore refusal leaves the challenge unanswered and re-approvable (rule 10)', async () => {
    const rig = await rigWith(new UnavailableKeystore(), 'missing-key');
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const res = await rig.service.decide(review.reviewed, rig.identity, 'approve');
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('keystore-unavailable');}
    expect(rig.ledger.isConsumed('chg-test-0001')).toBe(false);
    expect(rig.history.size).toBe(0);
    expect(rig.queue.size).toBe(0);
    // Still answerable once a keystore exists: deny works (unsigned path).
    const deny = await rig.service.decide(review.reviewed, rig.identity, 'deny');
    expect(deny.ok).toBe(true);
  });

  it('deny is unsigned, queued best-effort, and consumes the id (§6.3)', async () => {
    const rig = await pairedRig();
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const res = await rig.service.decide(review.reviewed, rig.identity, 'deny');
    expect(res.ok).toBe(true);
    if (res.ok && res.decision === 'deny') {expect(res.queued).toEqual({ ok: true });}
    const pending = rig.queue.pending();
    expect(pending[0]?.response.signature_b64).toBe('');
    expect(pending[0]?.response.decision).toBe('deny');
    // Second answer is suppressed.
    const again = await rig.service.decide(review.reviewed, rig.identity, 'deny');
    expect(again.ok).toBe(false);
    if (!again.ok) {expect(again.reason).toBe('already-answered');}
    expect(rig.history.entries()).toHaveLength(1);
  });

  it('deciding without an identity fails closed even if a review was forged', async () => {
    const rig = await pairedRig();
    const review = rig.service.review(JSON.stringify(validChallenge()), rig.identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const res = await rig.service.decide(review.reviewed, null, 'approve');
    expect(res.ok).toBe(false);
    if (!res.ok) {expect(res.reason).toBe('no-identity');}
    expect(rig.queue.size).toBe(0);
    expect(rig.history.size).toBe(0);
  });
});
