/**
 * Ordered approval transaction (T-194, contract §6.1).
 *
 * One place implements the gate order — display-only parse, local clock,
 * registered-device binding, replay ledger, explicit user intent — and it
 * runs TWICE: once when the challenge is reviewed, and again at the moment
 * of the tap (AUTH-6/AUTH-7: binding is never optional, the clock is never
 * frozen, expiry is re-checked when Approve/Deny is pressed).
 *
 * Fail-closed by construction:
 * - no paired identity => nothing is reviewable or signable;
 * - expired => recorded locally as `expired` (AUTH-11), never as deny;
 * - keystore refusal => no signature, no ledger entry — a failed attempt
 *   never consumes the challenge (rule 10);
 * - deny is unsigned, non-consuming on the desktop, and best-effort queued.
 *
 * Pure logic + injected clock/keystore/transport (SECURITY.md rule 1).
 */
import type { ChallengeEvent } from './event';
import type { ChallengeData, Decision, PairedIdentity } from './types';
import {
  parseChallengeJson,
  buildChallengeResponseData,
  challengeFields,
  canonicalChallengeBytes,
  decodeB64,
} from './canonical';
import { base64Encode } from './bytes';
import { ReplayLedger, type LedgerClock } from './replay';
import { ChallengeQueue, type EnqueueResult } from './queue';
import { DecisionHistory } from './history';
import { KeystoreError, type DeviceKeystore } from '../keystore/keystore';

/** Human phrases for §6.1 step 5 — the user sees these, never raw enums. */
export const EVENT_PHRASES: Record<ChallengeEvent, string> = {
  unlock: 'Unlock KIWI',
  'device-pairing': 'Pair this device',
  recovery: 'Account recovery',
  'elevated-action': 'Elevated action',
};

const NONCE_BYTES = 32;
const SIGNATURE_BYTES = 64;
/** Keystore refusals that mean "no signer here yet", not "crypto broke". */
const UNAVAILABLE_CODES = new Set(['not-implemented', 'keystore-unavailable', 'key-not-found']);

export interface ReviewedChallenge {
  readonly challenge: ChallengeData;
  readonly reviewedAtUnix: number;
}

export type GateReject = 'expired' | 'no-identity' | 'wrong-device' | 'already-answered';

export type ReviewResult =
  | { ok: true; reviewed: ReviewedChallenge }
  | { ok: false; reason: 'malformed' | GateReject; message: string };

export type DecideReject = GateReject | 'keystore-unavailable' | 'keystore-error' | 'ledger-full';

export type DecideResult =
  | { ok: true; decision: 'deny'; queued: EnqueueResult }
  | { ok: true; decision: 'approve'; signatureB64: string; queued: EnqueueResult }
  | { ok: false; reason: DecideReject; message: string };

export interface ApprovalDeps {
  ledger: ReplayLedger;
  queue: ChallengeQueue;
  history: DecisionHistory;
  keystore: DeviceKeystore;
  clock: LedgerClock;
}

function boundedMessage(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : fallback;
  return msg.length > 200 ? `${msg.slice(0, 200)}…` : msg;
}

export class ApprovalService {
  constructor(private readonly deps: ApprovalDeps) {}

  /**
   * Gate order per §6.1: bounded parse -> live clock -> binding -> replay.
   * Expiry at review time is recorded (`expired`) so a re-pushed copy of the
   * same challenge is not re-prompted (AUTH-11 / §6.4).
   */
  review(raw: string, identity: PairedIdentity | null): ReviewResult {
    let challenge: ChallengeData;
    try {
      challenge = parseChallengeJson(raw);
    } catch (err) {
      return { ok: false, reason: 'malformed', message: boundedMessage(err, 'invalid challenge') };
    }
    const gate = this.gate(challenge, identity);
    if (!gate.ok) {
      return { ok: false, reason: gate.reason, message: gate.message };
    }
    return {
      ok: true,
      reviewed: { challenge, reviewedAtUnix: this.deps.clock.nowUnix() },
    };
  }

  /**
   * The tap-time transaction. Re-runs the clock / binding / replay gates
   * against THIS reviewed challenge before any keystroke-level effect: a
   * challenge that expired, got answered elsewhere, or is addressed to
   * another device between review and tap fails closed.
   */
  async decide(
    reviewed: ReviewedChallenge,
    identity: PairedIdentity | null,
    decision: Decision,
  ): Promise<DecideResult> {
    const challenge = reviewed.challenge;
    const gate = this.gate(challenge, identity);
    if (!gate.ok) {
      return { ok: false, reason: gate.reason, message: gate.message };
    }
    if (identity === null) {return { ok: false, reason: 'no-identity', message: 'not paired' };} // narrowed for TS

    if (decision === 'deny') {
      return this.recordDeny(challenge);
    }
    return this.recordApprove(challenge, identity);
  }

  /** Drain the queue and reflect outcomes into the history log. */
  async flush(): Promise<{ delivered: string[]; offline: string[]; dropped: string[]; skipped: number }> {
    const result = await this.deps.queue.tick();
    for (const id of result.delivered) {this.deps.history.markDelivery(id, 'delivered');}
    for (const id of result.offline) {this.deps.history.markDelivery(id, 'offline');}
    for (const id of result.dropped) {this.deps.history.markDelivery(id, 'dropped');}
    return result;
  }

  get queuedCount(): number {
    return this.deps.queue.size;
  }

  private gate(
    challenge: ChallengeData,
    identity: PairedIdentity | null,
  ): { ok: true } | { ok: false; reason: GateReject; message: string } {
    // 2. Live clock — the phone's own time, re-evaluated on every call.
    if (this.deps.clock.nowUnix() >= challenge.expires_unix) {
      this.noteExpired(challenge);
      return { ok: false, reason: 'expired', message: 'Challenge expired — no response (not a denial).' };
    }
    // 3. Binding — mandatory: without a paired identity nothing is signable
    //    (AUTH-6: the old null-identity path skipped this gate).
    if (identity === null) {
      return { ok: false, reason: 'no-identity', message: 'No paired device — complete pairing first.' };
    }
    if (challenge.device_id !== identity.deviceId) {
      return {
        ok: false,
        reason: 'wrong-device',
        message: 'Challenge is addressed to a different device.',
      };
    }
    // 4. Replay ledger — one answer per challenge id, approve or deny.
    if (this.deps.ledger.isConsumed(challenge.challenge_id)) {
      return { ok: false, reason: 'already-answered', message: 'Already answered — suppressed.' };
    }
    return { ok: true };
  }

  private noteExpired(challenge: ChallengeData): void {
    const recorded = this.deps.ledger.record(challenge.challenge_id, 'expired');
    if (recorded !== 'duplicate') {
      this.deps.history.record({
        challengeId: challenge.challenge_id,
        event: challenge.event,
        sessionId: challenge.session_id,
        decision: 'expired',
      });
    }
  }

  private recordDeny(challenge: ChallengeData): DecideResult {
    const recorded = this.deps.ledger.record(challenge.challenge_id, 'deny');
    if (recorded === 'duplicate') {
      return { ok: false, reason: 'already-answered', message: 'Already answered — suppressed.' };
    }
    if (recorded === 'full') {
      return { ok: false, reason: 'ledger-full', message: 'Local ledger is full — deny not recorded.' };
    }
    this.deps.history.record({
      challengeId: challenge.challenge_id,
      event: challenge.event,
      sessionId: challenge.session_id,
      decision: 'deny',
    });
    // Deny is unsigned (§6.3) and best-effort (§7): enqueue if the queue
    // accepts it; the desktop audits the timeout if it never arrives.
    const response = buildChallengeResponseData(challenge, 'deny', null);
    const queued = this.deps.queue.enqueue(challenge, response, 'deny');
    return { ok: true, decision: 'deny', queued };
  }

  private async recordApprove(challenge: ChallengeData, identity: PairedIdentity): Promise<DecideResult> {
    // Sign first: constructing the signature IS the approval (§7), so a
    // keystore refusal leaves the challenge unanswered and re-approvable.
    let signature: Uint8Array;
    try {
      const nonce = decodeB64(challenge.nonce_b64, NONCE_BYTES, 'nonce_b64');
      const bytes = canonicalChallengeBytes(challengeFields(challenge, nonce));
      signature = await this.deps.keystore.sign(identity.keystoreRef, bytes);
    } catch (err) {
      if (err instanceof KeystoreError && UNAVAILABLE_CODES.has(err.code)) {
        return {
          ok: false,
          reason: 'keystore-unavailable',
          message: 'Approve needs the platform keystore — unavailable (fail closed).',
        };
      }
      return { ok: false, reason: 'keystore-error', message: boundedMessage(err, 'signing failed') };
    }
    if (signature.length !== SIGNATURE_BYTES) {
      return { ok: false, reason: 'keystore-error', message: `signature must be ${SIGNATURE_BYTES} bytes` };
    }
    const signatureB64 = base64Encode(signature);
    const response = buildChallengeResponseData(challenge, 'approve', signatureB64);
    const recorded = this.deps.ledger.record(challenge.challenge_id, 'approve');
    if (recorded === 'duplicate') {
      return { ok: false, reason: 'already-answered', message: 'Already answered — suppressed.' };
    }
    if (recorded === 'full') {
      return { ok: false, reason: 'ledger-full', message: 'Local ledger is full — approve not recorded.' };
    }
    this.deps.history.record({
      challengeId: challenge.challenge_id,
      event: challenge.event,
      sessionId: challenge.session_id,
      decision: 'approve',
    });
    const queued = this.deps.queue.enqueue(challenge, response, 'approve');
    return { ok: true, decision: 'approve', signatureB64, queued };
  }
}
