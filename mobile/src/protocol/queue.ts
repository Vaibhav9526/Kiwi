/**
 * Sign-then-queue challenge delivery (T-136 contract §7).
 *
 * - Approve commits at sign time: the signed response enters this queue and
 *   is retried until delivered (the desktop stays the expiry authority —
 *   queued approvals are never silently dropped, §7).
 * - Deny is best-effort and bounded: it is dropped after `denyTtlSecs`
 *   (AUTH-8) so a deny can never be queued indefinitely.
 * - FIFO, bounded backlog (default 64), one outcome per challenge id —
 *   an id that was already delivered can never be re-admitted (T270-06) —
 *   delivery attempts throttled (default >= 10 s apart), injectable clock.
 * - Entries are consistency-checked at admission (challenge/response/decision
 *   must agree) and stored immutable; attempts live in their own map.
 * - Nothing is sent by the queue itself; delivery is delegated to the
 *   injected `ChallengeTransport` (offline stub in scaffold, mock in T-194).
 */
import type { ChallengeData, ChallengeResponseData, Decision } from './types';

export type TransportResult =
  | { kind: 'delivered'; requestId: string }
  | { kind: 'offline'; reason: string };

export interface QueueTransport {
  postResponse(resp: ChallengeResponseData): Promise<TransportResult>;
}

export interface QueueClock {
  nowUnix(): number;
}

export interface PendingItem {
  readonly challenge: ChallengeData;
  readonly response: ChallengeResponseData;
  readonly decision: Decision;
  readonly enqueueUnix: number;
}

export interface QueueOptions {
  maxBacklog?: number;
  minRetrySecs?: number;
  /** Best-effort deny retention; after this age a deny is dropped (AUTH-8). */
  denyTtlSecs?: number;
}

export type EnqueueResult =
  | { ok: true }
  | { ok: false; reason: 'duplicate' | 'backlog-full' | 'already-delivered' | 'inconsistent' };

export type DeliveryOutcome =
  | { kind: 'delivered'; requestId: string }
  | { kind: 'offline'; reason: string }
  | { kind: 'skipped'; reason: string }
  | { kind: 'dropped'; reason: string };

const DEFAULT_BACKLOG = 64;
const DEFAULT_RETRY = 10;
const DEFAULT_DENY_TTL = 300;
/** Bounded memory for the delivered-id guard (same bound as the ledger). */
const MAX_COMPLETED = 256;

function clampInt(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isSafeInteger(value)) {return fallback;}
  return Math.min(max, Math.max(min, value));
}

export class ChallengeQueue {
  private readonly items = new Map<string, PendingItem>();
  private readonly attempts = new Map<string, number>();
  private readonly lastAttempt = new Map<string, number>();
  /** Ids whose response already reached the desktop — never re-admitted. */
  private readonly completed = new Set<string>();
  private readonly maxBacklog: number;
  private readonly minRetrySecs: number;
  private readonly denyTtlSecs: number;

  constructor(
    private readonly transport: QueueTransport,
    private readonly clock: QueueClock,
    opts: QueueOptions = {},
  ) {
    this.maxBacklog = clampInt(opts.maxBacklog ?? DEFAULT_BACKLOG, 1, 256, DEFAULT_BACKLOG);
    this.minRetrySecs = clampInt(opts.minRetrySecs ?? DEFAULT_RETRY, 0, 3600, DEFAULT_RETRY);
    this.denyTtlSecs = clampInt(opts.denyTtlSecs ?? DEFAULT_DENY_TTL, 1, 86400, DEFAULT_DENY_TTL);
  }

  /**
   * Add a signed outcome. Dedupes per challenge id, bounds the backlog,
   * refuses ids that already delivered, and rejects entries whose
   * challenge/response/decision disagree (a mismatched triple would put an
   * unreviewed response on the wire).
   */
  enqueue(challenge: ChallengeData, response: ChallengeResponseData, decision: Decision): EnqueueResult {
    if (
      response.challenge_id !== challenge.challenge_id ||
      response.device_id !== challenge.device_id ||
      response.session_id !== challenge.session_id ||
      response.event !== challenge.event ||
      response.decision !== decision
    ) {
      return { ok: false, reason: 'inconsistent' };
    }
    if (this.completed.has(challenge.challenge_id)) {
      return { ok: false, reason: 'already-delivered' };
    }
    if (this.items.has(challenge.challenge_id)) {return { ok: false, reason: 'duplicate' };}
    if (this.items.size >= this.maxBacklog) {return { ok: false, reason: 'backlog-full' };}
    this.items.set(challenge.challenge_id, {
      challenge,
      response,
      decision,
      enqueueUnix: this.clock.nowUnix(),
    });
    this.attempts.set(challenge.challenge_id, 0);
    return { ok: true };
  }

  has(challengeId: string): boolean {
    return this.items.has(challengeId);
  }

  /** FIFO snapshot for UI display. */
  pending(): PendingItem[] {
    return [...this.items.values()];
  }

  get size(): number {
    return this.items.size;
  }

  /** Try to deliver one item (throttled). Denies drop at TTL; approvals stay. */
  async deliver(challengeId: string): Promise<DeliveryOutcome> {
    const item = this.items.get(challengeId);
    if (!item) {return { kind: 'skipped', reason: 'not queued' };}
    const now = this.clock.nowUnix();
    // AUTH-8: a deny is advisory — retain it briefly for retry, then drop it
    // (§7: denies are never queued indefinitely; desktop audits the timeout).
    if (item.decision === 'deny' && now - item.enqueueUnix >= this.denyTtlSecs) {
      this.removeItem(challengeId);
      return { kind: 'dropped', reason: 'deny-ttl' };
    }
    const last = this.lastAttempt.get(challengeId);
    if (last !== undefined && now - last < this.minRetrySecs) {
      return { kind: 'skipped', reason: 'throttled' };
    }
    this.lastAttempt.set(challengeId, now);
    this.attempts.set(challengeId, (this.attempts.get(challengeId) ?? 0) + 1);
    const result = await this.transport.postResponse(item.response);
    if (result.kind === 'delivered') {
      this.markCompleted(challengeId);
      return result;
    }
    return result;
  }

  /** Attempt count for an item (0 when not queued). */
  attemptsFor(challengeId: string): number {
    return this.attempts.get(challengeId) ?? 0;
  }

  /** Try every due item in FIFO order. */
  async tick(): Promise<{ delivered: string[]; offline: string[]; dropped: string[]; skipped: number }> {
    const delivered: string[] = [];
    const offline: string[] = [];
    const dropped: string[] = [];
    let skipped = 0;
    for (const item of [...this.items.values()]) {
      const outcome = await this.deliver(item.challenge.challenge_id);
      if (outcome.kind === 'delivered') {delivered.push(item.challenge.challenge_id);}
      else if (outcome.kind === 'offline') {offline.push(item.challenge.challenge_id);}
      else if (outcome.kind === 'dropped') {dropped.push(item.challenge.challenge_id);}
      else {skipped += 1;}
    }
    return { delivered, offline, dropped, skipped };
  }

  /** Drop everything (e.g. unpair). */
  clear(): void {
    this.items.clear();
    this.attempts.clear();
    this.lastAttempt.clear();
    this.completed.clear();
  }

  private removeItem(challengeId: string): void {
    this.items.delete(challengeId);
    this.attempts.delete(challengeId);
    this.lastAttempt.delete(challengeId);
  }

  private markCompleted(challengeId: string): void {
    this.removeItem(challengeId);
    if (this.completed.size >= MAX_COMPLETED) {
      const oldest = this.completed.values().next();
      if (!oldest.done) {this.completed.delete(oldest.value);}
    }
    this.completed.add(challengeId);
  }
}
