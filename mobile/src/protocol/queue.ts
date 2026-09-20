/**
 * Sign-then-queue challenge delivery (T-136 contract §7).
 *
 * - Approve commits at sign time: the signed response enters this queue and
 *   is retried until delivered or expired out.
 * - FIFO, bounded backlog (default 64), one outcome per challenge id,
 *   delivery attempts throttled (default ≥10 s apart), injectable clock —
 *   deterministic and testable (SECURITY.md rule 1).
 * - Nothing is sent by the queue itself; delivery is delegated to the
 *   injected `ChallengeTransport` (offline stub in scaffold).
 */
import type { ChallengeData, ChallengeResponseData, Decision } from "./types";

export type TransportResult =
  | { kind: "delivered"; requestId: string }
  | { kind: "offline"; reason: string };

export interface QueueTransport {
  postResponse(resp: ChallengeResponseData): Promise<TransportResult>;
}

export interface QueueClock {
  nowUnix(): number;
}

export interface PendingItem {
  challenge: ChallengeData;
  response: ChallengeResponseData;
  decision: Decision;
  enqueueUnix: number;
  attempts: number;
}

export interface QueueOptions {
  maxBacklog?: number;
  minRetrySecs?: number;
}

export type EnqueueResult =
  | { ok: true }
  | { ok: false; reason: "duplicate" | "backlog-full" };

export type DeliveryOutcome =
  | { kind: "delivered"; requestId: string }
  | { kind: "offline"; reason: string }
  | { kind: "skipped"; reason: string };

const DEFAULT_BACKLOG = 64;
const DEFAULT_RETRY = 10;

export class ChallengeQueue {
  private readonly items = new Map<string, PendingItem>();
  private readonly lastAttempt = new Map<string, number>();
  private readonly maxBacklog: number;
  private readonly minRetrySecs: number;

  constructor(
    private readonly transport: QueueTransport,
    private readonly clock: QueueClock,
    opts: QueueOptions = {},
  ) {
    this.maxBacklog = opts.maxBacklog ?? DEFAULT_BACKLOG;
    this.minRetrySecs = opts.minRetrySecs ?? DEFAULT_RETRY;
  }

  /** Add a signed outcome; dedupes per challenge id and bounds the backlog. */
  enqueue(challenge: ChallengeData, response: ChallengeResponseData, decision: Decision): EnqueueResult {
    if (this.items.has(challenge.challenge_id)) return { ok: false, reason: "duplicate" };
    if (this.items.size >= this.maxBacklog) return { ok: false, reason: "backlog-full" };
    this.items.set(challenge.challenge_id, {
      challenge,
      response,
      decision,
      enqueueUnix: this.clock.nowUnix(),
      attempts: 0,
    });
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

  /** Try to deliver one item (throttled). Kept on offline; removed on delivery. */
  async deliver(challengeId: string): Promise<DeliveryOutcome> {
    const item = this.items.get(challengeId);
    if (!item) return { kind: "skipped", reason: "not queued" };
    const now = this.clock.nowUnix();
    const last = this.lastAttempt.get(challengeId);
    if (last !== undefined && now - last < this.minRetrySecs) {
      return { kind: "skipped", reason: "throttled" };
    }
    this.lastAttempt.set(challengeId, now);
    item.attempts += 1;
    const result = await this.transport.postResponse(item.response);
    if (result.kind === "delivered") {
      this.items.delete(challengeId);
      return result;
    }
    return result;
  }

  /** Try every due item in FIFO order. */
  async tick(): Promise<{ delivered: string[]; offline: string[]; skipped: number }> {
    const delivered: string[] = [];
    const offline: string[] = [];
    let skipped = 0;
    for (const item of [...this.items.values()]) {
      const outcome = await this.deliver(item.challenge.challenge_id);
      if (outcome.kind === "delivered") delivered.push(item.challenge.challenge_id);
      else if (outcome.kind === "offline") offline.push(item.challenge.challenge_id);
      else skipped += 1;
    }
    return { delivered, offline, skipped };
  }

  /** Drop everything (e.g. unpair). */
  clear(): void {
    this.items.clear();
    this.lastAttempt.clear();
  }
}
