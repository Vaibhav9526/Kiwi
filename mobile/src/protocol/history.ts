/**
 * Local decision history (T-194) — the History screen's data source.
 *
 * One bounded entry per challenge id: what was decided (approve / deny /
 * expired), when, against which event/session, and how delivery ended.
 * A timeout is recorded as `expired` — never as `deny` (contract §6.3:
 * deny is an explicit user decision; "expired / no response" is the absence
 * of one). Pure, clock-injected, no I/O (SECURITY.md rule 1).
 */
import type { ChallengeEvent } from './event';

export type HistoryDecision = 'approve' | 'deny' | 'expired';

export type DeliveryState = 'queued' | 'delivered' | 'offline' | 'dropped' | 'not-queued';

export interface HistoryEntry {
  readonly challengeId: string;
  readonly event: ChallengeEvent;
  readonly sessionId: string;
  readonly decision: HistoryDecision;
  readonly atUnix: number;
  readonly delivery: DeliveryState;
}

export interface HistoryClock {
  nowUnix(): number;
}

export interface HistoryInput {
  challengeId: string;
  event: ChallengeEvent;
  sessionId: string;
  decision: HistoryDecision;
}

/** Bounded the same way as the replay ledger (256 entries). */
const MAX_ENTRIES = 256;

export class DecisionHistory {
  private readonly store = new Map<string, HistoryEntry>();

  constructor(
    private readonly clock: HistoryClock,
    private readonly maxEntries: number = MAX_ENTRIES,
  ) {}

  /** Record the first outcome for a challenge id; later calls are ignored. */
  record(input: HistoryInput): boolean {
    if (this.store.has(input.challengeId)) {return false;}
    if (this.store.size >= this.maxEntries) {
      const oldest = this.store.keys().next();
      if (!oldest.done) {this.store.delete(oldest.value);}
    }
    this.store.set(input.challengeId, {
      challengeId: input.challengeId,
      event: input.event,
      sessionId: input.sessionId,
      decision: input.decision,
      atUnix: this.clock.nowUnix(),
      delivery: 'not-queued',
    });
    return true;
  }

  /** Update the delivery outcome once the queue has tried the item. */
  markDelivery(challengeId: string, delivery: DeliveryState): boolean {
    const entry = this.store.get(challengeId);
    if (entry === undefined) {return false;}
    this.store.set(challengeId, { ...entry, delivery });
    return true;
  }

  /** Newest first — the order a history list should render. */
  entries(): HistoryEntry[] {
    return [...this.store.values()].reverse();
  }

  get size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
