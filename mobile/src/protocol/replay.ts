/**
 * Replay/consumption ledger (T-136 contract §6.4). Client-side defense in
 * depth only — the desktop `ChallengeBook` is the single-use authority
 * (security-session.md §6). Persisted with the keystore's non-exportable
 * storage; in this scaffold it is in-memory behind an interface.
 * Pure logic, injectable clock (SECURITY.md rule 1).
 */
import type { ChallengeData } from './types';

export interface LedgerEntry {
  challengeId: string;
  consumedUnix: number;
  decision: 'approve' | 'deny' | 'expired';
}

/** Why a `record` call did (or did not) land — duplicate ≠ capacity (T270-05). */
export type RecordResult = 'recorded' | 'duplicate' | 'full';

export interface LedgerClock {
  nowUnix(): number;
}

/** Wall clock for the app (live, never frozen — AUTH-7). */
export class SystemClock implements LedgerClock {
  nowUnix(): number {
    return Math.floor(Date.now() / 1000);
  }
}

/** Contract §4.3: answered-challenge entries are pruned after one hour. */
export const LEDGER_PRUNE_SECS = 3600;

export class ReplayLedger {
  private readonly entries = new Map<string, LedgerEntry>();

  constructor(private readonly clock: LedgerClock) {}

  /** Has this challenge already been answered (approve or deny)? */
  isConsumed(challengeId: string): boolean {
    this.prune(LEDGER_PRUNE_SECS); // AUTH-12: the policy is wired, not aspirational
    return this.entries.has(challengeId);
  }

  /**
   * Record the first answer (approve, deny, or local `expired` — AUTH-11).
   * Distinguishes "already answered" from "ledger at capacity" so the UI can
   * tell replay suppression from a storage-bound failure.
   */
  record(challengeId: string, decision: LedgerEntry['decision']): RecordResult {
    this.prune(LEDGER_PRUNE_SECS); // prune before capacity checks so old entries cannot evict new ones
    if (this.entries.has(challengeId)) {return 'duplicate';}
    if (this.entries.size >= ReplayLedger.MAX_ENTRIES) {return 'full';} // bounded (§4.3)
    this.entries.set(challengeId, { challengeId, consumedUnix: this.clock.nowUnix(), decision });
    return 'recorded';
  }

  /** Read-only snapshot of the retained entries (newest last). */
  entriesSnapshot(): LedgerEntry[] {
    return [...this.entries.values()];
  }

  /** True when the challenge is past expiry and not yet consumed. */
  isExpired(c: ChallengeData): boolean {
    return this.clock.nowUnix() >= c.expires_unix;
  }

  /** Purge entries older than `maxAgeSecs` (bounded memory). */
  prune(maxAgeSecs: number): number {
    const now = this.clock.nowUnix();
    let removed = 0;
    for (const [id, entry] of this.entries) {
      if (now - entry.consumedUnix > maxAgeSecs) {
        this.entries.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  /** Bounded load: refuse new entries beyond this size. */
  get size(): number {
    return this.entries.size;
  }

  static readonly MAX_ENTRIES = 256;
}

/** Injectable fixed clock for tests. */
export class FixedClock implements LedgerClock {
  constructor(public unix: number) {}
  nowUnix(): number {
    return this.unix;
  }
}
