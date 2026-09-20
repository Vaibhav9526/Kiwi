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

export interface LedgerClock {
  nowUnix(): number;
}

export class ReplayLedger {
  private readonly entries = new Map<string, LedgerEntry>();

  constructor(private readonly clock: LedgerClock) {}

  /** Has this challenge already been answered (approve or deny)? */
  isConsumed(challengeId: string): boolean {
    return this.entries.has(challengeId);
  }

  /** Record the first answer; returns false if already answered or the ledger is full. */
  record(challengeId: string, decision: LedgerEntry['decision']): boolean {
    if (this.entries.has(challengeId)) {return false;}
    if (this.entries.size >= ReplayLedger.MAX_ENTRIES) {return false;} // bounded (§4.3)
    this.entries.set(challengeId, { challengeId, consumedUnix: this.clock.nowUnix(), decision });
    return true;
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
