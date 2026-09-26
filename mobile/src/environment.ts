/**
 * Fail-closed environment + approval bundle (T-194).
 *
 * An `Environment` is everything a screen needs to run: clock, keystore,
 * transport, pairing link, plus optional demo affordances. The default
 * environment is FAIL-CLOSED — unavailable keystore, offline transport,
 * rejecting link, no demo hooks — so nothing can pretend to authorize.
 *
 * The mock environment lives in `src/mock/` and is wired ONLY by
 * `src/App.tsx`; core modules never import it (enforced by
 * `tests/isolation/mock-isolation.test.ts`).
 */
import { OfflineTransport, type ChallengeTransport } from './transport/transport';
import type { AuthenticatorLink, DeviceStatus, PairingHello, PairingRegistered } from './transport/link';
import { UnavailableKeystore, type DeviceKeystore } from './keystore/keystore';
import { ReplayLedger, SystemClock, type LedgerClock } from './protocol/replay';
import { ChallengeQueue } from './protocol/queue';
import { DecisionHistory } from './protocol/history';
import { ApprovalService } from './protocol/approval';
import type { ChallengeEvent } from './protocol/event';
import type { ChallengeData } from './protocol/types';

export type EnvironmentMode = 'fail-closed' | 'mock';

export interface Environment {
  readonly mode: EnvironmentMode;
  readonly clock: LedgerClock;
  readonly keystore: DeviceKeystore;
  readonly transport: ChallengeTransport;
  readonly link: AuthenticatorLink;
  /**
   * Demo-only affordances, absent in fail-closed mode: fabricate a pairing
   * QR (the real desktop renders it) and ask the mock desktop to issue a
   * challenge. Screens feature-detect these; they are never a trust input.
   */
  readonly demoQr?: (deviceLabel?: string) => string;
  readonly demoIssueChallenge?: (deviceId: string, event: ChallengeEvent) => string;
  /** Mock-only link state toggle so offline retry (§7) can be demonstrated. */
  readonly demoSetOnline?: (online: boolean) => void;
}

/** Link that refuses everything — no pairing, no challenges, no status. */
class RejectingLink implements AuthenticatorLink {
  private fail(): never {
    throw new Error('pairing transport unavailable (fail closed until Phase 4)');
  }
  async hello(_msg: PairingHello): Promise<PairingRegistered> {
    return this.fail();
  }
  async pullChallenges(_deviceId: string): Promise<ChallengeData[]> {
    return this.fail();
  }
  async deviceStatus(_deviceId: string): Promise<DeviceStatus> {
    return this.fail();
  }
}

/** Default environment: every seam closed (SECURITY.md rule 7). */
export function createFailClosedEnvironment(clock: LedgerClock = new SystemClock()): Environment {
  return {
    mode: 'fail-closed',
    clock,
    keystore: new UnavailableKeystore(),
    transport: new OfflineTransport(),
    link: new RejectingLink(),
  };
}

export interface ApprovalBundle {
  readonly service: ApprovalService;
  readonly ledger: ReplayLedger;
  readonly queue: ChallengeQueue;
  readonly history: DecisionHistory;
}

/** One ledger/queue/history/service set per environment (app instance). */
export function createApprovalBundle(env: Environment): ApprovalBundle {
  const ledger = new ReplayLedger(env.clock);
  const queue = new ChallengeQueue(env.transport, env.clock);
  const history = new DecisionHistory(env.clock);
  const service = new ApprovalService({ ledger, queue, history, keystore: env.keystore, clock: env.clock });
  return { service, ledger, queue, history };
}
