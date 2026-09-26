/**
 * Mock environment factory (T-194) — the ONLY place that ties the mock
 * desktop to the soft-HSM test keystore.
 *
 * Import graph is enforced by `tests/isolation/mock-isolation.test.ts`:
 * nothing under `src/protocol/`, `src/transport/`, `src/keystore/keystore.ts`
 * or `src/screens/` may import this package (or the soft HSM) — only
 * `src/App.tsx` wires it, behind an explicitly labelled mock mode.
 */
import { MockDesktop } from './mock-desktop';
import { SoftHsmKeystore } from '../keystore/soft-hsm';
import type { Environment } from '../environment';
import type { ChallengeEvent } from '../protocol/event';
import type { LedgerClock } from '../protocol/replay';

export function createMockEnvironment(clock: LedgerClock): Environment {
  const desktop = new MockDesktop(clock);
  return {
    mode: 'mock',
    clock,
    keystore: SoftHsmKeystore.createTestOnly(),
    transport: desktop,
    link: desktop,
    demoQr: (deviceLabel?: string) => desktop.beginPairing(deviceLabel ?? 'Mock phone'),
    demoIssueChallenge: (deviceId: string, event: ChallengeEvent) =>
      JSON.stringify(desktop.issueChallenge(deviceId, event)),
    demoSetOnline: (online: boolean) => {
      desktop.online = online;
    },
  };
}
