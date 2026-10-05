/**
 * Desktop (USB/LAN) environment factory — the real-thing counterpart to
 * `src/mock/index.ts`, wired ONLY by `src/App.tsx`.
 *
 * - `DevNaclKeystore`: real Ed25519 signatures the desktop verifies
 *   (dev-grade: memory-only keys, NOT the Android Keystore — bannered).
 * - `HttpAuthenticatorLink` + `HttpChallengeTransport`: the desktop's
 *   `KIWI_PAIR_LISTEN` dev listener over LAN or `adb reverse` USB.
 *
 * Isolation note: the mock-isolation suite constrains mock-only imports —
 * this module is the production-shaped path and is equally injected
 * (screens never construct it directly).
 */
import type { Environment } from './environment';
import { DevNaclKeystore } from './keystore/nacl-keystore';
import {
  HttpAuthenticatorLink,
  HttpChallengeTransport,
  createEndpointStore,
  type DesktopEndpointStore,
} from './transport/http';
import { SystemClock, type LedgerClock } from './protocol/replay';

export interface DesktopEnvironmentBundle {
  environment: Environment;
  endpointStore: DesktopEndpointStore;
}

export function createDesktopEnvironment(clock: LedgerClock = new SystemClock()): DesktopEnvironmentBundle {
  const endpointStore = createEndpointStore();
  const link = new HttpAuthenticatorLink(endpointStore);
  const environment: Environment = {
    mode: 'desktop',
    clock,
    keystore: new DevNaclKeystore(),
    transport: new HttpChallengeTransport(endpointStore),
    link,
  };
  return { environment, endpointStore };
}

export type { DesktopEndpointStore };
