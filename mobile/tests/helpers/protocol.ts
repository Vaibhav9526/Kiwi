/**
 * Synthetic fixture helpers (T-136 tests). SECURITY.md §4: fixtures are
 * synthetic and generated in-test — never real keys, tickets, or ids.
 * The "signature" bytes here are non-cryptographic filler; only the
 * protocol plumbing is exercised, never a real trust decision.
 */
/* eslint-disable no-bitwise -- fixture byte assembly compares raw bytes. */
import { canonicalChallengeBytes } from '../../src/protocol/canonical';
import type { ChallengeData } from '../../src/protocol/types';

export const ISSUED = 1_729_000_000;
export const EXPIRES = ISSUED + 120;

export const NONCE = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 3) & 0xff);

export function validChallenge(): ChallengeData {
  return {
    schema_version: 1,
    challenge_id: 'chg-test-0001',
    device_id: 'dev-test-0001',
    // §4.2 session grammar: unlock/device-pairing => boot-<...> form.
    session_id: 'boot-test-0001',
    event: 'unlock',
    nonce_b64: Buffer.from(NONCE).toString('base64'),
    issued_unix: ISSUED,
    expires_unix: EXPIRES,
  };
}

/** Non-cryptographic 64-byte filler standing in for an Ed25519 signature. */
export function fakeSignature(seed = 7): string {
  return Buffer.from(Uint8Array.from({ length: 64 }, (_, i) => (i * seed + 1) & 0xff)).toString('base64');
}

export function canonicalOf(c: ChallengeData): Uint8Array {
  return canonicalChallengeBytes({
    challengeId: c.challenge_id,
    deviceId: c.device_id,
    sessionId: c.session_id,
    event: c.event,
    nonce: new Uint8Array(Buffer.from(c.nonce_b64, 'base64')),
    issuedUnix: c.issued_unix,
    expiresUnix: c.expires_unix,
  });
}
