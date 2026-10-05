/**
 * TEST-ONLY software keystore stub (T-136 contract §5, §8; T-194 mock mode).
 *
 * NOT a signature scheme. SECURITY.md rule 7: stubs sit behind interfaces,
 * are explicitly marked, and fail closed. This class:
 *  - is constructed only by `src/mock` (the labelled mock environment) and
 *    tests — `tests/isolation/mock-isolation.test.ts` proves no core,
 *    transport or screen module reaches it directly;
 *  - reaches the UI only through the app's MOCK mode, which is bannered
 *    as demo-only (mock signatures authorize nothing);
 *  - derives deterministic NON-CRYPTOGRAPHIC bytes for fixtures, so tests
 *    are reproducible without any key material or CSPRNG;
 *  - refuses every operation unless constructed through `createTestOnly()`;
 *  - its 64-byte "signatures" verify nothing and MUST never be trusted —
 *    they exist only to exercise response-building/plumbing paths.
 *
 * Production signing is the platform keystore's job (SECURITY.md rule 8).
 */
/* eslint-disable no-bitwise -- test-only xorshift fixture RNG is bitwise by construction. */
import { KeystoreError, type DeviceKeystore, type KeystoreKeyHandle } from './keystore';

interface SoftKey {
  seed: Uint8Array;
  publicKey: Uint8Array;
}

export class SoftHsmKeystore implements DeviceKeystore {
  private readonly keys = new Map<string, SoftKey>();

  private constructor(private readonly allowTesting: boolean) {}

  /** The ONLY way to get an instance — makes the test-only intent explicit. */
  static createTestOnly(): SoftHsmKeystore {
    return new SoftHsmKeystore(true);
  }

  async generateKey(alias: string): Promise<KeystoreKeyHandle> {
    this.assertTestMode();
    if (this.keys.has(alias)) {
      throw new KeystoreError('fail-closed', `alias already exists: ${alias.length} chars kept private`);
    }
    // Deterministic synthetic seed — NOT entropy, NOT a real key. Fixture only.
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = (i * 7 + (alias.charCodeAt(i % alias.length) ?? 0)) & 0xff;
    }
    const publicKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      publicKey[i] = (seed[i] ?? 0) ^ 0xa5; // visibly derived; no crypto meaning
    }
    this.keys.set(alias, { seed, publicKey });
    return {
      keystoreRef: `soft-hsm:${alias}`,
      publicKeyB64: toB64(publicKey),
      algorithm: 'ed25519',
    };
  }

  async sign(keystoreRef: string, message: Uint8Array): Promise<Uint8Array> {
    this.assertTestMode();
    const alias = keystoreRef.startsWith('soft-hsm:') ? keystoreRef.slice(9) : keystoreRef;
    const key = this.keys.get(alias);
    if (!key) {throw new KeystoreError('key-not-found', 'unknown keystoreRef');}
    // Non-cryptographic 64-byte filler so plumbing tests have shape.
    const out = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      out[i] = ((key.seed[i % 32] ?? 0) ^ (message[i % message.length] ?? 0) ^ i) & 0xff;
    }
    return out;
  }

  async deleteKey(keystoreRef: string): Promise<void> {
    this.assertTestMode();
    const alias = keystoreRef.startsWith('soft-hsm:') ? keystoreRef.slice(9) : keystoreRef;
    this.keys.delete(alias);
  }

  async hasKey(keystoreRef: string): Promise<boolean> {
    const alias = keystoreRef.startsWith('soft-hsm:') ? keystoreRef.slice(9) : keystoreRef;
    return this.keys.has(alias);
  }

  private assertTestMode(): void {
    if (!this.allowTesting) {
      throw new KeystoreError('fail-closed', 'SoftHsmKeystore is test-only');
    }
  }
}

/** Minimal dependency-free base64 (RFC 4648) for scaffold handles. */
function toB64(bytes: Uint8Array): string {
  const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    out += table[b0 >> 2];
    out += table[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? table[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? table[b2 & 0x3f] : '=';
  }
  return out;
}
