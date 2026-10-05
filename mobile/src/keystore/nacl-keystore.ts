/**
 * DEV Ed25519 keystore (USB bring-up) — real signatures, honest limits.
 *
 * The scaffold's `UnavailableKeystore` (fail-closed) and `SoftHsmKeystore`
 * (test-only, non-cryptographic) cannot complete a real pairing: the desktop
 * `Ed25519Verifier` would reject every approval. This keystore uses
 * tweetnacl (pure JS, no native modules, Hermes-compatible) to generate and
 * hold Ed25519 keypairs in memory and sign canonical challenge bytes, so a
 * USB-connected phone produces signatures the desktop actually verifies.
 *
 * HONEST LIMITS (bannered in the UI as DEV KEYS):
 * - keys live in JS memory, NOT the Android Keystore / Secure Enclave —
 *   this is a dev bridge, not the Phase-4 platform keystore (contract §5).
 * - keys do not survive app restart (memory-only); re-pair after relaunch.
 * - never use for production trust — the Phase-4 keystore module replaces
 *   this file behind the same `DeviceKeystore` interface.
 */
import nacl from 'tweetnacl';

import { KeystoreError, type DeviceKeystore, type KeystoreKeyHandle } from './keystore';
import { base64Encode, base64DecodeStrict } from '../protocol/bytes';

const REF_PREFIX = 'dev-nacl:';
const MAX_ALIAS = 128;

function assertAlias(alias: string): void {
  if (typeof alias !== 'string' || alias.length === 0 || alias.length > MAX_ALIAS) {
    throw new KeystoreError('fail-closed', 'key alias must be 1..128 chars');
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(alias)) {
    throw new KeystoreError('fail-closed', 'key alias has an unsupported shape');
  }
}

export class DevNaclKeystore implements DeviceKeystore {
  private readonly keys = new Map<string, nacl.BoxKeyPair | nacl.SignKeyPair>();

  async generateKey(alias: string): Promise<KeystoreKeyHandle> {
    assertAlias(alias);
    if (this.keys.has(alias)) {
      throw new KeystoreError('fail-closed', 'alias already exists');
    }
    const pair = nacl.sign.keyPair();
    this.keys.set(alias, pair);
    return {
      keystoreRef: `${REF_PREFIX}${alias}`,
      publicKeyB64: base64Encode(pair.publicKey),
      algorithm: 'ed25519',
    };
  }

  async sign(keystoreRef: string, message: Uint8Array): Promise<Uint8Array> {
    const alias = keystoreRef.startsWith(REF_PREFIX)
      ? keystoreRef.slice(REF_PREFIX.length)
      : keystoreRef;
    const pair = this.keys.get(alias) as nacl.SignKeyPair | undefined;
    if (pair === undefined || (pair as nacl.SignKeyPair).secretKey === undefined) {
      throw new KeystoreError('key-not-found', 'unknown keystoreRef');
    }
    return nacl.sign.detached(message, (pair as nacl.SignKeyPair).secretKey);
  }

  async deleteKey(keystoreRef: string): Promise<void> {
    const alias = keystoreRef.startsWith(REF_PREFIX)
      ? keystoreRef.slice(REF_PREFIX.length)
      : keystoreRef;
    const pair = this.keys.get(alias) as nacl.SignKeyPair | undefined;
    if (pair !== undefined && pair.secretKey !== undefined) {
      pair.secretKey.fill(0);
    }
    this.keys.delete(alias);
  }

  async hasKey(keystoreRef: string): Promise<boolean> {
    const alias = keystoreRef.startsWith(REF_PREFIX)
      ? keystoreRef.slice(REF_PREFIX.length)
      : keystoreRef;
    return this.keys.has(alias);
  }

  /** Test helper: verify a signature against a stored key's public half. */
  async verifyPublic(publicKeyB64: string, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    let publicKey: Uint8Array;
    try {
      publicKey = base64DecodeStrict(publicKeyB64);
    } catch {
      return false;
    }
    if (publicKey.length !== 32 || signature.length !== 64) {
      return false;
    }
    return nacl.sign.detached.verify(message, signature, publicKey);
  }
}
