/**
 * Dev NaCl keystore — real Ed25519 signatures the desktop verifies.
 *
 * Proves: generate → 32-byte public key, sign → 64-byte signature that
 * verifies against the public half, wrong message fails, delete forgets,
 * duplicate alias fails closed. Deterministic assertions only on shapes
 * and verify outcomes — never on key bytes.
 */
import { describe, it, expect } from 'vitest';

import { DevNaclKeystore } from '../../src/keystore/nacl-keystore';
import { base64DecodeStrict } from '../../src/protocol/bytes';

describe('DevNaclKeystore', () => {
  it('generates a 32-byte key and signs verifiably', async () => {
    const ks = new DevNaclKeystore();
    const handle = await ks.generateKey('usb-phone');
    expect(handle.algorithm).toBe('ed25519');
    expect(base64DecodeStrict(handle.publicKeyB64).length).toBe(32);
    expect(await ks.hasKey(handle.keystoreRef)).toBe(true);

    const message = new Uint8Array([1, 2, 3, 4, 5]);
    const sig = await ks.sign(handle.keystoreRef, message);
    expect(sig.length).toBe(64);
    expect(await ks.verifyPublic(handle.publicKeyB64, message, sig)).toBe(true);
    expect(await ks.verifyPublic(handle.publicKeyB64, new Uint8Array([9, 9, 9]), sig)).toBe(false);
  });

  it('fails closed on duplicates, unknown refs, and bad aliases', async () => {
    const ks = new DevNaclKeystore();
    await ks.generateKey('dup');
    await expect(ks.generateKey('dup')).rejects.toThrow();
    await expect(ks.sign('dev-nacl:missing', new Uint8Array([1]))).rejects.toThrow();
    await expect(ks.generateKey('')).rejects.toThrow();
    await expect(ks.generateKey('has space')).rejects.toThrow();
  });

  it('delete zeroizes and forgets', async () => {
    const ks = new DevNaclKeystore();
    const handle = await ks.generateKey('forget-me');
    await ks.deleteKey(handle.keystoreRef);
    expect(await ks.hasKey(handle.keystoreRef)).toBe(false);
    await expect(ks.sign(handle.keystoreRef, new Uint8Array([1]))).rejects.toThrow();
  });
});
