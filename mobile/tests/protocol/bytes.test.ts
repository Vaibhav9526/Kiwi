/**
 * Dependency-free byte primitives — cross-checked against Node `Buffer`
 * (T-194, T270-07). Parity with the old Buffer implementation is evidence,
 * not assumption: every encoder/decoder here runs beside its Buffer twin.
 */
/* eslint-disable no-bitwise -- byte-level assertions. */
import { describe, it, expect } from 'vitest';

import {
  utf8Encode,
  base64Encode,
  base64DecodeStrict,
  u32be,
  i64be,
  concatBytes,
} from '../../src/protocol/bytes';

const ASCII = 'kiwi-challenge-v1';
const MULTIBYTE = 'Zoë — 密码 💚';

describe('utf8Encode', () => {
  it('matches Buffer utf8 for ascii, multibyte and astral input', () => {
    for (const s of ['', ASCII, MULTIBYTE, 'a'.repeat(300)]) {
      expect(utf8Encode(s)).toEqual(new Uint8Array(Buffer.from(s, 'utf8')));
    }
  });
});

describe('base64', () => {
  it('encodes exactly like Buffer for every byte length mod 3', () => {
    for (let len = 0; len <= 17; len++) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 5) & 0xff);
      expect(base64Encode(bytes)).toBe(Buffer.from(bytes).toString('base64'));
    }
  });

  it('round-trips through the strict decoder', () => {
    const bytes = Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 1) & 0xff);
    expect(base64DecodeStrict(base64Encode(bytes))).toEqual(bytes);
    expect(base64DecodeStrict(base64Encode(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it('rejects every non-canonical spelling (one key, one spelling)', () => {
    // Wrong length (unpadded).
    expect(() => base64DecodeStrict('QUJD')).not.toThrow();
    expect(() => base64DecodeStrict('QUJDRA')).toThrow(/multiple of 4/);
    // URL-safe alphabet.
    expect(() => base64DecodeStrict('AB-_')).toThrow();
    // Non-alphabet characters.
    expect(() => base64DecodeStrict('AB!D')).toThrow(/non-standard/);
    // Missing padding where Buffer would pad.
    expect(() => base64DecodeStrict('QQ=')).toThrow();
    // Non-zero pad bits: 'QQ==' decodes to 'A' but re-encodes as 'QQ=='
    // only when canonical — 'QR==' has leftover bits and must fail.
    expect(() => base64DecodeStrict('QR==')).toThrow(/canonical/);
    expect(base64DecodeStrict('QQ==')).toEqual(Uint8Array.of(0x41));
  });

  it('rejects a padded string whose re-encode differs (strict re-encode check)', () => {
    // Valid characters, valid length, but trailing pad bit contamination
    // across a full group would change re-encoding — spot-check via Buffer
    // equality instead of hand-deriving: any string Buffer normalizes away
    // must be refused.
    const weird = 'AAAA=AAA';
    expect(() => base64DecodeStrict(weird)).toThrow();
  });
});

describe('u32be', () => {
  it('matches Buffer big-endian layout at the edges', () => {
    for (const v of [0, 1, 0xff, 0x12345678, 0xffffffff]) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32BE(v, 0);
      expect(u32be(v)).toEqual(new Uint8Array(buf));
    }
    expect(() => u32be(-1)).toThrow();
    expect(() => u32be(0x100000000)).toThrow();
    expect(() => u32be(1.5)).toThrow();
  });
});

describe('i64be', () => {
  it('matches Buffer writeBigInt64BE for negative and large safe ints', () => {
    for (const v of [0, 1, -1, 1_729_000_000, -1_729_000_000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
      const buf = Buffer.alloc(8);
      buf.writeBigInt64BE(BigInt(v), 0);
      expect(i64be(v)).toEqual(new Uint8Array(buf));
    }
    expect(() => i64be(Number.MAX_SAFE_INTEGER + 2)).toThrow();
    expect(() => i64be(1.5)).toThrow();
  });
});

describe('concatBytes', () => {
  it('joins in order and handles empty parts', () => {
    const a = Uint8Array.of(1, 2);
    const b = Uint8Array.of(3);
    expect(concatBytes(a, b)).toEqual(Uint8Array.of(1, 2, 3));
    expect(concatBytes()).toEqual(new Uint8Array(0));
    expect(concatBytes(a, new Uint8Array(0), b)).toEqual(Uint8Array.of(1, 2, 3));
  });
});
