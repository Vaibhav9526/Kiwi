/**
 * Canonical-bytes evidence (T-136 contract §4.1). Proves the mobile encoder
 * matches the documented layout that kiwi-core signs/verifies, and that
 * every bound field is covered by the encoding.
 */
/* eslint-disable no-bitwise -- test asserts byte-level encoding output. */
import { describe, it, expect } from 'vitest';

import { canonicalChallengeBytes, parseChallengeData, buildChallengeResponseData, decodeB64 } from '../../src/protocol/canonical';
import { eventFromTag, eventTag } from '../../src/protocol/event';
import { validChallenge, NONCE, ISSUED, EXPIRES, canonicalOf } from '../helpers/protocol';

const DOMAIN = 'kiwi-challenge-v1';

describe('canonical challenge bytes', () => {
  it('encodes the exact documented layout', () => {
    const c = validChallenge();
    const bytes = canonicalOf(c);
    // 4+17 (domain) + 4+13 (chg-test-0001) + 4+13 (dev-test-0001)
    // + 4+14 (boot-test-0001) + 1 tag + 32 nonce + 8 + 8
    expect(bytes.length).toBe(4 + 17 + 4 + 13 + 4 + 13 + 4 + 14 + 1 + 32 + 8 + 8);
    // Domain length prefix = 17, then the domain string.
    expect([bytes[0], bytes[1], bytes[2], bytes[3]]).toEqual([0, 0, 0, 17]);
    expect(Buffer.from(bytes.slice(4, 21)).toString('utf8')).toBe(DOMAIN);
    // Event tag byte sits right after the three string fields.
    const tagOffset = (4 + 17) + (4 + 13) + (4 + 13) + (4 + 14);
    expect(bytes[tagOffset]).toBe(0x01);
    // Nonce follows raw (32 bytes), then i64be times.
    expect(Buffer.from(bytes.slice(tagOffset + 1, tagOffset + 33))).toEqual(Buffer.from(NONCE));
    const issued = Buffer.from(bytes.slice(tagOffset + 33, tagOffset + 41));
    expect(issued.readBigInt64BE(0)).toBe(BigInt(ISSUED));
    const expires = Buffer.from(bytes.slice(tagOffset + 41, tagOffset + 49));
    expect(expires.readBigInt64BE(0)).toBe(BigInt(EXPIRES));
  });

  it('covers every bound field — changing any of them changes the bytes', () => {
    const base = canonicalOf(validChallenge());
    const c = validChallenge();
    const variants: Array<[string, () => Uint8Array]> = [
      ['challenge_id', () => canonicalOf({ ...c, challenge_id: 'chg-test-0002' })],
      ['device_id', () => canonicalOf({ ...c, device_id: 'dev-test-0002' })],
      ['session_id', () => canonicalOf({ ...c, session_id: 'x-tx-test-0002' })],
      ['event', () => canonicalOf({ ...c, event: 'recovery' })],
      ['issued', () => canonicalOf({ ...c, issued_unix: ISSUED + 1 })],
      ['expires', () => canonicalOf({ ...c, expires_unix: EXPIRES + 1 })],
    ];
    for (const [name, make] of variants) {
      const bytes = make();
      expect(Buffer.from(bytes).equals(Buffer.from(base)), name).toBe(false);
    }
    // Nonce flip.
    const otherNonce = NONCE.slice();
    otherNonce[0] = (otherNonce[0] ?? 0) ^ 0xff;
    const nonceFlipped = canonicalChallengeBytes({
      challengeId: c.challenge_id,
      deviceId: c.device_id,
      sessionId: c.session_id,
      event: c.event,
      nonce: otherNonce,
      issuedUnix: c.issued_unix,
      expiresUnix: c.expires_unix,
    });
    expect(Buffer.from(nonceFlipped).equals(Buffer.from(base))).toBe(false);
  });

  it('event tags match the kiwi-core table', () => {
    expect(eventTag('unlock')).toBe(0x01);
    expect(eventTag('device-pairing')).toBe(0x02);
    expect(eventTag('recovery')).toBe(0x03);
    expect(eventTag('elevated-action')).toBe(0x04);
    expect(eventFromTag(0x04)).toBe('elevated-action');
    expect(eventFromTag(0x05)).toBeNull();
  });

  it('rejects a nonce that is not exactly 32 bytes', () => {
    const c = validChallenge();
    expect(() =>
      canonicalChallengeBytes({
        challengeId: c.challenge_id,
        deviceId: c.device_id,
        sessionId: c.session_id,
        event: c.event,
        nonce: new Uint8Array(31),
        issuedUnix: c.issued_unix,
        expiresUnix: c.expires_unix,
      }),
    ).toThrow(/32 bytes/);
  });
});

describe('challenge parsing (strict, unknown fields ignored)', () => {
  it('round-trips a valid challenge', () => {
    const parsed = parseChallengeData(validChallenge());
    expect(parsed).toEqual(validChallenge());
  });

  it('ignores unknown fields', () => {
    const withExtra = { ...validChallenge(), future_field: { nested: true } };
    expect(parseChallengeData(withExtra)).toEqual(validChallenge());
  });

  it('rejects wrong schema version, unknown event, bad nonce', () => {
    expect(() => parseChallengeData({ ...validChallenge(), schema_version: 2 })).toThrow(/schema_version/);
    expect(() => parseChallengeData({ ...validChallenge(), event: 'lunch' })).toThrow(/event/);
    expect(() => parseChallengeData({ ...validChallenge(), nonce_b64: 'short' })).toThrow();
    // 31-byte nonce (base64 without '=' padding round-trips shorter)
    const shortNonce = Buffer.from(Uint8Array.from({ length: 31 }, (_, i) => i)).toString('base64');
    expect(() => parseChallengeData({ ...validChallenge(), nonce_b64: shortNonce })).toThrow(/32 bytes/);
    expect(() =>
      parseChallengeData({ ...validChallenge(), expires_unix: ISSUED, issued_unix: ISSUED }),
    ).toThrow(/expiry/);
  });

  it('decodeB64 enforces exact decoded length', () => {
    expect(decodeB64(Buffer.from(NONCE).toString('base64'), 32, 'nonce')).toEqual(NONCE);
    expect(() => decodeB64('', 32, 'nonce')).toThrow();
    // Canonical padded base64 of exactly 3 bytes -> valid spelling, but it
    // is not the 32 bytes the field requires.
    const threeBytes = Buffer.from(new Uint8Array([0, 0, 0])).toString('base64');
    expect(() => decodeB64(threeBytes, 32, 'nonce')).toThrow(/exactly 32/);
    // Unpadded / non-canonical spellings fail before the length check.
    expect(() => decodeB64('AAAAAA', 3, 'nonce')).toThrow(/canonical/);
  });
});

describe('response building (§6.2)', () => {
  it('approve requires a 64-byte signature', () => {
    const c = validChallenge();
    const resp = buildChallengeResponseData(c, 'approve', Buffer.from(new Uint8Array(64)).toString('base64'));
    expect(resp.decision).toBe('approve');
    expect(resp.signature_b64.length).toBeGreaterThan(0);
    // Canonical base64 of the wrong length fails the byte-count check...
    const short = Buffer.from(new Uint8Array(63)).toString('base64');
    expect(() => buildChallengeResponseData(c, 'approve', short)).toThrow(/64 bytes/);
    // ...and non-base64 text never reaches it (fail closed, rule 9).
    expect(() => buildChallengeResponseData(c, 'approve', 'not-enough')).toThrow();
  });

  it('deny carries no signature', () => {
    const resp = buildChallengeResponseData(validChallenge(), 'deny', null);
    expect(resp.decision).toBe('deny');
    expect(resp.signature_b64).toBe('');
  });
});
