/* eslint-disable no-bitwise -- byte assembly is bitwise by nature. */
/**
 * Dependency-free byte primitives (T-194).
 *
 * The T-136 scaffold encoded with Node's global `Buffer`, which Hermes does
 * not provide — canonical bytes and base64 would crash on a device before
 * any signature existed (T270-07). These functions are pure, deterministic,
 * and identical to the `Buffer` results they replace; the test suite
 * cross-checks every path against `Buffer` in Node, so parity is evidence,
 * not an assumption. No I/O, no AI (SECURITY.md rule 1).
 */

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP: Record<string, number> = {};
for (let i = 0; i < BASE64_ALPHABET.length; i++) {
  BASE64_LOOKUP[BASE64_ALPHABET[i] ?? ''] = i;
}

/** UTF-8 encode a string to bytes (astral code points included). */
export function utf8Encode(input: string): Uint8Array {
  const out: number[] = [];
  for (const ch of input) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    }
  }
  return Uint8Array.from(out);
}

/** RFC 4648 standard base64, always padded — matches `Buffer#toString('base64')`. */
export function base64Encode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    out += BASE64_ALPHABET[b0 >> 2] ?? '';
    out += BASE64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] ?? '';
    out += i + 1 < bytes.length ? (BASE64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] ?? '') : '=';
    out += i + 2 < bytes.length ? (BASE64_ALPHABET[b2 & 0x3f] ?? '') : '=';
  }
  return out;
}

/**
 * Strict RFC 4648 base64 decode: standard alphabet only, canonical padding,
 * canonical re-encode (rejects URL-safe/unpadded/non-zero-pad-bit spellings).
 * Throws on anything non-canonical — the same shape as the desktop's
 * `check_desktop_key` (ipc.md §9d.8).
 */
export function base64DecodeStrict(input: string): Uint8Array {
  if (input.length % 4 !== 0) {
    throw new Error('base64 length must be a multiple of 4');
  }
  const body = input.endsWith('==') ? input.slice(0, input.length - 2)
    : input.endsWith('=') ? input.slice(0, input.length - 1)
      : input;
  const out: number[] = [];
  for (let i = 0; i < body.length; i += 4) {
    const groupLen = Math.min(4, body.length - i);
    if (groupLen < 2) {throw new Error('invalid base64 group');}
    const c0 = sextet(body, i);
    const c1 = sextet(body, i + 1);
    out.push((c0 << 2) | (c1 >> 4));
    if (groupLen >= 3) {
      const c2 = sextet(body, i + 2);
      out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
    }
    if (groupLen === 4) {
      const c2 = sextet(body, i + 2);
      const c3 = sextet(body, i + 3);
      out.push(((c2 & 0x03) << 6) | c3);
    }
  }
  const bytes = Uint8Array.from(out);
  // Canonical check: non-zero pad bits in the final group, missing/extra
  // padding, or a wrong alphabet all re-encode differently — one key has
  // exactly one spelling, same as the desktop's check_desktop_key (§9d.8).
  if (base64Encode(bytes) !== input) {
    throw new Error('base64 is not canonical');
  }
  return bytes;
}

function sextet(s: string, index: number): number {
  const ch = s[index];
  const v = ch === undefined ? -1 : (BASE64_LOOKUP[ch] ?? -1);
  if (v < 0) {throw new Error('base64 contains a non-standard character');}
  return v;
}

/** Big-endian u32 of a safe non-negative integer (< 2^32). */
export function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('u32be value must be an integer in 0..2^32-1');
  }
  return Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

/**
 * Big-endian i64 of a safe integer (|n| < 2^53) — two's-complement without
 * BigInt, which older Hermes builds lack. Split is arithmetic, so no
 * bit-by-bit 64-bit emulation can drift from `Buffer#writeBigInt64BE`
 * (cross-checked in tests).
 */
export function i64be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value)) {
    throw new Error('i64be value must be a safe integer');
  }
  const hi = Math.floor(value / 0x100000000);
  const lo = value - hi * 0x100000000;
  const hiU = hi < 0 ? hi + 0x100000000 : hi;
  return Uint8Array.from([
    (hiU >>> 24) & 0xff,
    (hiU >>> 16) & 0xff,
    (hiU >>> 8) & 0xff,
    hiU & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  ]);
}

/** Concatenate byte arrays into one buffer. */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {total += p.length;}
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
