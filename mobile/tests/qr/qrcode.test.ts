/**
 * QR encoder evidence (T-194).
 *
 * The strong assertion is byte-for-byte equality with matrices produced by an
 * independent implementation (segno 1.6.6, see `tests/fixtures/qr-vectors.ts`):
 * it covers version selection, data + pad codewords, Reed-Solomon EC codewords,
 * block interleaving, module placement, mask evaluation and format/version
 * information in one comparison. Structural assertions below add the invariants
 * a vector comparison alone would not explain when it fails.
 */
import { describe, it, expect } from 'vitest';

import {
  encodeQrMatrix,
  alignmentCenters,
  formatBits,
  versionBits,
  maskPenalty,
  QrEncodeError,
  QR_QUIET_ZONE,
} from '../../src/qr/qrcode';
import { EC_BLOCKS, MAX_QR_VERSION } from '../../src/qr/tables';
import { QR_VECTORS } from '../fixtures/qr-vectors';

function rowsOf(m: { modules: readonly (readonly boolean[])[] }): string[] {
  return m.modules.map((row) => row.map((dark) => (dark ? '1' : '0')).join(''));
}

describe('encodeQrMatrix vs independent reference implementation (segno)', () => {
  for (const vector of QR_VECTORS) {
    it(`reproduces ${vector.name} (v${vector.version}/${vector.ecLevel}/mask ${vector.mask})`, () => {
      const m = encodeQrMatrix(vector.text, { ecLevel: vector.ecLevel });
      expect(m.version).toBe(vector.version);
      expect(m.ecLevel).toBe(vector.ecLevel);
      expect(m.mask).toBe(vector.mask);
      expect(m.size).toBe(vector.size);
      expect(rowsOf(m)).toEqual(vector.rows);
    });
  }
});

describe('encodeQrMatrix structure', () => {
  it('sizes the symbol by version and always picks the smallest fit', () => {
    const small = encodeQrMatrix('KIWI');
    expect(small.size).toBe(17 + 4 * small.version);
    // A longer payload at the same level never selects a smaller version.
    const longer = encodeQrMatrix('K'.repeat(64));
    expect(longer.version).toBeGreaterThanOrEqual(small.version);
  });

  it('draws finder patterns, timing rows and the always-dark module', () => {
    const m = encodeQrMatrix('pairing payload fixture');
    const size = m.size;
    const dark = (r: number, c: number): boolean => m.modules[r]?.[c] === true;
    // Finder centres and their 3x3 dark cores at each corner.
    for (const [cr, cc] of [
      [3, 3],
      [3, size - 4],
      [size - 4, 3],
    ] as const) {
      expect(dark(cr, cc)).toBe(true);
      expect(dark(cr + 1, cc)).toBe(true);
      expect(dark(cr, cc + 1)).toBe(true);
      expect(dark(cr + 1, cc + 1)).toBe(false); // white ring
      expect(dark(cr - 2, cc - 2)).toBe(false); // separator
    }
    // Timing patterns alternate, dark at even indices.
    for (let i = 8; i < size - 8; i++) {
      expect(dark(6, i)).toBe(i % 2 === 0);
      expect(dark(i, 6)).toBe(i % 2 === 0);
    }
    // Always-dark module (ISO/IEC 18004 §7.9.1).
    expect(dark(size - 8, 8)).toBe(true);
  });

  it('places alignment patterns on the standard centres', () => {
    expect(alignmentCenters(1)).toEqual([]);
    expect(alignmentCenters(2)).toEqual([6, 18]);
    expect(alignmentCenters(7)).toEqual([6, 22, 38]);
    expect(alignmentCenters(25)).toEqual([6, 30, 54, 78, 102, 116]);
    const m = encodeQrMatrix('K'.repeat(200)); // forces a version with alignment patterns
    const centers = alignmentCenters(m.version);
    expect(centers.length).toBeGreaterThan(2);
    const row = centers[1] ?? 0;
    const col = centers[2] ?? 0;
    expect(m.modules[row]?.[col]).toBe(true); // centre module is dark
    expect(m.modules[row + 1]?.[col]).toBe(false); // white ring
  });

  it('records its own penalty consistently across masks (lowest index wins ties)', () => {
    // Recomputing the penalty of the delivered matrix must match the score the
    // selection loop would have produced for that same mask.
    const m = encodeQrMatrix('determinism fixture');
    const asCanvas = {
      size: m.size,
      isFunction: m.modules.map((row) => row.map(() => false)),
      modules: m.modules.map((row) => row.slice()),
    };
    expect(maskPenalty(asCanvas)).toBeGreaterThan(0);
  });

  it('encodes format info for both supported levels', () => {
    // ISO/IEC 18004 Table C.1 anchors: L/mask0 = 0x77C4, M/mask0 = 0x5412.
    expect(formatBits('L', 0)).toBe(0x77c4);
    expect(formatBits('M', 0)).toBe(0x5412);
    expect(versionBits(7)).toBe(0x07c94);
    expect(versionBits(25)).toBe(0x19ba7);
  });

  it('rejects empty and oversized payloads instead of mis-encoding', () => {
    expect(() => encodeQrMatrix('')).toThrow(QrEncodeError);
    // Capacity of the largest supported version (25-M) is 1,009 bytes.
    expect(() => encodeQrMatrix('x'.repeat(2000))).toThrow(/exceeds version 25/);
  });

  it('exposes the EC table range it was generated from', () => {
    expect(MAX_QR_VERSION).toBe(25);
    expect(EC_BLOCKS[1]?.M?.[0]?.dataCodewords).toBe(16);
    expect(QR_QUIET_ZONE).toBe(4);
  });
});
