/**
 * QR EC block structure -- GENERATED FILE, do not hand-edit.
 *
 * Source: `mobile/tools/gen-qr-vectors.py`, which reads
 * `qrcode.base.rs_blocks` (mirrors ISO/IEC 18004 Table 9). Regenerate with:
 *
 *   python mobile/tools/gen-qr-vectors.py
 *
 * Versions 1..25, error-correction levels L and M (the ones `qrcode.ts`
 * encodes). Each entry lists block groups as (count, totalCodewords per
 * block, dataCodewords per block).
 */

export interface EcBlockGroup {
  readonly count: number;
  readonly totalCodewords: number;
  readonly dataCodewords: number;
}

export type EcLevel = 'L' | 'M';

export const EC_BLOCKS: Readonly<
  Record<number, Readonly<Record<EcLevel, readonly EcBlockGroup[]>>>
> = {
  1: { L: [{ count: 1, totalCodewords: 26, dataCodewords: 19 }], M: [{ count: 1, totalCodewords: 26, dataCodewords: 16 }] },
  2: { L: [{ count: 1, totalCodewords: 44, dataCodewords: 34 }], M: [{ count: 1, totalCodewords: 44, dataCodewords: 28 }] },
  3: { L: [{ count: 1, totalCodewords: 70, dataCodewords: 55 }], M: [{ count: 1, totalCodewords: 70, dataCodewords: 44 }] },
  4: { L: [{ count: 1, totalCodewords: 100, dataCodewords: 80 }], M: [{ count: 2, totalCodewords: 50, dataCodewords: 32 }] },
  5: { L: [{ count: 1, totalCodewords: 134, dataCodewords: 108 }], M: [{ count: 2, totalCodewords: 67, dataCodewords: 43 }] },
  6: { L: [{ count: 2, totalCodewords: 86, dataCodewords: 68 }], M: [{ count: 4, totalCodewords: 43, dataCodewords: 27 }] },
  7: { L: [{ count: 2, totalCodewords: 98, dataCodewords: 78 }], M: [{ count: 4, totalCodewords: 49, dataCodewords: 31 }] },
  8: { L: [{ count: 2, totalCodewords: 121, dataCodewords: 97 }], M: [{ count: 2, totalCodewords: 60, dataCodewords: 38 }, { count: 2, totalCodewords: 61, dataCodewords: 39 }] },
  9: { L: [{ count: 2, totalCodewords: 146, dataCodewords: 116 }], M: [{ count: 3, totalCodewords: 58, dataCodewords: 36 }, { count: 2, totalCodewords: 59, dataCodewords: 37 }] },
  10: { L: [{ count: 2, totalCodewords: 86, dataCodewords: 68 }, { count: 2, totalCodewords: 87, dataCodewords: 69 }], M: [{ count: 4, totalCodewords: 69, dataCodewords: 43 }, { count: 1, totalCodewords: 70, dataCodewords: 44 }] },
  11: { L: [{ count: 4, totalCodewords: 101, dataCodewords: 81 }], M: [{ count: 1, totalCodewords: 80, dataCodewords: 50 }, { count: 4, totalCodewords: 81, dataCodewords: 51 }] },
  12: { L: [{ count: 2, totalCodewords: 116, dataCodewords: 92 }, { count: 2, totalCodewords: 117, dataCodewords: 93 }], M: [{ count: 6, totalCodewords: 58, dataCodewords: 36 }, { count: 2, totalCodewords: 59, dataCodewords: 37 }] },
  13: { L: [{ count: 4, totalCodewords: 133, dataCodewords: 107 }], M: [{ count: 8, totalCodewords: 59, dataCodewords: 37 }, { count: 1, totalCodewords: 60, dataCodewords: 38 }] },
  14: { L: [{ count: 3, totalCodewords: 145, dataCodewords: 115 }, { count: 1, totalCodewords: 146, dataCodewords: 116 }], M: [{ count: 4, totalCodewords: 64, dataCodewords: 40 }, { count: 5, totalCodewords: 65, dataCodewords: 41 }] },
  15: { L: [{ count: 5, totalCodewords: 109, dataCodewords: 87 }, { count: 1, totalCodewords: 110, dataCodewords: 88 }], M: [{ count: 5, totalCodewords: 65, dataCodewords: 41 }, { count: 5, totalCodewords: 66, dataCodewords: 42 }] },
  16: { L: [{ count: 5, totalCodewords: 122, dataCodewords: 98 }, { count: 1, totalCodewords: 123, dataCodewords: 99 }], M: [{ count: 7, totalCodewords: 73, dataCodewords: 45 }, { count: 3, totalCodewords: 74, dataCodewords: 46 }] },
  17: { L: [{ count: 1, totalCodewords: 135, dataCodewords: 107 }, { count: 5, totalCodewords: 136, dataCodewords: 108 }], M: [{ count: 10, totalCodewords: 74, dataCodewords: 46 }, { count: 1, totalCodewords: 75, dataCodewords: 47 }] },
  18: { L: [{ count: 5, totalCodewords: 150, dataCodewords: 120 }, { count: 1, totalCodewords: 151, dataCodewords: 121 }], M: [{ count: 9, totalCodewords: 69, dataCodewords: 43 }, { count: 4, totalCodewords: 70, dataCodewords: 44 }] },
  19: { L: [{ count: 3, totalCodewords: 141, dataCodewords: 113 }, { count: 4, totalCodewords: 142, dataCodewords: 114 }], M: [{ count: 3, totalCodewords: 70, dataCodewords: 44 }, { count: 11, totalCodewords: 71, dataCodewords: 45 }] },
  20: { L: [{ count: 3, totalCodewords: 135, dataCodewords: 107 }, { count: 5, totalCodewords: 136, dataCodewords: 108 }], M: [{ count: 3, totalCodewords: 67, dataCodewords: 41 }, { count: 13, totalCodewords: 68, dataCodewords: 42 }] },
  21: { L: [{ count: 4, totalCodewords: 144, dataCodewords: 116 }, { count: 4, totalCodewords: 145, dataCodewords: 117 }], M: [{ count: 17, totalCodewords: 68, dataCodewords: 42 }] },
  22: { L: [{ count: 2, totalCodewords: 139, dataCodewords: 111 }, { count: 7, totalCodewords: 140, dataCodewords: 112 }], M: [{ count: 17, totalCodewords: 74, dataCodewords: 46 }] },
  23: { L: [{ count: 4, totalCodewords: 151, dataCodewords: 121 }, { count: 5, totalCodewords: 152, dataCodewords: 122 }], M: [{ count: 4, totalCodewords: 75, dataCodewords: 47 }, { count: 14, totalCodewords: 76, dataCodewords: 48 }] },
  24: { L: [{ count: 6, totalCodewords: 147, dataCodewords: 117 }, { count: 4, totalCodewords: 148, dataCodewords: 118 }], M: [{ count: 6, totalCodewords: 73, dataCodewords: 45 }, { count: 14, totalCodewords: 74, dataCodewords: 46 }] },
  25: { L: [{ count: 8, totalCodewords: 132, dataCodewords: 106 }, { count: 4, totalCodewords: 133, dataCodewords: 107 }], M: [{ count: 8, totalCodewords: 75, dataCodewords: 47 }, { count: 13, totalCodewords: 76, dataCodewords: 48 }] },
};

/** Highest version this table covers (larger payloads are rejected). */
export const MAX_QR_VERSION = 25;
