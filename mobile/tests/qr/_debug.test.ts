import { describe, it } from 'vitest';
import { encodeQrMatrix, maskPenalty } from '../../src/qr/qrcode';

describe('debug', () => {
  it('dumps', () => {
    const m = encodeQrMatrix('KIWI', { ecLevel: 'M' });
    // eslint-disable-next-line no-console
    console.log(`MASK=${m.mask} VERSION=${m.version}`);
    // eslint-disable-next-line no-console
    console.log(m.modules.map((row) => row.map((d) => (d ? '#' : '.')).join('')).join('\n'));
  });
});
