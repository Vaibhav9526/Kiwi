/**
 * Mock-import isolation (T-194; SECURITY.md rules 4, 7).
 *
 * The mock desktop and the soft-HSM test keystore are demo/test
 * affordances. Core protocol, transport, keystore interface, the
 * environment module and the screens must never reach for them directly —
 * they receive an injected `Environment`, and only `src/App.tsx` decides
 * which one (mock vs fail-closed). This test enforces the graph so the
 * boundary is structural, not aspirational.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

// vitest runs with the mobile package as root.
const SRC = join(process.cwd(), 'src');

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {out.push(...walk(full));}
    else {out.push(full);}
  }
  return out;
}

const files = walk(SRC);
const rel = (f: string): string => f.slice(SRC.length + 1).replace(/\\/g, '/');

/** Files (relative paths) that must stay mock-free (injected Environment only). */
const FORBIDDEN = files
  .map((f) => rel(f))
  .filter((r) => {
    return (
      r.startsWith('protocol/') ||
      r.startsWith('transport/') ||
      r === 'keystore/keystore.ts' ||
      r === 'environment.ts' ||
      r.startsWith('screens/')
    );
  });

const read = (r: string): string => readFileSync(join(SRC, r), 'utf8');

const MOCK_IMPORT = /from\s+['"][^'"]*(\/|^)(mock(\/|['"])|soft-hsm['"])/;

describe('mock isolation', () => {
  it('covers the intended source surface (not an empty allow-list)', () => {
    expect(FORBIDDEN.length).toBeGreaterThan(15);
    expect(FORBIDDEN).toContain('environment.ts');
    expect(FORBIDDEN).toContain('screens/PairingScreen.tsx');
    expect(FORBIDDEN).toContain('protocol/approval.ts');
    expect(FORBIDDEN).toContain('transport/link.ts');
    expect(FORBIDDEN).toContain('keystore/keystore.ts');
  });

  it('core, transport, keystore interface, environment and screens never import the mock or soft HSM', () => {
    const offenders = FORBIDDEN.filter((r) => MOCK_IMPORT.test(read(r)));
    expect(offenders).toEqual([]);
  });

  it('outside src/mock, only App.tsx may wire the mock in', () => {
    const importers = files
      .filter((f) => !rel(f).startsWith('mock/'))
      .filter((f) => /from\s+['"][^'"]*\/mock['"]/.test(readFileSync(f, 'utf8')))
      .map(rel);
    expect(importers).toEqual(['App.tsx']);
  });

  it('the soft-HSM keystore is only constructed by src/mock and tests', () => {
    const users = files
      .filter((f) => rel(f) !== 'keystore/soft-hsm.ts')
      .filter((f) => readFileSync(f, 'utf8').includes('soft-hsm'))
      .map(rel);
    expect(users).toEqual(['mock/index.ts']);
  });
});
