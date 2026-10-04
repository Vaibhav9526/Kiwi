/**
 * HTTP desktop link/transport — endpoint math + wire behavior over a stubbed
 * fetch. Proves: base derivation, override precedence, adb-reverse loopback
 * fallback, hello/pull/status/response mapping, fail-closed errors, and
 * malformed-row tolerance. No sockets, no secrets.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  baseOf,
  baseCandidates,
  HttpAuthenticatorLink,
  HttpChallengeTransport,
  createEndpointStore,
} from '../../src/transport/http';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const CHALLENGE = {
  schema_version: 1,
  challenge_id: 'chg-http-0001',
  device_id: 'dev-http-1',
  session_id: 'boot-http-1',
  event: 'device-pairing',
  nonce_b64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  issued_unix: 1729000000,
  expires_unix: 1729000120,
};

describe('baseOf / baseCandidates', () => {
  it('derives the origin from a QR endpoint', () => {
    expect(baseOf('http://192.168.1.20:49310/pair')).toBe('http://192.168.1.20:49310');
    expect(baseOf('http://127.0.0.1:49310/pair')).toBe('http://127.0.0.1:49310');
  });

  it('rejects non-dev endpoints fail-closed', () => {
    expect(() => baseOf('wss://10.0.0.2:49310/pair')).toThrow();
    expect(() => baseOf('')).toThrow();
    expect(() => baseOf('http://has space/pair')).toThrow();
  });

  it('prefers the override and adds the adb-reverse loopback fallback', () => {
    const store = createEndpointStore();
    store.qrEndpoint = 'http://192.168.1.20:49310/pair';
    expect(baseCandidates(store)).toEqual([
      'http://192.168.1.20:49310',
      'http://127.0.0.1:49310',
    ]);
    store.override = 'http://127.0.0.1:49310/pair';
    expect(baseCandidates(store)).toEqual([
      'http://127.0.0.1:49310',
      'http://192.168.1.20:49310',
    ]);
  });

  it('yields no candidates when nothing is set', () => {
    expect(baseCandidates(createEndpointStore())).toEqual([]);
  });
});

describe('HttpAuthenticatorLink', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('hello posts to the override base and returns the registration', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { type: 'kiwi-pairing-registered', device_id: 'dev-1', issued_unix: 42, v: 1 }),
    );
    const store = createEndpointStore();
    store.override = 'http://127.0.0.1:49310/pair';
    const link = new HttpAuthenticatorLink(store);
    const res = await link.hello({
      type: 'kiwi-pairing-hello',
      pairing_ticket: 'A'.repeat(43),
      device_label: 'Phone',
      device_public_key_b64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      keystore_ref: 'dev-nacl:x',
    });
    expect(res.device_id).toBe('dev-1');
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('http://127.0.0.1:49310/pair');
  });

  it('hello fails closed with no endpoint', async () => {
    const link = new HttpAuthenticatorLink(createEndpointStore());
    await expect(
      link.hello({
        type: 'kiwi-pairing-hello',
        pairing_ticket: 'A'.repeat(43),
        device_label: 'Phone',
        device_public_key_b64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        keystore_ref: 'dev-nacl:x',
      }),
    ).rejects.toThrow();
  });

  it('pullChallenges returns parsed rows and skips malformed ones', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { type: 'kiwi-challenges', challenges: [CHALLENGE, { bogus: true }], v: 1 }),
    );
    const store = createEndpointStore();
    store.qrEndpoint = 'http://192.168.1.20:49310/pair';
    const link = new HttpAuthenticatorLink(store);
    const rows = await link.pullChallenges('dev-http-1');
    expect(rows.length).toBe(1);
    expect(rows[0]?.challenge_id).toBe('chg-http-0001');
  });

  it('deviceStatus maps the desktop state', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { type: 'kiwi-device-status', device_id: 'dev-1', status: 'active', v: 1 }),
    );
    const store = createEndpointStore();
    store.qrEndpoint = 'http://192.168.1.20:49310/pair';
    const link = new HttpAuthenticatorLink(store);
    expect(await link.deviceStatus('dev-1')).toBe('active');
  });
});

describe('HttpChallengeTransport', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('delivers on 200 and reports offline without throwing on refusal', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { type: 'kiwi-challenge-result', ok: true, v: 1 }))
      .mockResolvedValueOnce(jsonResponse(400, { type: 'kiwi-pairing-error', error: 'ticket-invalid', v: 1 }));
    const store = createEndpointStore();
    store.override = 'http://127.0.0.1:49310/pair';
    const transport = new HttpChallengeTransport(store);
    const resp = {
      schema_version: 1 as const,
      challenge_id: 'chg-1',
      device_id: 'dev-1',
      session_id: 'boot-1',
      event: 'unlock' as const,
      signature_b64: 'A'.repeat(88),
      decision: 'approve' as const,
    };
    const ok = await transport.postResponse(resp);
    expect(ok.kind).toBe('delivered');
    const refused = await transport.postResponse(resp);
    expect(refused.kind).toBe('offline');
  });

  it('reports offline when no endpoint is set', async () => {
    const transport = new HttpChallengeTransport(createEndpointStore());
    const out = await transport.postResponse({
      schema_version: 1 as const,
      challenge_id: 'chg-1',
      device_id: 'dev-1',
      session_id: 'boot-1',
      event: 'unlock' as const,
      signature_b64: '',
      decision: 'deny' as const,
    });
    expect(out.kind).toBe('offline');
  });
});
