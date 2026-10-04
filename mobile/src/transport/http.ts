/**
 * HTTP desktop link + transport (USB/LAN bring-up, dev-only).
 *
 * Talks to the desktop's `KIWI_PAIR_LISTEN` dev listener (plaintext HTTP on
 * the LAN/USB bridge — authenticator.md §3.2 open item; NOT the shipping
 * wss/TLS transport). Same `AuthenticatorLink` / `ChallengeTransport`
 * interfaces as the mock, so the screens run unmodified:
 *
 *   hello → POST {base}/pair
 *   pullChallenges → GET {base}/challenges?device_id=…
 *   deviceStatus → GET {base}/device-status?device_id=…
 *   postResponse → POST {base}/response
 *
 * Endpoint sourcing (fail-closed, never invented):
 * - the QR `desktop_endpoint` (set per pairing — see `noteQrEndpoint`) is
 *   the primary base;
 * - an operator override (the app's endpoint textbox, e.g.
 *   `http://127.0.0.1:49310/pair` after `adb reverse`) wins when set;
 * - a 127.0.0.1 same-port fallback is tried whenever the primary host is
 *   not loopback, so `adb reverse tcp:<port> tcp:<port>` works without
 *   re-scanning the QR.
 * - non-`http://` endpoints (`wss://`, provisioned TLS names) are rejected
 *   with a clear error — the TLS transport is Phase 4.
 *
 * Bounds: every outbound id is length-checked before it touches the URL;
 * every inbound payload is parsed by the strict protocol parsers (a single
 * malformed challenge row is skipped, never fatal); raw error text is
 * bounded to 160 chars and never echoes secrets.
 */
import { parseChallengeData } from '../protocol/canonical';
import type { ChallengeData, ChallengeResponseData } from '../protocol/types';
import type { AuthenticatorLink, DeviceStatus, PairingHello, PairingRegistered } from './link';
import type { ChallengeTransport, TransportResult } from './transport';

export interface DesktopEndpointStore {
  qrEndpoint: string | null;
  override: string | null;
}

export function createEndpointStore(): DesktopEndpointStore {
  return { qrEndpoint: null, override: null };
}

const TIMEOUT_MS = 8000;
const MAX_ID = 128;

function bounded(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : fallback;
  return msg.length > 160 ? `${msg.slice(0, 160)}…` : msg;
}

/** `http://host:port/pair` → `http://host:port`; throws fail-closed. */
export function baseOf(endpoint: string): string {
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > 256) {
    throw new Error('desktop endpoint is not usable');
  }
  if (!endpoint.startsWith('http://')) {
    throw new Error('desktop endpoint needs the dev http:// channel (TLS lands in Phase 4)');
  }
  const rest = endpoint.slice('http://'.length);
  if (rest.length === 0 || /\s/.test(rest)) {
    throw new Error('desktop endpoint is not usable');
  }
  const slash = rest.indexOf('/');
  const hostPort = slash === -1 ? rest : rest.slice(0, slash);
  if (hostPort.length === 0 || hostPort.includes('?') || hostPort.includes('#')) {
    throw new Error('desktop endpoint is not usable');
  }
  return `http://${hostPort}`;
}

function portOf(base: string): string | null {
  const m = /:(\d+)$/.exec(base.slice('http://'.length));
  return m === null ? null : (m[1] ?? null);
}

/** Ordered dial candidates: override → QR → loopback same-port fallback. */
export function baseCandidates(store: DesktopEndpointStore): string[] {
  const out: string[] = [];
  const push = (endpoint: string | null): void => {
    if (endpoint === null) {
      return;
    }
    try {
      const base = baseOf(endpoint);
      if (!out.includes(base)) {
        out.push(base);
      }
    } catch {
      // Invalid entries are skipped here; the caller re-raises a clear
      // error when NO candidate survives.
    }
  };
  push(store.override);
  push(store.qrEndpoint);
  const primary = out[0];
  if (primary !== undefined && !primary.startsWith('http://127.0.0.1') && !primary.startsWith('http://localhost')) {
    const port = portOf(primary);
    if (port !== null) {
      const loopback = `http://127.0.0.1:${port}`;
      if (!out.includes(loopback)) {
        out.push(loopback);
      }
    }
  }
  return out;
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function assertDeviceId(deviceId: string): void {
  if (typeof deviceId !== 'string' || deviceId.length === 0 || deviceId.length > MAX_ID) {
    throw new Error('device id is not usable');
  }
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text.length === 0 || text.length > 65536) {
    throw new Error('desktop reply is not usable');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error('desktop reply is not usable');
  }
}

export class HttpAuthenticatorLink implements AuthenticatorLink {
  constructor(private readonly store: DesktopEndpointStore) {}

  /** Remember the QR endpoint the user just scanned/pasted. */
  noteQrEndpoint(endpoint: string): void {
    this.store.qrEndpoint = endpoint;
  }

  private candidates(): string[] {
    const bases = baseCandidates(this.store);
    if (bases.length === 0) {
      throw new Error('no desktop endpoint — scan the QR or set http://127.0.0.1:<port>/pair');
    }
    return bases;
  }

  async hello(msg: PairingHello): Promise<PairingRegistered> {
    if (msg.type !== 'kiwi-pairing-hello') {
      throw new Error('unexpected pairing message type');
    }
    const body = JSON.stringify({
      type: 'kiwi-pairing-hello',
      pairing_ticket: msg.pairing_ticket,
      device_public_key_b64: msg.device_public_key_b64,
      keystore_ref: msg.keystore_ref,
    });
    let lastError = 'desktop unreachable';
    for (const base of this.candidates()) {
      try {
        const res = await fetchWithTimeout(`${base}/pair`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
        });
        const json = (await readJson(res)) as Record<string, unknown>;
        if (!res.ok) {
          const err = typeof json.error === 'string' ? json.error : 'pairing rejected';
          throw new Error(err.length > 80 ? `${err.slice(0, 80)}…` : err);
        }
        if (json.type !== 'kiwi-pairing-registered' || typeof json.device_id !== 'string') {
          throw new Error('desktop reply is not usable');
        }
        return {
          type: 'kiwi-pairing-registered',
          device_id: json.device_id,
          issued_unix: typeof json.issued_unix === 'number' ? json.issued_unix : Date.now() / 1000,
        };
      } catch (err) {
        lastError = bounded(err, 'desktop unreachable');
      }
    }
    throw new Error(`Pairing channel rejected the hello: ${lastError}`);
  }

  async pullChallenges(deviceId: string): Promise<ChallengeData[]> {
    assertDeviceId(deviceId);
    let lastError = 'desktop unreachable';
    for (const base of this.candidates()) {
      try {
        const res = await fetchWithTimeout(
          `${base}/challenges?device_id=${encodeURIComponent(deviceId)}`,
          { method: 'GET' },
        );
        const json = (await readJson(res)) as Record<string, unknown>;
        if (!res.ok) {
          throw new Error('desktop refused the pull');
        }
        const rows = Array.isArray(json.challenges) ? json.challenges : [];
        const out: ChallengeData[] = [];
        for (const row of rows) {
          try {
            out.push(parseChallengeData(row));
          } catch {
            // One malformed row never kills the list (rule 9).
          }
        }
        return out;
      } catch (err) {
        lastError = bounded(err, 'desktop unreachable');
      }
    }
    throw new Error(`Pull failed (fail closed): ${lastError}`);
  }

  async deviceStatus(deviceId: string): Promise<DeviceStatus> {
    assertDeviceId(deviceId);
    let lastError = 'desktop unreachable';
    for (const base of this.candidates()) {
      try {
        const res = await fetchWithTimeout(
          `${base}/device-status?device_id=${encodeURIComponent(deviceId)}`,
          { method: 'GET' },
        );
        const json = (await readJson(res)) as Record<string, unknown>;
        if (!res.ok) {
          throw new Error('desktop refused the status check');
        }
        const status = json.status;
        if (status === 'pending' || status === 'active' || status === 'revoked' || status === 'unknown') {
          return status;
        }
        return 'unknown';
      } catch (err) {
        lastError = bounded(err, 'desktop unreachable');
      }
    }
    throw new Error(`Status check failed (fail closed): ${lastError}`);
  }
}

export class HttpChallengeTransport implements ChallengeTransport {
  constructor(private readonly store: DesktopEndpointStore) {}

  async postResponse(resp: ChallengeResponseData): Promise<TransportResult> {
    const body = JSON.stringify({
      schema_version: resp.schema_version,
      challenge_id: resp.challenge_id,
      device_id: resp.device_id,
      session_id: resp.session_id,
      event: resp.event,
      decision: resp.decision,
      signature_b64: resp.signature_b64,
    });
    const bases = baseCandidates(this.store);
    if (bases.length === 0) {
      return { kind: 'offline', reason: 'no desktop endpoint — scan the QR first' };
    }
    for (const base of bases) {
      try {
        const res = await fetchWithTimeout(`${base}/response`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
        });
        if (!res.ok) {
          const json = (await readJson(res).catch(() => null)) as Record<string, unknown> | null;
          const err = json !== null && typeof json.error === 'string' ? json.error : `http ${res.status}`;
          // A reached desktop that refuses is NOT offline — surface it as
          // an offline-queue reason so the UI stays honest without throwing.
          return { kind: 'offline', reason: err.length > 120 ? `${err.slice(0, 120)}…` : err };
        }
        return { kind: 'delivered', requestId: `${resp.challenge_id}:http` };
      } catch (err) {
        // Try the next candidate (LAN → adb-reverse loopback) before
        // reporting offline.
        if (base === bases[bases.length - 1]) {
          return { kind: 'offline', reason: bounded(err, 'desktop unreachable') };
        }
      }
    }
    return { kind: 'offline', reason: 'desktop unreachable' };
  }
}
