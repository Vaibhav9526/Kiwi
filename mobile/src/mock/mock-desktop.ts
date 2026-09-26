/**
 * Mock desktop backend (T-194) — pairing + challenge/response plumbing over
 * an in-process transport, so the four screens can be exercised end to end
 * WITHOUT a wire, a native keystore, or any trust claim.
 *
 * HONESTY RULES (SECURITY.md rules 4, 7, 10):
 * - `postResponse` validates SHAPE only. It never verifies signatures —
 *   the desktop `ChallengeBook` + `Ed25519Verifier` remain the sole
 *   verification authority (contract §6.2). "delivered" here means the mock
 *   accepted the response, nothing more.
 * - Nonces/tickets/keys are deterministic fixtures, NOT secrets and NOT
 *   CSPRNG output. The production desktop uses `getrandom` (§4.3).
 * - This class is reachable only from `src/mock/` and tests; the shipping
 *   transport (wss/TLS) lands in Phase 4 behind the same interfaces.
 *
 * Implements the phone-facing halves of contract §3.2 (hello / registered /
 * device-pairing activation) and §4.2 (challenge delivery), plus
 * `ChallengeTransport.postResponse` (§6.2/§7).
 */
/* eslint-disable no-bitwise -- deterministic mock fixture bytes are bitwise by construction. */
import type { AuthenticatorLink, DeviceStatus, PairingHello, PairingRegistered } from '../transport/link';
import type { ChallengeTransport, TransportResult } from '../transport/transport';
import type { ChallengeData, ChallengeResponseData } from '../protocol/types';
import { safeDeviceLabel } from '../protocol/qr';
import { base64Encode, base64DecodeStrict } from '../protocol/bytes';
import { decodeB64 } from '../protocol/canonical';
import type { ChallengeEvent } from '../protocol/event';
import type { LedgerClock } from '../protocol/replay';

const QR_VALIDITY_SECS = 300; // contract §3.1 maximum
const CHALLENGE_TTL_SECS = 120; // contract §4.2 default
const NONCE_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** Deterministic synthetic desktop key — public by construction, not a secret. */
const MOCK_DESKTOP_KEY_BODY = base64Encode(
  Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 7) & 0xff),
);
const MOCK_DESKTOP_KEY = `ed25519:${MOCK_DESKTOP_KEY_BODY}`;
const MOCK_ENDPOINT = 'wss://127.0.0.1:49310/pair';

interface MockDevice {
  deviceId: string;
  deviceLabel: string;
  publicKeyB64: string;
  keystoreRef: string;
  status: DeviceStatus;
  registeredUnix: number;
}

export class MockDesktop implements AuthenticatorLink, ChallengeTransport {
  /** Scriptable link state for offline-queue demos and tests. */
  online = true;

  private readonly clock: LedgerClock;
  private readonly tickets = new Map<string, { label: string; expiresUnix: number; consumed: boolean }>();
  private readonly devices = new Map<string, MockDevice>();
  private readonly challenges: ChallengeData[] = [];
  private readonly answered = new Set<string>();
  private readonly responses: ChallengeResponseData[] = [];
  private counter = 0;

  constructor(clock: LedgerClock) {
    this.clock = clock;
  }

  // ── Pairing (contract §3.1 / §3.2) ────────────────────────────────────

  /**
   * Fabricate a pairing QR payload (compact JSON) — the demo stand-in for
   * the desktop's rendered QR. Validity is the §3.1 five-minute maximum.
   */
  beginPairing(deviceLabel = 'Mock phone'): string {
    this.counter += 1;
    const ticket = `mockticket${String(this.counter).padStart(6, '0')}`;
    const issued = this.clock.nowUnix();
    const expires = issued + QR_VALIDITY_SECS;
    this.tickets.set(ticket, { label: safeDeviceLabel(deviceLabel), expiresUnix: expires, consumed: false });
    return JSON.stringify({
      v: 1,
      type: 'kiwi-pairing',
      pairing_ticket: ticket,
      desktop_endpoint: MOCK_ENDPOINT,
      device_label: safeDeviceLabel(deviceLabel),
      desktop_public_key_b64: MOCK_DESKTOP_KEY,
      issued_unix: issued,
      expires_unix: expires,
    });
  }

  /** Ticket validation + Pending registration, then the §3.2 step-3 challenge. */
  async hello(msg: PairingHello): Promise<PairingRegistered> {
    if (msg.type !== 'kiwi-pairing-hello') {
      throw new Error('unexpected pairing message type');
    }
    const ticket = this.tickets.get(msg.pairing_ticket);
    if (ticket === undefined || ticket.consumed) {
      throw new Error('pairing ticket is unknown or already used');
    }
    if (this.clock.nowUnix() >= ticket.expiresUnix) {
      throw new Error('pairing ticket expired');
    }
    // ipc.md §9d register-device wire: plain std Base64, exactly 32 bytes —
    // no `ed25519:` prefix (that prefix belongs to the QR's desktop key).
    let keyBytes: Uint8Array;
    try {
      keyBytes = base64DecodeStrict(msg.device_public_key_b64);
    } catch {
      throw new Error('device key is not canonical base64');
    }
    if (keyBytes.length !== 32) {
      throw new Error('device key must decode to 32 bytes');
    }
    ticket.consumed = true;
    this.counter += 1;
    const deviceId = `dev-mock-${String(this.counter).padStart(4, '0')}`;
    this.devices.set(deviceId, {
      deviceId,
      // ipc.md §9d: the claimant-supplied label is ignored — the ticket's
      // bound label (from the QR the desktop rendered) is authoritative.
      deviceLabel: ticket.label,
      publicKeyB64: msg.device_public_key_b64,
      keystoreRef: msg.keystore_ref,
      status: 'pending',
      registeredUnix: this.clock.nowUnix(),
    });
    // Contract §3.2 step 3: the desktop immediately issues the
    // device-pairing challenge the phone must sign to activate.
    this.issueChallenge(deviceId, 'device-pairing');
    return { type: 'kiwi-pairing-registered', device_id: deviceId, issued_unix: this.clock.nowUnix() };
  }

  async deviceStatus(deviceId: string): Promise<DeviceStatus> {
    return this.devices.get(deviceId)?.status ?? 'unknown';
  }

  // ── Challenge delivery (contract §4.2) ─────────────────────────────────

  /**
   * Issue a challenge for `deviceId`. The nonce is a deterministic fixture
   * (mock-only — production desktops use the OS CSPRNG, §4.3) and the
   * session id follows the §4.2 event grammar (boot- for session-scoped
   * events, x-tx: for transaction-scoped ones).
   */
  issueChallenge(deviceId: string, event: ChallengeEvent): ChallengeData {
    if (typeof deviceId !== 'string' || deviceId.length < 1 || deviceId.length > 128) {
      throw new Error('deviceId must be 1..128 chars');
    }
    this.counter += 1;
    const n = this.counter;
    const issued = this.clock.nowUnix();
    const sessionScoped = event === 'unlock' || event === 'device-pairing';
    const nonce = Uint8Array.from({ length: NONCE_BYTES }, (_, i) => (i * 31 + n * 7 + 5) & 0xff);
    const challenge: ChallengeData = {
      schema_version: 1,
      challenge_id: `chg-mock-${String(n).padStart(4, '0')}`,
      device_id: deviceId,
      session_id: sessionScoped ? `boot-mock-${String(n).padStart(4, '0')}` : `x-tx:mock-${String(n).padStart(4, '0')}`,
      event,
      nonce_b64: base64Encode(nonce),
      issued_unix: issued,
      expires_unix: issued + CHALLENGE_TTL_SECS,
    };
    this.challenges.push(challenge);
    return challenge;
  }

  /** Unanswered, unexpired challenges for this device (copies, never aliased). */
  async pullChallenges(deviceId: string): Promise<ChallengeData[]> {
    const now = this.clock.nowUnix();
    return this.challenges
      .filter((c) => c.device_id === deviceId && !this.answered.has(c.challenge_id) && now < c.expires_unix)
      .map((c) => ({ ...c }));
  }

  // ── Response intake (contract §6.2 / §7) ───────────────────────────────

  async postResponse(resp: ChallengeResponseData): Promise<TransportResult> {
    if (!this.online) {
      return { kind: 'offline', reason: 'mock desktop is offline' };
    }
    const challenge = this.challenges.find((c) => c.challenge_id === resp.challenge_id);
    if (challenge === undefined) {
      return { kind: 'offline', reason: 'mock desktop does not know this challenge' };
    }
    if (resp.decision === 'approve') {
      // Shape check only — the mock does NOT verify (see header).
      try {
        decodeB64(resp.signature_b64, SIGNATURE_BYTES, 'signature_b64');
      } catch {
        return { kind: 'offline', reason: 'approve response must carry a 64-byte signature' };
      }
    } else if (resp.decision !== 'deny') {
      return { kind: 'offline', reason: 'response must carry an explicit decision' };
    }
    this.responses.push(resp);
    // Phone-side suppression model (§6.4): once an outcome exists the mock
    // stops re-delivering that id. Desktop-side challenge consumption on
    // deny remains the real ChallengeBook's rule (deny does NOT consume).
    this.answered.add(resp.challenge_id);
    if (resp.decision === 'approve' && challenge.event === 'device-pairing') {
      const device = this.devices.get(resp.device_id);
      if (device !== undefined && device.status === 'pending') {
        device.status = 'active';
      }
    }
    this.counter += 1;
    return { kind: 'delivered', requestId: `mock-resp-${String(this.counter).padStart(4, '0')}` };
  }

  // ── Test/demo introspection (not part of any wire) ─────────────────────

  recordedResponses(): readonly ChallengeResponseData[] {
    return [...this.responses];
  }

  deviceOf(deviceId: string): MockDevice | undefined {
    const device = this.devices.get(deviceId);
    return device === undefined ? undefined : { ...device };
  }
}
