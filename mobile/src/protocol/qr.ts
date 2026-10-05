/**
 * QR payload parsing (T-136 contract §3). The QR string is the only input;
 * treat it as attacker-controlled (SECURITY.md rule 9): validate + bound
 * everything, ignore unknown fields, fail closed on any security-relevant
 * defect. Pure functions — deterministic, no I/O, no AI (rule 1).
 */
import { isRecord, assertIntInRange, assertBoundedString } from './validate';
import { base64DecodeStrict, base64Encode } from './bytes';
import type { QrPayload } from './types';

const MAX_QR_CHARS = 1024;

/** Non-secret public-key prefix kept in the QR for endpoint verification. */
const DESKTOP_KEY_ED25519_PREFIX = 'ed25519:';

/** Contract §3.1: QR validity is at most five minutes (recommended = 300 s). */
const MAX_QR_VALIDITY_SECS = 300;

/** Ed25519 public keys are exactly 32 bytes (contract §1 invariant). */
const DESKTOP_KEY_BYTES = 32;

function isFiniteInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v);
}

/**
 * Parse a raw QR string into a validated QrPayload.
 * Throws on malformed payloads; callers should surface a bounded error and
 * never echo the raw payload into logs (it can contain attacker text).
 */
export function parseQrPayload(raw: string, nowUnix: number): QrPayload {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_QR_CHARS) {
    throw new Error(`qr payload must be 1..${MAX_QR_CHARS} chars`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('qr payload is not valid JSON');
  }
  if (!isRecord(parsed)) {throw new Error('qr payload must be a JSON object');}

  const v = parsed.v;
  if (!isFiniteInt(v)) {throw new Error('missing integer field v');}
  if (v !== 1) {throw new Error(`unsupported schema_version ${v} — update the app`);}
  if (parsed.type !== 'kiwi-pairing') {throw new Error('unknown QR payload type');}

  const pairingTicket = assertBoundedString(parsed.pairing_ticket, 'pairing_ticket', 8, 128);
  const endpoint = assertBoundedString(parsed.desktop_endpoint, 'desktop_endpoint', 1, 256);
  const label = assertBoundedString(parsed.device_label, 'device_label', 1, 128);
  const keyB64 = assertBoundedString(parsed.desktop_public_key_b64, 'desktop_public_key_b64', 1, 512);

  if (!keyB64.startsWith(DESKTOP_KEY_ED25519_PREFIX)) {
    throw new Error('unsupported desktop key algorithm');
  }
  // AUTH-4: the pin must be THE key — `ed25519:` + RFC 4648 standard
  // Base64, padded, decoding to exactly 32 bytes, re-encoded byte-for-byte.
  // Prefix+length alone accepts URL-safe/unpadded spellings of the same key,
  // which breaks the QR-swap equality pin. Same rule as the desktop's
  // `check_desktop_key` (kiwi-app pair.rs, ipc.md §9d.8).
  const keyBody = keyB64.slice(DESKTOP_KEY_ED25519_PREFIX.length);
  let keyBytes: Uint8Array;
  try {
    keyBytes = base64DecodeStrict(keyBody);
  } catch {
    throw new Error('desktop key is not canonical base64');
  }
  if (keyBytes.length !== DESKTOP_KEY_BYTES) {
    throw new Error(`desktop key must decode to exactly ${DESKTOP_KEY_BYTES} bytes`);
  }
  if (base64Encode(keyBytes) !== keyBody) {
    throw new Error('desktop key is not canonical base64');
  }

  const issued = parsed.issued_unix;
  const expires = parsed.expires_unix;
  if (!isFiniteInt(issued) || !isFiniteInt(expires)) {
    throw new Error('issued_unix/expires_unix must be integers');
  }
  assertIntInRange(issued, 'issued_unix', 0, Number.MAX_SAFE_INTEGER);
  assertIntInRange(expires, 'expires_unix', 0, Number.MAX_SAFE_INTEGER);
  if (expires < issued) {throw new Error('expires_unix precedes issued_unix');}
  if (expires === issued) {throw new Error('expires_unix must strictly follow issued_unix');}
  // AUTH-10 / contract §3.1: a QR may never be valid for more than 5 minutes,
  // whatever the producer claims — a long-lived ticket widens the
  // interception window on a hostile LAN.
  if (expires - issued > MAX_QR_VALIDITY_SECS) {
    throw new Error(`QR validity exceeds the ${MAX_QR_VALIDITY_SECS}-second maximum`);
  }
  if (nowUnix >= expires) {throw new Error('pairing ticket expired — regenerate the QR');}

  // Bounded, opaque ticket charset (base64url-ish + dashes).
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(pairingTicket)) {
    throw new Error('pairing_ticket has unexpected charset');
  }

  // Unknown fields are ignored (contract invariant) — never copied.
  return {
    schema_version: v,
    pairing_ticket: pairingTicket,
    desktop_endpoint: endpoint,
    device_label: label,
    desktop_public_key_b64: keyB64,
    issued_unix: issued,
    expires_unix: expires,
    raw,
  };
}

/** True when the payload is within its validity window at `nowUnix`. */
export function isQrPayloadCurrent(payload: QrPayload, nowUnix: number): boolean {
  return nowUnix >= payload.issued_unix && nowUnix < payload.expires_unix;
}

/** Bounded human label for UI display — never trust the raw string. */
export function safeDeviceLabel(label: string): string {
  const cleaned = label.replace(/[\r\n\t]+/g, ' ').trim();
  return cleaned.length === 0 ? 'Unnamed device' : cleaned.slice(0, 128);
}
