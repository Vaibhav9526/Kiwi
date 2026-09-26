/**
 * Canonical challenge bytes (T-136 contract §4) — byte-for-byte parity with
 * `kiwi_core::challenge::Challenge::canonical_bytes()` (kiwi-core/src/challenge.rs):
 *
 *   u32be(len) "kiwi-challenge-v1"
 *   u32be(len) challenge_id        \  length-prefixed UTF-8 strings
 *   u32be(len) device_id            |
 *   u32be(len) session_id          /
 *   u8         event tag (0x01..0x04)
 *   32 bytes   nonce (raw)
 *   i64be      issued_unix
 *   i64be      expires_unix
 *
 * Every bound element is covered — tampering with any of them invalidates
 * the Ed25519 signature. Pure functions only (SECURITY.md rule 1).
 */
import { eventFromTag, eventTag, CHALLENGE_EVENTS } from './event';
import { isRecord, assertBoundedString, assertIntInRange, assertBase64 } from './validate';
import { utf8Encode, base64DecodeStrict, u32be, i64be } from './bytes';
import { SCHEMA_VERSION } from './types';
import type { ChallengeData, ChallengeResponseData, Decision } from './types';

const DOMAIN = 'kiwi-challenge-v1';
const NONCE_BYTES = 32;
const ED25519_SIG_BYTES = 64;
const MAX_FIELD_BYTES = 4096;

/**
 * Total raw-size cap before JSON.parse (AUTH-14 / T270-04): every field is
 * already individually bounded, but the container itself must be too —
 * a multi-megabyte "challenge" is rejected before parsing, and parse errors
 * are fixed strings that never echo untrusted text (SECURITY.md rule 9).
 */
export const MAX_CHALLENGE_JSON_CHARS = 4096;

function pushField(bytes: number[], field: string): void {
  const encoded = utf8Encode(field);
  if (encoded.length > MAX_FIELD_BYTES) {throw new Error(`field exceeds ${MAX_FIELD_BYTES} bytes`);}
  bytes.push(...u32be(encoded.length), ...encoded);
}

export interface CanonicalChallengeFields {
  challengeId: string;
  deviceId: string;
  sessionId: string;
  event: Parameters<typeof eventTag>[0];
  nonce: Uint8Array;
  issuedUnix: number;
  expiresUnix: number;
}

/** Encode the canonical byte string the device signs. */
export function canonicalChallengeBytes(fields: CanonicalChallengeFields): Uint8Array {
  if (fields.nonce.length !== NONCE_BYTES) {
    throw new Error(`nonce must be exactly ${NONCE_BYTES} bytes`);
  }
  const bytes: number[] = [];
  pushField(bytes, DOMAIN);
  pushField(bytes, fields.challengeId);
  pushField(bytes, fields.deviceId);
  pushField(bytes, fields.sessionId);
  bytes.push(eventTag(fields.event));
  bytes.push(...fields.nonce);
  bytes.push(...i64be(fields.issuedUnix), ...i64be(fields.expiresUnix));
  return new Uint8Array(bytes);
}

/**
 * Parse an untrusted Challenge JSON object into validated ChallengeData
 * (unknown fields ignored). Throws on any defect; the caller treats
 * malformed challenges as display-not-signable.
 */
export function parseChallengeData(raw: unknown): ChallengeData {
  if (!isRecord(raw)) {throw new Error('challenge must be a JSON object');}
  const v = raw.schema_version;
  if (v !== SCHEMA_VERSION) {
    // AUTH-14: never interpolate untrusted text — only a safe integer can be
    // echoed (its rendering is bounded by construction); anything else gets
    // a fixed message.
    throw new Error(
      typeof v === 'number' && Number.isSafeInteger(v)
        ? `unsupported schema_version ${v}`
        : 'unsupported schema_version',
    );
  }
  const challengeId = assertBoundedString(raw.challenge_id, 'challenge_id', 1, 128);
  const deviceId = assertBoundedString(raw.device_id, 'device_id', 1, 128);
  const sessionId = assertBoundedString(raw.session_id, 'session_id', 1, 128);
  const eventRaw = raw.event;
  if (typeof eventRaw !== 'string') {throw new Error('unknown challenge event');}
  // Typed lookup keeps the union type without a cast; anything outside
  // CHALLENGE_EVENTS is rejected here (unknown-field rule still holds).
  const event = CHALLENGE_EVENTS.find((e) => e === eventRaw);
  if (event === undefined) {throw new Error('unknown challenge event');}
  // AUTH-16 / contract §4.2: the session id form is bound to the event.
  // unlock / device-pairing authorize a session (boot-<...>); recovery /
  // elevated-action authorize a narrower transaction (x-tx:<txn>). A
  // mismatch is fail-closed — the signed bytes would otherwise bless an id
  // shape the desktop never issues for that event.
  const wantsSession = event === 'unlock' || event === 'device-pairing';
  const hasSessionForm = sessionId.startsWith('boot-');
  const hasTransactionForm = sessionId.startsWith('x-tx:');
  if (wantsSession ? !hasSessionForm : !hasTransactionForm) {
    throw new Error('session_id does not match the challenge event');
  }
  const nonceB64 = assertBase64(raw.nonce_b64, 'nonce_b64', NONCE_BYTES);
  // Exact-length check: base64 validation alone allows padded shorter
  // payloads — the nonce MUST decode to exactly 32 bytes (§4.2).
  decodeB64(nonceB64, NONCE_BYTES, 'nonce_b64');
  const issuedUnix = assertIntInRange(raw.issued_unix, 'issued_unix', 0, Number.MAX_SAFE_INTEGER);
  const expiresUnix = assertIntInRange(raw.expires_unix, 'expires_unix', 0, Number.MAX_SAFE_INTEGER);
  if (expiresUnix <= issuedUnix) {throw new Error('expiry must be after issue time');}
  return {
    schema_version: SCHEMA_VERSION,
    challenge_id: challengeId,
    device_id: deviceId,
    session_id: sessionId,
    event,
    nonce_b64: nonceB64,
    issued_unix: issuedUnix,
    expires_unix: expiresUnix,
  };
}

/**
 * Bounded string entry point: caps the raw container (AUTH-14) before the
 * first parse, then runs the strict {@link parseChallengeData} path. Fixed
 * error messages only — the raw text is never echoed (rule 6).
 */
export function parseChallengeJson(raw: string): ChallengeData {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_CHALLENGE_JSON_CHARS) {
    throw new Error(`challenge must be 1..${MAX_CHALLENGE_JSON_CHARS} chars`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('challenge is not valid JSON');
  }
  return parseChallengeData(parsed);
}

/** Decode base64 (already validated) into exact bytes. */
export function decodeB64(b64: string, expectedBytes: number, field: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base64DecodeStrict(b64);
  } catch {
    throw new Error(`${field} is not canonical base64`);
  }
  if (bytes.length !== expectedBytes) {
    throw new Error(`${field} must decode to exactly ${expectedBytes} bytes`);
  }
  return bytes;
}

/** Build the typed fields for {@link canonicalChallengeBytes} from parsed data. */
export function challengeFields(c: ChallengeData, nonceBytes: Uint8Array): CanonicalChallengeFields {
  return {
    challengeId: c.challenge_id,
    deviceId: c.device_id,
    sessionId: c.session_id,
    event: c.event,
    nonce: nonceBytes,
    issuedUnix: c.issued_unix,
    expiresUnix: c.expires_unix,
  };
}

/**
 * Build the signed approve/deny response (contract §6). `sigB64` is the
 * Ed25519 signature (64 bytes decoded) over canonical bytes — approve;
 * deny requires no signature (advisory only).
 */
export function buildChallengeResponseData(
  c: ChallengeData,
  decision: Decision,
  sigB64: string | null,
): ChallengeResponseData {
  const base = {
    schema_version: SCHEMA_VERSION,
    challenge_id: c.challenge_id,
    device_id: c.device_id,
    session_id: c.session_id,
    event: c.event,
  };
  if (decision === 'approve') {
    const sig = sigB64 ?? '';
    decodeB64(sig, ED25519_SIG_BYTES, 'signature_b64');
    return { ...base, signature_b64: sig, decision: 'approve' };
  }
  // Deny: explicit marker, no signature field at all (§6.3).
  return { ...base, signature_b64: '', decision: 'deny' };
}

export { eventFromTag };
