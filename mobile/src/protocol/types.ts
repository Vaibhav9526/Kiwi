/**
 * Wire shapes (T-136) — authoritative field semantics: T-136 contract.
 * Rust-side shapes live in kiwi-core (`Challenge`, `ChallengeResponse`);
 * the desktop IPC layer (`kiwi-app/src-tauri`, T-120) encodes between.
 */
import type { ChallengeEvent } from './event';

/** Wire tag carried in every payload (JSON) — integer. */
export const SCHEMA_VERSION = 1;

/** Canonical QR payload (contract §3) — `raw` retains the unparsed QR string. */
export interface QrPayload {
  schema_version: number;
  pairing_ticket: string;
  desktop_endpoint: string;
  device_label: string;
  desktop_public_key_b64: string;
  issued_unix: number;
  expires_unix: number;
  /** Not part of the QR string; provided by the scanner context. */
  readonly raw?: string;
}

/** Challenge as delivered to the authenticator (contract §4, JSON encode). */
export interface ChallengeData {
  schema_version: number;
  challenge_id: string;
  device_id: string;
  session_id: string;
  event: ChallengeEvent;
  nonce_b64: string;
  issued_unix: number;
  expires_unix: number;
}

/** Response payload the authenticator returns (contract §4). */
export interface ChallengeResponseData {
  schema_version: number;
  challenge_id: string;
  device_id: string;
  session_id: string;
  event: ChallengeEvent;
  /** Ed25519 signature over canonicalChallengeBytes(challenge). */
  signature_b64: string;
  /**
   * Explicit decision, always present (contract §6.2/§6.3): `approve`
   * carries a real 64-byte signature, `deny` carries the empty string and
   * confers no authorization. Absence is never read as approval.
   */
  decision: 'approve' | 'deny';
}

export type Decision = 'approve' | 'deny';

export type DeliveryResult =
  | { kind: 'delivered'; requestId: string }
  | { kind: 'offline'; reason: string };

export type DeliveryOutcome = DeliveryResult | { kind: 'skipped'; reason: string };

/**
 * Locally held paired-device identity (app state, not a wire shape — T-194).
 * `deviceId` is desktop-assigned during pairing; `keystoreRef` points at the
 * private key that never leaves the platform keystore (contract §5);
 * `desktopKeyB64` is the QR-carried pin the channel must match (§3.1).
 */
export interface PairedIdentity {
  deviceId: string;
  deviceLabel: string;
  desktopEndpoint: string;
  desktopKeyB64: string;
  keystoreRef: string;
  publicKeyB64: string;
  pairedUnix: number;
}
