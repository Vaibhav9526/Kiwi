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
  /** Optional explicit denial marker; absent = approve (see contract §6.3). */
  decision?: 'approve' | 'deny';
}

export type Decision = 'approve' | 'deny';

export type DeliveryResult =
  | { kind: 'delivered'; requestId: string }
  | { kind: 'offline'; reason: string };

export type DeliveryOutcome = DeliveryResult | { kind: 'skipped'; reason: string };
