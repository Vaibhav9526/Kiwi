/**
 * Pairing-channel link interface (T-194) — shapes from contract §3.2 and
 * §4.2, transport-agnostic so the screens never import a concrete wire.
 *
 * The shipping transport (wss/TLS, T-184) is a Phase-4 concern behind this
 * interface; the T-194 screens drive it through the mock desktop, and the
 * fail-closed environment substitutes an always-unavailable link. All input
 * crossing this boundary is validated by the caller's normal protocol
 * parsers (SECURITY.md rule 9).
 */
import type { ChallengeData } from '../protocol/types';

/** Phone -> desktop pairing hello (contract §3.2 step 1). */
export interface PairingHello {
  type: 'kiwi-pairing-hello';
  pairing_ticket: string;
  device_label: string;
  /** Std Base64 of this phone's 32-byte Ed25519 public key (ipc.md §9d pair-hello wire: no prefix). */
  device_public_key_b64: string;
  keystore_ref: string;
}

/** Desktop -> phone registration reply (contract §3.2 step 2). */
export interface PairingRegistered {
  type: 'kiwi-pairing-registered';
  device_id: string;
  issued_unix: number;
}

export type DeviceStatus = 'pending' | 'active' | 'revoked' | 'unknown';

export interface AuthenticatorLink {
  /**
   * Send the pairing hello and receive the desktop-assigned device id.
   * Rejects (never resolves) on ticket/shape failure — fail closed.
   */
  hello(msg: PairingHello): Promise<PairingRegistered>;

  /** Challenges the desktop has pushed for `deviceId` and not yet answered. */
  pullChallenges(deviceId: string): Promise<ChallengeData[]>;

  /** Desktop-side device status (contract security-session.md §7). */
  deviceStatus(deviceId: string): Promise<DeviceStatus>;
}
