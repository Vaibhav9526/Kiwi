/**
 * Platform keystore interface (T-136 contract §5).
 *
 * SECURITY.md rule 8: private keys live only in the platform keystore
 * (Android Keystore / iOS Secure Enclave / Keychain). No implementation in
 * this scaffold performs real key generation or signing — the app wires a
 * fail-closed `UnavailableKeystore` until Phase 4 lands the native module.
 * Any production key handling re-triggers the SECURITY.md §6 review gate.
 */
export type KeyAlgorithmName = "ed25519";

export type KeystoreErrorCode =
  | "not-implemented"
  | "keystore-unavailable"
  | "key-not-found"
  | "fail-closed";

export class KeystoreError extends Error {
  constructor(
    public readonly code: KeystoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "KeystoreError";
  }
}

/** Public facts of a generated keypair — never private material. */
export interface KeystoreKeyHandle {
  /** Opaque alias in the platform keystore (non-secret, ≤256 chars). */
  keystoreRef: string;
  /** Raw Ed25519 public key, base64 (decodes to exactly 32 bytes). */
  publicKeyB64: string;
  algorithm: KeyAlgorithmName;
}

export interface DeviceKeystore {
  /** Generate an Ed25519 keypair inside the platform keystore. */
  generateKey(alias: string): Promise<KeystoreKeyHandle>;
  /** Sign `message` with the key at `keystoreRef` — inside the keystore. */
  sign(keystoreRef: string, message: Uint8Array): Promise<Uint8Array>;
  /** Destroy the key (revocation / user request — contract §5). */
  deleteKey(keystoreRef: string): Promise<void>;
  hasKey(keystoreRef: string): Promise<boolean>;
}

/** Scaffold default: every operation fails closed (SECURITY.md rule 7). */
export class UnavailableKeystore implements DeviceKeystore {
  async generateKey(_alias: string): Promise<KeystoreKeyHandle> {
    throw new KeystoreError(
      "not-implemented",
      "platform keystore module lands in Phase 4 (contract §5)",
    );
  }
  async sign(_keystoreRef: string, _message: Uint8Array): Promise<Uint8Array> {
    throw new KeystoreError("not-implemented", "platform keystore module lands in Phase 4");
  }
  async deleteKey(_keystoreRef: string): Promise<void> {
    throw new KeystoreError("not-implemented", "platform keystore module lands in Phase 4");
  }
  async hasKey(_keystoreRef: string): Promise<boolean> {
    return false;
  }
}
