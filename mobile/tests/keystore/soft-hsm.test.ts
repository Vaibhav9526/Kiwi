/**
 * Fail-closed keystore posture (T-136 contract §5, SECURITY.md rules 7, 8).
 */
import { describe, it, expect } from "vitest";

import { UnavailableKeystore, KeystoreError } from "../../src/keystore/keystore";
import { SoftHsmKeystore } from "../../src/keystore/soft-hsm";

describe("UnavailableKeystore (scaffold default)", () => {
  it("fails closed on every operation", async () => {
    const ks = new UnavailableKeystore();
    await expect(ks.generateKey("alias")).rejects.toMatchObject({ code: "not-implemented" });
    await expect(ks.sign("ref", new Uint8Array(4))).rejects.toMatchObject({ code: "not-implemented" });
    await expect(ks.deleteKey("ref")).rejects.toMatchObject({ code: "not-implemented" });
    await expect(ks.hasKey("ref")).resolves.toBe(false);
  });
});

describe("SoftHsmKeystore (test-only)", () => {
  it("yields deterministic fixtures and rejects duplicate aliases", async () => {
    const ks = SoftHsmKeystore.createTestOnly();
    const h1 = await ks.generateKey("fixture-a");
    // Duplicate alias is refused (fail closed, no silent overwrite).
    await expect(ks.generateKey("fixture-a")).rejects.toMatchObject({ code: "fail-closed" });
    // Same alias regenerates the same synthetic bytes (deterministic fixture).
    await ks.deleteKey("soft-hsm:fixture-a");
    const h2 = await ks.generateKey("fixture-a");
    expect(h2.publicKeyB64).toBe(h1.publicKeyB64);
    expect(h2.keystoreRef).toBe(h1.keystoreRef);
  });

  it("generates a 32-byte public key handle and signs 64 bytes", async () => {
    const ks = SoftHsmKeystore.createTestOnly();
    const handle = await ks.generateKey("fixture-b");
    expect(handle.algorithm).toBe("ed25519");
    expect(Buffer.from(handle.publicKeyB64, "base64").length).toBe(32);
    const sig = await ks.sign(handle.keystoreRef, new Uint8Array(10));
    expect(sig.length).toBe(64);
    await expect(ks.sign("soft-hsm:unknown", new Uint8Array(10))).rejects.toMatchObject({ code: "key-not-found" });
  });

  it("deleteKey destroys the alias", async () => {
    const ks = SoftHsmKeystore.createTestOnly();
    const handle = await ks.generateKey("fixture-c");
    expect(await ks.hasKey(handle.keystoreRef)).toBe(true);
    await ks.deleteKey(handle.keystoreRef);
    expect(await ks.hasKey(handle.keystoreRef)).toBe(false);
    await expect(ks.sign(handle.keystoreRef, new Uint8Array(4))).rejects.toBeInstanceOf(KeystoreError);
  });
});
