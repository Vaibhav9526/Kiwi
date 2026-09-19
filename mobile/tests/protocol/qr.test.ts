/**
 * QR payload parsing evidence (T-136 contract §3.1).
 */
import { describe, it, expect } from "vitest";

import { parseQrPayload, isQrPayloadCurrent, safeDeviceLabel } from "../../src/protocol/qr";

const NOW = 1_729_000_000;

/** Valid base64 of 32 bytes, for the desktop key field. */
const DESKTOP_KEY = Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => i)).toString("base64");

function qrJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    type: "kiwi-pairing",
    pairing_ticket: "Ab12Cd34Ef56",
    desktop_endpoint: "ws://192.168.1.20:49310/pair",
    device_label: "Vaibhav's Pixel",
    desktop_public_key_b64: `ed25519:${DESKTOP_KEY}`,
    issued_unix: NOW,
    expires_unix: NOW + 300,
    ...overrides,
  });
}

function validQr(): string {
  return qrJson();
}

describe("parseQrPayload", () => {
  it("parses a valid payload", () => {
    const p = parseQrPayload(validQr(), NOW + 1);
    expect(p.schema_version).toBe(1);
    expect(p.pairing_ticket).toBe("Ab12Cd34Ef56");
    expect(p.device_label).toBe("Vaibhav's Pixel");
    expect(p.desktop_public_key_b64).toBe(`ed25519:${DESKTOP_KEY}`);
    expect(isQrPayloadCurrent(p, NOW + 1)).toBe(true);
    expect(isQrPayloadCurrent(p, NOW + 299)).toBe(true);
    expect(isQrPayloadCurrent(p, NOW + 300)).toBe(false); // expires is exclusive
    expect(isQrPayloadCurrent(p, NOW)).toBe(true);
  });

  it("ignores unknown fields", () => {
    const withExtra = JSON.stringify({ ...JSON.parse(validQr()), hint: "extra" });
    expect(parseQrPayload(withExtra, NOW + 1).pairing_ticket).toBe("Ab12Cd34Ef56");
  });

  it("rejects: not JSON, wrong type, wrong version, oversize, empty", () => {
    expect(() => parseQrPayload("not json", NOW + 1)).toThrow(/JSON/);
    expect(() => parseQrPayload(qrJson({ type: "other-app" }), NOW + 1)).toThrow(/type/);
    expect(() => parseQrPayload(qrJson({ v: 2 }), NOW + 1)).toThrow(/schema_version/);
    expect(() => parseQrPayload("x".repeat(1025), NOW + 1)).toThrow(/1024/);
    expect(() => parseQrPayload("", NOW + 1)).toThrow(/1024/);
    expect(() => parseQrPayload("[]", NOW + 1)).toThrow(/object/);
  });

  it("rejects expired and time-inverted payloads", () => {
    expect(() => parseQrPayload(validQr(), NOW + 300)).toThrow(/expired/);
    expect(() => parseQrPayload(qrJson({ expires_unix: NOW - 1 }), NOW)).toThrow(/precedes/);
  });

  it("rejects bad tickets and non-ed25519 keys", () => {
    expect(() => parseQrPayload(qrJson({ pairing_ticket: "short" }), NOW + 1)).toThrow(/8\.\.128/);
    expect(() => parseQrPayload(qrJson({ pairing_ticket: "has space" }), NOW + 1)).toThrow(/charset/);
    expect(() =>
      parseQrPayload(qrJson({ desktop_public_key_b64: `p256:${DESKTOP_KEY}` }), NOW + 1),
    ).toThrow(/algorithm/);
  });

  it("rejects untrusted field types (rule 9)", () => {
    expect(() => parseQrPayload(qrJson({ device_label: 42 }), NOW + 1)).toThrow(/device_label/);
    expect(() => parseQrPayload(qrJson({ issued_unix: "now" }), NOW + 1)).toThrow(/integer/);
  });
});

describe("safeDeviceLabel", () => {
  it("strips control characters and truncates", () => {
    expect(safeDeviceLabel("bad\nlabel\twith CR\r")).toBe("bad label with CR");
    expect(safeDeviceLabel("a".repeat(200)).length).toBe(128);
  });

  it("falls back for empty labels", () => {
    expect(safeDeviceLabel("   ")).toBe("Unnamed device");
  });
});
