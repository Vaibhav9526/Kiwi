import { describe, expect, it } from "vitest";
import { parseSecuritySession } from "./kiwi";

/**
 * T-260: the renderer must **safe-render** the security-session enum tokens.
 * An unknown token degrades to its honest unknown form — never echoed
 * verbatim, never a confident-looking substitute, never a thrown crash.
 */
describe("parseSecuritySession", () => {
  const valid = {
    schemaVersion: 1,
    sessionId: "app:imap:3",
    accountId: "a1",
    deviceId: null,
    protocol: "imap",
    serverHost: "imap.x.test",
    serverPort: 993,
    transport: "tls",
    tlsVersion: "tls1.3",
    keyExchangeGroup: "x25519",
    certChain: { presentedLen: 2, validation: "valid" },
    starttlsOffered: null,
    starttlsUsed: false,
    authMechanism: "xoauth2",
    authSucceeded: true,
    establishedUnix: 1_758_000_000,
    source: "live-client",
  };

  it("passes a well-formed §3 envelope through unchanged", () => {
    const parsed = parseSecuritySession(valid);
    expect(parsed).not.toBeNull();
    expect(parsed!.transport).toBe("tls");
    expect(parsed!.tlsVersion).toBe("tls1.3");
    expect(parsed!.source).toBe("live-client");
    expect(parsed!.authMechanism).toBe("xoauth2");
    expect(parsed!.certChain?.validation).toBe("valid");
  });

  it("returns null when the envelope is not a session at all", () => {
    expect(parseSecuritySession(null)).toBeNull();
    expect(parseSecuritySession("nope")).toBeNull();
    expect(parseSecuritySession({})).toBeNull();
    // Missing the identity fields — not renderable as a session.
    expect(parseSecuritySession({ ...valid, sessionId: undefined })).toBeNull();
    expect(parseSecuritySession({ ...valid, serverHost: "" })).toBeNull();
  });

  it("degrades an unknown enum token to its honest unknown form", () => {
    const parsed = parseSecuritySession({
      ...valid,
      transport: "quantum-tls",
      tlsVersion: "tls9.9",
      source: "some-future-probe",
      certChain: { presentedLen: 1, validation: "weird" },
    });
    expect(parsed).not.toBeNull();
    // Never the unrecognized value verbatim, never a confident-looking one.
    expect(parsed!.transport).not.toBe("quantum-tls");
    expect(parsed!.tlsVersion).toBe("unknown");
    expect(parsed!.source).toBe("unknown");
    expect(parsed!.certChain?.validation).toBe("unknown");
  });

  it("keeps optional facts absent rather than inventing them", () => {
    const parsed = parseSecuritySession({
      ...valid,
      tlsVersion: null,
      keyExchangeGroup: null,
      certChain: null,
      starttlsOffered: null,
      authSucceeded: null,
      accountId: null,
    });
    expect(parsed).not.toBeNull();
    expect(parsed!.tlsVersion).toBeNull();
    expect(parsed!.keyExchangeGroup).toBeNull();
    expect(parsed!.certChain).toBeNull();
    expect(parsed!.authSucceeded).toBeNull();
  });

  it("keeps the open `other:<name>` kex vocabulary renderable", () => {
    const parsed = parseSecuritySession({ ...valid, keyExchangeGroup: "other:psk" });
    expect(parsed!.keyExchangeGroup).toBe("other:psk");
  });
});
