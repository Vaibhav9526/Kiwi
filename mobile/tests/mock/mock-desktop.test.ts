/**
 * Mock desktop + environment evidence (T-194).
 *
 * End-to-end: pairing QR -> hello -> Pending -> device-pairing activation
 * challenge -> ordered gates -> signed approve -> delivered -> active.
 * Also proves the fail-closed environment refuses everything and the mock's
 * honesty rules (shape-only intake, single-use tickets, §4.2 grammar).
 */
import { describe, it, expect } from 'vitest';

import { MockDesktop } from '../../src/mock/mock-desktop';
import { createMockEnvironment } from '../../src/mock';
import {
  createApprovalBundle,
  createFailClosedEnvironment,
} from '../../src/environment';
import { parseQrPayload } from '../../src/protocol/qr';
import { buildChallengeResponseData } from '../../src/protocol/canonical';
import { FixedClock } from '../../src/protocol/replay';
import { KeystoreError } from '../../src/keystore/keystore';
import type { PairedIdentity } from '../../src/protocol/types';

const T0 = 1_729_000_000;

async function hello(deviceLabel: string) {
  const clock = new FixedClock(T0);
  const desktop = new MockDesktop(clock);
  const qrRaw = desktop.beginPairing(deviceLabel);
  const payload = parseQrPayload(qrRaw, clock.nowUnix());
  return { clock, desktop, payload, qrRaw };
}

describe('MockDesktop pairing (contract §3)', () => {
  it('issues a QR that passes the strict §3.1 parser', async () => {
    const { payload, clock } = await hello('Pixel 8');
    expect(payload.pairing_ticket.startsWith('mockticket')).toBe(true);
    expect(payload.expires_unix - payload.issued_unix).toBeLessThanOrEqual(300);
    // Ticket charset survives the bounded parser.
    expect(payload.pairing_ticket).toMatch(/^[A-Za-z0-9_-]{8,128}$/);
    // The desktop key in the QR is canonical ed25519 (AUTH-4).
    expect(payload.desktop_public_key_b64.startsWith('ed25519:')).toBe(true);
    expect(clock.nowUnix()).toBe(T0);
  });

  it('hello registers Pending, mints the id, and auto-issues the activation challenge', async () => {
    const { desktop, payload } = await hello('Pixel 8');
    const reg = await desktop.hello({
      type: 'kiwi-pairing-hello',
      pairing_ticket: payload.pairing_ticket,
      device_label: payload.device_label,
      device_public_key_b64: 'A'.repeat(43) + '=', // 32 bytes canonical
      keystore_ref: 'kiwi-auth-test',
    });
    expect(reg.type).toBe('kiwi-pairing-registered');
    expect(reg.device_id.startsWith('dev-mock-')).toBe(true);
    expect(await desktop.deviceStatus(reg.device_id)).toBe('pending');
    const pending = await desktop.pullChallenges(reg.device_id);
    const activation = pending.find((c) => c.event === 'device-pairing');
    expect(activation).toBeDefined();
    expect(activation?.session_id.startsWith('boot-')).toBe(true); // §4.2 grammar
  });

  it('tickets are single-use and expire with the QR (§3.1)', async () => {
    const { desktop, payload } = await hello('Pixel 8');
    const helloMsg = {
      type: 'kiwi-pairing-hello' as const,
      pairing_ticket: payload.pairing_ticket,
      device_label: payload.device_label,
      device_public_key_b64: 'A'.repeat(43) + '=',
      keystore_ref: 'kiwi-auth-test',
    };
    await desktop.hello(helloMsg);
    await expect(desktop.hello(helloMsg)).rejects.toThrow(/used/);

    const second = await hello('Other');
    second.clock.unix = T0 + 300; // QR window closed
    await expect(
      second.desktop.hello({
        type: 'kiwi-pairing-hello',
        pairing_ticket: second.payload.pairing_ticket,
        device_label: second.payload.device_label,
        device_public_key_b64: 'A'.repeat(43) + '=',
        keystore_ref: 'kiwi-auth-test',
      }),
    ).rejects.toThrow(/expired/);
  });

  it('rejects device keys that are not canonical 32-byte base64 (ipc.md §9d)', async () => {
    const { desktop, payload } = await hello('Pixel 8');
    const base = {
      type: 'kiwi-pairing-hello' as const,
      pairing_ticket: payload.pairing_ticket,
      device_label: payload.device_label,
      keystore_ref: 'kiwi-auth-test',
    };
    await expect(desktop.hello({ ...base, device_public_key_b64: 'AAAA' })).rejects.toThrow(/32 bytes/);
    await expect(desktop.hello({ ...base, device_public_key_b64: 'AAAA AAA' })).rejects.toThrow(/canonical/);
    await expect(desktop.hello({ ...base, device_public_key_b64: 'ed25519:AAAAAA==' })).rejects.toThrow(
      /canonical/,
    );
  });
});

describe('MockDesktop challenges + intake (§4, §6, §7)', () => {
  function desktopWithDevice(): { clock: FixedClock; desktop: MockDesktop; deviceId: string } {
    const clock = new FixedClock(T0);
    const desktop = new MockDesktop(clock);
    desktop.issueChallenge('dev-mock-0001', 'unlock');
    return { clock, desktop, deviceId: 'dev-mock-0001' };
  }

  it('issues session- and transaction-scoped session ids per §4.2', () => {
    const desktop = new MockDesktop(new FixedClock(T0));
    expect(desktop.issueChallenge('dev', 'unlock').session_id.startsWith('boot-')).toBe(true);
    expect(desktop.issueChallenge('dev', 'device-pairing').session_id.startsWith('boot-')).toBe(true);
    expect(desktop.issueChallenge('dev', 'recovery').session_id.startsWith('x-tx:')).toBe(true);
    expect(desktop.issueChallenge('dev', 'elevated-action').session_id.startsWith('x-tx:')).toBe(true);
  });

  it('pull returns unanswered, unexpired challenges as copies', async () => {
    const { desktop, deviceId, clock } = desktopWithDevice();
    const first = await desktop.pullChallenges(deviceId);
    expect(first).toHaveLength(1);
    first[0]!.expires_unix = 0; // mutating the copy must not poison the store
    const again = await desktop.pullChallenges(deviceId);
    expect(again[0]?.expires_unix).not.toBe(0);

    const challenge = again[0]!;
    await desktop.postResponse(
      buildChallengeResponseData(challenge, 'deny', null),
    );
    expect(await desktop.pullChallenges(deviceId)).toHaveLength(0);

    desktop.issueChallenge(deviceId, 'recovery');
    clock.unix = T0 + 5000; // everything now expired
    expect(await desktop.pullChallenges(deviceId)).toHaveLength(0);
  });

  it('postResponse validates shape only and never verifies signatures', async () => {
    const { desktop, deviceId } = desktopWithDevice();
    const challenge = (await desktop.pullChallenges(deviceId))[0]!;

    // Offline link.
    desktop.online = false;
    const off = await desktop.postResponse(buildChallengeResponseData(challenge, 'deny', null));
    expect(off.kind).toBe('offline');
    desktop.online = true;

    // Unknown challenge id.
    const unknown = await desktop.postResponse({
      ...buildChallengeResponseData(challenge, 'deny', null),
      challenge_id: 'chg-not-here',
    });
    expect(unknown.kind).toBe('offline');

    // Approve must carry a 64-byte signature blob — checked for SHAPE only.
    // (Built by hand: the protocol builder itself refuses short signatures.)
    const badSig = await desktop.postResponse({
      ...buildChallengeResponseData(challenge, 'deny', null),
      decision: 'approve',
      signature_b64: Buffer.from(new Uint8Array(12)).toString('base64'),
    });
    expect(badSig.kind).toBe('offline');

    // Structural approve with a 64-byte (meaningless, unverified) blob lands.
    const goodSig = await desktop.postResponse(
      buildChallengeResponseData(challenge, 'approve', Buffer.from(new Uint8Array(64)).toString('base64')),
    );
    expect(goodSig.kind).toBe('delivered');
    expect(desktop.recordedResponses()).toHaveLength(1);
    expect(desktop.recordedResponses()[0]?.decision).toBe('approve');
  });

  it('an approved device-pairing challenge activates the device (§3.2 step 3)', async () => {
    const clock = new FixedClock(T0);
    const desktop = new MockDesktop(clock);
    const payload = parseQrPayload(desktop.beginPairing('Pixel'), clock.nowUnix());
    const registered = await desktop.hello({
      type: 'kiwi-pairing-hello',
      pairing_ticket: payload.pairing_ticket,
      device_label: payload.device_label,
      device_public_key_b64: 'A'.repeat(43) + '=',
      keystore_ref: 'kiwi-auth-test',
    });
    const activation = (await desktop.pullChallenges(registered.device_id))[0]!;
    await desktop.postResponse(
      buildChallengeResponseData(activation, 'approve', Buffer.from(new Uint8Array(64)).toString('base64')),
    );
    expect(await desktop.deviceStatus(registered.device_id)).toBe('active');
  });
});

describe('mock environment + full T-194 flow', () => {
  it('pairs and activates end to end through the ApprovalService', async () => {
    const clock = new FixedClock(T0);
    const env = createMockEnvironment(clock);
    const bundle = createApprovalBundle(env);

    // QR -> parse -> keystore keypair -> hello -> activation -> approve.
    const qrRaw = env.demoQr?.('Pixel 8') ?? '';
    const payload = parseQrPayload(qrRaw, clock.nowUnix());
    const handle = await env.keystore.generateKey('kiwi-auth-pair');
    const registered = await env.link.hello({
      type: 'kiwi-pairing-hello',
      pairing_ticket: payload.pairing_ticket,
      device_label: payload.device_label,
      device_public_key_b64: handle.publicKeyB64,
      keystore_ref: handle.keystoreRef,
    });
    expect(await env.link.deviceStatus(registered.device_id)).toBe('pending');

    const identity: PairedIdentity = {
      deviceId: registered.device_id,
      deviceLabel: payload.device_label,
      desktopEndpoint: payload.desktop_endpoint,
      desktopKeyB64: payload.desktop_public_key_b64,
      keystoreRef: handle.keystoreRef,
      publicKeyB64: handle.publicKeyB64,
      pairedUnix: clock.nowUnix(),
    };

    const activation = (await env.link.pullChallenges(identity.deviceId)).find(
      (c) => c.event === 'device-pairing',
    );
    expect(activation).toBeDefined();
    const review = bundle.service.review(JSON.stringify(activation), identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const decided = await bundle.service.decide(review.reviewed, identity, 'approve');
    expect(decided.ok).toBe(true);
    const flushed = await bundle.service.flush();
    expect(flushed.delivered).toEqual([activation?.challenge_id]);
    expect(await env.link.deviceStatus(identity.deviceId)).toBe('active');

    // The answered challenge is gone from pull; history shows the approval.
    const still = await env.link.pullChallenges(identity.deviceId);
    expect(still.some((c) => c.challenge_id === activation?.challenge_id)).toBe(false);
    expect(bundle.history.entries()[0]).toMatchObject({ decision: 'approve', delivery: 'delivered' });
    expect(bundle.ledger.isConsumed(activation!.challenge_id)).toBe(true);
  });

  it('mock issues a recovery challenge the service approves under x-tx grammar', async () => {
    const clock = new FixedClock(T0);
    const env = createMockEnvironment(clock);
    const bundle = createApprovalBundle(env);
    const identity: PairedIdentity = {
      deviceId: 'dev-mock-0001',
      deviceLabel: 'Pixel',
      desktopEndpoint: 'wss://127.0.0.1:49310/pair',
      desktopKeyB64: 'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      keystoreRef: (await env.keystore.generateKey('kiwi-auth-test')).keystoreRef,
      publicKeyB64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      pairedUnix: T0,
    };
    const raw = env.demoIssueChallenge?.(identity.deviceId, 'recovery') ?? '';
    expect(JSON.parse(raw).session_id.startsWith('x-tx:')).toBe(true);
    const review = bundle.service.review(raw, identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const denied = await bundle.service.decide(review.reviewed, identity, 'deny');
    expect(denied.ok).toBe(true);
    expect(bundle.history.entries()[0]?.decision).toBe('deny');
  });

  it('offline desktop: approve queues, stays queued, delivers on reconnect (§7)', async () => {
    const clock = new FixedClock(T0);
    const env = createMockEnvironment(clock);
    const bundle = createApprovalBundle(env);
    const identity: PairedIdentity = {
      deviceId: 'dev-mock-0001',
      deviceLabel: 'Pixel',
      desktopEndpoint: 'wss://127.0.0.1:49310/pair',
      desktopKeyB64: 'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      keystoreRef: (await env.keystore.generateKey('kiwi-auth-test')).keystoreRef,
      publicKeyB64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      pairedUnix: T0,
    };
    env.demoSetOnline?.(false);
    const raw = env.demoIssueChallenge?.(identity.deviceId, 'unlock') ?? '';
    const review = bundle.service.review(raw, identity);
    expect(review.ok).toBe(true);
    if (!review.ok) {return;}
    const approved = await bundle.service.decide(review.reviewed, identity, 'approve');
    expect(approved.ok).toBe(true);
    const first = await bundle.service.flush();
    expect(first.offline).toHaveLength(1);
    expect(bundle.queue.size).toBe(1); // approvals are never dropped
    expect(bundle.history.entries()[0]?.delivery).toBe('offline');
    env.demoSetOnline?.(true);
    clock.unix += 11; // past the 10 s retry throttle
    const second = await bundle.service.flush();
    expect(second.delivered).toHaveLength(1);
    expect(bundle.history.entries()[0]?.delivery).toBe('delivered');
  });
});

describe('fail-closed environment (SECURITY.md rule 7)', () => {
  it('refuses keystore, transport, link — and exposes no demo hooks', async () => {
    const env = createFailClosedEnvironment(new FixedClock(T0));
    expect(env.mode).toBe('fail-closed');
    expect(env.demoQr).toBeUndefined();
    expect(env.demoIssueChallenge).toBeUndefined();
    expect(env.demoSetOnline).toBeUndefined();

    await expect(env.keystore.generateKey('alias')).rejects.toBeInstanceOf(KeystoreError);
    expect(await env.keystore.hasKey('alias')).toBe(false);
    const posted = await env.transport.postResponse({
      schema_version: 1,
      challenge_id: 'c',
      device_id: 'd',
      session_id: 'boot-x',
      event: 'unlock',
      signature_b64: '',
      decision: 'deny',
    });
    expect(posted.kind).toBe('offline');
    await expect(env.link.hello({ type: 'kiwi-pairing-hello' } as never)).rejects.toThrow(/fail closed/);
    await expect(env.link.pullChallenges('dev')).rejects.toThrow(/fail closed/);
    await expect(env.link.deviceStatus('dev')).rejects.toThrow(/fail closed/);
  });

  it('bundles are independent (one ledger/queue/history per bundle)', async () => {
    const env = createFailClosedEnvironment(new FixedClock(T0));
    const a = createApprovalBundle(env);
    const b = createApprovalBundle(env);
    a.ledger.record('c1', 'deny');
    expect(a.ledger.isConsumed('c1')).toBe(true);
    expect(b.ledger.isConsumed('c1')).toBe(false);
    expect(a.queue).not.toBe(b.queue);
    expect(a.history).not.toBe(b.history);
  });
});

describe('QR validity ceiling (AUTH-10 / §3.1)', () => {
  it('rejects a payload claiming more than 300 seconds of validity', () => {
    const payload = JSON.stringify({
      v: 1,
      type: 'kiwi-pairing',
      pairing_ticket: 'Ab12Cd34Ef56',
      desktop_endpoint: 'wss://192.168.1.20:49310/pair',
      device_label: 'Pixel',
      desktop_public_key_b64: `ed25519:${Buffer.from(new Uint8Array(32)).toString('base64')}`,
      issued_unix: T0,
      expires_unix: T0 + 301,
    });
    expect(() => parseQrPayload(payload, T0 + 1)).toThrow(/300-second maximum/);
  });
});
