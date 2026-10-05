/**
 * Pairing screen (T-194; contract §3, §3.2, §6.1).
 *
 * Flow: load/paste the pairing QR payload -> strict §3.1 validation
 * (type, version, ticket charset, 5-minute maximum, canonical 32-byte
 * desktop key) -> platform keystore keypair -> `kiwi-pairing-hello` over
 * the configured link -> desktop-assigned device id (Pending) -> review
 * the issued `device-pairing` challenge through the SAME ordered gate
 * service the Approvals tab uses -> approve -> delivered -> activation.
 *
 * Fail-closed rules honored here:
 * - a keystore refusal stops pairing BEFORE any identity exists
 *   (T270-08: no fabricated "paired" state);
 * - identity is only reported upward once the desktop reports `active`;
 * - the raw QR string is never logged or echoed (rule 6).
 */
import React, { useCallback, useState } from 'react';
import { Alert, StyleSheet, Text, TextInput, TouchableOpacity, View } from 'react-native';

import { parseQrPayload, safeDeviceLabel, isQrPayloadCurrent } from '../protocol/qr';
import { EVENT_PHRASES } from '../protocol/approval';
import { KeystoreError } from '../keystore/keystore';
import type { PairingRegistered } from '../transport/link';
import type { ApprovalBundle, Environment } from '../environment';
import type { PairedIdentity } from '../protocol/types';

export type { PairedIdentity };

interface PairingScreenProps {
  environment: Environment;
  bundle: ApprovalBundle;
  identity: PairedIdentity | null;
  onPaired: (identity: PairedIdentity) => void;
}

function bounded(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : fallback;
  return msg.length > 160 ? `${msg.slice(0, 160)}…` : msg;
}

export function PairingScreen(props: PairingScreenProps): React.JSX.Element {
  const { environment, bundle, identity, onPaired } = props;
  const [qrText, setQrText] = useState('');
  const [status, setStatus] = useState('Paste a pairing QR payload, or load the mock desktop code.');
  const [busy, setBusy] = useState(false);

  const onDemoQr = useCallback(() => {
    const demo = environment.demoQr;
    if (demo === undefined) {
      setStatus('Demo QR generation only exists in mock mode — paste a payload here.');
      return;
    }
    setQrText(demo('Mock phone'));
    setStatus('Mock desktop QR loaded — tap Validate & pair to run the full §3.2 flow.');
  }, [environment]);

  const onPair = useCallback(async () => {
    if (busy) {return;}
    setBusy(true);
    try {
      const nowUnix = environment.clock.nowUnix();
      const payload = parseQrPayload(qrText, nowUnix); // §3.1 gates, incl. 5-min max + canonical key
      // USB/LAN mode: the link dials the QR endpoint (plus the adb-reverse
      // loopback fallback) — remember it before the hello goes out.
      (environment.link as { noteQrEndpoint?: (endpoint: string) => void }).noteQrEndpoint?.(
        payload.desktop_endpoint,
      );
      if (!isQrPayloadCurrent(payload, nowUnix)) {
        setStatus('Pairing QR is not yet valid (issued in the future) — regenerate it.');
        return;
      }

      // Keystore first: without a signer there is no identity at all.
      let keystoreRef: string;
      let publicKeyB64: string;
      try {
        const handle = await environment.keystore.generateKey(
          `kiwi-auth-${payload.pairing_ticket.slice(0, 12)}`,
        );
        keystoreRef = handle.keystoreRef;
        publicKeyB64 = handle.publicKeyB64;
      } catch (err) {
        const expected = err instanceof KeystoreError;
        setStatus(
          expected
            ? 'Platform keystore unavailable — pairing stopped before any identity was created (fail closed).'
            : `Keystore error — pairing aborted: ${bounded(err, 'keystore failure')}`,
        );
        return;
      }

      // §3.2 step 1/2: hello -> desktop-assigned id (Pending).
      let registered: PairingRegistered;
      try {
        registered = await environment.link.hello({
          type: 'kiwi-pairing-hello',
          pairing_ticket: payload.pairing_ticket,
          device_label: safeDeviceLabel(payload.device_label),
          device_public_key_b64: publicKeyB64,
          keystore_ref: keystoreRef,
        });
      } catch (err) {
        setStatus(`Pairing channel rejected the hello: ${bounded(err, 'link failure')}`);
        return;
      }

      const provisional: PairedIdentity = {
        deviceId: registered.device_id,
        deviceLabel: safeDeviceLabel(payload.device_label),
        desktopEndpoint: payload.desktop_endpoint,
        desktopKeyB64: payload.desktop_public_key_b64,
        keystoreRef,
        publicKeyB64,
        pairedUnix: nowUnix,
      };

      // §3.2 step 3: sign the device-pairing challenge through the ordered
      // gates (parse -> clock -> binding -> replay), then deliver it.
      const pending = await environment.link.pullChallenges(registered.device_id);
      const activation = pending.find((c) => c.event === 'device-pairing');
      if (activation === undefined) {
        setStatus(`Registered (${registered.device_id}) but no activation challenge arrived.`);
        return;
      }
      const review = bundle.service.review(JSON.stringify(activation), provisional);
      if (!review.ok) {
        setStatus(`Activation blocked by gate "${review.reason}": ${review.message}`);
        return;
      }
      const decided = await bundle.service.decide(review.reviewed, provisional, 'approve');
      if (!decided.ok) {
        setStatus(`Activation signing failed: ${decided.message}`);
        return;
      }
      const flushed = await bundle.service.flush();
      const statusNow = await environment.link.deviceStatus(registered.device_id);
      if (statusNow !== 'active') {
        setStatus(
          flushed.offline.length > 0
            ? `Registered (${registered.device_id}) — activation response queued, device still pending.`
            : `Registered (${registered.device_id}) — activation not confirmed yet.`,
        );
        return;
      }
      setStatus(
        `Paired and active: ${registered.device_id} — event "${EVENT_PHRASES['device-pairing']}" approved.`,
      );
      onPaired(provisional);
    } catch (err) {
      setStatus(`Rejected: ${bounded(err, 'invalid pairing input')}`);
      Alert.alert('Pairing failed', 'The pairing input was rejected. Check the payload and retry.');
    } finally {
      setBusy(false);
    }
  }, [busy, bundle, environment, onPaired, qrText]);

  return (
    <View>
      <Text style={styles.h2}>Pair with desktop</Text>
      <Text style={styles.p}>
        On the desktop open Settings → Devices → Pair authenticator and scan the QR. In this
        scaffold you can paste the payload, or load the mock desktop&apos;s code below.
      </Text>
      <View style={styles.row}>
        <TouchableOpacity
          style={[styles.button, styles.demoBtn]}
          onPress={onDemoQr}
          disabled={busy}
          accessibilityRole="button"
          accessibilityLabel="Load mock desktop pairing QR"
        >
          <Text style={styles.buttonText}>Load mock QR</Text>
        </TouchableOpacity>
      </View>
      <TextInput
        style={styles.input}
        multiline
        onChangeText={setQrText}
        value={qrText}
        placeholder='{"v":1,"type":"kiwi-pairing",...}'
        placeholderTextColor="#5a6a78"
        accessibilityLabel="Pairing QR payload"
        autoCapitalize="none"
        autoCorrect={false}
      />
      <TouchableOpacity
        style={[styles.button, busy ? styles.buttonDisabled : styles.primaryBtn]}
        onPress={onPair}
        disabled={busy}
        accessibilityRole="button"
      >
        <Text style={styles.buttonText}>{busy ? 'Working…' : 'Validate & pair'}</Text>
      </TouchableOpacity>
      {identity !== null && (
        <Text style={styles.ok}>Active device: {identity.deviceLabel} ({identity.deviceId})</Text>
      )}
      <Text style={styles.status}>{status}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: '#e8edf2', fontSize: 17, fontWeight: '600', marginBottom: 8 },
  p: { color: '#aebccb', fontSize: 13, marginBottom: 12 },
  row: { flexDirection: 'row', gap: 8, marginBottom: 8 },
  input: {
    minHeight: 90,
    borderColor: '#2c3945',
    borderWidth: 1,
    borderRadius: 8,
    color: '#e8edf2',
    padding: 10,
    marginBottom: 12,
    fontSize: 12,
  },
  button: { borderRadius: 8, padding: 12, alignItems: 'center' },
  demoBtn: { backgroundColor: '#2c3945', flex: 1 },
  primaryBtn: { backgroundColor: '#2c7a4b' },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#ffffff', fontWeight: '600', fontSize: 13 },
  ok: { color: '#6fd29a', marginTop: 12, fontSize: 13 },
  status: { color: '#aebccb', marginTop: 8, fontSize: 12 },
});
