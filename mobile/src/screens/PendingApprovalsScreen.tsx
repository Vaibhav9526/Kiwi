/**
 * Pending approvals screen (T-136 contract §6).
 *
 * Scaffold: challenges arrive as pasted JSON (push delivery is Phase 4).
 * Every submission goes through the §6.1 gate order — strict parse, local
 * clock, binding check against this device, replay ledger — before the UI
 * offers Approve/Deny. Approve stays disabled in scaffold because the
 * keystore cannot sign (fail closed); Deny exercises the no-signature path.
 */
import React, { useCallback, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, TouchableOpacity, View } from 'react-native';

import { parseChallengeData, buildChallengeResponseData } from '../protocol/canonical';
import { ReplayLedger, FixedClock } from '../protocol/replay';
import { ChallengeQueue } from '../protocol/queue';
import { OfflineTransport } from '../transport/transport';
import { UnavailableKeystore, KeystoreError } from '../keystore/keystore';
import type { ChallengeData } from '../protocol/types';
import type { PairedIdentity } from './PairingScreen';

export const EVENT_LABELS: Record<ChallengeData['event'], string> = {
  unlock: 'Unlock KIWI',
  'device-pairing': 'Pair this device',
  recovery: 'Account recovery',
  'elevated-action': 'Elevated action',
};

export function PendingApprovalsScreen(props: { identity: PairedIdentity | null }): React.JSX.Element {
  const [raw, setRaw] = useState('');
  const [status, setStatus] = useState('Paste a challenge JSON to review it.');
  const [pending, setPending] = useState<ChallengeData | null>(null);

  // One ledger + queue per app instance (scaffold); Phase 4 persists them.
  const ledger = useMemo(() => new ReplayLedger(new FixedClock(Math.floor(Date.now() / 1000))), []);
  const queue = useMemo(
    () => new ChallengeQueue(new OfflineTransport(), new FixedClock(Math.floor(Date.now() / 1000))),
    [],
  );
  const keystore = useMemo(() => new UnavailableKeystore(), []);

  const onReview = useCallback(() => {
    try {
      const challenge = parseChallengeData(JSON.parse(raw));
      if (ledger.isConsumed(challenge.challenge_id)) {
        setStatus('This challenge was already answered — suppressed (§6.4).');
        return;
      }
      if (props.identity !== null && challenge.device_id !== props.identity.deviceId) {
        setStatus('Challenge is addressed to a different device — rejected.');
        return;
      }
      if (ledger.isExpired(challenge)) {
        setStatus('Challenge expired on arrival — removed.');
        return;
      }
      setPending(challenge);
      setStatus(
        `${EVENT_LABELS[challenge.event]} requested. Expires ${challenge.expires_unix}. ` +
          'Verify the request on the desktop before approving.',
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'invalid challenge';
      setStatus(`Rejected challenge: ${msg}`);
    }
  }, [raw, ledger, props.identity]);

  const onDeny = useCallback(() => {
    if (pending === null) {return;}
    const recorded = ledger.record(pending.challenge_id, 'deny');
    if (!recorded) {
      setStatus('Already answered — nothing changed.');
      return;
    }
    const resp = buildChallengeResponseData(pending, 'deny', null);
    queue.enqueue(pending, resp, 'deny');
    setPending(null);
    setStatus('Denied. Queued for best-effort delivery; a denial confers no authorization.');
  }, [pending, ledger, queue]);

  const onApprove = useCallback(async () => {
    if (pending === null) {return;}
    try {
      // Scaffold: the keystore is the fail-closed UnavailableKeystore, so
      // signing cannot succeed — exactly the intended posture (§5). The
      // real flow builds canonical bytes then keystore-signs (§6.1).
      await keystore.sign('no-key', new Uint8Array(0));
      setStatus('Unexpected signing success — re-run review (Phase 4).');
    } catch (err) {
      const expected = err instanceof KeystoreError && err.code === 'not-implemented';
      setStatus(
        expected
          ? 'Approve unavailable in scaffold: the platform keystore (Ed25519 signing) lands in Phase 4.'
          : 'Keystore error — approve aborted.',
      );
    }
  }, [pending, keystore]);

  return (
    <View>
      <Text style={styles.h2}>Pending approvals</Text>
      <Text style={styles.p}>
        {props.identity === null
          ? 'No paired identity yet — complete Pairing first.'
          : `Device: ${props.identity.deviceLabel} (${props.identity.deviceId})`}
      </Text>
      <TextInput
        style={styles.input}
        multiline
        onChangeText={setRaw}
        value={raw}
        placeholder='{"schema_version":1,"challenge_id":"...",...}'
        placeholderTextColor="#5a6a78"
        accessibilityLabel="Challenge JSON"
        autoCapitalize="none"
        autoCorrect={false}
      />
      <View style={styles.row}>
        <TouchableOpacity style={[styles.button, styles.reviewBtn]} onPress={onReview} accessibilityRole="button">
          <Text style={styles.buttonText}>Review</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, pending === null ? styles.buttonDisabled : styles.denyBtn]}
          onPress={onDeny}
          disabled={pending === null}
          accessibilityRole="button"
        >
          <Text style={styles.buttonText}>Deny</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, pending === null ? styles.buttonDisabled : styles.approveBtn]}
          onPress={onApprove}
          disabled={pending === null}
          accessibilityRole="button"
        >
          <Text style={styles.buttonText}>Approve</Text>
        </TouchableOpacity>
      </View>
      <Text style={styles.status}>{status}</Text>
      <Text style={styles.p}>Queued outcomes: {queue.size} (offline queue; delivery is Phase 4).</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: '#e8edf2', fontSize: 17, fontWeight: '600', marginBottom: 8 },
  p: { color: '#aebccb', fontSize: 13, marginBottom: 12 },
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
  row: { flexDirection: 'row', gap: 8 },
  button: { borderRadius: 8, padding: 12, alignItems: 'center', flex: 1 },
  reviewBtn: { backgroundColor: '#2c3945' },
  approveBtn: { backgroundColor: '#2c7a4b' },
  denyBtn: { backgroundColor: '#8a3a3a' },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#ffffff', fontWeight: '600' },
  status: { color: '#aebccb', marginTop: 12, fontSize: 12 },
});
