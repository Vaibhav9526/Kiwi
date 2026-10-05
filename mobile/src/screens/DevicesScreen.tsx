/**
 * Devices screen (T-194; contract §5, §7 pairing status).
 *
 * Shows only public facts: desktop-assigned id, label, pinned desktop
 * key/endpoint, the public half of the phone key, and the opaque keystore
 * ref. Forgetting a device destroys the local key material and clears the
 * pending queue — history is kept as a local audit trail.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { Alert, StyleSheet, Text, TouchableOpacity, View } from 'react-native';

import type { ApprovalBundle, Environment } from '../environment';
import type { PairedIdentity } from '../protocol/types';
import { fmtTime, shortId } from './format';

interface DevicesScreenProps {
  environment: Environment;
  bundle: ApprovalBundle;
  identity: PairedIdentity | null;
  onForget: () => void;
}

export function DevicesScreen(props: DevicesScreenProps): React.JSX.Element {
  const { environment, identity } = props;
  const [keyPresent, setKeyPresent] = useState<boolean | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setKeyPresent(null);
    setStatus(null);
    if (identity === null) {return undefined;}
    environment.keystore
      .hasKey(identity.keystoreRef)
      .then((present) => {
        if (!cancelled) {setKeyPresent(present);}
      })
      .catch(() => {
        if (!cancelled) {setKeyPresent(false);}
      });
    environment.link
      .deviceStatus(identity.deviceId)
      .then((s) => {
        if (!cancelled) {setStatus(s);}
      })
      .catch(() => {
        if (!cancelled) {setStatus('unreachable');}
      });
    return () => {
      cancelled = true;
    };
  }, [environment, identity]);

  const onForget = useCallback(() => {
    if (identity === null) {return;}
    Alert.alert(
      'Forget this device?',
      'The local key is destroyed and queued outcomes are dropped. History stays on this phone.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Forget', style: 'destructive', onPress: props.onForget },
      ],
    );
  }, [identity, props]);

  if (identity === null) {
    return (
      <View>
        <Text style={styles.h2}>Paired devices</Text>
        <Text style={styles.empty}>No paired device — pair from the Pairing tab first.</Text>
      </View>
    );
  }

  return (
    <View>
      <Text style={styles.h2}>Paired devices</Text>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>{identity.deviceLabel}</Text>
        <Text style={styles.rowText}>Device ID: {identity.deviceId}</Text>
        <Text style={styles.rowText}>Status: {status ?? 'checking…'}</Text>
        <Text style={styles.rowText}>Desktop: {identity.desktopEndpoint}</Text>
        <Text style={styles.rowText}>Pinned key: {shortId(identity.desktopKeyB64, 32)}</Text>
        <Text style={styles.rowText}>Phone key: {shortId(identity.publicKeyB64, 24)} (public)</Text>
        <Text style={styles.rowText}>Keystore ref: {shortId(identity.keystoreRef, 32)}</Text>
        <Text style={styles.rowText}>
          Key present: {keyPresent === null ? 'checking…' : keyPresent ? 'yes' : 'NO (approvals will fail closed)'}
        </Text>
        <Text style={styles.rowText}>Paired: {fmtTime(identity.pairedUnix)}</Text>
      </View>
      <Text style={styles.p}>
        Queued outcomes not yet sent: {props.bundle.service.queuedCount} · history entries:{' '}
        {props.bundle.history.size}
      </Text>
      <TouchableOpacity
        style={styles.forgetBtn}
        onPress={onForget}
        accessibilityRole="button"
        accessibilityLabel="Forget paired device"
      >
        <Text style={styles.buttonText}>Forget this device</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: '#e8edf2', fontSize: 17, fontWeight: '600', marginBottom: 8 },
  p: { color: '#aebccb', fontSize: 13, marginBottom: 12 },
  empty: { color: '#7a8a99', fontSize: 13 },
  card: {
    backgroundColor: '#1c232b',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    borderColor: '#2c3945',
    borderWidth: 1,
  },
  cardTitle: { color: '#e8edf2', fontSize: 15, fontWeight: '600', marginBottom: 8 },
  rowText: { color: '#aebccb', fontSize: 12, marginBottom: 4 },
  forgetBtn: { backgroundColor: '#8a3a3a', borderRadius: 8, padding: 12, alignItems: 'center' },
  buttonText: { color: '#ffffff', fontWeight: '600', fontSize: 13 },
});
