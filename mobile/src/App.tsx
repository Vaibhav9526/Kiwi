/**
 * KIWI Authenticator app root (T-194).
 *
 * Four screens, local-state navigation:
 *   Pairing     — QR payload -> keystore keypair -> hello -> activation challenge -> active identity
 *   Approvals   — pull/paste challenges -> ordered gates -> approve/deny -> queue -> history
 *   Devices     — public facts of the paired device + forget (key destroyed)
 *   History     — local decision log (approve / deny / expired + delivery)
 *
 * Environment wiring lives HERE and nowhere else (SECURITY.md rules 4, 7):
 * - `mock` (default): in-process mock desktop + soft-HSM test keystore, so
 *   every screen is exercisable end to end. Persistently bannered — mock
 *   signatures are non-cryptographic, nothing in this mode authorizes.
 * - `fail-closed`: unavailable keystore, offline transport, rejecting link —
 *   the posture a signed build must keep until Phase 4 wires the real
 *   wss/TLS transport (contract §3.2) and the platform keystore (§5).
 *
 * `tests/isolation/mock-isolation.test.ts` enforces that screens and core
 * modules never import `src/mock/**` — they receive this environment.
 */
import React, { useCallback, useMemo, useState } from 'react';
import { SafeAreaView, ScrollView, StyleSheet, Text, TouchableOpacity, View } from 'react-native';

import {
  createApprovalBundle,
  createFailClosedEnvironment,
  type EnvironmentMode,
} from './environment';
import { createMockEnvironment } from './mock';
import { SystemClock } from './protocol/replay';
import { PairingScreen, type PairedIdentity } from './screens/PairingScreen';
import { PendingApprovalsScreen } from './screens/PendingApprovalsScreen';
import { DevicesScreen } from './screens/DevicesScreen';
import { HistoryScreen } from './screens/HistoryScreen';

export type ScreenName = 'pairing' | 'approvals' | 'devices' | 'history';

const TABS: { name: ScreenName; label: string }[] = [
  { name: 'pairing', label: 'Pairing' },
  { name: 'approvals', label: 'Approvals' },
  { name: 'devices', label: 'Devices' },
  { name: 'history', label: 'History' },
];

export function App(): React.JSX.Element {
  const [screen, setScreen] = useState<ScreenName>('pairing');
  const [mode, setMode] = useState<EnvironmentMode>('mock');
  const [identity, setIdentity] = useState<PairedIdentity | null>(null);

  const environment = useMemo(() => {
    // Fresh clock per mode: switching environments resets all local state.
    const clock = new SystemClock();
    return mode === 'mock' ? createMockEnvironment(clock) : createFailClosedEnvironment(clock);
  }, [mode]);
  const bundle = useMemo(() => createApprovalBundle(environment), [environment]);

  const onPaired = useCallback((paired: PairedIdentity) => {
    setIdentity(paired);
    setScreen('approvals');
  }, []);

  const onToggleMode = useCallback(() => {
    setMode((m) => (m === 'mock' ? 'fail-closed' : 'mock'));
    setIdentity(null);
    setScreen('pairing');
  }, []);

  const onForget = useCallback(() => {
    if (identity !== null) {
      // Best effort: destroying the key is what makes approvals fail closed.
      environment.keystore.deleteKey(identity.keystoreRef).catch(() => undefined);
      bundle.queue.clear();
    }
    setIdentity(null);
    setScreen('pairing');
  }, [bundle, environment, identity]);

  return (
    <SafeAreaView style={styles.root}>
      <View style={styles.headerRow}>
        <Text style={styles.title}>KIWI Authenticator</Text>
        <TouchableOpacity
          style={[styles.modeBtn, mode === 'mock' ? styles.modeMock : styles.modeFail]}
          onPress={onToggleMode}
          accessibilityRole="button"
          accessibilityLabel="Toggle environment mode"
        >
          <Text style={styles.modeText}>{mode === 'mock' ? 'MOCK (dev)' : 'FAIL-CLOSED'}</Text>
        </TouchableOpacity>
      </View>
      <Text style={mode === 'mock' ? styles.bannerMock : styles.bannerFail}>
        {mode === 'mock'
          ? 'MOCK TRANSPORT — demo only. No desktop is contacted, mock signatures are non-cryptographic, nothing here authorizes anything.'
          : 'FAIL-CLOSED — platform keystore and live pairing transport land in Phase 4; every action here refuses.'}
      </Text>
      <View style={styles.tabs}>
        {TABS.map((t) => (
          <TouchableOpacity
            key={t.name}
            style={[styles.tab, screen === t.name && styles.tabActive]}
            onPress={() => setScreen(t.name)}
            accessibilityRole="button"
            accessibilityLabel={`Show ${t.label}`}
          >
            <Text style={styles.tabText}>{t.label}</Text>
          </TouchableOpacity>
        ))}
      </View>
      <ScrollView contentContainerStyle={styles.body}>
        {screen === 'pairing' ? (
          <PairingScreen
            environment={environment}
            bundle={bundle}
            identity={identity}
            onPaired={onPaired}
          />
        ) : screen === 'approvals' ? (
          <PendingApprovalsScreen environment={environment} bundle={bundle} identity={identity} />
        ) : screen === 'devices' ? (
          <DevicesScreen environment={environment} bundle={bundle} identity={identity} onForget={onForget} />
        ) : (
          <HistoryScreen bundle={bundle} />
        )}
      </ScrollView>
      <Text style={styles.footer}>
        Scaffold (T-194) — contract docs/contracts/authenticator.md; transport + platform keystore in
        Phase 4.
      </Text>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#101418' },
  headerRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingTop: 16 },
  title: { color: '#e8edf2', fontSize: 20, fontWeight: '700', flex: 1 },
  modeBtn: { borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6 },
  modeMock: { backgroundColor: '#7a5a1e' },
  modeFail: { backgroundColor: '#2c3945' },
  modeText: { color: '#ffffff', fontSize: 11, fontWeight: '700' },
  bannerMock: { color: '#e0a34a', fontSize: 11, paddingHorizontal: 16, paddingTop: 8 },
  bannerFail: { color: '#7a8a99', fontSize: 11, paddingHorizontal: 16, paddingTop: 8 },
  tabs: { flexDirection: 'row', paddingHorizontal: 16, paddingTop: 10, gap: 8 },
  tab: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 8,
    backgroundColor: '#1c232b',
  },
  tabActive: { backgroundColor: '#2c7a4b' },
  tabText: { color: '#e8edf2', fontSize: 13 },
  body: { padding: 16 },
  footer: { color: '#7a8a99', fontSize: 11, padding: 12, textAlign: 'center' },
});
