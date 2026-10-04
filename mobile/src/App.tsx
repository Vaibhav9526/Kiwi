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
 * - `desktop` (USB/LAN bring-up): real Ed25519 dev keystore (tweetnacl,
 *   memory-only) + HTTP link to the desktop's KIWI_PAIR_LISTEN dev
 *   listener. Bannered DEV KEYS — not the Android Keystore (contract §5).
 * - `fail-closed`: unavailable keystore, offline transport, rejecting link —
 *   the posture a signed build must keep until Phase 4 wires the real
 *   wss/TLS transport (contract §3.2) and the platform keystore (§5).
 *
 * `tests/isolation/mock-isolation.test.ts` enforces that screens and core
 * modules never import `src/mock/**` — they receive this environment.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { SafeAreaView, ScrollView, StyleSheet, Text, TextInput, TouchableOpacity, View } from 'react-native';

import {
  createApprovalBundle,
  createFailClosedEnvironment,
  type EnvironmentMode,
} from './environment';
import { createMockEnvironment } from './mock';
import { createDesktopEnvironment, type DesktopEnvironmentBundle } from './desktop';
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

const MODE_ORDER: EnvironmentMode[] = ['mock', 'desktop', 'fail-closed'];

export function App(): React.JSX.Element {
  const [screen, setScreen] = useState<ScreenName>('pairing');
  const [mode, setMode] = useState<EnvironmentMode>('mock');
  const [identity, setIdentity] = useState<PairedIdentity | null>(null);
  const [desktopOverride, setDesktopOverride] = useState('http://127.0.0.1:49310/pair');
  const desktopRef = useRef<DesktopEnvironmentBundle | null>(null);

  const environment = useMemo(() => {
    // Fresh clock per mode: switching environments resets all local state.
    // The desktop bundle persists across override edits so generated keys
    // survive typing in the endpoint box.
    const clock = new SystemClock();
    if (mode === 'mock') {
      return createMockEnvironment(clock);
    }
    if (mode === 'desktop') {
      if (desktopRef.current === null) {
        desktopRef.current = createDesktopEnvironment(clock);
      }
      // Override text is applied in the effect below so typing in the
      // endpoint box never recreates the environment or approval bundle.
      return desktopRef.current.environment;
    }
    return createFailClosedEnvironment(clock);
  }, [mode]);
  const bundle = useMemo(() => createApprovalBundle(environment), [environment]);

  useEffect(() => {
    if (desktopRef.current !== null) {
      const trimmed = desktopOverride.trim();
      desktopRef.current.endpointStore.override = trimmed.length === 0 ? null : trimmed;
    }
  }, [desktopOverride, mode]);

  const onPaired = useCallback((paired: PairedIdentity) => {
    setIdentity(paired);
    setScreen('approvals');
  }, []);

  const onToggleMode = useCallback(() => {
    setMode((m) => MODE_ORDER[(MODE_ORDER.indexOf(m) + 1) % MODE_ORDER.length] ?? 'mock');
    setIdentity(null);
    setScreen('pairing');
  }, []);

  const modeLabel = mode === 'mock' ? 'MOCK (dev)' : mode === 'desktop' ? 'DESKTOP (USB)' : 'FAIL-CLOSED';
  const banner =
    mode === 'mock'
      ? 'MOCK TRANSPORT — demo only. No desktop is contacted, mock signatures are non-cryptographic, nothing here authorizes anything.'
      : mode === 'desktop'
        ? 'DESKTOP (USB/LAN) — real Ed25519 signatures over the dev http:// channel. DEV KEYS live in app memory (not the Android Keystore). Use adb reverse + KIWI_PAIR_LISTEN=1 on the desktop.'
        : 'FAIL-CLOSED — platform keystore and live pairing transport land in Phase 4; every action here refuses.';

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
          style={[
            styles.modeBtn,
            mode === 'mock' ? styles.modeMock : mode === 'desktop' ? styles.modeDesktop : styles.modeFail,
          ]}
          onPress={onToggleMode}
          accessibilityRole="button"
          accessibilityLabel="Toggle environment mode"
        >
          <Text style={styles.modeText}>{modeLabel}</Text>
        </TouchableOpacity>
      </View>
      <Text style={mode === 'mock' ? styles.bannerMock : mode === 'desktop' ? styles.bannerDesktop : styles.bannerFail}>
        {banner}
      </Text>
      {mode === 'desktop' && (
        <View style={styles.endpointRow}>
          <Text style={styles.endpointLabel}>Desktop endpoint override (adb reverse target):</Text>
          <TextInput
            style={styles.endpointInput}
            onChangeText={setDesktopOverride}
            value={desktopOverride}
            placeholder="http://127.0.0.1:49310/pair"
            placeholderTextColor="#5a6a78"
            accessibilityLabel="Desktop endpoint override"
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Text style={styles.endpointHint}>
            Empty = use the QR endpoint. With USB: run `adb reverse tcp:49310 tcp:49310`, start the desktop with
            KIWI_PAIR_LISTEN=1 KIWI_PAIR_PORT=49310, then paste the QR payload in Pairing.
          </Text>
        </View>
      )}
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
  modeDesktop: { backgroundColor: '#1f5fa8' },
  modeFail: { backgroundColor: '#2c3945' },
  bannerDesktop: { color: '#7db8f0', fontSize: 11, paddingHorizontal: 16, paddingTop: 8 },
  endpointRow: { paddingHorizontal: 16, paddingTop: 8 },
  endpointLabel: { color: '#aebccb', fontSize: 11, marginBottom: 4 },
  endpointInput: {
    borderColor: '#2c3945',
    borderWidth: 1,
    borderRadius: 8,
    color: '#e8edf2',
    padding: 8,
    fontSize: 12,
  },
  endpointHint: { color: '#7a8a99', fontSize: 11, marginTop: 4 },
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
