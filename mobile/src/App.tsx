/**
 * KIWI Authenticator app root (T-136 scaffold).
 *
 * Two screens, local state navigation:
 *   Pairing           — scan/enter QR payload → validated device identity
 *   PendingApprovals  — challenge list → approve/deny → ChallengeQueue
 *
 * Deliberately minimal: real QR camera ingest, push channel, and keystore
 * wiring are Phase 4 (docs/contracts/authenticator.md §3.2, §5). This shell
 * exists so the protocol modules have a host and the UX gates (§6.1) have a
 * surface to be reviewed against.
 */
import React, { useCallback, useMemo, useState } from "react";
import { SafeAreaView, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";

import { PairingScreen, type PairedIdentity } from "./screens/PairingScreen";
import { PendingApprovalsScreen } from "./screens/PendingApprovalsScreen";

export type ScreenName = "pairing" | "approvals";

export function App(): React.JSX.Element {
  const [screen, setScreen] = useState<ScreenName>("pairing");
  const [identity, setIdentity] = useState<PairedIdentity | null>(null);

  const onPaired = useCallback((id: PairedIdentity) => {
    setIdentity(id);
    setScreen("approvals");
  }, []);

  const tabs = useMemo(
    () =>
      [
        { name: "pairing" as const, label: "Pairing" },
        { name: "approvals" as const, label: "Approvals" },
      ].slice(),
    [],
  );

  return (
    <SafeAreaView style={styles.root}>
      <Text style={styles.title}>KIWI Authenticator</Text>
      <View style={styles.tabs}>
        {tabs.map((t) => (
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
        {screen === "pairing" ? (
          <PairingScreen onPaired={onPaired} />
        ) : (
          <PendingApprovalsScreen identity={identity} />
        )}
      </ScrollView>
      <Text style={styles.footer}>
        Scaffold only — pairing transport + platform keystore land in Phase 4
        (docs/contracts/authenticator.md).
      </Text>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#101418" },
  title: { color: "#e8edf2", fontSize: 20, fontWeight: "700", padding: 16 },
  tabs: { flexDirection: "row", paddingHorizontal: 16, gap: 8 },
  tab: {
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 8,
    backgroundColor: "#1c232b",
  },
  tabActive: { backgroundColor: "#2c7a4b" },
  tabText: { color: "#e8edf2", fontSize: 14 },
  body: { padding: 16 },
  footer: { color: "#7a8a99", fontSize: 11, padding: 12, textAlign: "center" },
});
