/**
 * Pairing screen (T-136 contract §3).
 *
 * Scaffold flow: paste the QR payload JSON (camera ingest is Phase 4) →
 * `parseQrPayload` validates it fail-closed → generate the keystore keypair
 * → show the derived registration facts that Phase 4 will POST over the
 * pinned pairing channel (`kiwi-pairing-hello`).
 *
 * SECURITY.md rule 9: the pasted string is attacker-controlled; every field
 * is validated/bounded before display, and the raw string is never logged.
 */
import React, { useCallback, useMemo, useState } from "react";
import { Alert, StyleSheet, Text, TextInput, TouchableOpacity, View } from "react-native";

import { parseQrPayload, safeDeviceLabel, isQrPayloadCurrent } from "../protocol/qr";
import { UnavailableKeystore, KeystoreError } from "../keystore/keystore";

export interface PairedIdentity {
  deviceId: string;
  deviceLabel: string;
  desktopEndpoint: string;
}

/** Phase 4 will assign the real device id from the pairing-registered reply. */
const SCAFFOLD_DEVICE_ID_PREFIX = "dev-scaffold-";

export function PairingScreen(props: {
  onPaired?: (identity: PairedIdentity) => void;
}): React.JSX.Element {
  const [qrText, setQrText] = useState("");
  const [status, setStatus] = useState<string>("Paste a pairing QR payload to begin.");
  const [pairedLabel, setPairedLabel] = useState<string | null>(null);
  const keystore = useMemo(() => new UnavailableKeystore(), []);

  const onPair = useCallback(async () => {
    // Bounded local clock — scaffold uses wall clock; Phase 4 keeps the
    // same independent-check semantics (contract §6.1 step 2).
    const nowUnix = Math.floor(Date.now() / 1000);
    try {
      const payload = parseQrPayload(qrText, nowUnix);
      if (!isQrPayloadCurrent(payload, nowUnix)) {
        setStatus("Pairing QR expired — generate a new one on the desktop.");
        return;
      }
      // Scaffold: key generation is fail-closed until the native keystore
      // module lands (contract §5). Surface the honest error.
      try {
        await keystore.generateKey(`kiwi-auth-${payload.pairing_ticket.slice(0, 8)}`);
        setStatus("Keystore unexpectedly available — re-run review (Phase 4).");
        return;
      } catch (err) {
        const expected =
          err instanceof KeystoreError &&
          (err.code === "not-implemented" || err.code === "keystore-unavailable");
        if (!expected) {
          // Any other keystore failure must stop pairing (fail closed).
          setStatus("Keystore error — pairing aborted.");
          return;
        }
      }
      const label = safeDeviceLabel(payload.device_label);
      const identity: PairedIdentity = {
        // Scaffold id; Phase 4 replaces it with the desktop-assigned id.
        deviceId: `${SCAFFOLD_DEVICE_ID_PREFIX}${payload.pairing_ticket.slice(0, 8)}`,
        deviceLabel: label,
        desktopEndpoint: payload.desktop_endpoint,
      };
      setPairedLabel(label);
      setStatus(
        `Validated pairing for "${label}" → ${payload.desktop_endpoint}.\n` +
          "Scaffold stops here: the pinned pairing channel (Phase 4) would " +
          "now send kiwi-pairing-hello and activate the device.",
      );
      props.onPaired?.(identity);
    } catch (err) {
      // Bounded, non-echoing error surface (rule 6: no raw payload in logs).
      const msg = err instanceof Error ? err.message : "invalid QR payload";
      setStatus(`Rejected QR: ${msg}`);
      Alert.alert("Invalid pairing QR", "The scanned payload failed validation.");
    }
  }, [qrText, keystore, props]);

  return (
    <View>
      <Text style={styles.h2}>Pair with desktop</Text>
      <Text style={styles.p}>
        On the desktop, open Settings → Devices → “Pair authenticator”, then
        paste the QR payload below.
      </Text>
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
      <TouchableOpacity style={styles.button} onPress={onPair} accessibilityRole="button">
        <Text style={styles.buttonText}>Validate & pair</Text>
      </TouchableOpacity>
      {pairedLabel !== null && (
        <Text style={styles.ok}>Paired (scaffold): {pairedLabel}</Text>
      )}
      <Text style={styles.status}>{status}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  h2: { color: "#e8edf2", fontSize: 17, fontWeight: "600", marginBottom: 8 },
  p: { color: "#aebccb", fontSize: 13, marginBottom: 12 },
  input: {
    minHeight: 90,
    borderColor: "#2c3945",
    borderWidth: 1,
    borderRadius: 8,
    color: "#e8edf2",
    padding: 10,
    marginBottom: 12,
    fontSize: 12,
  },
  button: { backgroundColor: "#2c7a4b", borderRadius: 8, padding: 12, alignItems: "center" },
  buttonText: { color: "#ffffff", fontWeight: "600" },
  ok: { color: "#6fd29a", marginTop: 12, fontSize: 13 },
  status: { color: "#aebccb", marginTop: 8, fontSize: 12 },
});
