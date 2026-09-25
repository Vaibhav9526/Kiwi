# T-311 — Authenticator contract rulings: proposed diffs

**Status: PROPOSED — pending owner/Lead ratification.** Companion diff
sketch for DECISIONS.md ADR-013. Nothing here is applied to normative
text; each block shows the intended `authenticator.md`/`ipc.md` edit only
if the corresponding ruling (R1–R8) is ratified.

Source audit: `docs/audits/authenticator-drift-1.md` ("Contract decisions
required before implementation", 8 rows). Unblocks T-194.

---

## R1 — Desktop-key encoding

**`authenticator.md` §3.1 QR example:**

```diff
-  "desktop_public_key_b64": "ed25519:<64-char base64>",
+  "desktop_public_key_b64": "ed25519:<44-char canonical std Base64>",
```

**`authenticator.md` §3.1 field row** — make the canonical rule explicit:

```diff
-| `desktop_public_key_b64` | string | `ed25519:` prefix + base64 of the desktop's 32-byte Ed25519 public key; lets the phone pin the desktop identity for the pairing channel |
+| `desktop_public_key_b64` | string | `ed25519:` + RFC 4648 standard Base64 (padded) decoding to exactly 32 bytes, requiring byte-for-byte re-encode equality — the canonical form the TLS pin compares |
```

**Consumers:** mobile `qr.ts` adds decode+reencode (mirrors
`kiwi-app/src-tauri/src/commands/pair.rs::check_desktop_key`, which
already enforces all three checks at the IPC boundary).

## R2 — TLS pin identity

**`authenticator.md` §3.2** — replace the undefined "pin = desktop_public_key_b64"
with the concrete comparison:

```diff
 - The channel must be TLS-protected (pinned self-signed desktop cert is
-  acceptable on LAN; pin = `desktop_public_key_b64`). Plaintext pairing
-  transport is forbidden.
+  acceptable on LAN; the pin comparison is leaf-certificate public-key
+  equality — the cert's SPKI MUST carry the exact 32-byte Ed25519 key
+  carried in `desktop_public_key_b64`; no CA chain, no hostname check,
+  no fingerprint). Plaintext pairing transport is forbidden.
```

The desktop generates its pairing cert from the same Ed25519 keypair that
`kiwi.pair.desktop-key` stores. Flagged for Agent 6: if a target mobile
TLS stack cannot verify Ed25519 certs, an ECDSA-cert + in-channel proof
fallback requires explicit crypto sign-off before use.

## R3 — Pairing scheme grammar

**`authenticator.md` §3.1 example:**

```diff
-  "desktop_endpoint": "ws://192.168.1.20:49310/pair",
+  "desktop_endpoint": "wss://192.168.1.20:49310/pair",
```

**`authenticator.md` §3.1 field row:**

```diff
-| `desktop_endpoint` | string | 1..256 chars; LAN-local address of the pairing channel |
+| `desktop_endpoint` | string | 1..256 chars; `wss://<host-or-ip>:<port>/<path>` only — `ws://`, `http://`, `https://`, userinfo, query, and fragment are rejected; `http://` appears only under the dev-flagged T-304 listener |
```

**`authenticator.md` §3.2** — the T-184 bullet upgrades from
"recommendation, Lead to ratify" to ratified grammar; the §10.2 open item
closes; the T-304 interim listener note stays as the dev seam.

## R4 — Challenge casing/version

**`authenticator.md` §4.2/§6.2** — keep snake_case + `schema_version`
(examples are already correct here); add the boundary statement:

```diff
+- **Wire dialects.** This document's snake_case fields + `schema_version`
+  are the PHONE-facing transport wire. ipc.md's camelCase `nonceB64`
+  (no `schema_version`) is the ratified desktop renderer IPC wire.
+  A single adapter at the channel boundary maps the two; a payload must
+  never carry both spellings of the same field.
```

**`ipc.md` §9d.4** — add the reciprocal note (camelCase is renderer IPC;
the phone channel speaks authenticator.md §4.2 and an adapter maps).
No field changes on either wire.

## R5 — Session form

**`authenticator.md` §4.2 + §6.2 examples:**

```diff
-  "session_id": "x-tx:...",
   "event": "unlock",
+  "session_id": "boot-…",
```

(when the event is `unlock`/`device-pairing`; the `x-tx:` form stays the
example for `recovery`/`elevated-action` once those flows land).
Plus one enforcement line: consumers reject `x-tx:` on
unlock/device-pairing and `boot-` on recovery/elevated-action — the
event↔form pairing is part of the grammar.

## R6 — Approval-context field

**`authenticator.md` §4.2 delivery JSON:**

```diff
 {
   "schema_version": 1,
   "challenge_id": "chg-...",
   "device_id": "dev-...",
   "session_id": "boot-…",
   "event": "unlock",
   "nonce_b64": "<base64 of the 32-byte nonce>",
+  "desktop_label": "Vaibhav's Desktop",
   "issued_unix": 1729000000,
   "expires_unix": 1729000120
 }
```

```diff
+- `desktop_label`: display-only context for §6.1 step 5 — the desktop's
+  own label, ≤128 chars, sanitized per `safeDeviceLabel` rules. NOT
+  signed (canonical bytes unchanged) and NOT a trust input; the signed
+  binding is device_id + session_id.
```

`mobile/src/protocol/types.ts::ChallengeData` gains the optional field;
the approval screen shows it. No canonical-byte change, no contract
major-version bump.

## R7 — Timeout audit

**`authenticator.md` §7:**

```diff
 - **Deny degrades gracefully.** If a deny cannot be delivered, the phone
-  may drop it (desktop audits the timeout instead); denies are never
-  queued indefinitely.
+  may drop it (the desktop simply lets the challenge expire — §6.3: a
+  timeout is the absence of a decision, no audit row unless a late
+  response arrives); denies are never queued indefinitely.
```

**`authenticator.md` §10 open item 4** — drop the stale "DONE" line or
repoint it at this reconciliation (both sections now agree).

## R8 — QR secrecy wording

**`authenticator.md` rule 6 (§1) + §3.1 rules:**

```diff
-- **No secrets in QR, logs, or fixtures (rule 6).** The QR carries no key
-  material; public keys travel inside the pairing channel only.
+- **No private key material in QR, logs, or fixtures (rule 6).** The QR
+  carries no private key material; the `pairing_ticket` IS short-lived
+  single-use bearer material — never logged, audited, persisted beyond
+  the flow window, or echoed in errors. The QR payload is renderer
+  display-only under the ratified local-render exception (ipc.md §9d).
```

```diff
-- The QR contains **no key material, no secrets** — the desktop public key
-  is public by definition; the ticket is single-use and short-lived.
+- The QR contains **no private key material** — the desktop public key is
+  public by definition; the ticket is bearer material and is handled as
+  such (never echoed, never logged, expires ≤ 5 min).
```

---

## Cross-reference map (audit row → ruling → touched text)

| Audit row | Ruling | Contract text touched | Code consumer change |
|---|---|---|---|
| Desktop-key encoding | R1 | authenticator.md §3.1 example + field row | mobile qr.ts decode+reencode |
| TLS pin identity | R2 | authenticator.md §3.2 pin clause | cert-key = QR key in wss impl |
| Pairing scheme | R3 | authenticator.md §3.1 example + field row, §3.2, §10.2 | scanner scheme gate; T-304 flag stays dev-only |
| Challenge casing/version | R4 | authenticator.md §4.2 + ipc.md §9d.4 boundary notes | one adapter at channel boundary |
| Session form | R5 | authenticator.md §4.2/§6.2 examples + grammar line | consumer event↔form check |
| Approval context | R6 | authenticator.md §4.2 new field | ChallengeData + approval screen |
| Timeout audit | R7 | authenticator.md §7 + §10 item 4 | none (wording only) |
| QR secrecy | R8 | authenticator.md §1 rule 6 + §3.1 rules | none (wording already true in code) |
