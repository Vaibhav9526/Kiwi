# Contract — Mobile Authenticator (pairing + challenge-response)

> Owner: Agent 4 · **Contract version: 1** · Status: draft (T-136)
> Implemented by `mobile/` (React Native client, scaffold). Verified against
> the authoritative Rust semantics: `kiwi-core/src/challenge.rs`
> (`ChallengeBook`), `kiwi-core/src/device.rs` (`DeviceRegistry`), and the
> desktop verifier `kiwi-app/src-tauri/src/verifier.rs` (Ed25519). Field
> semantics of challenges/devices live in `contracts/security-session.md`
> §6–7; this document owns the QR + pairing-channel wire and the
> authenticator-side obligations. Changes require Lead review
> (API_CONTRACTS.md rule) → record in DECISIONS.md.
>
> **Crypto sign-off gate:** this contract adds key handling; per
> SECURITY.md §6 it needs **Lead + Agent 6 sign-off** before any Phase 4
> implementation is enabled in production paths. The `mobile/` code ships
> fail-closed stubs only.

Parties: **mobile authenticator** (`mobile/`, Phase 4) ↔ **kiwi-app desktop**
(`src-tauri` IPC commands `kiwi_register_device`, `kiwi_list_devices`,
`kiwi_revoke_device`, challenge issue/verify) ↔ **kiwi-core**
(`DeviceRegistry`, `ChallengeBook`, `SessionBook`).

## 1. Invariants (binding on all parties)

- **Deterministic only.** No AI anywhere in pairing or approval (rule 1).
- **Established crypto only (rule 4):** signatures are **Ed25519 (RFC 8032)**
  over the challenge's canonical bytes. `ecdsa-p256` and `rsa3072` are
  reserved names matching kiwi-core `KeyAlgorithm`; desktop registration
  accepts them as names today but `algorithm_supported()` is Ed25519-only —
  a device registering another algorithm must be rejected
  (`unsupported-algorithm`, fail closed per rule 7) until a verifier lands.
- **Keystore-only private keys (rule 8).** The private key is generated and
  used inside the platform keystore (Android Keystore with TEE/StrongBox
  backing when available; iOS Secure Enclave/Keychain). It never crosses
  IPC, the pairing channel, QR, logs, or backups. Only the raw public key
  (Ed25519: exactly 32 bytes) and an opaque `keystore_ref` alias (≤256
  chars, not secret) ever leave the device. If a platform keystore cannot
  produce Ed25519 signatures natively, the Phase 4 fallback is an Ed25519
  seed wrapped by an AES-GCM key that lives in the keystore — never
  plaintext at rest (open item §11).
- **Challenge binding + single use (rule 10).** Every challenge binds
  device + session + event + 32-byte CSPRNG nonce + expiry; replay fails;
  failed attempts do not consume; nonce reuse at issue is a
  `replay-detected` incident (security-session.md §6).
- **No secrets in QR, logs, or fixtures (rule 6).** The QR carries no key
  material; public keys travel inside the pairing channel only.
- **All input is untrusted (rule 9).** Scanned QR payloads, pairing-channel
  messages, and desktop commands are validated + bounded on both sides.
  Unknown fields are ignored; auth decisions fail closed.
- **Approve is the only cryptographic act.** Denial is advisory UX; it is
  audited but confers no authorization and does not consume the challenge
  (§6.3).
- **Audited elevated actions (rule 11).** Desktop records every
  registration, approval verification outcome, denial, and revocation.
- `v` (schema_version) is an integer; producers emit `1`; consumers ignore
  unknown fields.

## 2. Roles

| party | owns |
|-------|------|
| `mobile/` | keypair lifecycle in keystore, QR ingest, challenge display, signing, approve/deny UX, local consumed-challenge cache |
| kiwi-app `src-tauri` | pairing ticket + QR display, device registration, challenge issue/verify (via `ChallengeBook` + `Ed25519Verifier`), audit |
| kiwi-core | challenge/canonical-bytes/verify-order semantics; device status machine |

## 3. Pairing — QR payload + ticket

### 3.1 QR payload format (v1)

The desktop renders a QR containing this exact JSON (compact, no whitespace):

```json
{
  "v": 1,
  "type": "kiwi-pairing",
  "pairing_ticket": "b1Qc-9xR...",
  "desktop_endpoint": "ws://192.168.1.20:49310/pair",
  "device_label": "Vaibhav's Pixel",
  "desktop_public_key_b64": "ed25519:<64-char base64>",
  "issued_unix": 1729000000,
  "expires_unix": 1729000300
}
```

| field | type | rules |
|-------|------|-------|
| `v` | int | `1`; a scanner seeing a higher major version rejects with "update the app", never guesses |
| `type` | string | literal `kiwi-pairing`; anything else is rejected |
| `pairing_ticket` | string | **single-use**, 8..128 chars, charset `[A-Za-z0-9_-]`; desktop-generated opaque token bound to the pending registration, consumed on first successful pairing-transport use |
| `desktop_endpoint` | string | 1..256 chars; LAN-local address of the pairing channel |
| `device_label` | string | 1..128 chars; display only, sanitized before render (`safeDeviceLabel`) |
| `desktop_public_key_b64` | string | `ed25519:` prefix + base64 of the desktop's 32-byte Ed25519 public key; lets the phone pin the desktop identity for the pairing channel |
| `issued_unix` / `expires_unix` | int | Unix seconds; QR validity **≤ 5 minutes** (recommended `expires = issued + 300`) |

Rules:
- The QR contains **no key material, no secrets** — the desktop public key
  is public by definition; the ticket is single-use and short-lived.
- Expired / malformed / wrong-typed / reused QRs are rejected with bounded
  errors; the raw QR text is never echoed to logs (rule 6).
- The `ed25519:` key-prefix check fails closed on other algorithms
  (`unsupported-algorithm` — matches the desktop verifier's today-reality).

### 3.2 Pairing channel (Phase 4; abstract in this scaffold)

One-shot channel addressed by `desktop_endpoint`:

1. Phone → desktop: `{type: "kiwi-pairing-hello", pairing_ticket,
   device_label, device_public_key_b64, keystore_ref}`.
2. Desktop validates the ticket (exists, unconsumed, unexpired), decodes and
   size-checks the public key (Ed25519 = 32 bytes → matches
   `kiwi_register_device` input), registers the device `Pending`, consumes
   the ticket, replies `{type: "kiwi-pairing-registered", device_id,
   issued_unix}`.
3. Desktop issues a `device-pairing` challenge (§4); the phone signs (§6)
   and returns the response; desktop verifies via `ChallengeBook` +
   `Ed25519Verifier`, then `DeviceRegistry.activate` + audit
   `device-paired`.

- The channel must be TLS-protected (pinned self-signed desktop cert is
  acceptable on LAN; pin = `desktop_public_key_b64`). Plaintext pairing
  transport is forbidden.
- The phone refuses a channel whose desktop key differs from the QR payload
  (QR-swap / channel-mismatch defense).
- Transport decision (T-184, Agent 6 recommendation, Lead to ratify):
  `wss://<lan-ip>:<port>` with the endpoint carried in the QR alongside
  the pin. Platform TLS stacks own framing + certificate validation, no
  custom framing code to get wrong, no mDNS chatter. mDNS advertisement
  stays a future discovery enhancement (endpoint format unchanged).
- **Interim claim listener (T-304).** While the wss/TLS ruling is pending,
  a bounded plaintext HTTP claim listener exists behind the
  `KIWI_PAIR_LISTEN` dev flag (ipc.md §9d.12) — a development seam that
  makes the claim path real and testable, **not** the shipping transport.
  The plaintext-forbidden rule above stands for production.

## 4. Challenge structure + signing

### 4.1 Canonical bytes (authoritative encoding)

Byte-for-byte parity with `kiwi_core::challenge::Challenge::canonical_bytes()`:

```
u32be(len) "kiwi-challenge-v1"
u32be(len) challenge_id        \  length-prefixed UTF-8
u32be(len) device_id            |
u32be(len) session_id          /
u8         event tag            (0x01 unlock | 0x02 device-pairing | 0x03 recovery | 0x04 elevated-action)
32 bytes   nonce                (raw, not base64)
i64be      issued_unix
i64be      expires_unix
```

The event tag byte is signed — a signature for one event can never be
replayed as another (kiwi-core `ChallengeEvent::tag()`). The mobile
`eventTag()` table MUST stay numerically identical; a renumbering requires
a contract major-version bump (§12).

### 4.2 Challenge delivery JSON (desktop → phone)

```json
{
  "schema_version": 1,
  "challenge_id": "chg-...",
  "device_id": "dev-...",
  "session_id": "x-tx:...",
  "event": "unlock",
  "nonce_b64": "<base64 of the 32-byte nonce>",
  "issued_unix": 1729000000,
  "expires_unix": 1729000120
}
```

- `session_id` semantics follow security-session.md §6: the id of the bound
  desktop session/transaction — never an actor label or free-text.
- Accepted forms (T-184, confirmed against kiwi-app `system.rs:126`):
  `boot-<...>` session ids for `unlock` / `device-pairing` (the session
  is the context being authorized); `x-tx:<txn>` transaction ids required
  once `recovery` / `elevated-action` flows land (the action is narrower
  than the session). The phone MUST NOT mint either form — it echoes the
  delivered value into the signed bytes.
- `expires - issued = 120` s default (`TrustPolicy::challenge_ttl_secs`);
  the phone additionally enforces its own local clock check (§6.1).
- Parsing is strict: bounded strings, exact-decode base64 (nonce = 32
  bytes), unknown fields ignored, unknown events rejected.

### 4.3 Nonce, expiry, replay (SECURITY.md rule 10)

- Nonce: 32 bytes, OS CSPRNG (`getrandom`), single-use, desktop-issued.
  Nonce reuse at issue time is a `replay-detected` incident (kiwi-core).
- Single-use: a consumed challenge can never verify again; failed
  verification does **not** consume (no DoS on legitimate retry).
- Phone-side defense in depth (`ReplayLedger`): the app records every
  answered challenge id and refuses to answer the same id twice (approve
  or deny), prunes entries older than 1 hour, caps the ledger at 256
  entries. The desktop `ChallengeBook` remains the consumption authority.

## 5. Keypair generation + platform keystore (SECURITY.md rule 8)

| step | requirement |
|------|-------------|
| generation | inside the platform keystore only: Android Keystore (Ed25519 where available, StrongBox when present), iOS Secure Enclave / Keychain-backed key |
| usage | every Ed25519 signature is performed by the keystore or its bound runtime; raw private key bytes are never exposed to app code, IPC, logs, or backups |
| storage | desktop/kiwi-core store **only** the public key + status; the phone keeps `keystore_ref` (alias ≤256 chars, non-secret) locally |
| algorithm | `ed25519` required (desktop verifier is Ed25519-only today); `ecdsa-p256` / `rsa3072` are reserved names — fail closed (`unsupported-algorithm`) until verifiers land |
| fallback | if the keystore cannot sign Ed25519 natively: generate the seed, wrap with an AES-GCM keystore key, store only the wrapped blob; unwrap per use, zeroize after. **Open item §11.1 — needs Lead + Agent 6 sign-off before Phase 4.** |
| destruction | on revocation or user request, destroy the keystore key on the phone — desktop revocation alone is not enough |

Scaffold posture: `mobile/src/keystore/keystore.ts` defines the
generation/sign/delete interface; `keystore/soft-hsm.ts` provides a
**test-only** in-memory implementation explicitly marked fail-closed
(UNIMPLEMENTED-style) — no production key handling ships from this task.

## 6. Approve/deny — response signing + decision rules

### 6.1 Phone-side gate order (all must pass before any signature exists)

1. **Display-only parse** — strict parse (§4.2) succeeds; otherwise show a
   bounded error and stop. A malformed challenge is never signable.
2. **Local clock check** — `now < expires_unix` using the phone's own clock
   (independent of desktop-supplied fields; defense against stale pushes).
   Expired → remove from the pending list, record `expired` locally.
3. **Binding sanity** — `device_id` must equal this phone's registered
   device id; a challenge addressed elsewhere is rejected (display-only).
4. **Replay ledger** — `challenge_id` not already answered (§4.3).
5. **Explicit user intent** — the user taps Approve or Deny on THIS
   challenge after seeing: event (human phrase, e.g. "Unlock KIWI"),
   desktop label, transaction id, issue/expiry times. No hidden or
   aggregated approvals; no default-approve timers.

Only then: `canonicalChallengeBytes(...)` → keystore Ed25519 sign →
`ChallengeResponseData` (§6.2). The signature exists only after step 5.

### 6.2 Response JSON (phone → desktop)

```json
{
  "schema_version": 1,
  "challenge_id": "chg-...",
  "device_id": "dev-...",
  "session_id": "x-tx:...",
  "event": "unlock",
  "decision": "approve",
  "signature_b64": "<base64, decodes to exactly 64 bytes (Ed25519)>"
}
```

- `approve` REQUIRES a valid 64-byte Ed25519 signature over the canonical
  bytes (§4.1), made by the registered device key. A response missing or
  oversize/undersize signature is invalid — desktop fails closed.
- Signature verification order on the desktop = `ChallengeBook::verify`
  (security-session.md §6): exists → unexpired → unconsumed → binding
  fields match → signature valid → consume. Every outcome is audited;
  failure reasons use kiwi-core `ChallengeError` names
  (`UnknownChallenge` | `Expired` | `AlreadyConsumed` | `BindingMismatch`
  | `InvalidSignature`).

### 6.3 Deny semantics

- Deny is an **explicit user decision**, carried as `"decision": "deny"`
  with **no signature field** (empty string allowed for JSON shape
  stability). It is audited desktop-side as `challenge-denied` but confers
  **no authorization** and does **not** consume the challenge.
- Rationale: a third party with stolen transport access gains nothing from
  forging denies, and a legitimate user is never locked out of re-approving
  a still-valid challenge.
- The phone still records the deny in its local ledger (one answer per
  challenge id, §4.3) so a re-pushed copy of the same challenge is not
  re-prompted.
- Deny vs timeout wording (binding, T-184): a timeout (no answer before
  expiry) is the ABSENCE of a decision — no audit row unless a late response
  is later verified (then `challenge-verification-failed Expired`, IPC code
  `challenge-expired` — the ratified ipc.md §9d.9 spelling; builds before the
  §9d.11 wire migration emit the legacy `expired`). It must never be recorded
  or rendered as a deny: deny is an
  explicit user decision (`challenge-denied`, challenge unconsumed,
  re-approvable). UI copy says "expired / no response", never "denied".

### 6.4 Replay / conflict handling

- If a challenge with an already-answered id re-arrives, the phone
  suppresses the prompt (idempotent UI) and does not re-sign.
- If the user denies and the same challenge is re-presented before expiry,
  the prior deny stands (no re-prompt spam); the desktop may re-issue a
  fresh challenge with a fresh nonce if the user re-tries the action.

## 7. Delivery — offline queue + retry

- **Approve commits at sign time.** Constructing the signed response is the
  approval; network loss after that queues the response for retry
  (`ChallengeQueue`), FIFO, bounded (default 64), one outcome per
  challenge id, delivery attempts throttled (default ≥10 s apart).
- **Deny degrades gracefully.** If a deny cannot be delivered, the phone
  may drop it (the desktop simply lets the challenge expire — §6.3: a
  timeout is the absence of a decision, no audit row unless a late
  response arrives); denies are never queued indefinitely.
- **No implicit expiry on the wire.** Expiry is judged by challenge fields
  + local clock only; a queued approve that reaches the desktop after
  expiry simply fails `Expired` there and is audited — never partially
  trusted.
- Transport binding is Phase 4 (§3.2 channel); the queue speaks
  `ChallengeTransport.postResponse` only, so the wire can be the pairing
  channel, a push relay, or a LAN socket without protocol changes.

## 8. `mobile/` scaffold map (this task — code only, no build run)

```
mobile/
  package.json / tsconfig.json / tsconfig.core.json / vitest.config.ts
  .eslintrc.js / babel.config.js / metro.config.js / app.json / index.js
  src/
    App.tsx                  RN root: registered as "KIWI Authenticator"
    screens/PairingScreen.tsx       QR ingest → validate → register flow
    screens/PendingApprovalsScreen.tsx  challenge list → approve/deny → queue
    keystore/keystore.ts     KeystoreError + generate/sign/delete interface (fail-closed)
    keystore/soft-hsm.ts     test-only in-memory impl (UNIMPLEMENTED posture)
    protocol/event.ts        event↔tag table (parity-checked with kiwi-core)
    protocol/types.ts        QrPayload / ChallengeData / ChallengeResponseData
    protocol/qr.ts           parseQrPayload + isQrPayloadCurrent + safeDeviceLabel
    protocol/canonical.ts    canonicalChallengeBytes + parseChallengeData + response builder
    protocol/replay.ts       ReplayLedger (one answer per challenge id)
    protocol/queue.ts        ChallengeQueue (sign-then-queue delivery)
    protocol/validate.ts     bounded validation helpers
    transport/transport.ts   ChallengeTransport interface (Phase 4 wire)
  tests/
    protocol/*.test.ts       deterministic protocol evidence
    keystore/soft-hsm.test.ts    fail-closed posture evidence
    helpers/protocol.ts           fixture helpers (synthetic only — SECURITY.md §4)
```

Pure modules (`protocol/`) run under Node vitest; RN imports are confined to
`App.tsx`, `screens/`, so `npm run typecheck` validates the protocol core
without a React Native toolchain.

## 9. Audit + test map (SECURITY.md rules 2, 11)

Desktop-side (kiwi-app, existing + Phase 4): `device-registered`,
`device-paired`, `challenge-approved` (per event), `challenge-denied`,
`challenge-verification-failed <ChallengeError name>`, `device-revoked`.
All outcomes audited — including failures (rule 2: reproducible evidence).
**Implemented (T-282):** `kiwi_submit_challenge` writes the approval
rows before the bound post-action runs (evidence-before-effect), audits
`challenge-verification-failed` with detail `err=<ChallengeError name>`
(the §9d.9 IPC code stands in for engine failures with no ChallengeError)
on every failed response, and records `challenge-denied` only for denies
attributable to a live challenge — unattributable denies audit as failed
responses, and silent timeouts write no row (§6.3).

Mobile-side tests shipped with this task:

| test file | proves |
|-----------|--------|
| `protocol/canonical.test.ts` | canonical bytes match the §4.1 layout; every bound field is covered; wrong event/device/session/nonce/times change the bytes |
| `protocol/qr.test.ts` | QR parse: valid, expired, wrong-type, oversize, unknown-version, bad ticket charset, unknown-field-ignored |
| `protocol/replay.test.ts` | one answer per id (approve and deny), prune, cap |
| `protocol/queue.test.ts` | sign-then-queue ordering, dedupe, throttling, bounded backlog, offline retry |
| `keystore/soft-hsm.test.ts` | fail-closed: no production key path, sign requires explicit test key material |

Fixtures are synthetic, generated in-test (rule 6 — no real credentials).

## 10. Versioning + open items

- Additive JSON fields → same major version; consumers ignore unknowns.
- Event-tag table change, canonical-byte change, or field removal →
  **contract version 2** + ADR + coordinated desktop release (the signed
  bytes must not differ between phone and desktop builds).
- Open items for Lead + Agent 6 sign-off (T-184 outcomes):
  1. Keystore-wrapped-seed fallback (§5) — Agent 6 assessment: CONDITIONAL path
     to yes. Wrapping key non-extractable + device-auth-gated where the
     platform allows; never persist an unwrapped seed; constant-time
     Ed25519 (no hand-rolled curve); device-integrity signal before
     enabling fallback; record fallback use in telemetry. Final approval
     stays Lead's.
  2. Pairing transport choice (§3.2): Agent 6 recommends `wss://` with QR-carried
     endpoint (rationale in §3.2); Lead to ratify.
  3. Session-id sourcing: CONFIRMED as `boot-<...>` in kiwi-app
     (`system.rs:126`); contract now documents both accepted forms
     (§4.2). `x-tx:<txn>` required for recovery/elevated-action when
     those flows land (Agent 7).
  4. Deny-vs-timeout audit wording: RESOLVED — §6.3 is binding; §7's
     "desktop audits the timeout" wording was reconciled to it (T-282).

## 11. Known limitations (honest-enforcement note)

- The phone-side clock is user-controllable; a skewed clock only affects the
  phone's own UX gate (§6.1 step 2) — the desktop `ChallengeBook` remains
  the authoritative expiry check. No security decision rests on the phone
  clock alone (SECURITY.md §4 time-safety).
- The desktop `device-pairing` challenge is issued to a `Pending` device;
  its registration key is verified at activation, so a pending device
  cannot activate itself — pairing requires an already-trusted desktop
  operator step (QR generation). QR interception alone grants nothing
  without the phone's keystore-held private key.
- This scaffold signs nothing in production: `soft-hsm` is test-only, and
  `transport.ts` has no live wire. Phase 4 work must re-trigger the
  SECURITY.md §6 crypto review gate.

---
*Owner: Agent 4 (T-136). Verification evidence + review requests:
`docs/agents/agent-4-status.md`.*
