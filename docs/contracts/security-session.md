# Contract — SecuritySession + Trust/Lock Semantics

> Owner: Agent 2 · **Contract version: 1** · Status: draft (T-002)
> Implemented by `kiwi-core/` (Rust). Reference impl is authoritative for
> field semantics; this document is authoritative for the wire/IPC shape.
> Changes require Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: Thunderbird integration hooks → **kiwi-core**; kiwi-core → UI
surfaces; kiwi-forensics may also produce `SecuritySession` records
(`source = "forensic-pcap"`). kiwi-forensics owns *findings*; this contract
owns the *live-session view* and the *trust decision*.

## 1. Invariants (binding on all parties)

- Deterministic only. No field of this contract may require AI.
- No credentials, tokens, message bodies, or private keys anywhere in the
  payload (SECURITY.md rules 6, 9).
- Every trust-reducing signal carries `evidence_ref` pointing at a persisted
  evidence/finding record — never a free-text-only conclusion.
- Unknown enum values / new fields must be ignored, not fatal
  (API_CONTRACTS.md cross-cutting invariants).
- `schema_version` is an integer; producers emit `1`. A consumer that sees a
  higher major version must not assume field semantics.

## 2. `SecuritySession` — one observed mail connection

Canonical shape (JSON field names; Rust types in `kiwi-core::session`):

| field | type | notes |
|-------|------|-------|
| `schema_version` | u32 | always `1` |
| `session_id` | string | producer-assigned, unique per observation |
| `account_id` | string \| null | SecureMail account binding |
| `device_id` | string \| null | registered device binding |
| `protocol` | `"smtp" \| "imap" \| "pop3"` | |
| `server_host` | string | configured server name, not greeting strings |
| `server_port` | u16 | |
| `transport` | `"plaintext" \| "starttls" \| "tls"` | `starttls` = upgraded on cleartext port; `tls` = implicit |
| `tls_version` | `"ssl3" \| "tls1.0" \| "tls1.1" \| "tls1.2" \| "tls1.3" \| "unknown"` \| null | `null` when plaintext |
| `cipher_suite` | object \| null | `{iana_id: u16\|null, name: string, forward_secrecy: bool}` — observed facts only, no strength verdict |
| `key_exchange_group` | `"x25519" \| "secp256r1" \| "secp384r1" \| "secp521r1" \| "ffdhe2048" \| "ffdhe3072" \| "ffdhe4096" \| "static" \| "other:<name>" \| "unknown"` \| null | `static` = non-ephemeral kx, never forward-secret |
| `cert_chain` | object \| null | `{leaf: CertificateSummary\|null, presented_len: u8, validation: enum}` |
| `cert_chain.validation` | `"valid" \| "invalid" \| "untrusted" \| "expired" \| "hostname-mismatch" \| "unknown"` | as reported by NSS, no reinterpretation |
| `starttls_offered` | bool \| null | server advertised STARTTLS |
| `starttls_used` | bool | upgrade actually performed |
| `auth_mechanism` | `"none" \| "plain" \| "login" \| "cram-md5" \| "scram-sha-1" \| "scram-sha-256" \| "xoauth2" \| "oauthbearer" \| "ntlm" \| "gssapi" \| "client-cert" \| "other:<name>" \| "unknown"` | |
| `auth_succeeded` | bool \| null | `false` on observed failure; `null` if not attempted |
| `established_unix` | i64 | session establishment, seconds since epoch |
| `source` | `"thunderbird-hook" \| "forensic-pcap" \| "test-fixture"` | provenance — never guessed |

`CertificateSummary`: `{subject_dn, issuer_dn, serial_hex, not_before_unix,
not_after_unix, signature_algorithm, public_key_algorithm, public_key_bits,
sha256_fingerprint, is_self_signed}` — all strings/i64/u32/bool as named.

Derived fact (not a field): `has_forward_secrecy` = TLS 1.3, or
`cipher_suite.forward_secrecy`.

## 3. Trust evaluation — inputs and outputs

**Inputs** (to `TrustMachine::evaluate`):

1. `TrustSignal[]` — measurable indicators. Signal kinds:
   `plaintext-transport`, `starttls-downgrade-suspected`,
   `deprecated-tls-version`, `weak-cipher-suite`, `no-forward-secrecy`,
   `certificate-invalid`, `certificate-expired`, `certificate-untrusted`,
   `certificate-hostname-mismatch`, `certificate-unexpected-change`,
   `weak-auth-mechanism`, `repeated-auth-failure`, `new-device-unverified`,
   `remote-session-indicator`, `endpoint-integrity-failure`,
   `device-suspended`, `device-revoked`, `replay-detected`,
   `policy-violation`.
   Each signal: `{kind, severity: info|low|medium|high|critical,
   penalty: u32, evidence_ref: string}`.
   Sources: `TrustPolicy::session_signals()` (session-derived), device
   registry status (`device-suspended/revoked/new-device-unverified`),
   endpoint measurements, kiwi-forensics findings.
2. `TrustPolicy` — thresholds + hard-lock set + unlock requirements
   (see §5 defaults).

**Output** `TrustEvaluation`: `{state, score: u32 (0–100, 100 = clean),
signals, required_action}` where `required_action` ∈ `none | warn-user |
require-reauth | require-authenticator-unlock | block-access`.

`score = max(0, 100 − Σ penalties)` — deterministic, auditable, replayable.

## 4. Lock-state semantics

States: `Trusted → Degraded → Locked` (Rust `trust::TrustState`).

**What reduces trust** (any `TrustSignal`; score drops by summed penalties):

- transport/crypto indicators: plaintext, suspected STARTTLS stripping,
  deprecated TLS (< 1.2 or unknown), non-forward-secret suites, cert
  invalid/expired/untrusted/hostname-mismatch/unexpected-change, weak auth
  mechanism over cleartext, repeated auth failures;
- endpoint indicators: unverified new device, remote-session indicator,
  endpoint-integrity failure, suspended device.

**What locks** (sticky — entered regardless of score for hard-lock kinds,
or whenever `score < lock_threshold`):

- hard-lock signal kinds (default): `device-revoked`, `replay-detected`,
  `policy-violation`, `certificate-hostname-mismatch`, `certificate-invalid`;
- `score < policy.lock_threshold` (default 40);
- administrative `force_lock` (audited elevated action).

While `Locked`: no mailbox access, no credential use on the session —
`required_action` is `require-authenticator-unlock` (default policy) or
`block-access`. Locked **never** self-recovers: a clean evaluation leaves a
locked session locked.

**What unlocks**:

- When `policy.unlock_requires_authenticator` (default: true): a verified
  `ChallengeResponse` for event `unlock` (see §6). The trust engine must be
  passed the *result of verification*, never the raw response.
- When false: an authorized admin/re-auth path (audited).
- Post-unlock landing state: `Degraded` if adverse signals are still active,
  else `Trusted`. `Degraded → Trusted` auto-recovers once signals clear
  (`auto_recover_degraded`, default true).

## 5. `TrustPolicy` — defaults (kiwi-core `Default`)

| field | default |
|-------|---------|
| `degrade_threshold` | 80 |
| `lock_threshold` | 40 |
| `hard_lock` | device-revoked, replay-detected, policy-violation, cert-hostname-mismatch, cert-invalid |
| `min_tls_version` | tls1.2 |
| `unlock_requires_authenticator` | true |
| `auto_recover_degraded` | true |
| `challenge_ttl_secs` | 120 |
| `session_ttl_secs` | 43200 |

Org overrides arrive via kiwi-admin policy distribution (Phase 6 contract).

## 6. Challenge binding (unlock / pairing / recovery / elevated actions)

`ChallengeSpec` → `Challenge`: `{challenge_id, device_id, session_id, event,
nonce: 32B CSPRNG, issued_unix, expires_unix}`. Signed payload =
`canonical_bytes()`: length-prefixed fields —
`"kiwi-challenge-v1" | challenge_id | device_id | session_id | event_tag |
nonce | issued | expires`. Because the signature covers every bound element,
re-targeting a response to another device/session/event invalidates it.

`ChallengeResponse`: `{challenge_id, device_id, session_id, event,
signature}` — signature by the device's keystore-held private key over the
challenge's canonical bytes.

Verification order (`ChallengeBook::verify`): exists → unexpired →
unconsumed → binding fields match → signature valid → consume. Rules:

- Single-use: consumed challenges can never verify again (replay fails).
- Failed attempts do NOT consume (no DoS on legitimate retry); rate limiting
  is the caller's concern.
- Nonce reuse at issue time is rejected and treated as a `replay-detected`
  incident.
- Signature verification goes through the `SignatureVerifier` trait — no
  accept-all path exists in non-test code; Phase 4 supplies the
  Ed25519/ECDSA-P-256 implementation per `contracts/authenticator.md`.

## 7. Device + identity lifecycle (summary)

- Device: `pending → active → suspended → revoked`; `revoked` is terminal —
  the device id can never reactivate. `pending`/`suspended`/`revoked` feed
  `new-device-unverified`/`device-suspended`/`device-revoked` signals.
- Account session: `active → expired | revoked`; sessions are device-bound
  (`is_valid` requires matching `device_id` + unexpired); device revocation
  kills all its sessions (`revoke_all_for_device`).
- Credentials: never modeled here. Thunderbird/OS credential store owns
  them; `SecureMailAccount` carries identity, bound devices, and
  `RecoveryPolicy` only.

## 8. Versioning

- Additive fields → same major version; consumers ignore unknowns.
- Changed field semantics or removed fields → bump contract major version,
  record ADR, keep old readers working during transition.
