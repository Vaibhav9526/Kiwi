# Contract — kiwi-pair (desktop pairing engine)

**Version:** 1 (draft) · **Owner:** Agent 10 (T-174) · **Consumers:**
kiwi-app `src-tauri` IPC layer (`kiwi_register_device`,
`kiwi_list_devices`, `kiwi_revoke_device`, challenge issue/verify),
Lead orchestration · **Implements:** the desktop side of
`contracts/authenticator.md` · **Depends on:** `kiwi-core`
(`challenge`, `device` semantics are authoritative there)

`authenticator.md` owns the wire protocol and phone-side obligations.
This document owns the **desktop engine API + persistence schema** —
the part that differs from it: `authenticator.md` describes messages;
`kiwi-pair` is the Rust surface that produces/consumes them.

## Invariants (inherited — binding)

- Ed25519 only (RFC 8032). `ecdsa-p256`/`rsa3072` registrations are
  rejected `UnsupportedAlgorithm` — fail closed until verifiers land.
- No private key material ever exists in this crate — the phone's
  keystore signs; the desktop only verifies (`Ed25519Verifier`).
  `DeviceSigner` exists for deterministic tests / future mobile parity
  vectors only.
- Canonical challenge bytes are kiwi-core's
  `Challenge::canonical_bytes()` — never re-encoded here.
- Nonces are caller-supplied CSPRNG bytes (`os_nonce()` wraps
  `getrandom`); the engine never generates pseudo-randomness. A repeat
  nonce at issue → `ReplayDetected` (audit `replay-detected`).
- All replay state is **persistent** — a consumed challenge or seen
  nonce replays-fails even across process restarts.
- `PairEngine::open` paths and all string fields are length-bounded.

## API surface

```rust
struct PairEngine { /* wraps PairStore (SQLite) */ }

impl PairEngine {
    fn open(root: &Path) -> Result<Self>;        // <root>/pair.db
    fn open_memory() -> Result<Self>;            // tests

    // -- pairing tickets (QR flow, authenticator.md §3) --
    fn issue_pairing_ticket(&mut self, device_label: &str,
        rand: &[u8;32] /*CSPRNG*/, now: i64) -> Result<PairingTicket>;
    fn consume_pairing_ticket(&mut self, ticket: &str, now: i64)
        -> Result<String /*device_label*/>;
    fn qr_payload_json(ticket: &PairingTicket, desktop_endpoint: &str,
        device_label: &str, desktop_public_key_b64: &str,
        issued_unix: i64) -> Result<String>;     // §3.1 exact JSON

    // -- devices --
    fn register_device(&mut self, device_id: &str, label: &str,
        algorithm: KeyAlgorithm, public_key: &[u8],
        keystore_ref: Option<&str>, now: i64) -> Result<()>;  // → pending
    fn revoke_device(&mut self, device_id: &str, now: i64) -> Result<()>;
    fn suspend_device(&mut self, device_id: &str, now: i64) -> Result<()>;
    fn list_devices(&self) -> Result<Vec<DeviceRow>>;
    fn device_fingerprint(&self, device_id: &str) -> Result<Option<String>>;

    // -- challenges --
    fn issue_challenge(&mut self, spec: ChallengeSpec, now: i64,
        ttl_secs: u64) -> Result<Challenge>;
    fn verify_response(&mut self, resp: &ChallengeResponse, now: i64)
        -> Result<()>;
}
```

## Behavioural rules

- **Ticket:** base64url of 32 CSPRNG bytes (43 chars, `[A-Za-z0-9_-]`),
  single-use via atomic `UPDATE ... WHERE consumed=0 RETURNING`, expires
  `now + QR_TTL_SECS (300)`. Consume validates charset/length before any
  store touch. Re-issue of the same bytes → store PK collision error.
- **register_device** → `pending`. Ed25519 + 32-byte key enforced;
  everything else fails closed.
- **issue_challenge status gate:** `device-pairing` challenges are only
  issuable to `pending` devices; all other events require `active`;
  `revoked` devices get nothing. `ttl_secs` bounded `1..=300`.
- **verify_response order** (contract §6.2 / `ChallengeBook::verify`):
  challenge exists → device not revoked → unexpired → unconsumed →
  binding (device/session/event) match → Ed25519 over canonical bytes →
  atomic consume. Failed verification never consumes. A successful
  `device-pairing` verification auto-activates the device.
- **revoke_device:** terminal (`revoked` + `revoked_unix` set); revoked
  devices fail `verify_response` (`DeviceRevoked`) and `issue_challenge`.
  Idempotent — revoking twice returns `Ok` so operator retries are safe.
  Callers MUST audit `device-revoked` (elevated action, rule 11).
- **Replay ledger:** `nonces` table, 1-hour retention window + 4096-row
  cap; `challenges` table capped at 4096 (oldest pruned).
- **Fingerprint:** `device_fingerprint(pk)` = uppercase hex of
  `SHA-256(pk)[..16]`, dash-grouped 4s — display-only, never a trust
  input. Fixed vector: `device_fingerprint([0;32])` =
  `6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20`.

## Persistence schema (`pair.db`, `user_version` = 1)

```sql
devices(device_id PK, label, algorithm, public_key BLOB, keystore_ref,
        status, registered_unix, last_seen_unix, revoked_unix);
pairing_tickets(ticket PK, device_label, issued_unix, expires_unix, consumed);
challenges(challenge_id PK, device_id FK→devices, session_id, event,
           nonce BLOB, issued_unix, expires_unix, consumed);
nonces(nonce BLOB PK, issued_unix);
```

## Errors

`PairError`: `Store(rusqlite)`, `Io`, `Challenge(ChallengeError)`
(re-exported kiwi-core names: `UnknownChallenge | Expired |
AlreadyConsumed | BindingMismatch | InvalidSignature`),
`UnsupportedAlgorithm`, `BadKeyLength`, `InvalidField{field,reason}`,
`InvalidTicket`, `TicketConsumed`, `TicketExpired`, `DeviceExists`,
`DeviceNotFound`, `DeviceRevoked`, `DeviceNotActive`, `ReplayDetected`,
`Entropy`. Error names mirror the contract — IPC/audit layers should map
them verbatim.

## Out of scope (per authenticator.md)

- The pairing *transport* (LAN ws/TCP) — Phase 4 open item §10.2.
- Deny-response handling — denial is advisory UX, never consumes.
- Keystore-wrapped-seed fallback — gated on Lead + Agent 6 sign-off.
- `kiwi-app` IPC wiring (T-120) — this crate is the engine behind it.
