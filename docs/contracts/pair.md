# Contract — kiwi-pair (desktop pairing engine)

**Version:** 2 (T-269) · **Owner:** Agent 10 (T-174) · **Consumers:**
kiwi-app `src-tauri` IPC layer — the canonical §9d commands
(`pair_begin`, `pair_status`, `unlock_challenge`, `device_list`,
`device_revoke`) plus the `kiwi_register_device` / `kiwi_list_devices` /
`kiwi_revoke_device` / `kiwi_request_challenge` / `kiwi_submit_challenge`
compatibility aliases — Lead orchestration · **Implements:** the desktop
side of `contracts/authenticator.md` · **Depends on:** `kiwi-core`
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
- **One authority.** There is exactly one `PairEngine` per profile and
  `pair.db` is the only device/challenge/ticket store. IPC layers must
  not keep an in-memory registry/book shadow.

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
        -> Result<String /*device_label*/>;      // transports only — NOT polling
    fn ticket_status(&self, ticket: &str, now: i64)
        -> Result<TicketStatus>;                  // read-only; never consumes
    fn claim_ticket_and_register(&mut self, ticket: &str,
        device_id: &str, algorithm: KeyAlgorithm, public_key: &[u8],
        keystore_ref: Option<&str>, now: i64) -> Result<()>;
    fn qr_payload_json(ticket: &PairingTicket, desktop_endpoint: &str,
        device_label: &str, desktop_public_key_b64: &str,
        issued_unix: i64) -> Result<String>;     // §3.1 exact JSON

    // -- devices --
    fn register_device(&mut self, device_id: &str, label: &str,
        algorithm: KeyAlgorithm, public_key: &[u8],
        keystore_ref: Option<&str>, now: i64) -> Result<()>;  // → pending
    fn revoke_device(&mut self, device_id: &str, now: i64) -> Result<()>;
    fn suspend_device(&mut self, device_id: &str, now: i64) -> Result<()>;
    fn list_devices(&self, limit: u32) -> Result<Vec<DeviceRow>>;
    fn device_fingerprint(&self, device_id: &str) -> Result<Option<String>>;

    // -- challenges --
    fn issue_challenge(&mut self, spec: ChallengeSpec, now: i64,
        ttl_secs: u64) -> Result<Challenge>;
    fn verify_response(&mut self, resp: &ChallengeResponse, now: i64)
        -> Result<()>;
}
```

`TicketStatus` is `{ state, device_id, expires_unix }` where `state ∈
{ AwaitingPhone, Claimed, Expired }`: `AwaitingPhone` = unlinked +
unexpired, `Claimed` = `device_id` link present (device may be any status
— claim outcome, not trust), `Expired` = unlinked + `now >= expires_unix`.
Unknown, malformed, or consumed-but-unlinked tickets return
`InvalidTicket` — polling is never a live-ticket oracle and `pair_status`
responses never echo the ticket.

## Behavioural rules

- **Ticket:** base64url of 32 CSPRNG bytes (43 chars, `[A-Za-z0-9_-]`),
  single-use, expires `now + QR_TTL_SECS (300)`. Live (unclaimed,
  unexpired) tickets are capped at 64 per profile — issuance beyond the
  cap fails `InvalidTicket` rather than growing the table unboundedly.
  Expired *unlinked* rows are pruned; claimed rows are retained so a
  `Claimed` verdict survives ticket expiry.
- **claim_ticket_and_register** is the pairing-transport seam: consume +
  device-row insert (`pending`) + `pairing_tickets.device_id` link commit
  in ONE SQLite transaction. Partial consumption without a linked
  registration is impossible. The ticket's own `device_label` column is
  the device label — the claimant cannot rename it.
- **register_device** → `pending`. Ed25519 + 32-byte key enforced;
  everything else fails closed. Duplicate normalized labels
  (whitespace-collapsed, case-folded) on live (non-revoked) devices fail
  `DeviceLabelConflict`; a revoked device's label may be re-registered.
- **list_devices** is bounded (`limit`, clamped ≥1 by callers) and
  totally ordered `registered_unix ASC, device_id ASC` — deterministic
  across engines and repeated calls.
- **issue_challenge status gate:** `device-pairing` challenges are only
  issuable to `pending` devices; all other events require `active`;
  `revoked` devices get nothing. `ttl_secs` bounded `1..=300`. Nonce +
  challenge row commit in one transaction — a failed challenge insert
  never burns a nonce.
- **verify_response order** (contract §6.2 / `ChallengeBook::verify`):
  challenge exists → linked device exists → device not revoked →
  unexpired → binding (device/session/event) match → Ed25519 over
  canonical bytes → atomic consume. Failed verification never consumes.
  The consume's atomic boolean is authoritative: a zero-row `UPDATE` is
  `AlreadyConsumed`, closing the multi-instance race — two engines cannot
  both verify one challenge. A successful `device-pairing` verification
  activates the device in the SAME transaction as the consume.
- **revoke_device:** terminal (`revoked` + `revoked_unix` set), persisted
  — revocation survives process restart. Revoked devices fail
  `verify_response` (`DeviceRevoked`) and `issue_challenge`. Idempotent —
  revoking twice returns `Ok` and preserves the original `revoked_unix`.
  Callers MUST audit `device-revoked` (elevated action, rule 11).
- **Replay ledger:** `nonces` table, 1-hour retention window + 4096-row
  cap; `challenges` table capped at 4096 (oldest pruned).
- **Fingerprint:** `device_fingerprint(pk)` = uppercase hex of
  `SHA-256(pk)[..16]`, dash-grouped 4s — display-only, never a trust
  input. Fixed vector: `device_fingerprint([0;32])` =
  `6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20`.

## Persistence schema (`pair.db`, `user_version` = 2)

```sql
devices(device_id PK, label, algorithm, public_key BLOB, keystore_ref,
        status, registered_unix, last_seen_unix, revoked_unix);
pairing_tickets(ticket PK, device_label, issued_unix, expires_unix,
                consumed, device_id NULL→devices);   -- v2: device_id link
challenges(challenge_id PK, device_id FK→devices, session_id, event,
           nonce BLOB, issued_unix, expires_unix, consumed);
nonces(nonce BLOB PK, issued_unix);
```

v1→v2 migration adds `pairing_tickets.device_id` (nullable) on open;
legacy consumed-but-unlinked rows read as `InvalidTicket` by
`ticket_status`.

## Errors

`PairError`: `Store(rusqlite)`, `Io`, `Challenge(ChallengeError)`
(re-exported kiwi-core names: `UnknownChallenge | Expired |
AlreadyConsumed | BindingMismatch | InvalidSignature`),
`UnsupportedAlgorithm`, `BadKeyLength`, `InvalidField{field,reason}`,
`InvalidTicket`, `TicketConsumed`, `TicketExpired`, `DeviceExists`,
`DeviceNotFound`, `DeviceRevoked`, `DeviceNotActive`,
`DeviceLabelConflict`, `ReplayDetected`, `Entropy`. Error names mirror the
contract — IPC/audit layers map them per ipc.md §9d.9
(`DeviceLabelConflict` → `conflict`).

## Out of scope (per authenticator.md)

- The pairing *transport* TLS/wss ruling — Phase 4 open item §10.2. The
  IPC layer provisions the trusted endpoint + desktop key and calls
  `claim_ticket_and_register`; a bounded dev-flagged plaintext claim
  listener now exists in `kiwi-app` (`pairing_listen.rs`, ipc.md §9d.12)
  — still not in this crate, and not the ratified production transport.
- Deny-response handling — denial is advisory UX, never consumes.
- Keystore-wrapped-seed fallback — gated on Lead + Agent 6 sign-off.
