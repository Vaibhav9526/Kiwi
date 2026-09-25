# Pair IPC / kiwi-pair Implementation Gap Audit (T-235)

**Reviewer:** Agent 23 · **Date:** 2026-09-25 · **Snapshot:** `7522469` plus the current shared worktree
**Mode:** read-only implementation audit. No source, contract, task-ledger, or
master-findings file was changed.

## Scope and verdict

This audit compares the Lead-ratified pairing command contract in
`docs/contracts/ipc.md` §9d (`ipc.md:951-1328`) with the current
`kiwi-pair` engine and `kiwi-app/src-tauri` command layer. The supporting
engine contract (`docs/contracts/pair.md`) is used only where §9d delegates
engine/schema authority to it.

**Verdict: 0 of the 5 canonical §9d command handlers are implemented or
registered.** `kiwi-app` does not depend on `kiwi-pair`, does not own a
`PairEngine`, and has no pair command module or registration. Three existing
kiwi-core paths overlap §9d, but they use process-local state and are not the
ratified `kiwi-pair` integration:

- `kiwi_request_challenge` / `kiwi_submit_challenge` overlap
  `unlock_challenge`;
- `kiwi_list_devices` overlaps `device_list`;
- `kiwi_revoke_device` overlaps `device_revoke`.

`kiwi-pair` itself has substantial primitives (ticket issue/consume, Ed25519
verification, persistent device/challenge/nonce tables, fingerprints, and
terminal revocation), but the `pair_status` schema/API and the required atomic
ticket-claim/device-link transaction do not exist.

## Status legend

- **Implemented** — the requested behavior is present and test-backed.
- **Partial** — a useful primitive exists, but part of the requirement is absent.
- **Missing** — no callable/registered implementation exists.
- **Divergent** — a compatibility path exists, but it is not the ratified §9d
  command/backend and does not meet the complete contract.

## Canonical command matrix

| §9d command / requirement | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| `pair_begin({ deviceLabel })` | **Missing** | No handler, type, registration, or frontend path. `kiwi-app/src-tauri/Cargo.toml:16-55` has no `kiwi-pair` dependency; `AppState` owns only the kiwi-core registry/challenge book (`state.rs:484-542,672-703`); the Tauri registry ends without a pair command (`lib.rs:68-166`). The engine primitive `issue_pairing_ticket` and QR builder exist (`kiwi-pair/src/engine.rs:112-174`), but there is no backend-owned endpoint/key source or active-flow state. | Add one persisted `PairEngine`, trusted backend endpoint/desktop-key provisioning, active-flow state, the canonical view, and handler. Renderer fields must remain limited to `deviceLabel`. |
| `pair_status({ ticket })` | **Missing — blocking** | No command, lookup type, or non-mutating engine method. `PairStore` exposes only mutating `consume_ticket` (`kiwi-pair/src/store.rs:193-228`); `pairing_tickets` has no linked-device column (`store.rs:37-43`); `register_device` does not accept a ticket (`engine.rs:178-214`); `PairStore` exposes no transaction operation. Calling `consume_pairing_ticket` for polling would consume the bearer ticket and cannot produce the three required states. | Add a persistent read-only status API and schema link, then a single transaction for consume + device insert + ticket→device link. Add crash/race tests before the command ships. |
| `unlock_challenge({ deviceId })` | **Divergent** | Canonical name absent. The registered compatibility issue/submit path is exempt (`lib.rs:69-75`; `commands/system.rs:79-241`) and generates a boot-bound nonce/challenge, but it lets the renderer choose `event`, uses in-memory `ChallengeBook`, and does not call `PairEngine::issue_challenge` / `verify_response` (`system.rs:87-147,166-217`; `state.rs:492,682-683`). It also emits `nonceHex`, not §9d `nonceB64` (`types/system.rs:48-76`). | Keep the old names only as thin compatibility aliases. The canonical command fixes event `Unlock`, generates all other fields, delegates to the persistent engine, and returns the exact `PairChallengeView`. |
| `device_list({})` | **Divergent** | Canonical name absent. `kiwi_list_devices` is correctly gated (`commands/devices.rs:82-95`) but reads the process-local `DeviceRegistry` plus a persisted id-list sidecar (`devices.rs:88-95`; `state.rs:680-703`). `DeviceView` omits `fingerprint`, `keystoreRef`, and `revokedUnix` (`types/devices.rs:7-20`). `PairEngine` has list/fingerprint primitives (`engine.rs:244-254`), but store order is only `registered_unix` with no required `deviceId` tie-breaker (`store.rs:169-190`). | Delegate the canonical command to `PairEngine`, project the safe fields without `public_key`, add both fingerprints, and impose the contract's total ordering. |
| `device_revoke({ deviceId })` | **Divergent** | Canonical name absent. `kiwi_revoke_device` is gated and audits, then refreshes trust (`commands/devices.rs:99-128`), but it revokes the in-memory kiwi-core registry. A second revoke is not idempotent (`kiwi-core/src/device.rs:108-132`) and state disappears on restart. The `kiwi-pair` implementation is correctly terminal/idempotent (`kiwi-pair/src/engine.rs:216-230`) but unused. | Make the canonical handler an alias over `PairEngine::revoke_device`; audit both transition and idempotent retry; preserve the existing `SecurityStatusView` response and map errors per §9d.9. |

## Lock-gate enforcement

| Surface | Contract requirement | Current result | Status |
|---|---|---|---|
| `pair_begin` | Exempt only during a backend-owned active pairing flow; otherwise `locked` | No command and no flow state exist. | **Missing** |
| `pair_status` | Exempt only during that same backend-owned flow; otherwise `locked` | No command, ticket capability, or flow state exist. | **Missing** |
| `unlock_challenge` | Always exempt | `kiwi_request_challenge` and `kiwi_submit_challenge` are registered without `gate(...)` (`lib.rs:69-75`; `system.rs:79-241`). The compatibility posture is correct, but the canonical command is absent. | **Partial** |
| `device_list` | Gated | `kiwi_list_devices` calls `gate` before reading devices (`commands/devices.rs:82-95`). | **Partial / legacy match** |
| `device_revoke` | Gated | `kiwi_revoke_device` calls `gate` before mutation (`commands/devices.rs:99-105`). | **Partial / legacy match** |
| First-device trusted flow | Backend-owned flow, TLS/pin enforcement, TOFU evidence, and authenticator-only activation | No pairing transport, backend flow state, or pair DB ownership exists. The generic endpoint signal collector is not a pairing-channel implementation. | **Missing** |

No current renderer bypass exists because the canonical begin/status commands
are absent. Implementing them without backend-owned flow state would violate
§9d; adding new canonical device/challenge handlers as parallel independent
implementations would violate the single-path ruling at `ipc.md:953-958`.

## `pair_status` and ticket-claim blocker

The current engine cannot implement the ratified status contract safely:

- `issue_pairing_ticket` creates a 43-character base64url ticket with a
  300-second expiry (`engine.rs:112-130`).
- `consume_pairing_ticket` validates 8..=128 ASCII ticket characters, performs
  an atomic `UPDATE ... WHERE consumed=0 RETURNING`, and returns only the bound
  label (`engine.rs:132-145`; `store.rs:210-228`).
- The store has no read-only ticket lookup and no `device_id`/linked-device
  column (`store.rs:25-58,193-228`).
- `register_device` is an independent insert and accepts no ticket identifier
  (`engine.rs:178-214`; `store.rs:111-133`).
- There is no public transaction API in `PairStore`; the public surface consists
  of individual SQL operations (`store.rs:87-307`).

Calling the mutating consume method from a status poll would therefore destroy
the only state needed to distinguish `awaiting-phone`, `claimed`, and `expired`.
A cache in `kiwi-app` would create a second bearer-ticket store outside
`pair.db`, which the contract explicitly rejects. This is the primary blocking
item for T-235.

## Engine invariant matrix

| Requirement | Status | Evidence and detail |
|---|---|---|
| Persistent `pair.db` store | **Implemented** | `PairEngine::open` and four SQLite tables are present (`engine.rs:92-104`; `store.rs:25-107`). The app never opens this engine. |
| Ticket issue and exact 43-char/300-second behavior | **Implemented** | `engine.rs:112-130`; exact-shape test at `pair_tests.rs:138-204`. |
| Ticket single-use consume | **Partial** | Atomic update is present, but expiry is checked only after the row is marked consumed (`store.rs:213-227`), unknown and already-consumed both return `InvalidTicket`, and `PairError::TicketConsumed` is never constructed (`lib.rs:52-56`). This is adequate for a mutating consume API but not for §9d.3 status semantics. |
| Read-only status and ticket-device link | **Missing** | No linked column/API and no transaction. |
| Atomic consume + device row + link | **Missing** | No ticket-aware registration or transaction operation. A crash can leave a consumed ticket with no linked device. |
| Ed25519-only 32-byte device registration | **Implemented in `kiwi-pair`** | `engine.rs:178-214`; Ed25519 verifier is fail-closed (`crypto.rs:16-38`). The legacy Tauri registration path is not equivalent: it accepts the reserved ECDSA/RSA key-size ranges and only rejects them later at submit (`commands/devices.rs:27-66`; `types/devices.rs:54-68`). |
| Device list and fingerprint primitives | **Implemented in `kiwi-pair`** | `engine.rs:244-254`; fingerprint vector and lookup tests at `pair_tests.rs:97-105,255-265`. No safe IPC projection is wired. |
| Deterministic device ordering | **Partial** | Store orders only by `registered_unix` (`store.rs:169-190`); §9d requires `deviceId` as tie-breaker. |
| Device list bound/pagination | **Missing** | `list_devices` returns every row; §9d.11 explicitly keeps this an implementation gate. |
| Terminal/idempotent engine revocation | **Implemented in `kiwi-pair`** | `engine.rs:216-230`; test asserts first `revoked_unix` is preserved (`pair_tests.rs:234-253`). |
| Revoked device cannot issue/verify challenges | **Implemented in `kiwi-pair`** | `engine.rs:279-290,322-328`; test at `pair_tests.rs:438-453`. |
| Challenge issue bounds and status gates | **Partial** | ID/session/TTL/label checks exist (`engine.rs:73-80,264-290`). The `(Active, _)` arm also permits `DevicePairing`, although §9d says pairing is for pending devices (`engine.rs:283-290`). |
| Canonical challenge bytes and binding | **Implemented** | The engine reconstructs the kiwi-core challenge and verifies the same canonical bytes (`engine.rs:304-309,344-366`); fixed layout test at `pair_tests.rs:107-134`. |
| Failed verification does not consume | **Implemented** | Consume occurs after binding and signature verification (`engine.rs:330-369`); tests cover failed binding/signature and replay (`pair_tests.rs:381-436`). |
| Atomic challenge consumption | **Divergent** | `consume_challenge` returns a `bool`, but `verify_response` discards it with `?` and then activates pairing devices (`engine.rs:364-373`; `store.rs:280-286`). Two engine instances can both report successful verification. |
| Persistent nonce/challenge replay ledger | **Partial** | Nonce and challenge rows persist, with 1-hour/4096 nonce retention and 4096 challenge cap (`store.rs:18-23,44-57,247-253,288-307`). There is no disk-reopen regression test, and nonce/challenge insert is not one transaction. |
| No renderer-selected challenge fields | **Divergent in Tauri** | The canonical command is absent. The legacy request accepts renderer-selected `event` (`commands/system.rs:79-94`), whereas §9d fixes `Unlock` and backend-generates the other fields. |
| `PairError` → IPC mapping | **Missing** | No Tauri dependency or conversion exists. The legacy challenge path maps expired to `expired`, not the ratified `challenge-expired` (`error.rs:79-95`). The legacy revoke path returns generic `device-error` on repeat revocation (`commands/devices.rs:113-121`). |

## `nonceB64` wire drift

**Status: divergent.**

The ratified wire requires one field, `nonceB64`, containing canonical padded
RFC 4648 standard Base64 that decodes to exactly 32 bytes
(`ipc.md:1090-1118`). Current code emits a different field and encoding:

- Rust `ChallengeView` declares `nonce_hex` and serializes lowercase hex
  (`kiwi-app/src-tauri/src/types/system.rs:48-76`).
- The TypeScript interface declares `nonceB64`
  (`kiwi-app/src/kiwi.ts:798-807`), so the declared client shape and runtime
  Rust shape disagree.
- No `PairChallengeView` or `kiwi_unlock_challenge` handler exists.
- The existing canonical-bytes Base64 is unrelated to the nonce field; it does
  not compensate for the missing nonce encoding.

This is the existing IPC-3/AUTH-3 migration gate. It must be fixed together
with the canonical `unlock_challenge` handler rather than adding another
independent path.

## Bounds and validation

§9d.8 is binding at `ipc.md:1220-1240`. Current status is mixed:

| Bound | Status | Evidence |
|---|---|---|
| `deviceLabel`: 1..=128 UTF-8 bytes, no ASCII controls | **Implemented in engine** | `check_field` and issue-ticket call (`engine.rs:73-80,121`). The legacy Tauri `bounded` helper permits empty strings and tabs, and the compatibility registration uses it (`commands/mod.rs:94-105`; `commands/devices.rs:31-33`). |
| `deviceId` / generated `challengeId`: 1..=128 bytes | **Partial** | Engine register/issue checks (`engine.rs:189-190,270-272`). `verify_response` does not bound response strings (`engine.rs:316-342`), and the legacy submit path has separate core bounds. |
| Generated `sessionId`: 1..=256 bytes | **Implemented in engine issue** | `engine.rs:39,272`; no canonical IPC projection exists. |
| `keystoreRef`: optional 1..=256 bytes | **Implemented in engine only** | `engine.rs:191-193`; legacy Tauri registration copies the field without an engine or IPC bound (`commands/devices.rs:47-54`). |
| Backend `desktopEndpoint`: 1..=256 bytes | **Partial** | Engine checks printable length (`engine.rs:41,156`), but no trusted endpoint source/transport provisioning exists. |
| Ticket input: 8..=128 ASCII `[A-Za-z0-9_-]` | **Implemented** | `engine.rs:134-145`; current §9d.8 wording is inclusive, so the older PAIR-7 off-by-one concern is not a defect against the ratified contract. |
| Challenge TTL: 1..=300 seconds, fixed 120 at IPC | **Implemented in engine primitive** | `engine.rs:32-35,273-278`; canonical IPC command is missing. |
| Device public key: exactly 32 bytes, Ed25519 only | **Implemented in `kiwi-pair`; divergent legacy path** | `engine.rs:194-203`; legacy Tauri accepts reserved algorithm ranges at registration (`commands/devices.rs:31-44`). |
| Desktop key text: `ed25519:` + canonical padded standard Base64, 32 bytes | **Divergent** | Engine checks only the prefix (`engine.rs:158-162`); the required canonical decode/re-encode check is absent because no IPC layer exists. |
| Resource bounds | **Missing** | Ticket issuance has no per-profile cap/retention policy; device listing is unbounded (`store.rs:193-208,288-307`; `engine.rs:244-245`). These are explicit §9d.11 gates. |

## Revocation and trust behavior

The `kiwi-pair` primitive is correct for its own database: revocation is
terminal, idempotent, preserves the original `revoked_unix`, and blocks
challenge issue/verification (`engine.rs:216-230,279-290,322-328`). The Tauri
path is not equivalent:

1. `kiwi_revoke_device` mutates the process-local `DeviceRegistry` rather than
   `pair.db` (`commands/devices.rs:108-128`; `state.rs:680-684`).
2. The kiwi-core transition rejects a second revoke rather than returning the
   ratified idempotent success (`kiwi-core/src/device.rs:108-132`).
3. The app has no `From<PairError>` mapping, so it cannot emit the fixed
   `device-revoked` or `device-exists` boundary codes (§9d.9).
4. The legacy path does audit `device-revoked`, but the audit occurs after the
   mutation and before trust refresh (`commands/devices.rs:113-127`).
5. A direct Tauri audit test is absent.

## Security findings

| ID | Severity | Finding | Evidence | Required action |
|---|---|---|---|---|
| **T235-01** | **High** | `pair_status` and the atomic ticket claim are impossible with the current engine/schema. | `ipc.md:1072-1088,1313-1314`; `store.rs:37-43,210-228`; `engine.rs:132-145,178-214`. | Add a persistent status API, linked-device schema field, and one transaction for consume/register/link. Add crash and race tests. |
| **T235-02** | **High** | The ratified IPC surface has no `kiwi-pair` integration: Tauri does not depend on, instantiate, or call `PairEngine`; it maintains a second in-memory device/challenge truth source. | `kiwi-app/src-tauri/Cargo.toml:16-55`; `state.rs:484-542,672-703`; `commands/system.rs:196-225`. | Make `PairEngine` the single persistent device/challenge authority and keep old IPC names as thin aliases only. |
| **T235-03** | **High** | Challenge consumption is not atomically enforced across engine instances. The engine ignores the false result from `consume_challenge`, allowing two valid verifications to report success. | `engine.rs:364-373`; `store.rs:280-286`; contract explicitly calls this out at `ipc.md:1291-1293,1315-1317`. | Treat false as `AlreadyConsumed` before activation; preferably make consume plus pairing activation one transaction. |
| **T235-04** | **Medium** | The five canonical commands and the four required §9d lock classifications are absent, so the flow-scoped begin/status exemption cannot be enforced. | `ipc.md:951-992,1193-1210`; `lib.rs:68-166`; `commands/mod.rs:13-27`. | Add the canonical registry and a backend-owned pairing-flow state; do not add renderer-controlled bypasses. |
| **T235-05** | **Medium** | `pair_begin` has no trusted endpoint/key source, canonical desktop-key validation, or transport provisioning. | `engine.rs:147-174`; `state.rs:484-542`; `ipc.md:1006-1012,1025-1032,1206-1218`. | Provision endpoint/key from backend identity state and implement the trusted first-device flow; enforce the canonical Base64/32-byte check at IPC. |
| **T235-06** | **Medium** | The legacy revoke path is non-persistent, non-idempotent, and has a different error vocabulary from the ratified contract. | `commands/devices.rs:108-128`; `kiwi-core/src/device.rs:108-132`; `error.rs:79-95`. | Delegate to `PairEngine::revoke_device` and map/audit the ratified outcomes. |
| **T235-07** | **Medium** | The runtime challenge wire emits `nonceHex` while the TypeScript interface/contract require `nonceB64`; the coordinated migration is still pending. | `types/system.rs:48-76`; `kiwi.ts:798-807`; `ipc.md:1090-1118`. | Replace the Rust field and frontend expectation in the canonical handler change. |
| **T235-08** | **Medium** | Resource bounds required before shipping are absent: ticket issuance has no cap and device listing is unbounded. | `store.rs:193-208,288-307`; `engine.rs:244-245`; `ipc.md:1321-1322`. | Add per-profile ticket limits/retention and bounded/paginated device listing. |
| **T235-09** | **Low** | The engine permits a `device-pairing` challenge for an active device because `(Active, _)` accepts every event. | `engine.rs:279-290`; `ipc.md:1120-1122`; existing PAIR-1. | Restrict pairing issue to pending devices and add a matrix test. |
| **T235-10** | **Low** | `verify_response` does not apply the §9d.8 string bounds; a missing linked device is reported as `UnknownChallenge`, and the method comment reverses the actual verification order. | `engine.rs:311-342`; `store.rs:44-53`; `ipc.md:1220-1240`. | Bound response fields, preserve `DeviceNotFound` semantics, and correct the comment. |
| **T235-11** | **Low** | Nonce recording precedes challenge insertion without a transaction; a failed challenge insert can burn a nonce. | `engine.rs:291-303`; existing PAIR-8. | Make nonce and challenge insertion transactional or roll the nonce back on insert failure. |

## Existing PAIR finding disposition

The focused audit confirms the existing register rows as follows:

- **PAIR-1 remains open:** active-device pairing issue gate is still present.
- **PAIR-2 remains open:** `TicketConsumed` and `pairing-ticket-consumed` are
  unreachable; unknown and consumed tickets collapse to `InvalidTicket`.
- **PAIR-3 is documentation-only:** the method comment reverses the documented
  order, while the implementation order is correct.
- **PAIR-4 is low reachability:** missing device maps to `UnknownChallenge`,
  though foreign keys make that difficult for normal persisted rows.
- **PAIR-5 is confirmed and security-relevant:** the atomic consume boolean is
  discarded, enabling a multi-instance success race.
- **PAIR-6 is partially resolved by §9d.8:** the current table explicitly
  defines the principal bounds, but response-string/root bounds remain absent.
- **PAIR-7 is not a current defect:** §9d.8 explicitly says `8..=128`, matching
  the engine.
- **PAIR-8 remains open:** nonce-before-insert can burn a nonce on failure.
- **PAIR-9 remains open:** suspension transition policy is broader/ambiguous
  relative to the device lifecycle wording.
- **PAIR-I remains informational:** the public `PairStore` and row types form a
  broad parallel API surface.

## Test coverage assessment

The current 11 `kiwi-pair` tests cover fixed crypto/fingerprint vectors,
canonical challenge bytes, ticket issue/consume/expiry, QR shape, device
registration/revocation, issue status gates, a full pairing-to-unlock flow,
binding/signature failure, replay, and revoked-device verification. The
following critical cases have no regression test:

- disk-backed reopen and replay persistence across processes;
- two `PairEngine` instances racing one challenge consume;
- atomic ticket consume + device insert + link, including crash recovery;
- ticket status state transitions and unknown/consumed non-oracle behavior;
- canonical desktop-key Base64/length rejection;
- 4096-row caps, ticket issuance limits, and equal-timestamp device ordering;
- all five Tauri handlers, `PairError` mapping, wire projections, and the
  flow-scoped lock matrix.

## Required implementation order

1. **Engine/schema gate:** add a persistent read-only ticket status API, a
   linked-device column, and one SQLite transaction for ticket claim +
   registration + link.
2. **Replay correctness:** check the atomic challenge-consume boolean and add
   disk-reopen and multi-engine race tests.
3. **Tauri integration:** add the `kiwi-pair` dependency, own one persisted
   `PairEngine` in `AppState`, and make the five canonical handlers the only
   behavior path; retain old names only as aliases.
4. **Wire migration:** implement `nonceB64`, `PairChallengeView`,
   `PairDeviceView`, and the normative `PairError` mapping, then update the
   frontend types/wrappers in the same change.
5. **Pairing security flow:** provision a trusted endpoint/key source and
   backend-owned active-flow state; implement TLS/pin checks and the first-device
   TOFU path before exposing flow-scoped exemptions.
6. **Bounds and ordering:** add canonical input validation, desktop-key
   canonicality, device-list ordering/bounds, and ticket resource limits.

## T-235 conclusion

The pair engine is not a blank implementation: its cryptographic and basic
persistence primitives are real and mostly aligned with the supporting
contract. The ratified IPC integration, however, is absent. The two decisive
blockers are the missing `pair_status`/atomic-claim design and the Tauri
second authority in `kiwi-core` rather than `kiwi-pair`. Until those are fixed,
the compatibility challenge/device handlers are useful local scaffolding but
not a compliant implementation of `ipc.md` §9d.
