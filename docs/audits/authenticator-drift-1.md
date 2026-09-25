# Mobile Authenticator Drift Audit 1 (T-270)

**Reviewer:** Agent 23 · **Date:** 2026-09-25 · **Snapshot:** `9f13f47` plus the current shared worktree
**Mode:** read-only implementation audit. `mobile/` and implementation files were inspected, not edited. This report and the Agent 23 status entry are the only T-270 writes.

## Scope and verdict

This audit enumerates `docs/contracts/authenticator.md` against the current React Native client, its deterministic protocol modules and tests, the `kiwi-core` challenge/device primitives, the current `kiwi-pair` worktree, and the relevant Tauri receiver. The concurrently edited QR-encoder files under `mobile/src/qr/` and `mobile/tests/qr/` are outside the protocol finding set; the clean `mobile/src/protocol/qr.ts` parser is in scope.

**Verdict: the mobile client is an honestly labelled, fail-closed scaffold, not a production authenticator.** The deterministic QR/challenge primitives, canonical byte encoder, event tags, replay helper, and queue helper have substantial test-backed coverage. However, the required pairing channel, native keystore, durable identity/replay/queue state, desktop-compatible challenge handoff, explicit deny receiver, and complete approval transaction are absent or divergent.

The current default cannot authorize or deliver anything: `UnavailableKeystore` rejects signing, and `OfflineTransport` always returns `offline`. This prevents the listed gaps from becoming a current unauthorized-approval path, but it does not satisfy the contract's production obligations. T-269 is also changing `kiwi-pair`; its current primitive improvements are recorded below, while claims requiring Tauri integration or new regression tests remain unverified.

### T-269 snapshot caveat

The current shared worktree is mid-migration. T-269 has added the `kiwi-pair` dependency, a persisted `AppState::pair`, backend channel provisioning, and `PairError` mapping (`kiwi-app/src-tauri/Cargo.toml:16-25`; `src/state.rs:511-587,734-890`; `src/error.rs:115-161`). The canonical command handlers are not registered or callable, while the old device/challenge handlers still reference the removed in-memory fields. Those transitional sources are therefore classified as **in progress**, not as a completed Tauri integration.

## Contract decisions required before implementation

| Decision | Contract conflict or omission | Current consequence |
|---|---|---|
| Desktop key encoding | The QR example says “64-char base64,” but a 32-byte Ed25519 key is 44 characters in canonical padded standard Base64 (`authenticator.md:79,92`; `ipc.md:1146-1151`). | Mobile and PairEngine cannot know whether length or decoded bytes is authoritative. Ratify the 32-byte/44-character rule already present in `ipc.md`. |
| TLS pin identity | The channel is required to pin `desktop_public_key_b64`, but the contract does not state whether that raw Ed25519 key is the TLS certificate key, an SPKI pin, or an application signature exchanged inside a separately pinned TLS channel (`authenticator.md:92,119-123`). | A transport can be implemented with the wrong trust semantics. Define the certificate/channel design and exact peer comparison before mobile code. |
| Transport scheme | The binding text forbids plaintext and recommends `wss://`, while the exact QR example uses `ws://`; Agent 6's `wss://` recommendation remains described as awaiting Lead ratification (`authenticator.md:77,119-128,359-360`). | Both current parsers accept plaintext. Ratify the `ipc.md` `wss://` form and amend this draft contract. |
| Challenge wire casing | `authenticator.md` uses snake_case `nonce_b64`; ratified `ipc.md` §9d uses camelCase `nonceB64` and explicitly calls it canonical (`authenticator.md:152-164`; `ipc.md:1211-1232`). | Tauri can be internally camelCase while the pairing transport must explicitly adapt to the authenticator wire. The contract needs an adapter boundary, not two accepted nonce fields. |
| Session example | The challenge/response examples use `x-tx` for `unlock`, while the normative text reserves `x-tx:` for recovery/elevated actions and uses `boot-` for unlock/pairing (`authenticator.md:154-174,227-238`). | Tests currently encode the contradictory example. Correct the examples before enforcing event/session forms. |
| Desktop approval context | Approval requires a trusted desktop label, transaction ID, and issue/expiry time, but `ChallengeData` has no desktop-label field and the desktop Tauri view sends no trusted display identity (`authenticator.md:219-225`; `mobile/src/protocol/types.ts:24-34`; `kiwi-app/src-tauri/src/types/system.rs:48-76`). | The phone cannot display all required context from the current wire. Define the trusted source/field. |
| Timeout audit | Section 6.3 says timeout creates no audit row, while §7 says a dropped deny may be handled because the desktop audits the timeout (`authenticator.md:263-270,286-288`). | Deny/drop behavior and required audit semantics are contradictory. Ratify one rule before implementing delivery. |
| Secret wording | The QR is called free of secrets, but the single-use ticket is a bearer capability and `ipc.md` explicitly labels it a **BEARER SECRET** (`authenticator.md:45-46,89,95-97`; `ipc.md:1122,1155-1160`). | The contract must explicitly say no private/secret key material, while treating the ticket as sensitive bearer data with strict retention/logging rules. |

## Status legend

- **Implemented** — the behavior is present and backed by current tests.
- **Partial** — a useful primitive exists, but part of the requirement is absent.
- **Missing** — no callable implementation exists.
- **Divergent** — code exists, but its wire, safety, ordering, or semantics differ from the contract.
- **Deferred** — intentionally scaffold-only and fail-closed; valid for today, still a Phase-4 release gate.

Severity is **H** for a trust, identity, replay, or authorization failure; **M** for a material security, interop, or state-integrity gap; **L** for bounded contract, diagnostics, or test drift.

## Pairing and QR matrix

| Contract obligation | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Deterministic pairing/approval; no AI | **Implemented** | QR/challenge parsing and canonical encoding are pure; replay/queue clocks are injectable. No AI or network path exists under the reviewed protocol modules (`protocol/qr.ts:24-87`, `protocol/canonical.ts:45-100`, `protocol/replay.ts:16-70`, `protocol/queue.ts:22-130`). | Preserve. |
| QR version and type | **Implemented** | `v` must be safe integer `1`, and `type` must equal `kiwi-pairing`; wrong values reject (`protocol/qr.ts:36-39`; `tests/protocol/qr.test.ts:49-56`). | Preserve. |
| QR size, wrong types, unknown fields | **Implemented** | Raw QR is capped at 1024 characters, known fields are bounded, JSON must be an object, and unknown fields are not copied (`protocol/qr.ts:24-75`; `tests/protocol/qr.test.ts:44-74`). | Preserve; use a byte cap when the live scanner adapter lands. |
| Ticket shape `8..128` and `[A-Za-z0-9_-]` | **Implemented** | The mobile parser and current `PairEngine` use the same inclusive bounds and charset (`protocol/qr.ts:41,60-63`; `kiwi-pair/src/engine.rs:193-203`). | Preserve. |
| Ticket single-use and successful-use semantics | **Divergent** | Mobile has no pairing transport. The current `consume_pairing_ticket` atomically marks the ticket consumed before checking expiry, so an expired attempt burns it (`kiwi-pair/src/engine.rs:182-190`; `kiwi-pair/src/store.rs:309-326`). The new atomic claim path is safer but has no test/caller yet. | Deprecate the split consume/register API; make the tested transaction the only production path. |
| Compact desktop QR producer | **Implemented** | `qr_payload_json` emits the fixed field set with `v=1`, ticket, endpoint, label, key, and timestamps (`kiwi-pair/src/engine.rs:257-284`). | Preserve, with stricter key/endpoint validation. |
| QR validity at most five minutes | **Partial** | Mobile checks ordering/current expiry but not `expires_unix - issued_unix <= 300`; it even permits equal timestamps (`protocol/qr.ts:50-58`). The current pair producer correctly mints `issued + 300` (`kiwi-pair/src/engine.rs:30-35,160-179`). Tests cover current expiry but not a longer window (`tests/protocol/qr.test.ts:58-61`). | Require `1 <= expires-issued <= 300`; add long-window and zero-window tests. This confirms AUTH-10. |
| `desktop_endpoint` is a bounded LAN endpoint | **Partial** | Both sides enforce only 1..256 characters/bytes, not URL syntax, host scope, or the approved scheme (`protocol/qr.ts:42`; `kiwi-pair/src/engine.rs:266`). | Parse structurally; define allowed LAN host forms, required port/path, and forbidden credentials/fragments. |
| TLS-only pairing channel | **Divergent** | The contract forbids plaintext at `authenticator.md:119-121` but its example uses `ws://` at `:77`; mobile accepts it and the pair producer accepts it (`protocol/qr.ts:42`; `kiwi-pair/src/engine.rs:266`; `tests/protocol/qr.test.ts:18`). | Ratify one `wss://` form, correct the contract example, then reject every other scheme on both boundaries. This confirms AUTH-5. |
| Desktop Ed25519 key is canonical Base64 for exactly 32 bytes | **Divergent** | Mobile and `PairEngine` check only the `ed25519:` prefix and outer length. `ed25519:` and `ed25519:AAAA` pass (`protocol/qr.ts:44-48`; `kiwi-pair/src/engine.rs:268-272`; `pair_tests.rs:180-203`). | Strip the prefix, require canonical padded standard Base64, decode exactly 32 bytes, and re-encode for equality. This confirms AUTH-4. |
| Desktop key and TLS peer identity are the same trust pin | **Deferred** | The field is parsed and retained but no transport compares it with a live peer. The contract does not define how a raw Ed25519 identity key maps to a TLS certificate/SPKI pin (`authenticator.md:92,119-123`; `protocol/types.ts:12-22`). | Make the contract define the pin representation and native comparison semantics before implementing the channel. |
| Device label is bounded and safely displayed | **Partial** | Input is length-bounded, but `safeDeviceLabel` removes only CR/LF/tab; other controls and bidi controls remain (`protocol/qr.ts:43,83-87`; `tests/protocol/qr.test.ts:77-86`). | Strip C0/C1/DEL and bidi controls; truncate without splitting graphemes; keep a distinct display DTO. |
| Raw QR is never logged | **Implemented for current code** | No logging call exists in the reviewed mobile source, and parser errors are fixed/bounded for QR input. The parser retains `raw` in its result but current callers do not log it (`protocol/qr.ts:24-32,65-75`). | Keep ticket-bearing raw text out of serializable state and future telemetry. |
| Pairing hello/registered reply wire | **Missing** | No pairing message types or transport methods exist. The only transport interface is response `postResponse` (`protocol/types.ts:11-47`; `transport/transport.ts:10-23`). | Add strict bounded hello/reply/activation messages and the one-shot channel. |
| Server-issued pending device identity and activation | **Missing / scaffold-UI divergent** | After the expected keystore failure, the screen fabricates `dev-scaffold-<ticket-prefix>`, calls `onPaired`, and navigates to approvals. No key, registration, or activation occurred (`screens/PairingScreen.tsx:45-74`; `App.tsx:25-28,55-60`). | Keep a distinct “QR validated / pairing unavailable” state. Create identity only after desktop registration and successful pairing verification. |

## Challenge, response, and replay matrix

| Contract obligation | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Canonical bytes match `kiwi-core` | **Implemented** | Mobile emits the same domain, three u32be-prefixed IDs, event byte, raw nonce, and i64be timestamps as kiwi-core (`protocol/canonical.ts:22-63`; `kiwi-core/src/challenge.rs:53-75`). Structural and mutation tests cover every bound field (`tests/protocol/canonical.test.ts:15-64`). | Add one kiwi-core-generated golden vector consumed by both languages. |
| Event names and tags are identical | **Implemented** | Mobile and kiwi-core both map unlock/pairing/recovery/elevated to `0x01..0x04`; unknown events reject (`protocol/event.ts:9-30`; `protocol/canonical.ts:77-82`; `tests/protocol/canonical.test.ts:66-73`). | Preserve with the shared golden vector. |
| Strict challenge parse; exact nonce; unknown fields ignored | **Implemented for decoded objects** | Required fields, types, bounds, event, Base64 syntax, exact 32-byte nonce, and time ordering are checked; unknown fields are omitted (`protocol/canonical.ts:70-100`; `tests/protocol/canonical.test.ts:91-118`). | Preserve. |
| Entire challenge input is bounded before parsing | **Missing** | `JSON.parse(raw)` receives an unbounded TextInput value before `parseChallengeData` validates known fields (`PendingApprovalsScreen.tsx:41-43,106-116`). QR has a raw cap; challenge JSON does not. | Add a fixed total UTF-8 byte cap before JSON parsing and cap the input widget. |
| Session form matches event (`boot-` vs `x-tx:`) | **Divergent** | The parser accepts any nonempty 1..128 string and never mints one, but it does not enforce the event-specific forms (`protocol/canonical.ts:74-89,111-121`). The “valid” fixture uses `x-tx` with `unlock`, contradicting `authenticator.md:169-174` (`tests/helpers/protocol.ts:16-26`). | Correct the examples/fixture and validate `boot-` for unlock/pairing and `x-tx:` for recovery/elevated. This confirms and broadens AUTH-16. |
| Challenge TTL policy | **Partial** | Mobile accepts any positive lifetime. The contract calls 120 seconds the default; current `PairEngine` defaults to 120 and caps at 300 (`protocol/canonical.ts:87-89`; `kiwi-pair/src/engine.rs:32-35,379-393`). | Clarify policy override versus hard ceiling; enforce the agreed ceiling on mobile. |
| Phone uses its own current clock | **Divergent** | Replay receives a `FixedClock(Date.now())` captured at component mount. Expiry and queue throttling therefore never advance while the screen stays mounted (`PendingApprovalsScreen.tsx:33-38`; `protocol/replay.ts:64-70`; `protocol/queue.ts:97-103`). | Use a live advancing clock and check expiry at review and again on every tap. This confirms AUTH-7. |
| Gate order is parse → clock → binding → replay → intent | **Divergent** | Review runs parse → replay → conditional binding → expiry; neither action revalidates clock, binding, or replay (`PendingApprovalsScreen.tsx:41-65,67-96`). | Put the ordered gates in one service and bind its result to the exact immutable challenge shown. |
| Device binding is mandatory | **Divergent** | Binding is skipped when identity is `null`, while the Approvals tab remains reachable and actions remain enabled (`App.tsx:42-60`; `PendingApprovalsScreen.tsx:48-51,118-136`). The current identity is only a scaffold value. | Fail closed without a real registered identity; recheck at tap. This confirms AUTH-6. |
| Stale pending state cannot be actioned | **Divergent** | A rejected review returns without clearing the previous `pending`; after reviewing A, a rejected B can leave buttons bound to A (`PendingApprovalsScreen.tsx:41-65`). | Clear selection before review and bind buttons to the reviewed immutable snapshot. |
| Replay ledger records one answer and caps at 256 | **Implemented as primitive** | First answer wins and capacity is 256 (`protocol/replay.ts:20-61`; `tests/protocol/replay.test.ts:9-24,46-54`). | Preserve. |
| Replay ledger prunes at one hour | **Partial** | `prune(maxAgeSecs)` exists and its test passes, but there is no one-hour constant and no production caller. A full ledger stays permanently full (`protocol/replay.ts:30-54`; `tests/protocol/replay.test.ts:35-44`). | Define the retention constant and prune before capacity checks/review. This confirms AUTH-12. |
| Expired challenge is recorded locally | **Missing** | The ledger type supports `expired`, but the screen only prints “expired on arrival” and does not record or clear pending (`PendingApprovalsScreen.tsx:52-55`; `protocol/replay.ts:10-14`). | Record `expired`, clear pending, and suppress re-prompt. This confirms AUTH-11. |
| Replay/identity/queue state survives navigation/restart | **Missing** | All three objects are component-local. Switching tabs unmounts the approval screen and loses answers and queued outcomes (`App.tsx:55-60`; `PendingApprovalsScreen.tsx:33-38`). | Add an app-scoped, integrity-protected, bounded persistence layer before Phase 4. |
| Response carries explicit decision | **Partial** | The builder always emits `approve` or `deny`, and deny has an empty signature. The exported type makes `decision` optional and documents absence as approve (`protocol/canonical.ts:129-148`; `protocol/types.ts:37-47`). | Make `decision` required and validate the runtime value before branching. |
| Approve signature is exactly 64 bytes | **Implemented as a response builder rule** | The builder decodes and requires exactly 64 bytes; deny is empty (`protocol/canonical.ts:141-147`; `tests/protocol/canonical.test.ts:121-134`). | Preserve and add strict canonical-Base64 validation if exposed outside the trusted signer path. |
| Signature exists only after all gates and signs canonical bytes | **Missing / divergent scaffold** | Approve calls `sign('no-key', new Uint8Array(0))`; it never builds canonical bytes or queues a response (`PendingApprovalsScreen.tsx:80-96`). The unavailable signer currently fails closed. | Gate first, decode nonce, canonicalize, sign with the persisted native handle, validate the signature, record the answer, and durably enqueue as one transaction. |
| User sees event, desktop label, transaction ID, issue/expiry | **Missing** | UI shows only event phrase and raw expiry (`PendingApprovalsScreen.tsx:56-60`). `ChallengeData` has no desktop-label field, and the paired label is the phone label, not a trusted desktop identity. | Add a trusted pairing/display source and show challenge/session ID plus local issue/expiry times. This confirms AUTH-13 and exposes its contract-data gap. |

## Queue and transport matrix

| Contract obligation | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Approve commits at signing and queues the exact signed response | **Missing integration** | Queue insertion exists, but no production signing path ever enqueues approve. A caller supplies challenge, response, and decision independently (`protocol/queue.ts:66-78`; `PendingApprovalsScreen.tsx:80-96`). | Admit only a branded response produced by the approval transaction and validate all echoed fields. |
| FIFO | **Partial** | Map insertion order and `tick` preserve order, but the test enqueues only one item and public `deliver(id)` can bypass the head (`protocol/queue.ts:51-53,84-124`; `tests/protocol/queue.test.ts:20-37`). | Make retry head-only; test at least three distinct challenges. |
| One outcome per challenge ID | **Divergent** | Dedupe applies only while an item is queued. Successful delivery removes it, allowing later re-admission; separate replay and queue maps do not share durable answer state (`protocol/queue.ts:66-78,104-109`). | Couple queue admission to the durable replay ledger and retain bounded terminal tombstones if needed. |
| Backlog default 64 and truly bounded | **Partial** | Default item cap is 64, but options accept arbitrary values and `lastAttempt` entries remain after delivered items are removed (`protocol/queue.ts:34-37,48-69,102-107`). | Validate/clamp options, bound metadata, and delete throttle state on terminal delivery. |
| Retry throttle is at least 10 seconds | **Partial** | Positive default and gate exist, but the mounted clock is frozen and option values are not validated (`protocol/queue.ts:48-63,97-103`; `tests/protocol/queue.test.ts:49-61`). | Use a live monotonic clock and fixed safe option bounds. |
| Signed offline approve remains queued | **Implemented as an in-memory primitive** | Offline results retain the item and a test asserts it (`protocol/queue.ts:103-109`; `tests/protocol/queue.test.ts:39-47`). No durable storage or scheduler exists. | Persist before first send and recover atomically on startup. |
| Deny is best-effort, never indefinite | **Divergent** | Deny is inserted into the same approval queue and offline items are retained; the screen never calls `deliver`/`tick`, and no TTL/drop rule exists (`protocol/queue.ts:66-78,103-130`; `PendingApprovalsScreen.tsx:67-78,139`). | Separate deny from approval retry or permit one bounded best-effort attempt, then drop it. This confirms and narrows AUTH-8. |
| Transport is a replaceable `ChallengeTransport` | **Partial** | The interface exists but queue duplicates structurally identical transport/result types instead of importing the authority (`transport/transport.ts:10-17`; `protocol/queue.ts:14-20`). | Reuse the canonical interface and typed delivery outcome. |
| Live transport and retry scheduler | **Deferred** | The only implementation is permanently offline, and production UI never calls delivery (`transport/transport.ts:19-23`; `PendingApprovalsScreen.tsx:35-38,139`). | Implement only after crypto, endpoint, pin, deny, audit, and durable-state gates are resolved. |
| Transport rejection is normalized | **Partial** | Interface promises non-throwing implementations, but `deliver` has no catch around `postResponse` (`transport/transport.ts:14-16`; `protocol/queue.ts:102-109`). | Normalize timeout/rejection to bounded retryable and terminal-rejected outcomes. |

## Keystore and private-key matrix

| Contract obligation | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Key lifecycle interface never exports private material | **Implemented** | `DeviceKeystore` exposes generate/sign/delete/has and a public-only handle (`keystore/keystore.ts:28-45`). | Preserve. |
| Production keystore is native and fails closed | **Deferred** | The app wires `UnavailableKeystore`; generation, signing, and deletion all throw `not-implemented` (`keystore/keystore.ts:47-64`; both screens). | Keep disabled until Lead + Agent 6 sign-off and platform-native review. |
| Native Ed25519 key and wrapped-seed fallback | **Missing** | No Android/iOS module exists; the fallback is an explicitly open contract item (`authenticator.md:32-40,191-205,352-365`). | Implement only the ratified path; never place an unwrapped seed at rest. |
| `keystore_ref` and public key are validated | **Partial** | The interface documents 32 bytes and 256 characters but performs no runtime validation; the test HSM accepts any alias and prefixes it (`keystore/keystore.ts:29-35`; `keystore/soft-hsm.ts:33-52`). | Validate exact public-key bytes and the native reference before registration. |
| Key deletion on user request or desktop revocation | **Missing** | Interface has `deleteKey`, default throws, and no production caller or revocation notification exists (`keystore/keystore.ts:42-43,58-60`). | Add authenticated local deletion and revocation reconciliation that destroys the key before accepting future work. |
| Soft HSM is test-only and cannot authorize | **Divergent documentation** | No production source imports it, but the contract/test map calls it “UNIMPLEMENTED-style” and says signing requires explicit test key material. The class is constructible, deterministically generates fake bytes, and signs 64 filler bytes (`keystore/soft-hsm.ts:23-82`; `tests/keystore/soft-hsm.test.ts:19-49`). | Move it under test support or add a build-time production exclusion. Keep AUTH-9, but describe impact as accidental reachability: fake signatures cannot pass Ed25519 verification. |
| Private material never crosses the intended boundary | **Implemented for current production graph** | Production imports only `UnavailableKeystore`; fake seed material is confined to a non-app-imported test helper. | Preserve and enforce with an import/architecture test. |

## Desktop and `kiwi-pair` receiver matrix

| Contract obligation | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Desktop challenge handoff is mobile-compatible | **Divergent** | Rust `ChallengeView` serializes camelCase plus `nonceHex` and has no `schema_version`; the mobile parser requires snake_case `nonce_b64` and version 1 (`types/system.rs:48-76`; `protocol/canonical.ts:70-86`). The desktop TypeScript interface expects `nonceB64`, so Rust and TS also disagree (`kiwi-app/src/kiwi.ts:946-955`). | Emit one ratified shape and map it explicitly; never make mobile infer a nonce from canonical bytes. This is IPC-3/AUTH-3/T235-07. |
| Desktop receiver preserves deny without verification | **Missing** | Tauri input has no decision and desktop always calls signature verification. A mobile deny becomes an empty signature/invalid-signature path (`types/system.rs:80-90`; `commands/system.rs:166-207`). | Add a separate explicit deny branch that audits and does not consume. AUTH-2 remains open. |
| Every approval/failure/denial/pairing outcome is audited | **Divergent** | Tauri audits successful `challenge-verified` only. Verification failures propagate before audit; pairing has no `device-paired`; no `challenge-denied` or `challenge-verification-failed` writer exists (`commands/system.rs:203-240`). | Audit every required outcome, including each `ChallengeError`, with the ratified action names. AUTH-1 remains open. |
| Registration rejects unsupported algorithms | **Divergent in Tauri** | Tauri accepts ECDSA/RSA names and key-size ranges at registration, then rejects unsupported algorithms only at submit (`commands/devices.rs:27-66`; `commands/system.rs:182-194`). `PairEngine::claim_ticket_and_register` correctly allows Ed25519 only (`kiwi-pair/src/engine.rs:225-254`). | Make the canonical receiver delegate to `PairEngine`; retain no parallel registration policy. |
| Core failed verification does not consume | **Implemented** | kiwi-core checks existence, expiry, consumed state, binding, and signature before setting consumed (`kiwi-core/src/challenge.rs:154-185`). | Preserve and audit externally. |
| Persistent pair store and atomic ticket claim | **Implemented in current T-269 worktree; untested** | Schema v2 links ticket to device; `claim_ticket_and_register` performs consume + insert + link in one transaction (`kiwi-pair/src/store.rs:18-166,329-420`). Current 11 tests do not exercise it. | Add transaction rollback, duplicate-claim, expiry, migration, and disk-reopen tests before calling T-235-01 fixed. |
| Pair challenge nonce + insert is atomic | **Implemented in current T-269 worktree; untested** | `record_nonce_and_insert_challenge` commits both or neither (`kiwi-pair/src/engine.rs:412-434`; `store.rs:448-497`). | Add failed-insert/replay rollback tests before closing PAIR-8. |
| Active-device re-pair is rejected | **Implemented in current T-269 worktree; untested** | Device-pairing is allowed only for `Pending` (`kiwi-pair/src/engine.rs:398-411`). | Add a status/event matrix test before closing PAIR-1. |
| Challenge consume + pairing activation is atomic | **Implemented in current T-269 worktree; untested** | The store combines both writes and the engine treats a false consume result as `AlreadyConsumed` (`store.rs:531-557`; `engine.rs:507-520`). | Add a two-engine race test before closing PAIR-5/T235-03. |
| Tauri uses `kiwi-pair` as the sole authority | **Missing in current snapshot** | Tauri has no `PairEngine` call and still owns process-local `DeviceRegistry`/`ChallengeBook`; device IDs alone are persisted in a sidecar (`commands/devices.rs:47-79,88-95`; `commands/system.rs:87-147,196-207`). | Complete T-269 integration and retire the parallel path. |
| Local key destruction follows desktop revocation | **Missing** | `PairEngine::revoke_device` is terminal/idempotent, but no phone-facing revocation or deletion path is connected (`kiwi-pair/src/engine.rs:329-342`; mobile has no native key or identity store). | Add authenticated revocation reconciliation and destructive local cleanup. |

## Security and drift findings

| ID | Severity | Finding | Evidence | Required action |
|---|---|---|---|---|
| **T270-01** | **H** | There is no production pairing/approval path: no pairing channel, native key, live challenge handoff, durable identity, or canonical deny/audit path. | `transport/transport.ts:14-23`; `keystore/keystore.ts:47-64`; `App.tsx:55-64`; `commands/system.rs:166-240`. | Keep fail-closed; complete the signed Phase-4 work only after all gates below and the required crypto review. |
| **T270-02** | **H** | The desktop and mobile challenge/response wires are incompatible at nonce, schema version, and decision boundaries. | `types/system.rs:48-90`; `protocol/canonical.ts:70-99`; `protocol/types.ts:24-47`; `kiwi-app/src/kiwi.ts:946-955`. | Ratify one wire and add a typed adapter; explicitly branch deny. Covers AUTH-2/AUTH-3. |
| **T270-03** | **M** | QR trust fields are prefix/length checks only: malformed desktop keys, plaintext endpoints, and long-lived windows pass. | `protocol/qr.ts:41-58`; `kiwi-pair/src/engine.rs:257-284`; `tests/protocol/qr.test.ts:18,58-69`. | Enforce secure endpoint, exact canonical key bytes, and 300-second maximum on both sides. |
| **T270-04** | **M** | The approval shell does not implement the normative decision transaction: binding can be skipped, clocks freeze, stale pending can be actioned, and taps do not re-gate. | `PendingApprovalsScreen.tsx:33-96`; `App.tsx:42-60`. | Centralize all gates and revalidate the exact displayed challenge on every action. |
| **T270-05** | **M** | Local identity, replay, and queue state is component-scoped and non-durable; prune is not wired and deny retention is unbounded. | `PendingApprovalsScreen.tsx:33-38,67-78,139`; `protocol/replay.ts:30-54`; `protocol/queue.ts:51-130`. | Add bounded integrity-protected persistence and lifecycle-owned state. |
| **T270-06** | **M** | Challenge input has no total size cap and parse errors can echo unbounded attacker-controlled schema text. | `PendingApprovalsScreen.tsx:41-43,61-64,106-116`; `protocol/canonical.ts:70-74`. | Bound raw UTF-8 bytes before parse and use fixed bounded error codes/messages. Extends AUTH-14. |
| **T270-07** | **M** | Session IDs are not validated by event; the canonical test fixture uses the reserved transaction form for unlock. | `protocol/canonical.ts:74-89`; `tests/helpers/protocol.ts:16-26`; `authenticator.md:167-174`. | Correct examples and enforce the event/session grammar. Extends AUTH-16. |
| **T270-08** | **M** | The queue trusts caller-supplied response/challenge/decision relationships, stores mutable references, and permits re-admission after delivery. | `protocol/queue.ts:26-32,66-87,104-107`. | Validate/copy/freeze entries and couple admission to durable replay state. |
| **T270-09** | **M** | The canonical module depends on Node's global `Buffer`; Node types make typecheck pass, but no RN Buffer dependency/polyfill or Hermes-host proof exists. | `protocol/canonical.ts:27-32,57-61,103-108`; `tsconfig.core.json:2-5`; `package.json:15-27`; `index.js:1-5`. | Use RN-safe byte/Base64 primitives or an approved polyfill; add a device-host smoke test. |
| **T270-10** | **M** | Current `PairEngine` transaction improvements are not exercised by tests or wired into Tauri, so T-235 high rows cannot yet be closed. | `kiwi-pair/src/store.rs:329-420,448-557`; `kiwi-pair/tests/pair_tests.rs:1-454`; `commands/system.rs:87-240`. | Add migration/rollback/race/disk-reopen tests and complete T-269 single-authority wiring. |
| **T270-11** | **L** | Soft HSM is functional non-crypto fixture code, not an unimplemented fail-closed signer; current production does not import it. | `keystore/soft-hsm.ts:23-82`; `tests/keystore/soft-hsm.test.ts:19-49`. | Keep the existing AUTH-9 row open as accidental-reachability/documentation drift, not a presently usable authorization path. |

## Existing AUTH finding disposition

This audit confirms the existing register rows against the current snapshot:

- **AUTH-1 remains open:** success, failure, deny, and pairing outcomes are not audited under the required actions.
- **AUTH-2 remains open:** mobile can construct an explicit deny, but Tauri has no decision field and routes it to signature verification.
- **AUTH-3 remains open:** the active runtime handoff uses `nonceHex`, while the mobile contract parser requires `nonce_b64`; the Rust and desktop TypeScript views also disagree.
- **AUTH-4 remains open:** desktop-key validation is prefix/length only on mobile and in `PairEngine`.
- **AUTH-5 remains open:** plaintext endpoints pass both mobile parsing and pair QR generation; the contract's own example conflicts with its TLS rule.
- **AUTH-6 remains open:** identity-null binding is skipped and action-time revalidation is absent.
- **AUTH-7 remains open:** the production approval screen mounts a frozen clock.
- **AUTH-8 remains open and is narrowed:** the definite defect is indefinite deny retention; retaining expired approvals until the desktop decides `Expired` is correct under `authenticator.md:289-292`.
- **AUTH-9 remains open with impact clarification:** the fake HSM is reachable from production source but not from the current app graph and cannot produce a valid Ed25519 signature.
- **AUTH-10, AUTH-11, and AUTH-12 remain open:** no five-minute parser maximum, expired recording, or production prune wiring.
- **AUTH-13 remains open:** desktop label/session/issue context is absent; the contract also lacks a trustworthy desktop-label source in the challenge shape.
- **AUTH-14 remains open and is broadened:** schema text is echoed, and the whole challenge input lacks a pre-parse cap.
- **AUTH-15 remains a wording ambiguity:** the user-visible `displayName` is correct while the internal registered name is `kiwi-mobile`.
- **AUTH-16 remains open and is broadened:** parser enforcement and fixtures both violate the event/session-form rule.
- **AUTH-I remains open:** pairing channel, native keystore, durable state, live transport, and local key destruction are absent as expected Phase-4 gates.

## Existing PAIR/T-235 disposition

The T-269 worktree materially changes the T-235 snapshot, but this audit does not mark canonical register rows fixed:

- **PAIR-1 / T235-09:** implementation now restricts device-pairing to pending devices; the current 11 tests do not cover active-device rejection.
- **PAIR-2:** the preferred claim transaction returns `TicketConsumed`; unknown and legacy-consumed semantics still differ. No production caller uses the transaction yet.
- **PAIR-3:** the verify comment still reverses the first implementation checks; behavior is not the defect.
- **PAIR-4:** missing linked devices now map to `DeviceNotFound` in the current worktree; untested.
- **PAIR-5 / T235-03:** consume result is now checked and activation is transactional; add a two-engine race test before closure.
- **PAIR-6:** response IDs/session now have primitive bounds; root/resource concerns remain outside this audit.
- **PAIR-7:** not a defect; the engine and current §9d wording use inclusive `8..=128`.
- **PAIR-8:** nonce and challenge insertion are now transactional; add rollback coverage.
- **T235-01:** ticket status/link/schema/transaction primitives now exist, but there are no current regression tests for claim, status, migration, rollback, or disk reopen.
- **T235-02:** still open in the active runtime—Tauri has not adopted `PairEngine`.
- **T235-04..08:** remain open until the canonical Tauri commands, endpoint/key validation, wire migration, audit/deny mapping, and resource integration land.

## Test coverage assessment

The current focused mobile suite is **5 files / 32 tests** and passes. It covers QR basic parsing, canonical layout/tags, replay helpers, queue mechanics, and test-HSM behavior. It does **not** cover:

- malformed/wrong-length/noncanonical desktop keys, endpoint scheme/LAN validation, or QR windows over 300 seconds;
- session-form rules, total challenge-size limits, event/session bounds, or a shared kiwi-core golden vector;
- live clock progression, identity-null rejection, stale pending, action-time revalidation, expired recording, automatic prune, or restart/remount;
- actual canonical signing, deny receiver/audit behavior, queue response/challenge consistency, finite deny retention, transport errors, scheduler wiring, or durable recovery;
- an Android/iOS native-host build or keystore lifecycle;
- current T-269 ticket claim/status/migration/rollback, nonce transaction rollback, or multi-engine challenge-consume race.

The current `kiwi-pair` suite still defines 11 tests. It covers the RFC 8032 vector, fixed canonical layout, legacy ticket lifecycle, QR shape, registration/revocation, issue gates, full pairing-to-unlock, replay, and revoked-device rejection. It does not yet cover the new T-269 schema and transaction surface.

## Required implementation order

1. **Ratify contract details:** one `wss://` endpoint form; TLS pin representation; event/session grammar; exact key/field bounds; desktop-label source; bounded challenge error/input rules; mandatory response decision.
2. **Close the wire blocker:** make Tauri and mobile exchange one exact challenge/response shape, including `schema_version`, nonce encoding, and a separate audited non-consuming deny path.
3. **Complete T-269:** test and integrate `PairEngine` as the single persistent device/challenge authority; retire the process-local parallel path.
4. **Harden QR trust validation:** exact canonical desktop key bytes, approved secure endpoint/LAN form, five-minute maximum, safe label rendering, and no bearer-ticket retention in display state.
5. **Build the single approval transaction:** live clock, real identity binding, durable replay reservation, exact displayed snapshot, canonicalization, native signing, response validation, and durable queue admission.
6. **Add durable lifecycle state:** persisted paired identity, replay retention/prune, immutable queue, bounded metadata, restart recovery, foreground/background retry, and truthful delivery outcomes.
7. **Implement gated key lifecycle:** native Android/iOS key generation/signing/deletion, revocation-triggered destruction, and the separately approved wrapped-seed fallback.
8. **Add security tests and host proof:** core-generated vectors, adversarial parsers, screen/transport tests, RN/Hermes smoke coverage, PairEngine migration/race/disk tests, and exact audit-row tests.

## T-270 conclusion

The mobile scaffold has credible deterministic building blocks, but only a subset of the contract is implemented. QR/challenge primitives should not be mistaken for an end-to-end authenticator. The decisive gaps are a compatible desktop wire, a single fail-closed approval transaction, exact QR trust validation, durable replay/queue/identity state, explicit deny and audit semantics, native key lifecycle, and verified integration of the current T-269 `PairEngine` work. Until those are resolved and the Lead + Agent 6 crypto gate is satisfied, Phase 4 must remain disabled.
