# Mobile Authenticator Drift Audit 1 (T-270)

**Reviewer:** Agent 23 · **Date:** 2026-09-25 · **Snapshot:** `f424a04` plus the current shared worktree
**Mode:** read-only implementation audit of `mobile/`, `kiwi-core`, current `kiwi-pair`/Tauri primitives, and the existing audit register. No implementation or contract file was changed. This report and the Agent 23 status entry are the only T-270 writes.

## Scope and verdict

This audit enumerates `docs/contracts/authenticator.md` against the React Native client, its pure protocol modules, UI flow, keystore/transport seams, tests, the authoritative kiwi-core challenge/device semantics, and the current `kiwi-pair` worktree. The concurrently edited QR-encoder files under `mobile/src/qr/` and `mobile/tests/qr/` are not used to attribute authenticator findings.

**Verdict: the mobile client remains an honestly labelled, fail-closed scaffold.** Its canonical byte encoder, event tags, strict known-field parsing, exact nonce length, replay helper, and queue helper are useful and test-backed. It is not an end-to-end authenticator: pairing is pasted QR plus scaffold-only state, the platform signer and live transport do not exist, identity/replay/queue state is not durable, approval gates are incomplete, and the desktop wire/deny/audit contract is not integrated end to end.

The default path cannot currently authorize: `UnavailableKeystore` rejects signing and `OfflineTransport` always returns `offline`. This prevents a present mobile unauthorized-approval exploit. It does not satisfy Phase-4 requirements or the contract's Lead + Agent 6 crypto sign-off gate.

### Concurrent T-269 caveat

T-269 remains active in the shared worktree. Its current source has moved beyond a primitive-only draft: it persists `PairEngine` in `AppState`, provisions backend-owned endpoint/key material, registers all five canonical Tauri commands, delegates legacy aliases to the same engine, emits `nonceB64`, and adds schema-v2 ticket status/claim plus challenge transaction/race tests. It remains uncommitted; the trusted first-flow opener and pairing-channel claim handler are absent; rustfmt fails; and the full Tauri test build is red. T-270 therefore records the current source as **in progress**, not complete, and does not modify the master findings register.

## Status legend

- **Implemented** — behavior exists and has focused test evidence.
- **Partial** — a useful primitive exists, but the obligation is incomplete.
- **Missing** — no callable implementation exists.
- **Divergent** — code exists with unsafe, stale, or incompatible semantics.
- **Release gate** — intentionally absent Phase-4 work that must stay disabled.

Severity: **H** trust/authorization/security failure; **M** material security, state, or interoperability defect; **L** bounded contract or test-quality drift.

## Contract decisions required before implementation

| Decision | Current contract conflict or omission | Consequence |
|---|---|---|
| Desktop-key encoding | The QR example says `64-char base64`, while a 32-byte Ed25519 key is 44 characters in canonical padded standard Base64 (`authenticator.md:79,92`; `ipc.md:1146-1151`). | Keep the exact 32-byte/44-character rule authoritative; correct the example. |
| TLS pin identity | The QR carries a desktop Ed25519 public key and calls it the TLS pin, but the contract does not define whether it is the certificate key, an SPKI pin, or an application identity authenticated inside TLS (`authenticator.md:92,119-123`). | Define the exact peer comparison before transport implementation. |
| Pairing scheme | Plaintext is forbidden, yet the exact example uses `ws://`; the preferred `wss://` decision is still described as awaiting Lead ratification (`authenticator.md:77,119-128,359-360`). | Mobile, PairEngine, and Tauri provisioning currently accept plaintext; ratify one endpoint grammar and correct the contract. |
| Challenge casing/version | `authenticator.md` requires snake_case `nonce_b64` plus `schema_version`; ratified `ipc.md` uses camelCase `nonceB64` and omits `schema_version` (`authenticator.md:152-164`; `ipc.md:1211-1232`). | Define a transport adapter; do not create dual nonce meanings in one payload. |
| Session form | Examples use `x-tx:` with `unlock`, while normative text assigns `boot-…` to unlock/pairing and `x-tx:` to recovery/elevated action (`authenticator.md:154-174,227-238`). | Current fixtures encode the contradiction; correct examples before enforcing parser rules. |
| Approval context | The user must see desktop label, transaction ID, and issue/expiry, but `ChallengeData` has no desktop-label field and the desktop view does not supply trusted display identity (`authenticator.md:219-225`; `mobile/src/protocol/types.ts:24-34`; `kiwi-app/src-tauri/src/types/system.rs:48-64`). | Required approval context is not wire-defined. |
| Timeout audit | Section 6.3 says timeout creates no row; section 7 says a dropped deny may be handled because desktop audits timeout (`authenticator.md:263-270,286-288`). | Ratify one deny/timeout rule. |
| QR secrecy wording | The QR is described as containing no secrets, but the single-use ticket is bearer material (`authenticator.md:45-46,89,95-97`; `ipc.md:1122,1155-1160`). | State “no private/secret key material” and define ticket retention/logging rules. |

## Pairing, QR, and keystore matrix

| Contract obligation | Status | Current evidence | Required resolution |
|---|---|---|---|
| Deterministic protocol; no AI in pairing/approval | **Implemented** | Protocol modules are pure or clock-injected; no AI or network path was found (`mobile/src/protocol/canonical.ts:45-148`; `replay.ts:16-70`; `queue.ts:22-130`). | Preserve. |
| QR version/type, raw cap, known fields, unknown-field rejection | **Implemented** | Raw input is capped at 1024 characters, `v=1`, `type=kiwi-pairing`, known fields are type/length checked, and unknown fields are dropped (`mobile/src/protocol/qr.ts:24-75`; `tests/protocol/qr.test.ts:31-75`). | Preserve. |
| Ticket charset and inclusive `8..128` length | **Implemented** | Mobile and PairEngine enforce `[A-Za-z0-9_-]` and 8..128 (`protocol/qr.ts:41,60-63`; `kiwi-pair/src/engine.rs:193-203`). | Preserve. |
| Ticket single-use after successful pairing use | **Primitive implemented / integration missing** | T-269 adds a schema-v2 transaction joining claim, registration, and ticket→device link (`kiwi-pair/src/store.rs:329-420`; `engine.rs:219-255`) with focused tests (`tests/pair_tests.rs:513-599`). No production claim channel calls it; the legacy public consume method still marks before checking expiry (`store.rs:309-326`). | Expose only the atomic claim through the trusted channel and retire or deny the unlinked consume path. |
| QR validity no more than five minutes | **Divergent** | Mobile checks ordering/current expiry but not `expires-issued <= 300` (`protocol/qr.ts:50-58`; `tests/protocol/qr.test.ts:58-61`). PairEngine issues +300 but its builder accepts an independent issue timestamp (`engine.rs:30-35,160-179,257-284`). | Enforce 1..300 and bind producer timestamps to the issued ticket. |
| Secure LAN endpoint | **Divergent** | Mobile and PairEngine enforce only a length/control bound (`protocol/qr.ts:42`; `kiwi-pair/src/engine.rs:266`). Tauri provisioning also accepts any bounded printable endpoint (`kiwi-app/src-tauri/src/state.rs:863-890`). | Parse and enforce the ratified scheme/host/port/path grammar. AUTH-5. |
| Desktop key is canonical 32-byte Ed25519 public key | **Divergent** | Mobile and the generic PairEngine builder check only `ed25519:` plus outer length (`protocol/qr.ts:44-48`; `kiwi-pair/src/engine.rs:268-272`). T-269 correctly validates the backend-owned key at `pair_begin` (`commands/pair.rs:64-82,131-138`), but the mobile scanner still does not decode/reencode it. | Enforce the same exact 32-byte canonical check in every consumer. AUTH-4. |
| Device label is safely rendered | **Partial** | `safeDeviceLabel` removes only CR/LF/tab and slices UTF-16 code units (`protocol/qr.ts:83-87`; `tests/protocol/qr.test.ts:77-86`). | Remove other controls/bidi marks and use a bounded display DTO. |
| Pairing hello, registered reply, peer-pin comparison | **Missing** | `ChallengeTransport` has only response posting; no pairing wire or live transport exists (`mobile/src/transport/transport.ts:8-23`; `protocol/types.ts:11-47`). | Add strict one-shot pairing messages and transport after the trust model is ratified. |
| QR validation advances pairing state | **Divergent** | PairingScreen treats expected key-generation failure as normal, creates a ticket-derived scaffold device ID, calls `onPaired`, and navigates onward (`mobile/src/screens/PairingScreen.tsx:35-74`; `src/App.tsx:25-28`). | Keep a validated/unavailable state; create identity only after registration and activation. |
| Native key lifecycle | **Release gate** | Production wiring uses `UnavailableKeystore`; generate/sign/delete all fail closed (`mobile/src/keystore/keystore.ts:47-64`). No Android/iOS module exists. | Implement only after sign-off; private bytes must not enter JS. |
| Public key/reference validation and deletion | **Missing / Partial** | The interface documents exact key bytes and a 256-character ref but validates neither; `deleteKey` has no production caller (`keystore/keystore.ts:28-45,58-60`). | Validate native handles and destroy the key on user request or revocation. |
| Soft HSM test posture | **Divergent documentation** | It is a deterministic fake under `src/`, but no production module imports it and its filler signatures cannot pass Ed25519 (`keystore/soft-hsm.ts:1-82`; `tests/keystore/soft-hsm.test.ts:19-49`). | Move it under test support or enforce a production import ban. AUTH-9 is low reachability, not an active bypass. |

## Challenge, approval, replay, and queue matrix

| Contract obligation | Status | Current evidence | Required resolution |
|---|---|---|---|
| Canonical bytes match kiwi-core | **Implemented** | Domain, three length-prefixed IDs, event byte, raw nonce, and i64be timestamps are equivalent (`mobile/src/protocol/canonical.ts:22-63`; `kiwi-core/src/challenge.rs:53-75`; `tests/protocol/canonical.test.ts:15-64`). | Add one shared kiwi-core-generated golden vector. |
| Event names/tags match kiwi-core | **Implemented** | `unlock`, `device-pairing`, `recovery`, and `elevated-action` map to 1..4 (`protocol/event.ts:9-30`; `tests/protocol/canonical.test.ts:66-73`). | Preserve with the shared vector. |
| Strict challenge parsing | **Partial** | Known fields and exact 32-byte nonce are checked, but the complete JSON input is unbounded before `JSON.parse`, errors may reflect untrusted schema text, and session/event form is not enforced (`PendingApprovalsScreen.tsx:41-43,61-64,106-116`; `protocol/canonical.ts:70-89`). | Cap total bytes, use fixed errors, and enforce the ratified session grammar. AUTH-14/16 are broader than previously recorded. |
| Live phone-clock expiry | **Divergent** | The ledger and queue use `FixedClock(Date.now())` captured at mount, so time never advances (`PendingApprovalsScreen.tsx:33-38`; `protocol/replay.ts:64-70`). | Use a live clock and recheck on every action. AUTH-7. |
| Gate order and tap-time revalidation | **Divergent** | Review order is parse → replay → optional binding → expiry; Approve/Deny do not rerun gates (`PendingApprovalsScreen.tsx:41-96`). | Centralize the exact order and bind the decision to the reviewed challenge. |
| Mandatory registered-device binding | **Divergent** | Binding is skipped when identity is null, and the Approvals tab is reachable without pairing (`App.tsx:42-60`; `PendingApprovalsScreen.tsx:48-51`). | Fail closed without a real desktop-confirmed identity and recheck at tap. AUTH-6. |
| Stale challenge cannot be actioned | **Divergent** | Rejected reviews do not clear the prior pending value, so a later action can still target the earlier challenge (`PendingApprovalsScreen.tsx:41-65`). | Clear/replace selection atomically with a bounded challenge list. |
| Required approval context | **Partial** | UI shows event and raw expiry, not trusted desktop, session/transaction ID, issue time, or challenge ID (`PendingApprovalsScreen.tsx:56-60`). | Add a trusted display source and show all required context. AUTH-13. |
| Approve signs canonical bytes after all gates | **Missing** | The button is enabled with pending state, but the handler calls `sign('no-key', empty bytes)` and never canonicalizes or enqueues (`PendingApprovalsScreen.tsx:80-96,129-135`). | Disable now; later run one ordered decision transaction ending in native sign + durable enqueue. |
| Response decision/signature | **Partial** | Builder emits an explicit decision and exact 64-byte decoded approve signature; exported `decision` is optional (`protocol/canonical.ts:129-148`; `protocol/types.ts:37-47`). | Make decision required and validate canonical Base64. |
| Deny is unsigned, advisory, non-consuming, and audited | **Divergent end to end** | Mobile builds/records deny locally. kiwi-core `ChallengeResponse` and Tauri input have no decision, so desktop routes deny to signature failure (`kiwi-core/src/challenge.rs:89-97`; `kiwi-app/src-tauri/src/types/system.rs:83-93`; `commands/pair.rs:340-366`). | Branch explicit deny before verification and audit it without consuming. AUTH-2. |
| Replay: one answer, one-hour prune, 256 cap | **Partial** | Primitives exist (`protocol/replay.ts:20-61`; `tests/protocol/replay.test.ts:9-54`), but no production caller prunes; state disappears on tab navigation. | Persist, prune before capacity checks, record expiry, and distinguish duplicate from capacity failure. AUTH-12. |
| Expired challenge is recorded | **Missing** | The ledger supports `expired`, but the screen only prints “removed” and does not record or clear pending (`PendingApprovalsScreen.tsx:52-55`; `protocol/replay.ts:10-14`). | Record and suppress re-prompt. AUTH-11. |
| Queue: approve at sign, FIFO, bound 64, dedupe, 10 s throttle | **Partial primitives / missing integration** | Map FIFO, cap, pending-only dedupe, offline retention, and throttle exist (`protocol/queue.ts:48-124`), but no production approve/scheduler exists. | Validate/clamp options, freeze/copy entries, and connect to the approval transaction. |
| One outcome per challenge ID | **Divergent** | After delivery the item is removed and may be re-enqueued; replay and queue state are separate (`protocol/queue.ts:66-78,104-109`). | Couple admission to durable replay/answer state. |
| Deny never queued indefinitely | **Divergent** | Deny uses the approval queue and has no TTL/drop path; production UI never drains it (`protocol/queue.ts:67-130`; `PendingApprovalsScreen.tsx:67-78`). | Use a bounded one-shot/best-effort deny policy. AUTH-8. |
| No implicit local expiry of queued approve | **Implemented** | The queue does not drop by `expires_unix`; desktop remains authoritative (`protocol/queue.ts:93-109`). | Preserve. |
| Live delivery and durable retry | **Missing** | `OfflineTransport` is permanent and no lifecycle invokes `deliver`/`tick`; queue state is in memory (`transport/transport.ts:19-23`; `PendingApprovalsScreen.tsx:35-38,139`). | Add durable recovery, a live scheduler, and terminal delivery states. |
| React Native host compatibility | **Divergent** | Canonical bytes and Base64 use Node's global `Buffer`; no dependency/polyfill or RN/Hermes proof exists (`protocol/canonical.ts:27-32,57-61,103-108`; `mobile/index.js:1-5`; `package.json:15-27`). | Use RN-safe byte/Base64 primitives and add a host smoke test. |

## `kiwi-pair` and desktop receiver disposition

| Area | T-270 result |
|---|---|
| Core canonical challenge bytes and verify order | **Implemented primitive**; failed verification does not consume in kiwi-core (`kiwi-core/src/challenge.rs:154-185`). |
| PairEngine Ed25519, bounds, nonce ledger, revocation | **Implemented primitives**; production crypto verifier is fail-closed (`kiwi-pair/src/crypto.rs:16-38`; `engine.rs:286-343,379-520`). |
| Ticket/status/atomic claim/schema migration | **Implemented and PairEngine-tested, integration incomplete**: v2 linkage/transaction and 20 current pair tests pass, but no production pairing-channel claim handler calls the transaction; legacy unlinked consume remains public (`engine.rs:206-255`; `store.rs:286-420`). |
| Challenge consume/activate race and nonce/challenge transaction | **Implemented and PairEngine-tested**: atomic consume+activation and nonce+insert transactions pass reopen/two-engine tests (`store.rs:448-557`; `tests/pair_tests.rs:655-723`). |
| Revoked outstanding response | **Implemented and tested in the current worktree**: `verify_response` reloads and rejects revoked status before expiry/signature, and `revoked_device_cannot_verify` explicitly covers issue→revoke→verify (`engine.rs:453-466`; `tests/pair_tests.rs:438-454`). This T-269 source is uncommitted. |
| Desktop challenge wire | **Tauri side implemented, adapter missing**: `ChallengeView` now emits canonical camelCase `nonceB64` and no `schema_version`; mobile requires snake_case `nonce_b64` plus `schema_version` (`types/system.rs:48-80`; `mobile/src/protocol/canonical.ts:70-99`). AUTH-3 remains open end to end. |
| Desktop deny/audit | **Divergent**: response input has no decision; success is audited only as `challenge-verified`, while failures, deny, and distinct pairing success lack required names (`types/system.rs:83-93`; `commands/pair.rs:340-394`). AUTH-1/2 remain open. |
| Unsupported events/post-action failure | **Divergent**: recovery/elevated-action responses are consumed by PairEngine and only then return `unsupported-event`; `attempt_unlock` failure occurs after consumption and is not audited (`commands/pair.rs:368-393`). |
| Tauri single authority | **Partial / T-269 in progress**: `AppState::pair` is persisted, all five canonical commands are registered, and legacy aliases delegate to `PairEngine` (`state.rs:511-587,734-890`; `lib.rs:77-83`; `commands/devices.rs:16-44`; `commands/system.rs:67-102`). The full Tauri test build is currently red, no trusted first-flow opener exists, and no mobile channel consumes the commands. |
| Pairing flow bootstrap | **Missing**: `pair_flow` starts `None` and is assigned only after a successful `pair_begin`, but locked `pair_begin` requires an already-live flow; no other assignment/caller exists (`state.rs:68-77,529-532,752`; `commands/pair.rs:46-61,124-159`). |
| Resource/error bounds | **Mostly implemented**: ticket/device/challenge/nonce limits, deterministic device ordering, exact key/length checks, and semantic `PairError` mapping are present (`store.rs:18-27,147-165,233-283,439-495`; `engine.rs:193-255,379-452`; `error.rs:126-171`). Command-level coverage is missing. |

## Security and drift findings

| ID | Severity | Finding | Existing mapping |
|---|---|---|---|
| **T270-01** | **H** | No live mobile pairing/approval path exists: no native signer, pairing claim channel, pinned peer, desktop-confirmed identity, or response transport. | AUTH-I plus the Phase-4 release blocker. |
| **T270-02** | **H** | Explicit deny and failure outcomes are not carried/audited end to end; the Tauri path can consume a challenge before an unsupported post-action fails. | AUTH-1/2. |
| **T270-03** | **M** | Approval is not one ordered transaction: binding is optional, time is frozen, stale pending can be actioned, and taps are not re-gated. | AUTH-6/7/13. |
| **T270-04** | **M** | Challenge input and errors are not globally bounded; event/session grammar is not enforced. | Extends AUTH-14/16. |
| **T270-05** | **M** | Replay, identity, and queue state is not durable; prune is unwired; deny retention is indefinite. | AUTH-8/12/AUTH-I. |
| **T270-06** | **M** | Queue admission does not prove challenge/response/decision consistency and can re-admit an ID after delivery. | New queue-integrity finding. |
| **T270-07** | **M** | React Native runtime availability of canonical `Buffer` operations is unproved. | New host-portability finding. |
| **T270-08** | **M** | Pairing UI fabricates “paired” state after failed key generation and uses ticket-derived identity. | New scaffold-state finding. |
| **T270-09** | **M** | T-269 integration remains incomplete: locked first-flow bootstrap has no trusted opener, the atomic claim has no production caller, and command/audit/channel coverage is absent. | T235-02/07 and T-269 follow-up. |
| **T270-10** | **L** | Soft HSM wording/placement permit accidental fake-key import, although production does not import it and its signatures cannot authorize. | AUTH-9; reclassify to low reachability. |

## Existing finding reconciliation

- **AUTH-1 remains open:** failure, deny, and distinct approval/pairing outcomes are not fully audited.
- **AUTH-2 remains open, with wording correction:** mobile does emit a deny response; the desktop/core response schema drops `decision`, so deny is treated as invalid approval.
- **AUTH-3 is remediated at the current Tauri source boundary but open end to end:** `nonceHex` is removed and `nonceB64` is emitted; a coordinated mobile schema/casing adapter still does not exist.
- **AUTH-4/5/10 remain open:** exact key encoding, secure endpoint, and maximum QR lifetime are not enforced by mobile.
- **AUTH-6/7 remain open:** identity-null binding, frozen clock, and missing tap-time revalidation persist.
- **AUTH-8 remains open for denies:** retaining an approve until desktop expiry is correct; indefinite deny retention is not.
- **AUTH-9 is reachability/document drift:** no app import and no valid fake signature; recommend low unless production reachability changes.
- **AUTH-11/12 remain open:** expired decisions are not recorded and prune has no production caller.
- **AUTH-13 remains open and is partly a contract-data gap:** trusted desktop/display context is undefined and absent.
- **AUTH-14 is broader than recorded:** total challenge bytes are unbounded and parse failures are not uniformly fixed/bounded.
- **AUTH-15 is an ambiguity, not a security defect:** `displayName` is correct; internal RN registration name is `kiwi-mobile`.
- **AUTH-16 is broader than fixture-only:** production parsing also accepts arbitrary event/session combinations.
- **AUTH-I remains open:** native keystore, live transport, persistence, scheduler, revocation, and local key destruction are absent.
- **T235-01/03/05/08/09/10/11 now have current in-flight source/test changes:** do not edit their register status until T-269 merges and its command/channel/build gates pass. T235-02 remains the controlling integration gate.

## Test coverage and verification

Focused mobile evidence on the current shared worktree:

- `npx vitest run tests/protocol tests/keystore` — **5 files, 32 tests passed**.
- `npm run typecheck` — passed.
- `npm run typecheck:app` — passed.
- `npm run lint -- --quiet` — passed with zero errors.
- Full `npm test` — **43 passed, 3 failed** in concurrently edited QR encoder/vector work (`json-v21-l`, `json-v25-l`, and penalty/mask selection), not the T-270 protocol suites.
- Full lint previously reported zero errors with 4099 QR-generated warnings.

Current T-269 evidence:

- `cargo test -p kiwi-pair` — **20 passed, 0 failed**.
- `cargo clippy -p kiwi-pair --all-targets -- -D warnings` — passed.
- `cargo fmt -p kiwi-pair -- --check` — failed on T-269 formatting in `kiwi-pair/src/engine.rs` and `kiwi-pair/tests/pair_tests.rs`.
- `cargo test -p kiwi-app` — **blocked at compile time by unrelated concurrent `kiwi-app/src-tauri/src/commands/link.rs:263` unclosed-delimiter work**. PairEngine source tests pass, but the full Tauri command/audit verification does not.

Missing regression coverage includes RN/Hermes execution, screen gate order, stale/identity-null/tap-time behavior, total challenge cap, exact key/endpoint/TTL cases, deny delivery/audit, durable replay/queue, first-flow bootstrap, trusted claim channel, revoked-after-response at the Tauri boundary, and T-269 migration/command/error/audit matrices.

## Required implementation order

1. Ratify the contract decisions above and keep the Lead + Agent 6 crypto gate closed.
2. Finish and verify T-269: rustfmt/build-clean canonical commands, first-flow bootstrap, trusted claim/response channel, endpoint/pin enforcement, and full audit semantics.
3. Define one mobile↔desktop adapter, including `schema_version`, explicit decision, and a separate audited non-consuming deny path.
4. Harden mobile input/trust validation: exact key bytes, secure endpoint, QR/challenge bounds, session grammar, and bounded errors.
5. Replace the screen-local flow with one ordered decision service and a real persisted paired-device identity.
6. Add durable replay and queue stores, automatic pruning, finite deny delivery, immutable/validated entries, and lifecycle retry.
7. Implement the reviewed native keystore, secure channel/peer-pin semantics, key deletion, and revocation reconciliation.
8. Add the missing security and host tests before enabling any Phase-4 build path.

## T-270 conclusion

The mobile scaffold has credible deterministic protocol work, but only a subset of the contract is implemented. QR/challenge primitives must not be mistaken for an end-to-end authenticator. T-269 has materially improved the persisted PairEngine and canonical desktop source, but it remains an uncommitted, build-red transition without a pairing channel or complete deny/audit flow. The decisive mobile blockers remain a compatible decision/audit adapter, a single fail-closed approval transaction, exact QR trust validation, durable replay/queue/identity state, native key lifecycle, and a pinned pairing transport. Until those are resolved and the required sign-off is recorded, Phase 4 must remain disabled.
