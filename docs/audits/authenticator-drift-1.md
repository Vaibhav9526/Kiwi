# Mobile Authenticator Drift Audit 1 (T-270)

**Reviewer:** Agent 23 · **Date:** 2026-09-25 · **Snapshot:** `9f13f47` plus the current shared worktree  
**Mode:** read-only implementation audit. No mobile, Rust, contract, task-ledger,
or master-findings file was changed. This report and the Agent 23 status entry
are the only T-270 writes.

## Scope and verdict

This audit compares `docs/contracts/authenticator.md` §§1–11 with the current
`mobile/` implementation, the `kiwi-core` challenge/device primitives, the
current `kiwi-pair` primitives, and the current Tauri challenge/device receiver.
The prior AUTH register and T-235 pair audit are used for disposition, not as a
substitute for current source evidence.

**Verdict: the deterministic protocol core is substantially implemented, but
the mobile authenticator is still a fail-closed scaffold rather than an
end-to-end implementation.** The canonical byte layout, event tags, strict
known-field parsing, 32-byte nonce decode, one-answer replay primitive, and
bounded FIFO queue primitives are real. The production identity, key, transport,
persistence, signing, delivery, and desktop audit paths are absent.

The current default wiring cannot authorize a challenge: `UnavailableKeystore`
cannot sign and `OfflineTransport` cannot send. This prevents a demonstrated
mobile unauthorized-approval exploit. It does not make the remaining work
routine: the contract's Lead + Agent 6 sign-off gate remains open, and the
existing Tauri receiver has independent trust and audit gaps, including accepting
a signed response for an outstanding challenge from a device that has since
been revoked.

### In-flight snapshot caveats

- T-269 is actively changing `kiwi-pair` and `kiwi-app`. Its current worktree
  adds important ticket-status, atomic-claim, nonce-transaction, and atomic
  challenge-consume primitives, but the canonical Tauri integration is still
  absent and the new methods are not yet covered by the current 11-test suite.
- Current QR-encoder changes under `mobile/src/qr/`, `mobile/tests/qr/`, and
  `mobile/tools/` are unrelated to this audit. They are preserved and not used
  to excuse or attribute authenticator findings.
- Line references below describe this shared-worktree snapshot and may move
  when T-269 lands.

## Status legend

- **Implemented** — the requested behavior is present and test-backed.
- **Partial** — a useful primitive exists, but part of the requirement is absent.
- **Missing** — no callable implementation exists.
- **Divergent** — a path exists, but it does not enforce the contract or is not
  the intended authority.
- **Release gate** — expected Phase-4 absence that must remain disabled until
  completed; not counted as a current bypass while fail closed.

## Executive summary

| Area | Current result |
|---|---|
| Deterministic canonical bytes and event tags | **Implemented**; exact parity with kiwi-core, with unit evidence |
| QR/challenge parsers | **Partial**; core fields are strict, but several trust and resource gates are missing |
| Pairing identity and ticket lifecycle | **Partial primitives / missing runtime**; PairEngine can issue/claim, mobile has no channel or real identity |
| Platform keystore | **Missing by design**; the wired implementation fails closed |
| Approval gates and signing | **Divergent**; review is incomplete and the approve handler signs neither canonical bytes nor a real key |
| Replay ledger and delivery queue | **Partial primitives / missing runtime**; in-memory, not pruned in the app, no scheduler or durable storage |
| Desktop decision/audit receiver | **Divergent**; no compatible deny path and incomplete outcome auditing |
| Current Tauri ↔ PairEngine integration | **Missing**; Tauri still uses separate process-local kiwi-core state |

## Contract implementation matrix

### Binding invariants and pairing

| Contract requirement | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Deterministic, no AI in pairing/approval | **Implemented** | Protocol modules are pure/injectable; no AI or network call is in the approval decision path (`mobile/src/protocol/canonical.ts:45-63`, `replay.ts:16-18`, `queue.ts:22-24`). | Preserve; keep the Phase-4 coordinator deterministic. |
| Ed25519 only; unsupported algorithms fail closed | **Partial** | Mobile's type admits only `ed25519` (`mobile/src/keystore/keystore.ts:10,28-35`), and PairEngine rejects other algorithms (`kiwi-pair/src/engine.rs:234-243,299-308`). The legacy Tauri registration path still accepts reserved ECDSA/RSA names and defers rejection until submit (`kiwi-app/src-tauri/src/commands/devices.rs:27-44`; `system.rs:182-194`). | Reject unsupported algorithms at every registration boundary; keep only Ed25519 live. |
| Keystore-only private key; public key and `keystore_ref` only | **Release gate** | The interface exposes no private-key export (`mobile/src/keystore/keystore.ts:28-45`). The wired `UnavailableKeystore` rejects generate/sign/delete (`:47-63`). SoftHsm is non-cryptographic and only imported by tests. | Implement reviewed Android/iOS native key lifecycle; never expose seed/private bytes to JS. |
| Challenge binds device/session/event/nonce/expiry and is single-use | **Partial** | kiwi-core and PairEngine implement the binding/verification order; mobile canonical encoding matches. The approval screen does not require an identity and does not maintain a production replay ledger. | Preserve canonical primitives; require a registered identity and durable answer state before decisions. |
| No secrets in QR/logs/fixtures; raw QR not echoed | **Partial** | No `console.*` call was found and QR errors do not include the raw text. The bearer ticket is retained in `QrPayload.raw` and an eight-character ticket prefix is used in the scaffold alias/device ID (`mobile/src/protocol/types.ts:11-21`; `PairingScreen.tsx:48,61-67`). | Do not retain/log the raw QR longer than needed; never derive persistent identity or telemetry from bearer-ticket text. |
| Untrusted input is bounded, validated, and fail-closed | **Partial** | QR raw input and known fields are bounded. Challenges are parsed directly from an unbounded TextInput before validation; unknown and oversized JSON values can consume resources, and an untrusted version value is echoed (`PendingApprovalsScreen.tsx:41-43,61-64,106-116`; `canonical.ts:70-89`). | Cap raw challenge bytes before `JSON.parse`; use closed error codes/messages and reject unknown oversized fields without reflection. |
| Approve is the only cryptographic act; deny is unsigned | **Implemented locally** | The response builder requires an exact decoded 64-byte signature for approve and emits `decision:'deny'` with an empty signature for deny (`mobile/src/protocol/canonical.ts:129-148`). | Keep deny outside signature verification on the desktop. |
| Every registration, approval, denial, failure, and revocation is audited | **Divergent** | Tauri audits registration/revocation and successful verification, but failures propagate before an audit row; success is `challenge-verified`, and no `challenge-approved`, `challenge-denied`, `challenge-verification-failed`, or `device-paired` action exists (`kiwi-app/src-tauri/src/commands/system.rs:203-240`; `devices.rs:74-78,122-126`). | Add one mandatory structured outcome-audit layer around every decision and post-verification action. |
| Version is integer 1; unknown fields are ignored | **Implemented** | QR and challenge parsers require version 1 and construct explicit allowlisted result objects (`mobile/src/protocol/qr.ts:36-75`; `canonical.ts:70-100`). | Preserve and test boundary/version-skew cases. |
| QR v1 field shape, ticket bounds, and unknown-field handling | **Partial** | Version/type, ticket length/charset, and basic field bounds are enforced (`mobile/src/protocol/qr.ts:24-75`). Desktop-key encoding/size, endpoint security, and maximum lifetime are not. | Complete the trust-bearing QR validation below. |
| Pairing ticket is single-use | **Missing on mobile / Partial primitive** | Mobile has no pairing transport. PairEngine has a persistent store and current T-269 atomic claim path, while its legacy `consume_pairing_ticket` still marks a row consumed before returning `TicketExpired` (`kiwi-pair/src/engine.rs:182-190`; `store.rs:309-326`). | Use only the atomic claim transaction in production; deprecate/remove the legacy consume path or make expiry precede mutation. |
| TLS-protected pairing channel, desktop identity pin, and peer-key comparison | **Missing** | The only transport is permanently offline (`mobile/src/transport/transport.ts:14-23`). QR parsing accepts any 1–256-character endpoint and only checks an `ed25519:` prefix (`qr.ts:42-48`). No endpoint, TLS peer, or pin comparison exists. | Implement the ratified secure transport and compare the negotiated peer identity to the QR pin before sending ticket/key material. |
| Pairing hello, registered reply, pending registration, activation | **Missing on mobile** | No hello/reply types or transport exist. PairingScreen fabricates a scaffold identity after expected key-generation failure and calls `onPaired` (`PairingScreen.tsx:35-74`). | Model explicit `validated → key-ready → registered-pending → active`; call paired only after desktop-assigned registration and successful pairing verification. |
| Device lifecycle and local key destruction | **Release gate** | PairEngine has persistent registration, activation, and terminal revocation. Mobile has a `deleteKey` interface but no caller, revocation notification, identity removal, or queue cleanup. | Coordinate desktop revocation with native local destruction and durable cleanup. |

### Challenge, response, replay, and queue

| Contract requirement | Status | Current behavior and evidence | Required resolution |
|---|---|---|---|
| Canonical bytes match kiwi-core byte-for-byte | **Implemented** | Domain, three length-prefixed fields, event tag, raw 32-byte nonce, and two i64be timestamps match (`mobile/src/protocol/canonical.ts:22-63`; `kiwi-core/src/challenge.rs:53-75`). Unit test covers layout and every bound field. | Add one shared Rust/TypeScript golden vector and fixed Ed25519 signature. |
| Event tags are exactly 0x01–0x04 | **Implemented** | Mobile, kiwi-core, and PairEngine use the same four values (`mobile/src/protocol/event.ts:9-23`; `kiwi-core/src/challenge.rs:15-37`). | Preserve with a cross-language version gate. |
| Challenge delivery uses `schema_version` and `nonce_b64` | **Divergent** | Mobile expects the documented snake_case fields (`mobile/src/protocol/canonical.ts:70-99`). Tauri emits camelCase without `schema_version` and with `nonceHex`; its TS interface says `nonceB64` (`kiwi-app/src-tauri/src/types/system.rs:48-76`; `kiwi-app/src/kiwi.ts:946-955`). | Land one canonical challenge view/transport adapter; remove runtime fallback among nonce encodings. |
| Strict challenge parsing: bounded strings, exact nonce, known events, unknown fields ignored | **Partial** | Known fields and exact nonce decode are enforced. Raw JSON is not bounded, session-form rules are not enforced, and challenge TTL is accepted as any positive interval (`canonical.ts:70-100`; contract `:167-178`). | Add a pre-parse byte cap, exact field bounds, session/event validation, and an explicit TTL/profile rule. |
| Nonce is desktop-issued CSPRNG and replay-detected at issue | **Partial** | Tauri and `kiwi_pair::os_nonce` use `getrandom`; PairEngine persists and caps nonces. No active Tauri PairEngine caller exists, and `replay-detected` is not written as an audit event (`kiwi-pair/src/crypto.rs:80-86`; `engine.rs:412-428`). | Wire PairEngine as the authority and audit collision incidents without recording the nonce. |
| Desktop verifies in exists → expiry → unconsumed → binding → signature → consume order | **Implemented in primitives** | kiwi-core follows the order; current PairEngine adds bounds, revocation, and atomic consume+activation (`kiwi-core/src/challenge.rs:154-185`; `kiwi-pair/src/engine.rs:442-520`). Tauri still uses the in-memory core path. | Finish the single persistent PairEngine integration and preserve this order. |
| Phone gate order and explicit intent on the displayed challenge | **Divergent** | Review runs parse → replay → conditional binding → expiry, not contract order; null identity skips binding; both Approve and Deny act without re-running gates (`PendingApprovalsScreen.tsx:41-96`). | Centralize review and tap-time decisions in one coordinator that revalidates the exact reviewed challenge. |
| User sees event, desktop label, transaction ID, and issue/expiry times | **Partial** | The screen shows only a human event label and expiry. It does not show desktop label, session/transaction ID, issue time, or challenge ID (`PendingApprovalsScreen.tsx:56-60,100-105`). The challenge wire has no desktop-label field. | Define a trusted desktop-label source and include the required signed context before enabling approval. |
| Response shape and 64-byte Ed25519 signature | **Partial** | The mobile builder includes schema, bound fields, and decision, and checks decoded signature length. The exported `decision` type is optional (`mobile/src/protocol/types.ts:36-47`), and desktop input has no decision/schema version. | Make decision mandatory; validate exact/canonical Base64; define one response adapter shared with Tauri. |
| Deny is explicit, unsigned, audited, non-authorizing, and non-consuming | **Divergent end-to-end** | Mobile builds and locally records deny correctly. Tauri drops the `decision` field and routes the empty signature into signature verification, yielding `InvalidSignature`; no deny audit exists (`mobile/src/protocol/canonical.ts:146-147`; `kiwi-app/src-tauri/src/types/system.rs:80-90`; `system.rs:175-207`). | Branch explicit deny before signature verification, audit it, and do not consume. |
| Replay ledger: one answer, 1-hour prune, 256 cap | **Partial** | Primitives/tests exist (`mobile/src/protocol/replay.ts:20-61`; `tests/protocol/replay.test.ts:9-54`), but the app never calls `prune`; state is component-local and disappears on tab unmount. Expired challenges are not recorded. | Persist ledger, prune before capacity checks, record expiry, and distinguish duplicate from capacity failure. |
| Queue: sign-time approve, FIFO, bounded, dedupe, ≥10 s retry, durable offline approve | **Partial primitives / missing runtime** | Queue map, cap 64, dedupe, FIFO tick, and 10-second throttle exist (`mobile/src/protocol/queue.ts:48-124`). No production approve exists, no scheduler calls `tick`, state is in memory, and the app ignores enqueue failure. | Build an atomic sign/persist/enqueue coordinator and a lifecycle-owned durable scheduler. |
| Deny never remains queued indefinitely | **Divergent** | Deny is accepted by the same queue and remains on every offline result; there is no deny TTL/drop terminal state (`queue.ts:67-77,93-124`; contract `authenticator.md:286-288`). | Give deny a bounded one-shot or age-bounded policy and surface dropped delivery accurately. |
| No implicit local expiry of queued approve | **Implemented in queue primitive** | `ChallengeQueue` does not drop by `expires_unix`; late desktop verification remains authoritative (`queue.ts:93-109`). | Preserve; do not apply the deny policy to approvals. |
| Mobile scaffold claims and tests are honest | **Partial** | Mobile README clearly labels the scaffold, but PairingScreen advances with a fake identity, Approve is enabled despite no signer, and screen/transport behavior has no tests. | Disable actions that are not actually available; add component and transport-contract tests. |

## `kiwi-pair` primitive disposition

The current T-269 worktree materially changes the T-235 result. The following are
present in source now, but remain in-flight and are not yet a released Tauri
integration:

| Primitive | Current result | Evidence / remaining gap |
|---|---|---|
| Persistent `pair.db` and schema v2 migration | **Implemented in current worktree** | Ticket-to-device link and migration are present (`kiwi-pair/src/store.rs:18-27,41-50,147-165`). No disk-reopen/migration regression test is present. |
| Ticket issue and bounds | **Implemented** | 43-char base64url ticket, 300-second expiry, 32-live-ticket cap (`engine.rs:157-180`; `store.rs:248-283`). |
| Read-only ticket status | **Implemented in current worktree** | `ticket_status` and `TicketRow` distinguish awaiting/claimed/expired (`engine.rs:105-125,206-217`; `store.rs:286-307`). Current 11 tests do not call it. |
| Atomic ticket claim + pending registration + link | **Implemented in current worktree** | One SQLite transaction (`engine.rs:219-255`; `store.rs:329-420`). No race/crash/reopen tests are present. |
| Ed25519-only 32-byte registration | **Implemented** | `claim_ticket_and_register` and legacy registration validate algorithm and key length (`engine.rs:234-243,299-308`). |
| QR trust validation | **Divergent** | Endpoint/label bounds and key prefix only; no TLS/LAN, exact 32-byte desktop key, canonical Base64, or 300-second QR-lifetime check (`engine.rs:257-283`). |
| Challenge issue and nonce transaction | **Implemented in current worktree** | Active devices cannot receive `device-pairing`; nonce plus challenge insertion is transactional (`engine.rs:377-434`; `store.rs:448-497`). Session-form semantics are still not validated. |
| Verification and atomic consumption | **Implemented in current worktree** | Response fields are bounded; missing device and revoked device fail closed; consume plus pairing activation is one transaction and checks the update result (`engine.rs:442-520`; `store.rs:531-557`). |
| Persistent terminal revocation | **Implemented** | Revocation is idempotent and blocks issue/verify (`engine.rs:329-355,394-410,461-467`). |
| Bounded device listing/challenge/nonce storage | **Implemented in current worktree** | Ordered/limited device query and 4096 challenge/nonce caps exist. Current tests do not exercise limits. |
| Tauri use of PairEngine | **Missing** | Tauri still owns process-local `DeviceRegistry`/`ChallengeBook`; no `kiwi-pair` dependency or PairEngine state is present. |

## Current Tauri receiver gaps

These are relevant because the contract names Tauri and kiwi-core as the
counterparties, and because a mobile-only implementation would otherwise be
wired to a non-compatible receiver.

| ID | Severity | Finding | Evidence | Required resolution |
|---|---|---|---|---|
| **T270-01** | **High** | A revoked device with an already-issued challenge can still submit a valid response: submit fetches the public key/algorithm but never checks device status. PairEngine correctly rejects revoked devices, but it is not wired. | `kiwi-app/src-tauri/src/commands/system.rs:182-207`; `commands/devices.rs:108-127`; `kiwi-pair/src/engine.rs:461-467`. | Make persistent PairEngine the authority and add revoke-after-issue regression tests for every challenge event. |
| **T270-02** | **High** | The desktop and mobile challenge/response wires are incompatible: Tauri emits `nonceHex` and no `schema_version`; mobile requires `nonce_b64`; Tauri drops `decision`, so deny becomes invalid-signature verification. | `kiwi-app/src-tauri/src/types/system.rs:48-90`; `mobile/src/protocol/types.ts:24-47`; `canonical.ts:70-148`. | Add one canonical view/adapter; serialize only `nonceB64`; require explicit decision and branch deny before crypto. |
| **T270-03** | **High** | Required verification/denial/pairing audit outcomes are absent, and failures return before the only audit call. | `kiwi-app/src-tauri/src/commands/system.rs:203-240`; contract `authenticator.md:327-332`. | Audit every `ChallengeError`, deny, successful approval, pairing activation, and post-verification action failure. |
| **T270-04** | **Medium** | Unsupported recovery/elevated events are accepted and cryptographically consumed, then return `unsupported-event` before audit. | `kiwi-app/src-tauri/src/commands/system.rs:228-240`; core consume occurs at `:203-207`. | Reject unsupported events before issue/verify, or implement their action and mandatory audit in one transaction. |
| **T270-05** | **Medium** | Legacy registration accepts reserved non-Ed25519 algorithms even though the verifier is Ed25519-only. | `kiwi-app/src-tauri/src/commands/devices.rs:27-44`; `system.rs:182-194`; contract `authenticator.md:26-31`. | Enforce Ed25519 at registration and retain a single pair authority. |
| **T270-06** | **Medium** | Tauri device/challenge state is process-local and separate from the persistent PairEngine store. | `kiwi-app/src-tauri/src/commands/system.rs:124-147,203-207`; `state.rs` process-local registry/challenge book; T269 remains in progress. | Complete T-269's single persistent authority; remove the parallel truth source. |

## Focused security findings

| ID | Severity | Finding | Existing mapping |
|---|---|---|---|
| **T270-01** | **High** | Revoked-device outstanding responses are accepted by the current Tauri receiver. | New T-270 row; T235 integration context. |
| **T270-02** | **High** | Mobile and Tauri challenge/response/deny wires cannot interoperate. | IPC-3/AUTH-3 and AUTH-2, with AUTH-2 wording corrected. |
| **T270-03** | **High** | Success, failure, deny, and pairing outcomes are not all audited. | AUTH-1. |
| **T270-04** | **Medium** | QR parsing and PairEngine QR generation do not validate TLS/LAN endpoint semantics, exact 32-byte canonical desktop key, or a maximum five-minute lifetime. | AUTH-4, AUTH-5, AUTH-10. |
| **T270-05** | **Medium** | Approval review has reversed gate order, skips binding when identity is null, freezes time, and does not revalidate at the action tap. | AUTH-6, AUTH-7; extends the gate requirement. |
| **T270-06** | **Medium** | Challenge input is not capped before JSON parsing, untrusted version text is reflected, and event/session form is not enforced. | AUTH-14; extends AUTH-16. |
| **T270-07** | **Medium** | Replay and queue state is component-local, pruning is unwired, deny retention is indefinite, and no durable retry/terminal delivery path exists. | AUTH-8 (narrowed to deny), AUTH-12, AUTH-I. |
| **T270-08** | **Medium** | Pairing UI advances to approvals with a locally fabricated identity after expected key-generation failure; it never performs registration or activation. | AUTH-I plus a new UI-state finding. |
| **T270-09** | **Medium** | Canonical TypeScript uses global Node `Buffer`, but the React Native dependency graph has no explicit Buffer implementation or polyfill and no RN-host execution evidence. | New runtime-portability finding. |
| **T270-10** | **Low** | `SoftHsmKeystore` is a public, functional non-cryptographic implementation despite the contract/test-map description as an UNIMPLEMENTED-style fail-closed stub. It is not imported by the app and its signatures cannot authorize. | AUTH-9, recommended reclassification to Low/documentation-test drift. |

## Existing AUTH finding disposition

| Existing ID | T-270 disposition |
|---|---|
| AUTH-1 | **Confirmed High.** Missing failure/deny/pairing audit outcomes; success action name is also wrong. |
| AUTH-2 | **End-to-end defect confirmed, wording corrected.** Mobile emits deny correctly; Tauri drops `decision` and reports empty signature as `InvalidSignature`. |
| AUTH-3 | **Confirmed.** Tauri runtime emits `nonceHex`; canonical mobile wire expects `nonce_b64`; TS desktop interface says `nonceB64`. |
| AUTH-4 | **Confirmed.** Both mobile and PairEngine validate only `ed25519:` prefix, not exact canonical 32-byte Base64. |
| AUTH-5 | **Confirmed.** Mobile and PairEngine accept plaintext/invalid endpoints; live transport is correctly absent/fail closed. |
| AUTH-6 | **Confirmed.** Binding is skipped when identity is null; no action-time re-gate exists. |
| AUTH-7 | **Confirmed.** `FixedClock(Date.now())` is frozen for screen lifetime. |
| AUTH-8 | **Confirmed but narrowed.** The definite queue defect is indefinite deny retention; approvals correctly have no implicit local wire expiry. |
| AUTH-9 | **Confirmed as documentation/test drift; recommend Low.** The HSM is functional and test-only, not production-imported, and emits non-verifying filler. |
| AUTH-10 | **Confirmed.** QR parser does not enforce a 300-second maximum. |
| AUTH-11 | **Confirmed.** Expired challenge is not recorded in the ledger. |
| AUTH-12 | **Confirmed.** One-hour prune exists as a tested method but has no production caller. |
| AUTH-13 | **Confirmed and partly under-specified.** UI lacks desktop label, transaction/session ID, and issue time; the challenge wire defines no trusted desktop-label source. |
| AUTH-14 | **Confirmed and broadened.** Challenge raw input lacks a pre-parse cap; untrusted version text can be reflected into UI status. |
| AUTH-15 | **Contract-wording issue, not a functional defect.** `displayName` is `KIWI Authenticator`; RN's internal registered name is `kiwi-mobile`. Clarify whether the contract means display name. |
| AUTH-16 | **Confirmed and broadened.** Production parsing does not enforce boot/x-tx event semantics, and the canonical unlock fixture uses `x-tx-test-0001`. |
| AUTH-I | **Confirmed.** Native keystore, live pairing/transport, durable state, background delivery, revocation notification, and local key deletion remain absent. |

## Test coverage and verification

### Mobile evidence

- `npx vitest run tests/protocol tests/keystore` — **5 files, 32 tests passed**.
- `npm run typecheck` — passed.
- `npm run typecheck:app` — passed.
- `npm run lint -- --quiet` — passed with zero errors.
- Full `npm test` — **43 passed, 3 failed**. All three failures are in the
  concurrently modified QR encoder/vector work (`json-v21-l`, `json-v25-l`, and
  mask selection), not in the T-270 protocol/keystore suites.
- Full `npm run lint` — zero errors and 4099 warnings, overwhelmingly from the
  concurrently generated QR tables. The focused `--quiet` gate is clean.

The passing tests prove deterministic pure-module behavior, not the React Native
runtime. No native bundle or device test was run.

### `kiwi-pair` evidence

- `cargo test -p kiwi-pair` — **11 passed, 0 failed** for the current snapshot.
- `cargo clippy -p kiwi-pair --all-targets -- -D warnings` — passed.
- `cargo fmt -p kiwi-pair -- --check` — failed only on two formatting deltas in
  T-269's current `engine.rs`; T-270 did not modify them.

The 11 tests do not yet cover the current ticket-status, atomic ticket claim,
schema migration, disk reopen, concurrent consume, new resource limits,
Tauri wire, explicit deny, or revoked-after-issue paths.

### Missing regression coverage

- React Native host execution of canonical bytes/Base64 (the `Buffer` path).
- QR exact desktop-key decode, canonical Base64, `wss://`/LAN validation, and
  >300-second lifetime.
- Raw challenge byte cap, bounded fixed errors, and event/session form matrix.
- Screen gate order, null identity, stale pending challenge, tap-time expiry,
  and truthful paired state.
- Replay prune/capacity/expired recording across remount/restart.
- Queue deny drop, durable restart recovery, scheduler behavior, transport
  failure normalization, and terminal desktop rejection.
- Tauri explicit deny, every audit outcome, `nonceB64` serialization,
  revoked-after-issue, unsupported-event, and PairEngine integration.
- One shared kiwi-core-generated canonical/Ed25519 vector consumed by mobile
  and Rust tests.

## Required implementation order

1. **Contract ratification:** resolve endpoint/pin semantics, the
   `nonce_b64`/`nonceB64` adapter, required approval context, exact session and
   challenge bounds, and the Lead + Agent 6 crypto gate.
2. **Desktop authority:** finish T-269's persistent PairEngine integration,
   deny/audit semantics, exact wire projections, and revoked-device checks.
3. **Mobile trust boundary:** enforce exact QR key/endpoint/TTL validation,
   RN-compatible bytes/Base64, bounded challenge errors, and event/session rules.
4. **Real pairing/key lifecycle:** implement native Ed25519 keystore, secure
   channel, peer-pin comparison, atomic registration/activation, persistent
   identity metadata, and local key destruction.
5. **Decision coordinator:** centralize ordered review and tap-time revalidation;
   record the exact displayed challenge before signing or recording deny.
6. **Durable state and delivery:** persist replay/queue state, wire pruning,
   separate bounded deny delivery, and add terminal result handling and a
   lifecycle-owned retry scheduler.
7. **Verification:** add the missing screen, transport, persistence, race,
   audit, and shared-vector tests; rerun full mobile, PairEngine, and Tauri gates
   only after T-269 stabilizes.

## T-270 conclusion

The scaffold contains credible deterministic protocol work, not a blank module:
canonical bytes, event tags, strict known-field parsing, exact nonce length,
replay/queue data structures, and the core/pair verification algorithms are
implemented. The deployable authenticator is nevertheless incomplete. The
highest-risk current issues are on the desktop receiver (revoked-device
acceptance, incompatible nonce/decision wire, and incomplete audit coverage);
the mobile path remains safely unable to sign or deliver. Phase 4 must not be
enabled until the Lead + Agent 6 gate, desktop authority/wire/audit fixes,
native key lifecycle, secure pairing transport, real approval coordinator, and
durable replay/delivery state are complete.
