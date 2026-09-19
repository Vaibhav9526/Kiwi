# KIWI Mobile Authenticator (scaffold)

React Native (TypeScript) authenticator client — **T-136 scaffold**: pairing
+ challenge-response protocol code, fail-closed keystore interface, two UI
screens. Protocol spec: [`docs/contracts/authenticator.md`](../docs/contracts/authenticator.md)
(contract v1, Owner: Agent 4).

> **Scaffold posture:** no native modules, no camera, no push channel, no
> live pairing transport. Key generation is **fail-closed**
> (`UnavailableKeystore`) until the platform keystore module lands in
> Phase 4. This task ships no production key handling — SECURITY.md §6
> crypto review gate re-triggers then.

## Layout

```
src/protocol/      pure protocol modules (Node-testable, no RN imports)
src/keystore/      KeystoreError + interface; test-only SoftHsm
src/screens/       PairingScreen, PendingApprovalsScreen (RN)
src/App.tsx        two-tab shell (pairing / approvals)
tests/             vitest — 32 deterministic protocol/keystore tests
```

## Scripts

| command | what |
|---------|------|
| `npm run typecheck` | strict typecheck, protocol + keystore core (no RN toolchain needed) |
| `npm run typecheck:app` | full typecheck incl. RN screens |
| `npm test` | vitest protocol/keystore suites |
| `npm run lint` | eslint (@react-native config) |
| `npm run android` / `npm run ios` | RN build (not exercised in this task) |

## Security rules honored (docs/SECURITY.md)

- Ed25519 only; `ecdsa-p256`/`rsa3072` are reserved names, rejected
  fail-closed (`unsupported-algorithm`) until verifiers exist.
- Private keys: keystore-only (rule 8) — the scaffold never holds one.
- Challenge binding + single-use + replay ledger (rule 10); the desktop
  `ChallengeBook` remains the verification authority.
- All parsed input bounded + validated; unknown fields ignored; raw QR
  text never logged (rules 6, 9).
- Deterministic only — no AI anywhere in the approval path (rule 1).

## Verification evidence

`npm run typecheck` → 0 errors · `npm run typecheck:app` → 0 errors ·
`npm test` → 5 files / 32 tests passed. Full run log:
`docs/agents/agent-4-status.md` (T-136 entry).
