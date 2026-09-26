# KIWI Mobile Authenticator (scaffold)

React Native (TypeScript) authenticator client — **T-136 protocol scaffold +
T-194 screens over mock transport**: pairing, approvals, devices, history.
Protocol spec: [`docs/contracts/authenticator.md`](../docs/contracts/authenticator.md)
(contract v1, Owner: Agent 4).

> **Scaffold posture:** no native modules, no camera, no push channel, no
> live pairing transport. The default run is **MOCK mode** — an in-process
> mock desktop + soft-HSM test keystore, bannered as demo-only (mock
> signatures authorize nothing). The **FAIL-CLOSED** toggle switches to the
> posture a signed build must keep until Phase 4 wires the real wss/TLS
> transport (contract §3.2) and the platform keystore (§5). This task ships
> no production key handling — SECURITY.md §6 crypto review gate re-triggers
> then.

## Layout

```
src/protocol/      pure protocol modules (Node-testable, no RN imports)
                   — approval gates, decision history, byte primitives
src/keystore/      KeystoreError + interface; test-only SoftHsm (mock/tests only)
src/transport/     ChallengeTransport + AuthenticatorLink abstractions
src/environment.ts Environment seam: fail-closed default + approval bundle
src/mock/          in-process MockDesktop (pairing/challenge plumbing) — wired
                   ONLY by src/App.tsx; import graph enforced by tests
src/screens/       Pairing, PendingApprovals, Devices, History (RN)
src/App.tsx        four-tab shell; mock/fail-closed mode toggle + banner
tests/             vitest — protocol, mock flow, keystore, isolation suites
```

## Scripts

| command | what |
|---------|------|
| `npm run typecheck` | strict typecheck, protocol/mock core (no RN toolchain needed) |
| `npm run typecheck:app` | full typecheck incl. RN screens |
| `npm test` | vitest suites (protocol + mock flow + isolation) |
| `npm run lint` | eslint (@react-native config) |
| `npm run android` / `npm run ios` | RN build (not exercised in this task) |

## Mock mode honesty rules

- The mock desktop validates response **shape only** — it never verifies
  signatures; the desktop `ChallengeBook` + `Ed25519Verifier` remain the
  sole verification authority (contract §6.2).
- Mock tickets/nonces/keys are deterministic fixtures, not secrets.
- The UI labels mock mode persistently; nothing produced in it authorizes
  anything on a real desktop.

## Security rules honored (docs/SECURITY.md)

- Ed25519 only; `ecdsa-p256`/`rsa3072` are reserved names, rejected
  fail-closed (`unsupported-algorithm`) until verifiers exist.
- Private keys: keystore-only (rule 8) — the scaffold never holds one.
- Challenge binding + single-use + replay ledger (rule 10); the desktop
  `ChallengeBook` remains the verification authority.
- All parsed input bounded + validated; unknown fields ignored; raw QR
  text never logged (rules 6, 9).
- Deterministic only — no AI anywhere in the approval path (rule 1).
- Mock isolation (rules 4, 7): core/screens never import `src/mock` or the
  soft HSM — enforced by `tests/isolation/mock-isolation.test.ts`.

## Verification evidence

`npm run typecheck` → 0 errors · `npm run typecheck:app` → 0 errors ·
`npm test` → 11 files / 88 tests passed · `npm run lint` → 0 errors.
Run logs: `docs/agents/agent-4-status.md` (T-136), `docs/agents/agent-26-status.md`
(T-194).
