# Contract — UI Surface Registry (Agent 5, T-005)

> Owner: Agent 5. Consumers: Agent 2 + Lead (Thunderbird wiring), Agent 3
> (findings feed S-04/S-09/S-10), Agent 4 (policy feed S-07, admin UI S-11).
> Spec: `docs/ui-spec.md`. Indexed in `docs/API_CONTRACTS.md`.
> **Rule:** surface IDs are stable. Renaming/removing an ID requires a Lead
> decision recorded in `docs/DECISIONS.md`. New surfaces append new rows.

## 1. Surface registry

| Surface ID | Name | Host window / anchor (provisional until T-007) | Data source | Spec |
|------------|------|------------------------------------------------|-------------|------|
| `KIWI-UI-001` | Message security pill | Message header bar; icon column (opt-in) in thread pane | `kiwi-core` session trust for the delivering session | ui-spec §1 S-01 |
| `KIWI-UI-002` | Account security chip | Folder-pane account row (icon) + status bar (text chip) | `kiwi-core` account trust aggregate + lock state | ui-spec §1 S-02 |
| `KIWI-UI-003` | Account security panel | Account Settings → "KIWI Security" section; summary card in account hub | `kiwi-core` session detail + `kiwi-forensics` finding counts + scan timestamps | ui-spec §1 S-03 |
| `KIWI-UI-004` | Finding-detail dialog | Modal from 001/003/009/010 rows | `kiwi-forensics` finding + evidence record (one finding) | ui-spec §1 S-04 |
| `KIWI-UI-005` | Lock-screen overlay | Full mail-window chrome overlay | `kiwi-core` lock policy event + reason category | ui-spec §1 S-05 |
| `KIWI-UI-006` | Authenticator dialog | Modal above 005 (or standalone enrollment test) | `kiwi-core` challenge (device name, event label, expiry) | ui-spec §1 S-06 |
| `KIWI-UI-007` | Composer policy banner + send-block | Compose window infobar slot + Send path | `kiwi-admin` recipient-domain / min-TLS evaluation | ui-spec §1 S-07 |
| `KIWI-UI-008` | Certificate viewer | Sub-dialog of 003/004 | NSS/cert data via TB hooks (Agent 2 adapter, T-011) | ui-spec §1 S-08 |
| `KIWI-UI-009` | Re-scan / diff results | Section of 003 + results dialog | `kiwi-forensics` re-scan + diff model | ui-spec §1 S-09 |
| `KIWI-UI-010` | Security event center tab | Thunderbird content tab ("KIWI Security") | `kiwi-core` + `kiwi-forensics` events; export via forensics format | ui-spec §1 S-10 |
| `KIWI-UI-011` | Local admin UI | Standalone localhost React+TS app (outside TB chrome) | `kiwi-admin` API contract (`contracts/admin-api.md`, Agent 4) | ui-spec §1 S-11 |
| `KIWI-UI-012` | Device pairing dialog | Account Settings → KIWI → Devices → "Add device" | `kiwi-core` pairing flow (Phase 4, `contracts/authenticator.md`) | ui-spec §1 S-12 |

## 2. Severity vocabulary (shared with all data producers)

UI renders exactly these severity tokens from `kiwi-core` / `kiwi-forensics`.
Producers must not send any other severity string.

- `secure` — no findings; all checks passed.
- `warning` — weak/degraded configuration; functional but should be fixed.
- `danger` — plaintext, downgrade/strip indication, invalid chain, or policy
  block condition.
- `unknown` — no data (local folders, unevaluated session, IPC unavailable
  with no cache). UI renders grey; never green.
- `locked` — orthogonal overlay state from `kiwi-core` lock policy; any
  severity display is replaced by the lock affordance while active.

## 3. Minimum payload fields the UI needs (requests to data owners)

> Agent 2 (T-002/T-011) and Agent 3 (T-003) confirm or revise field names when
> their contracts land. UI treats every field as optional at render time and
> falls back to `unknown`/stale-labeled display — missing data must never
> crash or fake a `secure` render.

- Session summary (001/002/003): `sessionId`, `protocol` (smtp/imap/pop3),
  `host`, `port`, `starttls` (bool), `tlsVersion`, `cipherSuite`,
  `keyExchange`, `forwardSecrecy` (bool), `authMechanism`,
  `evaluatedAt` (timestamp), `stale` (bool).
- Finding (004/009/010): `findingId`, `severity` (§2), `title`,
  `sessionRef`, `evidence` (verbatim block + `evidenceKind`), `impact`,
  `remediation[]`, `engineVersion`.
- Lock event (005): `locked` (bool), `reasonCategory` (display-safe enum,
  never raw sensor dumps), `policyName`.
- Challenge (006): `eventLabel` (e.g. "Unlock mailbox"), `deviceName`,
  `deviceFingerprintTail`, `expiresAt`, `status`
  (waiting/approved/denied/expired/error).
- Policy evaluation (007): per-recipient `address`, `verdict`
  (allow/warn/block), `ruleId`, `scopeNote` (client-only enforcement text).
- Certificate (008): `subject`, `issuer`, `serial`, `notBefore`, `notAfter`,
  `sha256Fingerprint`, `sigAlg`, `status` per chain hop.
- Diff (009): `beforeScanAt`, `afterScanAt`, `engineVersion`,
  groups `new[]` / `resolved[]` / `unchanged[]` of finding refs.
- Event row (010): `eventId`, `timestamp`, `accountId`, `category`,
  `severity`, `summary`, `detailRef` (finding/cert/session id).

## 4. UI guarantees back to data producers

1. Unknown/error/stale renders are always labeled and never green
   (fail-closed display, ui-spec §3).
2. Evidence blocks render verbatim with a copy affordance; UI never edits,
   summarizes, or hides evidence fields.
3. AI text (when present) renders only inside the labeled "AI-generated, not
   authoritative" collapsible in 004 — producers never route authoritative
   verdicts through the AI field.
4. No UI surface transports or displays credentials, private keys, message
   bodies, or full mailbox content (per `docs/SECURITY.md` rules 5–6; S-05
   additionally makes content panes inert while locked).
5. Versioning: payloads carry a `contractVersion`; UI ignores unknown fields
   rather than failing (per `docs/API_CONTRACTS.md` invariants).

## 5. Wiring order (after T-007 source map)

1. 001 + 002 read-only indicators (lowest risk, cached session state).
2. 003 panel + 004 dialog (read paths over the same data).
3. 008 cert viewer (reuses TB viewer patterns where possible).
4. 009 re-scan + 010 event tab.
5. 007 composer policy (send-path gating — needs Agent 4 policy contract first).
6. 005 lock overlay + 006 authenticator (needs Agent 2 lock-state semantics).
7. 012 pairing, 011 admin UI (Phase 4 / Phase 6).
