# Contract — UI Surface Registry v2 (Agent 5, T-111)

> Owner: Agent 5. Consumers: Lead (T-110 Tauri shell + IPC), Agent 2
> (kiwi-mail/kiwi-core data), Agent 3 (findings feed), Agent 4 (policy feed,
> admin UI). Spec: `docs/ui-spec.md` v2. Indexed in `docs/API_CONTRACTS.md`.
> **Rule:** surface IDs are stable. `KIWI-UI-001`…`012` keep their v1 meanings;
> only the host anchors changed (Thunderbird chrome → our React frontend).
> Renaming/removing an ID requires a Lead decision in `docs/DECISIONS.md`.

## 1. Surface registry

### Security surfaces (stable IDs, re-anchored)

| Surface ID | Name | Anchor in kiwi-app frontend | Data source | Spec |
|------------|------|-----------------------------|-------------|------|
| `KIWI-UI-001` | Message security pill + list glyph | Reader header + message-list row glyph | `kiwi-core` session trust for delivering session | ui-spec §4 + §9 S-01 |
| `KIWI-UI-002` | Trust status chip | Top bar + sidebar account node | `kiwi-core` account trust aggregate + lock state | ui-spec §9 S-02 |
| `KIWI-UI-003` | Account security panel | Settings → KIWI Security → per-account card + Account view | `kiwi-core` session detail + `kiwi-forensics` counts + scan timestamps | ui-spec §9 S-03 |
| `KIWI-UI-004` | Finding-detail dialog | Modal from 001/003/009/010 rows | `kiwi-forensics` finding + evidence record | ui-spec §9 S-04 |
| `KIWI-UI-005` | Lock-screen overlay | Full-app overlay above all panes | `kiwi-core` lock policy event + reason category | ui-spec §9 S-05 |
| `KIWI-UI-006` | Authenticator dialog | Modal above 005 / enrollment test | `kiwi-core` challenge (device, event label, expiry) | ui-spec §9 S-06 |
| `KIWI-UI-007` | Composer policy banner + send-block | Composer infobar + Send path | `kiwi-admin` recipient-domain / min-TLS evaluation | ui-spec §5 + §9 S-07 |
| `KIWI-UI-008` | Certificate viewer | Sub-dialog of 003/004 | `kiwi-mail::transport` TlsObservation via Agent 2 (was: NSS/TB hooks) | ui-spec §9 S-08 |
| `KIWI-UI-009` | Re-scan / diff results | 003 section + results dialog | `kiwi-forensics` re-scan + diff model | ui-spec §9 S-09 |
| `KIWI-UI-010` | Security event center | App-nav "Security" view (in-app route, was: TB content tab) | `kiwi-core` + `kiwi-forensics` events; forensics JSON export | ui-spec §9 S-10 |
| `KIWI-UI-011` | Local admin UI | Standalone localhost app (outside kiwi-app) | `kiwi-admin` API (`contracts/admin-api.md`, Agent 4) | ui-spec §9 S-11 |
| `KIWI-UI-012` | Device pairing dialog | Settings → KIWI Security → Devices → "Add device" | `kiwi-core` pairing flow (Phase 4) | ui-spec §9 S-12 |

### App surfaces (new in v2)

| Surface ID | Name | Anchor | Data source (Tauri IPC → backend) | Spec |
|------------|------|--------|-----------------------------------|------|
| `KIWI-UI-013` | App shell + three-pane layout | Root layout (sidebar/list/reader/top bar) | Shell state; sync status per account | ui-spec §1 |
| `KIWI-UI-014` | Folder tree | Sidebar | `kiwi-mail::account` folders + unread counts | ui-spec §2 |
| `KIWI-UI-015` | Unified inbox | Top tree node (virtual view) | `kiwi-mail::store` merged query + sync | ui-spec §2 |
| `KIWI-UI-016` | Message list | Center pane | `kiwi-mail::store` folder query; bulk ops | ui-spec §3 |
| `KIWI-UI-017` | Message reader | Right/below pane | `kiwi-mail::store` body + `mime` render; sanitized HTML | ui-spec §4 |
| `KIWI-UI-018` | Composer | Compose window/route | `kiwi-mail::smtp` send queue; `mime` builder | ui-spec §5 |
| `KIWI-UI-019` | Account setup wizard | First-run + Accounts → Add | `kiwi-mail::account` verify; `transport` TLS observation | ui-spec §7 |
| `KIWI-UI-020` | Snooze | List/reader action + Snoozed folder | Local scheduler + `kiwi-mail::store` return | ui-spec §6 |
| `KIWI-UI-021` | Send later + undo send | Composer send-options + Outbox/Scheduled | `kiwi-mail::smtp` send queue (grace window, schedule) | ui-spec §5 |
| `KIWI-UI-022` | Message templates | Composer picker + Settings CRUD | Local template store (frontend + backend persist) | ui-spec §5 |
| `KIWI-UI-023` | Settings | Settings route (nav sections) | Per-section backend prefs; org-managed flags | ui-spec §8 |

## 2. Severity vocabulary (shared with all data producers)

UI renders exactly these severity tokens from `kiwi-core` / `kiwi-forensics`.
Producers must not send any other severity string.

- `secure` — no findings; all checks passed.
- `warning` — weak/degraded configuration; functional but should be fixed.
- `danger` — plaintext, downgrade/strip indication, invalid chain, or policy
  block condition.
- `unknown` — no data (unevaluated session, IPC unavailable with no cache).
  UI renders grey; never green.
- `locked` — orthogonal overlay state from `kiwi-core` lock policy; any
  severity display is replaced by the lock affordance while active.

## 3. Minimum payload fields the UI needs (requests to data owners)

> Agent 2 (T-101…T-106, T-002) and Agent 3 (T-107) confirm or revise field
> names when their contracts land. UI treats every field as optional at render
> time and falls back to `unknown`/stale-labeled display — missing data must
> never crash or fake a `secure` render.

- Session summary (001/002/003): `sessionId`, `protocol` (smtp/imap/pop3),
  `host`, `port`, `starttls` (bool), `tlsVersion`, `cipherSuite`,
  `keyExchange`, `forwardSecrecy` (bool), `authMechanism`,
  `evaluatedAt` (timestamp), `stale` (bool). Source: `kiwi-mail::transport`
  TlsObservation → `kiwi-core` SecuritySession.
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
  `sha256Fingerprint`, `sigAlg`, `status` per chain hop. Source: rustls peer
  chain captured by `kiwi-mail::transport`.
- Diff (009): `beforeScanAt`, `afterScanAt`, `engineVersion`,
  groups `new[]` / `resolved[]` / `unchanged[]` of finding refs.
- Event row (010): `eventId`, `timestamp`, `accountId`, `category`,
  `severity`, `summary`, `detailRef` (finding/cert/session id).
- Mail views (013–023): field shapes follow Lead's T-110 IPC layer; Agent 5
  will bind the v2 spec views to exact command/event names once the shell
  lands (T-112). Requests: account+folder listing, message envelopes,
  body fetch, send/schedule/undo queue ops, snooze store, template store,
  setup-verify result (incl. TLS observation inline), settings prefs.

## 4. UI guarantees back to data producers

1. Unknown/error/stale renders are always labeled and never green
   (fail-closed display, ui-spec §11).
2. Evidence blocks render verbatim with a copy affordance; UI never edits,
   summarizes, or hides evidence fields.
3. AI text (when present) renders only inside the labeled "AI-generated, not
   authoritative" collapsible in 004 — producers never route authoritative
   verdicts through the AI field.
4. No UI surface transports or displays credentials, private keys, message
   bodies to admin/analytics, or full mailbox content while locked (per
   `docs/SECURITY.md`; S-05 makes content panes inert).
5. Versioning: payloads carry a `contractVersion`; UI ignores unknown fields
   rather than failing (per `docs/API_CONTRACTS.md` invariants).
6. No business logic in the frontend beyond UI state — all verdicts,
   scheduling, sync, and enforcement live in Rust/Node backends; the
   frontend is a renderer of backend state (ARCHITECTURE.md §3).

## 5. Wiring order (after T-110 shell lands)

1. 013/014/015/016/017 read paths (mailbox skeleton over stub IPC).
2. 019 wizard (needs Agent 2 verify + TLS observation, T-101/T-105).
3. 018 composer + 021 send queue + 022 templates + 020 snooze.
4. 001/002/003/004 security read paths (same data as mailbox).
5. 008 cert viewer (rustls chain via transport).
6. 009 re-scan + 010 event view.
7. 007 composer policy (needs Agent 4 bridge, T-108).
8. 005 lock overlay + 006 authenticator (needs Agent 2 lock semantics).
9. 012 pairing, 011 admin UI, 023 org-managed settings rows.
