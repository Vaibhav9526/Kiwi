# Agent 20 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-196: contract-drift audit (read-only)

**Status:** done. Deliverable: `docs/audits/contract-drift-1.md` —
severity-ranked findings for all 11 contract files present in
`docs/contracts/` + `kiwi-integrations` gap notes (no `integrations.md`
exists yet — T-226 in-flight). **No code changed; no commits.**

### Method

Seven parallel read-only sub-audits, one per contract↔code pair (every
contract file read in full; each documented command/route/type/field/enum/
constant located or proven absent in code). I spot-verified 6 high-severity
claims myself — all reproduced (FOR-1/2 serde enum spellings, IPC-2
`SecurityStatusView`, SS-1 locked `required_action` splice, AUTH-1 missing
failure audits, FOR-3 conditional severity, ADM-1 camelCase policies list).

### Totals

10 High · ~47 Medium · ~40 Low · grouped Info items (undocumented public
API surfaces + Phase-4/in-flight gaps). Headline Highs:

- IPC-1/IPC-2 — `AccountView`/`SecurityStatusView` wire shapes diverge from
  ipc.md (renames, missing fields, different enum vocabularies).
- FOR-1/FOR-2 — forensics enums serialize serde-snake_case (`tls12`,
  `start_tls`, `x_o_auth2`) not the contract's `as_str()` spellings;
  `TlsVersion::Unknown` is externally tagged `{"unknown":N}`.
- AUTH-1 — `kiwi_submit_challenge` audits success only; no
  `challenge-denied`/`challenge-verification-failed`/`device-paired` rows.
- SS-1 — locked `TrustMachine` can emit `required_action: None`.
- ACFG-1/MAUTH-1 — T-195 `oauth2` module violates autoconfig's documented
  "no secrets/connections" invariant; `HickoryResolver` documented but
  absent (T-183 in-flight).
- UIS-5/6 — frontend invokes `kiwi_get_prefs`/`kiwi_set_prefs` /
  `kiwi_lookup_autoconfig` — names in no contract and no registry.

Cross-cutting patterns and a suggested fix order are in the report.

### Files changed

`docs/audits/contract-drift-1.md` (new), this file (new). Nothing else.

### Commands run

`git status/branch/log` (read-only), `orca skills get orca-cli`,
directory listings, targeted `read`/`grep` for spot-verification. No
build/test runs (read-only audit; not needed — findings are
source-readable).

### Assumptions

- Working tree `release/v0.1.0 @ 6f74a8b` + uncommitted `admin-api.md`
  edits audited as-found; in-flight work flagged (T-183 mailauth mid-edit,
  T-191 frontend rebuild, T-195 oauth2, T-226 integrations, T-189 held
  snooze, T-193/T-188 admin). Re-verify before acting on those rows.
- `ui-surfaces.md` §3/§5 are explicitly provisional/wiring-order — absent
  surfaces rated M/L not H.
- Severity rubric: H = documented item absent/incompatible or security
  invariant broken; M = name/type/field/order/bound mismatch; L = doc
  drift/hygiene; I = undocumented code or not-yet-implemented feature.

### Risks / open items

- Sub-agent line numbers on `kiwi-mailauth`/`kiwi-autoconfig` may drift —
  edits were landing mid-audit (noted per-finding).
- The `challenge-expired` (ipc.md) vs `expired` (authenticator.md + code)
  row is a contract-vs-contract disagreement needing a Lead ruling.
- `kiwi-integrations` has two dangling "contract is authoritative" code
  references with no contract file; needs the T-226 contract or the refs
  removed.
- DONE report sent to Lead terminal `term_c20c6737…` via `orca terminal
  send`.

## 2026-09-25 — T-237: drift fixes (audit items 6+7)

**Status:** done. Scope-limited fix pass — frontend wrapper names + contract
bookkeeping only. `npx tsc --noEmit` in `kiwi-app` → clean (no `typecheck`
script exists; `tsc` is the check, `noEmit` already set).

### (1) UIS-5/6 — ipc.ts wrapper names

- `kiwi_get_prefs`/`kiwi_set_prefs` → **rebound to the registered §9c API**,
  not a bare rename: the backend is per-key, so `getPrefs()` now calls
  `kiwi_prefs_list` and folds `{key,value}[]` into the bag callers expect;
  `setPrefs(bag)` pushes each entry through `kiwi_prefs_set` (first rejection
  aborts — callers still see failure rather than a silent partial write).
- `kiwi_lookup_autoconfig` → **`kiwi_discover_account`** (the
  contract-ratified name at ipc.md:188). The handler lands with T-230, so the
  wrapper is still wrapped-but-absent — verified both call sites degrade to
  the labeled local guess / manual-entry fallback (`setup.tsx:160-176`,
  `settings.tsx:183-189`); comments updated to say so.
- Stale name references fixed in `prefs.ts:6`, `settings.tsx:6,100`,
  `setup.tsx:3,28`, `kiwi.ts:434`.

### (2) Contract bookkeeping

- `API_CONTRACTS.md` index now lists **all 14** `contracts/*.md` (task said
  13 — `rules.md` (kiwi.rules/1, Agent 22/T-236) also exists post-snapshot;
  indexed it too). Each row carries owner + contract-version + status from
  the file's own header.
- `challenge-expired` conflict resolved by keeping the **Lead-ratified**
  `challenge-expired` (ipc.md §9d.9/§9d.11-1 ratified it 2026-09-25; it
  namespaces cleanly against `pairing-ticket-expired`):
  `authenticator.md:265-266` now says `challenge-expired` and flags the
  legacy `expired` emitted by pre-migration builds; `ipc.md:123-127` gained
  the same one-line current-state note so §4 alone isn't misleading.
- `admin-api.md`: the T-193 staleness was **already fixed in the working
  tree** (lines 57-64 fail-closed scope + H4 default, line 74 `org.create`
  cell, line 85 mailflow note, §12.3 explicit org-bound default) — ADM-2 and
  ADM-6 verified covered, no rewrite needed. Added the one missing symmetric
  note to the `GET /api/v1/audit` row (line 86).

### Files changed

`kiwi-app/src/{ipc.ts, prefs.ts, kiwi.ts, views/settings.tsx,
views/setup.tsx}`, `docs/API_CONTRACTS.md`,
`docs/contracts/{authenticator.md, ipc.md, admin-api.md}`, this file.
**Not touched:** src-tauri rust, rules/, mailauth/, oauth2 rust.

### Assumptions / risks

- `kiwi_discover_account` chosen over keeping `kiwi_lookup_autoconfig`:
  the contract name is ratified (T-178) and the backend lands in T-230 —
  pointing at the contract name now means the wrapper works the day the
  handler registers. Flagged here so Lead can correct cheaply if T-230
  intends a different name.
- `setPrefs` aborts on first per-key rejection (`saved` reports partial
  count); callers surface that as a failed sync — honest, not hidden.
- Not committed — Lead integrates.

## 2026-09-25 — T-239: wire-shape reconciliation (audit items 1+4)

**Status:** done. Scope honored: `kiwi-core/src/trust.rs` (SS-1, mandated by
item 2), `kiwi-app/src-tauri/src/types/{mod,accounts}.rs`,
`kiwi-app/src/kiwi.ts`, `docs/contracts/ipc.md`. **Not touched:** commands/,
rules/, oauth2 rust, integrations, mailauth.

### (1) IPC-1 `AccountView` — contract right, struct fixed

The frontend was authored to the contract (`a.trustToken`/`unreadCount`/
`incomingProtocol`/`incoming.*`/`username` read at `state/accounts.ts:36-37`,
`App.tsx:220`, `settings.tsx:203,269`); the Rust view emitted none of them,
so live accounts rendered `unknown` trust / 0 unread / missing servers.
Fixed `types/accounts.rs` to emit the §5 shape verbatim: nested
`incoming`/`outgoing` `ServerView{host,port,security}` (new `socket_security`
map in `types/mod.rs`, same `plaintext|starttls|tls` spelling `ServerInput`
accepts), `username` (`MailAccount.incoming.username`), `unreadCount`,
`trustToken`. `account_view` signature unchanged — zero `commands/` churn.

`trustToken` vocab kept contract (`trusted|warning|locked|unknown`):
severity roll-up is Info|Low→`trusted`, Medium→`warning`,
High|Critical→`locked` — `locked` is the vocab's only danger-tier token and
the frontend maps it to the `danger` chip; `degraded`/`warning` would
*understate* Critical signals. `degraded` documented as reserved/not
emitted (ipc.md §5 note).

### (1) IPC-2 `SecurityStatusView` — code right, contract amended

- `endpointSignals`/`knownDevices` **dropped from ipc.md §3** (code right):
  populating them requires `commands/mod.rs::status_view` (out of this
  task's boundary), zero frontend consumers read them (`toTrustState`
  ignores them; only the kiwi.ts interface declared them — removed there),
  and the data is already reachable via `kiwi_collect_endpoint_signals` (§10)
  and `kiwi_list_devices` (§9). §3 now documents the emitted shape:
  `trust`, `state`, `score`, `locked`, `requiredAction`, `signals`,
  `sessionsObserved`, `deviceId` — plus a note saying detail lives behind
  the dedicated commands. If Lead wants them embedded it's a commands/
  follow-up, one line in `status_view`.
- `requiredAction` vocab amended to the **kiwi-core `RequiredAction`**
  spellings `none|warn-user|require-reauth|require-authenticator-unlock|
  block-access` — security-session.md §4 ratifies those; the old
  `notify-user`/`require-authenticator` were stale.
- `trust`/`sessionsObserved`/`deviceId` extras documented (code right —
  `trust` is the ui-surfaces §2 token, §9d.6's example already showed them).
- `kiwi.ts SecurityStatusView` updated to the ratified wire shape.
- Also fixed a stale `SignalView` example (`starttls-stripped` →
  `starttls-downgrade-suspected`).

### (2) SS-1 — locked `TrustMachine` emitted `required_action: None`

`TrustMachine::evaluate` spliced `state: self.state` but kept the fresh
eval's `required_action` — a still-locked machine on a clean/weak eval
reported `None`. Now when `self.state == Locked` the returned
`TrustEvaluation.required_action` is forced to
`RequireAuthenticatorUnlock` (default) or `BlockAccess` when
`policy.unlock_requires_authenticator` is false — same derivation as the
free `evaluate`'s Locked arm and `commands/mod.rs::status_view`.
Regression tests: `locked_does_not_self_recover` extended with the action
assert; new `locked_keeps_block_action_without_authenticator_policy`
(non-authenticator policy → `BlockAccess`). `kiwi-core` is the authority —
`status_view` already compensated; consumers of `refresh_trust()`
(`observe.rs:104`, `endpoint.rs:40`) now get the correct eval.

### (3) Serde posture note — ipc.md §1

Documented the actual strategy (verified by grep: zero `deny_unknown_fields`
/`serde(other)` in types/, no Deserialize enums): consumers ignore unknown
view fields; inputs ignore unknown fields; enum inputs are strings
validated by parse fns → `invalid-input` (fail closed); unknown enum
*outputs* must render `unknown`, never pass. This is the cross-cutting
FOR-6/MAUTH-5 answer for the IPC layer specifically; the forensics-crate
serde spellings (FOR-1/2) remain a separate decision.

### Files changed

`kiwi-core/src/trust.rs`, `kiwi-app/src-tauri/src/types/{mod.rs,
accounts.rs}`, `kiwi-app/src/kiwi.ts`, `docs/contracts/ipc.md`, this file.

### Verification

- `cargo test -p kiwi-core -p kiwi-app` — **33 core + 87 app tests, all
  green** (incl. both new lock-action tests).
- `npx tsc --noEmit` — clean.
- Caveat: first build hit a transient kiwi-mail mid-write error
  (`UpstreamAuthEvidence` Default) — T-232 agent was mid-edit; resolved on
  retry, unrelated to this change.

### Assumptions / risks

- `username` emitted = `MailAccount.incoming.username` (primary identity);
  `outgoing.username` stays internal (contract has no `outgoingUsername`
  field on the view).
- `AccountView` now carries `security` per direction — no secret material;
  consistent with the never-secrets rule.
- Not committed — Lead integrates.
