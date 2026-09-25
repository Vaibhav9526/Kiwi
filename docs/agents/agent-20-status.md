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

## 2026-09-25 — T-245: FSV-1 forensics serde vocabulary (ratified spec)

**Status:** done. Implemented `docs/audits/for-serde-vocab-1.md` across
`kiwi-forensics`; `CONTRACT_VERSION` → `kiwi.forensics/2` (spec-recommended
bump; `rule_catalog_version` and `scoring_model_version` untouched).

### What changed (code)

- `model/tls.rs` — `TlsVersion` got a custom `Deserialize`: canonical
  snake tags (`ssl2`..`tls13`), externally-tagged `{"unknown": <u16>}`
  (payload preserved), plus legacy aliases `ssl2.0`/`ssl3.0`/`tls1.0`–
  `tls1.3` and bare `"unknown"` → `LEGACY_UNKNOWN_WIRE = 0xFFFF`
  (documented sentinel — the `/1` bare string carried no payload, so no
  raw value is fabricated). Unknown tags still fail closed.
- `CaptureFormat`, `LinkType` (`pcap/mod.rs`) — added
  `rename_all = "snake_case"` + PascalCase aliases (`ClassicPcap`,
  `PcapNg`, `Ethernet`, `{"Other": N}`); payloads preserved on read.
- Legacy `as_str()` aliases on `TransportSecurity` (`starttls`),
  `AuthMechanism` (`cram-md5`, `digest-md5`, `xoauth2`, `oauthbearer`,
  `oauth_bearer`, `scram-sha-1`, `scram-sha-256`, `scram-sha-256-plus`,
  `scram-sha-512-plus`), `BulkCipher` (`3des`, `chacha20_poly1305`),
  `Grade` (`A`–`F`), `ChangeKind` (`added`, `persisting`),
  `FindingCategory` (`starttls`), `EvidenceKind`
  (`starttls_negotiation`). Canonical writes stay snake_case.
- `EvidenceValue` untouched — internally tagged `type` (contract-exact
  exception). **Zero `as_str()` body changes** (verified in commit diff:
  no `=> "` hunk). Finding IDs, subject keys, scoring unchanged.
- `model/mod.rs` re-exports `LEGACY_UNKNOWN_WIRE`.

### Spec corrections found by the fixture tests (documented)

- `AuthMechanism::OAuthBearer` canonical is `o_auth_bearer` (serde
  splits `O|Auth|Bearer`), not the spec's `oauth_bearer`; both legacy
  spellings accepted as aliases.
- `FindingCategory::StartTls`/`EvidenceKind::StartTlsNegotiation`
  canonical are `start_tls`/`start_tls_negotiation`, not
  `starttls`/`starttls_negotiation` as the spec table claimed — those
  were real divergences (as_str spellings, now read-aliases).

### Tests / fixtures

- `tests/fixtures/fsv1_canonical.json` — all 27 serde-carrying enums,
  every variant, canonical write form (frozen).
- `tests/fixtures/fsv1_legacy.json` — `/1` spellings incl. lossy bare
  `"unknown"` and payload-bearing `{"ClassicPcap":…}`/`{"Other":N}`.
- `tests/fsv1_serde.rs` — 5 tests: canonical round-trip per variant,
  legacy read→canonical write (lossy `unknown` via `None` index),
  `Report::to_json`/`from_json` crossing the migration boundary,
  `TlsVersion::Unknown(0x4A4A)` wire-value preservation, unknown-tag
  fail-closed.

### Contracts

- `forensics.md` — header `/2`, §1 invariant dual-read, §2 enum
  spellings canonical + `{"unknown":N}`, §3 `start_tls` category,
  §6 `grade` wire note, §9 semantic-vs-wire clarification, §11 severity
  note, **new §12** (FSV-1 rules, dual-read alias inventory,
  `LEGACY_UNKNOWN_WIRE` sentinel, single-write, fixture pointer).
- `ipc.md` — `kiwi.forensics/2` at §6 probe / §8 findings+detail+report;
  SessionView note distinguishing session tokens (`tls1.3`, `xoauth2`,
  `hostname-mismatch`, `starttls`) from forensics FSV-1 tags.

### Verification

- `cargo test -p kiwi-forensics` — all green (8 suites, incl. 5 fsv1).
- `cargo clippy -p kiwi-forensics --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — clean after fixing one rustfmt
  line-wrap in `kiwi-autoconfig/src/autoconfig_xml.rs:113` (Agent 19's
  in-flight file; zero-semantic hunk, disclosed).

### Assumptions / risks

- `src/` changes were swept into A15's commit `fbc3c76` (shared-tree
  `add -A`); content verified correct at HEAD. Only
  `tests/fsv1_serde.rs` remains in my uncommitted diff.
- `LEGACY_UNKNOWN_WIRE = 0xFFFF` reads as `{"unknown":65535}` on re-emit
  — irrecoverable-value marker, never a real negotiated version.
- Dual-read covers `/1` spellings enumerated in §12; any other historical
  spelling fails closed by design.

## 2026-09-25 — T-247: wire-shape batch 2 (T-241 queue + FOR leftovers)

**Status:** done. Four IPC reconciliations + three forensics leftovers.
Direction per item chosen by consumer evidence.

### Per-item decisions

**(1) IPC-6 `FolderView` → code right, contract amended.** `exists`/
`unseen` require a per-folder `COUNT` query that does not exist in
`kiwi-mail::store` (no count fn; `FolderMeta`/`FolderEntry` carry no
counts) — producing them would need commands/ + store changes, both
outside scope; emitting zeros would fabricate data. ipc.md §6 now
documents the real shape (`id, accountId, name, uidValidity|null,
uidNext|null, highestUid`), marks `exists`/`unseen` **withdrawn**, and
notes the unread-badge gap as a follow-up store task. `kiwi.ts`
interface updated; `unseen` kept `?: number` so badge code (`accounts.ts`
reads it, always absent today → 0) can adopt it when a count query lands.

**(2) IPC-7 `MessageView` → contract names win for `from`/`to`; contract
amended for extras + nullability.** The frontend reads `fromAddr`/
`toAddrs` everywhere (`mailbox.ts:47`, `App.tsx:83`, search-hit reader),
matching `SearchHitView`'s existing convention — serde `rename` added in
`types/mail.rs`. ipc.md §6 now documents the full emitted shape incl.
`unread`/`starred`/`bodyStored`/`category`/`unsubscribe*`/`auth`/
`attachRisk` and honest `| null` nullability. **Fixed a live dead
feature**: `parseUnsubscribe` read snake_case keys but serde emits
camelCase — now reads `unsubscribeUrl`/`Mailto`/`OneClick` (snake kept
as fallback). `kiwi.ts` interface rewritten to the real wire shape.

**(3) IPC-8 → canonical `vcardText`.** Rust param `vcard_text` → Tauri
camelCase `vcardText`; commands/ off-limits so contract yields.
ipc.md §9b + contacts.md now say `vcardText` (export response key
`{vcard}` unchanged — different surface, documented).

**(4) IPC-9 → serde rename.** `#[serde(rename_all = "camelCase")]` on
`EndpointObservation` (signals.rs — a view producer, not commands/rules/
oauth2/auth): `evidence_ref` → `evidenceRef`, matching `SignalView` and
the contract; frontend treats the report opaquely, no consumer break.

**(5) FOR-3** — forensics.md §5 documents KIWI-TRANSPORT-001's
High→Critical escalation when a reusable secret crossed in the clear.

**(6) FOR-4** — the three dormant flags are now live:
- `reject_broken_ciphers` gates `rule_cipher_broken` (same pattern as
  weak/legacy siblings) — `permissive()` no longer emits CIPHER-001.
- `require_tls13` is wired via `SecurityPolicy::effective_min_tls_version()`
  (shorthand for a TLS 1.3 floor); TLS-001 compares against it and
  reports the *effective* floor in evidence. strict()/default unchanged
  (strict already sets `min_tls_version: Tls13`).
- `report_cleartext_auth_under_tls` gates AUTH-002 for reusable-secret
  mechanisms under a protected channel only — challenge-response/
  anonymous deprecation stays governed by `report_deprecated_auth`.
`rule_catalog_version` kept at 1: gate wiring restores documented flag
semantics; no rule identity or default-policy output changed (noted in
forensics.md §5/§12 — flag for Lead ratification).

**(7) FOR-5** — `score_findings` now rounds each finding's deduction
half-up before summing (contract §6 wording); 2×High/Tentative now
deducts 26 not 25. `SCORING_MODEL_VERSION` → `kiwi-score-2` (the spec's
own rule: scoring changed, spelling didn't drive it); forensics.md §6
header + §12 bullet + `report/mod.rs` doc updated.

### Files changed

`types/mail.rs` (rename attrs), `signals.rs` (camelCase attr),
`types/security.rs` (doc), `kiwi-forensics/src/rules/{crypto,policy,
auth}.rs`, `score.rs`, `lib.rs`, `report/mod.rs`, `kiwi-app/src/kiwi.ts`,
`docs/contracts/{ipc,contacts,forensics}.md`. Plus two zero-semantic
rustfmt hunks in T-254's in-flight `kiwi-mail/src/{mime.rs,store/mod.rs}`
to satisfy `cargo fmt --all --check` — disclosed.

### Verification

- `cargo test -p kiwi-forensics` — 100 unit + all suites green incl. 4
  new regressions (`permissive_suppresses_broken_cipher_like_its_siblings`,
  `require_tls13_raises_the_effective_floor`,
  `cleartext_mechanism_under_tls_respects_report_flag`,
  `per_finding_rounding_sums_rounded_points`).
- `cargo test -p kiwi-app` — 98 green.
- `cargo clippy -p kiwi-forensics --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — clean (after the disclosed kiwi-mail hunks).
- `npx tsc --noEmit` — clean.

### Assumptions / risks

- `signals.rs` is outside `types/` but is a wire-view producer, not
  commands/rules/oauth2/auth — judged in-scope for the rename.
- `require_tls13` semantics chosen: effective-floor shorthand (field doc
  says "Require TLS 1.3 specifically"); alternative was deleting the
  redundant field — kept for API stability.
- Earlier T-245 hunks + this task's contract edits were swept into
  concurrent commits again (`9c7255d`, `033af05`, `83847e3`); content
  verified correct at HEAD.
- Scores under `/2` can differ by ±1pt in fractional cases vs stored
  `/1` scores — `model_version` records which produced them.

## 2026-09-25 — T-265: register cleanup (FINDINGS IPC-11..14 + FOR-7/8/9)

**Status:** done. Four IPC reconciliations + three forensics leftovers.
Direction per item chosen by consumer evidence and contract convention.

### Per-item decisions

**(1) IPC-11 `MessageBodyView` → contract amended.** `subject`,
`dateUnix`, `textBody`, `attachments[].filename` are `Option` in
`types/mail.rs`; forcing non-null would fabricate data when a MIME part
is absent. ipc.md §6 shape now shows `| null` + an honest-absence note
(`textBody: null` + `bodyPresent: true` = no text/plain alternative).
`kiwi.ts` interface updated to match; `inReplyTo`/`references` were
missing from the interface entirely — added (code emits them, contract
documents them). `mailbox.tsx` renders `body.textBody` inline — React
drops nulls, consumer-safe.

**(2) IPC-12 → contract amended.** `OutboxItem.accountId`: producers
always emit `Some` today — the `Option` is headroom for pre-binding
queue rows; contract now `| null` with a "tolerate null" client note.
`DeleteResultView.trashFolderId`: `| null`, documented as null when
nothing moved (`movedToTrash > 0` ⇒ set). `kiwi.ts` mirrors updated;
`uidMap` was missing from the interface — added.

**(3) IPC-13 → contract amended.** `DeviceView.keyFingerprintTail`
documented in §9: last 8 hex of SHA-256 over the raw public key —
display fingerprint only (ui-surfaces §3), explicitly NOT an auth token.
`kiwi.ts.DeviceView` updated.

**(4) IPC-14 → code fixed (bytes win).** `kiwi_render_body` capped with
`chars().take(8Mi)` — a char count, so multibyte payloads could emit far
more than the documented 8 MiB. Now `truncate_to_byte_cap()` —
`is_char_boundary` walk-back, never splits a code point, output always
valid UTF-8 ≤ 8 MiB. Contract wording sharpened ("8 MiB of UTF-8
bytes"). commands/message/render.rs touched per the task's explicit
code-fix directive; minimal diff, no behavior change beyond the cap
unit. Test in commands/message/mod.rs proves boundary behavior at small
caps.

**(5) FOR-7 → omit when unobserved.** `server_reply_ok` now has
`skip_serializing_if = "Option::is_none"` — matching the contract's `?:`
marker and sibling optionals (`TlsObservation::sni`,
`AuthObservation::mechanism`/`succeeded` already omit). Deserialization
is unaffected (absent Option → `None`; legacy `"server_reply_ok": null`
also reads as `None` — dual-read safe). Contract unchanged — `?:` was
already right.

**(6) FOR-8 → code titles aligned to catalog.** CERT-006..010 `RuleSpec`
titles now match forensics.md §5 verbatim (001..005 already matched).
Ids/severities untouched; `FindingKey` uses rule_id + subject_key so
diff semantics unchanged. `rule_catalog_version` kept at 1 (title is
display text, not identity — same rationale as T-247's ratified v1).

**(7) FOR-9 → contract amended.** §3 now documents the real
`ChangeKind` vocabulary — `new | resolved | unchanged |
severity_increased | severity_decreased` — with semantics per tag and
the §12 legacy aliases (`added`→`new`, `persisting`→`unchanged`).

### Files changed

`commands/message/render.rs` (byte cap + helper), `commands/message/
mod.rs` (cap test), `kiwi-forensics/src/model/mod.rs` (skip attr),
`kiwi-forensics/src/rules/certificate.rs` (5 titles),
`kiwi-app/src/kiwi.ts` (MessageBodyView/MessageAttachmentView/
DeleteResultView/DeviceView/OutboxItem), `docs/contracts/ipc.md`
(MessageBodyView + OutboxItem + DeleteResultView + DeviceView +
render-cap wording), `docs/contracts/forensics.md` (§3 ChangeKind).

### Verification

- `cargo test -p kiwi-forensics` — 100 unit + all suites green.
- `cargo test -p kiwi-app` — **106 green** incl.
  `render_cap_is_bytes_and_never_splits_a_char` (byte-cap boundary
  test: multibyte payload over a small cap drops rather than splits).
- `npx tsc --noEmit` — clean.
- `cargo clippy -p kiwi-forensics --lib -- -D warnings` — clean.
- `cargo fmt` on touched files — clean. Workspace `--all` clippy/fmt
  currently flags only T-266's in-flight files (`commands/sandbox.rs`,
  `e2e.rs`, `state.rs` — unused imports/dead fields while A21 iterates);
  none in this change's files. Re-check at integrate time.

### Assumptions / risks

- `commands/message/` touched only for the directed IPC-14 byte-cap fix;
  no other commands/ files changed.
- Workspace was mid-edit by T-266 (sandbox-open IPC) during verification
  — transient compile breaks in `state.rs`/`commands/sandbox.rs` are
  theirs; the suite passed after their module file landed.
- `keyFingerprintTail` is informational — documented as display-only so
  no reader treats an 8-hex tail as an authentication signal.

## 2026-09-25 — T-271: register finish (IPC-16 + IPC-5 + FINDINGS sweep)

**Status:** done. Event listener wired, error codes documented, register
swept — 25 rows flipped to `fixed`, remaining-open rows annotated with
exact work left.

### Per-item decisions

**(1) IPC-16 — listener landed.** `onMailChanged(handler)` in ipc.ts
(`listen<MailChangedEvent>` over `kiwi://mail-changed`, typed payload,
`BackendUnavailableError` off-webview) + `MailChangedEvent` interface in
kiwi.ts. **Consumer is App.tsx, not `useMailbox`** — mid-wiring I found
`useMailbox` is still dead code (UIS-19 confirmed again: exported,
never invoked; App.tsx owns `mailboxRev`/`loadFolders`/`notify`). The
effect subscribes once at App level, debounces ~300 ms (a sync bursts
per folder), collapses into ONE `mailboxRev` bump + `loadFolders()`,
and accumulates `newMessages` into a single `info` toast. ipc.md §6
documents the consumer + a MUST-debounce note (naive per-event reload
re-enters `listMessages` under the worker).

**(2) IPC-5 — catalog completed.** `not-locked` and
`authenticator-required` added to the ipc.md §11 error table with
semantics from `UnlockError` (`error.rs:84-92`): not-locked is
informational (treat as already-unlocked); authenticator-required names
the remediation path (`kiwi_request_challenge`/`kiwi_submit_challenge`).

**(3) Sweep — `FINDINGS.md` re-run against HEAD.**

Flipped `fixed` (25 rows): IPC-5/6/7/8(+CON-1)/9/11/12/13/14/16,
FOR-1..9, FOR-11, FOR-12, MAUTH-2/3 (per T-258 verification appendix),
UIS-5/6 (T-237 hunks now committed at HEAD). Opportunistic same-session
closes while sweeping: FOR-6 §1 wording reconciled with §12
fail-closed-for-variants (the two contract clauses contradicted each
other); FOR-11 §10 documents the `CaptureReport{report,diagnostics}`
wrapper; FOR-12 §7 spells out sort directions (severity desc → rule_id
asc → subject_key asc → confidence desc, matching `sort_findings`).

Verified still-open with remaining work noted inline: IPC-3 (nonceHex
still emitted; `nonceB64` migration pending), IPC-15 (6 wrappers still
absent — list in row), FOR-10 (3 limitation constants un-emitted; emit
sites or reserved-vocab amend), AUTH-1 (no failure-audit rows),
UIS-13/14/17/19/21. Not re-verified: rows owned by in-flight tasks
(AUTH-2.., SS-2.., ACFG-*, MAUTH-1/4..8, ADM-*, SBX-*, PAIR-*, CON-*,
UIS-1..22 rest, INT) — left as recorded.

**Late-arriving context:** T-264 landed `FolderView.exists`/`unseen`
(the count-query gap I flagged in T-265) — contract + kiwi.ts already
updated by that task; IPC-6's documented shape is now superseded-but-
coherent.

### Files changed

`kiwi-app/src/ipc.ts` (listen import + `onMailChanged`), `kiwi.ts`
(`MailChangedEvent`), `App.tsx` (debounced subscription effect),
`docs/contracts/ipc.md` (event consumer note + §11 codes),
`docs/contracts/forensics.md` (§1 unknown-tag clause, §7 sort
directions, §10 CaptureReport), `docs/audits/FINDINGS.md` (25 flips +
T-271 sweep section + queue summary refresh).

### Verification

- `cargo test -p kiwi-app` — **112 green**.
- `npx tsc --noEmit` — my files clean; 22 remaining errors are all
  T-267's mid-flight rebuild (`components/icons.tsx` barrel, `Icon.tsx`
  fill prop, `chrome.tsx` onSubmitSearch, `views/mailbox.tsx` onPick,
  plugins/registry safeParse). Re-run at integrate.

### Assumptions / risks

- `App.tsx` is the correct subscription site BECAUSE `useMailbox` is
  dead code — flagged in the sweep so UIS-19's owner knows the listener
  needs relocating if the hook ever gets adopted.
- Toast fires on the connect-time `reason:"sync"` pass too when new
  mail arrived — documented behavior (honest arrival count).
- No backend/Rust changes this task; wire event shape was already
  correct (syncer.rs emit verified field-for-field).

## 2026-09-25 — T-272: last non-T-269 register items (FOR-10 + IPC-15 + AUTH-1 note)

Scope: emit the three defined-but-un-emitted forensics limitation codes;
close the frontend wrapper inventory; annotate AUTH-1 ownership.

### Per-item decisions

**FOR-10 — emit sites landed (correctness fix, not reserved-vocab).**
Added `report::session_limitation_codes(&ConnectionSecurityEvent)` — the
single shared classifier over the event's own fields:
- `transport-unknown`: `transport == Unknown` (adapter-fed sessions) OR
  capture-path flows that carried bytes but yielded zero decodable lines
  (skipped before `analyze` — counted in the skip branch).
- `kex-unobserved`: `tls.session_resumed || !tls.handshake_complete`, OR
  a STARTTLS upgrade accepted (`server_reply_ok == Some(true)`) whose
  handshake bytes never appeared (`!handshake_completed`) — the second
  arm is reachable in the pcap path today (binary post-upgrade bytes
  decode as opaque lines, not a handshake).
- `auth-unobserved`: `is_encrypted() && (auth.is_none() ||
  auth.attempts == 0)`.

Emit sites: `analyze_capture` session loop (counts per code, one
limitation row each after the loop, matching existing emit style) and
`kiwi_security_report`'s live aggregation — live path emits
`auth-unobserved` only via `protected_without_auth()` over
`SecuritySession`: kiwi-core `TransportSecurity` has no `Unknown`
variant and `SecuritySession` carries no resumption/missing-handshake
flag (`key_exchange_group: None` is ambiguous — static-RSA suites
legitimately have none), so emitting the other two on the live path
would fabricate. Contract forensics.md §8 now documents the emit
conditions per code.

**IPC-15 — enum'd registered vs wrapped, wrapped only what exists.**
Full sweep of `generate_handler!` against `ipc.ts` found 10 unwrapped
registered names (finding listed 6). Landed 7 typed wrappers:
`syncStatus`→`kiwi_sync_status`, `scheduleSend`→`kiwi_schedule_send`,
`contactsByTag`→`kiwi_contacts_by_tag`, `contactTags`→`kiwi_contact_tags`,
`importVcards`→`kiwi_import_vcards` (wire arg `vcardText`),
`exportVcards`→`kiwi_export_vcards`, `prefsGet`→`kiwi_prefs_get`.
Three were documented compat aliases already covered by canonical
wrappers (`kiwi_lookup_autoconfig`→`kiwi_discover_account`,
`kiwi_list_devices`→`device_list`, `kiwi_revoke_device`→`device_revoke`)
— not double-wrapped. New kiwi.ts wire types: `SyncStatusView`,
`SendReceipt`, `TagCountView`, `ImportIssueView`, `VCardImportView`,
`VCardExportView` — all matching serde camelCase shapes in
`types/{mail,send,contacts}.rs`.

**AUTH-1 — annotated only.** Row now records A11/T-269 ownership of
`submit_challenge` failure audits (in-flight); pair code untouched per
Lead direction. Row stays `open`.

### Files changed

`kiwi-forensics/src/report/mod.rs` (`session_limitation_codes` + test),
`kiwi-forensics/src/pipeline.rs` (counters + 3 emits + undecodable-flow
count), `kiwi-app/src-tauri/src/commands/security.rs`
(`protected_without_auth` + live emit + test),
`kiwi-forensics/tests/capture_pipeline.rs` (3 integration tests),
`kiwi-app/src/kiwi.ts` (6 wire types), `kiwi-app/src/ipc.ts` (7 wrappers
+ stale contacts comment fix), `docs/contracts/forensics.md` (§8 emit
conditions), `docs/audits/FINDINGS.md` (FOR-10/IPC-15 → fixed, AUTH-1
ownership note, UIS-13/14/17 wrapper-landed annotations, sweep bullets).

### Verification

- `cargo test -p kiwi-forensics` — **101 unit + all integration suites
  green**, incl. 4 new FOR-10 regressions (`limitation_codes_classify_
  unobserved_facts`, `starttls_accepted_without_handshake_yields_kex_
  limitation`, `whitespace_only_flow_yields_transport_unknown`,
  `healthy_plaintext_session_emits_no_for10_limitations`).
- `cargo test -p kiwi-app` — **117 green** incl. `protected_without_auth_
  classifies_auth_unobserved`; `e2e_send_delivers_files_sent_copy` +
  `e2e_send_smtp_reject_retains_outbox` hang — **pre-existing defect,
  already assigned T-277→A21** (HEAD commit c111666 names it); unrelated
  to this task's files (send path untouched).
- `npx tsc --noEmit` — **zero errors**.
- `cargo clippy -p kiwi-forensics` clean; fmt clean on all touched files.

### Assumptions / risks

- Live-path `auth-unobserved` treats `AuthMechanism::None` + non-plaintext
  transport as "no visible auth exchange" — matches the code doc and
  core enum semantics.
- `kex-unobserved`/`transport-unknown` have no honest live-path signal —
  deliberately not emitted there (absence of evidence ≠ permission to
  fabricate the marker).
- T-269's pair-engine swap landed mid-task (devices.rs/system.rs/pair
  churn in working tree + commits); my register annotation was written
  against the documented ownership, not the in-flight code.

---

## T-279 — HickoryResolver production DNS (MAUTH-1)

**Goal:** close the T-196-era gap — mailauth's SPF/DKIM/DMARC had only
`MockResolver` (test-only); no live `DnsResolver` existed and the
`*_with_auth` sync variants were dead code.

**Shipped:**

- `kiwi-mailauth/src/dns.rs` — `HickoryResolver` (hickory-resolver 0.26,
  tokio feature): `system()` = 2 s × 2 attempts per query, `with_bounds`
  for explicit bounds (`attempts` clamps ≥ 1 — zero would fabricate
  `Temp`). System resolver config via `builder_tokio()` (preserves
  system ndots/search/transport opts; only our bounds overridden).
  Private `current_thread` runtime + resolver build **lazily** on first
  lookup inside a `Mutex`; a failed build memoizes as `Broken` → every
  lookup returns `Temp` (no rebuild loop on DNS-less hosts).
  `block_on` runs on a scoped thread — `Runtime::block_on` panics when
  called from a thread already inside a runtime, and this sync facade
  is invoked from Tauri async handlers. A panicking lookup thread maps
  to `Temp`. Error map: `is_no_records_found` (NXDOMAIN + NODATA) →
  `NxDomain`; everything else → `Temp`. TXT strings concat per RFC
  7208 §3.3, capped at `MAX_TXT_LEN` like the mock; MX sorted by
  preference ascending.
- `kiwi-app` wiring: `kiwi-mailauth` dep added; shared
  `OnceLock<HickoryResolver>` (`commands/mail.rs::auth_sealer()`) keeps
  the answer cache warm. `sync_pop3` → `sync_pop3_with_auth(sealer,
  None)`; lazy IMAP body ingest (`get_message_raw` on-demand fetch) now
  parses + `evaluate_and_stamp` + `set_auth` on first-body store.
  `SmtpReceipt: None` on both paths — POP3/IMAP cannot know client IP /
  envelope sender, so SPF records `none` honestly (DKIM/DMARC still
  evaluate from headers). Stamp failures swallowed — never fail mail
  read/sync.
- `docs/contracts/mailauth.md` §6 — bounds, lazy-build memoization,
  scoped-thread `block_on`, wiring locations, `None` receipt rationale,
  fail-closed error map.
- `docs/audits/FINDINGS.md` — MAUTH-1 → **fixed**.

**Tests (offline seam — no live DNS required):**

- `hickory_lookup_fails_closed_offline`: 1 ms bound against RFC 2606
  `.invalid` TLD must produce `NxDomain`/`Temp` — never `Ok`, never
  panic — proving the runtime → config → query → error-map path works.
- `hickory_resolver_fits_the_resolver_seam`: `Send + Sync + DnsResolver`
  compile assertion (the `AuthSealer` blanket impl follows).
- `with_bounds_clamps_zero_attempts`.
- `hickory_live_dns_smoke` (`#[ignore]`): manual live-DNS verification —
  real `lookup_mx("gmail.com")` + `lookup_host` through `system()`;
  documented in `mailauth.md` §6 (`cargo test -p kiwi-mailauth
  hickory_live -- --ignored`).

**Verification:** `cargo test -p kiwi-mailauth` — **66 green** + 1
ignored (the live smoke); `cargo test -p kiwi-app --lib` — **125 green**
(T-277's e2e_send fix landed; previous hang gone); `clippy -p
kiwi-mailauth --all-targets -D warnings` clean; `cargo fmt` clean on
touched files; `cargo check -p kiwi-app` green. Re-verified post-landing
by second pass: mailauth suite/clippy/fmt clean; `cargo check -p
kiwi-app` green with the wiring in place. (Transient foreign red during
re-verify: `kiwi-mail` `store/schema.rs` + `rules/eval.rs` mid-migration
under T-281 — reported, not touched.)

**Not done (scope note):** a mass `fetch_missing_bodies_with_auth`
deferred pass is still unwired — bodies are lazy-fetch-only by design;
the syncer never bulk-downloads. IMAP messages already stored before
this change keep no stamp (ingest-time evidence is not backfilled).

### Coordination follow-up (T-277 rerun unblock)

Coordinator reported dns.rs breaking kiwi-app/kiwi-mail gates — that was
a pre-commit mid-flight snapshot; T-279 landed complete at `301fd0e` and
green (`builder_tokio`, HRTB+boxed future, `answers()`, `txt_data`
field). Actual tree breakage on rerun was **T-244's in-flight hunks**,
repaired mechanically (all forced by compilation, zero semantic
choices): `SCHEMA_VERSION` dedup (13/14), `use crate::rules::Rule`
hoisted out of `NewMessageMeta`'s body, `PreviewHit.condition_hits`
wired to existing `eval::condition_hits(&rule.when, ..)`, `mut leaf`
closure, misplaced `#[test]` extracted from inside
`collect_condition_hits` into `mod tests`, missing `}` closing the CRUD
test + stray `}` removed, `Result` alias → `std::result::Result` in the
migration test, and the v13→v14 test seeded with the "existing row" its
doc comment promised (it rebuilt `rules` empty, so the health SELECT
found no rows). **A21/T-244 owner should review** — fixes were forced,
but semantics are theirs.

Post-repair: clippy `-D warnings --all-targets` clean on
mailauth/mail/app; kiwi-mail 209 green incl. both new T-244 tests;
kiwi-mailauth 66 + `hickory_live` ignored-test (manual live-DNS path —
passes under `--ignored`); kiwi-app 129/130 — sole failure is A19's
T-285 `e2e_pop3_delete_after_download_sends_dele`, still actively
in-flight (file was mid-keystroke this session; same hang class T-277
fixed). fmt clean.

## T-288-backend — message templates (store + IPC + contract + TS)

**Done.** The last Mailspring-parity item: composer boilerplate, owned
backend-side; the composer UI is A25's later task.

- `kiwi-mail/src/templates.rs` (new): `Template` model — flat named
  list (content, not policy; no account scoping), `validate()` with
  byte bounds (name ≤128 B non-blank, subject ≤998 B RFC 5322 line cap,
  bodyText ≤64 KiB, bodyHtml ≤128 KiB). `render()` is single-pass
  `{{name}}` substitution: token name `[A-Za-z0-9_.-]+` ≤64 B, inner
  whitespace trimmed; invalid/unterminated tokens stay literal (never
  reported, never guessed); unknown names stay verbatim + collected in
  sorted-deduped `missing_vars`; substitutions are non-recursive;
  `vars` bounded (≤64 entries, ≤4 KiB values → `invalid-input`).
  UTF-8-safe `find`-based scan, no byte indexing. 7 unit tests.
- `kiwi-mail` store: schema v15 — `templates` table
  (template_id/name/subject/body_text/body_html/created_unix/
  updated_unix). CRUD on `MailStore`: `insert_template` (store assigns
  `tpl-N`; `tpl-` prefix reserved for caller ids → invalid), `update_`
  (full replace, preserves `created_unix`), `get_`, `list_`
  (name-then-id order), `delete_` (idempotent bool). Migration test:
  v14→v15 creates the table, preserves rows. CRUD test incl. id
  sequence + ordering.
- `kiwi-app`: `types/templates.rs` (`TemplateView`/`TemplateInput`/
  `RenderedTemplateView` — serde camelCase, `bodyHtml` omitted not
  null). `commands/templates.rs`: five `#[tauri::command]`s —
  `kiwi_templates_list/create/update/delete/render`, all `gate()`d.
  Writes audited (`template-created/updated/deleted`, **id only** —
  bodies never enter the log); list/render unaudited reads. Audits
  fire only after the write succeeds (not-found precedes audit).
  Registered in `invoke_handler`. 3 tests: CRUD roundtrip + not-found,
  render vars/missing/bounds, invalid-input create.
- Contract: `docs/contracts/ipc.md` §6i — wire shapes, per-command
  semantics, placeholder grammar, bounds, error codes (`locked`/
  `invalid-input`/`not-found`), and the documented decision:
  **server-side substitution** (composer gets ready fields; grammar
  tested once in Rust) and **audited writes** (drafts-adjacent —
  tamper-evident trail, id-only detail, matches contacts posture).
- Frontend: `kiwi.ts` + `RenderedTemplateView`/`TemplateInput`/
  `TemplateView`; `ipc.ts` wrappers `templatesList/Create/Update/
  Delete/Render` — wired only to the five registered commands.

**Gates:** `cargo test -p kiwi-mail` **218** green; `cargo test -p
kiwi-app --lib` **133** green (A19 finished T-285 — the pop3-dele e2e
now passes); `clippy -D warnings --all-targets` clean on mail+app;
`fmt --check` clean; `tsc --noEmit` clean (fixed one A25 mid-flight
gap: `MessageSourceView` import missing in mailbox.tsx — mechanical).

**A25 hand-off:** consume `api.templates*`; `render.missingVars` is
the UI flag for unresolved `{{name}}` tokens. `tpl-` ids reserved.

## T-298 — OutboxItem state + lastError (schema v16)

**Done.** Held-vs-failed is now distinguishable in `kiwi_list_outbox`.

- **Schema v16** — `outbox.last_error TEXT` (nullable; `≤512 B` bounded at
  the store boundary). `ensure_outbox_error_column` sentinel-guarded like
  prior column adds. Pre-v16 rows keep `NULL` — a reason that predates
  the column is unknowable, never backfilled.
- **`OutboxRow.last_error`** threaded through `outbox_put`/`list`/`due`;
  `outbox_set_timing` gained `last_error: Option<&str>` (both callers:
  dispatch retry writes `Some`, reschedule writes `None`).
- **State is derived, never stored:** `attempts > 0` → `held` (a prior
  dispatch failed; the row only persists because retries remain),
  `attempts == 0` → `queued`. The wire vocabulary is wider
  (`queued|sending|held|cancelled|sent`) but `sending` is a sub-second
  in-memory transient not derivable from persisted state, and
  `sent`/`cancelled`/exhausted-`failed` delete the row — so the list
  honestly emits only `queued`/`held`. Documented in ipc.md §7.
- **lastError provenance:** dispatch's Held-requeue writes the sanitized
  `code: message` (same text as the `send-attempt-failed` audit — no
  provider body text, IpcError-sanitized) into `OutboxMeta` AND the
  outbox row, so it survives restart (meta is rebuilt from the table on
  open — a meta-only field would vanish). Manual reschedule clears it:
  a recommit is not a retry. `None` until first failure.
- **Wire:** `OutboxItem.state: String` + `last_error: Option<String>`;
  `kiwi.ts` union type + `lastError: string | null`; `kiwi_list_outbox`
  extracted to `list_outbox_impl` seam for tests.

**Gates:** kiwi-mail **219** green (v15→v16 migration test + outbox
roundtrip w/ error set+clear); kiwi-app **137** green (new
`outbox_item_state_is_derived_not_stored`: queued→held→reschedule-clear);
clippy `-D warnings` clean on mail+app; fmt + tsc clean.

**Concurrent churn handled:** kiwi-integrations was mid-rewrite this
session (SecretString/TestSlug capability-redaction, live-gate,
reject_in_band_error). Fixed mechanically where forced (serde import,
TestSlug::new call sites); owner's `public_url`+`reject_in_band_error`
landed as canonical — my interim spamtester-local duplicate removed.
Two A25 mid-flight gaps patched (`useRef`/`useComposerActions` imports,
`MessageSourceView` import in mailbox.tsx). No semantics overridden.

---

## T-304 — LAN pair-claim listener (done)

A11's T-269 gap closed: the claim path (`claim_ticket_and_register`) now
has a network listener that mobile can actually reach.

- **`kiwi-app/src-tauri/src/pairing_listen.rs`** — bounded hand-rolled HTTP
  over `tokio::net::TcpListener` (no new deps). `POST /pair` accepts the
  §3.2 `kiwi-pairing-hello` (`pairing_ticket` + `device_public_key_b64` +
  optional `keystore_ref`), decodes the key (canonical padded std Base64,
  exactly 32 B), mints `dev-<id>` server-side, and hands off to
  `PairEngine::claim_ticket_and_register` — the only registration path,
  still atomic (consume+register+link). Claimant-supplied `device_label`
  is ignored; the ticket's bound label is authoritative.
- **Transport posture (documented, not resolved):** authenticator.md §3.2
  requires TLS (`wss://`, pin = `desktop_public_key_b64`) and that ruling
  is still unratified — so this listener is **plaintext, gated behind
  `KIWI_PAIR_LISTEN=1`**, a development seam only. Production pairing
  stays plaintext-forbidden; the claim semantics are transport-agnostic
  so the wss swap changes only the socket layer.
- **Lifecycle:** bind at `AppState::open` (std `TcpListener` on
  `0.0.0.0:0`, no runtime needed), spawn the accept loop in `run()` setup.
  Explicit provisioning (`KIWI_PAIR_ENDPOINT`/`pairing-channel.json`)
  always wins over the flag. One listener per process; sequential
  per-connection handling, 5 s read timeout, whole request ≤16 KiB,
  Content-Length required, `connection: close` replies.
- **QR wiring:** when the dev listener binds, its real
  `http://<lan-ip>:<port>/pair` becomes `PairChannel.desktop_endpoint`
  (LAN ip via UDP routing-table lookup — no packets sent), so
  `pair_begin`'s QR payload advertises the actual socket.
- **Fail-closed vocabulary:** `malformed-request`/`unexpected-type`/
  `key-invalid`/`ticket-invalid`/`invalid-request`/`claim-failed` (400),
  `device-conflict` (409), `method-not-allowed` (405), `unknown-path`
  (404), `request-too-large` (413). Unknown/consumed/expired/malformed
  tickets collapse to `ticket-invalid` — no ticket-state oracle, and
  ticket/key bytes never enter replies, logs, or audit. Success audits
  `pair-ticket-claimed` with device_id only.
- **Tests:** real loopback `TcpStream` claims —
  `claim_roundtrip_over_real_socket` (pair_begin → HTTP POST →
  `kiwi-pairing-registered` → engine shows pending device with
  ticket-bound label + pair_status "claimed") and
  `unknown_and_malformed_claims_fail_closed` (unknown ticket →
  ticket-invalid; bad JSON → malformed-request; GET /other → 405).

**Gates:** kiwi-app **166** green; `cargo clippy --all-targets
-D warnings` clean workspace-wide; fmt clean.

**Concurrent churn handled:** this session spanned three other agents'
live work — a stale-file resurrection (committed HEAD carried
`send.rs`/`message.rs`/`types.rs` alongside their post-split dirs →
E0761; the stale flats deleted), integrations' `DeliverabilitySession`
rework (consent→consumed/enqueued/queue_id/last_status fields, cooldown
machinery, `send_impl_class`), sandbox session-kind refactor, and a
clippy `await_holding_lock` fix. Interim fills I made (session literals,
`OutboxClass::Ordinary` defaults, cfg-gated test imports, `_until`,
`.clone()` on a Drop type, std::sync::Mutex initializers) were all
mechanical; the owners landed their canonical versions and every fix
converged — final tree is theirs, not mine.
