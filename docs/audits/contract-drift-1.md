# Contract-Drift Audit 1 (T-196)

**Reviewer:** Agent 20 (Devin Pro). **Date:** 2026-09-25. **Scope:** every
`docs/contracts/*.md` (11 files present) vs its implementation, `release/v0.1.0`
working tree at `6f74a8b`. **Mode:** read-only — no tracked file was modified;
this report and `docs/agents/agent-20-status.md` are the only writes.

**Method:** seven parallel read-only sub-audits, one per contract↔code pair;
every contract file was read in full and each documented command/route/type/
field/enum/constant was located (or proven absent) in code. High-severity
claims were spot-verified by the reviewer (6/6 reproduced: FOR-1/2, IPC-2,
SS-1, AUTH-1, FOR-3, ADM-1). No code execution; all findings are
source-readable disagreements.

## In-flight caveats (line numbers reflect snapshot)

- `docs/contracts/admin-api.md` has **uncommitted working-tree edits**;
  T-193 fixes (Agent 13) and T-188 additions (Agent 18) are landing. Several
  ADM findings are *contract-stale after Lead-approved behavior changes*, not
  regressions.
- `kiwi-mailauth` was **edited mid-audit** (T-183, Agent 16) — re-verify MAUTH
  lines before acting.
- `kiwi-autoconfig` gained `src/oauth2/` mid-audit (T-195, Agent 19) —
  ACFG-1/2 concern that module.
- `docs/contracts/integrations.md` **does not exist** (T-226, Agent 11) —
  INT section is gap notes only.
- `kiwi-app` frontend rebuild in-flight (T-191/192, Agent 12); snooze held
  (T-189). UIS severities are calibrated against the contract's own §5 wiring
  order — registered surfaces explicitly sequenced later or held are M/L, not H.
- `ui-surfaces.md` is a forward-looking registry (§3 payloads are "requests to
  data owners", §5 is a wiring order); absent surfaces are reported as
  documented-vs-implemented gaps, not regressions.

## Summary matrix

| Contract (version) | Code target | Items checked | H | M | L | I |
|---|---|---|---|---|---|---|
| `ipc.md` (kiwi.ipc/1) | `kiwi-app/src-tauri/src/commands/` + `lib.rs` registry | 52 commands / ~45 wire shapes / 2 events | 2 | 8 | 4 | 2 |
| `forensics.md` (kiwi.forensics/1) | `kiwi-forensics` public API | ~115 | 2 | 4 | 6 | ~30 groups |
| `admin-api.md` (admin-api/1.3) | `kiwi-admin` routes/services | 15 endpoints + RBAC/schema/error model | 0 | 6 | 13 | 1 real gap |
| `sandbox.md` (v1.1) | `kiwi-sandbox` | ~37 | 0 | 2 | 5 | 4 groups |
| `pair.md` (v1) | `kiwi-pair` | ~31 | 0 | 2 | 7 | 2 groups |
| `contacts.md` (kiwi.contacts/1) | `kiwi-contacts` + `commands/contacts.rs` | ~40 | 0 | 3 | 7 | 1 group |
| `authenticator.md` (v1) | `mobile/` + desktop receivers | ~50 | 1 | 8 | 6 | 5 |
| `autoconfig.md` (kiwi.autoconfig/1) | `kiwi-autoconfig` | ~45 | 1 | 10 | 5 | large |
| `mailauth.md` | `kiwi-mailauth` | ~35 | 1 | 4 | 3 | large |
| `security-session.md` | `kiwi-core` | ~60 | 1 | 2 | 6 | large |
| `ui-surfaces.md` (v2) | `kiwi-app/src/` | 23 surfaces / 8 routes / payload sets | 2 | 11 | 4 | 2 |
| `integrations.md` — **absent** | `kiwi-integrations` (in-flight) | n/a | — | — | — | gaps only |

**Registration health:** all 51 implemented `#[tauri::command]` fns are
registered in `generate_handler!` (`kiwi-app/src-tauri/src/lib.rs:61-123`) and
all 51 are documented. `kiwi_discover_account` (ipc.md:188) and the five §9d
pairing commands (ipc.md:622-629) are documented-but-unregistered and the
contract itself marks them REQUESTED/PROPOSED — consistent. The reverse
direction fails on the **frontend**: `src/ipc.ts` invokes four names that exist
in neither the registry nor any contract (UIS-5/6/7).

---

## High findings

| ID | Contract says X | Code does Y | Evidence |
|----|-----------------|-------------|----------|
| IPC-1 | `AccountView` = `{id, displayName, email, incomingProtocol, incoming:{host,port,security}, outgoing:{host,port,security}, username, unreadCount, trustToken, color}`; `trustToken ∈ trusted\|degraded\|warning\|locked\|unknown` | Emits `{id, email, displayName, trust, unread, color, protocol, incomingHost, incomingPort, outgoingHost, outgoingPort}` — no `incoming`/`outgoing` objects, no `security`, no `username`; renamed `trustToken→trust`, `unreadCount→unread`, `incomingProtocol→protocol`; vocab `secure\|warning\|danger\|unknown`. Affects `kiwi_list_accounts`, `kiwi_add_account` | `ipc.md:130-138` vs `kiwi-app/src-tauri/src/types/accounts.rs:12-26`, `commands/accounts.rs:129-145` |
| IPC-2 | `SecurityStatusView` = `{state, score, locked, requiredAction, signals, endpointSignals, knownDevices}`; `requiredAction ∈ none\|notify-user\|require-authenticator\|block-access` | `endpointSignals` + `knownDevices` never emitted; undocumented `trust`/`sessionsObserved`/`deviceId` added; `requiredAction` emits `warn-user`/`require-authenticator-unlock`/`require-reauth`/`block-access`/`none` — contract spellings never produced. Affects `kiwi_security_status`, `kiwi_lock`, `kiwi_submit_challenge`, `kiwi_revoke_device`, nested `VerifyResult.trust` | `ipc.md:58-67` vs `types/system.rs:34-46`, `commands/mod.rs:62-83` |
| FOR-1 | "Enum strings use the `as_str()` spellings (`tls1.2`, `ecdhe`, `cram-md5`, `not_evaluated`, …)"; `transport ∈ plaintext\|starttls\|implicit_tls\|unknown` | All enums derive `rename_all="snake_case"` — wire spellings diverge for **19+ variants**: `tls12` vs `tls1.2`, `start_tls` vs `starttls`, `x_o_auth2` vs `xoauth2`, `triple_des` vs `3des`, `cha_cha20_poly1305` vs `chacha20_poly1305`, `cram_md5` vs `cram-md5`, `scram_sha256_plus` vs `scram-sha-256-plus`, etc. `Report::to_json` emits serde output directly — documented JSON shape is not the wire shape | `forensics.md:55-58,47,52,79-81` vs `model/tls.rs:18-19,249-250`, `model/protocol.rs:92-93`, `model/auth.rs:11-12`, `findings/mod.rs:112-113,150-151`, `report/mod.rs:208` |
| FOR-2 | "`TlsVersion::Unknown(raw)` serializes as `\"unknown\"`" | Newtype variant is externally tagged → `{"unknown": <u16>}`; deserializing documented `"unknown"` fails | `forensics.md:57-58` vs `model/tls.rs:18-20,33-34` |
| AUTH-1 | §9 audit map: `challenge-approved`, `challenge-denied`, `challenge-verification-failed <err>`, `device-paired`; "all outcomes audited — including failures" | `kiwi_submit_challenge` records `challenge-verified` on success only; all verify failures propagate via `?` with **no audit row**. No `challenge-denied`/`challenge-verification-failed`/`device-paired` event exists in src-tauri; pairing activation audits as `challenge-verified` | `authenticator.md:327-342` vs `commands/system.rs:203-207,236-240`; grep: zero hits for denied/failed events |
| SS-1 | While `Locked`, `required_action` is `require-authenticator-unlock` or `block-access` | `TrustMachine::evaluate` splices `state: self.state` but keeps the fresh eval's `required_action` — a Locked machine evaluating clean/medium signals emits `{state: Locked, required_action: None}` or `{Locked, WarnUser}`. Consumers see "no action" on a locked session | `security-session.md:106-109` vs `kiwi-core/src/trust.rs:145-163` |
| ACFG-1 | Crate "emits **no secrets and never opens connections**" | New `pub mod oauth2` (T-195 in-flight) holds `TokenSet{access_token,refresh_token,…}` and opens HTTPS via `live_transport`/`ReqwestClient`. lib.rs now self-documents the exception but the contract invariant still asserts it | `autoconfig.md:10-11,22-23` vs `kiwi-autoconfig/src/lib.rs:35`, `oauth2/token.rs:20`, `oauth2/transport.rs:65` |
| MAUTH-1 | "`HickoryResolver::system()` is the live adapter (private Tokio runtime, blocking facade)" | No `HickoryResolver` exists anywhere — `dns.rs` has only `MockResolver`; `hickory-resolver` + `tokio` are declared-but-unused deps. The crate cannot do a live DNS lookup (likely T-183 in-flight) | `mailauth.md:85` vs `kiwi-mailauth/src/dns.rs` (whole file), `kiwi-mailauth/Cargo.toml:18-19` |
| UIS-5 | §1 `KIWI-UI-023` data source "Per-section backend prefs"; `ipc.md` registers `kiwi_prefs_get`/`kiwi_prefs_set`/`kiwi_prefs_list` | Frontend invokes **`kiwi_get_prefs`/`kiwi_set_prefs`** — names in no contract and no registry; Settings→General permanently fails `BackendUnavailableError` even though the backend commands landed (T-175). Stale comments claim "backend pending" | `ui-surfaces.md:43` + `ipc.md:611-618` vs `kiwi-app/src/ipc.ts:177-182`, `views/settings.tsx:98-138`; registry `src-tauri/src/lib.rs:118-120` |
| UIS-6 | `KIWI-UI-019` setup wizard + requested command **`kiwi_discover_account(email)`** (ipc.md:188, T-178 done) | Frontend invokes **`kiwi_lookup_autoconfig`** — matches neither contract nor backend; when the backend command lands the wrapper still throws `BackendUnavailableError` | `ipc.md:188` vs `kiwi-app/src/ipc.ts:140-148`, call sites `views/setup.tsx:149`, `views/settings.tsx:171` |

## Medium findings

| ID | Contract says X | Code does Y | Evidence |
|----|-----------------|-------------|----------|
| IPC-3 / AUTH-3 | `ChallengeView.nonceB64` = base64 32-byte nonce (ipc.md §4; authenticator.md §4.2 requires `nonce_b64` on the phone) | Emits `nonceHex` (hex string) — name **and** encoding differ; mobile `parseChallengeData` would fail closed if the view were piped to the phone. ipc.md §12 already flags it | `ipc.md:107-108,963-964`; `authenticator.md:161` vs `types/system.rs:56,71` |
| IPC-4 | Error code `challenge-expired` for expired challenges | `ChallengeError::Expired` maps to `"expired"`. `authenticator.md:266` agrees with code — **the two contracts disagree with each other** | `ipc.md:124,993` vs `error.rs:83` + `authenticator.md:266` |
| IPC-5 | §11 error catalog is the closed set | `UnlockError` adds undocumented `"not-locked"`, `"authenticator-required"` (reachable via `kiwi_submit_challenge`) | `ipc.md:978-999` vs `error.rs:69-74`, `system.rs:216` |
| IPC-6 | `FolderView` = `{id, name, exists, unseen, uidValidity}` | Emits `{id, accountId, name, uidValidity, uidNext, highestUid}` — `exists`/`unseen` missing; extras undocumented; `uidValidity` nullable vs contract non-null | `ipc.md:240` vs `types/mail.rs:9-17` |
| IPC-7 | `MessageView` uses `fromAddr`, `toAddrs`; fields non-null | Emits `from`/`to`; adds `unread`/`starred`/`bodyStored`; `subject`/`from`/`to`/`dateUnix`/`size`/`snippet` all `Option` | `ipc.md:249-253` vs `types/mail.rs:21-44` |
| IPC-8 / CON-1 | `kiwi_import_vcards(vcard)` — param `vcard` | Rust param `vcard_text` → wire arg **`vcardText`**; `{vcard:…}` fails deserialization. Latent — no frontend caller exists | `ipc.md:589` + `contacts.md:85` vs `commands/contacts.rs:205-208` |
| IPC-9 | `EndpointReportView.observations[]` carries `evidenceRef` | `EndpointObservation` has no `rename_all` → serializes `evidence_ref` snake_case | `ipc.md:959` vs `signals.rs:59-68` |
| IPC-10 | "`xoauth2` not [valid] for POP3" — input-validation rule on `kiwi_add_account` | `xoauth2` accepted for `pop3` at add time; rejected only at connect — unusable account persists | `ipc.md:155` vs `commands/accounts.rs:206-227` vs `:715-731` |
| FOR-3 | "Severity/confidence are fixed per rule"; `KIWI-TRANSPORT-001` = High/Certain | Rule escalates to `Critical` when a reusable secret was exposed — deliberate (comment explains triage) but undocumented | `forensics.md:96,100` vs `rules/transport.rs:75-85` |
| FOR-4 | `strict()`/`permissive()` policies gate reject/report of broken ciphers, legacy TLS, cleartext-auth-under-TLS | `SecurityPolicy.{reject_broken_ciphers, require_tls13, report_cleartext_auth_under_tls}` are **never read by any rule** — `permissive()` still emits Critical `KIWI-CIPHER-001`; 6 more rules ungated | `forensics.md:146-151` vs `rules/policy.rs:25-35` + grep of `ctx.policy.*` consumers |
| FOR-5 | Per-finding `weight × multiplier / 10000`, **round half up per finding** | Accumulates 1e8 fixed-point then rounds the aggregate once — 2×High/Tentative: contract 26, code 25 | `forensics.md:155-156` vs `score.rs:183-207` |
| FOR-6 | "Unknown enum values / new fields must be ignored, not fatal" (cross-cutting invariant) | No `#[serde(other)]` anywhere — `Report::from_json` fails fatally on a forward-versioned variant (or on documented `tls1.2` spellings) | `forensics.md:28-29` vs `report/mod.rs:212-215`; grep `serde(other)` = 0 |
| ADM-1 | `GET /orgs/{o}/policies` returns "full definitions" — §5.1 snake_case `{id, org_id, name, enabled, min_tls, external_recipients, domain_rules[]}` | Returns camelCase `{id, enabled, minTls, externalRecipients, domainRules}` — **`name` + `org_id` omitted**. POST takes snake_case; asymmetric | `admin-api.md:68,116-126` vs `policy/services.ts:238-244` |
| ADM-2 | `GET /audit`: "Omitting `org` returns the whole log" | T-193/H4 fix: org-bound actor omitting `?org` silently gets own-org slice; whole log unreachable for them. Contract text stale post-approval | `admin-api.md:386` vs `mailflow/services.ts:126-128` |
| ADM-3 | Mailflow filters list no org default | Same T-193 default: omitting `org` → actor's org, undocumented | `admin-api.md:72` vs `mailflow/services.ts:54-55` |
| ADM-4 | "`verify` reads the FULL chain… a hash chain only validates over every row" | Route accepts undocumented `?limit` (default 1000) — verifies a **prefix** and still reports `valid:true` for longer chains, the dishonest attestation §13.3 forbids for export | `admin-api.md:376-378,205,460-467` vs `server.ts:395`, `mailflow/services.ts:156-165` |
| ADM-5 | "every authorization denial is audited … `outcome:"denied"`" (audit-service denials exempt §13.4) | Read-path denials not audited: `listUsers`, `listPolicies`, `listDomains`, `MailflowService.query` use bare `requirePermission` — 403, zero audit rows | `admin-api.md:31-32,54-55` vs `policy/services.ts:124,129,225`, `mailflow/services.ts:55` |
| ADM-6 | `POST /orgs` permission cell = "platform-level (bootstrap)" | Enforces `org.create` at null target (org_admin only). Matches H5 ruling; contract cell never names the permission | `admin-api.md:61` vs `policy/services.ts:44-51`, `rbac.ts:36-49` |
| SBX-1 | Inv. 5: "counts capped at 4096 entries each" — `fs_changes` is one of the bounded vectors | Guest fs_changes merge cap is `MAX_REPORT_ENTRIES * 3` = **12 288**; host fallback likewise | `sandbox.md:159-160,60` vs `wsl2.rs:639,373-377`, bound const `lib.rs:32` |
| SBX-2 | `SandboxError::ImageMissing` = "base image not provisioned yet" | Variant exists but is **never constructed** — missing rootfs reports as `Unavailable`; callers matching `ImageMissing` never see it | `sandbox.md:104` vs `error.rs:12`, `wsl2.rs:120-125,166-168` |
| PAIR-1 | "`device-pairing` challenges are only issuable to `pending` devices" | `(Active, _) => {}` arm permits `DevicePairing` to an **active** device — a transition class the contract forbids | `pair.md:75-77` vs `engine.rs:283-290,370-373` |
| PAIR-2 | `PairError::TicketConsumed` exists; `ipc.md:891` maps it to distinct code `pairing-ticket-consumed` | Variant **never constructed** — `consume_ticket` merges unknown+consumed into `InvalidTicket`; the documented IPC code is unreachable | `pair.md:107-114` + `ipc.md:891` vs `lib.rs:54-55`, `store.rs:223-227`, `engine.rs:142` |
| CON-2 | `createdUnix` is store-owned, "preserved on update"; `kiwi_update_contact` returns `ContactView` | `update()` preserves it in DB but returns the caller's prepared struct with `created_unix: 0` — wire response lies; a `get` shows truth | `contacts.md:60-61` + `ipc.md:575` vs `store.rs:212-253`, `types/contacts.rs:89-90` |
| CON-3 | §5.2 hard-error list (oversized input, line cap, unterminated card, malformed line, outside-card, too many cards/properties); per-field-cap issues are "skipped and reported" | `VCardError::ValueTooLong` (one NOTE > 4096 B) is a **stream-hard** abort, not a per-card skip — undocumented in the hard-error list | `contacts.md:165-172` vs `vcard.rs:637-642,69-70` |
| AUTH-2 | §6.2/§6.3: response carries `decision:"approve"\|"deny"`; deny audited `challenge-denied`, never consumes | Neither desktop receiver has a `decision` field — a mobile deny arrives as `signature_b64:""` → `InvalidSignature`, indistinguishable from a forged signature | `authenticator.md:253-268` vs `types/system.rs:82-90`, `kiwi-core/src/challenge.rs:89-97` |
| AUTH-4 | `desktop_public_key_b64` = "`ed25519:` prefix + base64 of the 32-byte key" — the pin source | Mobile checks only `startsWith('ed25519:')` + ≤512 chars — never decodes/size-checks; `ed25519:zz` becomes the pinned key. Same prefix-only check in kiwi-pair | `authenticator.md:92` vs `mobile/src/protocol/qr.ts:44-48`, `kiwi-pair/src/engine.rs:158-162` |
| AUTH-5 | "channel must be TLS-protected… Plaintext pairing transport is forbidden" | `parseQrPayload` accepts `desktop_endpoint` as any 1..256-char string — `ws://` passes; contract's own §3.1 example uses `ws://` (self-inconsistent) | `authenticator.md:119-128` vs `mobile/src/protocol/qr.ts:42`, `kiwi-pair/src/engine.rs:156`; example `authenticator.md:77` |
| AUTH-6 | §6.1 gate order parse→clock→**binding**→ledger→tap, "all must pass before any signature exists" | Screen runs replay→binding→clock (order differs), **skips binding entirely when `identity===null`** (unpaired device can review a foreign challenge), and never re-gates on approve/deny tap — a challenge expiring while displayed stays answerable | `authenticator.md:209-225` vs `PendingApprovalsScreen.tsx:44-55,67-96` |
| AUTH-7 | Expiry judged by "the phone's own clock" | `FixedClock(Date.now())` frozen at component mount — `isExpired` and queue throttle evaluate stale time forever; throttle permanently blocks retries (`now-last` always 0) | `authenticator.md:213-215` vs `PendingApprovalsScreen.tsx:34-38`, `queue.ts:99-101` |
| AUTH-8 | "denies are never queued indefinitely" | `ChallengeQueue` has no expiry/TTL eviction — undelivered items persist to process end; `expires_unix` never consulted | `authenticator.md:284-286` vs `mobile/src/protocol/queue.ts:94-124` |
| AUTH-9 | `soft-hsm.ts` is "test-only… fail-closed (UNIMPLEMENTED-style)… no production key handling" | `SoftHsmKeystore` is **functional** (deterministic keys + fake signatures); its `assertTestMode` gate is ceremonial — factory callable from any `src/` code. Honestly labeled, but the contract overstates the posture | `authenticator.md:15-16,195-200` vs `mobile/src/keystore/soft-hsm.ts:26-83` |
| ACFG-2 | `kiwi.autoconfig/1` is the crate's contract | `oauth2` module claims `CONTRACT_VERSION = "kiwi.oauth2/1"` citing `docs/contracts/oauth2.md §6` — **file does not exist** | `autoconfig.md` header vs `kiwi-autoconfig/src/oauth2/mod.rs:52` |
| ACFG-3 | Local-part charset `[A-Za-z0-9._%+\-']` | Accepts full RFC-5321 atext superset (`!#$%&'*+-/=?^_\`{\|}~`) — e.g. `a!b@x.test` accepted | `autoconfig.md:34` vs `lib.rs:139-141` |
| ACFG-4 | ISPDB fixtures cover "…GMX, Yandex, **GoDaddy**, AOL" | 9 entries; **GoDaddy absent** (only an MX hint `secureserver.net`) | `autoconfig.md:93-94` vs `ispdb.rs:73-146`, `heuristics.rs:126-132` |
| ACFG-5 | `MX_HINTS` e.g. `…yahoodns.net, pphosted.com` | `pphosted.com` absent; 9 suffixes | `autoconfig.md:97-98` vs `heuristics.rs:69-133` |
| ACFG-6 | ">256 KiB documents" are "hard `Err(MalformedXml)`" | Oversize returns `Err(TooLong)` — different variant | `autoconfig.md:110` vs `autoconfig_xml.rs:58-60` |
| ACFG-7 | "processing instructions" prohibited → hard Err | `skip_misc` silently **skips** PIs before/after root (needed for `<?xml?>` decl) | `autoconfig.md:110` vs `autoconfig_xml.rs:103-118,275` |
| ACFG-8 | "Root element must be `clientConfig`" | Bare `emailProvider` root also accepted | `autoconfig.md:115` vs `autoconfig_xml.rs:353-361` |
| ACFG-9 | `<domain>` entries checked against queried domain (exact preferred) | Falls back to provider-`id` match, then **first provider unconditionally** when no `<domain>` matches | `autoconfig.md:115-116` vs `autoconfig_xml.rs:372-377` |
| ACFG-10 | Only `%EMAILADDRESS%`, `%EMAILLOCALPART%` substituted; "others passed through verbatim" | `%EMAILDOMAIN%` is also substituted | `autoconfig.md:116-118` vs `autoconfig_xml.rs:474-488` |
| ACFG-11 | `<authentication>`: `password-*`→Password, `OAuth2`→XOAuth2; "anything else (e.g. `gssapi`) makes that server unusable" | `contains("oauth")`→XOAuth2 (accepts `oauthbearer`); empty tag →Password; `contains("cram")`→Password — `cram-md5` is contract-"anything else" | `autoconfig.md:119-122` vs `autoconfig_xml.rs:441-450` |
| ACFG-12 | "serde `snake_case` everywhere" | `security` field reuses `kiwi_mail::SocketSecurity` with **no serde rename** → emits `ImplicitTls`/`StartTls`/`Plaintext` PascalCase | `autoconfig.md:24-25` vs `kiwi-mail/src/transport.rs:84-91`, used `suggest.rs:94,108` |
| ACFG-13 | ipc.md T-178 mapping: auth `xoauth2 → "xoauth2"` | serde yields `"x_o_auth2"`; `as_str()` gives `"oauth2"` — **three spellings for one variant** across docs/code | `ipc.md:213,224` vs `suggest.rs:13-31` |
| ACFG-14 | "the production adapter blocks on a private runtime" | No non-mock `DiscoveryNet` impl exists — `discover` callable only with `MockNet`. Consistent with `kiwi_discover_account` being marked REQUESTED; the contract's adapter claim is unbacked | `autoconfig.md:144-145` vs `net.rs:20,67`; `ipc.md:188` |
| MAUTH-2 | "`l=` truncates before canon" | Truncation happens **after** canonicalization — code is RFC 6376-correct (its comment cites §3.7/§3.4.5); the contract sentence is inverted | `mailauth.md:62` vs `dkim.rs:471-503` |
| MAUTH-3 | "`x=` passed **or** `t=` older than 14 days → `fail`" | `t`-age checked only when `x` **absent** (`else if`) — future `x=` + ancient `t=` passes | `mailauth.md:57-58` vs `dkim.rs:349-367` |
| MAUTH-4 | `algorithm` wire spelling `rsa-sha256`/`ed25519-sha256` | `SigAlgorithm` has no serde rename → serializes `RsaSha256`/`Ed25519Sha256` | `mailauth.md:53` vs `dkim.rs:68-75` |
| MAUTH-5 | "Unknown enum values / new fields ignored, not fatal" | Derived `Deserialize` rejects unknown **variants** (no `serde(other)`); same defect in kiwi-autoconfig enums | `mailauth.md:20` vs `spf.rs:34-35`, `dkim.rs:20-21,49-60`, `dmarc.rs:17-18,40-41,108-109` |
| SS-2 | `source` wire spelling `"thunderbird-hook" \| "forensic-pcap" \| "test-fixture"` | Wire mapper emits `"live-client"` for `ThunderbirdHook` | `security-session.md:49` vs `kiwi-app/src-tauri/src/types/security.rs:170-174` |
| SS-3 | Device chain `pending → active → suspended → revoked`, revoked terminal | `transition()` also permits `pending→suspended`, `pending→revoked`, `suspended→active` — undocumented | `security-session.md:163` vs `kiwi-core/src/device.rs:108-132` |
| UIS-7 | ipc.md has **no search command** | Frontend invokes `kiwi_search_messages` — undocumented + unregistered (honest labeled fallback, but an uncontracted IPC surface) | `ipc.md` (absent) vs `ipc.ts:158-167`, `views/search.tsx:263`, `lib.rs:61-123` |
| UIS-1 | `KIWI-UI-008` cert viewer — per-hop subject/issuer/serial/dates/sha256/sigAlg/status | No cert viewer; `CertChainView` data ships on the wire but renders only as a raw JSON dump in session detail | `ui-surfaces.md:23,81-83` vs `views/security-center.tsx:193-212`, `types/security.rs:44-64` |
| UIS-2 | `KIWI-UI-009` re-scan/diff — "003 section + results dialog" | No re-scan trigger or diff UI; **no IPC command exists** for it | `ui-surfaces.md:24,84-85` vs `ipc.md:485-525` |
| UIS-3 | `KIWI-UI-012` pairing dialog under Settings→Devices | Devices list + revoke only; LockOverlay shows a literal QR placeholder; `api.registerDevice` never called | `ui-surfaces.md:27` vs `views/settings.tsx:620-655`, `components/security.tsx:262-282` |
| UIS-8 | Lock event fields `locked`, `reasonCategory` (display-safe enum), `policyName` | Overlay renders a frontend-authored free-text reason; `SecurityStatusView` carries neither field | `ui-surfaces.md:74-75` vs `App.tsx:147,1095-1103`, `ipc.md:58-67` |
| UIS-9 | §2 severity vocabulary is closed: `secure\|warning\|danger\|unknown` | Producers emit `info\|low\|medium\|high\|critical` (forensics/ipc); UI remaps — the contract's "no other severity" claim is stale vs producer contracts | `ui-surfaces.md:45-57` vs `forensics.md:77`, `ipc.md:73,490`, `kiwi.ts:540-570` |
| UIS-10 | §3 session-summary names `host`,`port`,`starttls`,`keyExchange`,`evaluatedAt`,`stale` | Wire uses `serverHost`,`serverPort`,`transport`/`starttlsUsed`,`keyExchangeGroup`,`establishedUnix`; **`stale` does not exist**. §3 was marked provisional, never reconciled | `ui-surfaces.md:66-70` vs `types/security.rs:12-33` |
| UIS-11 | `KIWI-UI-001` = "**delivering session**" trust; 004 opens from 001 rows | Row glyph + reader pill render **account-level** trust (self-admitted); pill opens `findings[0]` not a message-linked finding | `ui-surfaces.md:16,19` vs `mailbox.tsx:421-425,486-488,706-708` |
| UIS-12 | `KIWI-UI-003` per-account card with session detail + forensics counts | Settings→KIWI Security has no per-account security card; sidebar shows only a trust label | `ui-surfaces.md:18` vs `views/settings.tsx:594-687`, `chrome.tsx:151-171` |
| UIS-13 | `KIWI-UI-013` shell data includes "sync status per account"; `kiwi_sync_status` + `kiwi://mail-changed` registered | No `kiwi_sync_status` wrapper; `kiwi://mail-changed` never listened — live sync status never reaches the shell | `ui-surfaces.md:33` + `ipc.md:370-392` vs `mailbox.tsx:174-182`, `ipc.ts` (absent) |
| UIS-14 | `KIWI-UI-021` send-later + undo | `kiwi_schedule_send` (reschedule) never wrapped/called — queued sends can't be rescheduled | `ui-surfaces.md:41` + `ipc.md:424-428` vs `ipc.ts:293-308`, `compose.tsx:431-459` |
| UIS-15 | `KIWI-UI-022` templates — "Composer picker + Settings CRUD", local store | Settings CRUD writes `kiwi.templates` pref but composer picker reads a hardcoded const and inserts literal `"[X template inserted]"` — picker and store disconnected | `ui-surfaces.md:42` vs `compose.tsx:21,610-627`, `settings.tsx:44,689-716` |
| UIS-16 | `KIWI-UI-007` per-recipient evaluation fields `address/verdict/ruleId/scopeNote` | No pre-send per-recipient eval; a real block marks **all** recipients as offenders; `ruleId`/`scopeNote` never surfaced | `ui-surfaces.md:22,79-80` vs `compose.tsx:31-40,462-469` |
| UIS-17 | ipc.md §9b registers `kiwi_contacts_by_tag`, `kiwi_contact_tags`, `kiwi_import_vcards`, `kiwi_export_vcards` | No wrappers for them; vCard import loops `kiwi_create_contact` per card; export is client-side — stale comments claim "no backend command exists yet" (T-175 landed) | `ipc.md:556-601` vs `views/contacts.tsx:4,249-311`, `ipc.ts:184-228` |

## Low findings

| ID | Contract says X | Code does Y | Evidence |
|----|-----------------|-------------|----------|
| IPC-11 | `MessageBodyView` subject/dateUnix/textBody, `attachments[].filename` non-null | All `Option` → can serialize null | `ipc.md:269-274` vs `types/mail.rs:91,104,109-110` |
| IPC-12 | `OutboxItem.accountId`, `DeleteResultView.trashFolderId` shown non-null | Both `Option` | `ipc.md:433,333` vs `types/send.rs:60`, `types/message.rs:44` |
| IPC-13 | `DeviceView` 6-field shape | Adds undocumented `keyFingerprintTail` (harmless superset) | `ipc.md:535-538` vs `types/devices.rs:19,37` |
| IPC-14 | `kiwi_render_body` "Output capped at 8 MiB" | Cap is `chars().take(8Mi)` — chars, not bytes; multibyte UTF-8 can exceed | `ipc.md:315` vs `commands/message/render.rs:18,70-71` |
| FOR-7 | `starttls.server_reply_ok` optional ("may be absent") | No `skip_serializing_if` — always emitted, `null` when unobserved | `forensics.md:51` vs `model/mod.rs:246-248` |
| FOR-8 | CERT-006..010 catalog titles | Code titles differ ("Certificate uses a broken signature algorithm" etc.); ids/severities match | `forensics.md:124-128` vs `rules/certificate.rs:161,175,191,205,219` |
| FOR-9 | `RescanDiff`: "added / resolved / persisting keys" | `ChangeKind` = `new`/`resolved`/`unchanged`/`severity_increased`/`severity_decreased` — richer than documented | `forensics.md:68-70` vs `findings/diff.rs:50-73` |
| FOR-10 | limitation codes "e.g. `chain-unverified`, `kex-unobserved`, `protocol-unknown`" | `KEX_UNOBSERVED`, `AUTH_UNOBSERVED`, `TRANSPORT_UNKNOWN` defined but **never emitted** | `forensics.md:175-176` vs `report/mod.rs:23,27,29` |
| FOR-11 | "raw capture bytes → `Report`" | `analyze_capture` returns `Result<CaptureReport,_>` — wraps `{report, diagnostics}` | `forensics.md:244` vs `pipeline.rs:110-125,233-236` |
| FOR-12 | Output order "severity, rule id, subject key, then confidence" (directions unspecified) | Confidence sorts **descending** — undocumented | `forensics.md:165-166` vs `rules/mod.rs:326-333` |
| ADM-7 | `audit_log` "`seq PK AUTOINCREMENT`" | SQLite DDL `seq integer PRIMARY KEY` (no keyword; rowid alias anyway) | `admin-api.md:108` vs `drizzle/sqlite/0000_chubby_shard.sql:2` |
| ADM-8 | §3 documents no `limit` on list endpoints | Both accept `?limit` (default 50, clamp 1-500) | `admin-api.md:62,68` vs `server.ts:263,282` |
| ADM-9 | §12.3 pins param names for audit only | Mailflow uses `org`, `recipientDomain`, `since`, `until`, `limit` — undocumented for that route | `admin-api.md:382` vs `server.ts:378-383` |
| ADM-10 | §3 fixes no success status/body | Emits 201 `{id,name,created_at}` etc., `{items}` envelopes, `{ok:true}` — all undocumented | `admin-api.md:61-75` vs `server.ts:247,258,275,282,289,320,359,384,414` |
| ADM-11 | `POST /policies/{id}/evaluate` shapes undocumented | Requires `{direction, sender, recipient, tlsVersion}`; returns `evaluatedPolicyId` — inconsistent with §10's `policyId` for same concept | `admin-api.md:69` vs `server.ts:327-349`, `policy/model.ts:21-33` |
| ADM-12 | §7 audit record shape (actor, org_id, resource, request_id, details object, hashes) | `GET /audit` items = subset `{seq,ts,actor_subject,action,outcome,details}` — `details` is a raw JSON **string** | `admin-api.md:188-199` vs `mailflow/services.ts:72-79,136-143` |
| ADM-13 | §6 event schema shows `"id": "uuid"` | HTTP ingest ignores caller `id` — always `generateId()` | `admin-api.md:164` vs `server.ts:357-370` |
| ADM-14 | §5.3 lists `external-recipient` reason code | External-recipient **block** emits `recipient-domain-blocked`; `external-recipient` only accompanies `warn` | `admin-api.md:150-152` vs `evaluator.ts:60-66` |
| ADM-15 | §11 builder signatures `({…})` | Both take a second `generateId` param not shown | `admin-api.md:309-314` vs `emitter.ts:65,104` |
| ADM-16 | `org_id` is a valid PolicyObject body field | `org_id` in body silently ignored (path wins) — conflicting value not rejected | `admin-api.md:67` vs `server.ts:134-168` |
| ADM-17 | Contract silent on content-type | POST/PUT require `application/json` else 400 `validation.failed` | vs `server.ts:90-97` |
| ADM-18 | §6 enumerates `security_status`/`policy_verdict` values | Invalid values silently coerced `"unknown"` while invalid `tls_version` is 400 — inconsistent strictness | `admin-api.md` §6 vs `mailflow/model.ts:60-73` |
| ADM-20 | Contract silent on body size | `MAX_BODY_BYTES` = 1 MiB → 400 | vs `server.ts:27,103-105` |
| SBX-3 | `report.json.limits_applied` documented + emitted by agent | `GuestReport` has no such field — serde silently drops it | `sandbox.md:135` vs `wsl2.rs:561-582`, `agent.sh:178` |
| SBX-4 | `writes_outside_workdir` = "count of fs changes outside `/kiwi-work`" | Field not parsed; host recomputes over all three kinds incl. `deleted` within merge cap — different number | `sandbox.md:136` vs `wsl2.rs:638-647`, `agent.sh:169` |
| SBX-5 | `processes[].args` documented `{pid,ppid,exe,args}` with `args: Vec<String>` | Guest emits `args` as a **whitespace-joined string**; a conforming agent emitting a JSON array breaks parsing → `incomplete` | `sandbox.md:137` vs `agent.sh:157`, `wsl2.rs:592-594,630-635` |
| SBX-6 | `network.attempts_observed` documented; `EgressEvidence.attempts` exists | `GuestNet` doesn't declare it; `merge_into` hardcodes `attempts: []` — guest attempts silently dropped | `sandbox.md:143` vs `wsl2.rs:609-619,660`, `agent.sh:195` |
| SBX-7 | `probe_inside_netns` pass = `"unreachable"` | Agent can also emit `reachable` (failure) and `untested` — undocumented | `sandbox.md:140` vs `agent.sh:59-65`, `wsl2.rs:1090-1094` |
| PAIR-3 | Verify order "challenge exists → device not revoked → …" | Code correct, but method doc comment states the **reverse** order | `pair.md:78-80` vs `engine.rs:311-313` vs `317-328` |
| PAIR-4 | Verify order implies missing device → `DeviceNotFound` | Maps to `UnknownChallenge` (unreachable in practice — FK enforced) | `engine.rs:322-325`, `store.rs:46,103` |
| PAIR-5 | "atomic consume" is final verify step | `consume_challenge` returns `Result<bool>`; engine discards the verdict with `?` — harmless today, guarantee rests on unchecked return | `pair.md:81` vs `engine.rs:369`, `store.rs:281-286` |
| PAIR-6 | "all string fields are length-bounded" | `root` path not bounded; `verify_response` has no length gate on `challenge_id`/`device_id`/`session_id` | `pair.md:30` vs `store.rs:92-95`, `engine.rs:316-342` |
| PAIR-7 | Ticket gate implements "8..128 chars" (authenticator.md:89) | Gate is `len<8 ‖ len>128` → 8..=128 inclusive — off-by-one if contract means exclusive | `pair.md:71` + `authenticator.md:89` vs `engine.rs:136-141` |
| PAIR-8 | "repeat nonce at issue → `ReplayDetected`" | Nonce recorded **before** `insert_challenge` — a failed insert permanently burns the nonce | `pair.md:27` vs `engine.rs:291-303` |
| PAIR-9 | `suspend_device` listed, no transition rules | Code permits `pending`/`active`→`suspended`; `revoked`→`DeviceRevoked` — undocumented | `pair.md:55` vs `engine.rs:232-242` |
| CON-4 | Every text field besides notes refuses control characters | `tags` (list-row/chip-rendered) and `id` not covered — rationale applies equally | `contacts.md:134-141` vs `contact.rs:253-257,301-317` |
| CON-5 | email = "one `@`, non-empty local+domain, no whitespace/controls" | Also rejects domains starting/ending `.` — stricter, undocumented | `contacts.md:121,130-132` vs `contact.rs:339-348` |
| CON-6 | tags "de-duplicated, case-insensitively" | `eq_ignore_ascii_case` — ASCII-only; `Kürbis`/`KÜRBIS` not deduped (ASCII caveat documented only for search) | `contacts.md:52` vs `contact.rs:161-167` |
| CON-7 | "`contract_version` is `kiwi.contacts/1`" | No `CONTRACT_VERSION` const exists in the crate (siblings expose one) | `contacts.md:31` vs `kiwi-contacts/src/` — 0 occurrences |
| CON-9 | Contract silent on IPC input bounds | Extra bounds: `query`/`contactId` ≤256, `address` ≤320, `tag` ≤64, `contactIds` ≤500 — harmless hardening | `commands/contacts.rs` L28-30,65,160,176,281-283 |
| CON-10 | imports "never supply an `id` — vCard `UID` → `source_uid`" | Behavior correct but `store.rs` doc comment claims "import keeps vCard-derived keys" — misdescribes flow | `contacts.md:96-97` vs `store.rs:159-161`, `commands/contacts.rs:233-241` |
| CON-11 | "audit records on writes" | `contacts-imported` recorded only when ≥1 card stored — all-issues imports write no audit row | `ipc.md:562` vs `commands/contacts.rs:257-265` |
| AUTH-10 | "QR validity ≤ 5 minutes" | `expires>issued` + `now<expires` enforced but not ≤300 s; `kiwi-pair` mints +300 correctly | `authenticator.md:93` vs `qr.ts:57-58,79-81`, `engine.rs:31` |
| AUTH-11 | expired → "record `expired` locally" | `LedgerEntry.decision` supports `'expired'`; nothing ever records it | `authenticator.md:214-215` vs `replay.ts:13`, `PendingApprovalsScreen.tsx:52-55` |
| AUTH-12 | ReplayLedger "prunes entries older than 1 hour" | `prune(maxAgeSecs)` exists but is wired nowhere — no caller, no 3600 constant | `authenticator.md:187-189` vs `replay.ts:44-54,61` |
| AUTH-13 | user sees "desktop label, transaction id, issue/expiry times" | Status shows event phrase + `expires_unix` only; no desktop-label field exists in either payload — contract under-specifies | `authenticator.md:219-223` vs `PendingApprovalsScreen.tsx:56-60,104` |
| AUTH-14 | "bounded errors" on parse failure | `parseChallengeData` interpolates untrusted `schema_version` verbatim into the thrown message — unbounded status text | `authenticator.md:48-49` vs `canonical.ts:73`, `PendingApprovalsScreen.tsx:62-63` |
| AUTH-15 | RN root registered as "KIWI Authenticator" | Registers `app.json.name` = `"kiwi-mobile"`; "KIWI Authenticator" is only `displayName` | `authenticator.md:303` vs `mobile/index.js:3-5`, `app.json:2-3` |
| AUTH-16 | `x-tx:` session ids reserved for recovery/elevated-action | Test fixture pairs `x-tx-test-0001` with `event:'unlock'` — synthetic-only, contradicts documented form | `authenticator.md:169-174` vs `mobile/tests/helpers/protocol.ts:21-22` |
| ACFG-15 | §2 bounds list | Undocumented extras: local part ≤64; `trim()` on input | `autoconfig.md:33-35` vs `lib.rs:131-137` |
| ACFG-16 | "trailing dot stripped" (one) | `trim_end_matches('.')` strips **all** trailing dots | `autoconfig.md:37` vs `lib.rs:91,94,159-161` |
| ACFG-17 | socketType `plain`/`none`→Plaintext | Also accepts undocumented `"plaintext"` spelling | `autoconfig.md:112` vs `autoconfig_xml.rs:434` |
| ACFG-18 | §3 one table row per stage | Stage 4 emits **two** `mx_heuristic` attempts when MX empty — trail shows 6 for 5 stages | `autoconfig.md:47-53` vs `discovery.rs:184-217` |
| ACFG-19 | "53 tests" | 60 `#[test]`s present | `autoconfig.md:150` vs `src/*.rs` |
| MAUTH-6 | "Key missing → `fail`" | NXDOMAIN → Fail ✓ but NODATA (no `v=DKIM1`) → `PermError` — "missing" ambiguous | `mailauth.md:59` vs `dkim.rs:392-418` |
| MAUTH-7 | `record` "≤4096", `decided_by` ≤300, `explanation` ≤500 (bytes implied) | Caps use `chars().take(N)` — multibyte content can exceed byte bounds (same pattern: autoconfig `MAX_XML_LEN`) | `mailauth.md:36-40` vs `spf.rs:172,181-182,286-299` |
| MAUTH-8 | `MockResolver` builders incl. `with_temp_fail` | `with_temp_fail` doesn't affect `lookup_ptr` — PTR-path temperror unmockable | `mailauth.md:84` vs `dns.rs:102-110,136-138` |
| SS-4 | "canonical shape (JSON)", "unknown enum values/new fields ignored, not fatal" | No serde derives exist in kiwi-core at all (deliberate — mappers live in kiwi-app; all spellings verified correct except SS-2). Nothing enforces version-skew tolerance | `security-session.md:27,20` vs `types/mod.rs:3,43-175` |
| SS-5 | `Degraded` entered via signals/score; `degrade_threshold=80` | Also degrades on **any** Medium+ signal regardless of score — undocumented trigger | `security-session.md` §4-5 vs `trust.rs:229-231` |
| SS-6 | Locked entered "whenever `score < lock_threshold`" | Locked machine's `score` is overwritten by each eval — reports `score()==100` while Locked (misleading telemetry) | `security-session.md:98-99` vs `trust.rs:140` |
| SS-7 | "`repeated-auth-failure`" indicator | Fires on a **single** `auth_succeeded == Some(false)` | `security-session.md:89-96` vs `policy.rs:122-124` |
| SS-8 | signed payload = "length-prefixed fields" | Only 4 string fields length-prefixed; matches authenticator.md §4.1 authoritative encoding — ambiguous wording here | `security-session.md:140-142` vs `challenge.rs:57-74`, `authenticator.md:136-145` |
| SS-9 | unlock w/o authenticator = "an authorized admin/re-auth path (audited)" | `attempt_unlock` succeeds with `authenticator_approved=false`; "authorized" is entirely caller-side, no signal emitted | `security-session.md:116` vs `trust.rs:172-189` |
| UIS-4 | `KIWI-UI-020` snooze — list/reader action + Snoozed folder | Nothing but a demo folder label + unused CSS token. **Held, not dropped** (T-189) | `ui-surfaces.md:40` vs `mock.ts:72`, `mailspring-tokens.css:200`, `TASKS.md:118` |
| UIS-18 | `KIWI-UI-014` "Folder tree" | Sidebar renders a **flat** list (`role="tree"` but no nesting) | `ui-surfaces.md:34` vs `chrome.tsx:130-149`, `state/accounts.ts:45-55` |
| UIS-19 | — | `state/mailbox.ts` exports 626-line `useMailbox` — **never imported**; `App.tsx` header claims it uses the hook (stale) | `state/mailbox.ts:74` vs `App.tsx:4,12-19` |
| UIS-20 | — | Unused IPC wrappers: `submitChallenge`, `registerDevice`, `getContact`, `contactsByEmail` | `ipc.ts:106-116,212-228,330-332` |
| INT-6 | `docs/API_CONTRACTS.md` is the contract index | Fails to index existing `contacts.md`, `autoconfig.md`, `mailauth.md`, `pair.md`, `sandbox.md` (and future `integrations.md`) | `API_CONTRACTS.md:7-14` vs `docs/contracts/` listing |

## Info — implemented but undocumented / not-yet-implemented documented

| ID | Note | Evidence |
|----|------|----------|
| IPC-15 | Frontend calls unregistered `kiwi_get_prefs`/`kiwi_set_prefs`/`kiwi_lookup_autoconfig`/`kiwi_search_messages` (H-rated as UIS-5/6/7); **no wrappers exist** for registered `kiwi_schedule_send`, `kiwi_sync_status`, `kiwi_contacts_by_tag`, `kiwi_contact_tags`, `kiwi_import_vcards`, `kiwi_export_vcards`; stale "backend pending" comments | `ipc.ts:140-181`; `lib.rs:80,91,113-116` |
| IPC-16 | `kiwi://mail-changed` emitted correctly (payload field-for-field) but **no frontend `listen`** — only `kiwi://outbox` consumed | `syncer.rs:61,116` vs `mailbox.tsx:177` |
| FOR-I | ~30 undocumented pub groups: `PeerRole`, `TlsVersion` helpers, `cipher_table`, `CertThresholds` extras, `MAX_SAN_ENTRIES`, `DistinguishedName`/`SignatureAlgorithm`/`PublicKeyAlgorithm`/`HostnameMatch`/`CertificateProblem`, `CredentialKind`, `AuthMechanism::ALL`, `SessionId::from_label`, `EvidenceKind` vocabulary, `SeverityCounts`, `FindingKey`/`FindingBuilder`, diff types, `SecurityScore` shape (embedded in `Report.score` — `score.{score,grade,deduction_points,counts,dimmed_repeats,model_version}` unspecified), `Grade` serialized `"a".."f"`, `ScoringPolicy`/`Weights`, `Rule` trait + `RuleEngine` surface, `EvaluationDiagnostics.sessions_evaluated`, `AnalyzerLimits` defaults, `CaptureLimits`/`ReassemblyLimits` defaults, `CaptureError` (8 variants — no documented error model for pipeline), `SkipCount`, `PipelineDiagnostics` fields, `CaptureOptions`, `live::*` types (`SocketMode`, `LiveCertVerdict`, …) | `kiwi-forensics/src/` |
| ADM-19 | `OrgService.listDomains` RBAC-gated with no route and no contract row (`createDevice` disclosed in §14.6; `getPolicyDefinition` is a helper) | `policy/services.ts:123-126` |
| SBX-I | Extra `"agent":"shell-busybox"` top-level report field; `MAX_FINDINGS`(256 KiB)/`DEFAULT_MAX_ARTIFACT_BYTES`(64 MiB) values undocumented; `Result` alias, `Availability` helpers, `NullProvider`/`Wsl2Provider`/`Wsl2Config` pub surface | `agent.sh:174`, `lib.rs:20-36,79-89`, `wsl2.rs:53-85` |
| PAIR-I | `PairEngine::store()` exposes full `PairStore` (12 pub methods, all-pub row fields) — parallel public API; `PairingTicket` fields, `CHALLENGE_TTL_SECS=120`, `ChallengeBook` re-export, `algorithm_supported` undocumented | `engine.rs:31-35,48-52,106-108`, `lib.rs:24-34,82` |
| CON-I | Undocumented pubs: two-phase vCard API (`parse_vcards`, `RawCard`, `Property::{param,is_preferred}`), `parse_timestamp`/`format_timestamp`/`VCARD_VERSION`, `export_vcard(s)`, `VCardImport::is_complete`, `ContactStore::{count,schema_version,open_memory}`, `SCHEMA_VERSION`, `MAX_PAGE` | `vcard.rs:103-140,320,440,497,826,843`, `store.rs:22,80,99,141,150` |
| AUTH-I | Phase-4 gaps (expected): pairing channel unimplemented (no hello/registered messages, no pin check — screen simulates success); real platform keystore absent (`UnavailableKeystore` fail-closed ✓); no live `ChallengeTransport`; `ReplayLedger`/`ChallengeQueue` in-memory only. Undocumented module: `src/qr/` 623-line ISO/IEC 18004 QR encoder (imported only by tests; header comment contradicts §3.1 desktop-renders-QR flow) + `_debug.test.ts` leftover | `PairingScreen.tsx:24-25,62-74`, `transport/transport.ts`, `keystore.ts`, `mobile/src/qr/` |
| ACFG-I | Large undocumented surface incl. `Error::{InvalidDomain,TooLong}`, `WELL_KNOWN_PATH`/`AUTOCONFIG_HOST_PATH`, `ispdb::lookup_email`, `IspdbEntry`, `heuristics::*` helpers (`guess` unused by `discover`), `ManualEntry` API, `ClientConfig`/`ServerSpec`/`OAuth2Spec` types, `MxRecord`, and the entire `oauth2` module (~20 pub items) | `kiwi-autoconfig/src/` |
| MAUTH-I | `Error` variants, `DomainName`+`is_subdomain_of`, bound consts, `SpfInput`/`DkimInput`/`DmarcInput` field sets, `SigAlgorithm`/`AlignMode`/`DmarcPolicy`/`DmarcVerdict` type names, `dns::DnsError`; `rand_core` is a non-dev dep used only by tests | `kiwi-mailauth/src/`, `Cargo.toml` |
| SS-I | `trust::evaluate` free fn, `UnlockError`, `TrustMachine` accessors, `KeyAlgorithm` (incl. `Rsa3072` reserved), `Device`/`DevicePublicKey`/`DeviceRegistry` surface, `AccountStatus::{Suspended,RecoveryPending}`, `RecoveryPolicy`, `SessionBook::{issue,revoke,new}`, `ChallengeBook::is_consumed`, `TlsVersion::is_deprecated` | `kiwi-core/src/` |
| UIS-21 | §3 event row documents `eventId`,`timestamp`; wire uses `id`,`tsUnix` (UI maps correctly — doc drift) | `ui-surfaces.md:86-87` vs `ipc.md:499-503` |
| UIS-22 | Undocumented surfaces implemented: `#/search`, `#/contacts`, `#/filters` routes + CommandPalette + ShortcutsHelp + ToastStack; extras under existing anchors (threads, bulk bar, vCard IO, outbox "send all") | `router.ts:8,30-35`, `components/palette.tsx:18`, `shortcuts.tsx:23`, `toasts.tsx` |
| INT | **`docs/contracts/integrations.md` absent** while `kiwi-integrations/src/lib.rs:16` + `http.rs:8` cite it as authoritative (dangling refs). Code exists: `IntegrationError` (11 variants), `HttpClient`/`ReqwestClient` (HTTPS-only pre-socket, no redirects, 1 MiB body cap), `TempMailProvider`+`GuerrillaMail`, `DeliverabilityTester`+`EmailSpamTester`. Gaps: no consumers/workspace wiring; consent-gating + `PUBLIC_INBOX_NOTICE` have no enforcement point; integrations-specific ADR-009 entry not written (`DECISIONS.md:107` is the generic rule); tests inline-only; no `agent-11-status.md` | `kiwi-integrations/src/`, `TASKS.md:154` |

---

## Cross-cutting patterns (worth a single fix decision each)

1. **Serde vocabulary drift (systemic).** Contracts document semantic
   spellings (`as_str()` / kebab / dotted) while code derives
   `rename_all="snake_case"`. Diverges for 19+ forensics variants (FOR-1),
   `SocketSecurity`/`AuthKind` in autoconfig (ACFG-12/13), `SigAlgorithm` in
   mailauth (MAUTH-4). One variant (`XOAuth2`) has **three** spellings across
   the tree. Fix direction: either rename enums via `#[serde(rename)]` to the
   documented spellings, or amend the contracts — a Lead/contract-owner call.
2. **No `#[serde(other)]` anywhere** (FOR-6, MAUTH-5, plus autoconfig enums).
   The "unknown values ignored, not fatal" invariant in API_CONTRACTS.md is
   asserted by contracts but unenforced — forward-versioned payloads fail
   deserialization instead of degrading.
3. **`chars()` vs byte caps** — render 8 MiB (IPC-14), mailauth field caps
   (MAUTH-7), autoconfig `MAX_XML_LEN`. Byte-documented, char-implemented.
4. **Dead variants / unreachable documented codes** — `ImageMissing` (SBX-2),
   `TicketConsumed` while `ipc.md:891` promises `pairing-ticket-consumed`
   (PAIR-2), `challenge-expired` vs emitted `"expired"` where **the two
   contracts disagree** (IPC-4), forensics limitation codes never emitted
   (FOR-10).
5. **Frontend↔backend name drift** — `ipc.ts` invokes 4 names in no contract
   or registry; 6+ registered commands have no wrapper; `kiwi://mail-changed`
   is emitted but never listened (IPC-15/16, UIS-5/6/7/13/17). T-191 rebuild
   should reconcile the wrapper layer against ipc.md verbatim.
6. **Contract-stale after approved fixes** — admin-api.md still describes
   pre-T-193 behavior for org-defaulting, verify scope, and the createOrg
   permission cell (ADM-2/3/4/6). These are doc-updates owed to Agent 13/18,
   not code bugs.
7. **Audit-coverage gaps** — challenge failure paths unaudited (AUTH-1),
   admin read-path denials unaudited (ADM-5), zero-contact imports unaudited
   (CON-11). "Every outcome audited" is claimed in contracts; three surfaces
   don't honor it.

## Per-contract verified-consistent summaries

- **ipc.md**: all 51 implemented commands registered + documented; lock-gate
  exempt set matches §2 exactly; all top-level param names match (one param
  exception: IPC-8); all documented bounds/defaults verified (limits, clamps,
  TTLs, caps); both events emitted with exact names/payloads. The drift is in
  **view shapes** (IPC-1/2/6/7) and frontend wrapper names.
- **forensics.md**: constants (`CONTRACT_VERSION`, `RULE_CATALOG_VERSION`,
  `SCORING_MODEL_VERSION`), event/finding/evidence field sets, redaction
  rules, all 37 rule ids + severities (except FOR-3/8), scoring weights/grades,
  determinism (no clocks/floats/HashMap), report fields, §10 pipeline stage
  order and bounds, §11 live mapping — all verified.
- **admin-api.md**: all 15 §3 routes present except the contract-declared
  not-implemented `GET /orgs/{o}/devices`; RBAC matrix verbatim; fail-closed
  actor scaffold; error envelope + codes incl. now-emitted `conflict`; §13
  export exact (NDJSON layout, covers_through, key_id, self-audit); §5.2
  evaluator order + all 7 reason codes; §4 schema both dialects.
- **sandbox.md**: all 10 types + both traits signature-exact; invariants 1,3,4,
  6,7 verified in `wsl2.rs`/`agent.sh`; report.json schema emitted as
  documented (modulo SBX-3..7 nuances); sha256 cap; host-observed watchdog
  overrides guest self-report.
- **pair.md**: all 12 `PairEngine` methods signature-exact; verify ordering
  exact; atomic consume; ticket charset/TTL; pending-gate; auto-activate;
  revoke terminal+idempotent; nonce ledger caps; fingerprint vector;
  pair.db DDL (4 tables, FK, user_version=1); QR JSON exact field set; all 16
  error variants present.
- **contacts.md**: `Contact`/`ContactView` shapes; all 11 commands registered
  + lock-gated; `local-N` id assignment + rejection; search escaping/ordering;
  all byte bounds; VCardLimits defaults; VERSION gate; PREF promotion; export
  escaping/folding; §6 schema; §7 error mapping; re-import dedup path.
- **authenticator.md**: canonical bytes **byte-exact** vs kiwi-core;
  event-tag table identical; QR/challenge parse strict+bounded; response
  shape; replay ledger one-answer-per-id + 256 cap; queue FIFO/dedupe/
  throttle; `boot-<hex>` session ids; Ed25519-only verifier.
- **autoconfig.md**: stage order, `as_str()` spellings, `needs_manual_review`
  rule, `InvalidEmail`-only discovery error surface, outcome/attempt shapes,
  ranking rules, `checked()` rules, id/key formats, `DiscoveryNet`/`MockNet`
  seam, all T-158-named tests.
- **mailauth.md**: `SpfOutput`/`DkimOutput`/`DmarcOutput` verbatim; verdict
  vocabularies; limits 10/2/5; macro fail-closed; DKIM verify order; header
  selection + `b=` self-reference; caps; DMARC org-heuristic/alignment/
  sampling; `DnsResolver` trait shape.
- **security-session.md**: `SecuritySession` field-for-field; all 19
  `SignalKind` variants; `TrustEvaluation` + 5 `RequiredAction` variants;
  score = 100−Σ; hard-lock + threshold→Locked; Locked never self-recovers;
  all §5 policy defaults; challenge verify order + single-use + nonce reuse;
  device/identity/session lifecycle.
- **ui-surfaces.md**: 17/23 surfaces present (6 partial); 002 chip, 004
  finding dialog w/ `kiwi_finding_detail`, 005 lock overlay + inert panes,
  006 authenticator dialog w/ challenge IPC, 010 security center, 011 admin UI,
  014-018 mail path, 019 wizard — verified. Severity vocabulary structurally
  consistent with producer remap.

## Suggested fix order (for Lead)

1. **IPC-1/IPC-2** — reconcile view shapes (or amend ipc.md); fronts the
   pending frontend rebuild.
2. **FOR-1/FOR-2** — pick one enum wire vocabulary; affects every JSON
   report + re-scan diffing.
3. **AUTH-1/AUTH-2 + IPC-3** — before Phase-4 pairing transport lands:
   `decision` field, failure audits, `nonceB64`.
4. **SS-1** — locked-state `required_action` invariant (one-line splice fix).
5. **PAIR-1/PAIR-2 + SBX-1/SBX-2** — small contract-or-code decisions.
6. **UIS-5/6** — rename frontend wrappers to the registered names (independent
   of T-191 layout work).
7. Contract bookkeeping: write `integrations.md` + `oauth2.md`, index six
   existing contracts in `API_CONTRACTS.md`, resolve the `challenge-expired`
   contract-vs-contract disagreement, update admin-api.md for T-193 behavior.
### Missing / divergent table

| finding | current source or registry | `ipc.md` surface | disposition for T-241 |
|---|---|---|---|
| `IPC-T241-1` | `AccountView` emits `protocol`, `incomingHost/Port`, `outgoingHost/Port`, `unread`, `trust` (`types/accounts.rs:12-25`) | §5 promises nested `incoming/outgoing`, `incomingProtocol`, `username`, `unreadCount`, `trustToken` (`ipc.md:149-157`) | Existing IPC-1 shape drift; do not rewrite a T-239 decision in this docs-only pass |
| `IPC-T241-2` | `FolderView` emits `accountId`, `uidNext`, `highestUid`; `uidValidity` nullable (`types/mail.rs:9-17`) | §6 promises `exists` and `unseen` and non-null `uidValidity` (`ipc.md:290-294`) | Existing IPC-6 shape drift; flag for T-239 |
| `IPC-T241-3` | `MessageView` emits nullable `from`/`to` plus `unread`, `starred`, `bodyStored`, `category`, `unsubscribe*` (`types/mail.rs:21-58`) | §6 promises `fromAddr`/`toAddrs` and a smaller shape (`ipc.md:296-306`) | Existing IPC-7/11 drift; flag for T-239 |
| `IPC-T241-4` | Tauri argument is Rust `vcard_text`, so wire name is `vcardText` (`commands/contacts.rs:205-212`) | §9b command table says `vcard` (`ipc.md:722-734`) | Existing IPC-8 naming drift; no command is missing |
| `IPC-T241-5` | `EndpointObservation` has no serde rename and emits `evidence_ref` (`signals.rs:58-68`) | §10 promises `evidenceRef` (`ipc.md:1354-1367`) | Existing IPC-9 drift; no command is missing |
| `IPC-T241-6` | `kiwi_lookup_autoconfig` is registered with the canonical discovery signature (`commands/autoconfig.rs:46-52`, `lib.rs:81`) | The current §5 alias note documents the name and identical response (`ipc.md:282-285`) | Resolved in current worktree; do not add a duplicate command surface |
| `IPC-T241-7` | Five §9d logical pairing names are documented but have no Rust functions/handler entries | §9d explicitly says handlers are pending (`ipc.md:764-779`) | Intentional documentation-only future surface; not a T-241 omission |

### T-241 documentation changes

- Added the explicit lazy-body policy to `docs/contracts/rules.md`: sync does
  not fetch bodies solely for body predicates; `kiwi_rules_apply_now` and
  already-available body refinement paths are the evaluation points.
- Added the same bandwidth/binding note to `ipc.md` §6d so the IPC contract
  cannot be read as authorizing eager body downloads.
- The T-230 `kiwi_lookup_autoconfig` alias was already present in the current
  worktree and was not duplicated. No new non-in-flight command entry was
  missing after the current T-230/T-233/T-234/§9e reconciliation.
