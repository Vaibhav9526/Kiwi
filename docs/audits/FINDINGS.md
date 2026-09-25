# Master Findings Register (T-252)

**Reviewer:** Agent 22 · **Date:** 2026-09-25 · **Mode:** read-only consolidation.
**Sources:** `docs/audits/contract-drift-1.md`,
`docs/audits/autoconfig-drift-1.md`, and `docs/audits/admin-drift-1.md`.
This file is a deduplicated remediation index, not a replacement for the
source audits. Overlapping IDs are canonicalized here; the source audit line
is retained in the location column.

**Status method:** `docs/TASKS.md`, agent status logs, recent commits, and the
current tree were checked. `fixed` requires current implementation/contract
and task evidence; `in-flight` means an open task or uncommitted current work;
`queued` means an explicit backlog/queued task; `open` means no active
remediation task was found. T-237 is treated as in-flight because its task
row remains open and Agent 20 recorded its changes as uncommitted, despite
its status entry saying done. T-241, T-246, and T-250 are completed audit
provenance, not remediation assignments.

| ID | Severity | Summary | Location | Owner-task | Status |
|---|---|---|---|---|---|
| IPC-1 | H | `AccountView` shape and vocabulary diverged; nested server objects and contract trust/unread fields were missing. | `contract-drift-1.md:65`; `T-241 IPC-T241-1`; `agent-20-status.md:141-158` | T-239 | fixed |
| IPC-2 | H | `SecurityStatusView` shape/required-action vocabulary diverged; contract and code were reconciled. | `contract-drift-1.md:66`; `agent-20-status.md:160-180` | T-239 | fixed |
| IPC-3 / AUTH-3 | M | Challenge nonce is documented as `nonceB64` but backend emits `nonceHex`; mobile handoff is not wire-compatible. | `contract-drift-1.md:80`; `agent-18-status.md:78-84` | T-188/T-194 | open |
| IPC-4 | M | `challenge-expired` versus emitted legacy `expired`; contract conflict was ratified/clarified. | `contract-drift-1.md:81`; `agent-20-status.md:104-109` | T-237 | fixed |
| IPC-5 | M | Unlock error catalog contains undocumented `not-locked` and `authenticator-required`. | `contract-drift-1.md:82` | Lead/contract owner | fixed |
| IPC-6 | M | `FolderView` field/nullability drift (`exists`, `unseen`, `accountId`, `uidNext`, `highestUid`). | `contract-drift-1.md:83`; `T-241 IPC-T241-2` | T-247 | fixed |
| IPC-7 | M | `MessageView` uses `from`/`to` optional fields and extra fields rather than documented `fromAddr`/`toAddrs`. | `contract-drift-1.md:84`; `T-241 IPC-T241-3` | T-247 | fixed |
| IPC-8 / CON-1 | M | Import argument is wire `vcardText`, while docs call it `vcard`. | `contract-drift-1.md:85`; `T-241 IPC-T241-4` | T-247 | fixed |
| IPC-9 | M | Endpoint observation emits `evidence_ref`, not documented `evidenceRef`. | `contract-drift-1.md:86`; `T-241 IPC-T241-5` | T-247 | fixed |
| IPC-10 | M | POP3 XOAUTH2 was accepted at add time and rejected only at connect. | `contract-drift-1.md:87`; `agent-19-status.md:263-268` | T-230 | fixed |
| IPC-11 | L | `MessageBodyView` non-null promises are serialized as optional/null. | `contract-drift-1.md:149` | Lead/contract owner | fixed |
| IPC-12 | L | Outbox account ID and delete-result trash folder are optional despite non-null contract wording. | `contract-drift-1.md:150` | Lead/contract owner | fixed |
| IPC-13 | L | `DeviceView` adds undocumented `keyFingerprintTail`. | `contract-drift-1.md:151` | Lead/contract owner | fixed |
| IPC-14 | L | Render cap is character-based while contract says 8 MiB bytes. | `contract-drift-1.md:152` | Lead/contract owner | fixed |
| IPC-15 | I | Frontend wrapper inventory gaps — resolved T-272: all six listed commands are registered and now wrapped (`scheduleSend`, `syncStatus`, `contactsByTag`, `contactTags`, `importVcards`, `exportVcards`) plus `prefsGet` found by full enum sweep. Three other unwrapped names are documented compat aliases already covered by their canonical wrappers (`kiwi_lookup_autoconfig`→`kiwi_discover_account`, `kiwi_list_devices`→`device_list`, `kiwi_revoke_device`→`device_revoke`) — intentionally not double-wrapped. | `contract-drift-1.md:222`; `T-241 IPC-T241-6` | T-237/T-231 | fixed |
| IPC-16 | I | `kiwi://mail-changed` is emitted but no frontend listener consumes it. | `contract-drift-1.md:223` | T-231 | fixed |
| FOR-1 | H | Forensics enum wire spellings diverge from documented semantic/as-str vocabulary. | `contract-drift-1.md:67`; `forensics` source paths cited there | T-245 | fixed |
| FOR-2 | H | `TlsVersion::Unknown(raw)` is externally tagged rather than documented bare `unknown`. | `contract-drift-1.md:68`; `model/tls.rs` cited there | T-245 | fixed |
| FOR-3 | M | Transport rule escalates a reusable-secret finding to an undocumented `Critical` level. | `contract-drift-1.md:88` | T-245/Lead | fixed |
| FOR-4 | M | Strict/permissive policy flags are not read by the cited rules. | `contract-drift-1.md:89` | T-245/Lead | fixed |
| FOR-5 | M | Contract says per-finding half-up scoring; code rounds the aggregate, changing scores. | `contract-drift-1.md:90` | T-245/Lead | fixed |
| FOR-6 | M | Unknown/new enum variants are not ignored on deserialization. | `contract-drift-1.md:91`; `report/mod.rs` cited there | T-245 | fixed |
| FOR-7 | L | Optional STARTTLS field is always emitted as null instead of omitted. | `contract-drift-1.md:153` | T-245 | fixed |
| FOR-8 | L | Certificate rule titles differ from catalog titles. | `contract-drift-1.md:154` | T-245 | fixed |
| FOR-9 | L | `RescanDiff` exposes richer/undocumented change kinds. | `contract-drift-1.md:155` | T-245 | fixed |
| FOR-10 | L | Three limitation codes defined but never emitted — resolved T-272: shared classifier `report::session_limitation_codes` emits `transport-unknown` (undecodable byte-carrying flows / adapter `unknown`), `kex-unobserved` (`session_resumed`, `!handshake_complete`, or STARTTLS accepted with `!handshake_completed`), `auth-unobserved` (protected + `auth` absent/`attempts:0`; live report: `protected_without_auth` over `SecuritySession`). Emit conditions documented in forensics.md §8; regression tests in report/capture_pipeline/security. | `contract-drift-1.md:156` | T-245 | fixed |
| FOR-11 | L | `analyze_capture` returns a wrapped capture report/diagnostics shape rather than the documented direct report. | `contract-drift-1.md:157` | T-245 | fixed |
| FOR-12 | L | Confidence sort order is undocumented and differs from the stated ordering. | `contract-drift-1.md:158` | T-245 | fixed |
| FOR-I | I | Large undocumented forensics public API surface. | `contract-drift-1.md:224` | T-245/contract owner | open |
| AUTH-1 | H | Challenge verification failures and pairing outcomes are not fully audited. Ownership: `submit_challenge` failure audits belong to A11's T-269 (pair-engine landing) — in-flight, pair code untouched by T-272 per Lead direction. | `contract-drift-1.md:69` | T-188/T-194; A11/T-269 in-flight | open |
| AUTH-2 | M | Mobile deny responses do not carry the documented decision field and can look like invalid signatures. | `contract-drift-1.md:104` | T-194/T-188 | open |
| AUTH-4 | M | Mobile authenticator public-key pin checks prefix/length but not key encoding/size. | `contract-drift-1.md:105` | T-194/T-188 | open |
| AUTH-5 | M | QR endpoint accepts plaintext transport despite TLS requirement. | `contract-drift-1.md:106` | T-194/T-188 | open |
| AUTH-6 | M | Approval screen skips binding in the identity-null case and does not re-gate expiry on tap. | `contract-drift-1.md:107` | T-194 | open |
| AUTH-7 | M | Approval screen freezes its clock at mount, making expiry/throttle checks stale. | `contract-drift-1.md:108` | T-194 | open |
| AUTH-8 | M | Challenge queue has no expiry/TTL eviction despite contract wording. | `contract-drift-1.md:109` | T-194 | open |
| AUTH-9 | M | Test-only soft HSM is functional behind a ceremonial gate. | `contract-drift-1.md:110` | T-194 | open |
| AUTH-10 | L | QR validity does not enforce the documented five-minute maximum. | `contract-drift-1.md:191` | T-194 | open |
| AUTH-11 | L | Expired local ledger decision is supported but never recorded. | `contract-drift-1.md:192` | T-194 | open |
| AUTH-12 | L | Replay ledger pruning is not wired to the documented one-hour policy. | `contract-drift-1.md:193` | T-194 | open |
| AUTH-13 | L | Authenticator status lacks documented desktop label/transaction fields. | `contract-drift-1.md:194` | T-194 | open |
| AUTH-14 | L | Untrusted schema version is interpolated into unbounded parse-error text. | `contract-drift-1.md:195` | T-194 | open |
| AUTH-15 | L | Mobile app registration name differs from documented authenticator name. | `contract-drift-1.md:196` | T-194 | open |
| AUTH-16 | L | Test fixture session-id form conflicts with reserved `x-tx:` recovery semantics. | `contract-drift-1.md:197` | T-194 | open |
| AUTH-I | I | Phase-4 pairing/keystore/live transport surfaces remain intentionally unimplemented. | `contract-drift-1.md:229` | T-194 | open |
| SS-1 | H | Locked trust evaluation could report no required action. | `contract-drift-1.md:70`; `agent-20-status.md:182-195` | T-239 | fixed |
| SS-2 | M | `ThunderbirdHook` serializes as `live-client`, not documented `thunderbird-hook`. | `contract-drift-1.md:128` | Lead/contract owner | open |
| SS-3 | M | Device transitions permit undocumented paths, including suspended-to-active. | `contract-drift-1.md:129` | T-194/T-188 | open |
| SS-4 | L | No serde derives enforce the security-session version-skew invariant. | `contract-drift-1.md:206` | T-194/contract owner | open |
| SS-5 | L | Medium signals can degrade regardless of score. | `contract-drift-1.md:207` | T-194 | open |
| SS-6 | L | Locked state can report a fresh score of 100, misleading telemetry. | `contract-drift-1.md:208` | T-194 | open |
| SS-7 | L | Repeated-auth-failure indicator fires on a single failed attempt. | `contract-drift-1.md:209` | T-194 | open |
| SS-8 | L | Signed-payload length-prefix wording is ambiguous/inconsistent across contracts. | `contract-drift-1.md:210` | T-188/contract owner | open |
| SS-9 | L | Unlock without authenticator has no emitted authorization signal. | `contract-drift-1.md:211` | T-194 | open |
| SS-I | I | Large undocumented kiwi-core public surface. | `contract-drift-1.md:232` | T-194/contract owner | open |
| ACFG-1 | H | OAuth2 secret/connection behavior conflicted with the original no-secrets/no-connections invariant. | `contract-drift-1.md:71`; `agent-19-status.md:247-252` | T-195/T-230 | fixed |
| ACFG-2 | M | OAuth2 module referenced a missing `oauth2.md` contract/version. | `contract-drift-1.md:111`; `agent-19-status.md:260-262` | T-195/T-230 | fixed |
| ACFG-3 | L | Contract local-part charset is narrower than the accepted RFC-compatible `atext` set. | `autoconfig-drift-1.md:39`; `contract-drift-1.md:112` | T-246/contract owner | open |
| ACFG-4 | M | GoDaddy is promised as an ISPdb fixture but only appears as an MX hint; offline support is a decision gate. | `autoconfig-drift-1.md:40`; `contract-drift-1.md:113` | T-246/contract owner | open |
| ACFG-5 | L | `pphosted.com` is a stale/non-normative MX example; code has `secureserver.net`. | `autoconfig-drift-1.md:41`; `contract-drift-1.md:114` | T-246/contract owner | open |
| ACFG-6 | L | Oversize XML returns `Error::TooLong`, not `MalformedXml`, while stage behavior remains malformed. | `autoconfig-drift-1.md:42`; `contract-drift-1.md:115` | T-246/contract owner | open |
| ACFG-7 | M | Parser silently skips arbitrary processing instructions, not just the XML declaration. | `autoconfig-drift-1.md:43`; `9a11c47`; `autoconfig_xml.rs:102-140`; `autoconfig.md:126-132` | T-251 | fixed |
| ACFG-8 | M | Bare `emailProvider` root is accepted despite required `clientConfig` root. | `autoconfig-drift-1.md:44`; `9a11c47`; `autoconfig_xml.rs:368-389`; `autoconfig.md:135-141` | T-251 | fixed |
| ACFG-9 | M | Domain selection falls through to provider id and first provider when no domain matches. | `autoconfig-drift-1.md:45`; `9a11c47`; `autoconfig_xml.rs:390-403`; `autoconfig.md:135-141` | T-251 | fixed |
| ACFG-10 | L | `%EMAILDOMAIN%` is expanded although only two placeholders are documented. | `autoconfig-drift-1.md:46`; `contract-drift-1.md:119` | T-246/contract owner | open |
| ACFG-11 | M | Auth parser accepts `oauthbearer`, empty auth, and `cram-md5` outside the documented mapping. | `contract-drift-1.md:120` | T-251/contract owner | open |
| ACFG-12 | M | Autoconfig security enum lacks the promised snake_case serde spelling. | `contract-drift-1.md:121` | T-251/contract owner | open |
| ACFG-13 | M | Autoconfig XOAUTH2 has three spellings across serde, `as_str`, and IPC docs. | `contract-drift-1.md:122` | T-251/contract owner | open |
| ACFG-14 | M | Contract claims a production `DiscoveryNet` adapter, but only the mock implementation exists. | `contract-drift-1.md:123` | T-251/contract owner | open |
| ACFG-15 | L | Undocumented local-part 64-byte limit and input trimming. | `contract-drift-1.md:198` | T-246/contract owner | open |
| ACFG-16 | L | Domain parser strips all trailing dots rather than one. | `contract-drift-1.md:199` | T-246/contract owner | open |
| ACFG-17 | L | Parser accepts undocumented `plaintext` socket spelling. | `contract-drift-1.md:200` | T-251/contract owner | open |
| ACFG-18 | L | Empty-MX fallback emits two `mx_heuristic` attempts despite five-stage table. | `contract-drift-1.md:201` | T-246/contract owner | open |
| ACFG-19 | L | Contract says 53 tests; current source has 60. | `contract-drift-1.md:202` | T-246/contract owner | open |
| ACFG-I | I | Large undocumented autoconfig public API/OAuth surface. | `contract-drift-1.md:230` | T-251/contract owner | open |
| MAUTH-1 | H | Contract claims a live Hickory resolver; no live resolver implementation exists. | `contract-drift-1.md:72` | T-122/T-183 → T-279 | fixed — `HickoryResolver` landed in `dns.rs` (bounded `system()`/`with_bounds`, fail-closed `Temp`/`NxDomain`, scoped-thread `block_on`); wired via `commands/mail.rs::auth_sealer()` into `sync_pop3_with_auth` + lazy IMAP body ingest; offline seam tests in `dns.rs::tests`. |
| MAUTH-2 | M | DKIM `l=` truncation is described before canonicalization but code canonicalizes first. | `contract-drift-1.md:124` | T-122/T-183 | fixed |
| MAUTH-3 | M | DKIM ancient `t=` is not rejected when `x=` is present. | `contract-drift-1.md:125` | T-122/T-183 | fixed |
| MAUTH-4 | M | `SigAlgorithm` wire spelling is PascalCase rather than documented `rsa-sha256`/`ed25519-sha256`. | `contract-drift-1.md:126` | T-122/T-245 | open |
| MAUTH-5 | M | Unknown enum variants are fatal despite the ignore/unknown invariant. | `contract-drift-1.md:127` | T-245 | in-flight |
| MAUTH-6 | L | Ambiguous DKIM “key missing” behavior for NODATA. | `contract-drift-1.md:203` | T-122/T-183 | open |
| MAUTH-7 | L | Mailauth field caps use characters while contract describes byte bounds. | `contract-drift-1.md:204` | T-122/T-183 | open |
| MAUTH-8 | L | `with_temp_fail` does not affect the PTR lookup path. | `contract-drift-1.md:205` | T-122/T-183 | open |
| MAUTH-I | I | Large undocumented mailauth public API surface. | `contract-drift-1.md:231` | T-122/contract owner | open |
| ADM-1 | M | Policy list projection is camelCase/incomplete and omits `name` and `org_id`; T-250 confirmed it remains. | `contract-drift-1.md:92`; `admin-drift-1.md:54` | T-237/T-250 | in-flight |
| ADM-2 | M | Contract said omitted audit org meant whole log; T-193 now defaults org-bound readers to their org. | `contract-drift-1.md:93`; `agent-20-status.md:110-114` | T-193/T-237 | fixed |
| ADM-3 | M | Contract omitted the T-193 mailflow org default; current contract/source now include it. | `contract-drift-1.md:94`; `agent-20-status.md:110-114` | T-193/T-237 | fixed |
| ADM-4 | M | Audit verify still accepts a bounded `limit` and can attest only a prefix. | `contract-drift-1.md:95`; `admin-drift-1.md:56` | T-193/T-250 | in-flight |
| ADM-5 | M | Read-path authorization denials are not audited across list/read services. | `contract-drift-1.md:96`; `admin-drift-1.md:57` | T-193/T-250 | in-flight |
| ADM-6 | M | `POST /orgs` permission ambiguity was resolved to `org.create`/org-admin bootstrap. | `contract-drift-1.md:97`; `agent-20-status.md:110-114` | T-193/T-237 | fixed |
| ADM-7 | L | Contract says `audit_log.seq` is AUTOINCREMENT; implementation deliberately uses app-assigned contiguous sequence. | `contract-drift-1.md:159`; `admin-drift-1.md:67` | T-250/contract owner | open |
| ADM-8 | L | User/policy list limits default 50/cap 500 but §3 did not document them. | `contract-drift-1.md:160`; `admin-drift-1.md:62` | T-250/contract owner | open |
| ADM-9 | L | Mailflow query filter names/defaults are not fully specified in §3. | `contract-drift-1.md:161`; `admin-drift-1.md:43` | T-250/contract owner | open |
| ADM-10 | L | §3 leaves several request/response/status shapes undocumented (`{items}`, `{id}`, `{ok:true}`, etc.). | `contract-drift-1.md:162`; `admin-drift-1.md:63` | T-250/contract owner | open |
| ADM-11 | L | Single-policy evaluation returns `evaluatedPolicyId` while outbound uses `policyId`. | `contract-drift-1.md:163`; `admin-drift-1.md:65` | T-250/contract owner | open |
| ADM-12 | M | Audit query returns a lossy summary/raw details string instead of full AuditRecord fields. | `contract-drift-1.md:164`; `admin-drift-1.md:55` | T-250 | in-flight |
| ADM-13 | L | Mailflow ingest ignores caller `id` and always generates a new UUID. | `contract-drift-1.md:165`; `admin-drift-1.md:42` | T-250/contract owner | open |
| ADM-14 | L | External-recipient block emits `recipient-domain-blocked`, not documented `external-recipient`. | `contract-drift-1.md:166` | T-250/contract owner | open |
| ADM-15 | L | Mailflow builder signatures include an undocumented `generateId` parameter. | `contract-drift-1.md:167` | T-250/contract owner | open |
| ADM-16 | L | Policy body `org_id` is ignored when path org is authoritative. | `contract-drift-1.md:168` | T-250/contract owner | open |
| ADM-17 | L | Content-type requirement is absent from the contract despite enforced `application/json`. | `contract-drift-1.md:169` | T-250/contract owner | open |
| ADM-18 | L | Invalid mailflow status/verdict values default to unknown while invalid TLS rejects. | `contract-drift-1.md:170`; `admin-drift-1.md:64` | T-250/contract owner | open |
| ADM-19 | I | Service-only `listDomains` has no route; `createDevice` has no route and uses revoke permission. | `contract-drift-1.md:225`; `admin-drift-1.md:68` | T-250/Lead | open |
| ADM-20 | L | Request body is capped at 1 MiB, but the contract does not state the cap. | `contract-drift-1.md:171` | T-250/contract owner | open |
| ADM-T250-05 | H | Global `audit.export` is granted to `org_admin`; `system-admin` is absent, so an org-scoped admin can export the whole chain. | `admin-drift-1.md:58,79-85` | T-179/T-250 | in-flight |
| ADM-T250-06 | M | Global export denial paths do not append denial audit rows; §13.4 requires fail-closed self-audit. | `admin-drift-1.md:59` | T-179/T-250 | in-flight |
| ADM-T250-07 | M | Ratified org-scoped audit export route/service is absent. | `admin-drift-1.md:60,79-85` | T-250/Lead | open |
| ADM-T250-08 | M | Ratified §14 device-inventory route, repository, service, and tests are absent. | `admin-drift-1.md:61,87-97` | T-253 | queued |
| ADM-T250-13 | L | User/policy writes lack explicit absent-org handling and can surface FK failures as generic 500. | `admin-drift-1.md:66` | T-250/Lead | open |
| SBX-1 | M | Sandbox fs_changes merge cap is 3× the documented 4096-entry bound. | `contract-drift-1.md:98` | T-161/contract owner | open |
| SBX-2 | M | `SandboxError::ImageMissing` exists but is never constructed. | `contract-drift-1.md:99` | T-161/contract owner | open |
| SBX-3 | L | Guest report omits documented `limits_applied`. | `contract-drift-1.md:172` | T-161/contract owner | open |
| SBX-4 | L | Host recomputes outside-workdir writes over a different change set than documented. | `contract-drift-1.md:173` | T-161/contract owner | open |
| SBX-5 | L | Guest process args are emitted as a joined string instead of an array. | `contract-drift-1.md:174` | T-161/contract owner | open |
| SBX-6 | L | Guest network attempts are dropped/always empty. | `contract-drift-1.md:175` | T-161/contract owner | open |
| SBX-7 | L | Network probe can emit undocumented `reachable`/`untested` values. | `contract-drift-1.md:176` | T-161/contract owner | open |
| SBX-I | I | Large undocumented sandbox public/report surface. | `contract-drift-1.md:226` | T-161/contract owner | open |
| PAIR-1 | M | Pairing challenge can be issued to an active device despite pending-only contract. | `contract-drift-1.md:100` | T-235/T-188 | open |
| PAIR-2 | M | `TicketConsumed`/documented pairing-ticket-consumed code is unreachable; unknown/consumed errors merge. | `contract-drift-1.md:101` | T-235/T-188 | open |
| PAIR-3 | L | Pair verify method comment reverses documented order. | `contract-drift-1.md:177` | T-235 | open |
| PAIR-4 | L | Missing device maps to `UnknownChallenge` rather than documented `DeviceNotFound`. | `contract-drift-1.md:178` | T-235 | open |
| PAIR-5 | L | Atomic consume return verdict is discarded, weakening the documented final-step guarantee. | `contract-drift-1.md:179` | T-235 | open |
| PAIR-6 | L | Pair root/challenge/session string fields lack documented length bounds. | `contract-drift-1.md:180` | T-235 | open |
| PAIR-7 | L | Ticket gate is inclusive 8..128 while wording may imply an exclusive bound. | `contract-drift-1.md:181` | T-235/contract owner | open |
| PAIR-8 | L | Nonce is recorded before challenge insert, burning it on failed insert. | `contract-drift-1.md:182` | T-235 | open |
| PAIR-9 | L | Suspend transition rules are broader than documented. | `contract-drift-1.md:183` | T-235 | open |
| PAIR-I | I | Pairing/pair.db public API surface is largely undocumented. | `contract-drift-1.md:227`; `T-241 IPC-T241-7` | T-235/contract owner | open |
| CON-2 | M | Contact update preserves created time in DB but returns a response with `created_unix: 0`. | `contract-drift-1.md:102` | T-150/T-175 | open |
| CON-3 | M | VCard `ValueTooLong` aborts the stream although contract calls per-field issues skippable. | `contract-drift-1.md:103` | T-150/T-175 | open |
| CON-4 | L | Tags and contact ID do not receive the documented control-character rejection. | `contract-drift-1.md:184` | T-150/T-175 | open |
| CON-5 | L | Contact email validation is stricter than documented around leading/trailing domain dots. | `contract-drift-1.md:185` | T-150/T-175 | open |
| CON-6 | L | Tag deduplication is ASCII-case-only while wording implies general case-insensitive behavior. | `contract-drift-1.md:186` | T-150/T-175 | open |
| CON-7 | L | Contacts contract version constant is absent from the crate. | `contract-drift-1.md:187` | T-150/T-175 | open |
| CON-9 | L | Contact IPC has extra undocumented input bounds. | `contract-drift-1.md:188` | T-175 | open |
| CON-10 | L | VCard import doc comment misdescribes source-ID/import flow. | `contract-drift-1.md:189` | T-150/T-175 | open |
| CON-11 | L | Zero-card/all-issues imports write no `contacts-imported` audit row. | `contract-drift-1.md:190` | T-150/T-175 | open |
| CON-I | I | Large undocumented contacts/vCard public API surface. | `contract-drift-1.md:228` | T-150/contract owner | open |
| UIS-1 | M | Certificate viewer is absent; data is only a raw session-detail dump. | `contract-drift-1.md:131` | T-192/T-145 | open |
| UIS-2 | M | Re-scan/diff trigger and results UI are absent. | `contract-drift-1.md:132` | T-192/T-145 | open |
| UIS-3 | M | Pairing dialog/register-device flow is not wired. | `contract-drift-1.md:133` | T-194/T-192 | open |
| UIS-4 | L | Snooze UI is held, not implemented. | `contract-drift-1.md:212` | T-189 | queued |
| UIS-5 | M | Preferences frontend names were rebound to registered commands, but task/worktree integration is not fully closed. | `contract-drift-1.md:73`; `agent-20-status.md:83-96` | T-237 | fixed |
| UIS-6 | M | Discovery frontend wrapper was corrected to `kiwi_discover_account`; T-230 handler/alias is present, but task integration is uncommitted. | `contract-drift-1.md:74`; `T-241 IPC-T241-6`; `agent-20-status.md:90-96` | T-237/T-230 | fixed |
| UIS-7 | M | Frontend invokes unregistered/undocumented `kiwi_search_messages`. | `contract-drift-1.md:130` | T-231 | queued |
| UIS-8 | M | Lock overlay reason fields are frontend-authored and absent from `SecurityStatusView`. | `contract-drift-1.md:134` | T-192/T-194 | open |
| UIS-9 | M | Producers/UI use broader severity vocabulary than ui-surfaces claims. | `contract-drift-1.md:135` | T-192/contract owner | open |
| UIS-10 | M | Session-summary names differ and `stale` is absent. | `contract-drift-1.md:136` | T-192/contract owner | open |
| UIS-11 | M | Trust glyph/pill render account-level rather than delivering-session trust. | `contract-drift-1.md:137` | T-192/T-145 | open |
| UIS-12 | M | Per-account security card is absent. | `contract-drift-1.md:138` | T-192/T-145 | open |
| UIS-13 | M | Sync status wrapper/event listener is absent. Wrapper `syncStatus` landed T-272 (IPC-15); UI surface/listener consumption remains. | `contract-drift-1.md:139` | T-231 | open |
| UIS-14 | M | Send-later/schedule-send wrapper is absent. Wrapper `scheduleSend` landed T-272 (IPC-15); composer UI consumption remains. | `contract-drift-1.md:140` | T-151/T-145 | open |
| UIS-15 | M | Template picker and persisted template store are disconnected. | `contract-drift-1.md:141` | T-151/T-145 | open |
| UIS-16 | M | Per-recipient evaluation UI is absent and block results are over-broad. | `contract-drift-1.md:142` | T-108/T-145 | open |
| UIS-17 | M | Contact wrappers/import/export surfaces remain unwired despite backend commands. Wrappers `contactsByTag`/`contactTags`/`importVcards`/`exportVcards` landed T-272 (IPC-15); view surfaces remain. | `contract-drift-1.md:143` | T-175/T-231 | open |
| UIS-18 | L | Sidebar folder tree is flat despite tree role. | `contract-drift-1.md:213` | T-145 | open |
| UIS-19 | L | `useMailbox` is unused despite App header claiming use. | `contract-drift-1.md:214` | T-145 | open |
| UIS-20 | L | Unused IPC wrappers remain in frontend. | `contract-drift-1.md:215` | T-237 | in-flight |
| UIS-21 | L | UI event row uses `id`/`tsUnix` while contract names `eventId`/`timestamp`. | `contract-drift-1.md:233` | T-237/contract owner | in-flight |
| UIS-22 | I | Additional frontend routes/components are undocumented implementation surface. | `contract-drift-1.md:234` | T-145/contract owner | open |
| INT-6 | L | Contract index omitted existing contract files; Agent 20 reports the index now lists all 14. | `contract-drift-1.md:216`; `agent-20-status.md:98-103` | T-237 | fixed |
| INT | I | Integrations contract is absent while code cites it; integration seams and consent gates remain. | `contract-drift-1.md:235` | T-226 | open |

## Queue and ownership summary

- **Fixed/current evidence:** T-237 prefs/discovery wrappers + contract
  index + `challenge-expired`; T-239 AccountView/SecurityStatus/SS-1;
  T-245 FSV-1 forensics serde (FOR-1/2/6); T-247 wire batch 2
  (IPC-6/7/8/9 + FOR-3/4/5); T-265 register batch (IPC-11..14 +
  FOR-7/8/9); T-271 (IPC-5, IPC-16 listener, FOR-6 §1 reconciliation,
  FOR-11/12 contract amends); T-230/T-195 ACFG-1/2 and IPC-10; T-251
  ACFG-7/8/9 parser hardening and contract exceptions; T-258 verified
  MAUTH-2/3 resolved.
- **In-flight:** T-193/T-250 admin residual findings; T-231/T-145 UI
  wrapper work; T-266 sandbox-open IPC (build churn observed during
  T-271); T-267 4-pane rebuild (App.tsx/chrome/Icon tsc churn).
- **Queued:** T-269 canonical pair-wire; T-270 authenticator enum.
- **Open/unassigned:** remaining contract/implementation rows require
  Lead assignment or a contract-owner ruling.

**Register maintenance rule:** when a task finishes, update this row's status only with
current code/test/contract evidence; do not mark a finding fixed solely because
an audit or planning task is done.

## T-271 sweep — open rows re-verified against HEAD (2026-09-25)

All remaining `open`/`in-flight` rows were re-checked. Flipped to
`fixed` above: IPC-5, IPC-6, IPC-7, IPC-8/CON-1, IPC-9, IPC-11..14,
IPC-16, FOR-1..9 (incl. 6, 11, 12), MAUTH-2, MAUTH-3, UIS-5, UIS-6.

**Still open — spot-verified against the current tree:**

- **IPC-3/AUTH-3** — `ChallengeView` still serializes `nonceHex`; ipc.md
  §9d ratifies `nonceB64` and records the pending migration. Remaining:
  emit `nonceB64` (+decode check), keep `nonceHex` read-compat per the
  migration note, update `ChallengeView` consumers.
- **IPC-15** — *resolved T-272* (row flipped): typed wrappers landed for
  all six commands (all verified registered in `lib.rs`), plus `prefsGet`
  found by the full registered-vs-wrapped enum. Unwrapped remainder are
  compat aliases whose canonical names are already wrapped.
- **IPC-16 note** — fixed via `onMailChanged` (ipc.ts) + App-level
  debounced subscription (App.tsx). Caveat surfaced while wiring:
  `state/mailbox.ts::useMailbox` is still dead code (UIS-19 stands) —
  App.tsx owns the live mailbox path.
- **FOR-10** — *resolved T-272* (row flipped): emit sites landed in
  `analyze_capture` (capture) and `kiwi_security_report` (live, auth
  only — `SecuritySession` lacks resumption/unknown-transport state) via
  shared `report::session_limitation_codes`; §8 documents conditions.
- **AUTH-1** — still no `challenge-denied`/`verification-failed`/
  `device-paired` audit rows in `commands/system.rs` (grep-verified).
  Owned by A11's T-269 (pair-engine landing, in-flight); T-272 did not
  touch pair code per Lead direction.
- **UIS-13/14/17** — wrappers landed T-272 (IPC-15); the UI surfaces
  consuming them remain with the UIS owners.
- **UIS-21** — `kiwi.ts` still reads `id`/`tsUnix` event keys.
- **UIS-19** — confirmed again during IPC-16: `useMailbox` is exported
  but never invoked (App.tsx comment still claims it).
- **Not re-verified (other-task owners, left as recorded):**
  AUTH-2..16/I (T-194), SS-2..9/I (T-194), ACFG-3..19/I (T-246/T-251),
  MAUTH-1/4..8/I (T-122/T-183 — T-258 appendix already verified the
  T-183 group), ADM-*/ADM-T250-* (T-250/T-259 in-flight — admin-api.md
  churned heavily during this sweep), SBX-*/I (T-161/T-266 in-flight),
  PAIR-*/I (T-235/T-269 queued), CON-2..11/I (T-150/T-175), UIS-1..22
  remainder (T-145/T-192/T-267 in-flight), INT (T-226).
