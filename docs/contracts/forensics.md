# Contract — Forensics Findings, Evidence, Reports

> Owner: Agent 6 (full ownership from 2026-09-20; transferred from Agent 3
> per AGENT_HANDOFF.md T-003/T-107, 2026-09-19; Agent 3 did not return) ·
> **Contract version: `kiwi.forensics/2`** · Status: done (T-003; FSV-1
> wire vocabulary ratified T-245 — §12)
> Implemented by `kiwi-forensics/` (Rust). Reference impl is authoritative
> for field semantics; this document is authoritative for the JSON shape.
> Changes require Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: `kiwi-forensics` (producer) → reports/UI/admin ingest (consumers);
adapters (PCAP ingest, live `kiwi-mail` transport, test fixtures) feed
`ConnectionSecurityEvent` in. Concrete entry points: `pcap::PcapReader`
(frames) → `pcap::decode_tcp` (segments) → `StreamReassembler`
(`Reassembler`: flows) → `pipeline::analyze_capture` (flows → traces →
events, with client/server resolution + protocol sniffing) →
`analyzers::analyze` → `RuleEngine` → `report::ReportBuilder`.
`kiwi-forensics` owns *findings*; the live-session trust decision stays
with `kiwi-core` (`security-session.md`).

## 1. Invariants (binding on all parties)

- Deterministic only. No field of this contract may require AI (§7).
- No credentials, tokens, message bodies, or private keys anywhere in the
  payload. Excerpts are redacted per §4.
- Every finding carries ≥1 typed evidence item — never a free-text-only
  conclusion. The engine drops evidence-less findings and counts them in
  `EvaluationDiagnostics.dropped_without_evidence` (must be 0 in production).
- Unknown *fields* are ignored, not fatal (API_CONTRACTS.md
  cross-cutting invariants). Unknown enum *variant tags* fail closed —
  a report from a newer engine must not be silently downgraded
  (§12, FOR-6).
- `contract_version` is `"kiwi.forensics/2"` (FSV-1 wire vocabulary, §12);
  `rule_catalog_version` is a u16 (currently `1`, bumped on any
  decision-logic or default-severity change). Consumers must not equate
  findings across catalog versions. Readers MUST accept both `/1` and
  `/2` enum spellings (§12 dual-read); stored `/1` payloads stay
  byte-identical under their original version.
- This crate never validates X.509 signatures or builds trust paths:
  certificate metadata is adapter input. Capture-based reports must never
  claim "chain verified"; unverifiable facts become report `limitations`.

## 2. `ConnectionSecurityEvent` — the unit rules evaluate

JSON field names; Rust types in `kiwi_forensics::model`:

| field | type | notes |
|-------|------|-------|
| `id` | string | `<source-tag>:<proto>:<cport>-<sport>:<index>`, reproducible per capture |
| `protocol` | `"smtp" \| "imap" \| "pop3" \| "unknown"` | |
| `client` / `server` | `{address: string, port: u16}` | sanitized text, never raw bytes |
| `started_at_unix_ms` | i64 | caller-supplied (never the system clock) |
| `transport` | `"plaintext" \| "start_tls" \| "implicit_tls" \| "unknown"` | observed classification; `unknown` is NOT protected |
| `capabilities` | string[] | bounded (64), sanitized |
| `tls` \| null | object | `{version, cipher_suite: {iana_id, name?, key_exchange, bulk, mac, strength, recognized}, sni?, alpn[], handshake_complete, session_resumed, sources[]}` |
| `certificates` \| null | object | `{chain: CertificateInfo[] (leaf first, ≤16), trust: "not_evaluated" \| "trusted_by_local_anchor" \| "untrusted" \| "revoked" \| "unknown", chain_truncated: bool, sources[]}` |
| `starttls` \| null | object | `{advertised_by_server, client_requested, server_reply_ok?: bool, handshake_completed, application_data_before_tls, plaintext_auth_after_request}` |
| `auth` \| null | object | `{mechanism?: "plain" \| "login" \| "cram_md5" \| … \| "unknown", succeeded?: bool, attempts: u32, failures: u32}` |
| `sources` | `SourceRef[]` | `{session_id, frames: u64[] (1-based, empty for live), stream_offsets: u64[], excerpt: redacted SafeText}` |

Enum strings are FSV-1 wire tags (§12): lower `snake_case` unit variants
(`tls12`, `ecdhe`, `aes128_gcm`, `cram_md5`, `not_evaluated`, …).
`TlsVersion::Unknown(raw)` is data-bearing and serializes externally
tagged as `{"unknown": <u16>}`, preserving the raw wire value
(`wire_value()` exposes it to rules). The `as_str()` spellings
(`tls1.2`, `cram-md5`, …) are semantic/display tokens for evidence text
and the §9 session mapping — they are NOT the JSON wire form.

## 3. Finding / Evidence shapes

`Finding`: `{rule_id, rule_version, category, severity, confidence, title,
description, impact, remediation: {summary, steps[≤16], references[≤16]},
evidence[≥1], subject, observed_at_unix_ms, sources[], references[]}`.

`subject`: `{session_id, protocol, server_host, server_port, account_id?,
discriminator?}`. Stable key = `rule_id + "|" + subject_key` where
`subject_key = protocol:host:port[#discriminator]` — session id excluded so
re-scans line up across captures. `RescanDiff.changes[].kind` is a
`ChangeKind` with five wire tags: `new` (absent before), `resolved`
(absent after), `unchanged` (present both, same severity),
`severity_increased` / `severity_decreased` (present both, severity
moved). `new` and `severity_increased` are regressions. Readers must
also accept the legacy spellings `added` (= `new`) and `persisting`
(= `unchanged`) per §12 dual-read.

`Evidence`: `{kind, summary, value, source: SourceRef}`. `value` is typed:
`{type:"text",value} | {type:"number",value} | {type:"bool",value} |
{type:"bytes",digest_hex,len} | {type:"list",values[≤64]} |
{type:"unavailable",reason}` — never free prose, never raw secrets.

`severity`: `info(0) | low(5) | medium(12) | high(25) | critical(40)` points
at full weight. `confidence`: `tentative(0.5) | firm(0.85) |
certain(1.0)` multiplier. Category vocabulary: `transport | cipher |
key_exchange | certificate | authentication | start_tls | protocol |
capture_integrity`.

## 4. Redaction rules (binding on every adapter)

- `SourceRef.excerpt` and every `EvidenceValue::Text` pass through
  `SafeText` (control-char strip, whitespace collapse, 256-char cap).
- Excerpts must never contain: AUTH initial responses / passwords / bearer
  tokens, full message bodies, private keys, session tickets. Adapters quote
  at most the command verb + server reply code (e.g. `AUTH PLAIN → 235`).
- Certificate DER and capture buffers are referenced by
  `{digest_hex, len}` only — raw bytes never enter a finding or report.
- Hostnames/addresses are sanitized text; non-IP L2 identifiers stay text.

## 5. Rule catalog (`RULE_CATALOG_VERSION = 1`)

37 rules. Severity / confidence are fixed per rule (never AI, never float):

| rule id | title | sev / conf |
|---------|-------|------------|
| KIWI-TRANSPORT-001 | Mail transport is not encrypted | High / Certain — **Critical / Certain** when a reusable secret was observed in the clear (credential exposure, not just unencrypted transport) |
| KIWI-TRANSPORT-002 | TLS-only port served in plaintext | Critical / Certain |
| KIWI-PROTO-001 | Mail protocol could not be identified | Info / Tentative |
| KIWI-STARTTLS-001 | STARTTLS downgrade or stripping indicator | Critical / Firm |
| KIWI-STARTTLS-002 | Server did not offer STARTTLS | Medium / Certain |
| KIWI-STARTTLS-003 | Client did not attempt STARTTLS | High / Certain |
| KIWI-STARTTLS-004 | Server refused the STARTTLS upgrade | Medium / Certain |
| KIWI-TLS-001 | Negotiated TLS version below the policy floor | High / Certain |
| KIWI-TLS-002 | Deprecated TLS/SSL version negotiated | High / Certain |
| KIWI-TLS-003 | TLS version could not be classified | Medium / Firm |
| KIWI-TLS-004 | TLS claimed but no handshake observed | Medium / Firm |
| KIWI-TLS-005 | TLS session resumed: key exchange not observed | Info / Certain |
| KIWI-CIPHER-001 | Broken cipher suite negotiated | Critical / Certain |
| KIWI-CIPHER-002 | Weak cipher suite negotiated | High / Certain |
| KIWI-CIPHER-003 | Legacy cipher suite negotiated | Low / Certain |
| KIWI-CIPHER-004 | Cipher suite not recognized | Info / Certain |
| KIWI-KEX-001 | Key exchange without forward secrecy | Medium / Certain |
| KIWI-KEX-002 | Unauthenticated key exchange | Critical / Certain |
| KIWI-KEX-003 | Key exchange could not be classified | Info / Certain |
| KIWI-CERT-001 | Certificate expired | Critical / Certain |
| KIWI-CERT-002 | Certificate not yet valid | High / Certain |
| KIWI-CERT-003 | Certificate expires soon | Low / Certain |
| KIWI-CERT-004 | Self-issued certificate presented alone | High / Certain |
| KIWI-CERT-005 | Certificate does not cover the server name | High / Certain |
| KIWI-CERT-006 | Broken signature algorithm (MD2/MD5) | High / Certain |
| KIWI-CERT-007 | Deprecated signature algorithm (SHA-1) | Medium / Certain |
| KIWI-CERT-008 | Public key below minimum size | High / Certain |
| KIWI-CERT-009 | Discouraged public-key algorithm | Medium / Certain |
| KIWI-CERT-010 | Chain truncated by capture or bounds | Info / Firm |
| KIWI-CERT-011 | Chain trust was not validated | Info / Certain |
| KIWI-CERT-012 | Trust layer rejected the chain | Critical / Certain |
| KIWI-AUTH-001 | Reusable credential crossed an unprotected channel | Critical / Certain |
| KIWI-AUTH-002 | Deprecated authentication mechanism in use | Medium / Certain |
| KIWI-AUTH-003 | Authentication failure observed | Low / Certain |
| KIWI-AUTH-004 | Repeated authentication failures | Medium / Certain |
| KIWI-AUTH-005 | MD5-based authentication mechanism | Medium / Certain |
| KIWI-AUTH-006 | No authentication observed on a protected session | Info / Firm |

Semantics notes: STARTTLS-001 requires a *positive* indicator
(`application_data_before_tls` or `plaintext_auth_after_request`) —
absence of a handshake alone is not an attack claim. KEX-001/KEX-003 are
suppressed for resumed sessions (TLS-005 records the limitation instead).
AUTH-003 fires below the guessing threshold; AUTH-004 at/above it (the two
never double-report). Unrecognized mechanisms/suites/versions assert
nothing beyond their own `…-004/003/UNKNOWN` context findings.

Default policy (`SecurityPolicy::default`): floor TLS 1.2, require
TLS + STARTTLS + forward secrecy, reject broken/weak, report legacy +
deprecated-auth + cleartext-under-TLS, guessing threshold 3, strict
implicit-TLS ports, report unrecognized, RSA ≥2048 / EC ≥256, 30-day
expiry window. `strict()`: TLS 1.3 floor. `permissive()`: measures
everything, reports almost nothing (proves suppression ≠ blindness).
Every policy flag is live (T-247): `reject_broken_ciphers` gates
KIWI-CIPHER-001 like its weak/legacy siblings, `require_tls13` is a
shorthand floor of TLS 1.3 (it wins over `min_tls_version`; the effective
floor is what TLS-001 reports in evidence), and
`report_cleartext_auth_under_tls` gates KIWI-AUTH-002 specifically for
reusable-secret mechanisms under a protected channel — a PLAIN-under-TLS
deprecation is opt-in, while MD5/anonymous deprecation is not
channel-scoped. Reports under non-default policies may differ from `/1`
runs that ignored those flags.

## 6. Scoring (`kiwi-score-2`)

Per finding: `weight_points(severity) × multiplier_bp(confidence) / 10000`,
**round half up per finding**, then sum. Same rule repeating in one scope
dims: 1st ×1.0, 2nd ×0.5, 3rd ×0.25, 4th+ ×0.125. Total capped at 100
(`max_deduction_points`);
`score = 100 − deduction`. Grades: A 90–100, B 80–89, C 70–79, D 55–69,
F 0–54. Integer arithmetic only — identical input, identical score (§7).
`Report.score.grade` carries the FSV-1 wire tag (`"a"`–`"f"`, lowercase);
the uppercase letters are display/`as_str()` spellings, not JSON.

## 7. Determinism (binding)

No system clock, no RNG, no floating point, no map-iteration order in
findings or scoring. Times (`started_at_unix_ms`, validity bounds) and
capture identity are *inputs*. Output order is fixed: severity
descending (worst first), then `rule_id` ascending, then `subject_key`
ascending, then confidence descending (most certain first). Re-scan
diffing compares stable keys; a `rule_version` bump means logic changed
and keys must not be equated across versions.

## 8. Report aggregate (specified; `src/report/` implements)

`Report`: `{contract_version, scoring_model_version, rule_catalog_version,
scope, sessions_evaluated, findings[], score, limitations[], ai_enrichment?,
generated_from}`. `Limitation`: `{code, detail}` — `chain-unverified`
(capture input), `kex-unobserved`, `auth-unobserved`,
`transport-unknown`, `protocol-unknown`, `stream-gap`,
`capture-over-limit`, `rule-dropped-without-evidence`,
`ai-uncited-keys`. Emit conditions are deterministic and evidence-derived
(`report::session_limitation_codes` + the capture/live report paths):
`transport-unknown` when a flow carried bytes but yielded no decodable
lines, or an adapter session's `transport` is `unknown`; `kex-unobserved`
when `tls.session_resumed`/`!tls.handshake_complete`, or a STARTTLS
upgrade was accepted (`server_reply_ok`) yet `handshake_completed` is
false; `auth-unobserved` when the transport is protected and no
authentication exchange was observed (`auth` absent or `attempts: 0`;
live path: `AuthMechanism::None`). `AiEnrichment`: `{finding_keys[], text, model_id}` —
AI text must cite the deterministic keys it grounds in and is never
authoritative (prompt.md §12). Reports render JSON first; HTML/PDF are
views over the same aggregate.

## 9. `ConnectionSecurityEvent` ↔ `SecuritySession` mapping

Both directions are contract; the trust decision stays with `kiwi-core`
in both. Field vocabularies below are the `as_str()` *semantic*
spellings (`starttls`, `tls1.3`, `cram-md5`, …) — the mapping contract,
distinct from the FSV-1 JSON wire tags in §12.
`evidence_ref` on every derived signal is the finding stable key
(`rule_id|subject_key`, §3).

### 9a. Forensics → core (event/findings → `SecuritySession` + `TrustSignal`)

Implemented by consumers (kiwi-app bridge maps findings→status today);
`source` is always `"forensic-pcap"`, `account_id`/`device_id` are always
`null` (a capture knows neither — documented loss, never a finding).

| session field | from event field | notes |
|---------------|------------------|-------|
| `session_id` | `id` string | verbatim |
| `protocol` | `protocol` | `smtp`/`imap`/`pop3` map 1:1; `Unknown` events are findings-only (session has no unknown) |
| `server_host` / `server_port` | `server.address` / `server.port` | sanitized text |
| `transport` | `transport` | `plaintext`→`plaintext`, `starttls`→`starttls`, `implicit_tls`→`tls`; `unknown` → findings-only |
| `tls_version` | `tls.version.as_str()` | `ssl3.0`→`ssl3`, `tls1.0/1.1/1.2/1.3` verbatim; `ssl2.0`/`Unknown`→`unknown`; absent→`null` |
| `cipher_suite` | `tls.cipher_suite` | `{iana_id, name or "unrecognized", forward_secrecy from kex}` |
| `key_exchange_group` | `kex.as_str()` | `rsa`/`dh_static`/`ecdh_static`→`static`; `dhe`/`ecdhe`/`psk_dhe`/`psk_ecdhe`→`other:<name>`; `psk`→`other:psk`; `anonymous`→`other:anonymous`; `null`/`unknown`→`unknown` |
| `cert_chain` | `certificates` | `{leaf summary, presented_len, validation}`; validation is `unknown` unless a CERT finding fired (`CERT-001`→`expired`, `CERT-005`→`hostname-mismatch`, `CERT-012`→`untrusted`) — **never `valid` from capture** (§1) |
| `starttls_offered` / `starttls_used` | `starttls` | offered ← `advertised_by_server`; used ← `handshake_completed` |
| `auth_mechanism` | `auth.mechanism.as_str()` | `plain`/`login`/`cram-md5`/`ntlm`/`xoauth2`/`oauthbearer`/`gssapi`/`scram-sha-1`/`scram-sha-256` verbatim; `digest-md5`/`scram-sha-256-plus`/`scram-sha-512-plus`/`anonymous`/`external`→`other:<name>`; none observed→`none`; `unknown`→`unknown` |
| `auth_succeeded` | `auth.succeeded` | verbatim (`null` when unobserved) |
| `established_unix` | `started_at_unix_ms / 1000` | integer division (truncates toward zero; deterministic for all inputs) |

Findings → `TrustSignal` (severity vocabulary is identical; **penalties
are set by the consumer's `TrustPolicy`, never here**):

| finding(s) | signal kind |
|------------|-------------|
| KIWI-TRANSPORT-001 | `plaintext-transport` |
| KIWI-STARTTLS-001 | `starttls-downgrade-suspected` |
| KIWI-TLS-002 | `deprecated-tls-version` |
| KIWI-CIPHER-002 | `weak-cipher-suite` |
| KIWI-KEX-001 | `no-forward-secrecy` |
| KIWI-CERT-001 | `certificate-expired` |
| KIWI-CERT-004 / CERT-011 | `certificate-invalid` |
| KIWI-CERT-012 | `certificate-untrusted` |
| KIWI-CERT-005 | `certificate-hostname-mismatch` (a default hard-lock kind — handle with care) |
| KIWI-AUTH-002 | `weak-auth-mechanism` |
| KIWI-AUTH-004 | `repeated-auth-failure` |

KIWI-AUTH-003 (single failure, Low) carries no signal by default. Every
other rule is either Info-grade context or already covered above; new
rules must extend this table when they introduce a new trust-relevant
verdict (Lead review per API_CONTRACTS.md).

### 9b. Core → forensics (session → event, for rule-engine evaluation)

Inverse of the tables above, with two documented losses: account/device
bindings have no forensics counterpart (dropped), and `established_unix`
seconds become `started_at_unix_ms` milliseconds (×1000 — precision the
session never had is not invented). `Unknown` enum values on the event
side absorb anything the session cannot express. Implementation status:
`live::event_from_live` (T-107) covers kiwi-mail transport observations;
`SecuritySession`→event bridging is specified here for future consumers
and has no in-crate implementation yet.

## 10. Capture pipeline (`src/pipeline.rs`, `pipeline::analyze_capture`)

Composed entry point: raw capture bytes → `CaptureReport` — a thin
wrapper `{report: Report, diagnostics: PipelineDiagnostics}` (the report
plus the counted how-it-was-reached evidence; `diagnostics` is never a
finding source). Stages:
`PcapReader` (frames, bounds-first) → `decode_tcp` (Ethernet/IPv4/TCP
only; everything else is a counted `DecodeSkip`, never fatal) →
`Reassembler` (per-direction ordered bytes, first-seen-wins overlap,
gaps flagged, all bounds counted) → per-flow `ProtocolTrace` →
`analyzers::analyze` → `RuleEngine` → `ReportBuilder`.

- **Client/server resolution** (`resolve_roles`, all observations):
  well-known mail port first (exactly one endpoint on
  25/465/587/143/993/110/995 → that peer is the server), then greeting
  content (sender of the earliest line is the server when the line is
  `220`/`+OK`/`-ERR`/`* OK`/`* PREAUTH`/`* BYE`/`IMAP4REV` — covers
  dev servers on odd ports), then initiator default. The reassembler
  itself stays role-agnostic (`initiator`/`responder` naming).
- **Cross-direction ordering**: lines sort by earliest covering frame
  (frame order is time order), initiator's line first on ties; each line
  carries only its covering frames (bounded 64).
- **Limitations the pipeline can add**: `stream-gap` (gapped flows),
  `capture-over-limit` (dropped segments/flows),
  `rule-dropped-without-evidence` (must be 0; a rule needs review if it
  fires), `chain-unverified` (every capture-sourced report with ≥1
  session — captures never validate chains), `protocol-unknown`
  (unidentified sessions). Skip counts (non-TCP, truncated, malformed)
  live in `PipelineDiagnostics`, not the report.
- **Determinism**: flows drain first-seen order; skip reasons sort
  (`BTreeMap`); frames sort + dedup; no clock/RNG/floats anywhere.
- **Non-goals**: no X.509 validation, no TLS decryption — a
  TLS-encrypted stream yields no protocol lines, so encrypted captures
  are findings-light by design (use the live adapter for TLS sessions);
  IPv6/VLAN/tunnels are counted skips, not parsed.

## 11. Query API — Security view seam (app layer implements, T-164)

Payload types are owned here (`Finding` §3, severities §3); retention
and serving live in the app layer (src-tauri journals over
`finding_id()` keys). All three commands are lock-gated like their
siblings. Error codes are `invalid-input` / `not_found` (ipc.md §11).
Frontend vocabulary mapping (`eventSeverityToSeverity`,
`findingToInfo` in `kiwi-app/src/kiwi.ts`) is downstream of these
shapes and must not leak upstream: the backend emits forensics
spellings only.

### `list_findings({account_id?, severity?, limit?})` → `Finding[]`

Full `Finding` objects (§3 shape, verbatim — evidence included, never
projected). Filters: `account_id` (string ≤256, matches
`subject.account_id`) and `severity` (`info` | `low` | `medium` |
`high` | `critical`, the FSV-1/§12 spellings) are ANDed;
either absent means unfiltered. An unrecognized `severity` string is
an `invalid-input` error — never silently ignored (a typo must not
look like a clean bill of health). Sort is binding and total:
severity rank desc (critical first), then `observed_at_unix_ms` desc,
then `rule_id` asc, then `subject_key` asc — identical input yields
identical order. `limit` defaults to 100 and clamps at 1000 (same
clamp as `list_events`); empty result is `[]`.
T-164 changes to the existing `kiwi_security_findings` (accountId
only, observed_at-desc sort): add `severity` + `limit`, adopt this
sort.

### `list_events({limit?, account_id?})` → `EventRow[]`

One row per observed session, newest first. JSON (camelCase, as
emitted today): `{id (session id), tsUnix (established seconds),
accountId (string|null), category (observation label, e.g. "smtp
send"), severity (forensics spelling of the worst session signal),
summary ("<PROTO> host:port <transport> <tlsversion>", e.g. "SMTP
mail.example.test:587 starttls tls1.2"), detailRef
("session:<id>")}`. `severity` is the exact input domain of the
view's `eventSeverityToSeverity` (`critical`/`high`→danger,
`medium`/`low`→warning, `info`→unknown) — backend UI tokens are a
contract violation. `limit` clamps like findings (default 100, max
1000). T-164 addition: optional `account_id` filter (sessions already
carry it; the view filters client-side until then).

### `finding_detail({findingId})` → `FindingDetailView` (T-164, implemented)

Implemented as `kiwi_finding_detail(findingId)`: `findingId` (string,
1–512 chars) is the `finding_id()` form (`rule_id|subject_key`, §3).
Returns `{finding (full Finding, verbatim), session (SessionView|null —
null once the bounded session ring evicts the source; findings deliberately
outlive sessions), signals (that session's trust signals), siblingFindingIds
(other findings from the same session)}`. Empty/overlong id →
`invalid-input`; no match → `not_found` ("unknown finding id").
`kiwi_session_detail(sessionId)` keeps serving session context for the
cert viewer.

### UI derivation rules (for `findingToInfo`, Agent 5-owned)

`id` ← `finding_id()` computed as `rule_id + "|" + subject_key`
(it is deliberately NOT a serialized field — either side derives it
with this rule; the current `finding-${index}` fallback retires once
keys flow through). `remediation` is an object `{summary,
steps[≤16], references[≤16]}`, not an array — the mapper's
array-assumption currently yields `[]`; upgrading it is Agent 5's
call. Severity buckets stay mapper-side (`critical`/`high`→danger,
else warning).

### Live auth threading (Agent 7, T-164-adjacent)

`observe.rs` already collects `auth_mechanism`/`auth_succeeded` but
drops them before the adapter (`auth: None` compat today). Threading
spec: `mechanism` ← core `AuthMechanism` mapped to
`kiwi_forensics::model::AuthMechanism` via `from_token` over the core
spelling (`none` → no `LiveAuthObservation` at all; `client-cert` →
`External`; `other:<name>` → `from_token(<name>)`, `Unknown` on
mismatch — conservatism, not guessing); `succeeded` verbatim;
`attempts` ← 1 when a mechanism was observed else 0; `failures` ← 1
when `succeeded == Some(false)` else 0. Until then the AUTH rules
stay silent on the live path by design (proven by
`absent_auth_leaves_auth_rules_silent`).

## 12. Wire serialization & migration (FSV-1 — ratified, T-245)

Every enum on this contract serializes under FSV-1
(`docs/audits/for-serde-vocab-1.md`):

- **Unit variants** are JSON strings in lower `snake_case`
  (`"tls12"`, `"start_tls"`, `"x_o_auth2"`, `"triple_des"`, …).
- **Data-bearing variants** keep serde's externally tagged object form
  and preserve their payload: `TlsVersion::Unknown(u16)` →
  `{"unknown": <u16>}`, `LinkType::Other(u16)` → `{"other": <u16>}`,
  `CaptureFormat::ClassicPcap{nanosecond}` →
  `{"classic_pcap": {"nanosecond": bool}}`.
- **`EvidenceValue` is the contract-exact exception**: it stays
  internally tagged by its `"type"` field (`{"type":"text", …}` etc.) —
  unchanged by FSV-1.
- Canonical spellings for every enum variant are frozen in
  `kiwi-forensics/tests/fixtures/fsv1_canonical.json`; writers emit
  these forms only (single-write).
- **Dual-read migration**: stored `/1` payloads and their readers
  spelled some enums differently — `as_str()` strings (`"tls1.2"`,
  `"cram-md5"`, `"oauthbearer"`, `"3des"`, `"starttls"`), PascalCase
  serde defaults (`"ClassicPcap"`, `"PcapNg"`, `"Ethernet"`,
  `{"Other": N}`), uppercase `Grade` letters, `ChangeKind` `added` /
  `persisting`, and bare `"unknown"` for `TlsVersion::Unknown`.
  Deserializers accept all of these as aliases and normalize to the
  typed domain value. One documented loss: bare `"unknown"` carried no
  raw value, so it maps to `TlsVersion::LEGACY_UNKNOWN_WIRE` (`0xFFFF`)
  — the original wire value is irrecoverable and MUST NOT be
  fabricated.
- Unknown *variant tags* still fail closed (FOR-6 stands); unknown
  *fields* remain ignorable.
- `as_str()` is unchanged and remains semantic-only: finding IDs,
  subject keys, evidence text, §9 session mapping and the §11 severity
  filter keep using it. IPC/session-view vocabularies (`tls1.3`,
  `xoauth2`, `hostname-mismatch`, `starttls`) are a separate layer —
  see ipc.md §3.
- `scoring_model_version` stayed `kiwi-score-1` under FSV-1 (spelling ≠
  scoring); T-247's per-finding rounding (§6) bumped it to
  `kiwi-score-2`. `rule_catalog_version` stays `1` — the T-247 flag
  wiring restores documented flag semantics; no rule's identity or
  default-policy output changed (per §5 note, non-default-policy reports
  may differ from `/1` runs that ignored the flags).