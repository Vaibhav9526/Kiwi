# Contract — Forensics Findings, Evidence, Reports

> Owner: Agent 6 (transferred from Agent 3 per AGENT_HANDOFF.md T-003/T-107,
> 2026-09-19; Agent 3 resumes as reviewer) · **Contract version:
> `kiwi.forensics/1`** · Status: draft (T-003)
> Implemented by `kiwi-forensics/` (Rust). Reference impl is authoritative
> for field semantics; this document is authoritative for the JSON shape.
> Changes require Lead review (API_CONTRACTS.md rule) → record in DECISIONS.md.

Parties: `kiwi-forensics` (producer) → reports/UI/admin ingest (consumers);
adapters (PCAP ingest, live `kiwi-mail` transport, test fixtures) feed
`ConnectionSecurityEvent` in. `kiwi-forensics` owns *findings*; the
live-session trust decision stays with `kiwi-core` (`security-session.md`).

## 1. Invariants (binding on all parties)

- Deterministic only. No field of this contract may require AI (§7).
- No credentials, tokens, message bodies, or private keys anywhere in the
  payload. Excerpts are redacted per §4.
- Every finding carries ≥1 typed evidence item — never a free-text-only
  conclusion. The engine drops evidence-less findings and counts them in
  `EvaluationDiagnostics.dropped_without_evidence` (must be 0 in production).
- Unknown enum values / new fields must be ignored, not fatal
  (API_CONTRACTS.md cross-cutting invariants).
- `contract_version` is `"kiwi.forensics/1"`; `rule_catalog_version` is a
  u16 (currently `1`, bumped on any decision-logic or default-severity
  change). Consumers must not equate findings across catalog versions.
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
| `transport` | `"plaintext" \| "starttls" \| "implicit_tls" \| "unknown"` | observed classification; `unknown` is NOT protected |
| `capabilities` | string[] | bounded (64), sanitized |
| `tls` \| null | object | `{version, cipher_suite: {iana_id, name?, key_exchange, bulk, mac, strength, recognized}, sni?, alpn[], handshake_complete, session_resumed, sources[]}` |
| `certificates` \| null | object | `{chain: CertificateInfo[] (leaf first, ≤16), trust: "not_evaluated" \| "trusted_by_local_anchor" \| "untrusted" \| "revoked" \| "unknown", chain_truncated: bool, sources[]}` |
| `starttls` \| null | object | `{advertised_by_server, client_requested, server_reply_ok?: bool, handshake_completed, application_data_before_tls, plaintext_auth_after_request}` |
| `auth` \| null | object | `{mechanism?: "plain" \| "login" \| "cram-md5" \| … \| "unknown", succeeded?: bool, attempts: u32, failures: u32}` |
| `sources` | `SourceRef[]` | `{session_id, frames: u64[] (1-based, empty for live), stream_offsets: u64[], excerpt: redacted SafeText}` |

Enum strings use the `as_str()` spellings in code (`tls1.2`, `ecdhe`,
`aes128_gcm`, `cram-md5`, `not_evaluated`, …). `TlsVersion::Unknown(raw)`
serializes as `"unknown"` with the raw value available to rules via
`wire_value()` (evidence records the numeric value).

## 3. Finding / Evidence shapes

`Finding`: `{rule_id, rule_version, category, severity, confidence, title,
description, impact, remediation: {summary, steps[≤16], references[≤16]},
evidence[≥1], subject, observed_at_unix_ms, sources[], references[]}`.

`subject`: `{session_id, protocol, server_host, server_port, account_id?,
discriminator?}`. Stable key = `rule_id + "|" + subject_key` where
`subject_key = protocol:host:port[#discriminator]` — session id excluded so
re-scans line up across captures (`RescanDiff`: added / resolved /
persisting keys).

`Evidence`: `{kind, summary, value, source: SourceRef}`. `value` is typed:
`{type:"text",value} | {type:"number",value} | {type:"bool",value} |
{type:"bytes",digest_hex,len} | {type:"list",values[≤64]} |
{type:"unavailable",reason}` — never free prose, never raw secrets.

`severity`: `info(0) | low(5) | medium(12) | high(25) | critical(40)` points
at full weight. `confidence`: `tentative(0.5) | firm(0.85) |
certain(1.0)` multiplier. Category vocabulary: `transport | cipher |
key_exchange | certificate | authentication | starttls | protocol |
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
| KIWI-TRANSPORT-001 | Mail transport is not encrypted | High / Certain |
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

## 6. Scoring (`kiwi-score-1`)

Per finding: `weight_points(severity) × multiplier_bp(confidence) / 10000`,
round half up. Same rule repeating in one scope dims: 1st ×1.0, 2nd ×0.5,
3rd ×0.25, 4th+ ×0.125. Total capped at 100 (`max_deduction_points`);
`score = 100 − deduction`. Grades: A 90–100, B 80–89, C 70–79, D 55–69,
F 0–54. Integer arithmetic only — identical input, identical score (§7).

## 7. Determinism (binding)

No system clock, no RNG, no floating point, no map-iteration order in
findings or scoring. Times (`started_at_unix_ms`, validity bounds) and
capture identity are *inputs*. Output order is fixed: severity (worst
first), rule id, subject key, then confidence. Re-scan diffing compares
stable keys; a `rule_version` bump means logic changed and keys must not
be equated across versions.

## 8. Report aggregate (specified; `src/report/` implements)

`Report`: `{contract_version, scoring_model_version, rule_catalog_version,
scope, sessions_evaluated, findings[], score, limitations[], ai_enrichment?,
generated_from}`. `Limitation`: `{code, detail}` — e.g.
`chain-unverified` (capture input), `kex-unobserved` (resumption),
`protocol-unknown`. `AiEnrichment`: `{finding_keys[], text, model_id}` —
AI text must cite the deterministic keys it grounds in and is never
authoritative (prompt.md §12). Reports render JSON first; HTML/PDF are
views over the same aggregate.

## 9. `ConnectionSecurityEvent` ↔ `SecuritySession` mapping

Forensics → kiwi-core (live adapter, T-107): transport/v
...[truncated 1583 chars]