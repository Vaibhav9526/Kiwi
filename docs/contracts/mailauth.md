# Contract — Mail Authentication Results (SPF / DKIM / DMARC)

> Owner: Agent 8 · **Contract version: `kiwi.mailauth/1`** · Status: draft
> (T-122) · Implemented by `kiwi-mailauth/` (Rust). Reference impl is
> authoritative for field semantics; this document is authoritative for the
> JSON shape. Changes require Lead review → record in DECISIONS.md.

Parties: `kiwi-mailauth` (typed auth results) → `kiwi-forensics`
(Agent 6 maps results to findings) → reports/UI/admin ingest. This crate
emits **no findings** — only evidence-grade typed results.

## 1. Invariants (binding)

- Deterministic only. No field may require AI.
- No credentials, tokens, bodies, or private keys. Only public-key query
  names + verdicts cross this boundary.
- Never invent findings: no record → `none`; DNS errors → `temperror`.
- Expiry/age take `now` as input (`DkimInput.now_unix`, DMARC
  `sample_roll`); never the system clock; no RNG in verdicts.
- Unknown enum values / new fields ignored, not fatal.
- `contract_version` is `"kiwi.mailauth/1"`.

## 2. Result vocabulary

Shared spellings (`as_str()`): `pass` (authenticated), `fail`
(present but not authenticated), `softfail` (SPF `~`), `neutral` (SPF
`?`/no-match), `none` (no record — NOT a failure), `temperror`
(transient DNS — retryable, never a finding), `permerror` (bad record,
limits, unsupported).

## 3. `SpfOutput` (`spf::SpfOutput`)

| field | type | notes |
|-------|------|-------|
| `result` | verdict | |
| `decided_by` | string\|null | deciding mechanism/modifier, e.g. `-all` (≤300 chars) |
| `record` | string\|null | evaluated record text (≤4096) |
| `ptr_deprecated_used` | bool | `ptr` evaluated (deprecated, RFC 7208 §5.5) |
| `lookups_used` | u8 | DNS mechanisms consumed (limit 10) |
| `explanation` | string | evidence text (≤500), never a finding |

Limits (§4.6.4): ≤10 DNS mechanisms, ≤2 void lookups, recursion ≤5 —
excess is `permerror`. Unknown modifiers ignored (§6); unknown
mechanisms → `permerror`. Macros per §7; hostile expansion that is not
a valid domain → `permerror` (fail-closed).


## 4. `DkimOutput` (`dkim::{DkimOutput, DkimSignature}`)

| field | type | notes |
|-------|------|-------|
| `result` | `pass\|fail\|none\|temperror\|permerror` | |
| `signature` | object\|null | `sdid`, `selector`, `algorithm` (`rsa-sha256`/`ed25519-sha256`), `header_canon`/`body_canon` (`simple`/`relaxed`), `signed_headers` (≤64), `body_hash`/`signature` (bytes), `body_length?`, `timestamp?`, `expiry?` |
| `key_query` | string\|null | `selector._domainkey.sdid` when fetched |
| `explanation` | string | evidence text, never a finding |

Parse → expiry on caller clock (`x=` passed or `t=` older than 14 days
→ `fail`) → body-hash → key fetch → RSA-SHA256/Ed25519 verify.
Key missing → `fail`; DNS error → `temperror`;
unparseable/unsupported/revoked → `permerror`. Duplicate tags error;
unknown tags ignored. Last-unused-occurrence header selection;
self-reference hashed with `b=` emptied. `l=` truncates before canon.
Caps: header ≤16 KiB, canon ≤4 MiB.

## 5. `DmarcOutput` (`dmarc::{DmarcOutput, DmarcRecord}`)

| field | type | notes |
|-------|------|-------|
| `result` | `pass\|none\|fail\|temperror\|permerror` | `fail` = unaligned (see `policy_applied`) |
| `policy_applied` | `none\|quarantine\|reject` | `p=`/`sp=` after alignment; `none` when aligned/sampled-out/no-record |
| `spf_aligned` / `dkim_aligned` | bool | pass + identifier alignment |
| `sampled_out` | bool | `sample_roll >= pct` (deterministic caller input, no RNG) |
| `record` | object\|null | `policy`, `sub_policy`, `spf_align`, `dkim_align`, `pct`, `raw` |
| `explanation` | string | evidence text, never a finding |

Fetch `_dmarc.<org>`; org = last-two-labels heuristic (documented PSL
limitation — exact deployments pass `org_override`). Strict = exact
match; relaxed = same org. Subdomains use `sp=`.

## 6. `DnsResolver` (offline-mockable DNS)

Sync trait (`dns::DnsResolver`): `lookup_txt/host/mx/ptr` or
`Temp`/`NxDomain`. `MockResolver` (builders `with_txt/host/mx/ptr/
temp_fail`) is the ONLY test resolver — suite runs fully offline.
`HickoryResolver::system()` is the live adapter (private Tokio
runtime, blocking facade).

## 7. Determinism

No clock/RNG/floats/map-order in verdicts. `unsafe_code = "forbid"`;
deps minimal+pinned.

## 8. Forensics mapping (Agent 6 owns, non-binding)

SPF `fail` + DMARC `fail/reject` → spoofing signal. DKIM aligned `pass`
→ auth evidence (not trust alone). `temperror` → limitation. `none` →
absence of evidence. `ptr_deprecated_used` → hardening note only.
