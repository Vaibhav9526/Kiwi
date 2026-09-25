# Contract — Mail Authentication Results (SPF / DKIM / DMARC)

> Owner: Agent 8 · **Contract version: `kiwi.mailauth/1`** · Status: draft
> (T-122) · **Hardened in T-183 (Agent 16) — changes marked ⛔ below are
> pending Lead review; see `docs/agents/agent-16-status.md`.**
> Implemented by `kiwi-mailauth/` (Rust). Reference impl is
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

⛔ **T-183 behaviour fixes (RFC-conformant):**
- `include` whose target has no SPF record is **`permerror`**, not
  no-match (RFC 7208 §5.2 result table: `none → return permerror`).
- `redirect=` whose target has no SPF record is **`permerror`**, not
  `neutral` (RFC 7208 §6.1: "if no SPF record is found … the result is a
  `permerror` rather than `none`").
- Void lookups are counted for `exists`, and for empty (NODATA) answers on
  `mx`/`ptr` hosts (§4.6.4); exceeding 2 voids is `permerror`.
- One `mx` evaluation queries ≤10 address records → `permerror`; one `ptr`
  evaluation queries ≤10 and ignores the rest (§4.6.4).
- Macro §7.3 conformance: split on the *specified delimiters* (not always
  `.`), rejoin parts with `.`, uppercase macro letters URL-escape their
  expansion, IPv6 `%{i}` expands to the 32-nibble dot format, a zero `DIGIT`
  transformer is a syntax error, and `%` not followed by `{`/`%`/`-`/`_` is a
  syntax error. All are fail-closed `permerror`.
- A `ptr` spec that does not expand to a valid domain is `permerror`; it no
  longer silently falls back to the current domain (which would have
  authorized a zone the record never named).
- `a`/`mx` accept a CIDR-only tail (`a/24`); `a:` / `exists:` with an empty
  domain-spec is a syntax error.
- `mx` host address lookups are not double-charged against the 10-lookup
  limit (the `mx` term itself counts once).
- `exp=` is still parsed-and-skipped (no explanation lookup, no DNS charge;
  §4.6.4 exempts `exp` from the limit).


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
unknown tags ignored. Caps: header ≤16 KiB, canon ≤4 MiB.

⛔ **T-183 behaviour fixes (RFC 6376 conformance):**
- **`l=` now truncates AFTER canonicalization** (was: before). §3.7: the
  body is "canonicalized … **and then** truncated to the length specified in
  the `l=` tag"; §3.4.5: "the body length count MUST be calculated following
  the canonicalization algorithm; … any whitespace ignored by a
  canonicalization algorithm is not included as part of the body length
  count". Consequence: the same `l=` yields different bytes under `simple`
  and `relaxed`. `l=0` ⇒ body completely unsigned. An `l=` larger than the
  canonicalized body is treated as no truncation. (Checked against the
  RFC 6376 errata list: no verified erratum changes this ordering.)
- **Header-hash composition (hash step 2) fixed.** The DKIM-Signature field
  under verification is now always hashed — *after* the `h=` fields and
  **without** a trailing CRLF (§3.7 items 1–2). Previously it was included
  only when `h=` literally listed `dkim-signature`, and then in the wrong
  position with a trailing CRLF, so conforming real-world signatures failed
  verification.
- **`h=dkim-signature` no longer means "self-reference".** §3.5 forbids the
  field under verification from appearing in its own `h=`; an `h=` entry of
  that name therefore selects *other* DKIM-Signature fields (§3.5 "may
  include others").
- `h=` entries are hashed in **`h=` order** (not message order); repeated
  names take the **last unused occurrence, bottom-up** (§5.4.2); names with
  no occurrence contribute nothing — the null input (§3.5).
- **Simple header canonicalization is byte-preserving** (§3.4.1): field-name
  case, WSP before the colon and internal folding are all left as
  transmitted (verified against the §3.4.5 Example 2 vector). It previously
  unfolded, silently altering signed bytes.
- `b=` emptying tolerates FWS around `=` (`sig-b-tag = %x62 [FWS] "=" [FWS]…`)
  and CRLF-folded `b=` values; the tag name, its FWS and the `=` are kept and
  only the value (plus surrounding WSP) is removed (§3.7).
- Empty-body canonicalization is pinned by the RFC's published vectors:
  `simple` ⇒ one CRLF (SHA-256 `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=`),
  `relaxed` ⇒ the **null input** (`47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`).
  T-122's tests asserted `relaxed` ⇒ CRLF; the implementation was
  RFC-correct and the tests were corrected.
- `x=` must be greater than `t=` when both are present (§3.5), else
  `permerror`. A future `x=` overrides the 14-day `t=` freshness policy.

## 5. `DmarcOutput` (`dmarc::{DmarcOutput, DmarcRecord}`)

| field | type | notes |
|-------|------|-------|
| `result` | `pass\|none\|fail\|temperror\|permerror` | `fail` = unaligned (see `policy_applied`) |
| `policy_applied` | `none\|quarantine\|reject` | `p=`/`sp=` after alignment; `none` when aligned/sampled-out/no-record |
| `spf_aligned` / `dkim_aligned` | bool | pass + identifier alignment |
| `sampled_out` | bool | `sample_roll >= pct` (deterministic caller input, no RNG) |
| `record` | object\|null | `policy`, `sub_policy`, `spf_align`, `dkim_align`, `pct`, `raw` |
| `explanation` | string | evidence text, never a finding |

Fetch order: `_dmarc.<from_domain>` first, then `_dmarc.<org>` when the
From domain is a subdomain and the first lookup yields no DMARC record
(RFC 7489 §6.6.3 steps 1–4). org = last-two-labels heuristic (documented
PSL limitation — exact deployments pass `org_override`). Strict = exact
match; relaxed = same org.

⛔ **T-183 behaviour fixes (RFC 7489 conformance):**
- **Policy discovery now queries the RFC5322.From domain first** (§6.6.3
  step 1), falling back to the Organizational Domain (step 3). T-122 only
  queried `_dmarc.<org>`, so a subdomain that published its own DMARC
  record was silently ignored.
- **`sp=` is ignored for records published on a subdomain.** §6.3: "Note
  that 'sp' will be ignored for DMARC records published on subdomains of
  Organizational Domains due to the effect of the DMARC policy discovery
  mechanism". `sp=` therefore applies **only** when the record was
  discovered at the org domain for a subdomain From; a record found at the
  From domain itself always uses `p=`. T-122 applied `sp=` whenever
  From ≠ org, including for subdomain-published records.
- **Multiple DMARC records at a level → `permerror`** (§6.6.3 step 5:
  "policy discovery terminates and DMARC processing is not applied").
  T-122 picked the first matching record.
- Records not starting with `v=DMARC1` are discarded at each level (§6.6.3
  steps 2/4); an empty set falls through to the next level instead of
  returning `none` early.

## 6. `DnsResolver` (offline-mockable DNS)

Sync trait (`dns::DnsResolver`): `lookup_txt/host/mx/ptr` or
`Temp`/`NxDomain`. `MockResolver` (builders `with_txt/host/mx/ptr/
temp_fail`) is the ONLY test resolver — suite runs fully offline.
`HickoryResolver::system()` is the live adapter (private Tokio
runtime, blocking facade). Bounds: `with_bounds(timeout, attempts)`
— `system()` uses 2 s × 2 attempts per query; `attempts` clamps
≥ 1. The private runtime + resolver build lazily on first lookup
and memoize failure as `Temp` (no rebuild loop on DNS-less hosts).
`block_on` runs on a scoped thread so the sync facade is safe to
call from inside an async runtime (Tauri command handlers). The
app wires it via a shared `OnceLock` (`commands/mail.rs
auth_sealer()`) into `sync_pop3_with_auth` and the lazy IMAP body
ingest; `SmtpReceipt` is `None` on both — POP3/IMAP cannot know
the client IP or envelope sender, so SPF records `none` there.
NXDOMAIN **and** NODATA map to `NxDomain`; every other failure
(transport, timeout, config, lookup panic) maps to `Temp` —
fail-closed, never `fail`.

## 7. Determinism

No clock/RNG/floats/map-order in verdicts. `unsafe_code = "forbid"`;
deps minimal+pinned.

## 8. Forensics mapping (Agent 6 owns, non-binding)

SPF `fail` + DMARC `fail/reject` → spoofing signal. DKIM aligned `pass`
→ auth evidence (not trust alone). `temperror` → limitation. `none` →
absence of evidence. `ptr_deprecated_used` → hardening note only.

## 9. Known deviations / open items (T-183)

Deliberate, evidence-preserving choices — **Lead review requested**:

1. **Invalid/absent `p=` (or invalid `sp=`) → `permerror`, not `none`.**
   RFC 7489 §6.6.3 step 6 says the receiver "applies no DMARC processing"
   for such a record (i.e. `none`). We return `permerror` so the caller can
   still see that a record *exists but is broken* — the crate's invariant is
   evidence-first, and `none` would hide a misconfigured domain. Consumers
   must treat `permerror` as "no policy applied", never as a finding.
   (§6.6.3 step 6 also allows treating it as `p=none` when a valid `rua` is
   present; we do not yet implement that `rua` special case.)
2. **Percent-escaped macro output cannot be used as a domain-spec.**
   RFC 7208 §7.3 URL-escapes uppercase macro expansions, but this crate's
   `DomainName` grammar is strict LDH (`[A-Za-z0-9_-]`), so an escape such
   as `%20` is rejected → `permerror`. Fail-closed (never a wrong-zone
   match); loosening the name grammar is a Lead call.
3. **Org domain = last-two-labels heuristic, not the Public Suffix List.**
   Unchanged from T-122; `co.uk`-style suffixes over-approximate. Callers
   needing exact PSL behaviour pass `DmarcInput.org_override`.
4. **The 14-day `t=` freshness window is KIWI policy, not an RFC rule.**
   RFC 6376 gives `t=` no maximum age (only `x=` expires). Retained from
   T-122 so archived mail is not re-verified forever; it is evidence, not an
   RFC verdict. An `x=` value, when present, takes precedence.
5. **`exists` resolves A/AAAA, not A-only.** RFC 7208 §5.7 says the `exists`
   mechanism queries an A record even for IPv6 sessions. The `DnsResolver`
   seam has no A-only method, so `exists` uses `lookup_host`. Fail-open in
   a narrow way (an AAAA-only name can match `exists`); fixing it means
   extending the trait.
6. **DKIM `i=` (AUID) is not parsed or validated.** §3.5 requires the AUID
   domain to be the `d=` domain or a subdomain of it. Out of T-183 scope
   (not in the task list); the tag is currently ignored as an unknown tag.
7. **Algorithms: `rsa-sha256` and `ed25519-sha256` only** (unchanged).
   `rsa-sha1`/x25519/Ed448 are `permerror` (unsupported).
8. **RSA Marvin advisory (RUSTSEC-2023-0071) stands** — verify-only
   public-key use; see `docs/SECURITY.md`.
