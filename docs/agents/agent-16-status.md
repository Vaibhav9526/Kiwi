# Agent 16 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-183 `kiwi-mailauth` hardening (claimed → done)

**Status: done.** 63/63 tests green, fully offline; clippy `--all-targets -D
warnings` clean; `cargo fmt --check` clean; `unsafe_code = "forbid"` inherited
via workspace lints and zero `unsafe` in the crate.

### Starting point (important)

The branch was **RED before any edit of mine**: `cargo test -p kiwi-mailauth`
failed 2/30 (`dkim::tests::canon_body_empty_variants`,
`dkim::tests::canon_body_length_tag`). Those two failures were a *wrong test
model*, not a broken implementation — I verified against the normative text
and the RFC's own published hash vectors (see DKIM item 1). Agent 8's T-122
status line claimed 26/26 green; the canon tests added later in that work
encode a relaxed-body expectation that contradicts RFC 6376.

### Files changed

- `kiwi-mailauth/src/dkim.rs` — canon + header-hash rework, `b=` emptying, tests
- `kiwi-mailauth/src/spf.rs` — lookup/void limits, include+redirect results,
  macro §7.3 conformance, mx/ptr caps, tests
- `kiwi-mailauth/src/dmarc.rs` — §6.6.3 policy discovery, `sp=` rule,
  multiple-record handling, tests
- `docs/contracts/mailauth.md` — ⛔-marked behaviour-change notes + new §9
  (deviations / open items, Lead review requested)
- `docs/agents/agent-16-status.md` — this entry

No changes to `Cargo.toml`, no new dependencies, no public API break beyond
the private-helper renames noted below.

### DKIM (RFC 6376)

1. **Red baseline corrected.** `relaxed` canonicalization of an empty body is
   the **null input**, not a CRLF. Proof: §3.4.4 publishes its SHA-256 as
   `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` (the hash of ""), and
   §3.4.3 publishes `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=` for
   `simple`. Both are now asserted in `canon_body_empty_matches_rfc_vectors`.
2. **`l=` truncated the WRONG operand — fixed.** It was applied *before*
   canonicalization. §3.7 says the body is "canonicalized … **and then**
   truncated to the length specified in the `l=` tag"; §3.4.5: "the body
   length count MUST be calculated following the canonicalization
   algorithm". Now `l=` applies after canon (`canon_body_untruncated` +
   truncate). Consequence proven by `canon_body_length_applies_after_canonicalization`:
   the same `l=3` on `A  B\r\n` yields `A  ` (simple) vs `A B` (relaxed) —
   only possible if the count is measured post-canonicalization. Also: `l=0`
   ⇒ body completely unsigned; `l=` > body ⇒ no truncation.
   Checked the RFC 6376 errata list — no verified erratum changes this
   ordering (only 5252 touches §3.7, and it is about the `data-hash`
   pseudo-code, not body truncation).
3. **Header hash step 2 was wrong — fixed (interop bug).** §3.7 requires
   (1) the `h=` fields in `h=` order each terminated by CRLF, then (2) the
   DKIM-Signature field under verification, `b=` emptied, **without** a
   trailing CRLF. The old code included the signature field *only* if `h=`
   literally listed `dkim-signature`, and then in the wrong position and
   with a trailing CRLF. Real-world signatures would fail. Now
   `header_hash_input()` implements the exact order.
4. **`h=dkim-signature` no longer means self-reference.** §3.5 forbids the
   field under verification in its own `h=`; such an entry now selects
   *other* DKIM-Signature headers (§3.5 "may include others"), and the field
   under verification is never double-counted.
5. **`h=` order / repeats / absences** (§3.5, §5.4.2): `h=` order wins over
   message order; repeated names take the last unused occurrence bottom-up
   (RFC's own `Received <A>/<B>/<C>` example → signs C then B); a name with
   no occurrence contributes the null input (nothing, not an error).
6. **Simple header canonicalization is now byte-preserving** (§3.4.1). The
   old code unfolded folded headers, which silently changed signed bytes.
   Verified against the §3.4.5 Example 1 (relaxed → `a:X` / `b:Y Z`) and
   Example 2 (simple → `A: X ` / `B : Y <HTAB><CRLF><HTAB> Z  `).
7. **`b=` emptying hardened:** handles FWS around `=` and CRLF-folded values;
   keeps the tag name/FWS/`=` and removes only the value + surrounding WSP
   (§3.7). Verified `bh=` is not mistaken for the signature tag.
8. **`t=`/`x=`:** expiry runs before any DNS; a future `x=` overrides the
   14-day `t=` policy; `x=` must be > `t=` (§3.5) else `permerror`.
9. Test-only signature-path change: the round-trip tests now sign the field
   value as transmitted (`DKIM-Signature: <tags>`, i.e. with the leading
   SP). Under simple canon that SP is significant, so the old test input was
   inconsistent with what `verify` re-canonicalizes.


### SPF (RFC 7208)

10. **`include` → no record is `permerror`**, not no-match (§5.2 result
    table: `none → return permerror`). Previously it was converted to
    `neutral`, i.e. a dangling include silently did not match.
11. **`redirect=` → no record is `permerror`**, not `neutral` (§6.1: "if no
    SPF record is found … the result is a `permerror` rather than `none`").
12. **Void-lookup limit now applied to `exists`** and to empty (NODATA)
    answers on `mx`/`ptr` hosts (§4.6.4). Previously only `a`/MX-host
    NXDOMAIN charged, so a record full of dead `exists` probes was free.
13. **`mx`/`ptr` address-lookup caps** (§4.6.4): `mx` may issue ≤10 address
    queries, exceeding it is `permerror`; `ptr` may issue ≤10 and ignores
    the rest. Replaced the old silent `take(32)` truncation, which could
    return "no match" for a domain that actually authorized the sender.
14. **Macro §7.3 conformance** — the old expander was wrong in four ways;
    all are now covered by the RFC 7208 §7.4 golden-vector test
    (`rfc7208_section7_golden_macro_vectors`, IPv4 + IPv6):
    - split on the **specified delimiter characters** (was: always `.`),
      then **rejoin with `.`** (§7.4: `%{l-}` → `strong.bad`, `%{l1r-}` →
      `strong`, `%{d2r}` → `example.email`);
    - **uppercase macro letters URL-escape**, lowercase do not (§7.3) — the
      old code escaped `i`/`h`/`l` unconditionally;
    - **IPv6 `%{i}` uses the 32-nibble dot format** (§7.3), so `%{ir}` now
      reproduces the §7.4 IPv6 example exactly;
    - `r` is a reversal transformer, not a delimiter.
15. **New syntax errors, all fail-closed `permerror`:** zero `DIGIT`
    transformer (§7.3 "the value MUST be nonzero" — previously treated as
    "keep all", a fail-open); `%` not followed by `{`/`%`/`-`/`_` (§7.3, the
    RFC's own `%(ir).sbl.example.org` counter-example).
16. **Removed a fail-open in `ptr`:** a spec that does not expand to a valid
    domain silently fell back to the *current* domain, which could authorize
    a zone the record never named. Now `permerror`.
17. **`a`/`mx` accept `a/24` (CIDR-only tail);** `a:`/`exists:` with an
    empty domain-spec is a syntax error. `split_dual_cidr` no longer
    requires a leading `:`.
18. `mx` host address lookups are no longer double-charged against the
    10-lookup limit (the `mx` term counts once, per §4.6.4's intent).

### DMARC (RFC 7489)

19. **Policy discovery now follows §6.6.3:** query `_dmarc.<from_domain>`
    first, then `_dmarc.<org>` if the From domain is a subdomain and the
    first level yielded no record. T-122 queried only `_dmarc.<org>`, so a
    subdomain publishing its own DMARC record was ignored.
20. **`sp=` is ignored for subdomain-published records** (§6.3 note): `sp=`
    applies only when the record was discovered at the org domain for a
    subdomain From; a record found at the From domain itself always uses
    `p=`. T-122 applied `sp=` whenever From ≠ org.
21. **Multiple DMARC records at a level → `permerror`** (§6.6.3 step 5)
    instead of silently picking the first.
22. Non-`v=DMARC1` strings are discarded per level and an empty set falls
    through to the next level (§6.6.3 steps 2–4) rather than returning
    `none` early.
23. Strict/relaxed alignment covered explicitly: `aspf=s` needs an exact
    match (subdomain SPF no longer aligns), `adkim=s` likewise, and a
    *passing but unaligned* identifier never aligns.

### Commands run (all green, from repo root)

    cargo test -p kiwi-mailauth                                  # 63 passed / 0 failed
    cargo clippy -p kiwi-mailauth --all-targets -- -D warnings    # clean
    cargo fmt -p kiwi-mailauth -- --check                         # clean
    cargo check -p kiwi-mailauth --all-targets                    # clean

Test distribution: dkim 29 (17 unit + 12 roundtrip/header-canon), spf 21,
dmarc 13. **Zero network in tests** — every test builds a `MockResolver`;
`HickoryResolver` appears only in prose/docs, never in a test.

### Assumptions / risks / for Lead

- **Contract changes need Lead review.** `docs/contracts/mailauth.md` marks
  every behaviour change with ⛔ and adds §9 (deviations). The wire shapes
  (`SpfOutput`/`DkimOutput`/`DmarcOutput` field sets) are **unchanged**, so
  no consumer breaks; only verdict values for previously-mis-handled records
  change (e.g. dangling `include` is now `permerror` instead of `neutral`).
- Agent 6's `tests/mailauth-mapping.md` expectations still hold: none of its
  six fixtures use a dangling include, a percent-escaped macro, or a
  subdomain-published DMARC record. I did **not** edit that file (Agent 6's
  territory) — worth a re-read given the new `permerror` paths.
- Private helper renames (no public API break): `signed_headers_bytes` →
  `header_hash_input` (+ the field name/value args), `push_canon_header`
  gained a `trailing_crlf` flag, `canon_body_bytes` split into
  `canon_body_untruncated`. `eval_domain` lost its `top` bool.
- Two syntax-break incidents during editing (duplicate `}` at the end of
  `mod tests` in dmarc.rs and spf.rs) were introduced and fixed by me within
  the same session; the suite is green now. Flagging because a watcher
  reported them mid-edit — the crate was briefly red.
- Out of scope, left documented: DKIM `i=` (AUID) validation; `exists`
  A-only lookup; the `rua` special case for an invalid `p=`; PSL-accurate org
  domains; `rsa-sha1`/x25519 algorithms. See contract §9.
- I did not edit `docs/TASKS.md` (Lead-owned per its header) — the T-183 row
  still says "in-progress" and should be merged to done by the Lead.
