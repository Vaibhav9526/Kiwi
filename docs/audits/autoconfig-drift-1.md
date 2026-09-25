# Autoconfig Drift Audit 1 (T-246)

**Reviewer:** Agent 22 · **Date:** 2026-09-25 · **Mode:** read-only analysis.
**Scope:** ACFG-3 through ACFG-10 from the T-196 contract-drift audit, checked
against `docs/contracts/autoconfig.md` and the current `kiwi-autoconfig/src/`
implementation. No Rust, TypeScript, schema, or contract implementation files
were changed.

## Method and severity

The contract was read in full and each disputed promise was traced to the
parser, validation, ISPdb, MX-heuristic, and discovery paths. Existing tests
were read as corroboration where they assert the behavior. Severity is the
user-visible/security impact of the contract mismatch, not the size of the
patch:

- **H:** credential, connection, or trust boundary is unsafe.
- **M:** can produce an incorrect suggestion, violates a stated parser
  security/selection invariant, or breaks an offline/data promise.
- **L:** error taxonomy, accepted-input, example, or documentation drift with
  no direct trust failure.

## Summary

| IDs | result | recommended owner |
|---|---|---|
| ACFG-3, 5, 6, 10 | contract wording is narrower/staler than the current implementation | contract owner; no parser code change required |
| ACFG-4 | documented ISPdb fixture is absent; GoDaddy exists only as an MX hint | decision gate: add verified fixture or remove the fixture claim |
| ACFG-7, 8, 9 | parser accepts constructs/fallbacks the contract says are prohibited or checked out | autoconfig code owner; harden parser, then amend contract for any intentional compatibility exception |

No item is a credential/connection-secret finding. ACFG-7/8/9 are the
security/selection-relevant subset and should be resolved before relying on
published documents as authoritative provider configuration.

## Detailed findings and candidate rulings

| ID | Contract promise | Actual code and file:line evidence | Severity | Candidate ruling / resolution |
|---|---|---|---|---|
| **ACFG-3** | `split_email` accepts local parts containing only `[A-Za-z0-9._%+\-']` (`autoconfig.md:47-50`). | `split_email` uses `rsplit_once('@')`, then accepts the RFC-5321 `atext` superset `!#$%&'*+-/=?^_{}|~` plus alphanumeric and `.` (`kiwi-autoconfig/src/lib.rs:131-154`, especially `:138-146`). The code does not intentionally restrict to the contract subset; the separate 64-byte local limit is ACFG-15. | L | **Contract-fix.** Replace the narrow character list with the RFC `atext` set and state that the parser validates the complete permitted set. Add punctuation regression coverage if the code owner wants the contract assertion executable. |
| **ACFG-4** | `ISPDB_FIXTURES` promises public provider entries including GoDaddy (`autoconfig.md:105-110`). | `ISPDB_FIXTURES` contains nine entries: Google, Microsoft 365, Yahoo, iCloud, Fastmail, Zoho, GMX, Yandex, and AOL (`kiwi-autoconfig/src/ispdb.rs:70-146`); GoDaddy is absent. GoDaddy is represented only by the MX hint `secureserver.net` (`kiwi-autoconfig/src/heuristics.rs:126-132`), so it can be found after network/MX stages but not by the promised offline fixture lookup. | M | **Decision gate, with code-fix preferred if GoDaddy support is required.** Add a verified GoDaddy `IspdbEntry` (domains, endpoints, security, auth) and an offline lookup test; do not invent endpoint facts. If offline GoDaddy support is not required, use a **contract-fix** to remove GoDaddy from the fixture list and describe it as MX-hint-only. |
| **ACFG-5** | The `MX_HINTS` examples include `pphosted.com` (`autoconfig.md:111-114`). | The current table has nine suffixes and no `pphosted.com` (`kiwi-autoconfig/src/heuristics.rs:67-133`); it includes `secureserver.net` for GoDaddy. Suffix matching itself is label-boundary and deterministic (`heuristics.rs:147-170`). | L | **Contract-fix.** The list is introduced as “e.g.”, so this is a stale example rather than a functional omission: replace it with `secureserver.net` or explicitly mark examples non-normative. Use a **code-fix** only if a verified pphosted provider mapping is an intended product requirement. |
| **ACFG-6** | Documents over 256 KiB are listed with prohibited constructs and are required to return hard `Err(MalformedXml)` (`autoconfig.md:118-125`). | `parse_root` checks `MAX_XML_LEN` and returns `Error::TooLong` (`kiwi-autoconfig/src/autoconfig_xml.rs:56-60`; error variant declared at `kiwi-autoconfig/src/lib.rs:70-86`). Discovery converts that to a non-fatal `StageOutcome::Malformed` with a bounded detail (`kiwi-autoconfig/src/discovery.rs:98-105,152-163`). The current test explicitly expects `Error::TooLong` (`autoconfig_xml.rs:787-790`). | L | **Contract-fix.** Document `Error::TooLong` as the dedicated size-bound result and its mapping to the public `malformed` stage outcome. A code-fix that collapses it into `MalformedXml` is possible, but would discard useful taxonomy and require changing the existing test/API expectation. |
| **ACFG-7** | Processing instructions are prohibited and must produce a hard parse error (`autoconfig.md:118-125`). | `parse_root` calls `skip_misc` before and after the root (`kiwi-autoconfig/src/autoconfig_xml.rs:69-79`). `skip_misc` skips every `<?...?>` construct, including the XML declaration and any non-declaration PI, before returning (`autoconfig_xml.rs:102-118`); the normal fixture itself starts with `<?xml ...?>` (`autoconfig_xml.rs:590-592`). | M | **Code-fix, with a contract clarification.** Permit only the XML declaration in the prolog, reject other PIs, and document that narrow declaration exception. Silently ignoring arbitrary PIs does not create the DTD/XXE surface, but it violates the stated fail-closed parser policy. |
| **ACFG-8** | The document root must be `clientConfig` (`autoconfig.md:118-129`). | `ClientConfig::parse` accepts either a `clientConfig` root or a bare `emailProvider` root (`kiwi-autoconfig/src/autoconfig_xml.rs:347-361`). `parse_root` is intentionally generic, and the existing negative test only covers `<html/>` (`autoconfig_xml.rs:814-820`). | M | **Code-fix.** Enforce `clientConfig` as the root in `ClientConfig::parse` and add a bare-`emailProvider` rejection test. If bare-provider compatibility is intentional, use a **contract-fix** to state the accepted compatibility format rather than leaving the promise silently broader. |
| **ACFG-9** | `<domain>` entries are checked against the queried domain, with an exact match preferred (`autoconfig.md:128-129`). | Selection first tries an exact `<domain>` match, then a provider `id` match, then unconditionally chooses the first provider when no match exists (`kiwi-autoconfig/src/autoconfig_xml.rs:363-377`). The first-provider fallback can turn a document for another domain into a suggestion. | M | **Code-fix.** Remove the unconditional first-provider fallback. Retain provider-`id` matching only if the contract explicitly permits it; otherwise return no provider/unsupported so discovery can fall through. A contract-fix is acceptable only if the fallback is intentionally documented and its trust implications are accepted. |
| **ACFG-10** | Only `%EMAILADDRESS%` and `%EMAILLOCALPART%` are substituted; other placeholders pass through verbatim (`autoconfig.md:130-131`). | `substitute` also expands `%EMAILDOMAIN%` (`kiwi-autoconfig/src/autoconfig_xml.rs:474-505`, especially `:484-493`); the test suite asserts `%EMAILDOMAIN%` expansion (`autoconfig_xml.rs:694-715`). | L | **Contract-fix.** Add `%EMAILDOMAIN%` to the supported placeholder list and retain the existing unknown-placeholder behavior. No parser change is needed. |

## Candidate ruling set

1. **Ratify contract fixes for ACFG-3, ACFG-5, ACFG-6, and ACFG-10.** The
   implementation is either standards-compatible or deliberately exposes a
   distinct bound error; the current contract text is narrower/staler.
2. **Make an explicit product decision for ACFG-4.** If GoDaddy must work
   offline, assign a verified fixture code-fix; otherwise remove GoDaddy from
   the fixture promise and document the existing MX-hint route.
3. **Assign ACFG-7/8/9 to the autoconfig code owner for fail-closed parser
   fixes.** The contract may be amended afterward only for intentional
   compatibility exceptions (for example, the XML declaration itself), never
   to conceal an unchecked provider-selection fallback.
4. **Re-run the autoconfig suite after any code-fix**, including the existing
   XML, domain, placeholder, stage-order, and custom-table tests. This audit
   itself makes no implementation or test-file changes.

## Scope boundary

ACFG-1/2 and ACFG-11 onward are intentionally outside this enumeration. The
T-195 OAuth2 exception, the missing `oauth2.md` file, and the broader wire
vocabulary issues have separate owners/decisions. T-246 records no new code
finding beyond ACFG-3..10.
