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
