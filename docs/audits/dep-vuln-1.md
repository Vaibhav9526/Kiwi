# Dependency Vulnerability Audit — 1 (T-199)

**Reviewer:** Agent 21. **Date:** 2026-09-25. **Scope:** `release/v0.1.0` working
tree. **Mode:** read-only (no code, manifest, or lockfile was modified; this
report and `docs/agents/agent-21-status.md` are the only writes).

**Tools:** `cargo-audit 0.22.2` (already installed) against
`~/.cargo/advisory-db` — **1,269 advisories** loaded, **579 crate
dependencies** scanned. `npm audit 11.11.0` (full, and `--omit=dev`) per npm
package.

> ### ⚠ Two blocking build-integrity problems (not vulnerabilities)
> These are not advisories, but they are more urgent than every advisory below,
> because **the Rust workspace currently does not resolve.**
>
> - **C1 — `kiwi-integrations` requests a `reqwest` feature that does not
>   exist.** `kiwi-integrations/Cargo.toml` declares
>   `features = ["rustls-tls-webpki-roots"]`, but `reqwest 0.13.5` has no such
>   feature. `cargo tree --workspace` and `cargo check --workspace` both fail
>   with *"package `kiwi-integrations` depends on `reqwest` with feature
>   `rustls-tls-webpki-roots` but `reqwest` does not have that feature"*.
>   `reqwest 0.13.5` exposes `rustls`, `rustls-no-provider`, and
>   `__rustls-aws-lc-rs`; the `webpki-roots` feature name is gone. **Owner:
>   whoever owns `kiwi-integrations`.** Not fixed here (read-only task).
>   Note `cargo audit` still reports because it parses `Cargo.lock` without
>   re-resolving — so a green audit does **not** mean the workspace builds.
> - **C2 — `kiwi-mailauth/src/dmarc.rs` does not currently parse.** An
>   unclosed `mod tests` block; `cargo check --workspace` reports
>   *"unexpected closing delimiter"* at `dmarc.rs:597`. The file is modified
>   and uncommitted, so this is most likely another agent's in-flight edit
>   rather than a committed defect. Reported for awareness, not fixed.

---

## 1. Summary

| Ecosystem / package | Result | Shipped-only (`--omit=dev`) |
|---|---|---|
| Rust workspace (`cargo audit`) | **1 vulnerability + 7 allowed warnings** | n/a — single lockfile |
| `kiwi-app` (npm, full) | **0 vulnerabilities** | 0 |
| `kiwi-admin` (npm, full) | **6 vulnerabilities** (1 critical, 5 moderate) | **0** |
| `kiwi-admin-ui` (npm, full) | **0 vulnerabilities** | 0 |
| `mobile` (npm, full) | **NOT AUDITABLE** — no `package-lock.json` | not auditable |

**Nothing is in a shipped/runtime dependency set.** `npm audit --omit=dev` is
clean in all three lockfile-backed packages, and every Rust finding is either
unreachable in our usage, Linux-target-only, or has no fix available.

**Ranked totals:** 2 actionable advisories (A1, A2 — the same critical, unfixed,
in two packages), 3 actionable non-security items (A3–A5), 4 accepted risks
with justification (B1–B4), 2 blocking build findings (C1, C2).

---

## 2. Actionable

### A1 — `vitest` < 3.2.6 — GHSA-5xrq-8626-4rwp — **CRITICAL** — `kiwi-admin`

| | |
|---|---|
| Advisory | GHSA-5xrq-8626-4rwp — "When Vitest UI server is listening, arbitrary file can be read and executed" |
| Severity | **Critical (9.8)** |
| Vulnerable range | `< 3.2.6` |
| Installed | **3.2.4** (declared `^3.2.4`, locked 3.2.4) |
| Fixed in | **3.2.6** (3.2.6 and 3.2.7 both exist on the registry — verified) |
| Chain | `vitest` (direct devDependency) |
| Dev-only? | **Yes** — listed under `devDependencies` |

**Our exposure: low, and not reachable as configured.** The advisory requires
the **Vitest UI server to be listening**. Verified absent on every axis:
- no `--ui`, `--api`, or `ui: true` anywhere
  (`git grep -E '\-\-ui|ui:\s*true|--api'` → 0 hits);
- `kiwi-admin/vitest.config.ts` sets only `environment: "node"`, `include`, and
  `onConsoleLog` — no `api`/`ui` block;
- the scripts are `vitest run` and `vitest` (watch) — neither starts a server.

`npm audit --omit=dev` is clean, so nothing ships. **But the fix is free**, so
"dev-only and unreachable" is not a reason to leave a critical open:

**Action (Agent 5 / kiwi-admin owner):** `npm i -D vitest@^3.2.7` — a
non-breaking minor bump inside the existing `^3` range. Re-run `npm audit` and
`npm test`.

### A2 — `vitest` 3.2.4 — same critical — `mobile` — **invisible to CI**

`mobile/package.json` pins `"vitest": "3.2.4"` (exact, no caret) in
devDependencies, and `mobile/node_modules/vitest` is **3.2.4**. Same critical
advisory, but `npm audit` cannot see it because `mobile/` has **no
`package-lock.json`** (A5) — so A1 is currently only half-reported.

**Action (Agent 4 / mobile owner):** bump to `^3.2.7` together with A1 so the
two do not drift.

### A3 — `@vitest/mocker` — GHSA-82fw-gwwq-j7x9 — **moderate**

| | |
|---|---|
| Severity | moderate |
| Vulnerable range | `>=2.1.0 <4.1.11` |
| Installed | `@vitest/mocker` 2.1.0 (nested under `vitest`) |
| Fixed in | `vitest >= 4.1.11` — **a major-version jump** |
| Reported under | `vitest` (critical rollup) and `@vitest/mocker` (moderate) |

**Our exposure: effectively none.** This is a path traversal in the `vi.mock`
*redirect-mock* path. Verified: `git grep -E 'vi\.mock|vi\.doMock|jest\.mock'`
across `kiwi-admin/` and `mobile/` returns **0 hits** — we do not use module
mocking at all, so the vulnerable path is never reached.

**Action:** do **not** force-upgrade to vitest 4.x for this alone (breaking
config/test-API churn for an unreachable moderate). Fold into a scheduled
vitest 4.x migration. The `npm audit fix` npm suggests would jump to 4.x.

### A4 — `esbuild` <= 0.24.2 — GHSA-67mh-4wv8-2f99 — **moderate**

| | |
|---|---|
| Severity | moderate |
| Vulnerable | `esbuild <= 0.24.2`; **installed 0.18.20** |
| Chain | `drizzle-kit` 0.31.4 (direct **devDep**) → `@esbuild-kit/esm-loader` 2.6.5 → `@esbuild-kit/core-utils` 3.3.2 → `esbuild` 0.18.20 |
| npm's offered fix | `npm audit fix --force` → downgrade to `drizzle-kit` 0.18.1 (**breaking, semver-major**) |

**Our exposure: none in practice.** The advisory is *"esbuild enables any
website to send any requests to the development server and read the response"* —
it needs the esbuild **dev server listening on a port**. In our tree `esbuild`
is reachable only as a **transform loader inside the `drizzle-kit` CLI**
(`db:generate` / `db:check`, `kiwi-admin/package.json:16-19`), which does not
bind a port. The same `drizzle-kit` also carries `esbuild` 0.25.12 and 0.28.2
at other depths — both **above** the vulnerable `<=0.24.2` range; only the
`@esbuild-kit/core-utils` copy at 0.18.20 is affected.

**Action:** accept as-is. Do **not** run `npm audit fix --force` — a
semver-major *downgrade* of `drizzle-kit` to 0.18.1 is a far worse outcome than
a moderate in an unreachable dev-only path. Revisit when `drizzle-kit` drops
the `@esbuild-kit/*` loader chain. (If the team wants it closed now: an npm
`overrides` entry pinning `esbuild >= 0.25`.)

### A5 — `mobile/` is not auditable at all — **process gap**

`npm audit` in `mobile/` fails with `ENOLOCK`: *"This command requires an
existing lockfile."* The mobile tree is **unversioned and unpinned** — CI
cannot gate it, and A2 was invisible for exactly this reason.

**Action (Agent 4):** `npm i --package-lock-only` and commit the lockfile so
`npm audit` and `npm ci` work. Carried over from the T-154 baseline
(`docs/SECURITY.md` §7) and **still open** — the third audit to raise it.

---

## 3. Accepted risk (justified, with the reasoning)

### B1 — `rsa 0.9.10` — RUSTSEC-2023-0071 "Marvin" — **medium (5.9)** — NO FIX

Direct dependency of `kiwi-mailauth` (the only crate that pulls it), declared
`rsa = { version = "0.9", features = ["sha2"] }`. **No fixed upgrade exists.**

**Exposure re-verified at the call sites** (this closes the T-154 assessment
with exact current line numbers, `kiwi-mailauth/src/dkim.rs`):

| Line | Code | Operation |
|---|---|---|
| 740 | `Rsa(rsa::RsaPublicKey)` | the key enum holds a **public** key only |
| 786–791 | `RsaPublicKey::from_pkcs1_der` / `from_public_key_der` | public-key **parsing** |
| 832–839 | `verify_rsa_sha256` → `pkcs1v15::VerifyingKey` + `Verifier::verify` | public-key **verification** |
| 1124 | `RsaPrivateKey::new(&mut rng, 1024)` | **inside `mod tests`** (opens line 426) — test keygen only |

Marvin recovers plaintext through an RSA **private-key operation**
(decryption/signing). KIWI performs **no RSA private-key operation outside
tests** — DKIM is verify-only, and the single private key that exists is a
1024-bit throwaway generated inside the test module.

**Accepted.** No code change. Track upstream; prefer removing the dependency
(verify-only alternatives remain nominally affected on paper) or migrating when
a fixed release appears. Matches the existing `docs/SECURITY.md` §7 entry.

### B2 — `glib 0.18.5` — RUSTSEC-2024-0429 — **unsound** — Linux-only

Chain (reverse deps, from `Cargo.lock`): `glib` ← `atk`, `cairo-rs`, `gdk`,
`gdk-pixbuf`, `gdkx11`, `gio`, `gtk`, `javascriptcore-rs`, `libappindicator`,
`pango`, `soup3`, `webkit2gtk` — i.e. the entire **Linux Tauri/wry/GTK
webview** path, not our code.

**Exposure: none on the shipped target.** KIWI is Windows-first; the GTK path is
not compiled on this host. **Accepted**, with a standing note for Linux
CI/packaging owners: if a Linux build is ever produced, re-assess — an
unsoundness is a correctness/safety issue, not only a vuln-class one.

### B3 — `proc-macro-error 1.0.4` — RUSTSEC-2024-0370 — **unmaintained** — Linux-only

Chain: `proc-macro-error` ← `glib-macros` ← `glib`, and ← `gtk3-macros`. A
**build-time proc-macro** on the same non-compiled Linux path. "Unmaintained" is
a maintenance signal, not an exploitable condition. **Accepted.**

### B4 — 5× `unic-char-*` — RUSTSEC-2025-0075/0080/0081/0098/0100 — **unmaintained**

`unic-char-property`, `unic-char-range`, `unic-common`, `unic-ucd-ident`,
`unic-ucd-version`, all 0.9.0.

Full chain, verified: **`tauri-utils` → `urlpattern` → `unic-ucd-ident` →
`unic-char-property`**. `tauri-utils` is pulled in by 6 crates (`tauri`,
`tauri-build`, `tauri-codegen`, `tauri-macros`, `tauri-runtime`,
`tauri-runtime-wry`) — all upstream Tauri, none directly selectable by us.

**Accepted.** These are Unicode-property tables used for identifier
normalisation; "unmaintained" carries no known vulnerability. **Action:** no
direct change — ride Tauri upgrades and re-check when Tauri bumps
`tauri-utils`/`urlpattern`.

---

## 4. Ranked index

| Rank | ID | Advisory | Sev | Package | Exposure | Disposition |
|---|---|---|---|---|---|---|
| 1 | **C1** | reqwest feature `rustls-tls-webpki-roots` does not exist | **blocker** | kiwi-integrations | **workspace does not resolve** | **fix now** |
| 2 | **C2** | unclosed `mod tests` in `dmarc.rs` | **blocker** | kiwi-mailauth | workspace does not compile | in-flight; confirm resolved |
| 3 | A1 | GHSA-5xrq-8626-4rwp | **critical 9.8** | kiwi-admin `vitest` 3.2.4 | dev-only, UI server never started | **fix now** (free, `^3.2.7`) |
| 4 | A2 | GHSA-5xrq-8626-4rwp | **critical 9.8** | mobile `vitest` 3.2.4 | dev-only, **invisible to audit** | **fix now** |
| 5 | A5 | no `package-lock.json` | process | mobile | **not auditable** | **fix now** |
| 6 | A3 | GHSA-82fw-gwwq-j7x9 | moderate | `@vitest/mocker` | `vi.mock` unused → unreachable | accept; schedule vitest 4.x |
| 7 | A4 | GHSA-67mh-4wv8-2f99 | moderate | `esbuild` 0.18.20 | dev-server never listens | accept; **do not** `fix --force` |
| 8 | B1 | RUSTSEC-2023-0071 | medium 5.9 | `rsa` 0.9.10 | verify-only, no private-key op | accept (no fix exists) |
| 9 | B2 | RUSTSEC-2024-0429 | unsound | `glib` 0.18.5 | Linux target only | accept; re-assess on Linux build |
| 10 | B3 | RUSTSEC-2024-0370 | unmaintained | `proc-macro-error` | Linux build-time macro | accept |
| 11 | B4 | RUSTSEC-2025-0075/0080/0081/0098/0100 | unmaintained | `unic-char-*` ×5 | via `tauri-utils` | accept; ride Tauri |

---

## 5. Delta vs the T-154 baseline (`docs/SECURITY.md` §7)

| Baseline item (2026-09-20) | Now (2026-09-25) | Change |
|---|---|---|
| `rsa` RUSTSEC-2023-0071, medium, no fix | same | unchanged; call sites re-verified |
| 7 unmaintained/unsound warnings | same 7 | unchanged |
| `kiwi-admin`: 6 vulns (1 critical + 5 moderate), all dev-only | same 6 | unchanged — **still unfixed after 5 days** |
| `kiwi-admin-ui`, `kiwi-app`: 0 | 0 | unchanged |
| `mobile`: NOT AUDITABLE (no lockfile) | still NOT AUDITABLE | **unchanged, 3rd audit running** |
| advisory DB 1251 | **1269** | +18 advisories; no new hits in our tree |

The most useful signal in this audit: **the `kiwi-admin` critical has now
survived three audits (T-154, the interim, and this one) while its fix is a
one-line non-breaking bump.** A5 (mobile lockfile) has likewise survived three.
Both are process failures, not technical ones.

---

## 6. Commands (reproducible, from repo root)

```powershell
cargo audit --version                 # cargo-audit-audit 0.22.2
cargo audit                           # 1 vulnerability, 7 allowed warnings
cargo tree --workspace                # FAILS today — see C1

foreach ($w in 'kiwi-app','kiwi-admin','kiwi-admin-ui','mobile') {
  Push-Location $w; npm audit; Pop-Location              # mobile -> ENOLOCK
  Push-Location $w; npm audit --omit=dev; Pop-Location   # all 0
}

# Exposure evidence for A1/A3:
git grep -n -I -E '\-\-ui|ui:\s*true|--api' -- 'kiwi-admin/*' 'mobile/*'   # 0 hits
git grep -n -I -E 'vi\.mock|vi\.doMock|jest\.mock' -- 'kiwi-admin/*' 'mobile/*'  # 0 hits
npm view vitest versions --json                    # confirms 3.2.6/3.2.7 exist
```

## 7. Scope limits / assumptions

- `cargo audit` reads `Cargo.lock` and does **not** re-resolve the workspace,
  which is why it reports cleanly while the workspace does not build (C1).
  A clean audit is therefore **not** evidence that the tree compiles.
- The Rust findings are evaluated against a **Windows-first** target. If a Linux
  build is ever produced, B2/B3 move from accepted to actionable.
- npm exposure reasoning assumes CI/dev run the documented scripts. A developer
  manually running `vitest --ui` would create a live listener and change the
  A1 exposure — worth a line in the contributor docs.
- `npm audit` reflects the registry's advisory data at run time; results drift.
  Re-run on every dependency change and monthly, per `SECURITY.md` §7.
- No fix was applied and no file outside this report and the status log was
  modified — C1, C2, A1–A5 are all recommendations for their owners.
