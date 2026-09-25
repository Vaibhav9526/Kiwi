# License-Compliance + Secret Scan — 1 (T-197)

**Reviewer:** Agent 21. **Date:** 2026-09-25. **Scope:** `release/v0.1.0` working
tree at `014859a`. **Mode:** read-only (no tracked file was modified; this report
and `docs/agents/agent-21-status.md` are the only writes).

**Verdict: PASS with 6 non-blocking findings (F1–F6). No GPL/AGPL/SSPL
contamination found, and no live secret is committed.**

---

## 1. GPL / AGPL boundary — Mailspring (GPL-3.0) & MailFlow (AGPL-3.0)

### 1.1 What the references actually are (verified on disk)

| Path | License (read from the file) |
|---|---|
| `reference/mailspring/LICENSE.md` | `### GNU GENERAL PUBLIC LICENSE / Version 3, 29 June 2007` |
| `reference/mailspring/package.json` → `license` | `GPL-3.0` |
| `reference/mailflow/LICENSE` | `GNU AFFERO GENERAL PUBLIC LICENSE / Version 3, 19 November 2007` |
| `reference/mailflow/LICENSE-COMMERCIAL` | present (dual AGPL/commercial) |

Both are **strong copyleft**. Any verbatim source or code block copied into the
KIWI tree would be a licensing incident (MPL-2.0 is file-level copyleft and
cannot absorb GPL/AGPL code into a shipped binary).

### 1.2 `reference/` is gitignored and untracked — CONFIRMED

```
$ git check-ignore -v reference
.gitignore:38:reference/        reference

$ git check-ignore -v reference/mailspring/README.md reference/mailflow/LICENSE
.gitignore:38:reference/        reference/mailspring/README.md
.gitignore:38:reference/        reference/mailflow/LICENSE

$ git ls-files | Select-String 'reference'
(no output — zero tracked files under reference/)

$ git status --porcelain --ignored=matching -- reference
!! reference/
```

`!!` = ignored-and-untracked. The boundary holds mechanically: nothing in
`reference/` can be committed without a forced `git add -f`.

Same posture for the Thunderbird checkout: `source/` is a **symlink**
(`Get-ChildItem` reports mode `d----l`) and is gitignored at `.gitignore:2`.
Thunderbird is MPL-2.0/LGPL-2.1 (not GPL/AGPL), so it is not a copyleft
conflict, but it likewise stays out of the tree.

### 1.3 No Mailspring / MailFlow code or headers in our tree

**Marker grep** — `git grep -i -E 'mailspring|mailflow|foundry376'` across the
repo excluding `reference/`: every hit is either prose in `docs/`/`README.md`
(naming Mailspring as a *behavioural* study reference, e.g.
`docs/ARCHITECTURE.md:125` "Study `source/comm/` (Thunderbird) and Mailspring for
behavior only") or **our own unrelated domain term** `mailflow` = mail-flow
metadata / audit events (`kiwi-admin` `mailflow_events` table, admin-api
contract, `kiwi-admin-ui/src/views/mailflow.tsx`). The latter is a domain
feature, not MailFlow-derived code.

**Distinctive-source grep** — `git grep -i -E 'Nylas|Foundry376|Mailspring, Inc|spaceduck|persona-id|participant-list|GPL-3'` over `kiwi-app/src`, `kiwi-admin-ui/src`, `kiwi-admin/src`, `mobile/src`, all `kiwi-*/src`: **zero hits.**

**No license headers of any kind** — `git grep -i -E 'copyright|Copyright \(c\)|SPDX-License-Identifier'` over the four JS/TS source trees: **zero hits.** Nothing carries a Mailspring GPL header, an MIT "Copyright (c) 2015-2017 Nylas" header, or an SPDX tag. (This also means we have no attribution headers of our own — see F5.)

**Verbatim-overlap scan (the decisive test).** I built a set of every distinct
trimmed source line ≥45 characters from 1,081 reference source files
(`reference/mailspring/{app/src,app/internal_packages,mailsync}`,
`reference/mailflow/{frontend/src,backend}`; `.js/.jsx/.ts/.tsx/.coffee/.py/.go`,
200 B–300 kB) → **52,024 distinct lines**. I then scanned all 204 source files
in our tree (`kiwi-*/src`, `kiwi-app/src-tauri/src`, `kiwi-app/src`,
`kiwi-admin/src`, `kiwi-admin-ui/src`, `mobile/src`, `tests`, `tools`, `infra`;
`.rs/.ts/.tsx/.js/.py/.sql/.yml`).

Result: **62 shared lines across 23 files. Every single one inspected and
judged non-substantive boilerplate:**

| Shared line (trimmed) | Occurrences | Verdict |
|---|---|---|
| `// ---------------------------------------------------------------------------` (comment ruler) | ~40 of 62 | Incidental. A 75-dash separator is not copyrightable and is ubiquitous boilerplate. |
| `const [sending, setSending] = useState(false);` | 1 (`kiwi-app/src/views/compose.tsx:200`) | Generic React idiom. |
| `const [syncing, setSyncing] = useState(false);` | 1 (`kiwi-app/src/App.tsx:134`) | Generic React idiom. |
| `const [paletteOpen, setPaletteOpen] = useState(false);` | 1 (`kiwi-app/src/App.tsx:148`) | Generic React idiom. |
| `// eslint-disable-next-line react-hooks/exhaustive-deps` | ~5 | Generic lint pragma. |
| `const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;` | 1 (`compose.tsx:22`) | One coincidental constant. |
| `<authentication>password-cleartext</authentication>` | 3 (`kiwi-autoconfig/src/autoconfig_xml.rs:601,608,615`) | **Thunderbird/Mozilla autoconfig XML vocabulary**, not Mailspring IP — and required verbatim by the Thunderbird autoconfig spec our parser implements. |

Longest contiguous run of shared lines in any file: **0** (no shared 2-line
block). No file-level, function-level, or block-level copy exists.

**Conclusion — the GPL/AGPL boundary is intact.** KIWI's mail engine, forensics
engine, autoconfig, admin plane, and UI are original code. The study-only
posture is documented and was honoured (`docs/ARCHITECTURE.md:74` "MPL: study
patterns, write our own code"; `docs/BACKLOG-MAILFLOW.md:3-4,65` "Study-only;
no source copying"; `docs/DECISIONS.md:61-65` ADR-005 "completely independent
email client from scratch. Do NOT fork or modify").

### 1.4 Upcoming-risk note (not a finding against current code)

`docs/TASKS.md:119-121` schedules **T-190** ("Mailspring archaeology … layout/
animations/inventory from reference/mailspring — study only") and **T-191**
("Rebuild … Mailspring-faithful"). Those tasks are the point at which a
copying failure becomes *likely*. T-190's deliverable must be a **written
specification/token inventory only** (positions, spacing, timings, colour
tokens) — no transliterated source, no Mailspring class/component names, no
comment blocks, and no identifier renaming of Mailspring internals. Recommend
the Lead require the same ≥45-char overlap scan I used above as a **gate on
T-190/T-191 before merge** (it is cheap and already reproducible).

---

## 2. Secret scan

### 2.1 Gate tooling

- `python tests/tools/secret_scan.py` → **`secret_scan: scanned=385 hits=0`**
  ✅ (this is the CI gate: `.github/workflows/ci.yml:81`).
- `gitleaks` binary: **NOT installed** on this host (`Get-Command gitleaks` →
  empty). `tests/tools/gitleaks.toml` exists and is the Agent-6-owned mirror
  config (`useDefault = true` + a synthetic-marker allowlist), but nothing
  runs it today. → **F1**.
- Tests use obvious dummies throughout: `password: Zeroizing::new("demo")`,
  `"p"`, `"s"`, `"dummy"`, `"wrong"`, `"s3cret"`, `"fke-wire"` — all inside
  `#[cfg(test)]` / `mod tests` / `tests/` fixtures. Excluded per task scope,
  and each is a deliberate wrong-password or single-char value, never a
  real-looking credential.

### 2.2 Pattern scan of tracked files (excluding `reference/`, `images/`, lockfiles)

| Scan | Result |
|---|---|
| Known token shapes: `AKIA…`, `ghp_/gho_/github_pat_`, `xox[baprs]-`, `sk-…`, `AIza…`, `ya29.…`, `-----BEGIN … PRIVATE KEY-----` | **0 hits** |
| Assignment form: `(password\|passwd\|pwd\|secret\|token\|api[_-]?key\|private[_-]?key\|client[_-]?secret\|access[_-]?key\|auth[_-]?key)\s*[:=]\s*"<value>"` | 0 real secrets — every hit is a Rust type/param declaration (`password: Zeroizing<String>`, `fn resolve_secret(…)`, `pub secret: Option<String>`) or a test dummy |
| `Bearer <20+ chars>`, `Authorization: <scheme> <token>`, `private_key`, `client_secret=`, `postgres(ql)://user:pass@`, `redis://user:pass@` | Docs prose only (`docs/DECISIONS.md`, `docs/SECURITY.md`, `docs/contracts/*`, `docs/THREAT-MODEL.md` describing what must *never* be stored) + the 2 `.env.example` dev DSNs below |

### 2.3 `.env` / `.env.example` — correct discipline

```
$ git check-ignore -v .env
.gitignore:27:.env            .env

$ git ls-files | Select-String '\.env'
.env.example          ← the only tracked env file, by design
```

`.env.example` ships **dev-only defaults, self-labelled**, compliant with
`docs/SECURITY.md` rule 15:

- the `POSTGRES_…` key, set to a self-labelled `kiwi-dev-only-change-me` literal
- the `DATABASE_URL` DSNs, both embedding that same dev literal
- the audit-export signing key, `kiwi-dev-only-audit-export-key-change-me`

Each is marked "DEV default … override in `.env` (gitignored)". A committed
`kiwi-dev-only-…` literal is a *documented placeholder*, not a credential, and
is exactly what `SECURITY.md` rule 15 prescribes. **Accepted.**

### 2.4 Untracked artefacts that are NOT gitignored — accidental-commit risk (F2)

`git status --porcelain` currently shows (beyond other agents' in-flight
work): `?? auth-test-out.txt`, `?? watcher_stdout.log`, `?? watcher_stderr.log`,
`?? nul`. Untracked = not committed today, but **`*.log` and `nul` are not in
`.gitignore`**, so a broad `git add -A` would stage build/log noise. → **F2**.

---

## 3. Dependency license inventory (top-level, per manifest)

Method: exact-version resolution against the committed `Cargo.lock` /
each installed `package.json`, reading the authoritative `license` field from
`~/.cargo/registry/src/*/<crate>/Cargo.toml` and `node_modules/*/package.json`.
No version was inferred from a wildcard.

### 3.1 Rust — workspace `Cargo.toml` shared deps + per-crate

| Crate | Locked version | License | Manifest |
|---|---|---|---|
| serde | 1.0.229 | MIT OR Apache-2.0 | workspace |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | workspace |
| thiserror | 1.0.69 | MIT OR Apache-2.0 | workspace |
| tokio | 1.53.1 | MIT | workspace |
| rusqlite | 0.32.1 | MIT | workspace |
| base64 | 0.21.7 | MIT OR Apache-2.0 | workspace |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | workspace |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | workspace |
| async-trait | 0.1.92 | MIT OR Apache-2.0 | workspace |
| tracing | 0.1.44 | MIT | workspace |
| bytes | 1.12.1 | MIT | workspace |
| time | 0.3.55 | MIT OR Apache-2.0 | workspace |
| mail-parser | 0.11.9 | Apache-2.0 OR MIT | workspace |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | workspace |
| tauri | 2.11.5 | Apache-2.0 OR MIT | `kiwi-app/src-tauri` |
| tauri-build | 2.6.3 | Apache-2.0 OR MIT | `kiwi-app/src-tauri` (build) |
| x509-parser | 0.17.0 | MIT OR Apache-2.0 | `kiwi-app/src-tauri` |
| keyring | 3.6.3 | MIT OR Apache-2.0 | `kiwi-app/src-tauri` |
| ed25519-dalek | 2.2.0 | BSD-3-Clause | `kiwi-app/src-tauri`, `kiwi-pair` |
| ammonia | 4.2.0 | MIT OR Apache-2.0 | `kiwi-app/src-tauri` |
| tokio-rustls | 0.26.5 | MIT OR Apache-2.0 | `kiwi-mail` |
| rustls | 0.23.45 | Apache-2.0 OR ISC OR MIT | `kiwi-mail` |
| webpki-roots | 0.26.11 | **CDLA-Permissive-2.0** | `kiwi-mail` |
| md5 | 0.8.1 | Apache-2.0 OR MIT | `kiwi-mail` (APOP only, T-104) |
| rsa | 0.9.10 | MIT OR Apache-2.0 | `kiwi-mailauth` |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | `kiwi-mailauth` |
| hickory-resolver | 0.26.3 | MIT OR Apache-2.0 | `kiwi-mailauth` |
| rcgen | 0.13.2 | MIT OR Apache-2.0 | `kiwi-mail` (dev) |
| tokio-test | 0.4.5 | MIT | `kiwi-mail` (dev) |
| ed25519-dalek (v3 line) | 3.0.0 | BSD-3-Clause | `kiwi-mailauth` |

Transitive platform crates reached through `tauri` (Linux path; not compiled
on this Windows target — matches the existing `glib` note in `SECURITY.md`
§7): `tao-0.35.3` Apache-2.0, `wry-0.55.1` Apache-2.0 OR MIT,
`tauri-runtime-wry-2.11.4` Apache-2.0 OR MIT, `gtk-0.18.2` MIT, `gtk-sys` MIT,
`webkit2gtk-2.0.2` MIT.

### 3.2 npm — per `package.json`

| Package | kiwi-app | kiwi-admin | kiwi-admin-ui | mobile | License |
|---|---|---|---|---|---|
| react | 18.3.1 | — | 18.3.1 | 18.3.1 | MIT |
| react-dom | 18.3.1 | — | 18.3.1 | — | MIT |
| @tauri-apps/api | 2.11.1 | — | — | — | Apache-2.0 OR MIT |
| @tauri-apps/cli (dev) | 2.11.4 | — | — | — | Apache-2.0 OR MIT |
| better-sqlite3 | — | 12.4.1 | — | — | MIT |
| drizzle-orm | — | 0.45.2 | — | — | Apache-2.0 |
| pg | — | 8.16.3 | — | — | MIT |
| react-native | — | — | — | 0.76.5 | MIT (Meta Platforms, Inc.) |
| typescript (dev) | 5.6.3 | 5.7.3 | 5.6.3 | 5.7.3 | Apache-2.0 |
| vite (dev) | 6.4.3 | — | 6.4.3 | — | MIT |
| @vitejs/plugin-react (dev) | 4.7.0 | — | 4.7.0 | — | MIT |
| @types/* (dev) | MIT | MIT | MIT | MIT | MIT |
| drizzle-kit, vitest, eslint (dev) | — | MIT | — | MIT | MIT |
| @react-native/{babel-preset,eslint-config,metro-config} (dev) | — | — | — | 0.76.5 | MIT |

### 3.3 Copyleft verdict for SHIPPED dependencies

> **No GPL, AGPL, SSPL, CDDL, EUPL, or MPL dependency is present in any
> shipped (runtime) dependency set, in any of the 4 npm packages or the 9
> Cargo workspace members.**

- Full transitive npm scan of all four `node_modules` trees for
  `GPL|AGPL|SSPL|CDDL|EUPL|MPL` in each `package.json` `license` field →
  **no matches in any workspace.**
- Rust: all top-level crates are MIT / Apache-2.0 / ISC / BSD-3-Clause.
- One item to note, **not a blocker**: `webpki-roots 0.26.11` is
  **CDLA-Permissive-2.0** (Community Data License Agreement). CDLA-Permissive
  is a *file-level* copyleft, i.e. materially weaker than AGPL and broadly
  compatible with Apache-2.0/MPL-2.0 distribution as a separate unmodified
  file. Mozilla ships it in every Firefox. → informational (F4).
- Note on GPL adjacency: `rustls` was chosen over `native-tls`/OpenSSL, and the
  `webkit2gtk`/`gtk` Linux path is LGPL via system libraries — dynamic linking
  only, and not compiled on the Windows-first target. No action.

---

## 4. Findings

| # | Severity | Finding | Evidence | Recommendation |
|---|---|---|---|---|
| **F1** | Medium | `docs/SECURITY.md` rule 6 and §6 claim a **"gitleaks gate"**, but gitleaks is not installed on any host and CI only runs the Python fallback. The stricter scanner is documented-but-inert; the fallback's pattern set is narrower than gitleaks' default rules. | `Get-Command gitleaks` → empty; `.github/workflows/ci.yml:81` runs only `python tests/tools/secret_scan.py`; `tests/tools/gitleaks.toml:1-5` says "Canonical usage once gitleaks is installed" | Install gitleaks in CI and run both, or amend `SECURITY.md` to state that `secret_scan.py` **is** the gate. Do not leave the doc claiming a gate that does not run. |
| **F2** | Low | Untracked `auth-test-out.txt`, `watcher_stdout.log`, `watcher_stderr.log`, `nul` are **not** covered by `.gitignore`. A `git add -A` would stage build logs / a stray NUL device artifact. | `git status --porcelain`; `.gitignore` has no `*.log` or `nul` rule | Add `*.log` and `nul` (or `auth-test-out*.txt`) to `.gitignore`. Tracked files are unaffected today. |
| **F3** | Medium | **No `LICENSE` file exists anywhere in the repo** (`git ls-files` finds zero `LICENSE`/`COPYING`/`NOTICE`), yet `Cargo.toml:17` declares `license = "MPL-2.0"` and `README.md:17,133` advertise MPL-2.0. Declaring a license without shipping its text is an incomplete-compliance defect. | `git ls-files \| Select-String '(?i)(^|/)(LICENSE\|COPYING\|NOTICE)'` → empty | Add the MPL-2.0 `LICENSE` text at repo root (standard practice; MPL-2.0 §3.1 distribution requirement). |
| **F4** | Info | `webpki-roots 0.26.11` is **CDLA-Permissive-2.0** (file-level copyleft), shipped in `kiwi-mail`. Compatible, but it is the only non-MIT/Apache/ISC/BSD item in the runtime set. | `~/.cargo/registry/src/*/webpki-roots-0.26.11/Cargo.toml` | No change needed. Record here so a future SBOM/notice sweep includes it. |
| **F5** | Low | `kiwi-core/Cargo.toml` omits the `license` field (it also hardcodes `edition = "2024"` instead of `edition.workspace = true`, unlike every sibling crate). Any future crate-level license audit will mis-read it. | `kiwi-core/Cargo.toml:1-9` | Add `license.workspace = true` and `edition.workspace = true`. One-line, zero behaviour change. |
| **F6** | Low | Stale **nested lockfiles** are tracked: `kiwi-core/Cargo.lock` (1 package) and `kiwi-forensics/Cargo.lock` (12 packages) are pre-workspace-member remnants. Cargo ignores them for a workspace build, so they silently drift and misrepresent the dependency set to any auditor or tool. | `git ls-files` → both tracked; root `Cargo.lock` has 562 packages | Delete both nested lockfiles; the root `Cargo.lock` is the single source of truth. |

**F1 and F3** are the two worth routing to the Lead this cycle. F2/F5/F6 are
one-line hygiene. F4 needs no action.

---

## 5. Re-run commands (reproducible, PowerShell, from repo root)

```powershell
# F1 — secret gate
python tests/tools/secret_scan.py                 # expect: scanned=385 hits=0
Get-Command gitleaks -ErrorAction SilentlyContinue # expect: empty (gap)

# Boundary — reference/ containment
git check-ignore -v reference
git ls-files | Select-String 'reference'          # expect: no output
git status --porcelain --ignored=matching -- reference   # expect: !! reference/
git grep -n -I -i -E 'nylas|foundry376|mailspring, inc|spaceduck|persona-id' -- . ':(exclude)reference/*'
git grep -n -I -i -E 'copyright|SPDX-License-Identifier' -- 'kiwi-app/src/*' 'kiwi-admin/src/*' 'kiwi-admin-ui/src/*' 'mobile/src/*'

# Boundary — verbatim overlap (build ref line-set, then scan our tree)
# step 1: 52,024 distinct ref lines >=45 chars -> %TEMP%\kiwi-ref-lines.txt
# step 2: scan our 204 source files -> expect 62 boilerplate-only hits

# F3 — missing license text
git ls-files | Select-String '(?i)(^|/)(LICENSE|COPYING|NOTICE)'

# Dep licenses (exact locked versions)
Select-String -Path Cargo.lock -Pattern '^name = "'
Get-Content <pkg>\node_modules\<dep>\package.json | ConvertFrom-Json | Select-Object license
```

## 6. Scope limits / assumptions

- Crate licenses were read from the **local cargo registry cache** at the exact
  locked version. `cargo license` is not installed; where a crate was absent
  from the cache the row would have read `<cache-miss>` — **no row did**, so
  every Rust license above is a read value, not a recollection.
- npm licenses were read from **installed** `node_modules`, not from
  `package-lock.json` (which carries no license field). `mobile/` still has
  **no `package-lock.json`** (already open in `SECURITY.md` §7), so mobile's
  license inventory is a point-in-time read of an unpinned tree.
- The overlap scan compares **individual lines ≥45 chars**. It cannot detect
  paraphrase, or a copy rewritten with renamed identifiers. The marker greps
  and the absence of any copyright/SPDX header in our source are the
  complementary evidence for that case.
- Secret scanning is pattern-based; it cannot prove the absence of an
  *unrecognised* credential format. It is a gate, not a proof.
- `source/` (Thunderbird symlink) was treated as out of scope beyond the
  gitignore verification, per the task's "excluding `reference/`" instruction.
