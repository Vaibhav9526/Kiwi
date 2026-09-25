# Agent 21 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-197 license-compliance + secret scan delivered

**Status:** COMPLETE. Audit written to
`docs/audits/license-secret-scan-1.md`. Verdict **PASS** — GPL/AGPL boundary
intact, no committed secret, no copyleft dependency in any shipped set — with
6 non-blocking findings (F1–F6). **Read-only task:** no tracked file was
modified; the only writes are this log and the audit report.

**Files created (2):**
- `docs/audits/license-secret-scan-1.md` — the audit.
- `docs/agents/agent-21-status.md` — this entry.

**Files changed:** none. **Tests run:** none (read-only audit; the only
executable gate I invoked is the secret scanner).

**What was verified (evidence, not inference):**

1. **Reference licenses confirmed on disk** — `reference/mailspring/LICENSE.md`
   = GPL-3.0, `reference/mailflow/LICENSE` = AGPL-3.0, plus
   `LICENSE-COMMERCIAL`. Both strong copyleft; MPL-2.0 KIWI cannot absorb them.
2. **`reference/` containment holds** — `.gitignore:38` `reference/`;
   `git check-ignore -v` confirms for the dir and for files inside both
   subtrees; `git ls-files | Select-String reference` → **zero** tracked files;
   `git status --ignored=matching` → `!! reference/`. `source/` is likewise a
   gitignored symlink (`.gitignore:2`).
3. **No Mailspring/MailFlow code in our tree** — three independent methods, all
   negative:
   - marker grep (`nylas|foundry376|mailspring, inc|spaceduck|persona-id`)
     over all source dirs → **0 hits**. The `mailspring`/`mailflow` hits that
     do exist are docs prose and our own unrelated `mailflow` audit feature.
   - copyright/SPDX header grep over all four JS/TS source trees → **0 hits**,
     so no Mailspring GPL header or Nylas MIT header is present.
   - **verbatim overlap scan**: 1,081 reference source files → 52,024 distinct
     trimmed lines ≥45 chars, cross-checked against all **204** of our source
     files → **62 shared lines in 23 files, every one manually inspected and
     all boilerplate** (comment rulers, `useState` idioms, an eslint pragma,
     one `25*1024*1024` constant, and 3 Thunderbird-spec autoconfig XML tags).
     **Longest contiguous shared run: 0 lines.** No block, function, or file
     was copied.
4. **Secret scan clean** — `python tests/tools/secret_scan.py` →
   `scanned=385 hits=0` (this is the actual CI gate, `ci.yml:81`).
   Independent grep for `AKIA/ghp_/gho_/github_pat_/xox*/sk-/AIza/ya29/
   BEGIN…PRIVATE KEY` → **0 hits**. Credential-shaped assignments → only Rust
   *type declarations* (`password: Zeroizing<String>`) and obvious test dummies
   (`"demo"`, `"p"`, `"wrong"`, `"dummy"`), all inside `#[cfg(test)]`/`tests/`
   and excluded per scope. `.env` is gitignored (`.gitignore:27`); only
   `.env.example` is tracked and it carries self-labelled
   `kiwi-dev-only-…-change-me` placeholders, exactly per `SECURITY.md` rule 15.
5. **Dependency licenses inventoried, zero copyleft shipped** — every top-level
   dep of all 9 Cargo workspace members and all 4 npm packages, resolved at the
   **exact locked version** and read from the authoritative `license` field
   (`~/.cargo/registry/src/*/<crate>/Cargo.toml`, `node_modules/*/package.json`)
   rather than recalled. All Rust: MIT / Apache-2.0 / ISC / BSD-3-Clause
   (+ `webpki-roots` CDLA-Permissive-2.0, file-level, compatible). All npm:
   MIT / Apache-2.0. A full transitive `node_modules` scan of all 4 workspaces
   for `GPL|AGPL|SSPL|CDDL|EUPL|MPL` → **no matches anywhere**.

**Findings routed to Lead (detail + evidence in the audit §4):**
- **F1 (Medium)** — `SECURITY.md` rule 6 advertises a "gitleaks gate", but
  gitleaks is not installed and CI runs only the narrower Python fallback.
  Doc/gate mismatch. Needs either CI install or a doc correction.
- **F3 (Medium)** — **no `LICENSE` file exists in the repo** even though
  `Cargo.toml:17` declares MPL-2.0 and the README badge advertises it.
  Incomplete licence compliance.
- F2 (Low) — `*.log` / `nul` / `auth-test-out.txt` are untracked but not
  gitignored → `git add -A` would stage noise.
- F5 (Low) — `kiwi-core/Cargo.toml` is the only crate missing `license.workspace`.
- F6 (Low) — stale nested `kiwi-core/Cargo.lock` (1 pkg) and
  `kiwi-forensics/Cargo.lock` (12 pkgs) are tracked alongside the real
  562-package root lock; they drift and mislead auditors.
- F4 (Info) — `webpki-roots` CDLA-Permissive-2.0, for the future notice sweep.

**Recommendation to Lead (not actioned — read-only task):** make the ≥45-char
overlap scan in audit §5 a **merge gate on T-190/T-191** ("Mailspring
archaeology" / "Mailspring-faithful rebuild", `TASKS.md:119-121`). Those are
the tasks where a copying failure becomes likely; T-190's deliverable should be
a written spec/token inventory only, with no transliterated source and no
Mailspring identifiers.

**Assumptions / limits (also in audit §6):** `cargo license` is not installed,
so crates were read from the local registry cache at exact locked versions
(no `<cache-miss>` occurred). `mobile/` still has no `package-lock.json`, so
its license inventory is a point-in-time read of an unpinned tree. The overlap
scan matches individual lines ≥45 chars and cannot detect paraphrase or
renamed-identifier copies — the marker greps and header absence are the
complementary evidence. Secret scanning is pattern-based; it is a gate, not a
proof of absence. `source/` was out of scope beyond its gitignore check.

**Commands of note:** `git check-ignore`/`ls-files`/`status --ignored` for
containment; `git grep` for markers/headers/secrets; a two-stage PowerShell
HashSet line-overlap scan (ref line-set cached to `%TEMP%\kiwi-ref-lines.txt`,
outside the repo); regex over `Cargo.lock` joined to the registry cache for
exact-version licenses; recursive `ConvertFrom-Json` walk of all 4
`node_modules` for the copyleft sweep. No repo file was written by any of them.
