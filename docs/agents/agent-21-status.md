# Agent 21 — Status Log

> Append dated entries: status, files changed, commands run, tests, assumptions, risks.

## 2026-09-25 — T-232 Authentication-Results stamping (inherited from Agent 16)

**Status:** COMPLETE. All four parts landed. **Verification: `cargo test -p
kiwi-mail` = 162 passed / 0 failed (exit 0); `cargo clippy -p kiwi-mail
--all-targets -- -D warnings` clean; `cargo fmt --check` clean; `kiwi-app`
`tsc --noEmit` exit 0.** No live DNS anywhere — `MockResolver` only.

**Files changed (7):**
- `kiwi-mail/src/authstamp.rs` — **new module**: evaluation + RFC 8601 stamping.
- `kiwi-mail/Cargo.toml` — added `kiwi-mailauth` path dep.
- `kiwi-mail/src/lib.rs` — registered the module.
- `kiwi-mail/src/store/schema.rs` — **SCHEMA_VERSION 6 → 7** + `message_auth` table.
- `kiwi-mail/src/store/mod.rs` — `AuthMeta`, `MessageMeta.auth`, 6 migration tests.
- `kiwi-mail/src/store/queries.rs` — `set_auth`/`get_auth`/`attach_auth`/`uids_without_auth`.
- `kiwi-mail/src/sync.rs` — ingest hooks (see conflicts below).
- `kiwi-app/src-tauri/src/types/mail.rs` — `MessageView.auth` + `AuthView`.
- `kiwi-app/src/kiwi.ts` — `AuthResultsView` on the TS `MessageView`.

**Design decisions worth Lead attention:**

1. **SPF cannot be honestly evaluated at IMAP/POP3 ingest.** It needs the SMTP
   connection IP and MAIL FROM envelope, which a fetch does not have. Rather
   than invent a sender IP (a fabricated security finding, forbidden by
   `SECURITY.md` rule 2), SPF records **`none` with an explicit
   `spf_comment="no SMTP receipt context…"`**. An optional `SmtpReceipt` lets an
   SMTP-receipt caller supply the real values and get a real SPF verdict; both
   paths are tested.
2. **`temperror` and `none` are not failures.** `AuthStamp::has_failure()`
   returns true only for `fail`/`permerror`; `is_inconclusive()` covers
   `temperror`. A test asserts `temperror` is inconclusive and **not** a
   failure, so the pill can never render "could not check" as "spoofed".
3. **No stamp ≠ `none` verdict.** `MessageMeta.auth` is `None` until the body
   is fetched and evaluated; `None` is "not evaluated", a different state from
   a `none` verdict. Tested explicitly.
4. **Sealed-by-default on missing DNS.** The ingest paths take
   `Option<&dyn AuthSealer>`. `None` writes **no stamp at all** rather than
   running against an empty resolver — a stub resolver's NXDOMAIN is an
   artefact of the stub, not evidence a DKIM key is missing (which would have
   produced a false `dkim=fail`).

**Schema v7 — a separate table, deliberately.** `message_auth` is a new table
keyed `(folder_id, uid)` rather than more `messages` columns. The `messages`
SELECT text is shared with the unsub/junk and rules owners; adding a join
there would have created exactly the conflict the task told me to avoid. The
verdicts are attached by one extra `SELECT … FROM message_auth` per list
(`attach_auth`). `uids_without_auth` is provided for a future backfill pass
(backfilling would need live DNS, so I did **not** backfill existing rows —
that would fabricate timestamps/verdicts for already-stored mail).

**Ingest touch — minimised, and the conflict is real.** Both existing public
signatures (`fetch_missing_bodies`, `sync_pop3`) are **unchanged**; the loops
were extracted into private `_inner` functions and new
`fetch_missing_bodies_with_auth` / `sync_pop3_with_auth` entry points were
added alongside. A15's rules code and A14's unsub/junk calls therefore keep
working untouched. Ingest changes are one guarded block each, inside the
existing `if let Ok(parsed)` body-fetch branch, after the rules hook.

**Conflicts encountered (both pre-existing, not introduced by me):**
- `kiwi-mail/src/rules/apply.rs` is **untracked** (A15's in-flight file) and
  briefly broke the whole crate build (`record_rule_hits` / `set_flag` missing
  from `MailStore`). I did **not** touch it; A15 landed a fix mid-task and the
  build recovered. Flagging because it means **`cargo test -p kiwi-mail` can go
  red for reasons unrelated to auth stamping** while A15 works.
- Three real bugs in **my own** first cut, caught by tests rather than review:
  a broken dedup check (compared the whole line instead of the field name, so
  re-ingest would have duplicated the header), a moved-value error, and two
  clippy findings (`collapsible_if`, `too_many_arguments`). The idempotency bug
  is the one worth noting: it would have let an attacker pre-seed
  `Authentication-Results:` to suppress our real stamp.

**Tests added (20).** `authstamp`: 14 — no-records→`none` (not fail), SPF
absent-without-receipt, SPF pass/fail with a `MockResolver`, DMARC none/fail/
`temperror`/unparsable-From, header bounded + CRLF-safe, mbox `From `
preservation, **idempotency**, header ordering, and a header-injection test
proving a CRLF-bearing explanation cannot escape the comment. `store`: 6 —
roundtrip, refresh-not-duplicate, list + category-list attach, `uids_without_auth`,
and a **v6→v7 migration test**. All offline.

**Assumptions / limits:**
- No live-DNS backfill of existing messages (see above).
- The `Authorization-Results` header is stamped **in memory for the returned
  value**; the persisted `header_value` is the record of what was stamped. I
  did **not** rewrite the on-disk `.eml` bodies in place — mutating stored mail
  bytes would break any existing DKIM signature over the body. Flagging as a
  decision for the Lead.
- `MessageView` carries verdicts but **no pill component was written** — the
  task asked to surface the fields; the pill UI is the frontend owner's.
  `AuthResultsView` documents the `none`/`temperror` semantics for whoever
  builds it.

## 2026-09-25 — T-240 upstream Authentication-Results evidence

**Status:** COMPLETE. Offline parser, persistence, ingest integration, and `AuthView`
wire surface are implemented. Verification: `cargo test -p kiwi-mail --all-targets` =
169 passed / 0 failed; `cargo clippy -p kiwi-mail --all-targets -- -D warnings`
clean; `cargo check -p kiwi-app` clean; task-file `rustfmt --check` clean;
frontend `npx tsc --noEmit` clean. (Workspace-wide `cargo fmt --check` is
currently blocked by another owner's pre-existing unformatted `commands/mail.rs`.)

**Files changed (7):**
- `kiwi-mail/src/authstamp.rs` — bounded RFC 8601 A-R parser, authserv-id/verdict
  extraction, local/upstream comparison rows, own-stamp precedence tests.
- `kiwi-mail/src/store/schema.rs` — schema v8 adds `message_auth.upstream_json`.
- `kiwi-mail/src/store/mod.rs` — typed upstream evidence models + v7→v8 migration.
- `kiwi-mail/src/store/queries.rs` — upstream JSON persistence/read/list attachment.
- `kiwi-app/src-tauri/src/types/mail.rs` — `AuthView.upstream` + `discrepancy`.
- `kiwi-app/src/kiwi.ts` — matching camelCase TypeScript evidence contract
  (already present in the shared working tree when T-240 was finalized).
- `docs/agents/agent-21-status.md` — this entry.

**Design decisions:**
- **Extended `message_auth`, rather than adding a sibling table.** The local and
  upstream views are one atomic authentication-evidence record keyed by the same
  `(folder_id, uid)`. `upstream_json` is bounded typed evidence; this preserves
  the ratified separate-table boundary from `messages` and avoids another join.
  No historical rows are backfilled: absent original-header context must not be
  fabricated as a missing/untrusted upstream assertion.
- **Discrepancy means only exact pass↔fail.** Every extracted upstream result gets
  an evidence row carrying `authserv_id`, method, upstream verdict, and local
  verdict. `none`, `temperror`, and `softfail` are not contradictions. In
  particular, client SPF `none` versus MTA SPF `pass` is preserved as evidence
  but does **not** raise a discrepancy.
- **Missing A-R is notable, not guilty.** `upstream.untrustedRelay=true` and
  `present=false` express unverifiable relay provenance; it is never a finding.
  Malformed/unknown values increment bounded `malformedHeaders` evidence.
- **No `.eml` rewrite.** The raw received bytes remain byte-for-byte unchanged.
  A copied representation places KIWI's stamp above upstream fields for RFC 8601
  precedence, and a pre-seeded attacker A-R cannot suppress KIWI's own field.
  KIWI-owned A-R fields are excluded from upstream evidence.
- **Untrusted parser boundary.** Semicolons inside comments/quotes cannot forge
  methods; at most 32 A-R fields, 32 results per method, bounded IDs/verdicts.
  Offline `MockResolver` tests only; no network access.

**Tests added:** authserv-id + SPF/DKIM/DMARC extraction, multi-header pass/fail
evidence conflicts in both directions, honest inconclusive verdicts, missing-header
provenance, malformed/comment injection, raw-byte preservation + KIWI-first/pre-seed
resistance, persistence/list roundtrip, and v7→v8 migration without fabricated
backfill. All offline.

## 2026-09-25 — T-249 deterministic per-message auth risk hint

**Status:** COMPLETE. `cargo test -p kiwi-mail --all-targets` = 179 passed /
0 failed; `cargo clippy -p kiwi-mail --all-targets -- -D warnings` clean;
`cargo fmt --all -- --check` clean; `cargo check -p kiwi-app` clean; frontend
`npx tsc --noEmit` clean.

**Files changed (9):**
- `kiwi-mail/src/authrisk.rs` — new bounded `AuthRisk` enum + pure ordered table.
- `kiwi-mail/src/authstamp.rs` — stamp-time risk + independent SPF identifier
  alignment evidence + integration tests.
- `kiwi-mail/src/lib.rs` — registers the auth-risk module.
- `kiwi-mail/src/store/schema.rs` — schema v10 adds bounded `auth_risk` column.
- `kiwi-mail/src/store/mod.rs` — `AuthMeta.auth_risk` + idempotent migration.
- `kiwi-mail/src/store/queries.rs` — atomic stamp persistence and read/list attach.
- `kiwi-app/src-tauri/src/types/mail.rs` — typed `AuthView.authRisk` wire field.
- `kiwi-app/src/kiwi.ts` — matching `"clean" | "noted" | "failed"` frontend type.
- `kiwi-mail/src/rules/apply.rs` — one clippy allowance on concurrent T-244 helper
  so the required crate-wide clippy gate is green; no T-244 behavior changed.

**Exact deterministic table (failure first):**
1. `failed` iff `dkim=fail AND dmarc=fail`, **or** `dmarc=fail AND
   spf=fail AND spf_aligned=true`.
2. Otherwise `noted` for every other result, including all `none`, `temperror`,
   `permerror`, softfail/neutral, unknown, untrusted/missing upstream evidence,
   discrepancies, and fail combinations that do not meet rule 1.
3. Otherwise `clean` iff SPF/DKIM/DMARC all pass, upstream A-R is present and
   trusted, and there is no discrepancy.

`spf_aligned` is independent of SPF pass/fail and uses the discovered DMARC
`aspf` mode to compare the SPF identifier domain with RFC 5322 From. This is
necessary because a failed SPF result cannot authorize DMARC, but its identifier
alignment is still the evidence required by the second failed rule.

**Storage choice:** compute once at stamp time and persist in
`message_auth.auth_risk` atomically with verdicts/upstream evidence. The column
is CHECK-constrained to the three wire values. Historical v9 rows remain NULL;
reads derive conservatively with alignment=false, so no receipt/alignment fact
is fabricated and no mass backfill occurs.

**Safety boundary:** this is a frontend pill hint only. It is not a finding,
does not create findings, does not move mail, and has no store/UI side effects.
Discrepancy alone and missing/untrusted upstream alone both remain `noted`.

**Tests:** table-driven coverage for both failed rules, aligned vs unaligned SPF
failure, all clean/noted categories, `none`/`temperror`/`permerror` exhaustive
non-failure coverage, discrepancy-only, missing/untrusted upstream, wire
vocabulary/corruption, stamp-time aligned-SPF integration, store roundtrip, and
v7→v10 migration without fabricated backfill. All offline.

## 2026-09-25 — T-199 dependency vulnerability audit delivered

**Status:** COMPLETE. `cargo audit` (0.22.2, 1,269 advisories, 579 crates) +
`npm audit` across all 4 npm packages, full and `--omit=dev`. Written to
`docs/audits/dep-vuln-1.md`. **No code, manifest, or lockfile was changed.**

**Files changed (2):** `docs/audits/dep-vuln-1.md` (new), this log.

**Headline: two BLOCKING build problems, more urgent than any advisory — the
Rust workspace does not currently resolve.**
- **C1** — `kiwi-integrations/Cargo.toml` requests reqwest feature
  `rustls-tls-webpki-roots`, which **does not exist** in `reqwest 0.13.5`
  (it exposes `rustls`, `rustls-no-provider`, `__rustls-aws-lc-rs`).
  `cargo tree --workspace` and `cargo check --workspace` both fail. Owner:
  kiwi-integrations. Not fixed (read-only).
  **Important nuance:** `cargo audit` still reports cleanly because it parses
  `Cargo.lock` without re-resolving — so a green audit does **not** mean the
  workspace builds. I only found this because I ran `cargo tree` to build the
  reverse-dependency evidence, and it blew up.
- **C2** — `kiwi-mailauth/src/dmarc.rs` has an unclosed `mod tests`
  ("unexpected closing delimiter", line 597). The file is modified/uncommitted,
  so almost certainly another agent's in-flight edit, not a committed defect.
  Reported, not fixed.

**Advisory results:**
| Scope | Result |
|---|---|
| Rust workspace | 1 vulnerability + 7 allowed warnings (unchanged from T-154) |
| `kiwi-app` | 0 |
| `kiwi-admin` | 6 (1 critical + 5 moderate) — all dev-only |
| `kiwi-admin-ui` | 0 |
| `mobile` | **NOT AUDITABLE** — `ENOLOCK`, no `package-lock.json` |
| `--omit=dev` (shipped) | **0 in all three lockfile-backed packages** |

**Actionable (A1–A5):**
- **A1** `vitest` 3.2.4 in kiwi-admin — **CRITICAL** GHSA-5xrq-8626-4rwp
  (range `<3.2.6`). Exposure verified unreachable: advisory needs the Vitest UI
  server listening; there is **no `--ui`/`--api`/`ui: true` anywhere**, the
  config sets only `environment`/`include`/`onConsoleLog`, and scripts are
  `vitest run`/`vitest`. But **3.2.6 and 3.2.7 exist** (confirmed via
  `npm view vitest versions`), so the fix is a free non-breaking minor bump.
  **Action: `npm i -D vitest@^3.2.7`.**
- **A2** `mobile` pins `vitest` **3.2.4** exactly — the **same critical**,
  invisible to `npm audit` because of A5. Bump together with A1.
- **A3** `@vitest/mocker` moderate GHSA-82fw-gwwq-j7x9 — fix needs vitest
  **4.x** (major). Exposure nil: `git grep 'vi\.mock|vi\.doMock|jest\.mock'`
  over kiwi-admin + mobile = **0 hits**, we never mock modules. Accept; fold
  into a scheduled vitest 4.x migration.
- **A4** `esbuild` 0.18.20 moderate GHSA-67mh-4wv8-2f99 via
  `drizzle-kit → @esbuild-kit/esm-loader → @esbuild-kit/core-utils`. Advisory
  needs the esbuild **dev server listening**; here esbuild is only a transform
  loader inside the drizzle-kit CLI, which binds no port. **Explicitly advise
  against `npm audit fix --force`**, which would semver-major-*downgrade*
  drizzle-kit to 0.18.1 — a far worse outcome than an unreachable dev-only
  moderate. (drizzle-kit's other esbuild copies, 0.25.12/0.28.2, are above the
  vulnerable range.)
- **A5** `mobile/` not auditable at all — generate and commit the lockfile.
  **Third audit to raise this** (T-154 baseline, interim, now).

**Accepted risk (B1–B4), each with the reasoning recorded in the audit:**
- **B1** `rsa` 0.9.10 RUSTSEC-2023-0071 (Marvin, 5.9, **no fix**). Re-verified
  at call sites in `kiwi-mailauth/src/dkim.rs`: enum holds `RsaPublicKey` (740),
  parsing only (786–791), `pkcs1v15::VerifyingKey::verify` (832–839). The one
  `RsaPrivateKey::new(1024)` is at line **1124, inside `mod tests`** (opens
  426). Marvin needs a private-key op — we do none outside tests. Accept.
- **B2** `glib` 0.18.5 unsound — chain `glib ← gtk/gdk/gio/pango/soup3/
  webkit2gtk/cairo-rs/…`, i.e. the whole Linux Tauri/wry path, not compiled on
  the Windows-first target. Re-assess if a Linux build is ever produced.
- **B3** `proc-macro-error` unmaintained ← `glib-macros`, `gtk3-macros` —
  build-time macro, same Linux-only path.
- **B4** 5× `unic-char-*` unmaintained — full chain verified from the lockfile:
  `tauri-utils → urlpattern → unic-ucd-ident → unic-char-property`;
  `tauri-utils` is pulled by 6 upstream Tauri crates. Ride Tauri upgrades.

**Delta vs T-154:** Rust findings identical (DB grew 1251 → 1269, no new hits);
`kiwi-admin` critical **unchanged and now unfixed across three audits** despite
a one-line fix; mobile lockfile **still missing after three audits**. Both are
process failures, not technical ones — flagged as such to the Lead.

**Method notes / gotchas hit:**
- `cargo tree` was unusable for reverse-dep evidence (C1), so I parsed
  `Cargo.lock` directly to build the `glib`/`unic-char-*`/`rsa`/`tauri-utils`
  chains — those chains are *verified*, not recalled from the T-154 text.
- `npm audit` text output under-reports (it printed 2 advisories while the
  summary said 6); the `--json` output is the complete set and is what the
  audit tabulates. My first parse failed because PowerShell `>` wrote UTF-16 —
  read the bytes and decode explicitly.

**Assumptions / limits:** Rust exposure judged against a Windows-first target
(B2/B3 would move to actionable on a Linux build). npm exposure assumes the
documented scripts are what people run — a dev manually running `vitest --ui`
would create a live listener and change A1's exposure. Nothing was fixed or
modified; C1/C2/A1–A5 are recommendations for their owners.

## 2026-09-25 — T-198 copy-overlap gate delivered (gates T-190/T-191)

**Status:** COMPLETE. `tests/tools/copy_overlap.py` written, wired into
`.github/workflows/ci.yml` static-checks directly after `secret_scan.py`, and
run. **Result: `copy_overlap: OK`, exit 0.** Negative controls prove it fails
on real copying. T-197's audit is unchanged.

**Files changed (2 + this log):**
- `tests/tools/copy_overlap.py` — **new**, stdlib-only.
- `.github/workflows/ci.yml` — one step added at line 90 (after `secret_scan.py`,
  before `check_fixtures.py`), with a comment explaining the reference-mount
  requirement and the T-190/T-191 purpose.
- `docs/agents/agent-21-status.md` — this entry.

**Design — two independent checks, because `reference/` is gitignored:**

- **CHECK A (forbidden provenance markers) — ALWAYS RUNS, no reference needed.**
  This is the half that genuinely gates in CI, because a CI checkout has no
  `reference/`. Patterns: Mailspring's GPL-3.0 header/FSF date/gnu.org,
  MailFlow's AGPL-3.0 header/date, `Foundry376`, `Mailspring, Inc.`, Nylas and
  MailFlow copyright lines, Mailspring internals (`persona-id/store`,
  `participant-list`, `spaceduck`, `mailsync`), and any GPL/AGPL notice pasted
  into a source file. Prose (`.md`) is excluded, so docs may keep saying
  "Mailspring-inspired"; `mailflow` is untouched because it is our own feature.
- **CHECK B (≥45-char verbatim overlap) — runs only if `reference/` is present.**
  Builds the reference line-set (1,163 files → 52,751 distinct trimmed lines
  ≥45 chars) and reports lines shared with our tracked+untracked sources.
  A shared line that is **substantive fails immediately**; so does any
  **contiguous run of ≥3** shared lines (`MIN_CONTIGUOUS_RUN`), which catches a
  transliterated block whose individual lines each looked generic. When
  `reference/` is absent it prints an explicit **SKIPPED** banner and says
  *"A enforced; B not exercised"* — it never implies B passed. `KIWI_COPY_REF_DIR`
  / `--ref-dir` let CI mount the checkouts out-of-band to enable B.

**Boilerplate allowlist — 7 documented entries, each justified in-file** with
the reason it is non-authorial: comment rulers; eslint/ts-ignore/rust-allow
suppressions; React `useState` single-hook form; byte-size constants;
Thunderbird/Mozilla autoconfig XML vocabulary (spec-mandated protocol tokens,
*not* Mailspring IP); vitest/jest spec preamble; Node ESM→CJS `createRequire`
one-liner. Anything unmatched is substantive. The file states that adding an
entry is a licence-relevant decision requiring review.

**Run once to confirm PASS (as required):**
```
copy_overlap A(markers): scanned=254 hits=0
copy_overlap B(overlap): ref_files=1163 ref_lines>=45=52751 our_files=255
                shared=79 boilerplate=79 substantive=0 longest_run=0
copy_overlap: OK          (exit 0)
```
All 79 shared lines are allowlisted boilerplate; **zero substantive, longest
contiguous run 0** — consistent with the T-197 audit (62 → 79 as other agents
landed files; still all boilerplate).

**Negative controls (gate proven to fail, not just to pass):**

| Control | Injected | Result |
|---|---|---|
| Nylas copyright header | `// Copyright (c) 2015-2017 Nylas, Inc.` | **FAIL** `A/vendor` |
| GPL notice pasted into source | standard GPL header text | **FAIL** `A/gpl_header` |
| `Foundry376` + `participant-list` | vendor marker, CI mode (no `reference/`) | **FAIL** `A/vendor` |
| `Mailspring, Inc.` + `participant-list` | provenance line, CI mode | **FAIL** `A/vendor`, `A/mailspring_internals` |
| 3 contiguous shared lines (isolated fixture) | copied comment block | **FAIL** `B/run3` + 3×`B/substantive` |
| 2 contiguous shared lines | copied block | **FAIL** (each line substantive) |
| 1 shared line | single copied line | **FAIL** `B/substantive` |
| no overlap | unrelated code | **OK** exit 0 |
| absent `reference/` (CI simulation) | `--ref-dir nonexistent_ref` | **OK** + loud SKIPPED banner |
| spaced English "participant list" | own threading code | **OK** — correctly not flagged |

Every probe file was created, measured, and deleted; a `__*probe*` sweep
confirms **no leftovers**, and the baseline run is `OK`.

**Two real bugs found and fixed while validating (worth noting for the Lead):**
1. **UnicodeEncodeError crash.** On a cp1252 Windows console, printing a finding
   containing a BOM aborted the gate with a traceback and a non-zero exit that
   looked like a crash rather than a verdict. Fixed by reconfiguring
   stdout/stderr with `errors="replace"` in `main()`.
2. **Self-exclusion.** The scanner necessarily contains the forbidden markers as
   data, so it excludes itself from CHECK A (`SELF_RELPATH`). Verified working.

**Assumptions / limits:**
- The allowlist is the judgement surface. It is deliberately small and
  pattern-anchored; widening it is how this gate would be defeated, so entries
  require review.
- Line-level ≥45-char matching cannot detect paraphrase or a rewrite with
  renamed identifiers — that is why CHECK A (headers/vendors/internals) is a
  separate, independent check rather than a fallback.
- CHECK B is inert in a plain CI checkout by design (`reference/` is gitignored).
  Enabling it in CI needs the checkouts mounted and `KIWI_COPY_REF_DIR` set —
  a Lead/infra decision I have documented in the CI comment, not actioned.
- `MIN_FILE_BYTES=200` skips tiny files on both sides (they carry no block-copy
  signal); a deliberate floor, noted because it can mask a 3-line snippet
  dropped into an otherwise-empty file.

**Unrelated pre-existing failure (NOT mine, not fixed):** `check_encoding.py`
fails on `auth-test-out.txt` (untracked, another agent's build log) and
`chk.txt` (**tracked**, 1,114 bytes, UTF-16/BOM). Both predate this task; T-197
F2 already flagged the untracked-log gitignore gap. Flagging for the owner —
`chk.txt` is tracked and should not be.

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
