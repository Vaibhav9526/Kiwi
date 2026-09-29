# Lock-gate coverage audit — kiwi-app IPC surface (T-340)

**Date:** 2026-09-25 · **Agent:** 21 · **Scope:** every command registered in
`kiwi-app/src-tauri/src/lib.rs`'s `tauri::generate_handler![…]` list.

## Question

The lock gate (`commands::mod.rs::gate`) refuses every non-exempt command while
the endpoint trust state is `Locked`. T-120 built it; T-269 made the pairing
exemption flow-scoped via `pair_gate`. But nothing ever verified that the
**whole registered surface** was covered. "Is every command gated?" was answered
by reading the hand-written group comments above each block in `lib.rs` and
trusting that whoever added the next command put it under the right header.

This audit enumerates all registered commands and classifies each one.

## Method

1. Parse the real `invoke_handler(tauri::generate_handler![…])` list from
   `lib.rs` (comments stripped) — **106 commands**.
2. Resolve each command's body by brace matching across the whole `src/` tree,
   following one level of `*_impl` delegation for thin command wrappers.
3. Classify: **gated** (`gate()` / `pair_gate()`), **exempt** (documented), or
   **ungated-by-omission** (neither).
4. Separately: confirm the gate runs *before* the command does any work
   (presence of a `gate()` call says nothing about ordering).

Steps 1–4 are now **automated** as `commands::lock_matrix.rs` (see Fix 1), not
a one-time reading.

## Result

| class | count | share |
|---|---:|---:|
| (a) gated via `gate()` | 95 | 89.6% |
| (a) gated via §9d.7 flow-scoped `pair_gate()` | 2 | 1.9% |
| (b) explicitly exempt, documented | 9 | 8.5% |
| **(c) ungated-by-omission** | **0** | **0%** |
| **total registered** | **106** | 100% |

**There are no (c) hits.** Every command reachable while locked is either gated
or carries a written exemption.

### The nine exemptions

| command | why it is safe while locked |
|---|---|
| `kiwi_ping` | static string; reads no state |
| `kiwi_app_info` | version / contract / `deviceId` / org / `accountCount` metadata. No mailbox data, credential, or body. |
| `kiwi_security_status` | **is** the lock-state surface the overlay renders from. Trust state + signal kind/severity/penalty + `evidenceRef` pointers — never signal payloads. |

## Findings

| id | sev | finding | disposition |
|---|---|---|---|
| LG-1 | **Med** | **The lock matrix was maintained by comment, not by code.** The only record of which commands are exempt was prose in `lib.rs` group headers and per-function doc comments. A new command added under the wrong header would be indistinguishable from a gated one, and no test would fail. Zero (c) hits today is a *fact about today*, not a *guarantee about tomorrow*. | **Fixed** — `commands/lock_matrix.rs` (Fix 1). |
| LG-2 | **Info** | `kiwi_collect_endpoint_signals` is exempt, mutates trust state (`refresh_trust`), persists evidence, and writes an audit row. I checked the obvious attack — *call it repeatedly to launder a lock away* — and it does not work: `TrustMachine::evaluate` is sticky for `Locked` on every path (`trust.rs:145-157`), and only `attempt_unlock` (reached solely through a verified challenge) can leave it. **Verified, not assumed.** | No change; reason recorded in `LOCK_EXEMPT`. |
| LG-3 | **Info** | `kiwi_app_info` exposes `org.baseUrl` and `accountCount` while locked. The exemption comment claims "no mailbox data" — true, but it is metadata, not nothing. Gating it would break the settings/pairing surface on a locked endpoint, and the values are already held by the same user's own renderer. | No change; the honest *scope* of the exemption is now written down rather than implied. |
| LG-4 | **Info** | `kiwi_audit_integrity` (T-331, mine) was documented in §8 but **missing from the `ipc.md` §2 exempt list** — a new exempt command that nobody added to the one place exemptions are collected. That is the omission mode in miniature, and it is why the §2 list is now checked against the code. | **Fixed** (Fix 3). |
| LG-5 | — | Every gated command runs its gate as the first statement; no command does store or network work before refusing. | Verified by test (Fix 1, 4th test). |

### Not a finding, but worth stating

`kiwi_prefs_get/set/list` are **fully gated**. The task brief speculated about a
"prefs subset" exemption — no such subset exists. Prefs are renderer-owned
settings, not credentials (the module header says so; credentials live in the
OS store), but they are gated like everything else, which is the stricter and
correct choice.

### A finding I had to retract

I first wrote LG-4 as "the `ipc.md` exempt list is stale — it lists 6, the code
has 9". That was **wrong**: re-reading `ipc.md:60-64` before filing, the §2 list
already names `unlock_challenge` and the `pair_begin`/`pair_status` flow
exemption. The only genuinely missing entry was my own T-331 command. Filing the
wrong version would have "fixed" correct documentation and buried the real,
smaller gap — so the audit doc records the correction rather than quietly
dropping it.

## Fixes applied

**Fix 1 (LG-1) — the matrix is now an enforced invariant.**
`kiwi-app/src-tauri/src/commands/lock_matrix.rs`, a `#[cfg(test)]` module with
four tests:

- `every_registered_command_is_gated_or_explicitly_exempt` — parses the real
  `invoke_handler!` list, resolves each body, and fails listing every command
  that is neither gated nor on `LOCK_EXEMPT`.
- `the_exempt_list_has_no_dead_entries` — an exemption for a renamed or deleted
  command is a stale claim about the security surface: it keeps the default
  "gated" for the renamed command while reviewers read the list as covering it.
- `every_exemption_documents_a_reason` — an undocumented exemption is
  indistinguishable from an omission, so each row needs a real reason.
- `the_gate_runs_before_the_command_does_any_work` — a gate that runs after the
  work is a gate that does not gate. Nothing may execute before the gate.

The design point: **the default is "gated"**, and `LOCK_EXEMPT` is the only way
to skip it, so an exemption is a deliberate, reviewable act — the T-269 pattern
generalised from two commands to the whole surface.

**Fix 2 — `clippy::doc_lazy_continuation` in `kiwi-mail/src/store/diagnostics.rs`.**
A multi-line doc bullet had a lazy continuation that failed the workspace
`-D warnings` gate. Reflowed the bullet; no content change. (That file is
A15's T-330; the lint was theirs, the fix mechanical and scoped to the doc text.)

**Fix 3 (LG-4) — `ipc.md` exempt set reconciled with the code** (9 exemptions,
§9d.7 cited).

## Why this matters beyond the current count

The valuable output is not "0 findings" — it is that the answer is now
**reproducible**. The next person to add a command gets a failing test unless
they gate it or write down why not. That converts lock-gate coverage from a
review-time habit into a build-time invariant, which is the only way a security
property survives a codebase this fast-moving.

| `kiwi_lock` | locking must stay available; while locked it is an idempotent re-lock that only reduces access |
| `kiwi_request_challenge` | step 1 of the unlock flow |
| `kiwi_submit_challenge` | step 2 of the unlock flow |
| `unlock_challenge` | §9d.7 — the canonical unlock path itself; gating it is a DoS |
| `pair_begin` / `pair_status` | §9d.7 / T-269 — **not** unconditional: `pair_gate` admits them only while a backend-owned unexpired flow is live, and `pair_status` only for that flow's own ticket |
| `kiwi_collect_endpoint_signals` | feeds trust evidence. `Locked` is sticky in `TrustMachine::evaluate` (`kiwi-core/src/trust.rs:145-157`), so this can never clear a lock. |
| `kiwi_audit_integrity` | T-331. Verdict only (`ok`/`corrupt`/`unknown` + boolean): no rows, counts, paths, or hashes. The row reader `kiwi_audit_events` stays gated. |
