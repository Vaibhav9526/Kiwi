# KIWI — Quality Gate Checklist

> Owner: Agent 6. Operationalizes prompt.md §14. A task moves to `done`
> only when every applicable box is checked with evidence linked in the
> owning agent's `docs/agents/agent-N-status.md`. Missing evidence →
> Agent 6 marks the task **NOT READY** — implementation looking complete
> is not sufficient.

## How to use

1. Copy this checklist into your status-file entry (or reference row IDs).
2. Mark each row `pass` / `fail` / `n/a` (with reason). `n/a` needs a
   one-line justification — "not applicable" alone is rejected.
3. Paste exact commands + result counts. Link fixture/test IDs.
4. Request Agent 6 review for any row marked (†) before claiming `done`.

## Gate rows

### G1 — Implementation complete
- [ ] Code matches the claimed task scope in `docs/TASKS.md`; no silent
      scope expansion, no unrelated refactors.

### G2 — Existing behavior preserved
- [ ] No regressions in sibling crates (`cargo test --workspace` green) or
      documented + handoff filed. Pre-Phase-1: state which gates are n/a
      (e.g. "E2E n/a — fake-server harness lands with T-101").

### G3 — Tests added/updated (†)
- [ ] New/changed behavior has unit + integration tests; security findings
      have permanent `security_*` regression tests with fixture references.
- [ ] Test IDs listed; TESTING.md §6 matrix rows covered or explicitly
      deferred with a follow-up task ID.

### G4 — Tests pass
- [ ] Exact commands pasted with counts, e.g.
      `cargo test → 41 passed, 0 failed`; `vitest run → 18 passed`.
- [ ] No test deleted or `#[ignore]`d to go green without a TASKS.md entry.

### G5 — Security implications reviewed (†)
- [ ] SECURITY.md §4 checklist walked; trust-boundary impact stated
      (which of B1–B7 touched, or "none"); AI-authority rule respected.
- [ ] Review triggers (new IPC / crypto / privileged op / scoring-rule
      change / `unsafe` / NSS touch) got Lead + Agent 6 sign-off.

### G6 — No secrets introduced (†)
- [ ] `gitleaks detect --config tests/tools/gitleaks.toml --source .`
      clean, or `python tests/tools/secret_scan.py → hits=0` (paste output).
- [ ] No credentials/tokens/keys in code, fixtures, logs, or docs.

### G7 — Documentation updated
- [ ] `docs/` touched as needed (contracts, ARCHITECTURE, DECISIONS for
      contract changes); fixture MANIFEST.json updated if fixtures added.

### G8 — Files-changed list recorded
- [ ] Exact paths listed in the status entry; no other agent's active
      files/modules edited without coordination (prompt.md §8).

### G9 — Build / lint / static checks pass
- [ ] Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings` clean; every crate has `[lints] workspace = true`.
      Node/TS: `npm run lint`, `npm run typecheck` clean (missing `lint`
      script itself fails this row).
      Paste outputs or state "n/a — no <lang> files touched".

### G10 — UI manually inspected (UI-affecting tasks only)
- [ ] Normal / error / loading / locked / unlock states; keyboard nav;
      focus handling; overflow; dark/light where relevant (prompt.md §13).
- [ ] Remote email content blocked by default; attachment
      open/save confirmation flows; Tauri CSP non-null.
      Evidence: checklist results + screenshots location.

### G11 — Handoff note for unresolved risks
- [ ] Known failures, assumptions, and residual risks recorded; if blocked,
      `docs/AGENT_HANDOFF.md` entry exists per the template.

## Verdicts

- **DONE** — all applicable rows pass with evidence.
- **NOT READY** (Agent 6 authority) — evidence missing on any row; work
  returns to owner, no re-review of passing rows needed.
- **BLOCKED** — external dependency prevents completion; handoff entry
  required (G11), task leaves owner's active list per prompt.md §9.
