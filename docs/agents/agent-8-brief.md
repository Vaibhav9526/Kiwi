# Agent 8 Brief — Cline Muse Spark — MAIL AUTH (SPF/DKIM/DMARC)

Read first: `prompt.md`, `docs/ARCHITECTURE.md`, `docs/TASKS.md`,
`docs/SECURITY.md`, `docs/contracts/forensics.md` (your results feed the
findings model). You are **Agent 8**.

## Mission

New crate **`kiwi-mailauth`**: deterministic domain-authentication checks
for received mail — SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489).
Feeds `kiwi-forensics` findings; works with zero AI.

## Tasks (see docs/TASKS.md)

- **T-122** — create `kiwi-mailauth/` crate (add to root workspace members):
  - `spf` — mechanism/macro evaluator: all, include, a, mx, ip4/ip6, ptr
    (deprecated-flagged), exists, redirect, modifiers; result set
    (pass/fail/softfail/neutral/none/temperror/permerror); bounded DNS
    lookups (RFC 7208 §4.6.4 limits: ≤10 lookups, ≤2 void).
  - `dkim` — signature header parse (tag-list), body+header canonicalization
    (simple/relaxed), RSA-SHA256/Ed25519 verify via existing crypto crates,
    key fetch `s._domainkey.d`; result + evidence fields.
  - `dmarc` — `v=DMARC1` record parse, alignment (strict/relaxed) of SPF/DKIM
    identifiers with From domain, policy outcome (none/quarantine/reject).
  - `dns` — lookup abstraction (hickory-resolver) with a mock resolver trait
    so ALL tests run offline; never hard-fail on DNS errors (temperror).
  - Emit results as typed structs serializable into the forensics evidence
    model; never invent findings — no record → `none`, not a failure.
  - `unsafe_code = "forbid"`; deps minimal+pinned; determinism rules per
    kiwi-forensics (no ambient clocks in verdicts — expiry checks take `now`
    as input).

## Boundaries

Yours: `kiwi-mailauth/` (new), `docs/agents/agent-8-status.md`,
`docs/contracts/mailauth.md` (create — result schemas). Do NOT edit
kiwi-forensics internals — emit typed results; Agent 6 maps them to
findings. Coordinate fixtures with `tests/fixtures/` (Agent 6 territory —
propose fixture list in your status file, don't write there).

## Reporting

Append dated entries to `docs/agents/agent-8-status.md`. `cargo test -p
kiwi-mailauth` green before reporting done. Hit a limit → handoff entry in
`docs/AGENT_HANDOFF.md`.
