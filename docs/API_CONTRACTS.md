# KIWI — Internal API Contracts

> Owner: Lead Agent. Stable interfaces between components. Detailed contracts
> live in `docs/contracts/`; this file indexes and versions them.
> **Rule:** contracts change only via Lead review — record in DECISIONS.md.

| Contract | File | Parties | Owner | Status |
|----------|------|---------|-------|--------|
| Security session model | `contracts/security-session.md` | TB hooks ↔ kiwi-core | Agent 2 | drafting (T-002) |
| Forensics findings/evidence | `contracts/forensics.md` | kiwi-forensics ↔ reports/UI | Agent 3 | drafting (T-003) |
| Admin/policy API | `contracts/admin-api.md` | kiwi-admin ↔ admin UI/TB | Agent 4 | drafting (T-004) |
| UI surface registry | `contracts/ui-surfaces.md` | UI spec ↔ TB integration | Agent 5 | drafting (T-005) |
| Authenticator pairing | `contracts/authenticator.md` | kiwi-core ↔ mobile | Lead | Phase 4 |
| IPC transport | `contracts/ipc.md` | TB ↔ local services | Lead | Phase 2 |

## Cross-cutting invariants

- All payloads typed + versioned; unknown fields ignored, not fatal.
- Findings carry `evidence` references — never free-text-only conclusions.
- No contract may require AI availability.
- No contract may transport credentials or message bodies to admin/analytics.
