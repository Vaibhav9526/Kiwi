# KIWI — Internal API Contracts

> Owner: Lead Agent. Stable interfaces between components. Detailed contracts
> live in `docs/contracts/`; this file indexes and versions them.
> **Rule:** contracts change only via Lead review — record in DECISIONS.md.

| Contract | File | Parties | Owner | Status |
|----------|------|---------|-------|--------|
| Security session model | `contracts/security-session.md` | TB-style hooks ↔ kiwi-core ↔ UI | Agent 2 | draft (T-002) |
| IPC transport | `contracts/ipc.md` | kiwi-app frontend ↔ src-tauri backend | Lead | `kiwi.ipc/1` |
| Forensics findings/evidence | `contracts/forensics.md` | kiwi-forensics ↔ reports/UI | Agent 3/6 | `kiwi.forensics/1` (T-003) |
| Mail authentication (SPF/DKIM/DMARC) | `contracts/mailauth.md` | kiwi-mailauth ↔ app | Agent 8 | `kiwi.mailauth/1`; T-183 hardening pending review |
| Account autoconfig | `contracts/autoconfig.md` | kiwi-autoconfig → kiwi-app | Agent 8 | `kiwi.autoconfig/1`, final (T-135/T-158) |
| OAuth2 grant acquisition | `contracts/oauth2.md` | kiwi-autoconfig::oauth2 ↔ providers/OS creds | Agent 19 | `kiwi.oauth2/1` (T-229 reviewed); IPC wiring T-230 |
| Local address book | `contracts/contacts.md` | kiwi-contacts ↔ kiwi-app IPC | Agent 9 | `kiwi.contacts/1`, draft (T-150) |
| Pairing engine | `contracts/pair.md` | kiwi-pair ↔ src-tauri IPC | Agent 10 | v1 draft (T-174) |
| Authenticator pairing | `contracts/authenticator.md` | kiwi-core ↔ mobile | Lead | v1; Phase 4 |
| Sandbox interface | `contracts/sandbox.md` | kiwi-sandbox ↔ app/forensics | Agent 2 | v1.1 (T-132/T-168) |
| Admin/policy API | `contracts/admin-api.md` | kiwi-admin ↔ admin UI/app | Agent 4/9 | `admin-api/1.3` (T-004/T-193) |
| External integrations | `contracts/integrations.md` | kiwi-integrations ↔ external providers | Agent 11 | `kiwi.integrations/1`, draft (T-226) |
| Deterministic inbox rules | `contracts/rules.md` | kiwi-mail rules ↔ app | Agent 22 | `kiwi.rules/1`, draft (T-236); IPC wiring pending |
| UI surface registry | `contracts/ui-surfaces.md` | UI spec ↔ kiwi-app frontend | Agent 5/12 | v2 (T-111); rebuild in-flight T-191/192 |

## Cross-cutting invariants

- All payloads typed + versioned; unknown fields ignored, not fatal.
- Findings carry `evidence` references — never free-text-only conclusions.
- No contract may require AI availability.
- No contract may transport credentials or message bodies to admin/analytics.
