# kiwi-admin-ui — local admin console (T-134 scaffold)

React + TypeScript + Vite. **Localhost only**: the dev server binds
`127.0.0.1:1421`; the admin service lives at `http://127.0.0.1:8471`
(configurable in the header, persisted to localStorage).

## Run

```
# terminal 1 — the service (from kiwi-admin/)
npm run build && npm run serve

# terminal 2 — the console (here)
npm install
npm run build   # or: npm run dev
```

Without the service running, the console probes `/healthz`, fails, and runs
in **demo mode** (badged in the header): local fixtures + the contract §2
permission matrix enforced client-side so the role switcher
(`org_admin` / `security_admin` / `viewer`) demonstrates real allow/deny
paths. Demo bridge verdicts are trivially derived and labeled — never confuse
them with the deterministic server evaluator.

## Views

Orgs (create + current-org context — no org-listing endpoint exists in
contract v1.3) · Users & roles (invite, grant with confirm, device revoke by
id with confirm) · Policies (list, create, outbound-bridge evaluation tester)
· Mail flow (filters, metadata-only table, send-attempt ingest) · Audit
(table + chain verification panel).

## Constraints honored

- Typed API client mirrors `docs/contracts/admin-api.md` v1.3 exactly; mock
  implements the same interface (swap is one line in `App.tsx`).
- Loading / error (with retry) / empty states on every view.
- Destructive actions confirm naming the target (ui-spec S-11).
- No secrets anywhere: no passwords, tokens, or message bodies in code,
  fixtures, or storage — only ids, metadata, and verdicts.
- Dev-auth warning: live mode sends `x-kiwi-*` actor headers (server
  scaffold); real session auth replaces them (Phase 3+).
