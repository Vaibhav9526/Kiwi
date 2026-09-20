# KIWI — Security Rules & Assumptions

> Owner: Agent 6 (content), Lead (enforcement). Standalone-pivot revision
> per T-113, 2026-09-19/20. Aligned with prompt.md §2, §11, §12 + ADR-005.
> Binding on all agents. (Supersedes the Thunderbird-hook revision: NSS-hook
> assumption A2 replaced; B2 redefined as webview↔core IPC.)

## 1. Non-negotiable rules (from prompt.md §2, §11)

1. Deterministic rules are authoritative for technical findings. AI explains
   and correlates — it never decides cert validity, TLS version, cipher
   class, auth success, policy enforcement, or endpoint trust.
2. Never invent a finding: every reported issue needs reproducible evidence +
   a test case (fixture + `security_*` regression test).
3. Never claim universal malware/compromise detection. Endpoint trust =
   measurable indicators + trust reduction, described as such in UI/docs.
4. Established crypto + platform APIs only. Mail TLS via `rustls` with
   explicit, reviewable configuration; key/token storage via OS facilities
   (Windows Credential Manager/DPAPI now; Android Keystore / iOS Keychain
   for mobile later). No invented algorithms/protocols.
5. Local-first, least privilege. No message content or credentials leave the
   machine without explicit, documented approval (decision record + user
   consent surface).
6. Secrets never logged or committed: keys, tokens, passwords, OAuth
   secrets, test credentials — none. Enforced by gitleaks gate (§6).
   `md5` exists in `kiwi-mail` deps solely for APOP challenge-response
   (protocol-mandated, T-104) — never for integrity/security hashing; its
   call sites require a comment stating this.
7. No fake security in core paths. Stubs only behind interfaces, explicitly
   marked (`UNIMPLEMENTED`), isolated, with tests asserting they fail closed.
8. Never store authenticator private keys or OAuth refresh tokens in
   plaintext — platform keystore/credential-manager only.
9. All externally supplied data is untrusted: server responses (SMTP/IMAP/
   POP3 bytes incl. hostile FETCH), PCAP bytes, email content, attachments,
   remote web content, admin API input, **and frontend IPC input**.
   Validate + bound everything (length, type, charset, depth — see §4).
10. Authenticator challenges bind to device + session + event (nonce,
    timestamp, scope); replay must fail; single-use enforced.
11. Elevated actions are audited; audit log is append-only/tamper-evident
    (hash-chained; verification procedure owned by Agent 4, audited by
    Agent 6).
12. Remote email content (images, stylesheets, external media) is blocked by
    default; loading it requires explicit per-sender/temporary consent and
    never sends credentials/cookies.
13. Attachments are untrusted files: spoofed extensions flagged, dangerous
    types confirmed before open, saved files get safe names (no path
    traversal), open-handlers never run with elevated privilege.
14. Active analysis of hostile content runs inside the disposable-VM sandbox
    only (`docs/sandbox.md`, ADR-008) — never on the host, never in a
    container. No sandbox provider → analysis reports `Unavailable`; there
    is no fallback to host execution, ever.
15. Local infrastructure secrets live in `.env` (gitignored) with dev-only
    defaults; `.env.example` stays tracked. Compose files pin image versions;
    the Tauri app is never containerized. Containers are services, not a
    hostile-code boundary.
16. Databases hold no secrets in any form: no passwords, keys, tokens, or
    private material in PG/SQLite rows, migrations, or seeds. Device-local
    secrets stay in OS credential storage (rule 8).

## 2. Trust boundaries (standalone)

| # | Boundary | Untrusted side | Notes / enforcement |
|---|----------|----------------|---------------------|
| B1 | Network ↔ kiwi-mail transport | mail servers, MITM | rustls explicit config; full `TlsObservation` capture; deterministic TLS/cert/cipher analysis; never silently downgrade |
| B2 | Webview (frontend) ↔ Rust core (Tauri IPC) | compromised/malicious renderer, XSS via mail content | typed commands, service-side validation + authz on every command; CSP mandatory (`csp: null` is a G5 finding); bodies/creds never cross to admin paths |
| B3 | kiwi services ↔ SQLite / mail store | tampered DB/file, other local users | per-service DB files (ADR-003); parameterized access only; sensitive fields encrypted at rest where practical; store corruption → rebuild, never silent loss |
| B3b | kiwi-admin ↔ PostgreSQL (compose) | tampered rows, leaked DSN, malicious migration | Drizzle ORM only (no raw SQL except reviewed migrations); migrations reviewed like code; least-privilege DB role; DSN from `.env`, never committed; audit append-only enforced at DB level (trigger) + hash-chain on read |
| B9 | Host ↔ sandbox guest (all tiers) | hostile attachment/document/link executing in guest; guest-escape attempt | disposable per-run instances (qcow2 overlay / unregister); base image versioned + hash-pinned, never booted mutable; no host FS/creds/keys/mailbox mapped in; no NIC by default; watchdog kill; provider capability reporting (`Available\|Degraded\|Unavailable`); WSL2 tier carries the documented shared-kernel caveat |
| B4 | kiwi-core ↔ mobile authenticator | network attacker, cloned device | asymmetric challenge-response; QR/local-net pairing; keypair in platform keystore; revocation honored before trust |
| B5 | kiwi-admin ↔ admin UI | unauthorized local user / CSRF | localhost-only bind; RBAC on every operation; session expiry; audited elevated actions |
| B6 | Anything ↔ AI provider | provider, prompt injection via mail content | optional; structured-findings payload only — never credentials/message bodies; AI output never a finding without deterministic re-validation |
| B7 | Forensics ingest ↔ PCAP files | crafted packet bytes | Rust memory-safe parsing; hard caps; fuzz/property tests; parse failures are findings about input, never panics |
| B8 | MIME/attachment handling ↔ mail content | hostile MIME, spoofed filenames, polyglots | bounded parse via `mail-parser`; nesting/size caps; filename sanitization; remote-content block (rule 12) |

## 3. Security assumptions (explicit; challenge these in review)

- A1. The local OS user account is trusted to file-access extent — KIWI
  raises the bar for remote/network attackers and opportunistic local
  actors, not for a fully compromised OS (see THREAT-MODEL.md out-of-scope).
- A2. `TlsObservation` comes from KIWI's own rustls transport (owned code,
  T-101) — full negotiated parameters available. If a value is genuinely
  unavailable, report `unknown` + reduced trust, never a guess.
- A3. The device clock is approximately correct (skew budget documented per
  protocol); expiry/replay windows depend on it.
- A4. SQLite file permissions + OS user separation are the at-rest
  guarantee in Phase 0–1; field-level encryption is defense-in-depth.
  OAuth refresh tokens + authenticator keys always use the OS
  credential-manager/keystore, never SQLite plaintext.
- A5. QR pairing happens over a physically proximate, human-verified
  channel; a photographed QR is equivalent to consent (documented UX risk).
- A6. Tauri auto-update (if enabled later) pins signing keys and verifies
   bundles; until then, releases are verified out-of-band.
- A7. Compose `.env` holds dev-only defaults; any shared/staging deployment
   replaces the PG password and treats `pgdata` as disposable unless
   explicitly backed up. Migrations are trusted dev input (reviewed like
   code) — the threat is tampering/failure, not malicious SQL from outside.
- A8. Sandbox availability is host-dependent (QEMU/WHPX target, WSL2
   interim, Firecracker on Linux). Absent provider = unavailable feature,
   never degraded-to-host-execution. WSL2 tier: hypervisor boundary vs host
   holds; shared-kernel escape could reach sibling distros (documented
   caveat, not a host compromise claim).

## 4. Secure-coding checklist (all agents, enforced in review)

- [ ] Input validation at every boundary: length caps, type checks, charset
      restrictions, recursion/nesting depth limits, explicit unknown-field
      policy (ignore, never fail-open on security decisions; fail-closed on
      auth/trust paths). Frontend input re-validated Rust-side (B2).
- [ ] No secrets in logs, fixtures, commits, or docs (gitleaks gate, §6).
      Logging helpers must redact by default — caller-discipline-only
      loggers (kiwi-admin `createConsoleLogger` at T-115 review) need a
      `redact()` wrapper before handling auth-adjacent paths.
- [ ] Fixture data never from real private mail/credentials — synthetic
      only, documented generation method.
- [ ] New dependencies justified, minimal, pinned (`Cargo.lock` /
      `package-lock.json` committed); `cargo audit` / `npm audit` at each
      milestone; `publish = false` on app crates.
- [ ] Every crate opts into `[lints] workspace = true` (inherits
      `unsafe_code = "forbid"`); any `unsafe` needs Lead + Agent 6 sign-off
      and a `// SAFETY:` invariant comment.
- [ ] Error paths fail closed on trust/auth/policy decisions; UI-facing
      errors never include secrets, tokens, or raw key material.
- [ ] Time/comparison safety: constant-time comparison for secrets/tokens;
      no security decision on wall-clock equality alone.
- [ ] Credentials zeroized after use (`zeroize` in kiwi-mail — must be
      wired into the auth paths, not merely depended on).
- [ ] Webview: non-null CSP; no `http://` remote code in production;
      external links open in the system browser after user action.
- [ ] Infra: `.env` gitignored + `.env.example` covers every compose var
      (test-enforced); image versions pinned; no mailbox/credential mounts
      in compose; no secrets in migrations/seeds (rule 16); migrations
      reviewed like code; audit-guard trigger preserved on schema changes.
- [ ] Sandbox: new providers behind the `SandboxProvider` interface with
      capability reporting; base images versioned + hash-pinned, never
      mutated; per-run instances never reused; guest output bounded before
      host parsing; QEMU binary provisioning is an explicit install
      decision, never bundled silently.

## 5. AI security rules (prompt.md §12, binding — unchanged by pivot)

AI MAY: explain findings, summarize incidents, correlate findings, describe
impact, suggest remediation, summarize re-scan diffs — always grounded in
structured findings/evidence records.

AI MAY NOT be sole authority for: certificate validity, TLS version
detection, cipher classification, authentication success, policy
enforcement, endpoint trust decisions.

Hard requirements:

- Every AI response about a security event must cite the underlying
  finding/evidence IDs; UI renders the deterministic finding alongside any
  AI text, labeled as AI-generated.
- When AI is disabled/unavailable, core analysis works fully (tests run
  the engine with AI stubbed off).
- Mail bodies/credentials never enter AI payloads. Allowed payload:
  finding IDs, rule IDs, protocol metadata, remediation templates.
- Prompt-injection posture: email/PCAP content is untrusted data, never
  concatenated into AI system instructions.

## 6. Verification & gates (Agent 6-operated)

- Secret scan: `gitleaks detect --config tests/tools/gitleaks.toml
  --source .` (or `python tests/tools/secret_scan.py` fallback). Blocks
  any task → `done` on a hit.
- Workspace gates: `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`; Node packages:
  `npm run lint`, `npm run typecheck`, `npm test`.
- Security regression: each fixed weakness keeps a permanent
  `security_*` test (TESTING.md §3, §5b).
- Review triggers (Lead + Agent 6 sign-off): new IPC command, new
  crypto/key/token handling, new admin privileged op, scoring-rule changes,
  transport/TLS-config changes, CSP changes, any `unsafe`.
- Residual risk tracked in THREAT-MODEL.md, reviewed each phase.

## 7. Dependency audit (T-154, Agent 6-operated, 2026-09-20)

Method: `cargo audit` (cargo-audit 0.22.2, RustSec DB 1251 advisories)
over the workspace lockfile; full `npm audit` (incl. dev) per JS
package. Production-only `npm audit --omit=dev` is clean everywhere it
runs. Re-run on every dependency change and monthly; findings below are
the baseline — closing them belongs to the owning agent (flagged, not
fixed here).

### Rust (`cargo audit`: 1 vulnerability + 7 warnings)

- **rsa 0.9.10 — RUSTSEC-2023-0071 (Marvin timing sidechannel, medium
  5.9). No fixed upgrade available.** Direct dep of `kiwi-mailauth`
  (Agent 8, T-122) for DKIM verification. Assessment: Marvin recovers
  plaintext through RSA *decryption* (private-key op); this crate uses
  RSA for public-key *verification* only (`verify_rsa_sha256`), and the
  sole private-key use is 1024-bit test keygen (`dkim.rs` round-trip
  tests). **Not exploitable in this usage.** Action for Agent 8: track
  upstream; prefer removal (verify-only crates such as `rsa` verify path
  stay affected on paper) or migration when a fixed release exists.
- **Unmaintained warnings (transitive, inherited):** `unic-char-*`
  (×5, via `tauri-utils → urlpattern`), `proc-macro-error` (Linux-only
  target, not compiled on this host). Action: ride Tauri upgrades; no
  direct action.
- **Unsound warning:** `glib 0.18.5` RUSTSEC-2024-0429
  (`VariantStrIter`, Linux-only GTK path via Tauri). Not compiled on
  this target; Linux CI/packaging owners note. No direct action.

### npm (full audit, dev included)

- **kiwi-admin (Agent 5): 6 vulns (1 critical + 5 moderate), all
  dev-only, fixes available.** Critical: `vitest`
  GHSA-5xrq-8626-4rwp (9.8 — UI-server file read/RCE, range <3.2.6;
  installed 3.2.4 → non-breaking upgrade ≥3.2.6 also clears the
  moderate `@vitest/mocker` path-traversal GHSA-82fw-gwwq-j7x9:
  `npm audit fix`). Moderate: `esbuild` dev-server request forgery
  (GHSA-67mh-4wv8-2f99) via `drizzle-kit` chain — `fix --force`
  (breaking: drizzle-kit 0.18.1) — accept or isolate dev-server
  binding instead. None ship in the runner image beyond devDeps pruned
  at build; still: run `npm audit fix` (Agent 5).
- **kiwi-admin-ui, kiwi-app: 0 vulnerabilities** (full audit clean).
- **mobile (Agent 4): NOT AUDITABLE — no `package-lock.json`.**
  `npm audit` refuses without a lockfile. Action for Agent 4/Lead:
  generate (`npm i --package-lock-only`) and commit so CI can gate it.

### Rules going forward

- New dependencies (any ecosystem) need owner + justification in the
  owning agent's status log; `cargo audit` / `npm audit` re-run before
  merge. Any **critical** or **exploitable-in-our-usage** finding blocks
  `done` until fixed, mitigated, or Lead-accepted in writing here.
