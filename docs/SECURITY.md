# KIWI — Security Rules & Assumptions

> Owner: Agent 6 (content), Lead (enforcement). Expanded per T-006,
> 2026-09-19. Aligned with prompt.md §2, §11, §12. Binding on all agents.

## 1. Non-negotiable rules (from prompt.md §2, §11)

1. Deterministic rules are authoritative for technical findings. AI explains
   and correlates — it never decides cert validity, TLS version, cipher
   class, auth success, policy enforcement, or endpoint trust.
2. Never invent a finding: every reported issue needs reproducible evidence +
   a test case (fixture + `security_*` regression test).
3. Never claim universal malware/compromise detection. Endpoint trust =
   measurable indicators + trust reduction, described as such in UI/docs.
4. Established crypto + platform APIs only. No invented algorithms/protocols.
   TLS via NSS/Thunderbird stack; key storage via OS keystore APIs
   (Windows DPAPI/CNG now, Android Keystore / iOS Keychain later).
5. Local-first, least privilege. No message content or credentials leave the
   machine without explicit, documented approval (decision record + user
   consent surface).
6. Secrets never logged or committed: keys, tokens, passwords, OAuth
   secrets, test credentials — none. Enforced by gitleaks gate (§6).
7. No fake security in core paths. Stubs only behind interfaces, explicitly
   marked (`UNIMPLEMENTED`), isolated, with tests asserting they fail closed.
8. Never store authenticator private keys in plaintext — platform keystore
   only; export prohibited by API design.
9. All externally supplied data is untrusted: PCAP bytes, email content,
   attachments, network responses, admin API input. Validate + bound
   everything (length, type, charset, depth — see §4).
10. Authenticator challenges bind to device + session + event (nonce,
    timestamp, scope); replay must fail; single-use enforced server-side.
11. Elevated actions are audited; audit log is append-only/tamper-evident
    (hash-chained; verification procedure owned by Agent 4, audited by
    Agent 6).

## 2. Trust boundaries

| # | Boundary | Untrusted side | Notes / enforcement |
|---|----------|----------------|---------------------|
| B1 | Network ↔ Thunderbird mail stack | mail servers, MITM | deterministic TLS/cert/cipher analysis, scoring, warnings; never silently downgrade |
| B2 | Thunderbird ↔ kiwi services | compromised renderer/chrome JS | local IPC only (named pipe / localhost socket), authenticated channel, no remote listeners by default; validate every message (§4) |
| B3 | kiwi services ↔ SQLite | tampered DB file, other local users | per-service DB files (ADR-003); parameterized access only; sensitive fields encrypted at rest where practical; integrity checks on open |
| B4 | kiwi-core ↔ mobile authenticator | network attacker, cloned device | asymmetric challenge-response; pairing via QR/local net; keypair in platform keystore; revocation list honored before trust |
| B5 | kiwi-admin ↔ admin UI | unauthorized local user / CSRF | localhost-only bind; RBAC on every operation; session expiry; audited elevated actions |
| B6 | Anything ↔ AI provider | provider, prompt injection via mail content | optional; structured-findings payload only — never credentials/message bodies; AI output never written back as a finding without deterministic re-validation |
| B7 | Forensics ingest ↔ PCAP files | crafted packet bytes | Rust memory-safe parsing; hard caps (file size, stream count, reassembly buffers); fuzz/property tests; parse failures are findings about the input, never panics in core paths |

## 3. Security assumptions (explicit; challenge these in review)

- A1. The local OS user account is trusted to the extent of file access —
  KIWI raises the bar for remote/network attackers and opportunistic local
  actors, not for a fully compromised OS (see THREAT-MODEL.md out-of-scope).
- A2. NSS/Thunderbird TLS state is read faithfully via the narrow hooks;
  if a hook cannot observe a value (e.g. cipher suite hidden by platform),
  the engine reports `unknown` with reduced trust — never a guessed value.
- A3. The device clock is approximately correct (skew budget documented per
  protocol); expiry/replay windows depend on it.
- A4. SQLite file permissions + OS user separation are the at-rest
  guarantee in Phase 0–1; field-level encryption is defense-in-depth.
- A5. QR pairing happens over a physically proximate, human-verified
  channel; a photographed QR is equivalent to consent (documented UX risk).

## 4. Secure-coding checklist (all agents, enforced in review)

- [ ] Input validation at every boundary: length caps, type checks, charset
      restrictions, recursion/nesting depth limits, explicit unknown-field
      policy (ignore, never fail-open on security decisions; fail-closed on
      auth/trust paths).
- [ ] No secrets in logs, fixtures, commits, or docs (gitleaks gate, §6).
- [ ] Fixture data never from real private mail/credentials — synthetic
      only, documented generation method.
- [ ] New dependencies justified, minimal, pinned (`Cargo.lock` /
      `package-lock.json` committed); `cargo audit` / `npm audit` at each
      milestone.
- [ ] Rust `unsafe` / C++ changes in `comm/` get extra reviewer scrutiny;
      `unsafe` requires a `// SAFETY:` comment stating the invariant.
- [ ] Error paths fail closed on trust/auth/policy decisions; error
      messages to users never include secrets, tokens, or raw key material.
- [ ] Time/comparison safety: constant-time comparison for secrets/tokens;
      no security decision on wall-clock equality alone (allow skew window).
- [ ] IPC/API input re-validated service-side even if the sender validated.

## 5. AI security rules (prompt.md §12, binding)

AI MAY: explain findings, summarize incidents, correlate findings, describe
impact, suggest remediation, summarize re-scan diffs — always grounded in
structured findings/evidence records.

AI MAY NOT be sole authority for: certificate validity, TLS version
detection, cipher classification, authentication success, policy
enforcement, endpoint trust decisions.

Hard requirements:

- Every AI response about a security event must cite the underlying
  finding/evidence IDs; UI must render the deterministic finding alongside
  any AI text, labeled as AI-generated.
- When AI is disabled/unavailable, core analysis works fully (tests run
  the engine with AI stubbed off).
- Mail bodies/credentials never enter AI payloads. Allowed payload:
  finding IDs, rule IDs, protocol metadata (versions, cipher names),
  remediation templates — see `docs/contracts/` AI payload schema (Lead).
- Prompt-injection posture: email/PCAP content is untrusted and must never
  be concatenated into AI system instructions; treat as data, quote/escape.

## 6. Verification & gates (Agent 6-operated)

- Secret scan: `gitleaks detect --config tests/tools/gitleaks.toml
  --source .` (or `python tests/tools/secret_scan.py` fallback). Gate
  blocks any task → `done` on a hit.
- Security regression: each fixed weakness keeps a permanent
  `security_*` test (docs/TESTING.md §3, §6).
- Review triggers (require Agent 6 + Lead sign-off): new IPC surface, new
  crypto/key handling, new admin privileged op, changes to scoring rules,
  any `unsafe`/NSS-touching code.
- Residual risk is tracked in docs/THREAT-MODEL.md and reviewed each phase.
