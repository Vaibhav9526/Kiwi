# KIWI — Threat Model

> Owner: Agent 6 (content). Expanded per T-006, 2026-09-19. Aligned with
> prompt.md §2, §11–§13 and docs/SECURITY.md. Living document — Agent 6
> updates residual risk each phase.

## 1. Assets (what we protect)

| ID | Asset | Confidentiality / Integrity stakes |
|----|-------|-------------------------------------|
| AS-1 | Mailbox content + credentials (SMTP/IMAP/POP3 passwords, OAuth tokens) | theft → account takeover; must never leave host without approval |
| AS-2 | TLS session confidentiality/integrity for mail transport | downgrade/MITM → credential + content exposure |
| AS-3 | Authenticator private keys + pairing/registration state | theft/clone → trust bypass |
| AS-4 | Device/session trust state; lock-state integrity | bypass → sensitive mailbox access while untrusted |
| AS-5 | Org policies, mail-flow metadata, audit-log integrity | tampering → silent policy disable, cover-up |
| AS-6 | Security findings + evidence records | forgery/skew → false assurance or false alarms |
| AS-7 | Certificate/TLS observation fidelity (NSS hook readings) | misread → wrong score, wrong user decision |

## 2. Attacker capabilities (in scope)

- **Network attacker (T-NET):** strip/downgrade STARTTLS, negotiate weak
  ciphers, present rogue/forged/expired certs, MITM mail protocols,
  DNS manipulation affecting MX/domain checks.
- **Malicious or misconfigured server (T-SRV):** weak TLS config, invalid
  chain, aggressive downgrade, hostile headers/content.
- **Untrusted-input attacker (T-INP):** crafted `.pcap/.pcapng`, malformed
  MIME, hostile headers/attachments, oversized inputs (DoS via parsing).
- **Local unauthorized actor (T-LOC):** another user/process attempting
  admin/policy changes, trust-state tampering, DB modification, IPC
  spoofing against kiwi services.
- **Authenticator attacker (T-AUTH):** replay of challenges, stolen/cloned
  device identity, pairing interception, revoked-device reuse.
- **Abuse of AI layer (T-AI):** prompt injection via email content to skew
  explanations; over-reliance on AI text as authority.

**Explicitly OUT of scope** (prompt.md §2.6 — no universal malware/EDR
claims): fully compromised OS/kernel, hardware backdoors, coercion of the
user, side-channel key extraction from a healthy device. These are
documented as accepted risks, not mitigated claims.

## 3. Trust boundaries → threats → mitigations

| Boundary (SECURITY.md §2) | Threats | Primary mitigations | Verifying tests |
|---------------------------|---------|---------------------|-----------------|
| B1 mail transport | downgrade, MITM, weak crypto, rogue cert | deterministic TLS/cert/cipher/key-exchange rules; forward-secrecy assessment; explainable scoring; user warnings | PCAP fixture suite (T-012); cert edge fixtures; downgrade-indicator tests |
| B2 TB ↔ local services | IPC spoofing, privilege abuse, malformed messages | authenticated local channel; no remote listeners; schema validation; fail-closed on malformed | IPC contract tests; malformed-input matrix rows |
| B3 services ↔ DB | tampering, injection, cross-service reads | parameterized access; per-service DB files (ADR-003); field encryption where practical; open-time integrity checks | injection tests; tamper-evident audit verification |
| B4 core ↔ authenticator | replay, cloning, pairing hijack, revoked reuse | device-bound keypair in platform keystore; challenge bound to device+session+event; nonce + expiry + single-use; revocation enforced | challenge/replay/rejection tests; revocation tests |
| B5 admin plane | unauthorized change, privilege escalation, CSRF | RBAC on every op; localhost-only; session expiry; append-only audit log | permission/authz matrix; unauthorized-access tests |
| B6 AI boundary | prompt injection, authority confusion | findings-only payload; AI text labeled + never authoritative; offline-capable core | AI-disabled test runs; payload-content assertions |
| B7 PCAP ingest | crafted packets, parser DoS, memory unsafety | Rust memory-safe parsing; hard input caps; fuzz/property tests; errors as findings, never panics | malformed-stream fixtures; fuzz corpus |

## 4. Attack scenarios (representative, each needs a regression test)

1. **STARTTLS stripping** on SMTP (plaintext where TLS expected) →
   finding `STARTTLS-STRIPPED`, trust reduced, user warned. Fixture:
   `pcap/smtp_stripped_*.pcapng` (T-012).
2. **Rogue certificate** (valid-looking chain, wrong trust anchor) →
   finding with chain evidence; connection never silently trusted.
3. **Weak cipher negotiation** (e.g. RC4/3DES/CBC-without-FS era suites) →
   cipher finding + forward-secrecy `fail`; score reflects it.
4. **Replayed authenticator approval** (captured approve reused) →
   rejected (single-use nonce + event binding); trust unchanged.
5. **Revoked device unlock attempt** → denied; audit event appended.
6. **Crafted PCAP crash attempt** (truncated headers, overlapping streams,
   giant lengths) → parse error contained; finding about input quality.
7. **Unauthorized policy change** (non-admin role calls admin API) →
   403 + audit event; policy unchanged.
8. **AI unavailable during incident review** → deterministic report still
   complete; AI panel shows degraded-state message.

## 5. Residual risk (maintained by Agent 6)

| ID | Risk | Why accepted / deferred | Planned reduction |
|----|------|------------------------|-------------------|
| RR-1 | First-connection trust (TOFU gaps before known-good baseline) | no CT/reputation baseline in Phase 0–1 | Phase 7: CT/SPF/DKIM/DMARC enrichment, documented in report |
| RR-2 | OS-compromised endpoint defeats lock state | out of scope per §2 (no EDR claims) | measurable indicators only; honest UX copy (Agent 5) |
| RR-3 | NSS hook blind spots (values platform won't expose) | depends on T-007 source map | `unknown`-with-reduced-trust policy (SECURITY.md A2); per-hook capability table |
| RR-4 | QR-pairing shoulder-surf/photograph | physical-channel assumption (A5) | short-lived pairing codes + explicit user confirm step |
| RR-5 | Audit-log tamper resistance is hash-chain only (no remote notary) in local-first mode | Phase 0–1 posture | export + independent verification procedure; org-scale notary later |
| RR-6 | Thunderbird build drift (upstream changes break hooks) | T-001/T-007 gating | narrow hooks + build-green gate + per-milestone re-verification |

## 6. Review cadence

- Each phase end: Agent 6 re-scores scenarios §4 against implementation,
  updates RR table, records evidence in `docs/agents/agent-6-status.md`.
- Any new asset, boundary, or attacker capability → update this file first,
  then SECURITY.md checklist, then TESTING.md matrix. No silent expansion
  of scope or claims.
