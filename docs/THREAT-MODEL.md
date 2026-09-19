# KIWI — Threat Model

> Owner: Agent 6 (content). Standalone-pivot revision per T-113,
> 2026-09-19/20. Living document — residual risk updated each phase.
> (Supersedes the Thunderbird-hook revision: the client itself is now the
> primary attack surface.)

## 1. Assets (what we protect)

| ID | Asset | Confidentiality / Integrity stakes |
|----|-------|-------------------------------------|
| AS-1 | Mailbox content + credentials (SMTP/IMAP/POP3 passwords, OAuth tokens) | theft → account takeover; never leave host without approval |
| AS-2 | TLS session confidentiality/integrity for mail transport | downgrade/MITM → credential + content exposure |
| AS-3 | Authenticator private keys + pairing/registration state | theft/clone → trust bypass |
| AS-4 | Device/session trust state; lock-state integrity | bypass → sensitive mailbox access while untrusted |
| AS-5 | Org policies, mail-flow metadata, audit-log integrity | tampering → silent policy disable, cover-up |
| AS-6 | Security findings + evidence records | forgery/skew → false assurance or false alarms |
| AS-7 | `TlsObservation` fidelity (own rustls transport) | misread/mis-wire → wrong score, wrong user decision |
| AS-8 | Local mail store (SQLite + on-disk bodies/attachments) | tampering → content forgery; theft → mailbox exposure |
| AS-9 | Rendered mail isolation (webview) | XSS/tracking via mail → session theft, privacy leak |

## 2. Attacker capabilities (in scope)

- **Network attacker (T-NET):** strip/downgrade STARTTLS, negotiate weak
  ciphers, present rogue/forged/expired certs, MITM mail protocols, DNS
  manipulation affecting MX/domain checks.
- **Malicious or misconfigured server (T-SRV):** weak TLS config, invalid
  chain, aggressive downgrade, hostile IMAP FETCH/POP3 responses crafted
  to exploit client parsing.
- **Malicious email (T-MAIL):** hostile MIME/nesting, spoofed attachment
  names, tracking pixels/remote content, phishing links, OAuth-consent
  phishing, prompt-injection text aimed at the AI layer.
- **Untrusted-input attacker (T-INP):** crafted `.pcap/.pcapng`, malformed
  MIME, oversized inputs (DoS via parsing/storage).
- **Renderer attacker (T-WEB):** XSS payload delivered via mail reaching
  the webview; attacks Tauri IPC, local APIs, exfiltration. (Mitigated by
  B2: CSP, sanitization, command authz — never assumed absent.)
- **Local unauthorized actor (T-LOC):** another user/process attempting
  admin/policy changes, trust-state or mail-store tampering, IPC abuse.
- **Authenticator attacker (T-AUTH):** replay of challenges, stolen/cloned
  device identity, pairing interception, revoked-device reuse.
- **Abuse of AI layer (T-AI):** prompt injection via email content to skew
  explanations; over-reliance on AI text as authority.

**Explicitly OUT of scope** (no universal malware/EDR claims): fully
compromised OS/kernel, hardware backdoors, user coercion, side-channel key
extraction from a healthy device. Documented as accepted risks.

## 3. Trust boundaries → threats → mitigations

| Boundary (SECURITY.md §2) | Threats | Primary mitigations | Verifying tests |
|---------------------------|---------|---------------------|-----------------|
| B1 mail transport | downgrade, MITM, weak crypto, rogue cert | rustls explicit config; `TlsObservation`; deterministic rules + scoring; warnings | fake-server adversarial modes (T-114); PCAP suite (T-012); cert fixtures |
| B2 webview ↔ Rust core | XSS→IPC abuse, malicious commands | non-null CSP; mail sanitization; per-command validation + authz; no bodies/creds to admin paths | IPC fuzz/property tests; CSP assertion test; sanitizer suite |
| B3 services ↔ store | tampering, injection, silent loss | parameterized access; per-service DBs (ADR-003); corruption→rebuild; token/keystore storage for secrets | injection tests; corruption-recovery tests |
| B4 core ↔ authenticator | replay, cloning, pairing hijack, revoked reuse | device-bound keypair in keystore; challenge binding; nonce+expiry+single-use; revocation | challenge/replay/rejection; revocation tests |
| B5 admin plane | unauthorized change, escalation | RBAC; localhost-only; session expiry; hash-chained audit | permission/authz matrix; unauthorized-access tests |
| B6 AI boundary | prompt injection, authority confusion | findings-only payload; labeled AI text; offline-capable core | AI-disabled runs; payload assertions |
| B7 PCAP ingest | crafted packets, parser DoS | memory-safe parsing; input caps; fuzz tests; errors-as-findings | malformed-stream fixtures; fuzz corpus |
| B8 MIME/attachments | hostile MIME, spoofed names, tracking | bounded parse; nesting/size caps; filename sanitization; remote-content block default | message fixtures; spoofed-ext/oversize cases |

## 4. Attack scenarios (each needs a permanent regression test)

1. **STARTTLS stripping** (fake SMTP hides the extension) →
   `STARTTLS-STRIPPED` finding, trust reduced, user warned.
2. **Rogue certificate** → finding with chain evidence; never silently trusted.
3. **Weak cipher negotiation** → cipher + forward-secrecy findings; score reflects.
4. **Replayed authenticator approval** → rejected (single-use nonce + event
   binding); trust unchanged.
5. **Revoked device unlock attempt** → denied + audit event.
6. **Crafted PCAP crash attempt** → contained parse error; input-quality finding.
7. **Unauthorized policy change** (non-admin role) → denied + audit; policy kept.
8. **AI unavailable during incident review** → deterministic report complete;
   AI panel shows degraded state.
9. **Tracking-pixel email** → remote content blocked by default; explicit
   consent loads it without credentials.
10. **Spoofed attachment** (`invoice.pdf.exe` / double extension) → flagged;
    save uses sanitized name; no traversal (`../../` neutralized).
11. **Hostile IMAP FETCH** (oversize/malformed literals from a rogue server) →
    bounded, rejected, surfaced — no panic, no unbounded allocation.
12. **Mail-to-webview XSS** (`<script>`/event-handler in HTML part) →
    sanitized before render; CSP backstop; no IPC access from mail content.

## 5. Residual risk (maintained by Agent 6)

| ID | Risk | Why accepted / deferred | Planned reduction |
|----|------|------------------------|-------------------|
| RR-1 | First-connection trust (TOFU gaps before known-good baseline) | no CT/reputation baseline in Phase 0–1 | Phase 7: CT/SPF/DKIM/DMARC enrichment |
| RR-2 | OS-compromised endpoint defeats lock state | out of scope (no EDR claims) | measurable indicators only; honest UX copy |
| RR-3 | Upstream parser vulns (`mail-parser`, `x509-parser`, webview engine) | dependencies do the dangerous parsing | pin + audit deps; fuzz corpus; caps at every boundary |
| RR-4 | QR-pairing shoulder-surf/photograph | physical-channel assumption (A5) | short-lived pairing codes + explicit confirm |
| RR-5 | Audit log is hash-chain only (no remote notary) in local-first mode | Phase 0–1 posture | export + independent verification; org notary later |
| RR-6 | Webview escape (renderer 0-day → IPC) | defense-in-depth limits | minimal capability surface; CSP; per-command authz; keep webview runtime updated |
| RR-7 | OAuth-consent phishing (fake provider page in external browser flow) | user must verify URL | exact-match redirect URIs; provider allowlist; UX anti-phishing guidance |

(Retired: NSS-hook blind spots — owned rustls transport gives full
observation; see SECURITY.md A2.)

## 6. Review cadence

- Each phase end: Agent 6 re-scores scenarios §4 against implementation,
  updates RR table, records evidence in `docs/agents/agent-6-status.md`.
- New asset, boundary, or attacker capability → update this file first,
  then SECURITY.md, then TESTING.md. No silent scope/claim expansion.
