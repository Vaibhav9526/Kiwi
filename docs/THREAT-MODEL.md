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
- **Malicious sideloaded plugin (T-PLG)** *(T-268, Agent-25)*: a plugin the
  user installs is code executing inside the renderer — in the alpha model
  it runs as **trusted code** (no context isolation), so a hostile plugin
  can read anything the renderer can (mailbox UI state, DOM) and abuse the
  bridge surface. Sideload-only distribution keeps supply-chain scope at
  "user-chosen local files", but the code-exec risk is real and accepted
  for alpha only (RR-11).

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
| B9 sandbox guest (QEMU/WHPX, WSL2, Firecracker) | hostile payload executing in guest; escape attempt; tampered base image | per-run disposable instances; pinned immutable base; no host FS/creds/mailbox; no NIC default; watchdog; capability reporting; WSL2 shared-kernel caveat explicit | PoC lifecycle scripts; capability tests; QEMU/agent transcripts (pending provider crate) |
| B3b compose PG | tampered rows, DSN leak, migration failure | Drizzle-only access; reviewed migrations; least-privilege role; `.env` gitignored; DB-level append-only trigger + hash-chain verification | migration-apply + guard tests (T-133); env-coverage test |
| B10 renderer ↔ plugin code *(T-268, exec model T-306)* | hostile plugin reads mail state/DOM, exfiltrates via net, calls privileged bridge methods | declared-capability gate on every bridge method; lock gate rejects all calls while locked; sideload-only install (user-chosen local files); plugin code runs in a dedicated `blob:` `Worker` — **no DOM/`window`/`localStorage`/cookies/`__TAURI__` in plugin context**; worker inherits document CSP so plugin `fetch` is clamped by `connect-src`; per-session dedicated message port (no broadcast bus; host posts same-origin `/`, never `*`) | manifest/capability validation tests; lock-gate denial test; worker-isolation e2e (host-global leak probe); post-alpha: origin pinning + signing gate + resource limits |

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
13. **Sandbox unavailable** (no provider on host) → analysis reports
    `Unavailable`, UI marks the feature disabled — nothing executes on the
    host, ever.
14. **Guest misbehavior in sandbox** (fork-bomb, FS spray, egress attempt) →
    watchdog kills, overlay discarded / instance unregistered, report
    flagged `incomplete: true`; base image untouched.

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
| RR-8 | WSL2-tier shared kernel (guest→guest escape reaches sibling distros) | interim tier; hypervisor-vs-host boundary holds | QEMU/WHPX dedicated-kernel target; caveat in UI copy; never claim full isolation on this tier |
| RR-9 | Container escape (compose services share host kernel) | accepted: containers are infra, never the hostile-code boundary | hostile content restricted to VM sandbox (B9); no mailbox/credential mounts in compose |
| RR-10 | PG data-volume tampering/disposal on dev hosts | dev posture; file-permission + user-separation only | explicit backup story before any shared deployment; secrets never in DB (rule 16) |
| RR-11 | **Plugins execute as trusted code** — narrowed T-306: plugin source runs in a dedicated `blob:` `Worker`, so a sideloaded plugin can no longer reach DOM/mailbox globals/cookies/`__TAURI__` directly, and its `fetch` is clamped by the inherited `connect-src`. Residuals: shared process (CPU/memory abuse), no origin pinning on the port, no signing; manifest capabilities are a *declared contract*, enforced at bridge-method level only | **Owner amendment 2026-09-25 (planner ITEM B): alpha ships trusted-code plugins.** T-306 landed the worker exec under strict CSP — the ONLY CSP delta was `worker-src 'self' blob:` (index.html meta + tauri.conf.json); `'unsafe-eval'` was deliberately NOT added (B2 backstop stays intact). Live-verified in the built app | Post-alpha hardening task: origin pinning, capability re-validation at the context boundary, no IPC-adjacent caps for unsigned plugins, resource limits, review/signing gate |
| RR-12 | **`KIWI_DEV_PLAINTEXT=1` dev fixture mode** — when set, `allow_plaintext_auth` is enabled for **loopback hosts only** (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost` literals — DNS answers never qualify) and loopback plaintext sessions record a `plaintext-transport` signal at `Info` severity instead of the locking cascade. Risk: an operator who exports the var on a real machine weakens B1 protection for loopback services only — a malicious local process could accept plaintext creds on a loopback socket. Non-loopback hosts keep full posture regardless of the flag | Accepted for local-mail-fixture development (Mailpit/GreenMail are unreachable otherwise): opt-in env only, never a shipped default; session still recorded as evidence (downgraded, not hidden); persistent visible `DEV — plaintext allowed` chip in the status bar whenever active | Ship a launcher script that scopes the env to the dev invocation; evaluate a build-time `cfg` compile-out for release channels |

(Retired: NSS-hook blind spots — owned rustls transport gives full
observation; see SECURITY.md A2.)

## 6. Review cadence

- Each phase end: Agent 6 re-scores scenarios §4 against implementation,
  updates RR table, records evidence in `docs/agents/agent-6-status.md`.
- New asset, boundary, or attacker capability → update this file first,
  then SECURITY.md, then TESTING.md. No silent scope/claim expansion.
