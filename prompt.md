# KIWI — Master Multi-Agent Build Prompt

## 0. Where to paste this prompt

Paste this entire prompt into **Devin SWE-2 Agent #1** and designate that agent as the **Lead / Technical Orchestrator**.

Use the other five agents according to the role assignments in Section 6. The Lead Agent owns architecture, task decomposition, integration, conflict resolution, and final quality gates.

---

# 1. PROJECT IDENTITY

Project name: **KIWI**

KIWI is a security-first desktop email platform built by **directly modifying the Thunderbird desktop source code**. Thunderbird remains the actual email client and normal user experience: inbox, folders, compose, send, receive, search, contacts, attachments, account management, etc. must continue to work like Thunderbird.

KIWI adds a serious security platform on top of the existing Thunderbird mail stack:

- SecureMail/KIWI account identity: sign up, sign in, recovery, sessions.
- Underlying email account integration: SMTP / IMAP / POP3 and supported authentication/OAuth flows.
- SMTP / IMAP / POP3 security analysis.
- STARTTLS/TLS inspection.
- Certificate and certificate-chain analysis.
- Cipher-suite and key-exchange analysis.
- Forward-secrecy assessment.
- Cryptographic weakness/misconfiguration detection.
- Explainable deterministic risk scoring.
- AI-assisted explanations, correlation, remediation guidance, and report summarization.
- Passive PCAP/network-traffic forensic analysis.
- Evidence-based security reports.
- Weakness -> evidence -> impact -> remediation -> re-scan/diff workflow.
- Trusted-device and endpoint-integrity posture.
- Suspicious remote-session/endpoint indicators.
- Native Thunderbird lock state when trust is sufficiently reduced.
- Independent mobile authenticator using asymmetric challenge-response.
- Device registration, device revocation, session management.
- Organization/admin controls.
- Recipient-domain restrictions and outbound policy enforcement.
- Mail-flow metadata visualization and audit history.
- SPF/DKIM/DMARC and related domain-security checks.
- Optional threat-intelligence / CT / reputation enrichment.
- Tamper-evident audit logging and forensic exports.
- Local-first operation during development; no public hosting is required for the initial build.

This is intended to become a **large long-term project**, not a throwaway demo.

---

# 2. CORE PRODUCT PRINCIPLES

1. **Modify Thunderbird directly.** Do not build a separate mail client that merely imitates Thunderbird.
2. **Do not rebuild existing Thunderbird mail functionality.** Reuse Thunderbird's SMTP/IMAP/POP3, message rendering, account management, synchronization, and networking capabilities wherever possible.
3. **Keep the Thunderbird user experience familiar.** Do not redesign the whole mail client. Add KIWI security functionality naturally inside the existing product.
4. **Security decisions must be evidence-driven.** Deterministic rules are authoritative for technical findings. AI is an explanation/correlation layer, not the final security authority.
5. **Never invent security findings.** Every reported issue must have reproducible evidence and a test case.
6. **Do not claim universal malware detection.** Endpoint protection must be described as detection of measurable indicators/anomalies and trust reduction, not perfect compromise detection.
7. **Use established cryptography and platform security APIs.** Never invent cryptographic algorithms or protocols.
8. **Prefer local processing and least privilege.** Do not send message contents or credentials to external services unless explicitly required and approved.
9. **Secrets must never be logged.** Never commit API keys, passwords, tokens, private keys, OAuth secrets, or test credentials.
10. **No fake/mock security functionality in core paths.** Stubs are allowed only when explicitly marked and isolated behind interfaces with tests.

---

# 3. CURRENT TECHNICAL DIRECTION

Use the technology that best fits the actual current Thunderbird source tree, while following these target choices unless repository constraints require another approach.

### Desktop / Thunderbird

- Official Thunderbird desktop repository/source tree.
- Thunderbird's native C++/Mozilla platform code.
- JavaScript / HTML / CSS for Thunderbird UI and frontend code where appropriate.
- Rust where it materially improves security-critical standalone services/components and integrates cleanly with the Mozilla build system.
- NSS/NSPR and Thunderbird's existing TLS/security primitives rather than introducing a second TLS implementation.

Important: do not blindly assume the repository layout from older tutorials. First inspect the current checkout and official current Thunderbird developer/build documentation. The official Thunderbird desktop repository currently describes Thunderbird code as the `comm/` directory integrated with the Mozilla/Firefox codebase; use the repository actually present on disk and its current build instructions.

### Security / forensics

Preferred directions:

- NSS for TLS/certificate information where possible.
- Npcap/libpcap for live packet capture where required.
- Scapy/dpkt or an equivalent well-maintained packet parsing stack for forensic analysis if Python is used for the PCAP engine.
- Rust is preferred for a long-lived standalone security/forensics engine when practical.
- OpenSSL CLI may be used for controlled test/debug tooling, but do not replace Thunderbird/NSS's runtime TLS stack without a justified reason.

### Local data/control plane

- SQLite first for local-first development.
- Clear interfaces so PostgreSQL can be introduced later for organization-scale deployment.
- Local service/control plane can be implemented in Rust or Node.js/TypeScript depending on the component and integration constraints.

### Admin UI

- React + TypeScript for the standalone/local administration interface.
- Keep it local during initial development.

### Mobile authenticator

- React Native or native mobile implementation.
- Android Keystore and iOS Keychain/Secure Enclave where supported.
- FCM/APNs for push notifications only if remote push is needed later; local-network pairing must remain possible for development.

### AI

- AI is an optional enhancement.
- Support either a local model or an external model API behind an abstraction.
- The deterministic security engine must work when AI is disabled or unavailable.

---

# 4. BRAND / ASSET RULE

The project already has an `images/` folder supplied by the owner. It contains the **KIWI logo, favicon, and banner**.

Before creating branding assets:

1. Inspect the existing `images/` directory.
2. Reuse those assets where applicable.
3. Do not overwrite them unless explicitly requested.
4. Keep branding consistent with the supplied assets.
5. Do not invent a replacement logo when an official project asset exists.

---

# 5. SOURCE-OF-TRUTH DOCUMENTATION TO CREATE

At the beginning of the project, create and maintain:

- `docs/ARCHITECTURE.md` — system architecture and module boundaries.
- `docs/ROADMAP.md` — prioritized implementation plan.
- `docs/TASKS.md` — task ledger with owner, status, dependencies, files, tests.
- `docs/SECURITY.md` — threat model, security assumptions, trust boundaries, secure coding rules.
- `docs/TESTING.md` — unit/integration/E2E/security testing strategy.
- `docs/DECISIONS.md` — architecture decision records.
- `docs/AGENT_HANDOFF.md` — work handoffs, blocked tasks, agent-limit recovery.
- `docs/API_CONTRACTS.md` — stable internal interfaces between Thunderbird, security engine, local service, mobile authenticator, and admin UI.
- `docs/THREAT-MODEL.md` — attacker capabilities, assets, trust boundaries, mitigations, residual risk.

Never let the project knowledge live only inside chat messages.

---

# 6. AGENT ROLES

## Agent 1 — Devin SWE-2 — LEAD / INTEGRATOR / ARCHITECT

**This is where the master prompt is pasted.**

Responsibilities:

- Own overall architecture and repository strategy.
- Inspect the real Thunderbird checkout before assigning implementation tasks.
- Map relevant Thunderbird code for SMTP, IMAP, POP3, TLS/NSS, certificates, authentication, message access/rendering, compose/send, preferences, startup/session lifecycle, and UI integration.
- Create the initial roadmap and task ledger.
- Assign tasks to the other agents.
- Review cross-agent changes.
- Resolve architectural conflicts.
- Own integration branches/merge order.
- Maintain API contracts and decision records.
- Enforce the no-duplicate/no-parallel-conflict rule.
- Run final end-to-end verification after each major milestone.
- Perform release/build packaging work.

The Lead Agent may create subagents for:

- repository archaeology
- dependency research
- architecture review
- integration testing
- build/debug investigation

The Lead Agent must NOT blindly rewrite large areas of Thunderbird. First understand the current implementation and identify the narrowest safe integration points.

---

## Agent 2 — Devin SWE-2 — CORE SECURITY + TRUSTED SESSION ENGINE

Primary responsibilities:

### Thunderbird security integration

- Identify and integrate with native TLS/NSS information.
- Build the internal normalized security-session model.
- Hook SMTP/IMAP/POP3 connection/security events at the narrowest reliable integration points.
- Extract negotiated TLS version, cipher suite, certificate data, key exchange, authentication/security metadata where available.
- Implement secure connection status inside Thunderbird.

### Endpoint trust

- Device registration.
- Device identity.
- Endpoint integrity signals.
- Suspicious session indicators.
- Remote-session indicators.
- Session trust state.
- Lock/unlock state.
- Securely prevent sensitive mailbox access while locked.
- Ensure unlock requires the independent authenticator path when policy says so.

### SecureMail identity

- Account/session model.
- Credential/session handling.
- Device registration and revocation interfaces.
- Recovery model.

Use subagents for:

- Thunderbird source mapping
- Windows endpoint research
- secure authentication review
- lock-state testing

Do not implement an antivirus/EDR. Build measurable, bounded indicators and an auditable trust decision.

---

## Agent 3 — Cline + DeepSeek v4.1 Flash — FORENSICS / PCAP / TLS RULE ENGINE

Primary responsibilities:

### Security analysis engine

- Normalized protocol/security data model.
- SMTP analyzer.
- IMAP analyzer.
- POP3 analyzer.
- STARTTLS analysis.
- TLS handshake parsing where available.
- Certificate analysis.
- Cipher-suite analysis.
- Key-exchange analysis.
- Forward-secrecy assessment.
- Cryptographic weakness rules.
- Deterministic security scoring.

### PCAP forensics

- `.pcap` / `.pcapng` ingestion.
- Packet parsing.
- TCP stream reconstruction.
- Protocol identification.
- SMTP/IMAP/POP3 session reconstruction where possible.
- TLS handshake metadata extraction.
- Evidence records.
- Forensic timeline.

### Reports

- Finding model.
- Evidence model.
- Impact/remediation fields.
- JSON/HTML/PDF report pipeline.
- Re-scan diff model.

Use subagents for:

- packet parsing research
- protocol test generation
- certificate/TLS test fixtures
- fuzz/property testing

The core analyzer must function without AI.

---

## Agent 4 — Cline + GLM 5.3 Flash — ORGANIZATION / POLICY / ADMIN CONTROL PLANE

Primary responsibilities:

### Organization model

- Organizations.
- Domains.
- Users.
- Roles/admin permissions.
- Devices.
- Security policies.

### Mail policies

- Allowed recipient domains.
- Blocked recipient domains.
- External-recipient warning/block rules.
- Minimum TLS/security requirements.
- Attachment/content policy interfaces.

### Mail-flow metadata

- Sender.
- Recipient.
- Timestamp.
- Direction.
- Message ID.
- Security status.
- Audit events.

Do not store full message bodies by default for admin analytics.

### Admin/control service

- Local API/service.
- Policy distribution.
- Audit logging.
- Role-based access control.
- Mail-flow queries.
- Security-event queries.

Use subagents for:

- policy engine design
- local API contract review
- authorization/security testing
- database schema review

Actual enterprise enforcement should eventually be possible at a mail gateway/relay layer; never represent a UI-only block as complete organizational enforcement.

---

## Agent 5 — OpenCode Muse 1.3 Contributor #1 — THUNDERBIRD UI / UX / BRANDING

Primary responsibilities:

- Preserve the Thunderbird visual language and normal workflows.
- Integrate KIWI security indicators into existing Thunderbird UI without turning the product into a dashboard-only app.
- Secure connection status UI.
- Account security panel.
- Risk/finding details.
- Native lock screen.
- Authenticator waiting/verification UI.
- Security event details.
- Re-scan/diff UI.
- Local admin UI if needed.
- Use the provided `images/` logo/favicon/banner assets.
- Accessibility and keyboard navigation.
- Responsive behavior for local web admin surfaces.

Use subagents for:

- UI audit
- accessibility audit
- visual consistency review
- manual workflow testing

Every UI change must be checked for:

- broken Thunderbird workflows
- overflow/clipping
- keyboard navigation
- focus handling
- error states
- locked/unlocked states
- dark/light theme compatibility where relevant

Do not redesign Thunderbird wholesale.

---

## Agent 6 — OpenCode Muse 1.3 Contributor #2 — QA / TESTING / SECURITY ASSURANCE / DOCS

Primary responsibilities:

- Build the test strategy and executable tests.
- Unit tests.
- Integration tests.
- End-to-end tests.
- Security regression tests.
- PCAP fixture tests.
- TLS/certificate fixture tests.
- Account login/session tests.
- Lock/unlock tests.
- Authenticator challenge/replay/rejection tests.
- Policy enforcement tests.
- Permission/authz tests.
- Secret-leak tests.
- Static analysis/linting/build checks.
- Performance/regression tracking.
- Maintain `docs/TESTING.md`, `docs/SECURITY.md`, and test evidence.

Use subagents for:

- test generation
- security review
- fuzz/property testing
- UI smoke testing

This agent has authority to mark a task **NOT READY** when evidence is missing, even if the implementation appears complete.

---

# 7. SUBAGENT RULES — MANDATORY FOR ALL AGENTS

Every primary agent should create subagents when a task can be independently researched/tested, but subagents must follow these rules:

1. First inspect the existing implementation.
2. Never duplicate work already assigned in `docs/TASKS.md`.
3. Never edit another agent's active files/modules without coordination.
4. Report exact files changed.
5. Report commands run.
6. Report tests run and their results.
7. Report assumptions.
8. Report remaining risks.
9. Never mark a task complete without verification evidence.
10. If the subagent reaches a tool/model limit, crashes, or encounters an unavailable capability, write a handoff entry and return the unfinished work to the parent agent.

---

# 8. TASK OWNERSHIP / CONFLICT RULE

Before editing:

- Read `docs/TASKS.md`.
- Claim the task by adding your agent ID, status, target files, and expected outputs.

No two agents should concurrently rewrite the same major source files.

If two tasks touch the same file:

- split responsibilities by function/module, or
- have the Lead Agent serialize the work, or
- create an explicit integration task.

Never solve merge conflicts by blindly accepting one entire side.

---

# 9. AGENT LIMIT / FAILURE-HANDOFF RULE

If an agent reports any of the following:

- quota reached
- context limit reached
- usage limit reached
- execution limit reached
- tool unavailable
- repeated runtime error
- agent stopped unexpectedly

then the task **must immediately become transferable**.

Required procedure:

1. Update `docs/AGENT_HANDOFF.md`.
2. Record:
   - task ID
   - current status
   - completed work
   - incomplete work
   - modified files
   - tests already run
   - known failures
   - next exact action
3. Remove the task from the failed/limited agent's active ownership.
4. The Lead Agent redistributes it to an available agent based on capability:
   - Thunderbird/core/security → Devin
   - forensics/protocol/testing → DeepSeek Cline
   - organization/admin/policy → GLM Cline
   - UI/UX → Muse
   - QA/security verification → Muse QA agent
5. The replacement agent must read the handoff before starting.
6. Never restart completed work from scratch unless the previous implementation is invalid.

If multiple agents hit limits, redistribute by dependency and unblock the highest-value path first.

---

# 10. DEVELOPMENT PHASES

## Phase 0 — Repository reconnaissance

Before major coding:

- Inspect the actual repository.
- Build Thunderbird unchanged.
- Verify the development toolchain.
- Identify the current Thunderbird source layout.
- Map SMTP/IMAP/POP3/TLS/NSS/authentication/UI/session code.
- Record findings in `docs/ARCHITECTURE.md`.

Do not begin broad implementation until the basic build is known to work.

## Phase 1 — Security foundation

- Normalized connection-security model.
- TLS/certificate/cipher analyzer.
- Deterministic rule engine.
- Initial security UI.
- Test fixtures.

## Phase 2 — Thunderbird integration

- Native security hooks.
- Real account connection analysis.
- Security status in the Thunderbird UI.
- Safe error handling.

## Phase 3 — Identity + trusted device

- SecureMail account identity.
- Device enrollment.
- Session security.
- Endpoint trust signals.
- Native lock state.

## Phase 4 — Mobile authenticator

- QR/device pairing.
- Key generation.
- Challenge-response.
- Approve/deny.
- Replay protection.
- Device revocation.

## Phase 5 — Forensics

- PCAP import.
- TCP stream reconstruction.
- SMTP/IMAP/POP3 identification.
- TLS evidence extraction.
- Forensic report generation.
- Re-scan/diff.

## Phase 6 — Organization controls

- Local admin service.
- Organization/domain/user models.
- Recipient policies.
- Mail-flow metadata.
- Audit logs.

## Phase 7 — Intelligence/enrichment

Optional integrations:

- Certificate Transparency.
- SPF/DKIM/DMARC.
- Threat intelligence.
- URL reputation.
- AI explanations.

These must degrade gracefully when unavailable.

## Phase 8 — Hardening / release engineering

- Security review.
- Dependency audit.
- Secret scanning.
- Fuzzing/property tests where appropriate.
- Performance testing.
- Upgrade/update strategy.
- Installer/package validation.
- Recovery/revocation testing.

---

# 11. SECURITY DESIGN REQUIREMENTS

Mandatory:

- Never store private authenticator keys in plaintext.
- Never log credentials or tokens.
- Encrypt sensitive local state where practical.
- Use least privilege.
- Authenticate and authorize admin operations.
- Prevent replay of authenticator challenges.
- Bind challenges to the specific device/session/event.
- Validate all externally supplied data.
- Treat PCAP data as untrusted input.
- Treat email contents and attachments as untrusted input.
- Sandbox risky parsing where practical.
- Keep security findings deterministic and auditable.
- Make all elevated actions auditable.
- Maintain a clear trust boundary between Thunderbird, local security service, mobile device, and admin controls.

---

# 12. AI SECURITY REQUIREMENTS

AI may:

- explain findings
- summarize incidents
- correlate findings
- describe impact
- suggest remediation
- summarize re-scan differences

AI may NOT be the sole authority for:

- certificate validity
- TLS version detection
- cipher classification
- authentication success
- policy enforcement
- endpoint trust decision

Every AI response about a security event must be grounded in structured findings/evidence.

When AI is unavailable, KIWI must still perform core security analysis.

---

# 13. TESTING CONTRACT — APPLY THROUGHOUT DEVELOPMENT

Every feature must have appropriate verification.

### For security features

Test at minimum:

- valid configuration
- invalid configuration
- weak configuration
- missing configuration
- network failure
- malformed input
- downgrade/stripping indicators where reproducible
- certificate edge cases
- authentication failure
- stale/replayed authenticator challenge
- unauthorized admin access

### For UI

Test:

- normal workflow
- error state
- loading state
- locked state
- unlock state
- keyboard navigation
- accessibility
- theme compatibility
- resize/overflow

### For Thunderbird integration

Test:

- account setup
- login
- receive mail
- send mail
- folders
- compose
- attachments
- message rendering
- reconnect
- offline/online transitions
- security alert/lock transitions

### For PCAP

Maintain fixtures for:

- SMTP plaintext
- SMTP STARTTLS
- SMTP TLS 1.2
- SMTP TLS 1.3
- IMAP equivalents
- POP3 equivalents
- invalid/expired certificates
- weak cipher configuration
- malformed packet streams

Never use real private email or sensitive production data in fixtures.

---

# 14. QUALITY GATE FOR COMPLETING ANY TASK

A task is **DONE** only when all applicable conditions are satisfied:

- Code implemented.
- Existing behavior preserved.
- Tests added/updated.
- Tests pass.
- Security implications reviewed.
- No secrets introduced.
- Documentation updated.
- Exact files changed recorded.
- Build/lint/static checks pass where applicable.
- UI manually inspected when UI is affected.
- Handoff note exists for unresolved risks.

A task may be marked **BLOCKED** instead of DONE when infrastructure or an external dependency prevents completion.

Never hide failures.

---

# 15. CODE QUALITY RULES

- Prefer small, composable modules.
- Avoid giant files and giant classes.
- Keep Thunderbird modifications narrowly scoped.
- Use clear interfaces between components.
- Avoid duplicated business/security logic.
- Prefer strongly typed structured security findings.
- Validate boundaries between JS/C++/Rust/services.
- Write comments for security-sensitive decisions, not obvious code.
- Preserve existing Thunderbird conventions where practical.
- Keep new dependencies minimal and justified.
- Pin or otherwise control security-sensitive dependency versions appropriately.

---

# 16. LOCAL-FIRST RULE

The current project can run entirely locally.

Do NOT block progress waiting for cloud hosting.

Use:

- local SQLite
- local services
- local admin UI
- local test mail accounts/servers
- local PCAP fixtures
- local authenticator pairing when practical

External APIs are optional enrichment and must have graceful fallbacks.

Do not turn this into a public SaaS architecture unless explicitly requested later.

---

# 17. IMPORTANT PRODUCT BEHAVIOR

KIWI should still feel like Thunderbird.

The security system should become visible when useful:

- account security status
- connection warnings
- certificate details
- security findings
- locked state
- authenticator request
- organization policy messages

Do not fill the normal mail UI with unnecessary security noise.

---

# 18. FIRST EXECUTION INSTRUCTIONS FOR THE LEAD AGENT

Start by doing the following in order:

1. Inspect the repository and its current branch/state.
2. Locate the `images/` folder and verify the supplied KIWI branding assets.
3. Build the unmodified/current Thunderbird checkout successfully.
4. Read the current official Thunderbird build/development guidance relevant to the checkout.
5. Identify the current source paths for:
   - SMTP
   - IMAP
   - POP3
   - TLS/NSS
   - certificate handling
   - authentication
   - mail message loading/rendering
   - compose/send
   - account/server configuration
   - startup/session lifecycle
   - relevant UI surfaces
6. Do NOT start broad refactors.
7. Create `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/TASKS.md`, `docs/SECURITY.md`, `docs/TESTING.md`, `docs/DECISIONS.md`, `docs/AGENT_HANDOFF.md`, `docs/API_CONTRACTS.md`, and `docs/THREAT-MODEL.md`.
8. Assign the initial tasks to the other five agents according to Section 6.
9. Require each agent to inspect existing code before editing.
10. Establish the initial integration/test strategy.
11. Only then begin implementation.

The Lead Agent must report back with:

- current repo/build status
- source-map findings
- initial architecture
- assigned tasks
- dependencies
- first milestone acceptance criteria
- exact next actions for every agent

---

# 19. OFFICIAL REFERENCE STARTING POINTS

Use current official Thunderbird documentation rather than stale tutorials:

- Thunderbird desktop repository: https://github.com/thunderbird/thunderbird-desktop
- Thunderbird codebase overview: https://developer.thunderbird.net/thunderbird-development/codebase-overview
- Thunderbird developer resources: https://developer.thunderbird.net/add-ons/resources
- Thunderbird extension/Experiment documentation: https://developer.thunderbird.net/add-ons/mailextensions/experiments

These references are starting points only. Always inspect the actual checkout and current documentation before making repository-specific assumptions.

---

# 20. FINAL OPERATING PRINCIPLE

Build KIWI as a real product.

Do not optimize for producing lots of code. Optimize for:

**correct architecture + real Thunderbird integration + measurable security + independent authentication + reproducible evidence + strong testing + maintainability.**

Every agent owns code, evidence, tests, and documentation—not just implementation.

When uncertain, inspect the source, create a focused experiment/test, document the result, and then implement the smallest reliable change.
