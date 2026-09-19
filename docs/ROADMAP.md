# KIWI — Roadmap

> Owner: Lead Agent. Phases mirror prompt.md §10. Status column updated as work lands.

## Phase 0 — Repository reconnaissance — IN PROGRESS
- [ ] Acquire Firefox + Thunderbird (`comm/`) source checkouts (Lead, in progress)
- [ ] Install MozillaBuild toolchain; verify VS Build Tools workloads (Lead)
- [ ] `mozconfig` with `--enable-project=comm/mail`; `./mach bootstrap` option 2
- [ ] Build unmodified Thunderbird successfully (BLOCKER for all TB integration)
- [ ] Map source paths for SMTP/IMAP/POP3/NSS/certs/auth/render/compose/accounts/startup/UI → ARCHITECTURE.md §5
- [x] Create docs/ source-of-truth set
- [x] Dispatch initial tasks to Agents 2–6

**Exit criteria:** `./mach build` completes; `mach run` launches unmodified
Thunderbird; source map published; every agent has a claimed task in TASKS.md.

## Phase 1 — Security foundation
- Normalized `SecuritySession` model in kiwi-core
- TLS/cert/cipher/key-exchange analyzers + forward-secrecy rules in kiwi-forensics
- Deterministic scoring engine (no AI dependency)
- Initial security status model + test fixtures
- **Depends on:** Phase 0 (fixtures + models can start in parallel)

## Phase 2 — Thunderbird integration
- Narrow native hooks into connection/security events
- Real account connection analysis against live SMTP/IMAP/POP3
- Security status UI surfaces in Thunderbird chrome
- Safe error handling; no regression to mail workflows
- **Depends on:** Phase 0 build + source map

## Phase 3 — Identity + trusted device
- SecureMail account identity, sessions, recovery model
- Device enrollment/registration/revocation
- Endpoint trust signals → trust state → native lock state
- **Depends on:** kiwi-core model (Phase 1), TB UI surfaces (Phase 2)

## Phase 4 — Mobile authenticator
- QR pairing, keygen in platform keystore, challenge-response
- Approve/deny UX, replay protection, revocation
- **Depends on:** Phase 3 device/session model

## Phase 5 — Forensics
- PCAP import, TCP reassembly, SMTP/IMAP/POP3 identification
- TLS evidence extraction, forensic reports, re-scan/diff
- **Depends on:** kiwi-forensics core (Phase 1)

## Phase 6 — Organization controls
- kiwi-admin local service, org/domain/user/role models
- Recipient-domain policies, mail-flow metadata, audit log
- Local React+TS admin UI
- **Depends on:** kiwi-admin scaffold (Phase 0 task T-004)

## Phase 7 — Intelligence / enrichment (optional)
- CT logs, SPF/DKIM/DMARC, threat intel, URL reputation, AI explanations
- All degrade gracefully when unavailable

## Phase 8 — Hardening / release engineering
- Security review, dependency audit, secret scanning, fuzzing
- Performance, update strategy, installer validation, revocation recovery
