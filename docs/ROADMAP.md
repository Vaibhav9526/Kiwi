# KIWI — Roadmap

> Owner: Lead Agent. Phases adapted to the standalone-client pivot (ADR-005);
> security mission unchanged.
> **Release rule (owner):** push to GitHub after each phase — work happens on
> `release/vX.Y.Z` branches; Lead merges to `main` and pushes at phase gates.

## Phase 0 — Standalone foundation — IN PROGRESS
- [x] Repo recon; Thunderbird checkout acquired (now read-only reference at `source/`)
- [x] docs/ source-of-truth set created
- [x] Cargo workspace + `kiwi-mail` skeleton (Lead)
- [ ] `kiwi-app` Tauri shell running (empty window → mailbox UI skeleton)
- [ ] `kiwi-mail` transport + SMTP/IMAP/POP3 happy-path vs local test server
- [x] kiwi-core / kiwi-forensics / kiwi-admin scaffolds
- [ ] Agent 6 gates green on all scaffolds

**Exit criteria:** `cargo test --workspace` green; `kiwi-app` launches;
kiwi-mail completes a send+receive round trip against a local test
mail server (e.g. mailpit/greenmail container or in-process fake);
every agent has a claimed task in TASKS.md.

## Phase 1 — Mail engine + security foundation
- kiwi-mail: full SMTP/IMAP/POP3 happy paths, MIME parse, account model,
  local mail store (SQLite + on-disk bodies), folder sync
- transport: `TlsObservation` capture on every connection
- kiwi-core: `SecuritySession` consumed from transport; trust engine live
- kiwi-forensics: deterministic analyzers consume live session events
- Initial security indicators in kiwi-app UI

## Phase 2 — Full client UX
- Mailbox views: unified inbox, folders, message list/detail, search
- Composer: rich text, attachments, drafts, send queue
- Contacts/address book
- Mailspring-inspired: snooze, send later, undo send, templates
- Account setup wizard (autoconfig), offline mode
- Security status surfaces per Agent 5 spec

## Phase 3 — Identity + trusted device
- SecureMail account identity, sessions, recovery
- Device enrollment/revocation, endpoint trust signals, native lock state

## Phase 4 — Mobile authenticator
- QR/local pairing, keystore keygen, challenge-response, approve/deny,
  replay protection, revocation

## Phase 5 — Forensics
- PCAP import UI, stream reconstruction, TLS evidence, forensic reports,
  re-scan/diff

## Phase 6 — Organization controls
- kiwi-admin service wired into client (policy fetch, outbound enforcement,
  mail-flow metadata), local React admin UI

## Phase 7 — Intelligence/enrichment (optional)
- SPF/DKIM/DMARC checks (native), CT, threat intel, AI explanations —
  graceful degradation

## Phase 8 — Hardening / release
- Security review, dep audit, secret scan, fuzzing, perf, packaging
  (Tauri bundle), update strategy, revocation recovery
