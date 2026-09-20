# KIWI — Local Test Mail Server Strategy (T-114)

> Owner: Agent 6. Decision record for how `kiwi-mail` protocol tests get a
> server to talk to. Implements TESTING.md §6.

## Decision

**Primary: in-process fakes** (tokio, owned by Agent 2 in the `kiwi-mail`
dev-harness). **Secondary interop profile: Mailpit (SMTP/POP3) + GreenMail
(IMAP) via Docker.** Transcript fixtures (`tests/fixtures/transcripts/`)
cover state-machine tests with zero infrastructure.

| Option | Verdict | Rationale |
|--------|---------|-----------|
| In-process fakes (tokio `TcpListener`, scripted peers) | **PRIMARY** | hermetic (no Docker/ports/host services); deterministic adversarial modes a real server can't do (strip STARTTLS, weak cipher only, hostile FETCH literals, truncated handshakes); fast; runs on CI and dev laptops identically |
| Mailpit (Docker: SMTP + POP3 + API/UI) + GreenMail standalone (Docker: IMAP) | **INTEROP PROFILE** | realistic server behavior, attachment round-trips, manual exploratory testing. Mailpit provably serves no IMAP (T-147: TCP accept, zero bytes) — GreenMail `standalone:2.1.14` fills exactly that gap (IMAP-only surface, zero-config test users). Gated behind an env flag so default `cargo test` never needs Docker |
| Dovecot (for IMAP) | rejected for now | real server, but needs baked Maildir + user config (custom image, ongoing maintenance); GreenMail covers the fixture need with less machinery. Revisit if authentic server quirks must be reproduced |
| MailHog | rejected | unmaintained; Mailpit covers the same ground maintained |
| Public test accounts (e.g. Ethereal) | rejected | network-dependent, credentials outside our control, violates local-first rule |

## Fake-server contract (Agent 2 implements; Agent 6 reviews)

Location proposal: `kiwi-mail/tests/common/fake.rs` (dev-dependency only —
fakes must never compile into the app binary).

- Ephemeral ports (`127.0.0.1:0`), one fake per test, no shared global state.
- Scripted modes per protocol:
  - SMTP: `Ok` (happy path), `AuthFail` (535), `NoStarttls` (EHLO without
    the extension → client must emit downgrade evidence), `WeakTlsOnly`
    (TLS with legacy suite for cipher findings), `TruncateData` (drop
    mid-DATA → client error, no hang: enforce read timeouts).
  - IMAP: `Ok` (LOGIN/SELECT/FETCH envelope), `UidValidityChange` (forces
    resync path), `HostileFetch` (absurd `{N}` literal size → client must
    bound/reject, never pre-allocate N), `ByeDrop` (untagged BYE + close).
  - POP3: `Ok` (USER/PASS/LIST/RETR/QUIT), `StlsOnlyAdvertised`,
    `ApopChallenge` (for `md5`-based APOP path, T-104).
- TLS modes: plaintext, STARTTLS/STLS-upgrade, implicit TLS — driven by
  the same rustls config shapes as production (test CA from
  `tests/fixtures/certs/`, never production roots).
- Every fake asserts the client's security-relevant behavior, not just
  protocol success: `TlsObservation` emitted (or explicit `unknown`),
  downgrade evidence on stripped upgrades, bounded handling of hostile input.

## How kiwi-mail tests run

```powershell
cargo test -p kiwi-mail                 # default: fakes only, hermetic, no Docker
KIWI_INTEROP=mailpit cargo test -p kiwi-mail -- --ignored   # interop profile (T-110+)
```

Interop profile requirements (when added): `tests/docker-compose.mailpit.yml`
(Mailpit SMTP :1025, IMAP :1143 + UI :8025), tests marked `#[ignore]` unless
`KIWI_INTEROP` is set, zero interference with default runs.

## Transcript fixtures

`tests/fixtures/transcripts/<proto>_<scenario>.txt` — hand-written,
synthetic line transcripts (`C:` client, `S:` server, wire is CRLF;
files use LF + trailing note). The fake harness replays them for
deterministic state-machine tests; Agent 3 may reuse SMTP/IMAP/POP3 shapes
for PCAP-generation cross-checks (T-012). Catalog:

| File | Scenario | Client must… |
|------|----------|--------------|
| `smtp_send_ok.txt` | EHLO → STARTTLS-ready → AUTH PLAIN → MAIL/RCPT/DATA → 250 → QUIT | complete send; emit `TlsObservation` at upgrade |
| `smtp_auth_fail.txt` | AUTH → `535` | surface auth failure; never retry with same creds blindly |
| `smtp_stripped.txt` | EHLO omits STARTTLS on a port/policy expecting TLS | emit `STARTTLS-STRIPPED` evidence; refuse or warn per policy |
| `imap_select_fetch.txt` | LOGIN → SELECT INBOX → FETCH envelope | parse envelope; sync by UID |
| `imap_hostile_fetch.txt` | FETCH with absurd `{999999999}` literal | bound/reject without allocating; input-quality finding |
| `pop3_retr.txt` | USER/PASS → LIST → RETR → QUIT | retrieve + UIDL dedup |
| `pop3_stls.txt` | STLS → upgrade → re-greet | emit `TlsObservation` at upgrade |

Rules: synthetic addresses only (`*.kiwi-test.invalid`); AUTH strings are
`base64("test-user")`-style dummies, never real credentials (secret-scan
enforced); each transcript has a MANIFEST.json entry (`suite: transcript`).
