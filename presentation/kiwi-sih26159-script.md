# KIWI × SIH26159 — Deep Presentation Script

**Problem statement:** SIH26159 — *SecureMailScope: AI-Assisted Cryptographic
Security Posture Assessment for Secure Email Communications* (NTRO ·
Blockchain & Cybersecurity · Software)

**Deck:** `KIWI-SIH26159-SecureMailScope.pptx` (6 slides, official SIH format)
**Runtime:** ~10 minutes at full depth. Cut markers `[TRIM]` show what to drop
for a 6-minute slot.

---

## SLIDE 1 — Title (0:00–0:30)

> "Good morning. We're presenting **KIWI — SecureMailScope**, our answer to
> problem statement **SIH26159** from NTRO: an AI-assisted cryptographic
> security posture assessment framework for secure email communications.
>
> Email still runs on three protocols designed before encryption existed —
> SMTP, IMAP, and POP3 — and TLS was bolted on afterwards. The result, as the
> problem statement notes, is an enormous deployed base of obsolete TLS
> versions, weak ciphers, broken STARTTLS negotiation, and expired or
> misconfigured certificates — all invisible to the people reading the mail,
> and only visible to tools like Wireshark as raw packets, with no verdict.
>
> KIWI is the layer that turns those packets into a verdict — with evidence."

---

## SLIDE 2 — The Idea (0:30–2:00)

> "Our proposed solution is a **passive network forensic engine** that ingests
> a PCAP file containing SMTP, IMAP, and POP3 traffic and answers the question
> the problem statement asks: *what is the cryptographic security posture of
> this email infrastructure?*
>
> It does this in three moves:
>
> **One — reconstruction.** It rebuilds complete TCP streams from the capture,
> identifies which streams are SMTP, IMAP, or POP3, detects where STARTTLS
> upgrades happen, and parses the TLS handshake itself — version, cipher
> suite, key exchange, and the X.509 certificates presented.
>
> **Two — deterministic verdicts.** A catalog of 37 rules evaluates each
> session: deprecated TLS versions, broken or weak cipher suites, missing
> forward secrecy, expired or self-issued certificates, STARTTLS downgrade
> indicators, cleartext credentials. Every finding carries typed evidence —
> the exact frames and stream offsets it came from.
>
> **Three — AI on top, never underneath.** An optional AI layer classifies
> risk, flags anomalous handshake patterns, and writes the plain-language
> summary an analyst reads first. But — and this is our core design rule —
> **the AI explains; it never asserts.** Every sentence it produces must cite
> the deterministic finding keys it grounds in, and our report builder
> literally rejects citations to findings that don't exist.
>
> The one thing that makes this entry unique: **KIWI is also a working mail
> client.** Every other submission is a sniffer. Ours sits at the endpoint —
> and that matters because TLS 1.3 encrypts the certificate itself, so a
> purely passive tool is blind where the endpoint can see everything. We cover
> the blind spot other tools can't."

*[Point at comparison table]*

> "Wireshark and Zeek decode — they don't assess. SSLyze and testssl.sh assess
> but only by actively probing a live server — useless when all you have is a
> capture from an incident last Tuesday. KIWI is the only row that is passive,
> email-native, scored, and self-verifying."

---

## SLIDE 3 — Technical Approach (2:00–5:30)

*[This is the deep section — the pipeline diagram is on screen.]*

> "Here's the pipeline, eight stages, and I'll walk it exactly as the code
> runs it — every stage is in our `kiwi-forensics` crate.

> **Stage 1 — PCAP ingest.** `PcapReader` reads classic `.pcap` and `.pcapng`,
> bounds-first: frame counts, byte limits, and truncation are enforced before
> any parsing happens, because a capture file is untrusted input. Truncated
> and malformed frames aren't fatal — they're *counted*.

> **Stage 2 — Decode.** We decode Ethernet, IPv4, and TCP only. Anything else
> — IPv6, VLAN tags, tunnels — is recorded as a counted skip with a reason,
> never silently dropped and never guessed.

> **Stage 3 — TCP reassembly.** The reassembler builds ordered byte streams
> per direction per flow. Overlapping segments resolve first-seen-wins —
> which is the safe choice against retransmission-injection tricks — and gaps
> in the sequence are *flagged as gaps*, surfaced in the report as a
> `stream-gap` limitation rather than papered over.

> **Stage 4 — Who's the server?** Role resolution runs in three steps:
> well-known mail ports first — 25, 465, 587, 143, 993, 110, 995 — then
> greeting content: whoever sent `220`, `+OK`, or `* OK` is the server, which
> catches dev servers on odd ports. Only then do we fall back to the TCP
> initiator.

> **Stage 5 — Protocol identification.** With roles resolved we fingerprint
> the application protocol — SMTP's `220`/`EHLO`, IMAP's tagged commands and
> `* OK`, POP3's `+OK`. Lines from both directions are interleaved by
> earliest covering frame, so we reconstruct the actual conversation, not two
> monologues.

> **Stage 6 — STARTTLS.** This is where the attacks live. We track the full
> state machine: was STARTTLS advertised, did the client request it, did the
> server accept, did the handshake actually complete — and critically, did
> **application data or a plaintext AUTH command cross the wire after the
> upgrade was requested**? That last signal is what separates 'STARTTLS
> didn't happen' from 'STARTTLS was *stripped*' — a positive downgrade
> indicator, our highest-severity finding.

> **Stage 7 — TLS handshake and certificates.** From the handshake bytes we
> extract the negotiated version, the cipher suite by its IANA identifier,
> the key-exchange mechanism — which is what lets us assess **forward
> secrecy** — session resumption, SNI and ALPN. Certificates come out leaf-
> first, up to 16 deep, with expiry windows, public-key algorithm and size,
> and signature algorithm. One honesty note we enforce in the contract: a
> capture can't prove a chain validates, so capture-based reports **never
> claim 'chain verified'** — they say `chain-unverified` as an explicit
> limitation. [TRIM: sentence ok to shorten]

> **Stage 8 — Rules and score.** Thirty-seven rules across eight categories
> evaluate each session. Severity is fixed per rule — info, low, medium,
> high, critical, worth 0 to 40 points — and confidence is a fixed
> multiplier: tentative halves it, firm takes 85%, certain is full weight.
> The score itself is **integer arithmetic only** — no floats, no clock, no
> RNG — so the same capture produces a byte-identical report on any machine,
> forever. Repeated findings in one scope count less — times 1, a half, a
> quarter — deductions cap at 100, and the remainder maps to a grade, A
> through F. Deterministic means *reproducible*, and reproducible means the
> report is evidence, not opinion.

> **The AI layer** sits strictly on top: it receives the findings, it writes
> the risk classification, the anomaly callouts, the remediation narrative —
> and it must cite which finding keys it's talking about. Citations to keys
> that don't exist get dropped and recorded as an `ai-uncited-keys`
> limitation. An AI that hallucinates a finding can't launder it into the
> report. And when AI is disabled or offline, the entire assessment still
> works — deterministically.

> **Output:** reports render JSON first — the canonical aggregate — with HTML
> and PDF as views over the same data. Exports are wrapped in a
> self-verifying SHA-256 envelope, so a forensic report can prove it wasn't
> altered after generation. Re-scanning a new capture diffs findings by
> stable key — new, resolved, unchanged, severity moved up or down — which is
> how you *prove* a remediation worked. And all of it lands in a hash-chained
> audit log. On screen: the dashboard — sessions, findings worst-first,
> score, and the AI summary that cites its evidence.

> **Tech stack:** one Rust workspace, edition 2024, `unsafe` forbidden
> workspace-wide; a Tauri 2 desktop shell with a React dashboard; SQLite
> local-first storage. No cloud dependency — it runs air-gapped, which is
> table stakes for a SOC tool."

---

## SLIDE 4 — Feasibility & Risks (5:30–7:00)

> "Feasibility first: this isn't a proposal, it's built. The PCAP pipeline,
> the rule engine, the scoring model, the self-verifying export, and the
> desktop shell exist and are CI-gated — cargo tests, clippy, frontend
> typecheck, and a headless-browser smoke suite on every commit. We develop
> against real mail servers — Mailpit for SMTP and POP3, GreenMail for IMAP —
> in Docker, plus the synthetic PCAP corpus attached to the problem
> statement.

> Now the honest risks, and how each is mitigated:

> **Risk one — TLS 1.3 encrypts certificates.** A passive sniffer literally
> cannot see the cert chain in a 1.3 session. Our mitigation is the hybrid
> model: because KIWI is *also* the mail client, our `TlsObservation` capture
> at the endpoint records the version, cipher, key exchange, and chain the
> connection actually negotiated — the ground truth passive capture can't
> reach. The same rules then evaluate both sources identically.
>
> **Risk two — real captures are messy.** Fragmentation, gaps, out-of-order
> segments. We don't guess: incomplete streams are flagged as limitations,
> and a finding requires a positive indicator — we never claim an attack from
> an absence.
>
> **Risk three — AI inventing findings.** Handled by contract, not by hope:
> uncited claims are mechanically stripped and recorded.
>
> **Risk four — heterogeneous stacks and downgrade tricks.** Addressed by the
> greeting-content role resolution, the STARTTLS positive-indicator rules,
> and lab validation against multiple server implementations.

> And viability: it's MPL-2.0 open source, runs offline on a normal laptop,
> deploys inside an air-gapped SOC, and produces no data egress — which is
> exactly the environment NTRO operates in."

---

## SLIDE 5 — Impact (7:00–8:00)

> "Four audiences benefit.

> **SOC, forensics, and incident-response teams** get posture triage in
> seconds — prioritized findings with evidence instead of a wireshark window
> and a deadline. The diff workflow answers the question IR always gets
> asked: *did the fix actually work?*
>
> **Government and enterprise administrators** get concrete remediation —
> 'upgrade this server's TLS floor', 'renew this certificate', 'this
> STARTTLS path is being stripped' — not a vague warning.
>
> **Auditors and compliance teams** get tamper-evident, self-verifying
> reports — the SHA-256 envelope means the report proves itself.
>
> **And India**: an offline-capable, open-source posture-assessment tool with
> no vendor lock-in and no data egress fits squarely in the sovereign
> security tooling direction — government mail infrastructure is exactly the
> deployment this problem statement cares about.

> Three protocols, four verdict tiers, one self-verifying report, and zero
> fabricated findings — that's the metric we're holding ourselves to."

---

## SLIDE 6 — References & Close (8:00–9:00)

> "The rules are grounded in the standards that actually govern this space:
> RFC 3207 and 2595 for SMTP and IMAP STARTTLS, RFC 8314 which deprecates
> cleartext mail entirely, RFC 8996 deprecating TLS 1.0 and 1.1, MTA-STS in
> RFC 8461, NIST SP 800-52r2 for TLS configuration, the CA/Browser Forum
> baseline requirements, and the MITRE ATT&CK techniques this detects —
> T1040 network sniffing and T1557 adversary-in-the-middle.
>
> And every claim in this deck is verifiable in the repository — the rule
> catalog, the scoring model, the contract documents are all checked in.

> So, to close: the problem statement asks for a tool that turns captured
> email traffic into a cryptographic verdict a SOC can act on. KIWI does
> that — passively, deterministically, verifiably — and then goes one step
> further: because it's also the endpoint, it sees what a sniffer can't.
>
> **KIWI doesn't ask you to trust it — it shows you the evidence.** Thank
> you. We welcome your questions."

---

# Appendix — Deep Q&A Bank

Anticipated jury questions with answers that go one level below the script.

**Q: TLS 1.3 encrypts the certificate — how do you assess posture you can't see?**
Two answers. From capture alone, we're *honest*: we extract everything that
remains visible — negotiated version, cipher, key exchange, resumption, SNI —
and record `chain-unverified` as a limitation instead of guessing. And the
hybrid advantage: KIWI is also the endpoint client, where `kiwi-mail`'s
transport layer records a `TlsObservation` — the actual chain, version, and
cipher negotiated — which flows through the *same* rule engine via the live
adapter. Passive where possible, endpoint truth where passive is blind.

**Q: How is this different from running Wireshark or Zeek?**
They decode; they don't assess. Wireshark will show you the TLS handshake
fields if you click through; it won't tell you the deployment is non-
compliant, won't score it, won't prioritize across a hundred sessions, and
won't give you a remediation. Zeek needs custom scripting to reach even part
of this. We produce the verdict, the evidence, and the report.

**Q: Why not just use SSLyze / testssl.sh?**
Those are *active* scanners — they need a live, reachable server and they
probe it. A forensic capture from a past incident, an air-gapped segment, or
an IDS export gives you packets, not a target to probe. Complementary tools;
different job. Also, our passive view shows what *clients actually
negotiated* — an active scan shows what the server *offers*, which misses
downgrade events that happened on the wire.

**Q: What does the AI actually decide?**
Nothing, by design — it *explains*. The verdict authority is the
deterministic rule engine; AI sits behind an abstraction writing risk
classification, anomaly callouts, and remediation narrative. Mechanically,
`AiEnrichment` carries `finding_keys` it must cite; the report builder drops
any citation to a nonexistent finding and records an `ai-uncited-keys`
limitation. If AI is off, the product loses the prose — never the verdict.

**Q: Your score — can two teams reproduce it?**
Byte-identically. Integer arithmetic only: severity points (0/5/12/25/40)
times a fixed confidence multiplier (0.5/0.85/1.0), round half-up per
finding, diminishing weight on repeats (×1, ½, ¼, ⅛…), deductions capped at
100, remainder maps to grade A–F. No floats, no clock, no RNG, fixed output
ordering. Same capture → same report → same grade, on any machine.

**Q: Can a finding ever have no evidence?**
No — the contract requires every finding to carry ≥1 typed evidence item
(frame numbers, stream offsets, redacted excerpt). The engine *drops*
evidence-less findings and counts them in `dropped_without_evidence`, which
must be zero in production — if it isn't, that's a bug we surface, not hide.

**Q: You're parsing captures containing credentials — how do you handle that?**
Redaction is a binding contract: `SafeText` strips control characters and
caps length on every excerpt; AUTH payloads, passwords, tokens, message
bodies, and private keys are structurally excluded — adapters quote at most
the command verb and reply code (`AUTH PLAIN → 235`). Certificate DER is
referenced by `{digest, len}`, never raw bytes. The report can't leak what
it never holds.

**Q: What about encrypted sessions where you see nothing?**
Said in the report, not hidden: a flow carrying bytes but yielding no
decodable lines emits `transport-unknown`/`kex-unobserved` limitations.
Encrypted captures are findings-light *by design and by declaration* —
that's what the endpoint vantage is for.

**Q: Is the "client" part real or slideware?**
Real: `kiwi-mail` has working SMTP/IMAP/POP3 clients (IMAP IDLE, POP3 UIDL),
SQLite + FTS5 store, MIME, rules, contacts — a full four-pane client in
Tauri + React. We develop it end-to-end against Mailpit and GreenMail in
Docker. The forensic engine reads the same transport truth the client
produces.

**Q: Scale — a SOC captures gigabytes?**
Bounds-first design: frame/byte limits enforced at ingest, excerpts bounded
per line, per-session evidence bounded (≤64 frames), flow/segment drops
counted as `capture-over-limit` rather than OOM. Rust throughout, single
binary, no external services required for core analysis.

**Q: Re-scan diffing — why does it matter?**
Because remediation needs proof. Findings have stable keys
(`rule_id | protocol:host:port`), so scan-fix-rescan produces a diff:
`new`, `resolved`, `unchanged`, `severity_increased/decreased`. An admin can
show 'the expired-cert finding resolved, no regressions' — that closes the
loop the PS asks for (identify → remediate → verify).

**Q: STARTTLS stripping — how do you detect an *attack* vs. a server that just doesn't offer it?**
Positive indicators only. `STARTTLS-001` (critical) requires evidence like
application data flowing before TLS completed, or a plaintext AUTH after the
client requested the upgrade. A server that simply doesn't advertise
STARTTLS is a different, lower-severity finding (`STARTTLS-002`, medium —
misconfiguration, not an attack claim). We never escalate absence into an
attack.

**Q: What do you do with TLS session resumption?**
Honest limitation: a resumed session abbreviates the handshake, so the key
exchange isn't observable — `KIWI-TLS-005` records it as info, and the
no-forward-secrecy rules are *suppressed* rather than guessing. Suppression
is documented, not silent blindness.

**Q: Where does this deploy?**
A desktop binary (~30 MB), fully offline-capable — suitable for analyst
workstations and air-gapped forensics labs. The org plane (Node + Postgres
admin service, localhost React UI) adds multi-user policy, mail-flow
metadata, and audit for enterprise rollout.

**Q: Provable provenance of the report itself?**
Exports are canonical bytes inside a self-verifying SHA-256 envelope;
internal mutations land in a hash-chained `audit.jsonl` (each record hashes
the previous, genesis-verified on open — corruption surfaces as
`audit-corrupt`, never hidden). The report proves the analysis; the audit
chain proves the report.

---

## Delivery notes

- **Total full depth ≈ 9–10 min.** For a strict 6-min slot: keep Slides 1–2
  at speed, compress Slide 3 to stages 1→3→6→8 + AI (skip 4,5,7 detail —
  point at the diagram), trim Slide 4 to the TLS-1.3 risk only.
- **Demo cue:** if you get demo time, the strongest 60 seconds is: ingest a
  capture with one clean IMAPS session + one STARTTLS-stripped SMTP session →
  the dashboard shows both reconstructed, the stripped one flagged critical
  with its evidence excerpt, the grade, and the AI summary citing the exact
  finding keys.
- **Never say** "the AI detects/decides" — always "the deterministic engine
  detects; the AI explains and prioritizes." That distinction is the pitch.
