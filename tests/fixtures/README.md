# KIWI — Test Fixture Catalog

> Owner: Agent 6. All fixtures are **synthetic**. Never commit real private
> mail, real credentials, real keys, or production captures. Generation
> method is documented per entry; `MANIFEST.json` is the machine-readable
> index consumed by `tests/tools/check_fixtures.py` and (from T-012) by the
> forensics crate runner.

## Naming scheme

- PCAP: `pcap/<proto>_<mode>_<tls>.pcapng`
  `<proto>` ∈ {`smtp`,`imap`,`pop3`}; `<mode>` ∈ {`plaintext`,`starttls`,
  `implicit-tls`,`stripped`}; `<tls>` ∈ {`notls`,`tls12`,`tls13`}.
  Edge cases append a suffix: `_expired-cert`, `_selfsigned`,
  `_weak-cipher`, `_malformed-NN`.
- Certs: `certs/<case>.pem` (+ `certs/<case>.key` only for synthetic test
  CAs documented here — never real keys; prefer publishing just the cert).
- Messages: `messages/<case>.eml` (synthetic MIME).

## PCAP catalog (T-012 acquisition plan — Agent 3 generates, Agent 6 reviews)

| File | Scenario | Generation | Expected findings |
|------|----------|------------|-------------------|
| `smtp_plaintext_notls.pcapng` | SMTP, no TLS offered | local test MTA (no TLS) + dumpcap | `TLS-ABSENT` |
| `smtp_starttls_tls12.pcapng` | SMTP STARTTLS → TLS 1.2, strong cipher | local MTA w/ TLS1.2-only + OpenSSL s_client session | clean baseline |
| `smtp_starttls_tls13.pcapng` | SMTP STARTTLS → TLS 1.3 | local MTA w/ TLS1.3 | clean baseline |
| `smtp_stripped_notls.pcapng` | server strips STARTTLS advertisement | MITM proxy removing 250-STARTTLS | `STARTTLS-STRIPPED` |
| `smtp_implicit-tls_tls12.pcapng` | SMTPS-465 style | local MTA implicit TLS | clean / version finding |
| `imap_plaintext_notls.pcapng` | IMAP plaintext | local Dovecot-equivalent, no TLS | `TLS-ABSENT` |
| `imap_starttls_tls12.pcapng` | IMAP STARTTLS → 1.2 | as above | clean baseline |
| `imap_starttls_tls13.pcapng` | IMAP STARTTLS → 1.3 | as above | clean baseline |
| `pop3_plaintext_notls.pcapng` | POP3 plaintext | local POP3, no TLS | `TLS-ABSENT` |
| `pop3_starttls_tls12.pcapng` | POP3 STLS → 1.2 | as above | clean baseline |
| `pop3_starttls_tls13.pcapng` | POP3 STLS → 1.3 | as above | clean baseline |
| `smtp_starttls_tls12_weak-cipher.pcapng` | weak suite negotiated | MTA restricted to legacy suite | cipher + forward-secrecy findings |
| `smtp_starttls_tls12_expired-cert.pcapng` | expired leaf | test CA, backdated cert | `CERT-EXPIRED` + chain evidence |
| `imap_starttls_tls12_selfsigned.pcapng` | self-signed | test CA | `CERT-UNTRUSTED` |
| `smtp_plaintext_notls_malformed-01-truncated-hello.pcapng` | truncated handshake | Scapy-crafted | input-quality finding, no panic |
| `smtp_plaintext_notls_malformed-02-overlap-streams.pcapng` | overlapping TCP segments | Scapy-crafted | input-quality finding, no panic |

Status Phase 0: all `planned` (see MANIFEST.json). Bytes land under T-012.

## Certificate fixtures (T-012; `openssl` synthetic, test-only CNs)

`valid-chain.pem`, `expired.pem`, `not-yet-valid.pem`, `self-signed.pem`,
`hostname-mismatch.pem`, `weak-sig-md5.pem` (legacy-alg rule),
`weak-sig-sha1.pem`, `rsa1024.pem`, `revoked.pem` (+ mini-CRL),
`wildcard.pem`, `san-multi.pem`. All subjects use `*.kiwi-test.invalid` /
`example.invalid` — never real domains. Generation commands recorded in
MANIFEST `generation` field when created.

## Message fixtures (synthetic `.eml`)

`normal-basic.eml`, `malformed-mime-boundary.eml`, `hostile-headers.eml`
(header injection attempts), `attachment-spoofed-ext.eml`,
`oversize-headers.eml` (cap test). Bodies are lorem-style filler.

## Rules

1. No real addresses, credentials, tokens, or private content — checker
   enforces via secret patterns.
2. Every binary fixture has a MANIFEST entry: `path`, `suite`, `status`
   (`planned`|`present`), `generation`, `expected_findings`.
3. `planned` entries need no file on disk; `present` entries must exist.
4. Size caps: individual fixture ≤ 5 MB; total `fixtures/` ≤ 100 MB.
5. PCAPs are treated as untrusted input (SECURITY.md B7) — parsers must
   handle every `malformed-*` file without panic (asserted in T-015).
