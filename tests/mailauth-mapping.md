# T-141 — mailauth fixture → mock-DNS → verdict mapping (Agent 6)

Companion to Agent 8's proposal (`docs/agents/agent-8-status.md` T-122) and
contract `docs/contracts/mailauth.md` §8. Each fixture below lists the
`MockResolver` builders reproducing it and the expected
`SpfOutput`/`DkimOutput`/`DmarcOutput`. Findings mapping (verdicts →
`kiwi-forensics` findings) lands with the forensics auth-analysis work;
`temperror` → limitation, `none` → absence of evidence (contract §8).

DNS fragments: `tests/fixtures/dns/mailauth.txt`. All names/addresses are
documentation space (`*.invalid`, `198.51.100.0/24`, `203.0.113.0/24`).

## Fixture table

| fixture | mock DNS (builders) | expected verdicts |
|---------|--------------------|--------------------|
| `messages/auth-spf-pass.eml` (From alice@kiwi-test.invalid) | `with_txt("kiwi-test.invalid", "v=spf1 ip4:198.51.100.7 -all")`, peer `198.51.100.7`, envelope-from `alice@kiwi-test.invalid` | SPF `pass`, decided_by `-all` |
| `messages/auth-spf-fail.eml` (same From) | same TXT, peer `203.0.113.9` (not authorized) | SPF `fail` |
| `messages/auth-dkim-valid.eml` | `with_txt("test._domainkey.kiwi-test.invalid", "v=DKIM1; k=rsa; p=<key>")` from `dns/mailauth.txt`; `now_unix` = send time | DKIM `pass` (rsa-sha256, simple/simple; signature verified by generator round trip) |
| `messages/auth-dkim-tampered.eml` | same key record | DKIM `fail` (body-hash mismatch) |
| `messages/auth-dmarc-reject-aligned.eml` (From alice@kiwi-test.invalid) | SPF pass (as above) + DKIM valid (as above) + `with_txt("_dmarc.kiwi-test.invalid", "v=DMARC1; p=reject; aspf=r; adkim=r")` | DMARC `pass`, `policy_applied: none` (aligned) |
| `messages/auth-dmarc-reject-spoof.eml` (From boss@kiwi-test.invalid) | SPF: envelope `crook@evil-test.invalid` + `with_txt("evil-test.invalid", "v=spf1 ip4:203.0.113.9 -all")` peer `203.0.113.9` (passes for evil domain, **misaligned** with From); no DKIM; `_dmarc.kiwi-test.invalid` reject record | SPF `pass` (unaligned) + DKIM `none` → DMARC `fail`, `policy_applied: reject` |
| `transcripts/smtp_auth-mixed-results.txt` | delivery of the spoof above (verdicts in-file comments) | SPF pass / DKIM none / DMARC fail+reject combo |

## Generation (reproducible)

DKIM keypair: fresh RSA-2048 (`crypto.generateKeyPairSync`), never reused
across runs — fixtures pin the signature, the DNS fragment pins the
matching `p=`. `c=simple/simple`, headers fold-free (simple == relaxed).
No `t=`/`x=` (avoids the 14-day expiry rule by omission). Tampered copy
differs by exactly one body line (verified by diff). Script kept out of the
repo; method recorded here.
