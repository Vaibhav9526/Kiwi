# Contract — Account Autoconfiguration (`kiwi-autoconfig`)

> Owner: Agent 8 · **Contract version: `kiwi.autoconfig/1`** · Status: final
> (T-135, T-158) · Implemented by `kiwi-autoconfig/` (Rust). This document is
> authoritative for stage order, wire spellings, and the attempt-trail
> shape. Changes require Lead review → record in DECISIONS.md.

Parties: `kiwi-autoconfig` (suggestions + evidence trail) → `kiwi-app`
setup wizard (Agent 5, T-156) → `kiwi-mail` account model.

**Secret/connection invariant (amended 2026-09-25, drift-audit ACFG-1):**
the discovery pipeline emits **no secrets and never opens connections** —
credential keys are derived deterministically; the app layer binds them
to the OS keystore. The `oauth2` module (T-195, `kiwi.oauth2/1`) is the
documented exception: it performs grant acquisition over HTTPS-only
endpoints via the `OAuthTransport` seam. Its secrets invariant is
stronger but differently worded — **no secrets in the DB, in plaintext
files, or in logs; the OS credential store is the sanctioned sink** —
`TokenSet` material persists only via
`kiwi_mail::account::CredentialStore`, never in mail.db or a file, and
`Debug` surfaces are redacted.

## 1. Invariants (binding)

- Deterministic: same inputs (email, `DiscoveryNet` responses, ISPDB
  table) → same `DiscoveryOutcome`. No floats, no RNG, no wall clock.
- Discovery never fails for a valid email: the only `Err` is
  `Error::InvalidEmail`. Everything else falls through stages to a
  usable result.
- Every stage attempt is recorded — a caller can always answer *why is
  this suggestion flagged for review?* from `attempts` alone.
- No secrets, no tokens, no message content in discovery output. Only
  published server facts (hosts, ports, socket security, credential
  *kind*). The OAuth2 acquisition submodule (T-195) handles token
  material under its own contract (`kiwi.oauth2/1`): the OS credential
  store is the only persistence sink — never the DB, never plaintext,
  never logs.
- Unknown enum values / new fields ignored, not fatal (serde
  `snake_case` everywhere).
- `contract_version` is `"kiwi.autoconfig/1"` (`CONTRACT_VERSION`).
- Offline-first: a hit in the bundled ISPDB fixtures short-circuits all
  network stages. With an empty `MockNet`, discovery still returns a
  usable (flagged) suggestion.

## 2. Email / domain validation

- `split_email`: ≤`MAX_EMAIL_LEN` (256) total; exactly one `@`
  separating a non-empty local part (charset `[A-Za-z0-9._%+\-']`,
  no leading/trailing/double dots) from a valid domain. Local-part case
  is preserved; domain is lowercased.
- `DomainName::parse`: ≤`MAX_DOMAIN_LEN` (253); lowercase, trailing dot
  stripped; labels 1–63 chars, `[a-z0-9-]`, no leading/trailing label
  hyphen. Rejected: empty, all-dot, invalid bytes.

## 3. Discovery pipeline (stage order is binding)

`discover(email, net)` / `discover_with_table(email, net, table)` run
stages in order; first hit wins; every run records a `StageAttempt
{ source, outcome, detail }`:

| # | `source` | input | outcome on failure |
|---|----------|-------|--------------------|
| 1 | `ispdb` | bundled (or caller) fixture table, exact-then-parent-domain lookup | `miss` |
| 2 | `autoconfig_host` | `https://autoconfig.<domain>/mail/config-v1.1.xml` | `unreachable` / `malformed` / `unsupported` |
| 3 | `well_known` | `https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml` | same as above |
| 4 | `mx_heuristic` | MX records → provider-suffix hint, else pattern guess `imap.<domain>:993` + `smtp.<domain>:587` | `miss` |
| 5 | `manual` | prefilled `ManualEntry::blank` placeholders | n/a (defense-in-depth; reached only if stage 4's guess fails `checked()`) |

- Wire spellings (`as_str()`): `ispdb`, `autoconfig_host`,
  `well_known`, `mx_heuristic`, `manual`.
- Stage outcomes (`as_str()`): `hit`, `miss`, `unreachable`,
  `malformed`, `unsupported`. Malformed documents are stage outcomes,
  never pipeline errors.
- `needs_manual_review == true` iff the suggestion came from the
  pattern guess or the manual stage. Provider-fixture / MX-hint /
  published-document hits are **not** flagged.
- Authenticated-provider hits (ISPDB/MX hint) prefer IMAP; published
  documents rank IMAP before POP3, then ImplicitTLS > STARTTLS >
  plaintext, ties in document order.

### 3.1 IPC envelope (`DiscoveryOutcome`)

What an IPC consumer receives from `discover(email, net)` — one JSON
object, always present for a valid email (`Error::InvalidEmail` is the
sole rejection, surfaced to IPC as an error, never a partial result):

```text
DiscoveryOutcome {
  email:              String,  // normalized address the run was for
  domain:             String,  // normalized domain part
  source:             String,  // wire spelling of the winning stage
  needs_manual_review: bool,   // true ⇒ UI must ask before saving
  suggestion:         AccountSuggestion,   // §6, never absent
  attempts: [                      // the "why", in stage order
    { source: String, outcome: String, detail: String }  // detail ≤120 chars
  ],
}
```

Consumers must treat `attempts` as the audit trail (render or log it)
and `needs_manual_review` as a hard gate — pattern guesses
(`mx_heuristic` with `detail` containing `pattern guess`) and the
manual fallback must not be persisted without explicit user consent.

## 4. Fixture tables (data, not policy)

- `ISPDB_FIXTURES`: public provider endpoints only (Google, Microsoft
  365, Yahoo, iCloud, Fastmail, Zoho, GMX, Yandex, GoDaddy, AOL).
  Apps may pass their own table via `discover_with_table`; the caller's
  table fully replaces the bundled one for stage 1.
- `MX_HINTS`: MX-host-suffix → provider map (e.g. `google.com`,
  `protection.outlook.com`, `yahoodns.net`, `pphosted.com`).
  `hint_for_host` matches exact or **label-boundary** suffix
  (`sub.google.com` hits; `notgoogle.com` does not).
- `MAX_CANDIDATES` (16) caps MX records considered; `MAX_XML_LEN`
  (256 KiB) caps document size.

## 5. Autoconfig XML parsing (hardened, zero-dependency)

Own parser in `autoconfig_xml.rs` — **no external XML crate**. Binding
rules:

- Prohibited constructs (hard `Err(MalformedXml)`, never best-effort):
  DOCTYPE/DTD/ENTITY (XXE), processing instructions, unknown entities,
  depth > 32, mismatched closing tags, documents > 256 KiB.
- Supported: entities `&amp;` `&lt;` `&gt;` `&quot;` `&apos;`,
  numeric (`&#65;`) and hex (`&#x42;`) character references, CDATA.
- Root element must be `clientConfig`; `<domain>` entries are checked
  against the queried domain (exact match preferred).
- Placeholders substituted in `<username>`: `%EMAILADDRESS%`,
  `%EMAILLOCALPART%` (others passed through verbatim).
- `<socketType>`: `SSL`/`TLS` → ImplicitTLS, `STARTTLS` → StartTls,
  `plain`/`none` → Plaintext. `<authentication>`: `password-cleartext`
  / `password-encrypted` → Password, `OAuth2` → XOAuth2; anything else
  (e.g. `gssapi`) makes that server unusable → stage outcome
  `unsupported`, not an error.
- Missing `<port>` falls back to protocol defaults (IMAP 993/143,
  POP3 995/110, SMTP 465/587/25 per security).

## 6. Output shape (`suggest.rs`)

`AccountSuggestion { source, email, display_name, incoming,
outgoing }`, serializable `snake_case`. `IncomingSuggestion { kind:
imap|pop3, host, port, security, auth, username }`;
`OutgoingSuggestion` likewise. `checked()` enforces: hostnames parse as
domains, ports 1–65535, usernames 1–256 chars, no plaintext on
implicit-TLS ports (993/995 in, 465 out). Failed `checked()` → stage
skips to the next rung.

`to_mail_account()` maps deterministically onto
`kiwi_mail::account::MailAccount`: `account_id =
"autoconfig:<lowercased email>"`, `credential_key =
"autoconfig/<email>/incoming|outgoing"` (kind `Password` or `XOAuth2`
per suggestion). No secret material is ever included.

## 7. Network seam

`DiscoveryNet { lookup_mx, fetch_https }` — synchronous trait; the
production adapter blocks on a private runtime; tests use `MockNet`
(in-memory maps, hosts validated through `DomainName`, bodies capped at
`MAX_XML_LEN`). All network failures are `None`/empty — stages skip,
never error.

## 8. Test coverage (53 tests, `cargo test -p kiwi-autoconfig`)

Fixture XML parsing (incl. XXE/DOCTYPE/deep-nesting/mismatch rejection,
entity+CDATA decoding, size cap), `lookup_in` exact/parent-domain/
case rules, placeholder substitution, stage ordering + evidence trail
under `MockNet`, malformed-document outcomes, MailAccount mapping with
deterministic credential keys, custom-table override, determinism.

T-158 additions verified present (same suite): full discovery order
under every fallthrough (`ispdb_stage_short_circuits_before_network`,
`autoconfig_host_beats_wellknown_and_both_beat_mx`,
`wellknown_stage_used_when_autoconfig_host_unreachable`,
`mx_hint_stage_when_no_documents`,
`full_fallthrough_ends_in_flagged_pattern_guess`), malformed-XML
rejection as stage outcome (`malformed_document_is_stage_outcome_not_error`
plus the `autoconfig_xml` rejection tests), and domain/email validation
edge cases (`domain_parse_normalizes_and_bounds`,
`split_email_rejects_bad_input`, `invalid_email_is_the_only_error`,
`urls_are_https_and_deterministic`).
