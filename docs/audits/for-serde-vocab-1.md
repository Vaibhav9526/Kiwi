# T-238 — Forensics Serde Vocabulary Unification

> **Status:** proposal / Lead ruling required · **Reviewer:** Agent 22 ·
> **Date:** 2026-09-25 · **Scope:** `kiwi-forensics/src/`, `forensics.md`,
> `ipc.md`, and FOR-1/FOR-2 in `contract-drift-1.md`.
>
> This is an analysis document only. It changes no Rust, TypeScript, schema,
> or contract files. The Lead chooses the canonical vocabulary first; a code
> owner then implements the ruling and updates the affected contracts.

## Decision requested

Ratify one canonical **forensics wire-enum rule**:

> **FSV-1:** every ordinary `kiwi-forensics` enum uses lower `snake_case` variant
> names. Unit variants serialize as JSON strings. A data-bearing variant uses
> Serde's externally tagged object form, preserving its payload. `EvidenceValue`
> remains the one deliberately internally tagged union, with `type` and
> `snake_case` variant names, because its shape is already contract-exact.

Under FSV-1, `TlsVersion::Unknown(raw)` is canonically
`{"unknown": <u16>}`, not the contract's current bare string `"unknown"`.
This preserves the raw value and makes the representation a normal Serde
externally tagged enum. A compatibility reader may accept the old bare string
as a lossy legacy input, but must not invent the missing raw value.

The proposed rule intentionally does **not** rewrite `as_str()` output.
`as_str()` is the semantic/display vocabulary used in evidence text, policy
references, and stable finding/subject keys. Changing it would be a second,
larger vocabulary migration and could break re-scan identity. The ruling should
make the distinction explicit: enum JSON tags use FSV-1; evidence text and
stable IDs retain their existing semantic tokens unless a later ruling says
otherwise.

## Why this recommendation

- The current code already has a mechanically consistent default for 24
  ordinary enum types: `#[serde(rename_all = "snake_case")]`. FSV-1 makes that
  behavior the contract rather than adding a large set of per-variant
  `rename` attributes.
- FSV-1 keeps data-bearing unknowns lossless and makes the FOR-2 shape
  explicit, instead of collapsing a raw wire value into a string.
- It gives forward readers one rule for PascalCase, dotted, kebab-case, and
  acronym-heavy variants. The current `as_str()` vocabulary intentionally
  mixes those forms (`tls1.2`, `cram-md5`, `3des`, `chacha20_poly1305`), so it
  is useful as a domain vocabulary but not a single predictable serialization
  rule.
- It minimizes new implementation surface: ordinary enums remain derived
  serde enums; only the `TlsVersion` compatibility deserializer and the
  existing `EvidenceValue` internal tag need special handling.
- It avoids silently treating `SessionView`/`SecuritySession` IPC values as
  raw forensics serde. Those are cross-component view vocabularies and must be
  mapped explicitly; `ipc.md` currently promises `"tls1.3"`, `"xoauth2"`, and
  `"hostname-mismatch"` for those views (`ipc.md:77-81`).

### Alternatives considered but not recommended as the ruling

1. **Make serde emit every `as_str()` value.** This would match much of the
   current `forensics.md` prose, but requires per-variant aliases and still
   leaves a mixed dotted/kebab/abbreviation vocabulary. It also makes the
   `TlsVersion::Unknown(raw)` contract shape a custom exceptional design.
2. **Keep both spellings indefinitely.** This avoids a one-time break but
   makes every consumer a dual-reader and leaves `Report::from_json`
   non-deterministic from the consumer's point of view. A versioned
   dual-read/single-write transition is safer.

## Current serde surface

The complete scan of `kiwi-forensics/src/` found:

| measure | result |
|---|---:|
| enum declarations | 31 (30 public, one private `Endian`) |
| enums deriving `Serialize` + `Deserialize` | 27 |
| ordinary enums with `#[serde(rename_all = "snake_case")]` | 24 |
| internally tagged enums | 1 (`EvidenceValue`, tag `type`) |
| per-variant `#[serde(rename = ...)]` | 0 |
| `#[serde(other)]` / enum defaults | 0 |
| enums without serde | 4 (`CaptureError`, `Endian`, `SocketMode`, `LiveCertVerdict`) |
| `serde_json` report call sites | `Report::to_json` / `from_json` in `report/mod.rs:203-215` |

`Report::to_json` serializes the structs directly (`kiwi-forensics/src/report/mod.rs:203-210`),
so the current enum tags are the current stored-report and forensic-finding
wire form. `Report::from_json` derives strict deserialization with no aliases or
unknown-variant fallback (`report/mod.rs:212-215`).

The `{"unknown":N}` form is not a hand-written string tag. It is Serde's default
external representation for the newtype variant `TlsVersion::Unknown(u16)`
(`kiwi-forensics/src/model/tls.rs:18-35`). There is no literal
`"unknown:<N>"` token in the crate. `LinkType::Other(u16)` is a second
external object, but currently uses the PascalCase key `Other` because its
enum has no `rename_all` (`kiwi-forensics/src/pcap/mod.rs:67-74`).

## Contract spellings and drift summary

`forensics.md` says that enum strings use the `as_str()` spellings
(`forensics.md:55-58`). Its event table promises:

- `protocol`: `smtp|imap|pop3|unknown` (`forensics.md:44`)
- `transport`: `plaintext|starttls|implicit_tls|unknown` (`forensics.md:47`)
- `auth.mechanism`: `plain|login|cram-md5|...|unknown` (`forensics.md:52`)
- TLS versions and cipher values in the `as_str()` family
  (`forensics.md:55-58`, `forensics.md:200-205`)
- `severity`, `confidence`, and finding categories
  (`forensics.md:72-81`)
- typed `EvidenceValue` objects with an internal `type` discriminator
  (`forensics.md:72-75`)

`ipc.md` adds a second, cross-component promise: `SessionView` values such as
`tls1.3`, `hostname-mismatch`, and `xoauth2` (`ipc.md:77-81`); its account
mapping promises `start_tls → "starttls"` and `xoauth2 → "xoauth2"`
(`ipc.md:236-240`); and forensic `Finding` objects are returned verbatim in
verify/detail responses (`ipc.md:190-197`, `ipc.md:318-326`). A Tauri view
therefore must not blindly re-serialize a forensics enum under a second naming
rule.

FOR-1 reproduced at least 19 divergent variants; the complete inventory finds
23 `as_str()`/serde divergences when the undocumented `Grade` and the unknown
payload are included. FOR-2 is a shape mismatch, not merely a spelling
mismatch. FOR-6 remains a separate forward-compatibility gap: no enum uses
`#[serde(other)]`, and `#[serde(other)]` cannot be applied to a newtype or
struct variant carrying data.

## Per-enum inventory and proposed forms

`SC` below means `#[derive(Serialize, Deserialize)]` plus
`#[serde(rename_all = "snake_case")]`. “Contract form” distinguishes an
explicit promise from an inferred `as_str()` convention or “not named.” FSV-1
is the proposed canonical form, not current behavior.

### Serde-derived enums

| enum / source | current serde attributes and wire form | `forensics.md` / `ipc.md` promise | proposed FSV-1 |
|---|---|---|---|
| `TlsVersion` · `model/tls.rs:20-35` | `SC`; `ssl2`, `ssl3`, `tls10`, `tls11`, `tls12`, `tls13`; `Unknown(u16)` → `{"unknown":N}` | `as_str()`: `ssl2.0`, `ssl3.0`, `tls1.0`, `tls1.1`, `tls1.2`, `tls1.3`, `unknown`; `forensics.md:55-58,200`; `ipc.md:80-81` promises `tls1.3` for SessionView | `ssl2`, `ssl3`, `tls10`, `tls11`, `tls12`, `tls13`, `{"unknown":N}`; update forensics contract; map IPC separately |
| `VersionComparison` · `model/tls.rs:44-53` | `SC`; `below`, `equal`, `above`, `indeterminate` | Not named; `as_str()` absent | same snake forms; document if made public |
| `KeyExchange` · `model/tls.rs:153-177` | `SC`; `null`, `rsa`, `dh_static`, `dhe`, `ecdh_static`, `ecdhe`, `psk`, `psk_dhe`, `psk_ecdhe`, `anonymous`, `unknown` | §9a mapping uses the same semantic tokens (`forensics.md:202`) | same |
| `ForwardSecrecy` · `model/tls.rs:227-234` | `SC`; `yes`, `no`, `unknown` | Broad `as_str()` convention; no closed table | same |
| `BulkCipher` · `model/tls.rs:250-285` | `SC`; `null`, `rc4_40`, `rc4_128`, `rc2_40`, `des`, `des40`, `triple_des`, `idea`, `seed`, `camellia128_cbc`, `aes128_cbc`, `aes256_cbc`, `aes128_gcm`, `aes256_gcm`, `aes128_ccm`, `cha_cha20_poly1305`, `unknown` | `as_str()`: `3des` and `chacha20_poly1305`; other values use snake_case (`model/tls.rs:289-309`) | same serde snake forms; update any `3des`/chacha prose to the canonical tags or explicitly call them evidence labels |
| `MacAlgorithm` · `model/tls.rs:387-402` | `SC`; `null`, `hmac_md5`, `hmac_sha1`, `hmac_sha256`, `hmac_sha384`, `aead`, `unknown` | No closed external table; `as_str()` agrees | same |
| `CipherStrength` · `model/tls.rs:436-451` | `SC`; `broken`, `weak`, `legacy`, `acceptable`, `strong`, `unknown` | No closed external table; `as_str()` agrees | same |
| `AuthMechanism` · `model/auth.rs:13-44` | `SC`; `plain`, `login`, `cram_md5`, `digest_md5`, `ntlm`, `x_o_auth2`, `oauth_bearer`, `scram_sha1`, `scram_sha256`, `scram_sha256_plus`, `scram_sha512_plus`, `anonymous`, `external`, `gssapi`, `unknown` | `as_str()`: `cram-md5`, `digest-md5`, `xoauth2`, `oauthbearer`, `scram-sha-1`, `scram-sha-256`, `scram-sha-256-plus`, `scram-sha-512-plus` (`forensics.md:52,205`; `ipc.md:80-81,238-240`) | current SC tags; update forensics prose; preserve explicit IPC mapping for `xoauth2` |
| `CredentialKind` · `model/auth.rs:158-169` | `SC`; `none`, `password`, `bearer_token`, `challenge_response`, `unknown` | Not named in contracts; `as_str()` agrees | same |
| `Protocol` · `model/protocol.rs:14-23` | `SC`; `smtp`, `imap`, `pop3`, `unknown` | Exact match in `forensics.md:44` and mapping §9a | same |
| `TransportSecurity` · `model/protocol.rs:94-103` | `SC`; `plaintext`, `start_tls`, `implicit_tls`, `unknown` | `forensics.md:47` promises `starttls`; `ipc.md:238-240` maps `start_tls → "starttls"` | `start_tls` on the wire; keep `starttls` only as IPC/session/evidence mapping unless Lead chooses a separate global vocabulary |
| `TrustState` · `model/cert.rs:34-45` | `SC`; `not_evaluated`, `trusted_by_local_anchor`, `untrusted`, `revoked`, `unknown` | Exact match in `forensics.md:50` | same |
| `SignatureAlgorithm` · `model/cert.rs:104-121` | `SC`; `md2`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `unknown` | Not named as a closed wire table; `as_str()` agrees | same |
| `PublicKeyAlgorithm` · `model/cert.rs:184-197` | `SC`; `rsa`, `dsa`, `ec`, `ed25519`, `ed448`, `unknown` | Not named; `as_str()` agrees | same |
| `HostnameMatch` · `model/cert.rs:243-250` | `SC`; `match`, `mismatch`, `indeterminate` | `ipc.md` promises `hostname-mismatch` for a core session value, not this enum | same for this enum; map to `hostname-mismatch` at the core/session boundary |
| `CertificateProblem` · `model/cert.rs:381-406` | `SC`; `not_yet_valid`, `expired`, `expiring_soon`, `self_issued`, `hostname_mismatch`, `broken_signature_algorithm`, `deprecated_signature_algorithm`, `weak_public_key`, `discouraged_public_key_algorithm`, `chain_truncated`, `trust_not_validated`, `trust_rejected` | Not a closed public contract table; `as_str()` agrees | same; document if exposed |
| `PeerRole` · `model/mod.rs:120-127` | `SC`; `client`, `server`, `unknown` | Not named; `as_str()` agrees | same; document if exposed |
| `Severity` · `findings/mod.rs:23-34` | `SC`; `info`, `low`, `medium`, `high`, `critical` | Exact contract domain in `forensics.md:77` and IPC finding filter (`ipc.md:485-499`) | same |
| `Confidence` · `findings/mod.rs:76-85` | `SC`; `tentative`, `firm`, `certain` | Exact contract domain in `forensics.md:78` | same |
| `FindingCategory` · `findings/mod.rs:114-131` | `SC`; `transport`, `cipher`, `key_exchange`, `certificate`, `authentication`, `starttls`, `protocol`, `capture_integrity` | Exact contract domain in `forensics.md:79-81` | same; `starttls` is intentionally one word |
| `EvidenceKind` · `findings/mod.rs:152-179` | `SC`; `transport_state`, `tls_version`, `cipher_suite`, `key_exchange`, `forward_secrecy`, `certificate_attribute`, `certificate_trust`, `auth_mechanism`, `auth_outcome`, `starttls_negotiation`, `protocol_capability`, `capture_metadata`, `session_structure` | `Evidence.kind` is named, but the closed kind list is not; `as_str()` agrees | same; add a closed list if it becomes public |
| `EvidenceValue` · `findings/mod.rs:208-241` | `#[serde(tag="type", rename_all="snake_case")]`; `{"type":"text","value":…}`, `number`, `bool`, `bytes{digest_hex,len}`, `list{values}`, `unavailable{reason}` | Exact shape in `forensics.md:72-75` | preserve this internal union and its current `type` tags |
| `ChangeKind` · `findings/diff.rs:50-61` | `SC`; `new`, `resolved`, `unchanged`, `severity_increased`, `severity_decreased` | `forensics.md:68-70` says `added/resolved/persisting`; FOR-9 records the richer code set | current snake tags; update the diff contract or add an explicit semantic mapping; not a serde spelling-only fix |
| `Direction` · `analyzers/mod.rs:39-44` | `SC`; `client`, `server` | Not named; no `as_str()` | same; internal analyzer field unless exposed |
| `Grade` · `score.rs:71-82` | `SC`; `a`, `b`, `c`, `d`, `f` | `forensics.md:158` describes display grades `A..F`; `Grade::as_str()` is uppercase; score JSON shape is FOR-I undocumented | lowercase `a..f` on wire under FSV-1; uppercase is a presentation/display conversion only; document `Report.score.grade` explicitly |
| `CaptureFormat` · `pcap/mod.rs:57-65` | Derives serde, no rename; `{"ClassicPcap":{"nanosecond":…}}` or `"PcapNg"` | Not named; not a `Report` field | if exposed, `{"classic_pcap":{"nanosecond":…}}` or `"pcap_ng"` |
| `LinkType` · `pcap/mod.rs:69-74` | Derives serde, no rename; `"Ethernet"` or `{"Other":N}` | Not named; not a `Report` field | if exposed, `"ethernet"` or `{"other":N}` |

### Enums without a current serde wire

| enum / source | current attributes/form | contract promise | proposed FSV-1 treatment |
|---|---|---|---|
| `CaptureError` · `pcap/mod.rs:142-201` | No `Serialize`/`Deserialize`; eight structured error variants | No documented forensic error model | remain internal; do not invent a wire enum in this ruling |
| `Endian` · `pcap/reader.rs:15-18` | Private; no serde | none | remain private/internal |
| `SocketMode` · `live/mod.rs:27-34` | No serde; adapter mirror of `kiwi-mail` socket mode | none | remain an input-only adapter enum; map to `TransportSecurity` |
| `LiveCertVerdict` · `live/mod.rs:39-52` | No serde; adapter mirror of the live verifier | none | remain an input-only adapter enum; map to `TrustState` |

## Drift inventory

The 23 `as_str()`/serde differences found in the complete scan are:

| enum | divergent current serde tag | current `as_str()` / contract form | count |
|---|---|---|---:|
| `TlsVersion` | `ssl2`, `ssl3`, `tls10`, `tls11`, `tls12`, `tls13`, `{"unknown":N}` | `ssl2.0`, `ssl3.0`, `tls1.0`, `tls1.1`, `tls1.2`, `tls1.3`, `unknown` | 7 |
| `TransportSecurity` | `start_tls` | `starttls` | 1 |
| `AuthMechanism` | `cram_md5`, `digest_md5`, `x_o_auth2`, `oauth_bearer`, `scram_sha1`, `scram_sha256`, `scram_sha256_plus`, `scram_sha512_plus` | `cram-md5`, `digest-md5`, `xoauth2`, `oauthbearer`, `scram-sha-1`, `scram-sha-256`, `scram-sha-256-plus`, `scram-sha-512-plus` | 8 |
| `BulkCipher` | `triple_des`, `cha_cha20_poly1305` | `3des`, `chacha20_poly1305` | 2 |
| `Grade` | `a`–`f` | `A`–`F` | 5 |

The FOR-1 examples are therefore real, not a parsing typo. `FindingCategory::StartTls`
and `EvidenceKind::StartTlsNegotiation` are not divergences: their existing
snake forms are `starttls` and `starttls_negotiation`. `TlsVersion::Unknown`
is both a divergence and a shape defect, and is called out separately as FOR-2.

## Representation and compatibility decisions required from the Lead

### 1. `TlsVersion::Unknown(raw)`

FSV-1 recommends:

```json
{ "unknown": 65535 }
```

The raw 16-bit value remains available to rules through `wire_value()`. The
contract should stop promising the bare string `"unknown"` as the JSON shape
and instead state that the externally tagged object is canonical. A reader may
accept `"unknown"` only as a legacy alias; because the string contains no raw
value, it must map to a documented sentinel (or be quarantined) rather than
fabricating a numeric fact. Evidence already carrying the numeric raw value
must remain authoritative.

### 2. `as_str()` and stable keys

FSV-1 does not change `Protocol::as_str()`, `TransportSecurity::as_str()`,
`AuthMechanism::as_str()`, or TLS/cipher `as_str()` methods. Those values are
used in `EvidenceValue::Text`, policy comparisons, and stable
`rule_id|subject_key` identities. If a future ruling instead makes every
semantic token snake_case, it must separately version finding IDs and re-scan
comparisons; that is outside this proposal.

### 3. IPC boundary

`ipc.md` should distinguish two vocabularies:

- `kiwi-forensics` report JSON enum tags follow FSV-1.
- `kiwi-core`/Tauri session views retain the security-session/IPC contract
  vocabulary (`tls1.3`, `xoauth2`, `hostname-mismatch`, `starttls`) and map
  explicitly from/forensics values.

If a Tauri response embeds `Finding` verbatim, the response's nested forensics
enum tags follow FSV-1 while the outer Tauri field names remain camelCase.
That is a field-name boundary, not a second enum naming rule. Add a
serialization contract test for each embedded view.

### 4. Forward compatibility (separate from spelling)

Renaming tags does not close FOR-6. Future unknown unit variants should be
mapped to a documented unknown domain value or ignored at the version
boundary. `#[serde(other)]` can cover unit variants only; it cannot be placed
on `TlsVersion::Unknown(u16)`, `LinkType::Other(u16)`, or the structured
variants of `CaptureFormat`/`CaptureError`. A custom deserializer or
version-gated parser is required for data-bearing unknown values. Do not
pretend that a vocabulary rule alone makes arbitrary future reports
non-fatal.

## Migration plan for existing stored reports

This is a wire-breaking proposal; the code owner must implement a coordinated
transition rather than changing `serde` attributes alone.

1. **Inventory first.** Treat every JSON produced by `Report::to_json` and every
   persisted diff/IPC response containing a forensic enum as version-1 data.
   Preserve the original bytes and original `contract_version`; do not silently
   rewrite evidence.
2. **Version the wire change.** Bump the report/contract vocabulary version
   (recommended: `kiwi.forensics/2`, or add an explicit wire-schema version)
   without bumping `rule_catalog_version` unless rule logic also changes.
   `scoring_model_version` changes only if scoring changes, not for spelling.
3. **Dual-read, single-write.** For one compatibility window, the report reader
   accepts version-1 serde tags and FSV-1 tags, normalizes them into the typed
   model, and the writer emits only FSV-1 tags. Record a limitation or migration
   marker when an old lossy form is normalized.
4. **Add aliases only where lossless.** Unit variants can accept legacy
   `as_str` aliases such as `starttls`, `cram-md5`, `xoauth2`, `3des`, and
   dotted TLS names while emitting snake_case. `TlsVersion::Unknown` needs a
   custom reader for the string/object pair; a string cannot recover a raw
   value. `LinkType`/`CaptureFormat` need PascalCase aliases if those public
   types are ever persisted.
5. **Update contracts atomically.** Change `forensics.md` enum tables to FSV-1,
   retain the IPC mapping tables, and update `ipc.md` examples that embed raw
   forensic values. Add tests for old-read/new-write and new-read/old-reject
   behavior as appropriate.
6. **Do not change stable keys in the same migration.** `finding_id` and
   `subject_key` are built from semantic `as_str()` values, not serde tags;
   changing them would invalidate re-scan histories and cached UI identities.
7. **Preserve auditability.** A migrated report should retain its original
   source/version in archival metadata. Consumers should be able to tell that
   a report was normalized rather than claiming the raw legacy input was
   emitted in the new vocabulary.

## Acceptance criteria for the implementation owner

- One ratified rule is reflected in code, `forensics.md`, and `ipc.md`.
- A machine-readable golden fixture covers every FSV-1 enum, including
  `TlsVersion::Unknown(N)`, `EvidenceValue`, `Grade`, `CaptureFormat`, and
  `LinkType` where exposed.
- Version-1 reports can be read without data loss where the old form carried
  data; lossy `"unknown"` is explicitly marked.
- New reports emit only the ratified tags; no frontend or backend silently
  depends on the old spellings.
- `Report::to_json` and `Report::from_json` are tested across the migration
  boundary.
- The separate forward-compatibility gap (FOR-6) has an owner and is not
  represented as solved by the spelling change.

## Evidence index

- FOR-1/FOR-2: `docs/audits/contract-drift-1.md:67-68`
- FOR-6: `docs/audits/contract-drift-1.md:91,241-251`
- FOR-9: `docs/audits/contract-drift-1.md:155`
- FOR-I (`Grade`/undocumented score shape): `docs/audits/contract-drift-1.md:224`
- Forensics promises: `docs/contracts/forensics.md:20-58,72-81,170-205,286-316`
- IPC promises/mappings: `docs/contracts/ipc.md:18-29,77-81,190-197,236-240,318-326`
- Enum implementation: `kiwi-forensics/src/model/{tls,auth,protocol,cert,mod}.rs`,
  `findings/{mod,diff}.rs`, `analyzers/mod.rs`, `score.rs`, `pcap/{mod,reader}.rs`,
  and `live/mod.rs`
