# Contract — Deterministic Inbox Rules (`kiwi.rules/1`)

> Owner: Agent 22 (T-236) · **Contract version: `kiwi.rules/1`** · Status:
> draft for Lead review — T-228 core is implemented; T-233 apply/persistence
> work is present in the shared tree, but IPC handlers and sync hook wiring
> are not yet complete. Changes require Lead review → record in
> `DECISIONS.md`.
>
> T-228 is implemented by `kiwi-mail` (`src/rules/` and `src/store/`).
> T-233 is assigned to Agent 15 and covers application on ingest, rules CRUD
> IPC, apply-now, and matched-rule audit. The current tree contains the
> `apply.rs` and store audit methods referenced by this contract, but does
> not contain the `kiwi-app` handlers or registered rules commands.

Parties: `kiwi-mail` (pure rules engine, bounded store, sync adapters) →
`kiwi-app/src-tauri` (trusted lock/input boundary and IPC projection) →
**kiwi-app webview** (React, untrusted). The webview never evaluates or
executes a rule; it edits bounded rule data and reads receipts/audit rows.
Sync workers call the same `kiwi-mail` APIs as manual apply-now.

## 1. Binding invariants

- **Determinism:** `evaluate(msg, rules)` is a pure, total function. It does
  not perform I/O, read a clock, access SQLite, create folders, move messages,
  or set flags.
- **One evaluation order:** enabled rules are ordered by ascending
  `position`, then by `id` as a total tie-breaker. Input slice order cannot
  change the outcome.
- **Block precedence:** enabled `is_block` rules are evaluated before every
  regular rule, regardless of position. The first matching block rule is
  terminal; regular rules are not evaluated after it.
- **At most one effective disposition:** the first ordered
  `Move`/`Archive`/`Delete` wins. Flag actions (`MarkRead`/`Star`) are
  de-duplicated and may be combined with the winning disposition.
- **No hard delete:** `Delete` is a move to `Trash`; the rules engine never
  hard-expunges a message.
- **Evidence before effects:** T-233 records rule hits before applying flags
  or moves. A move may remap a UID, but the hit remains at the coordinates at
  which evaluation occurred.
- **Untrusted input:** all renderer-originated rules are validated before
  persistence or evaluation. `Rule::validate` is a store-boundary gate; the
  evaluator assumes a validated tree and does not perform validation itself.
- **Local-first:** the rules subsystem has no network path and no secret or
  credential fields. The app is the only component that can turn a receipt
  into a live IMAP/POP3 operation.
- **Canonical junk flag:** the store's canonical flag is `\Junk`
  (`JUNK_FLAG`). Comparisons are case-insensitive. Legacy `$Junk` and bare
  `Junk` spellings are not normalized by this contract; normalization belongs
  to the T-212 caller.

## 2. Rule data model and wire spelling

### 2.1 Durable `Rule`

| field | type | meaning and bound |
|---|---|---|
| `id` | string | Caller-assigned printable ASCII identifier, 1–64 bytes; no whitespace |
| `account_id` | string or null | Owner account; `null` is global and applies to every account; 1–128 printable ASCII bytes when present |
| `name` | string | Human label, non-blank after trim, ≤128 bytes |
| `enabled` | boolean | Disabled rules are retained but never evaluated |
| `position` | signed 64-bit integer | Ascending evaluation position; no implicit reorder or automatic position assignment |
| `is_block` | boolean | Block-list class; evaluated first and terminal |
| `when` | `Predicate` | Bounded predicate AST |
| `then` | `RuleAction[]` | 1–8 actions in application order |

`RuleSpec` is the durable `spec_json` payload and contains only `{when, then}`
(see §3.2 and §6). The Rust `Rule` fields above are serde snake_case; the IPC
projection must use camelCase at the outer boundary (`accountId`, `isBlock`).
The nested AST deliberately retains its snake_case enum spellings.

### 2.2 Predicate AST

The AST is a tagged tree with `kind` in snake_case:

```jsonc
{ "kind": "sender",       "op": "domain", "value": "example.com" }
{ "kind": "recipient",    "op": "contains", "value": "team" }
{ "kind": "subject",      "op": "is", "value": "Invoice" }
{ "kind": "header",       "name": "List-Id", "op": "contains", "value": "lists" }
{ "kind": "body_contains", "value": "invoice" }
{ "kind": "attachment_name", "op": "ends_with", "value": ".pdf" }
{ "kind": "all",          "children": [] }
{ "kind": "any",          "children": [] }
{ "kind": "not",          "child": { "kind": "always" } }
{ "kind": "always" }
```

Variants and their field sources are:

| variant | source | semantics |
|---|---|---|
| `sender` | Every `From` address's `email` | Display names are never consulted; an empty address cannot domain-match |
| `recipient` | Every `To` and `Cc` address's `email` | Display names are never consulted; any one address may match |
| `subject` | `Subject`, if present | An absent subject does not match |
| `header` | Any header whose name folds case-insensitively | The name is a printable token and cannot contain `:` |
| `body_contains` | `text_body`, then raw `html_body`, then stored `snippet` | Case-insensitive substring; raw HTML is deterministic input and is not rendered by this engine |
| `attachment_name` | Every attachment's filename | Unnamed attachments do not match |
| `all` | Child predicates | Empty `all` is `true`; all children must match |
| `any` | Child predicates | Empty `any` is `false`; one child must match |
| `not` | One child | Logical negation |
| `always` | None | Always `true` |

### 2.3 `MatchOp` comparison contract

All operations compare a bounded value without normalizing the stored rule.
`is` uses ASCII case folding; `contains` and `ends_with` use the evaluator's
lowercase comparison and therefore follow Rust's Unicode-aware lowercase
conversion. The distinction is part of the contract.

- `contains`: substring anywhere in the field.
- `is`: whole-field equality (`eq_ignore_ascii_case`).
- `ends_with`: suffix equality after lowercase comparison.
- `domain`: dot-boundary suffix on the domain part. It takes the text after
  the last `@`, or the whole field when there is no `@`; trims whitespace and
  surrounding `<`, `>`, single/double quotes; lowercases both sides; strips one
  leading `@` from the pattern. A match is exact equality or a suffix beginning
  at a dot. Empty values do not match.

Examples that are binding:

| pattern | value | result |
|---|---|---|
| `evil.com` | `a@evil.com` | match |
| `evil.com` | `a@x.evil.com` | match |
| `evil.com` | `a@notevil.com` | no match |
| `evil.com` | `a@evil.com.e` | no match |
| `@evil.com` | `a@evil.com` | match |
| `lists.example` | `<dev.lists.example>` | match |

For a multi-address raw header value, the current implementation applies the
post-last-`@` rule to the final address. This is documented behavior, not a
promise to split every address in a header.

### 2.4 Actions and durable spelling

`RuleAction` is tagged with `do`:

```jsonc
{ "do": "move",     "folder": "Work" }
{ "do": "archive" }
{ "do": "delete" }       // Trash intent; never hard-expunge
{ "do": "mark_read" }    // set \\Seen
{ "do": "star" }         // set \\Flagged
```

`Move`, `Archive`, and `Delete` are folder dispositions. The evaluator emits
actions in source order after de-duplicating equal action values. In the
regular-rule path, only the first disposition is retained. A block rule is
terminal; the T-233 executor applies its first disposition and stops, so a
malformed block rule cannot relocate a message twice.

## 3. Pure evaluation contract

`evaluate` partitions enabled rules into block and regular sets, then sorts
each set by `(position, id)`.

1. For each block in order, evaluate `when`. The first match returns
   immediately with that rule's ID in `matched`, its ID in `blocked_by`, and
   its de-duplicated `then` actions.
2. If no block matches, evaluate every regular rule in order. Each matching
   rule appends its ID to `matched` in evaluation order and contributes its
   actions. Repeated equal flag actions are emitted once; the first folder
   disposition wins and later dispositions are discarded.
3. A non-match contributes neither an ID nor an action. With no match, the
   result is the default `RuleOutcome`.

`RuleOutcome` is an internal result shape:

```text
RuleOutcome {
  actions: Vec<RuleAction>,
  matched: Vec<String>,       // IDs in evaluation order; evidence trail
  blocked_by: Option<String>, // terminal block rule ID
}
```

`matched` is not a UI display string. It is the stable evidence surface and
must be preserved when the T-233 receipt is projected to IPC.

## 4. T-233 application and audit semantics

The current shared tree exposes these `kiwi-mail` entry points:

```text
apply_on_ingest(store, account_id, folder_id, uid, parsed_message, now)
  -> AppliedRules

apply_now(store, account_id, now)
  -> ApplyNowReport
```

### 4.1 One-message application

`apply_on_ingest` loads `list_rules(Some(account_id))`, evaluates the parsed
message, and is a no-op if there are no rules or no matches. Otherwise it:

1. Records every ID in `outcome.matched` with the pre-move `(folder_id, uid)`,
   optional RFC 822 `message_id`, and caller-supplied `now`.
2. Applies `MarkRead` as `\Seen` and `Star` as `\Flagged` before moving, so
   flag changes use the message's original UID. `set_flag` merges and reports
   only rows whose stored flag set changed.
3. Resolves the first disposition: `Move { folder }` to the named folder,
   `Archive` to `Archive`, and `Delete` to `Trash`. Folders are ensured on
   demand. Moving a message remaps its UID and moves its payload.
4. If a block verdict exists and no disposition moved the message, moves it
   to `Trash` even when the block rule contained only flag actions. This is
   the “block match = trash + stop” behavior.

`AppliedRules` is the receipt for one message:

```text
AppliedRules {
  matched: Vec<String>,       // echo of RuleOutcome::matched
  blocked_by: Option<String>,
  moved_to_folder: Option<i64>,
  flags_changed: u64,
}
```

### 4.2 `apply_now`

`apply_now` freezes a work list before evaluating anything. It walks the
account's folders and UIDs once, excludes `Trash` case-insensitively, reads a
stored body, and skips/counts a message when its body is absent, unreadable,
or unparseable. A parseable message is evaluated exactly once, even if an
earlier action moves it; the old `(folder_id, uid)` remains the audit
coordinate. Re-running is idempotent for flag merges, same-folder moves, and
audit rows.

The aggregate receipt is:

```text
ApplyNowReport {
  scanned: u64,             // parseable bodies evaluated
  matched: u64,             // messages with at least one matching rule
  moved: u64,               // messages moved by a disposition
  blocked: u64,             // terminal block verdicts
  flags_changed: u64,       // total changed stored flag rows
  skipped_no_body: u64,     // absent/unreadable/unparseable bodies
}
```

The current `sync.rs` functions store metadata/full bodies but do not call
`apply_on_ingest`. T-233 integration must call it only after a full parsed
message is available: IMAP metadata-only ingest must not pretend body or
attachment predicates are present; the IMAP body-fetch path and POP3 full
download path are the required candidate hooks. This integration remains a
T-233 implementation gate, not an already-landed behavior.

### 4.3 Audit persistence

Schema v6 adds `rule_hits`:

```text
rule_hits(
  folder_id, uid, rule_id, message_id, applied_unix,
  PRIMARY KEY (folder_id, uid, rule_id)
)
```

`folder_id`/UID identify the evaluation coordinates and become stale after a
move; `message_id` is the stable RFC 822 identity for tracing across moves.
`rule_id` is deliberately not a foreign key, so evidence survives rule
deletion. `record_rule_hits` uses `INSERT OR REPLACE`, refreshing
`applied_unix` for a repeated hit at the same stored coordinates.
`list_rule_hits(account_id, limit)` joins through folders and orders by
`applied_unix DESC`, `rule_id`, `folder_id`, `uid`.

The IPC audit projection is `RuleHitView` with camelCase fields:

```jsonc
{
  "folderId": 42,
  "uid": 1001,
  "ruleId": "block-evil",
  "messageId": "<m@example>",
  "appliedUnix": 1760000000
}
```

The audit list is bounded at the IPC layer; it must never allow a caller to
unbounded-query or infer deleted rule names. A deleted rule remains visible
only as its verbatim `ruleId`.

## 5. Validation and error semantics

`Rule::validate` runs at the store boundary and before persistence. It rejects
with `MailError::InvalidInput` whose message is prefixed `rule rejected:`.

| input | rejection rule |
|---|---|
| `id` | Empty, over 64 bytes, or containing non-graphic/ASCII-whitespace bytes |
| `name` | Blank after trim or over 128 bytes |
| `account_id` | Present but empty, over 128 bytes, or not printable ASCII |
| `then` | Empty or over 8 actions |
| `Move.folder` | Blank after trim, over 255 bytes, or contains an ASCII control byte |
| Every leaf `value` | Over 512 bytes |
| `Header.name` | Empty, over 64 bytes, non-graphic, or contains `:` |
| Predicate tree | Over 32 total nodes or deeper than 8 |

`position` is an `i64`; there is no automatic bounds or reorder operation.
Reordering is an upsert of the desired position. `enabled` and `is_block` are
booleans. A corrupt `spec_json` is skipped by `list_rules` so one bad row does
not disable the entire set; `get_rule` reports the corrupt row as a store
error. No rule from the renderer may bypass validation by calling the
evaluator directly.

At the app boundary these map to the standard IPC error catalog:

| source condition | IPC code |
|---|---|
| Locked endpoint | `locked` |
| Invalid rule, AST, bound, account/rule identifier, or malformed request | `invalid-input` |
| Account or other named resource absent | `not-found` |
| SQLite/store failure | `store-error`, sanitized |
| Unsupported policy rejection | `policy-blocked` (distinct from rule validation) |
| Unexpected runtime failure | `internal` |

Delete is idempotent: a missing rule returns `{ "removed": false }`, not
`not-found`. Parse failures during apply-now are skips, not errors. No error
message may echo a password, token, secret, or unrestricted renderer value.

## 6. Persistence contract (T-228)

Schema version is `6`. The `rules` table is:

```text
rules(
  rule_id TEXT PRIMARY KEY,
  account_id TEXT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL,
  is_block INTEGER NOT NULL DEFAULT 0,
  spec_json TEXT NOT NULL
)
```

`idx_rules_scope(account_id, position)` supports scoped reads. `account_id
NULL` means global. The store API is:

- `upsert_rule(&Rule)`: validate first, serialize `{when, then}`, then
  insert-or-replace by `rule_id`.
- `list_rules(None)`: global rules only.
- `list_rules(Some(account_id))`: global plus that account's rules.
- Both list forms order by `position`, then `rule_id`; undecodable specs are
  skipped.
- `get_rule(rule_id)`: missing is `None`; corrupt JSON is an error.
- `delete_rule(rule_id)`: returns whether a row was removed.

Deleting an account cascades its account-scoped rules, folders, messages, and
rule-hit rows. Deleting a rule does not delete `rule_hits`.

## 7. IPC contract — T-233 proposed seam

The four required logical names are `rules_list`, `rules_upsert`,
`rules_delete`, and `apply_now`. They follow the existing `kiwi_*` Tauri
prefix when registered; the registered spelling must be one canonical path,
not a duplicate logical/frontend path:

| logical name | Tauri registration | lock | request | response |
|---|---|---|---|---|
| `rules_list` | `kiwi_rules_list` | gated | `{ accountId?: string \| null }` | `RuleView[]` |
| `rules_upsert` | `kiwi_rules_upsert` | gated | `{ rule: RuleInput }` | `RuleView` |
| `rules_delete` | `kiwi_rules_delete` | gated | `{ ruleId: string }` | `{ removed: boolean }` |
| `apply_now` | `kiwi_apply_now` | gated | `{ accountId: string }` | `ApplyNowView` |
| `rules_hits` | `kiwi_rules_hits` | gated | `{ accountId: string, limit?: number }` | `RuleHitView[]` |

`accountId` omitted or `null` in `rules_list` means global-only. A supplied
account must exist; global rules are included in that account's list. The
app layer checks account ownership and calls `list_rules` only after the
lock gate.

### 7.1 `RuleInput` and `RuleView`

`RuleInput` has the outer camelCase fields `id`, `accountId`, `name`,
`enabled`, `position`, `isBlock`, `when`, and `then`. `RuleView` has the same
shape after conversion. Nested predicate/action discriminators remain the
snake_case spellings from §2 (`kind`, `do`, `body_contains`, `mark_read`, and
so on). The Tauri layer must:

- reject unknown/malformed enum spellings and invalid bounds as
  `invalid-input` before touching the store;
- never accept a `now`/clock value from the renderer;
- preserve the same `id`, `when`, and `then` values in the response;
- treat `Delete` as a Trash intent, not a permanent-delete request;
- not expose raw email bodies, AST source, or filesystem paths in a rule view.

A successful upsert is a full rule replacement by `id`; it is not a partial
patch. Updating a rule's `position` is the supported reorder mechanism.

### 7.2 `apply_now` and audit responses

`apply_now` takes only `accountId`. The backend reads `now_unix()` once and
passes it to `kiwi_mail::rules::apply_now`; callers cannot forge audit time.
The response is camelCased:

```jsonc
{
  "scanned": 12,
  "matched": 5,
  "moved": 2,
  "blocked": 1,
  "flagsChanged": 4,
  "skippedNoBody": 3
}
```

`rules_hits` is the transparency surface. The app should default `limit` to a
small bounded value and clamp it to the catalog's existing maximum of 1000;
unbounded or negative values are `invalid-input`. It returns the newest-first
`RuleHitView[]` from `list_rule_hits`, including hits for deleted rules because
`rule_id` is not an FK.

`AppliedRules` is available to the ingest/sync layer but is not a replacement
for the audit list: its `matched` IDs are the immediate receipt, while
`rules_hits` is the durable mailbox history.

## 8. Current implementation boundary

- **Implemented in `kiwi-mail`:** predicate/action model and validation,
  pure evaluator, schema v6 rules table, CRUD, T-233 `apply.rs` application
  helpers, `rule_hits` storage, and source-level tests.
- **Present but incomplete:** `apply_on_ingest`/`apply_now` are exported by
  `kiwi-mail`, but `sync.rs` does not yet invoke them; app-layer types,
  commands, registration, and frontend bindings are absent from the current
  tree.
- **T-233 required integration:** call `apply_on_ingest` after a full parsed
  message is available, expose the four CRUD/apply commands plus the bounded
  audit query, and add sync/command tests without duplicating business logic
  in the webview.
- **T-236 scope:** documentation only. No source behavior is changed by this
  contract; any implementation change must be recorded by T-233 and reviewed
  against this document.

## 9. Verification baseline

T-228's recorded source tests cover ordering and input-order invariance, block
precedence/terminal behavior, disposition selection, flag de-duplication,
all predicate kinds and combinators, validation bounds, durable spec shape,
CRUD scope/corruption handling, and v5→v6 migration. T-233 source tests cover
ingest receipt/audit, block-to-Trash behavior, no-match no-op, apply-now
scanning/Trash exclusion/idempotence, and flag-before-move behavior. IPC
contract tests and sync-hook tests remain required when the T-233 handlers
land.
