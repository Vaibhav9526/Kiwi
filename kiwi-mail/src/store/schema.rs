//! SQLite schema — DDL + version. Migrations are explicit and
//! append-only; `user_version` is the source of truth.

pub(crate) const SCHEMA_VERSION: u32 = 15;

pub(crate) const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email        TEXT NOT NULL,
    config_json  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS folders (
    id           INTEGER PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    uid_validity INTEGER,
    uid_next     INTEGER,
    highest_uid  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, name)
);
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY,
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid             INTEGER NOT NULL,
    message_id      TEXT,
    subject         TEXT,
    from_addr       TEXT,
    to_addrs        TEXT,
    date_unix       INTEGER,
    size            INTEGER,
    flags           TEXT NOT NULL DEFAULT '',
    has_attachments INTEGER NOT NULL DEFAULT 0,
    snippet         TEXT,
    body_path       TEXT,
    fetched_at      INTEGER NOT NULL,
    -- T-201: deterministic inbox-tab slug (category::Category::as_str).
    category        TEXT NOT NULL DEFAULT 'primary',
    -- T-202: RFC 2369/8058 unsubscribe offer (unsub::UnsubscribeInfo).
    unsub_http      TEXT,
    unsub_mailto    TEXT,
    unsub_oneclick  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (folder_id, uid)
);
CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder_id, uid);
CREATE TABLE IF NOT EXISTS pop3_seen (
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    uidl       TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, uidl)
);
-- Queued outbound sends (undo-send + send-later, T-142). The built MIME
-- lives in-row: one row is one committed send, so enqueue is a single
-- atomic write — no torn meta/body pair possible.
CREATE TABLE IF NOT EXISTS outbox (
    queue_id        TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    from_addr       TEXT NOT NULL,
    to_addrs        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    mime            BLOB NOT NULL,
    not_before_unix INTEGER NOT NULL,
    undo_until_unix INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_unix    INTEGER NOT NULL
);
-- Inbox rules (F1 groundwork, T-228): durable storage only — the engine
-- is crate::rules. account_id NULL = applies to every account; position
-- orders evaluation (ascending, rule_id breaks ties); is_block marks the
-- block-list class, evaluated before regular rules and terminal on
-- match. spec_json carries {when, then} (rules::RuleSpec) — logic stays
-- out of columns so the predicate grammar can grow without migrations.
CREATE TABLE IF NOT EXISTS rules (
    rule_id    TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL,
    is_block   INTEGER NOT NULL DEFAULT 0,
    spec_json  TEXT NOT NULL,
    -- T-244: cumulative sync-time apply failures and bounded diagnostics.
    -- Counters survive rule edits; the last error is overwritten on each
    -- later failure and never contains a message body or filesystem path.
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT,
    last_failure_unix INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rules_scope ON rules(account_id, position);
-- Rule-hit audit trail (T-233): which rules fired on which message.
-- (folder_id, uid) locate the message at eval time — a moved message's
-- trail stays on its ingest coordinates; message_id is the stable RFC822
-- identity for cross-move tracing. rule_id is deliberately NOT an FK:
-- the evidence must survive rule deletion. Re-evaluating the same rule
-- on the same stored row refreshes applied_unix (INSERT OR REPLACE), so
-- repeated "run rules now" passes never duplicate evidence.
CREATE TABLE IF NOT EXISTS rule_hits (
    folder_id    INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid          INTEGER NOT NULL,
    rule_id      TEXT NOT NULL,
    message_id   TEXT,
    applied_unix INTEGER NOT NULL,
    PRIMARY KEY (folder_id, uid, rule_id)
);
-- Deferred-eval watermark (T-244): the deepest stage the rules engine has
-- run per stored message. `stage` 0 = envelope facts only, 1 = full parse.
-- Rows exist even when no rule matched — the marker records that
-- *evaluation happened*, so a no-match message is not re-evaluated forever.
-- Wiped with the folder's messages on UIDVALIDITY reset (uid epoch
-- restarts); orphaned by moves, which is harmless — the pending query only
-- looks at INBOX coordinates where the message row still exists.
CREATE TABLE IF NOT EXISTS rule_evals (
    folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid       INTEGER NOT NULL,
    stage     INTEGER NOT NULL,
    at_unix   INTEGER NOT NULL,
    PRIMARY KEY (folder_id, uid)
);
-- Authentication-Results verdicts (T-232). Deliberately a SEPARATE table
-- rather than more `messages` columns: the auth stamp is written once at body
-- ingest and read alongside the list, and keeping it out of `messages` leaves
-- the many existing SELECTs over that table (list, search, FTS, move, rules)
-- untouched — that table is shared with the unsub/junk and rules owners.
-- `evidence_json` is one bounded JSON blob: the three explanations plus the
-- evidence refs (key query, DMARC record). Never a body, never a finding.
CREATE TABLE IF NOT EXISTS message_auth (
    folder_id      INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid            INTEGER NOT NULL,
    spf            TEXT NOT NULL DEFAULT 'none',
    dkim           TEXT NOT NULL DEFAULT 'none',
    dmarc          TEXT NOT NULL DEFAULT 'none',
    dmarc_policy   TEXT NOT NULL DEFAULT 'none',
    dkim_domain    TEXT,
    key_query      TEXT,
    dmarc_record   TEXT,
    header_value   TEXT,
    evidence_json  TEXT,
    -- T-240: bounded RFC 8601 Authentication-Results received from upstream
    -- MTAs. This is evidence, not authority: the object retains authserv-id,
    -- all extracted verdicts, and pass<->fail comparisons with KIWI's stamp.
    upstream_json   TEXT,
    -- T-249: bounded UI hint derived at stamp time from the local verdicts,
    -- SPF alignment, and T-240 upstream evidence. Never a finding/action.
    auth_risk      TEXT CHECK (auth_risk IN ('clean', 'noted', 'failed')),
    PRIMARY KEY (folder_id, uid)
);
-- Attachment hints (T-254) are deliberately a sibling, not message_auth:
-- MIME classification is local and must work even when DNS auth sealing is
-- unavailable. Reasons are a bounded fixed vocabulary JSON array, never
-- filenames, MIME parameters, or attachment bodies. Evidence only — this
-- table never blocks UI or mutates/moves mail.
CREATE TABLE IF NOT EXISTS message_attachment_risk (
    folder_id   INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid         INTEGER NOT NULL,
    risk        TEXT NOT NULL CHECK (risk IN ('clean', 'noted', 'failed')),
    reasons_json TEXT NOT NULL,
    PRIMARY KEY (folder_id, uid)
);
-- Snooze (T-255): reversible local-only parking. A row means "hide this
-- message from folder lists until until_unix" — the message row itself
-- NEVER moves, so snooze can't desync the server (a real folder move
-- would make the next UID-diff re-download the remote uid into INBOX).
-- The composite FK gives free cleanup on delete/expunge/UIDVALIDITY
-- reset; `move_messages` re-keys the row before its source DELETE so
-- parked mail stays parked across moves. `from_folder_id` records where
-- it was parked (the message may have since moved) — evidence for the
-- Snoozed view and future restore-to-origin semantics.
CREATE TABLE IF NOT EXISTS snoozed (
    folder_id      INTEGER NOT NULL,
    uid            INTEGER NOT NULL,
    until_unix     INTEGER NOT NULL,
    from_folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    set_at_unix    INTEGER NOT NULL,
    PRIMARY KEY (folder_id, uid),
    FOREIGN KEY (folder_id, uid) REFERENCES messages(folder_id, uid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snoozed_due ON snoozed(until_unix);
-- Link hints (T-261): sibling evidence because URL classification is local
-- parsed-body work, independent of auth sealing. Only the bounded enum and a
-- fixed reason-code JSON array are retained; URLs/display text are never kept.
CREATE TABLE IF NOT EXISTS message_link_risk (
    folder_id   INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid         INTEGER NOT NULL,
    risk        TEXT NOT NULL CHECK (risk IN ('clean', 'noted', 'failed')),
    reasons_json TEXT NOT NULL,
    PRIMARY KEY (folder_id, uid)
);
-- Message templates (T-288): composer boilerplate, a flat named list —
-- content, not policy, so no account scoping or ordering columns.
-- `body_html` is optional (plain-text templates are the common case);
-- `{{name}}` placeholders in subject/bodies are render-time resolved
-- (templates::Template::render), the stored row keeps them verbatim.
CREATE TABLE IF NOT EXISTS templates (
    template_id  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    subject      TEXT NOT NULL DEFAULT '',
    body_text    TEXT NOT NULL,
    body_html    TEXT,
    created_unix INTEGER NOT NULL,
    updated_unix INTEGER NOT NULL
);
"#;
