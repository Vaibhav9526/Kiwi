//! SQLite schema — DDL + version. Migrations are explicit and
//! append-only; `user_version` is the source of truth.

pub(crate) const SCHEMA_VERSION: u32 = 7;

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
    spec_json  TEXT NOT NULL
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
    PRIMARY KEY (folder_id, uid)
);
"#;
