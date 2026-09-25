//! SQLite schema — DDL + version. Migrations are explicit and
//! append-only; `user_version` is the source of truth.

pub(crate) const SCHEMA_VERSION: u32 = 6;

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
"#;
