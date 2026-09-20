//! Full-text message search — FTS5 over the local store (T-159).
//!
//! External-content table over `messages` (no text duplication), kept in
//! sync by triggers on INSERT/UPDATE/DELETE. The index covers subject /
//! from / to / snippet (best available proxy for body text until bodies
//! are parsed at read time). Queries are bounded: non-empty terms only,
//! column-scoped or plain, at most [`MAX_QUERY_TERMS`] tokens from the
//! caller's input, `LIMIT` capped at [`MAX_RESULTS`]. All SQL is
//! parameterized (SECURITY.md rule 9) and queries never touch the network.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Result;
use crate::store::MessageMeta;

/// Bounded result count per query (IPC shape — see docs/contracts/ipc.md).
pub const MAX_RESULTS: u32 = 200;

/// Max whitespace-separated terms accepted per query; extra terms are
/// dropped (bounded query API, never a DoS via mega-query).
pub const MAX_QUERY_TERMS: usize = 8;

const FTS_DDL: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    subject, from_addr, to_addrs, snippet,
    content='messages', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, subject, from_addr, to_addrs, snippet)
    VALUES (new.id, new.subject, new.from_addr, new.to_addrs, new.snippet);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addrs, snippet)
    VALUES ('delete', old.id, old.subject, old.from_addr, old.to_addrs, old.snippet);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addrs, snippet)
    VALUES ('delete', old.id, old.subject, old.from_addr, old.to_addrs, old.snippet);
    INSERT INTO messages_fts(rowid, subject, from_addr, to_addrs, snippet)
    VALUES (new.id, new.subject, new.from_addr, new.to_addrs, new.snippet);
END;
CREATE TABLE IF NOT EXISTS fts_state (
    k TEXT PRIMARY KEY,
    v INTEGER NOT NULL
);
"#;

/// Create the FTS table + sync triggers (idempotent) and rebuild the
/// inverted index when it lags the content table (external-content
/// `rebuild` idiom — a plain row-count probe cannot detect staleness
/// because reads fall through to the content table). Called from
/// [`crate::store::MailStore::migrate`].
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(FTS_DDL)?;
    let max_id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |r| {
        r.get(0)
    })?;
    if max_id > 0 {
        // Marker lags the newest message row → index was dropped or the
        // store predates it: full rebuild (idempotent, bounded by store size).
        let built: i64 = conn
            .query_row("SELECT v FROM fts_state WHERE k = 'max_id'", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0);
        if built < max_id {
            conn.execute(
                "INSERT INTO messages_fts(messages_fts) VALUES('rebuild')",
                [],
            )?;
            conn.execute(
                "INSERT INTO fts_state(k, v) VALUES('max_id', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![max_id],
            )?;
        }
    }
    Ok(())
}

/// One search term: bare token or `column:token` scope, possibly negated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchTerm {
    /// `None` = all columns; `Some` = one scoped column.
    pub column: Option<SearchColumn>,
    /// Term text, normalized to lowercase ASCII.
    pub text: String,
    /// `-term` — rows matching this term are excluded.
    pub negated: bool,
}

/// Column scope for a [`SearchTerm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchColumn {
    Subject,
    From,
    To,
    /// Body-text proxy: the stored preview snippet.
    Body,
}

impl SearchColumn {
    fn fts_column(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::From => "from_addr",
            Self::To => "to_addrs",
            Self::Body => "snippet",
        }
    }

    /// Parse a `column:` prefix; unknown prefixes are treated as plain text
    /// (the whole token stays a bare term).
    #[must_use]
    pub fn parse(prefix: &str) -> Option<Self> {
        match prefix.to_ascii_lowercase().as_str() {
            "subject" => Some(Self::Subject),
            "from" | "from_addr" => Some(Self::From),
            "to" | "to_addrs" => Some(Self::To),
            "body" | "text" | "snippet" => Some(Self::Body),
            _ => None,
        }
    }
}

/// Bounded query parser for IPC (T-159). Supported syntax: plain tokens
/// (`invoice`), column scopes (`from:alice`, `subject:report`, `to:bob`,
/// `body:wood`), quoted phrases (`"monthly report"`), `-`-prefixed
/// negation (`-spam`). Unknown `prefix:` tokens stay whole as plain text
/// (`site:foo` matches the words "site" and "foo"); punctuation-only
/// tokens (`-`, `--`, `"""`) are noise and dropped. Emits at most
/// [`MAX_QUERY_TERMS`] non-empty terms; noise-only input yields an empty
/// vec — an empty query is an empty result set downstream, never an error.
#[must_use]
pub fn parse_query(query: &str) -> Vec<SearchTerm> {
    let mut out = Vec::new();
    for raw in split_tokens(query) {
        if out.len() >= MAX_QUERY_TERMS {
            break;
        }
        let (negated, tok) = match raw.strip_prefix('-') {
            Some(rest) if !rest.is_empty() => (true, rest.to_string()),
            _ => (false, raw.to_string()),
        };
        // Malformed empty scope (`:x`, `-:x`): no column, no word — noise.
        if tok.starts_with(':') {
            continue;
        }
        // A known column prefix scopes the rest of the token (quotes
        // trimmed below); unknown/empty prefixes keep the whole token as
        // plain text so nothing the user typed is silently mangled.
        let (column, text) = match tok.split_once(':') {
            Some((prefix, rest)) if !rest.is_empty() && !prefix.is_empty() => {
                match SearchColumn::parse(prefix) {
                    Some(col) => (Some(col), rest.to_string()),
                    None => (None, tok),
                }
            }
            _ => (None, tok),
        };
        let text = text.trim_matches('"').to_lowercase();
        // Pure punctuation has no tokens after FTS tokenization and would
        // produce an invalid empty phrase — treat as noise.
        if !text.chars().any(char::is_alphanumeric) {
            continue;
        }
        out.push(SearchTerm {
            column,
            text,
            negated,
        });
    }
    out
}

/// Whitespace tokenizing that keeps double-quoted phrases (including the
/// spaces inside them) as one token: `"monthly report"` stays whole.
/// Unbalanced quotes degrade gracefully — the tail becomes one token.
fn split_tokens(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in query.chars() {
        match ch {
            '"' if in_quotes || cur.is_empty() || cur.ends_with(':') => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Compose the FTS5 MATCH expression for parsed terms. Positive terms AND
/// together; negated terms become `AND NOT (...)` clauses — FTS5 has no
/// unary `NOT`, so a query made only of negations yields no expression
/// (empty result). Scoped terms use `column : "phrase"` expressions. Every
/// user token is embedded as a quoted phrase (inner quotes doubled), so
/// the expression can never break out into arbitrary MATCH syntax.
fn build_match_sql(terms: &[SearchTerm]) -> Option<String> {
    if terms.is_empty() {
        return None;
    }
    let mut positive: Vec<String> = Vec::new();
    let mut negative: Vec<String> = Vec::new();
    for term in terms {
        let phrase = format!("\"{}\"", term.text.replace('"', "\"\""));
        let expr = match term.column {
            Some(col) => format!("{} : {phrase}", col.fts_column()),
            None => phrase,
        };
        if term.negated {
            negative.push(expr);
        } else {
            positive.push(expr);
        }
    }
    if positive.is_empty() {
        return None;
    }
    let mut sql = positive.join(" AND ");
    // FTS5's NOT is binary-only (no unary NOT): chain as `a NOT (n)` —
    // left-associative, so (a NOT n1) NOT n2 excludes both.
    for neg in &negative {
        sql.push_str(" NOT (");
        sql.push_str(neg);
        sql.push(')');
    }
    Some(sql)
}

/// Run a bounded full-text search. Returns full [`MessageMeta`] rows for
/// hits, newest first (`date_unix` DESC, then `uid` DESC for stability).
/// `folder_id` scopes to one folder; `None` searches every folder of the
/// store. Empty / noise-only queries return an empty vec.
pub fn search_messages(
    store: &crate::store::MailStore,
    query: &str,
    folder_id: Option<i64>,
    limit: u32,
) -> Result<Vec<MessageMeta>> {
    let terms = parse_query(query);
    let Some(match_expr) = build_match_sql(&terms) else {
        return Ok(Vec::new());
    };
    let limit = limit.clamp(1, MAX_RESULTS);
    // The MATCH parameter is the whole expression string. It is safe to
    // bind as one parameter: it is built exclusively from quoted phrases
    // (inner quotes doubled) plus fixed column names — never raw user text
    // outside a quoted phrase (SECURITY.md rule 9).
    let sql = "SELECT m.id, m.folder_id, m.uid, m.message_id, m.subject, m.from_addr,
                m.to_addrs, m.date_unix, m.size, m.flags, m.has_attachments,
                m.snippet, m.body_path
         FROM messages m
         JOIN messages_fts f ON f.rowid = m.id
         WHERE messages_fts MATCH ?1
           AND (?2 IS NULL OR m.folder_id = ?2)
         ORDER BY m.date_unix IS NULL, m.date_unix DESC, m.uid DESC
         LIMIT ?3";
    let conn = store.conn();
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(
        params![match_expr, folder_id, limit as i64],
        map_message_row,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn map_message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageMeta> {
    Ok(MessageMeta {
        id: r.get(0)?,
        folder_id: r.get::<_, i64>(1)?,
        uid: r.get::<_, i64>(2)? as u64,
        message_id: r.get(3)?,
        subject: r.get(4)?,
        from_addr: r.get(5)?,
        to_addrs: r.get(6)?,
        date_unix: r.get(7)?,
        size: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        flags: r
            .get::<_, String>(9)?
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        has_attachments: r.get::<_, i64>(10)? != 0,
        snippet: r.get(11)?,
        body_path: r.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MailStore, NewMessageMeta};

    fn msg(uid: u64, subject: &str, from: &str, to: &str, snippet: &str) -> NewMessageMeta {
        NewMessageMeta {
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            subject: Some(subject.into()),
            from_addr: Some(from.into()),
            to_addrs: Some(to.into()),
            date_unix: Some(1_758_000_000 + uid as i64),
            size: Some(100),
            flags: vec![],
            has_attachments: false,
            snippet: Some(snippet.into()),
        }
    }

    fn seeded() -> MailStore {
        let store = MailStore::open_memory().unwrap();
        let acct = crate::account::MailAccount {
            account_id: "a1".into(),
            display_name: "T".into(),
            email: "t@x.test".into(),
            incoming: crate::account::IncomingAccount {
                protocol: crate::account::IncomingProtocol::Imap,
                server: crate::account::ServerConfig {
                    host: "imap.x.test".into(),
                    port: 993,
                    security: crate::transport::SocketSecurity::ImplicitTls,
                },
                auth: crate::account::AuthRef::Password {
                    credential_key: "k".into(),
                },
                username: "t@x.test".into(),
            },
            outgoing: crate::account::OutgoingAccount {
                server: crate::account::ServerConfig {
                    host: "smtp.x.test".into(),
                    port: 587,
                    security: crate::transport::SocketSecurity::StartTls,
                },
                auth: crate::account::AuthRef::Password {
                    credential_key: "k".into(),
                },
                username: "t@x.test".into(),
            },
        };
        store.upsert_account(&acct).unwrap();
        store
    }

    fn subjects(rows: &[MessageMeta]) -> Vec<String> {
        rows.iter()
            .map(|m| m.subject.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn parse_query_basic_and_scopes() {
        assert_eq!(
            parse_query("invoice urgent"),
            vec![
                SearchTerm {
                    column: None,
                    text: "invoice".into(),
                    negated: false
                },
                SearchTerm {
                    column: None,
                    text: "urgent".into(),
                    negated: false
                },
            ]
        );
        assert_eq!(
            parse_query("From:ALICE subject:\"monthly report\" to:bob body:wood"),
            vec![
                SearchTerm {
                    column: Some(SearchColumn::From),
                    text: "alice".into(),
                    negated: false
                },
                SearchTerm {
                    column: Some(SearchColumn::Subject),
                    text: "monthly report".into(),
                    negated: false
                },
                SearchTerm {
                    column: Some(SearchColumn::To),
                    text: "bob".into(),
                    negated: false
                },
                SearchTerm {
                    column: Some(SearchColumn::Body),
                    text: "wood".into(),
                    negated: false
                },
            ]
        );
    }

    #[test]
    fn parse_query_negation_noise_and_caps() {
        assert_eq!(
            parse_query("keep -spam"),
            vec![
                SearchTerm {
                    column: None,
                    text: "keep".into(),
                    negated: false
                },
                SearchTerm {
                    column: None,
                    text: "spam".into(),
                    negated: true
                },
            ]
        );
        // Noise-only / empty input → empty terms (empty result set, not error).
        assert!(parse_query("").is_empty());
        assert!(parse_query("   \t ").is_empty());
        assert!(parse_query("-").is_empty());
        assert!(parse_query("-:x").is_empty());
        assert!(parse_query("\"\"").is_empty());
        // Unknown column prefix stays plain text (whole token, "site:foo").
        assert_eq!(
            parse_query("site:foo"),
            vec![SearchTerm {
                column: None,
                text: "site:foo".into(),
                negated: false
            }]
        );
        // Quoted scope phrases are supported.
        assert_eq!(
            parse_query("subject:\"monthly report\""),
            vec![SearchTerm {
                column: Some(SearchColumn::Subject),
                text: "monthly report".into(),
                negated: false,
            }]
        );
        // Cap: MAX_QUERY_TERMS terms, extras dropped.
        let ten = parse_query("a b c d e f g h i j");
        assert_eq!(ten.len(), MAX_QUERY_TERMS);
    }

    #[test]
    fn match_sql_is_bounded_and_quoted() {
        // Every token lands inside a quoted phrase; embedded quotes doubled
        // (o"brien is a literal mid-word quote, not a phrase opener).
        let sql = build_match_sql(&parse_query("o\"brien subject:\"re: x\"")).unwrap();
        assert!(sql.contains("\"o\"\"brien\""), "{sql}");
        // Scoped multi-word phrase stays one quoted expression.
        assert!(sql.contains("subject : \"re: x\""), "{sql}");
        assert!(!sql.contains(" OR "), "no OR injection surface: {sql}");
        // Unbalanced quote: mid-word quote stays literal, tail splits on
        // whitespace (degraded but sane), never one giant phrase.
        let sql2 = build_match_sql(&parse_query("o\"brien unpaid")).unwrap();
        assert!(
            sql2.contains("\"o\"\"brien\"") && sql2.contains("\"unpaid\""),
            "{sql2}"
        );
        // Empty → no expression.
        assert!(build_match_sql(&[]).is_none());
    }

    #[test]
    fn search_finds_by_subject_from_to_body() {
        let store = seeded();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store
            .upsert_message(
                fid,
                &msg(
                    1,
                    "Quarterly report",
                    "alice@corp.test",
                    "bob@corp.test",
                    "numbers attached",
                ),
                100,
            )
            .unwrap();
        store
            .upsert_message(
                fid,
                &msg(
                    2,
                    "Lunch plans",
                    "carol@corp.test",
                    "dave@corp.test",
                    "see you at noon",
                ),
                101,
            )
            .unwrap();

        // subject
        assert_eq!(
            subjects(&store.search("quarterly", Some(fid), 50).unwrap()),
            vec!["Quarterly report"]
        );
        // from
        assert_eq!(
            subjects(&store.search("from:carol", Some(fid), 50).unwrap()),
            vec!["Lunch plans"]
        );
        // to
        assert_eq!(
            subjects(&store.search("to:dave", Some(fid), 50).unwrap()),
            vec!["Lunch plans"]
        );
        // body proxy
        assert_eq!(
            subjects(&store.search("body:noon", Some(fid), 50).unwrap()),
            vec!["Lunch plans"]
        );
        // AND semantics across terms.
        assert!(
            store
                .search("quarterly lunch", Some(fid), 50)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn search_negation_and_folder_scope() {
        let store = seeded();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        let trash = store.ensure_folder("a1", "Trash").unwrap();
        store
            .upsert_message(inbox, &msg(1, "invoice paid", "a@x", "b@y", "..."), 100)
            .unwrap();
        store
            .upsert_message(inbox, &msg(2, "invoice unpaid", "a@x", "b@y", "..."), 101)
            .unwrap();
        store
            .upsert_message(trash, &msg(3, "invoice shredded", "a@x", "b@y", "..."), 102)
            .unwrap();

        assert_eq!(
            subjects(&store.search("invoice -unpaid", Some(inbox), 50).unwrap()),
            vec!["invoice paid"]
        );
        // Negation-only query: no positive anchor → empty result, not error.
        assert!(store.search("-invoice", None, 50).unwrap().is_empty());
        // Folder scoping: only the folder's rows, never the other folder's.
        assert_eq!(store.search("invoice", Some(trash), 50).unwrap().len(), 1);
        assert_eq!(store.search("invoice", None, 50).unwrap().len(), 3);
    }

    #[test]
    fn search_order_newest_first_and_limit_cap() {
        let store = seeded();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        for uid in 1..=5u64 {
            store
                .upsert_message(
                    fid,
                    &msg(uid, "bulletin", "a@x", "b@y", "..."),
                    200 + uid as i64,
                )
                .unwrap();
        }
        let rows = store.search("bulletin", Some(fid), 3).unwrap();
        assert_eq!(subjects(&rows), vec!["bulletin"; 3]);
        // Date order: newest uid (later date_unix) first.
        assert!(rows[0].date_unix.unwrap() > rows[2].date_unix.unwrap());
        // Limit above the cap clamps to MAX_RESULTS without error.
        let _ = store.search("bulletin", Some(fid), u32::MAX).unwrap();
    }

    #[test]
    fn search_empty_or_noise_query_returns_empty() {
        let store = seeded();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store
            .upsert_message(fid, &msg(1, "hello", "a@x", "b@y", "..."), 100)
            .unwrap();
        assert!(store.search("", Some(fid), 50).unwrap().is_empty());
        assert!(store.search("   ", Some(fid), 50).unwrap().is_empty());
        assert!(store.search("-", Some(fid), 50).unwrap().is_empty());
    }

    #[test]
    fn fts_index_tracks_delete_and_move() {
        let store = seeded();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        let trash = store.ensure_folder("a1", "Trash").unwrap();
        store
            .upsert_message(inbox, &msg(1, "unique-zebra", "a@x", "b@y", "..."), 100)
            .unwrap();
        assert_eq!(store.search("zebra", Some(inbox), 10).unwrap().len(), 1);

        // Move: FTS delete + reinsert via the UPDATE trigger.
        store.move_messages(inbox, trash, &[1]).unwrap();
        assert!(store.search("zebra", Some(inbox), 10).unwrap().is_empty());
        assert_eq!(store.search("zebra", Some(trash), 10).unwrap().len(), 1);

        // Delete: FTS delete trigger keeps the index consistent.
        store.delete_messages(trash, &[1]).unwrap();
        assert!(store.search("zebra", None, 10).unwrap().is_empty());
    }

    #[test]
    fn backfill_indexes_preexisting_rows() {
        // A store whose FTS table was dropped (schema migration scenario):
        // ensure_schema must recreate AND backfill, idempotently.
        let store = seeded();
        let fid = store.ensure_folder("a1", "INBOX").unwrap();
        store
            .upsert_message(fid, &msg(1, "oldtimer", "a@x", "b@y", "..."), 100)
            .unwrap();
        store
            .conn_for_test()
            .execute_batch("DROP TABLE messages_fts")
            .unwrap();
        crate::search::ensure_schema(store.conn_for_test()).unwrap();
        assert_eq!(store.search("oldtimer", Some(fid), 10).unwrap().len(), 1);
        // Idempotent: second call changes nothing.
        crate::search::ensure_schema(store.conn_for_test()).unwrap();
        assert_eq!(store.search("oldtimer", Some(fid), 10).unwrap().len(), 1);
    }
}
