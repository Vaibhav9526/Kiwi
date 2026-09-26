//! Message search — FTS5 over the local store plus structured field
//! predicates (T-159 grammar; T-334 fielded operators).
//!
//! External-content table over `messages` (no text duplication), kept in
//! sync by triggers on INSERT/UPDATE/DELETE. The index covers subject /
//! from / to / snippet (best available proxy for body text until bodies
//! are parsed at read time).
//!
//! Query shape: at most [`MAX_QUERY_TERMS`] whitespace-separated tokens,
//! each either a free-text FTS term (`plain`, `"phrase"`, `-negated`,
//! `body:`-scoped) or a fielded operator (`from:`/`to:`/`subject:`/
//! `has:`/`is:`/`before:`/`after:`/`in:`) that filters a real column.
//! Fielded predicates AND together and AND with the FTS terms; unknown
//! `key:value` tokens degrade to literal text rather than erroring or
//! vanishing. `LIMIT` is capped at [`MAX_RESULTS`]. All SQL is
//! parameterized (SECURITY.md rule 9) — operator values are bound
//! parameters, never interpolated — and queries never touch the network.

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

/// One free-text search term: bare token or `body:`-scope, possibly
/// negated. Fielded operators are NOT terms — they are
/// [`FieldPredicate`]s that filter real columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchTerm {
    /// `None` = all columns; `Some` = one scoped column.
    pub column: Option<SearchColumn>,
    /// Term text, normalized to lowercase ASCII.
    pub text: String,
    /// `-term` — rows matching this term are excluded.
    pub negated: bool,
}

/// FTS column scope for a [`SearchTerm`]. `from:`/`to:`/`subject:` are
/// fielded operators ([`SearchFilter`]) as of T-334; only the body-proxy
/// scope remains an FTS expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchColumn {
    /// Body-text proxy: the stored preview snippet.
    Body,
}

impl SearchColumn {
    fn fts_column(self) -> &'static str {
        match self {
            Self::Body => "snippet",
        }
    }

    /// Parse a `column:` prefix; unknown prefixes are treated as plain text
    /// (the whole token stays a bare term).
    #[must_use]
    pub fn parse(prefix: &str) -> Option<Self> {
        match prefix.to_ascii_lowercase().as_str() {
            "body" | "text" | "snippet" => Some(Self::Body),
            _ => None,
        }
    }
}

/// A fielded operator — `key:value` — resolved to a real-column filter
/// (T-334). The value travels to SQL only as a bound parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchFilter {
    /// `from:v` — `from_addr` substring, case-insensitive.
    FromLike(String),
    /// `to:v` — `to_addrs` substring, case-insensitive.
    ToLike(String),
    /// `subject:v` — `subject` substring, case-insensitive.
    SubjectLike(String),
    /// `has:attachment` — `has_attachments` set.
    HasAttachment,
    /// `is:unread` — no `\Seen` flag token.
    Unseen,
    /// `is:read` — has `\Seen`.
    Seen,
    /// `is:starred` (`is:flagged`) — has `\Flagged`.
    Flagged,
    /// `before:YYYY-MM-DD` — `date_unix` strictly before that UTC midnight.
    Before(i64),
    /// `after:YYYY-MM-DD` — `date_unix` on or after that UTC midnight.
    OnOrAfter(i64),
    /// `in:name` / `folder:name` — folder name match, case-insensitive,
    /// across every account that stores such a folder.
    InFolder(String),
}

/// One fielded predicate in the parsed query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPredicate {
    pub filter: SearchFilter,
    /// `-has:attachment` — the column predicate is negated.
    pub negated: bool,
}

/// A parsed query: free-text FTS terms plus real-column predicates. Both
/// sides AND together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSearch {
    pub terms: Vec<SearchTerm>,
    pub predicates: Vec<FieldPredicate>,
}

/// Bounded query parser for IPC (T-159 terms, T-334 operators).
///
/// Free-text syntax: plain tokens (`invoice`), `body:`/`text:`/`snippet:`
/// scopes, `"quoted phrases"` (and `'single'` for operator values),
/// `-`-prefixed negation (`-spam`, `-is:unread`). Fielded operators:
/// `from:`/`to:`/`subject:` substring, `has:attachment`,
/// `is:unread|read|starred`, `before:`/`after:YYYY-MM-DD`,
/// `in:`/`folder:` name. Unknown `key:value` tokens — and known operators
/// with malformed values (`before:tuesday`) — stay whole as plain text;
/// punctuation-only tokens (`-`, `--`, `"""`) are noise and dropped.
/// Emits at most [`MAX_QUERY_TERMS`] entries total; noise-only input
/// yields an empty parse — an empty query is an empty result set
/// downstream, never an error.
#[must_use]
pub fn parse_query(query: &str) -> ParsedSearch {
    let mut out = ParsedSearch::default();
    for raw in split_tokens(query) {
        if out.terms.len() + out.predicates.len() >= MAX_QUERY_TERMS {
            break;
        }
        let (negated, tok) = match raw.strip_prefix('-') {
            Some(rest) if !rest.is_empty() => (true, rest.to_string()),
            _ => (false, raw.to_string()),
        };
        // Malformed empty scope (`:x`, `-:x`): no key, no word — noise.
        if tok.starts_with(':') {
            continue;
        }
        // Fielded operator? Known key + well-formed value → column filter.
        // A `term`-shaped token with an unrecognized operator (or a known
        // operator with a malformed value) falls through to the FTS path
        // as literal text — nothing typed is silently dropped.
        if let Some(filter) = parse_operator(&tok) {
            out.predicates.push(FieldPredicate { filter, negated });
            continue;
        }
        // FTS column scope (`body:`/`text:`/`snippet:`); unknown/empty
        // prefixes keep the whole token as plain text.
        let (column, text) = match tok.split_once(':') {
            Some((prefix, rest)) if !rest.is_empty() && !prefix.is_empty() => {
                match SearchColumn::parse(prefix) {
                    Some(col) => (Some(col), rest.to_string()),
                    None => (None, tok),
                }
            }
            _ => (None, tok),
        };
        let text = unquote(&text).to_lowercase();
        // Pure punctuation has no tokens after FTS tokenization and would
        // produce an invalid empty phrase — treat as noise.
        if !text.chars().any(char::is_alphanumeric) {
            continue;
        }
        out.terms.push(SearchTerm {
            column,
            text,
            negated,
        });
    }
    out
}

/// `key:value` → [`SearchFilter`]; `None` when the key is unknown or the
/// value malformed — the caller then treats the whole token as text.
fn parse_operator(tok: &str) -> Option<SearchFilter> {
    let (key, raw_val) = tok.split_once(':')?;
    if key.is_empty() || raw_val.is_empty() {
        return None;
    }
    let val = unquote(raw_val);
    if val.is_empty() {
        return None;
    }
    Some(match key.to_ascii_lowercase().as_str() {
        "from" => SearchFilter::FromLike(val),
        "to" => SearchFilter::ToLike(val),
        "subject" => SearchFilter::SubjectLike(val),
        "has" => match val.to_ascii_lowercase().as_str() {
            "attachment" => SearchFilter::HasAttachment,
            _ => return None,
        },
        "is" => match val.to_ascii_lowercase().as_str() {
            "unread" => SearchFilter::Unseen,
            "read" => SearchFilter::Seen,
            "starred" | "flagged" => SearchFilter::Flagged,
            _ => return None,
        },
        "in" | "folder" => SearchFilter::InFolder(val),
        "before" => SearchFilter::Before(parse_date(&val)?),
        "after" => SearchFilter::OnOrAfter(parse_date(&val)?),
        _ => return None,
    })
}

/// Strip one matching `"…"`/`'…'` pair from an operator value or term.
fn unquote(v: &str) -> String {
    let b = v.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// `YYYY-MM-DD` → that day's UTC midnight as Unix seconds. Strict:
/// exactly 10 bytes, digits and dashes in place, a real calendar date.
fn parse_date(v: &str) -> Option<i64> {
    let b = v.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    if !b
        .iter()
        .enumerate()
        .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return None;
    }
    let year: i32 = v[0..4].parse().ok()?;
    let month = time::Month::try_from(v[5..7].parse::<u8>().ok()?).ok()?;
    let day: u8 = v[8..10].parse().ok()?;
    Some(
        time::Date::from_calendar_date(year, month, day)
            .ok()?
            .midnight()
            .assume_utc()
            .unix_timestamp(),
    )
}

/// Escape a LIKE pattern value and wrap it `%…%` (paired with
/// `ESCAPE '\'` in the clause so a literal `\`/`%`/`_` can't wildcard).
fn like_pattern(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('%');
    for c in text.chars() {
        match c {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('%');
    out
}

/// Static SQL fragment for one predicate — `?` placeholders only, never
/// interpolated text. `filter_param` returns the bound value (or `None`
/// for a parameterless clause like `has:attachment`).
fn filter_clause(p: &FieldPredicate) -> &'static str {
    match &p.filter {
        SearchFilter::FromLike(_) => "m.from_addr LIKE ? ESCAPE '\\'",
        SearchFilter::ToLike(_) => "m.to_addrs LIKE ? ESCAPE '\\'",
        SearchFilter::SubjectLike(_) => "m.subject LIKE ? ESCAPE '\\'",
        SearchFilter::HasAttachment => "m.has_attachments <> 0",
        // flags is a space-separated token list; padding makes the match
        // exact and SQLite's ASCII case-insensitive LIKE matches IMAP
        // flag semantics (same rule as MailStore::folder_stats).
        SearchFilter::Unseen => "' ' || m.flags || ' ' NOT LIKE '% \\Seen %'",
        SearchFilter::Seen => "' ' || m.flags || ' ' LIKE '% \\Seen %'",
        SearchFilter::Flagged => "' ' || m.flags || ' ' LIKE '% \\Flagged %'",
        SearchFilter::Before(_) => "m.date_unix < ?",
        SearchFilter::OnOrAfter(_) => "m.date_unix >= ?",
        SearchFilter::InFolder(_) => {
            "EXISTS (SELECT 1 FROM folders fl
                     WHERE fl.id = m.folder_id AND fl.name = ? COLLATE NOCASE)"
        }
    }
}

fn filter_param(p: &FieldPredicate) -> Option<Box<dyn rusqlite::ToSql>> {
    match &p.filter {
        SearchFilter::FromLike(v) | SearchFilter::ToLike(v) | SearchFilter::SubjectLike(v) => {
            Some(Box::new(like_pattern(v)))
        }
        SearchFilter::Before(ts) | SearchFilter::OnOrAfter(ts) => Some(Box::new(*ts)),
        SearchFilter::InFolder(name) => Some(Box::new(name.clone())),
        _ => None,
    }
}

/// The nullable column a predicate reads, when it reads one. Needed for
/// negation: `NOT (NULL_col op ?)` is NULL in SQL tri-state, which would
/// *drop* a row whose field is simply absent — so `-from:boss` would hide
/// a message whose sender failed to parse, although nothing says it is
/// from boss. Emitting `col IS NULL OR NOT (…)` keeps absent-value rows
/// under negation (absent cannot match, so it cannot be excluded).
/// Non-nullable predicates (`flags`, `has_attachments`, the EXISTS folder
/// probe) return `None` and negate plainly.
fn nullable_column(p: &FieldPredicate) -> Option<&'static str> {
    match &p.filter {
        SearchFilter::FromLike(_) => Some("m.from_addr"),
        SearchFilter::ToLike(_) => Some("m.to_addrs"),
        SearchFilter::SubjectLike(_) => Some("m.subject"),
        SearchFilter::Before(_) | SearchFilter::OnOrAfter(_) => Some("m.date_unix"),
        _ => None,
    }
}

/// Whitespace tokenizing that keeps quoted phrases (including the spaces
/// inside them) as one token: `"monthly report"` and `subject:'two words'`
/// stay whole. Quotes open only at token start or right after `:` (a
/// mid-word `'`/`"` like `o'brien` stays literal) and close on the same
/// quote char. Unbalanced quotes degrade gracefully — the tail becomes
/// one token.
fn split_tokens(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in query.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                cur.push(ch);
            }
            Some(_) => cur.push(ch),
            None => match ch {
                '"' | '\'' if cur.is_empty() || cur.ends_with(':') => {
                    quote = Some(ch);
                    cur.push(ch);
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Split parsed terms into the positive FTS expression (AND-joined) and
/// the negative one (OR-joined for a `NOT IN` subquery). Every user token
/// is embedded as a quoted phrase (inner quotes doubled), so the
/// expression can never break out into arbitrary MATCH syntax. FTS5 has
/// no unary `NOT`, so negatives need a positive anchor — a positive term
/// or at least one field predicate.
fn build_match_exprs(terms: &[SearchTerm]) -> (Option<String>, Option<String>) {
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
    (
        (!positive.is_empty()).then(|| positive.join(" AND ")),
        (!negative.is_empty()).then(|| negative.join(" OR ")),
    )
}

const MESSAGE_COLS: &str = "m.id, m.folder_id, m.uid, m.message_id, m.subject,
            m.from_addr, m.to_addrs, m.date_unix, m.size, m.flags,
            m.has_attachments, m.snippet, m.body_path, m.category,
            m.unsub_http, m.unsub_mailto, m.unsub_oneclick";

/// Run a bounded search (T-159 FTS; T-334 fielded operators). Returns
/// full [`MessageMeta`] rows for hits, newest first (`date_unix` DESC,
/// then `uid` DESC for stability). `folder_id` scopes to one folder;
/// `None` searches every folder of the store — an `in:`/`folder:`
/// operator narrows further by folder *name* across accounts.
///
/// Two shapes: positive free text runs through the FTS5 join; a query of
/// only fielded predicates skips the FTS table entirely (a real-column
/// scan, still `LIMIT`-bounded). Empty / noise-only queries return an
/// empty vec; negation-only free text without an anchor stays empty too.
pub fn search_messages(
    store: &crate::store::MailStore,
    query: &str,
    folder_id: Option<i64>,
    limit: u32,
) -> Result<Vec<MessageMeta>> {
    let parsed = parse_query(query);
    let (pos_expr, neg_expr) = build_match_exprs(&parsed.terms);
    if pos_expr.is_none() && parsed.predicates.is_empty() {
        // No anchor: pure noise or negation-only free text (unchanged
        // T-159 semantics — `-spam` alone matches nothing).
        return Ok(Vec::new());
    }
    let limit = limit.clamp(1, MAX_RESULTS);

    // The MATCH parameter is the whole expression string. It is safe to
    // bind as one parameter: it is built exclusively from quoted phrases
    // (inner quotes doubled) plus fixed column names — never raw user
    // text outside a quoted phrase (SECURITY.md rule 9). Predicate values
    // bind individually; their clauses are static strings.
    let mut sql = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(pos) = pos_expr {
        sql.push_str("SELECT ");
        sql.push_str(MESSAGE_COLS);
        sql.push_str(
            " FROM messages m
             JOIN messages_fts f ON f.rowid = m.id
             WHERE messages_fts MATCH ?",
        );
        params.push(Box::new(pos));
    } else {
        sql.push_str("SELECT ");
        sql.push_str(MESSAGE_COLS);
        sql.push_str(" FROM messages m WHERE 1=1");
    }
    // Two bare `?`s — rusqlite numbers each separately, so the scope value
    // binds twice.
    sql.push_str(" AND (? IS NULL OR m.folder_id = ?)");
    params.push(Box::new(folder_id));
    params.push(Box::new(folder_id));
    for p in &parsed.predicates {
        match (p.negated, nullable_column(p)) {
            // Negation over a NULL column keeps the row: absent data cannot
            // match, so it cannot be excluded (see nullable_column).
            (true, Some(col)) => {
                sql.push_str(" AND (");
                sql.push_str(col);
                sql.push_str(" IS NULL OR NOT (");
                sql.push_str(filter_clause(p));
                sql.push_str("))");
            }
            (true, None) => {
                sql.push_str(" AND NOT (");
                sql.push_str(filter_clause(p));
                sql.push(')');
            }
            (false, _) => {
                sql.push_str(" AND ");
                sql.push_str(filter_clause(p));
            }
        }
        if let Some(v) = filter_param(p) {
            params.push(v);
        }
    }
    if let Some(neg) = neg_expr {
        // Negated terms reach the FTS table only through this subquery,
        // which works with or without the positive-terms join above.
        sql.push_str(
            " AND m.id NOT IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)",
        );
        params.push(Box::new(neg));
    }
    sql.push_str(" ORDER BY m.date_unix IS NULL, m.date_unix DESC, m.uid DESC LIMIT ?");
    params.push(Box::new(limit as i64));

    let conn = store.conn();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params), map_message_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn map_message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageMeta> {
    use crate::category::Category;
    let slug: String = r.get(13)?;
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
        category: Category::from_slug(&slug).unwrap_or_default(),
        unsub_http: r.get(14)?,
        unsub_mailto: r.get(15)?,
        unsub_oneclick: r.get::<_, i64>(16)? != 0,
        // `None` = "not yet evaluated" — only the list paths call
        // `attach_auth`; search rows carry no verdicts.
        auth: None,
        attach_risk: None,
        link_risk: None,
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
            category: Default::default(),
            unsub_http: None,
            unsub_mailto: None,
            unsub_oneclick: false,
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

    fn term(text: &str) -> SearchTerm {
        SearchTerm {
            column: None,
            text: text.into(),
            negated: false,
        }
    }

    fn pred(filter: SearchFilter) -> FieldPredicate {
        FieldPredicate {
            filter,
            negated: false,
        }
    }

    #[test]
    fn parse_query_basic_and_scopes() {
        assert_eq!(
            parse_query("invoice urgent").terms,
            vec![term("invoice"), term("urgent")]
        );
        // Fielded operators parse as real-column predicates, never FTS terms.
        let p = parse_query("From:ALICE subject:\"monthly report\" to:bob body:wood");
        assert_eq!(
            p.predicates,
            vec![
                pred(SearchFilter::FromLike("ALICE".into())),
                pred(SearchFilter::SubjectLike("monthly report".into())),
                pred(SearchFilter::ToLike("bob".into())),
            ]
        );
        assert_eq!(
            p.terms,
            vec![SearchTerm {
                column: Some(SearchColumn::Body),
                text: "wood".into(),
                negated: false
            }]
        );
    }

    #[test]
    fn parse_query_negation_noise_and_caps() {
        let p = parse_query("keep -spam");
        assert_eq!(
            p.terms,
            vec![
                term("keep"),
                SearchTerm {
                    negated: true,
                    ..term("spam")
                },
            ]
        );
        // Noise-only / empty input → empty parse (empty result set, not error).
        assert_eq!(parse_query(""), ParsedSearch::default());
        assert_eq!(parse_query("   \t "), ParsedSearch::default());
        assert_eq!(parse_query("-"), ParsedSearch::default());
        assert_eq!(parse_query("-:x"), ParsedSearch::default());
        assert_eq!(parse_query("\"\""), ParsedSearch::default());
        // Unknown operator stays plain text (whole token, "site:foo").
        assert_eq!(parse_query("site:foo").terms, vec![term("site:foo")]);
        // A known operator with a malformed value falls back the same way.
        assert_eq!(
            parse_query("before:tuesday").terms,
            vec![term("before:tuesday")]
        );
        assert_eq!(parse_query("has:cheese").terms, vec![term("has:cheese")]);
        assert_eq!(parse_query("is:sent").terms, vec![term("is:sent")]);
        assert_eq!(parse_query("from:").terms, vec![term("from:")]);
        // Quoted field values are supported (" and ').
        assert_eq!(
            parse_query("subject:\"monthly report\"").predicates,
            vec![pred(SearchFilter::SubjectLike("monthly report".into()))]
        );
        assert_eq!(
            parse_query("in:'Sent Items'").predicates,
            vec![pred(SearchFilter::InFolder("Sent Items".into()))]
        );
        // Negated field operators are real predicates.
        assert_eq!(
            parse_query("-is:unread").predicates,
            vec![FieldPredicate {
                filter: SearchFilter::Unseen,
                negated: true
            }]
        );
        // Cap: MAX_QUERY_TERMS entries total, extras dropped.
        let ten = parse_query("a b c d e f g h i j");
        assert_eq!(ten.terms.len(), MAX_QUERY_TERMS);
        let mixed = parse_query("is:unread a b c d e f g h i j");
        assert_eq!(mixed.terms.len() + mixed.predicates.len(), MAX_QUERY_TERMS);
    }

    #[test]
    fn parse_dates_strictly() {
        let t = |y, m, d| {
            time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d)
                .unwrap()
                .midnight()
                .assume_utc()
                .unix_timestamp()
        };
        assert_eq!(
            parse_query("before:2025-06-15").predicates,
            vec![pred(SearchFilter::Before(t(2025, 6, 15)))]
        );
        assert_eq!(
            parse_query("after:2025-06-15").predicates,
            vec![pred(SearchFilter::OnOrAfter(t(2025, 6, 15)))]
        );
        // Feb 30 is not a calendar date → literal text, not a filter.
        assert_eq!(
            parse_query("before:2025-02-30").terms,
            vec![term("before:2025-02-30")]
        );
        // Loose formats are not dates.
        assert_eq!(
            parse_query("after:2025-6-5").terms,
            vec![term("after:2025-6-5")]
        );
        assert_eq!(
            parse_query("before:2025/06/15").terms,
            vec![term("before:2025/06/15")]
        );
    }

    #[test]
    fn match_exprs_are_bounded_and_quoted() {
        // Every token lands inside a quoted phrase; embedded quotes doubled
        // (o"brien is a literal mid-word quote, not a phrase opener).
        let p = parse_query("o\"brien body:\"re: x\"");
        let (pos, _) = build_match_exprs(&p.terms);
        let sql = pos.unwrap();
        assert!(sql.contains("\"o\"\"brien\""), "{sql}");
        // Scoped multi-word phrase stays one quoted expression.
        assert!(sql.contains("snippet : \"re: x\""), "{sql}");
        assert!(!sql.contains(" OR "), "no OR in positives: {sql}");
        // Negatives join as OR for the NOT IN subquery.
        let p = parse_query("keep -spam -trash");
        let (_, neg) = build_match_exprs(&p.terms);
        assert_eq!(neg.as_deref(), Some("\"spam\" OR \"trash\""));
        // Empty → no expressions.
        assert_eq!(build_match_exprs(&[]), (None, None));
    }

    #[test]
    fn search_finds_by_field_operators() {
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

        // subject (real-column substring now, not an FTS scope)
        assert_eq!(
            subjects(&store.search("subject:quarterly", Some(fid), 50).unwrap()),
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
        // substring + case-insensitive (LIKE, not FTS token match)
        assert_eq!(
            subjects(&store.search("from:AROL@corp", Some(fid), 50).unwrap()),
            vec!["Lunch plans"]
        );
        // body proxy stays an FTS scope
        assert_eq!(
            subjects(&store.search("body:noon", Some(fid), 50).unwrap()),
            vec!["Lunch plans"]
        );
        // AND semantics across free-text terms.
        assert!(
            store
                .search("quarterly lunch", Some(fid), 50)
                .unwrap()
                .is_empty()
        );
        // Field predicate AND free text.
        assert_eq!(
            subjects(&store.search("numbers from:alice", Some(fid), 50).unwrap()),
            vec!["Quarterly report"]
        );
        assert!(
            store
                .search("numbers from:carol", Some(fid), 50)
                .unwrap()
                .is_empty()
        );
    }

    /// Seed INBOX + Work with flagged/unflagged, attached/unattached,
    /// dated rows; `seen` marks `\Seen` on the listed uids.
    fn seeded_rich() -> (MailStore, i64, i64) {
        let store = seeded();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        let work = store.ensure_folder("a1", "Work").unwrap();
        let day = time::Date::from_calendar_date(2025, time::Month::June, 10)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp();
        for (i, (uid, subject, from, att, flags)) in [
            (1u64, "invoice may", "alice@corp.test", true, "\\Seen"),
            (
                2,
                "invoice june",
                "bob@corp.test",
                false,
                "\\Seen \\Flagged",
            ),
            (3, "invoice july", "carol@corp.test", false, ""),
        ]
        .into_iter()
        .enumerate()
        {
            let mut m = msg(uid, subject, from, "me@home.test", "snip");
            m.has_attachments = att;
            m.flags = flags.split_whitespace().map(str::to_string).collect();
            m.date_unix = Some(day + i as i64 * 30 * 86_400); // ~jun10/jul10/aug9
            store.upsert_message(inbox, &m, 100).unwrap();
        }
        let mut m = msg(9, "invoice work", "alice@corp.test", "me@home.test", "snip");
        m.flags = vec!["\\Seen".into()];
        m.date_unix = Some(day + 86_400);
        store.upsert_message(work, &m, 100).unwrap();
        (store, inbox, work)
    }

    #[test]
    fn search_operators_has_is_dates_and_in() {
        let (store, inbox, work) = seeded_rich();

        // has:attachment — real column, not a text term.
        assert_eq!(
            subjects(&store.search("has:attachment", Some(inbox), 50).unwrap()),
            vec!["invoice may"]
        );
        // is:unread / is:read / is:starred — flags tokens.
        assert_eq!(
            subjects(&store.search("is:unread", Some(inbox), 50).unwrap()),
            vec!["invoice july"]
        );
        assert_eq!(
            subjects(&store.search("is:read", None, 50).unwrap()).len(),
            3
        );
        assert_eq!(
            subjects(&store.search("is:starred", Some(inbox), 50).unwrap()),
            vec!["invoice june"]
        );
        // before:/after: — day-boundary semantics on date_unix.
        assert_eq!(
            subjects(&store.search("after:2025-07-01", Some(inbox), 50).unwrap()),
            vec!["invoice july", "invoice june"]
        );
        assert_eq!(
            subjects(&store.search("before:2025-07-01", Some(inbox), 50).unwrap()),
            vec!["invoice may"]
        );
        assert_eq!(
            subjects(
                &store
                    .search("after:2025-06-01 before:2025-07-01", Some(inbox), 50)
                    .unwrap()
            ),
            vec!["invoice may"]
        );
        // in:/folder: — name match, case-insensitive, across folders.
        assert_eq!(
            subjects(&store.search("in:work", None, 50).unwrap()),
            vec!["invoice work"]
        );
        assert_eq!(
            subjects(&store.search("folder:INBOX", None, 50).unwrap()).len(),
            3
        );
        // in: ANDs with a folderId scope — INBOX ∩ Work is empty.
        assert!(store.search("in:work", Some(inbox), 50).unwrap().is_empty());
        let _ = work;
    }

    #[test]
    fn search_filters_only_and_negated_filters() {
        let (store, inbox, _work) = seeded_rich();
        // Filters-only query: no FTS terms at all, still returns rows.
        assert_eq!(
            subjects(&store.search("from:alice", None, 50).unwrap()).len(),
            2
        );
        // Negated field predicate: unread-and-unstarred on INBOX.
        assert_eq!(
            subjects(
                &store
                    .search("is:unread -is:starred", Some(inbox), 50)
                    .unwrap()
            ),
            vec!["invoice july"]
        );
        // Negated field predicate AND negated free text — the predicates
        // supply the anchor that lets the negation exclude.
        assert_eq!(
            subjects(&store.search("is:unread -june", Some(inbox), 50).unwrap()),
            vec!["invoice july"]
        );
        // Pure negation without any anchor still yields nothing (unchanged).
        assert!(store.search("-invoice", None, 50).unwrap().is_empty());
    }

    /// Negated predicates on a NULL column keep the row: `NOT (NULL LIKE ?)`
    /// is NULL, which would silently drop a message whose field is absent.
    /// `-from:boss` means "not matching from:boss", and an unknown sender
    /// does not match — so it stays.
    #[test]
    fn negated_predicate_keeps_null_column_rows() {
        let store = seeded();
        let inbox = store.ensure_folder("a1", "INBOX").unwrap();
        let mut m = msg(1, "mystery", "alice@x", "me@y", "snip");
        m.from_addr = None;
        m.date_unix = None;
        store.upsert_message(inbox, &m, 100).unwrap();
        store
            .upsert_message(inbox, &msg(2, "known", "boss@x", "me@y", "snip"), 100)
            .unwrap();

        // Positive predicate: the NULL-sender row cannot match — excluded.
        assert_eq!(
            subjects(&store.search("from:alice", Some(inbox), 50).unwrap()),
            Vec::<String>::new()
        );
        // Negated predicate on the same column keeps it: nothing proves it
        // is from alice, so `-from:alice` does not exclude it (known is not
        // alice either, so both survive; NULL sorts last per ORDER BY).
        assert_eq!(
            subjects(
                &store
                    .search("is:unread -from:alice", Some(inbox), 50)
                    .unwrap()
            ),
            vec!["known", "mystery"]
        );
        // Same for a NULL date: `-before:2020` means "not before 2020" —
        // known's 2025 date qualifies, mystery's NULL cannot match before
        // so it is not excluded either.
        assert_eq!(
            subjects(
                &store
                    .search("is:unread -before:2020-01-01", Some(inbox), 50)
                    .unwrap()
            ),
            vec!["known", "mystery"]
        );
    }

    #[test]
    fn search_operators_degrade_honestly_and_safely() {
        let (store, inbox, _) = seeded_rich();
        // Unknown operator → literal text: no message contains "site:foo"
        // words → empty, but never an error and never silently dropped.
        assert!(
            store
                .search("site:foo", Some(inbox), 50)
                .unwrap()
                .is_empty()
        );
        // A message whose subject literally mentions the tokens DOES match
        // — proves the token reached the index as text.
        store
            .upsert_message(
                inbox,
                &msg(7, "site:foo explained", "a@x", "b@y", "about site foo"),
                100,
            )
            .unwrap();
        assert_eq!(
            subjects(&store.search("site:foo", Some(inbox), 50).unwrap()),
            vec!["site:foo explained"]
        );
        // Injection: values bind as parameters — a `'`/`%`/quote payload
        // inside an operator is literal data, not SQL syntax.
        assert!(
            store
                .search("from:' OR '1'='1", Some(inbox), 50)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .search("subject:%", Some(inbox), 50)
                .unwrap()
                .is_empty(),
            "escaped wildcard never matches everything"
        );
        assert!(
            store
                .search("in:\"; DROP TABLE messages; --", None, 50)
                .unwrap()
                .is_empty()
        );
        // The table still works afterwards.
        assert_eq!(store.search("invoice", Some(inbox), 50).unwrap().len(), 3);
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
