/**
 * Search view (T-160, T-176, live-wired T-231, operators T-334): results
 * over the real `kiwi_search_messages` IPC — FTS free text AND-ed with
 * fielded operator predicates evaluated server-side on real columns.
 * A labeled client-side fallback over already-loaded real messages
 * applies only when the IPC is unreachable or errors — it never reads
 * mock fixtures; demo mode searches the fixtures directly.
 *
 * Query grammar mirrors `kiwi-mail/src/search.rs`: plain tokens,
 * `"quoted phrases"`, `-negation`, `body:` scope, and the fielded
 * operators `from:` `to:` `subject:` `has:attachment`
 * `is:unread|read|starred` `before:`/`after:YYYY-MM-DD` `in:`/`folder:`.
 * Unknown `key:value` tokens degrade to literal text server-side — the
 * same string the index stores. Syntax chips + the `?` shortcuts overlay
 * surface the grammar; matches highlight with `<mark>`.
 * Demo mode searches the fixtures.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { MessageEnvelope, SearchHit } from "../kiwi";
import { unixToIso } from "../kiwi";
import { api, BackendUnavailableError } from "../ipc";
import { Icon } from "../components/icons/index";

export interface ParsedQuery {
  /** Verbatim backend string (the full grammar — nothing stripped). */
  serverQuery: string;
  /** Positive term texts for highlight (scopes/quotes/negation stripped). */
  highlight: string[];
  from?: string;
  hasAttachment: boolean;
  folder?: string;
  /** True when the query uses `to:` (unmatchable in local fallback). */
  hasToScope: boolean;
}

const KNOWN_SCOPES = new Set(["subject", "from", "to", "body"]);
/** T-334 fielded operator keys — parsed server-side into column
 *  predicates. Peeling them out of `highlight` keeps structural values
 *  ("unread", a date) from being underlined as literal text. */
const FIELD_OPS = new Set(["has", "is", "in", "folder", "before", "after"]);

/** Quote-aware split (mirrors search.rs split_tokens, UI-scale). */
function splitTokens(q: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (const ch of q) {
    if (ch === '"' && (inQuotes || cur === "" || cur.endsWith(":"))) {
      inQuotes = !inQuotes;
      cur += ch;
    } else if (/\s/.test(ch) && !inQuotes) {
      if (cur) {
        out.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur) out.push(cur);
  return out;
}

export function parseSearchQuery(q: string): ParsedQuery {
  const serverTokens: string[] = [];
  const highlight: string[] = [];
  let from: string | undefined;
  let hasAttachment = false;
  let folder: string | undefined;
  let hasToScope = false;
  for (const tok of splitTokens(q)) {
    const low = tok.toLowerCase();
    // T-334: every token reaches the server — fielded operators are real
    // column predicates there now, not UI post-filters.
    serverTokens.push(tok);
    if (low === "has:attachment") hasAttachment = true;
    if (
      (low.startsWith("folder:") && tok.length > 7) ||
      (low.startsWith("in:") && tok.length > 3)
    ) {
      folder = unquote(tok.slice(tok.indexOf(":") + 1));
    }
    // Highlight texts: drop negation, peel display-text scopes and the
    // structural operators (their values aren't body text), trim quotes.
    let h = tok.startsWith("-") ? tok.slice(1) : tok;
    const colon = h.indexOf(":");
    if (colon > 0) {
      const key = h.slice(0, colon).toLowerCase();
      if (FIELD_OPS.has(key)) {
        h = "";
      } else if (KNOWN_SCOPES.has(key)) {
        h = h.slice(colon + 1);
        if (key === "from" && from === undefined) from = unquote(h);
        if (key === "to") hasToScope = true;
      }
    }
    h = unquote(h).trim();
    if (h) highlight.push(h);
  }
  return { serverQuery: serverTokens.join(" "), highlight, from, hasAttachment, folder, hasToScope };
}

/** Strip one matching `"…"`/`'…'` pair (mirrors search.rs `unquote`). */
function unquote(v: string): string {
  return v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))
    ? v.slice(1, -1)
    : v;
}

function setToken(q: string, prefix: string, value: string | null): string {
  const low = prefix.toLowerCase();
  const rest = splitTokens(q).filter((t) => {
    const tLow = t.toLowerCase();
    return !(tLow.startsWith(low) || (tLow.startsWith("-") && tLow.slice(1).startsWith(low)));
  });
  if (value !== null && value !== "") rest.push(`${prefix}${value}`);
  return rest.join(" ");
}

/** Case-insensitive `<mark>` highlight of any term. */
export function Highlight({ text, terms }: { text: string; terms: string[] }) {
  const needles = terms.map((t) => t.toLowerCase()).filter(Boolean);
  if (needles.length === 0 || !text) return <>{text}</>;
  const lower = text.toLowerCase();
  const parts: { key: number; chunk: string; hit: boolean }[] = [];
  let i = 0;
  let k = 0;
  while (i < text.length) {
    let best: number | null = null;
    for (const n of needles) {
      if (n && lower.startsWith(n, i) && (best === null || n.length > best)) best = n.length;
    }
    if (best !== null) {
      parts.push({ key: k++, chunk: text.slice(i, i + best), hit: true });
      i += best;
    } else {
      const start = i;
      while (i < text.length) {
        let stop = false;
        for (const n of needles) {
          if (n && lower.startsWith(n, i)) {
            stop = true;
            break;
          }
        }
        if (stop) break;
        i++;
      }
      parts.push({ key: k++, chunk: text.slice(start, i), hit: false });
    }
  }
  return (
    <>
      {parts.map((p) => (p.hit ? <mark key={p.key}>{p.chunk}</mark> : <span key={p.key}>{p.chunk}</span>))}
    </>
  );
}

export interface SearchResultRow {
  key: string;
  accountId: string;
  folderId: number;
  uid: number;
  from: string;
  subject: string;
  snippet: string;
  date: string;
  hasAttachments: boolean;
  accountEmail: string;
}

function envelopeToRow(m: MessageEnvelope): SearchResultRow {
  return {
    key: m.id,
    accountId: m.accountId,
    folderId: m.folderId,
    uid: m.uid,
    from: m.from,
    subject: m.subject,
    snippet: m.snippet,
    date: m.date,
    hasAttachments: m.hasAttachments,
    accountEmail: m.accountEmail,
  };
}

function hitToRow(h: SearchHit, emailOf: (accountId: string) => string): SearchResultRow {
  return {
    key: `${h.accountId}:${h.folderId}:${h.uid}`,
    accountId: h.accountId,
    folderId: h.folderId,
    uid: h.uid,
    from: h.from,
    subject: h.subject,
    snippet: h.snippet,
    date: h.dateUnix !== null ? unixToIso(h.dateUnix) : "",
    hasAttachments: h.hasAttachments,
    accountEmail: emailOf(h.accountId),
  };
}

/** `YYYY-MM-DD` → that day's UTC midnight in ms; undefined when malformed
 *  (mirrors the strict server parse — loose dates degrade to text). */
function dayBoundaryMs(v: string): number | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return undefined;
  const t = Date.parse(`${v}T00:00:00Z`);
  return Number.isNaN(t) ? undefined : t;
}

/** One fielded operator against an envelope, or `undefined` when the
 *  value is malformed — the server treats that token as literal text and
 *  the fallback does the same. Envelope fields cover every operator
 *  except `to:` (no recipient data locally — noted in-view). */
function fieldOpHit(key: string, rawVal: string, m: MessageEnvelope): boolean | undefined {
  const v = rawVal.toLowerCase();
  switch (key) {
    case "has":
      return v === "attachment" ? m.hasAttachments : undefined;
    case "is":
      switch (v) {
        case "unread":
          return m.unread;
        case "read":
          return !m.unread;
        case "starred":
        case "flagged":
          return m.starred;
        default:
          return undefined;
      }
    case "in":
    case "folder":
      return v ? m.folder.toLowerCase() === v : undefined;
    case "before": {
      const bound = dayBoundaryMs(v);
      return bound === undefined ? undefined : Date.parse(m.date) < bound;
    }
    case "after": {
      const bound = dayBoundaryMs(v);
      return bound === undefined ? undefined : Date.parse(m.date) >= bound;
    }
    default:
      return undefined;
  }
}

/** Local mirror of the server grammar over envelope fields (no `to:` data). */
function localMatches(m: MessageEnvelope, serverQuery: string): boolean {
  const fields = (scope: string): string => {
    switch (scope) {
      case "subject":
        return m.subject.toLowerCase();
      case "from":
        return m.from.toLowerCase();
      case "to":
        return ""; // envelopes carry no recipients — caller notes this
      case "body":
        return m.snippet.toLowerCase();
      default:
        return `${m.from} ${m.subject} ${m.snippet}`.toLowerCase();
    }
  };
  for (const tok of splitTokens(serverQuery)) {
    let negated = false;
    let t = tok;
    if (t.startsWith("-") && t.length > 1) {
      negated = true;
      t = t.slice(1);
    }
    const colon = t.indexOf(":");
    const key = colon > 0 ? t.slice(0, colon).toLowerCase() : "";
    if (key && FIELD_OPS.has(key)) {
      const hit = fieldOpHit(key, unquote(t.slice(colon + 1)), m);
      if (hit !== undefined) {
        // The server evaluates this as a column predicate; mirror it.
        if (negated ? hit : !hit) return false;
        continue;
      }
      // Malformed value → literal text (same fallback as the server).
    }
    let scope = "";
    let text = t;
    if (colon > 0 && KNOWN_SCOPES.has(key) && t.length > colon + 1) {
      scope = key;
      text = t.slice(colon + 1);
    }
    if (scope === "to") continue; // server-only locally — noted in-view
    text = unquote(text).toLowerCase();
    if (!text) continue;
    const hit = fields(scope).includes(text);
    if (negated ? hit : !hit) return false;
  }
  return true;
}

const SYNTAX_CHIPS = [
  "from:",
  "to:",
  "subject:",
  "body:",
  "has:attachment",
  "is:unread",
  "is:starred",
  "before:",
  "after:",
  "in:",
  "-",
  '"phrase"',
];

export function SearchView({
  query,
  onQuery,
  demo,
  messages,
  emailOf,
  onOpenHit,
}: {
  query: string;
  onQuery: (q: string) => void;
  demo: boolean;
  /** Already-loaded envelopes for the labeled local fallback. */
  messages: MessageEnvelope[];
  emailOf: (accountId: string) => string;
  onOpenHit: (row: SearchResultRow) => void;
}) {
  const parsed = useMemo(() => parseSearchQuery(query), [query]);
  const [serverRows, setServerRows] = useState<SearchResultRow[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [fromDraft, setFromDraft] = useState(parsed.from ?? "");
  const [folderDraft, setFolderDraft] = useState(parsed.folder ?? "");
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    setFromDraft(parsed.from ?? "");
    setFolderDraft(parsed.folder ?? "");
  }, [parsed.from, parsed.folder]);

  // Live search (debounced) with the verbatim server grammar; any failure
  // → labeled local fallback.
  useEffect(() => {
    if (demo || !parsed.serverQuery.trim()) {
      setServerRows(null);
      setSearchError(null);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const t = window.setTimeout(() => {
      void (async () => {
        try {
          const hits = await api.searchMessages(parsed.serverQuery.trim(), 50);
          if (!cancelled) {
            setServerRows(hits.map((h) => hitToRow(h, emailOf)));
            setSearchError(null);
          }
        } catch (e) {
          if (!cancelled) {
            setServerRows(null);
            if (!(e instanceof BackendUnavailableError)) {
              setSearchError(e instanceof Error ? e.message : String(e));
            }
          }
        } finally {
          if (!cancelled) setSearching(false);
        }
      })();
    }, 300);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [demo, parsed.serverQuery, emailOf]);

  const localRows = useMemo(() => {
    return messages.filter((m) => localMatches(m, parsed.serverQuery)).map(envelopeToRow);
  }, [messages, parsed]);

  // T-334: no post-filtering of server rows — the backend evaluates every
  // operator itself now (has:/is:/in:/folder:/before:/after: included).
  const usingServer = serverRows !== null;
  const rows = usingServer ? serverRows : localRows;

  const insertChip = (chip: string) => {
    const token = chip === '"phrase"' ? '"phrase"' : chip === "-" ? "-" : chip;
    onQuery(query.trim() ? `${query.trim()} ${token}` : token);
    window.setTimeout(() => inputRef.current?.focus(), 0);
  };

  return (
    <section aria-label="Search results" style={{ maxWidth: "52rem" }}>
      <h1>Search {demo && <small style={{ color: "var(--kiwi-text-secondary)" }}>(demo)</small>}</h1>
      <p>
        <label>
          Query:{" "}
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder='terms, from:a, subject:"two words", is:unread, has:attachment, before:2025-01-01, in:Work, -spam'
            style={{ width: "min(30rem, 100%)" }}
            aria-label="Search query"
          />
        </label>
      </p>
      <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap", marginBottom: "0.5rem" }} aria-label="Syntax hints">
        {SYNTAX_CHIPS.map((chip) => (
          <button
            key={chip}
            type="button"
            onClick={() => insertChip(chip)}
            title={
              chip === "-"
                ? "Negation prefix (e.g. invoice -unpaid)"
                : chip === '"phrase"'
                  ? "Exact phrase"
                  : chip === "has:attachment"
                    ? "Only messages with attachments"
                    : chip === "is:unread" || chip === "is:starred"
                      ? "Flag predicate (also is:read)"
                      : chip === "before:" || chip === "after:"
                        ? "Date boundary: YYYY-MM-DD"
                        : chip === "in:"
                          ? "Folder name (folder: works too)"
                          : `Scope: ${chip}value`
            }
            style={{ fontSize: "0.8rem" }}
          >
            <code>{chip}</code>
          </button>
        ))}
      </div>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "0.6rem" }} aria-label="Filter chips">
        <label>
          <small>from: </small>
          <input
            type="text"
            value={fromDraft}
            onChange={(e) => {
              setFromDraft(e.target.value);
              const v = e.target.value.trim();
              const stripped = query.replace(/from:(?:"[^"]*"|[^\s]+)/gi, "").trim().replace(/\s{2,}/g, " ");
              onQuery(setToken(stripped, "from:", v ? (v.includes(" ") ? `"${v}"` : v) : null));
            }}
            placeholder="any sender"
            style={{ width: "10rem" }}
            aria-label="Filter by sender"
          />
        </label>
        <button
          type="button"
          aria-pressed={parsed.hasAttachment}
          onClick={() => onQuery(setToken(query, "has:", parsed.hasAttachment ? null : "attachment"))}
          title="Server predicate: only messages with attachments"
        >
          {parsed.hasAttachment && <Icon name="check" size={11} />} has:attachment
        </button>
        <label>
          <small>folder: </small>
          <input
            type="text"
            value={folderDraft}
            onChange={(e) => {
              setFolderDraft(e.target.value);
              // `in:` is canonical; `folder:` remains a valid alias. Strip
              // both so the field replaces either spelling.
              onQuery(setToken(setToken(query, "folder:", null), "in:", e.target.value.trim() || null));
            }}
            placeholder="any folder"
            style={{ width: "10rem" }}
            aria-label="Filter by folder"
          />
        </label>
        {(parsed.from || parsed.hasAttachment || parsed.folder) && (
          <button
            type="button"
            onClick={() => onQuery(setToken(setToken(setToken(query, "from:", null), "has:", null), "folder:", null))}
          >
            Clear filters
          </button>
        )}
      </div>
      <p role="status">
        <small style={{ color: "var(--kiwi-text-secondary)" }}>
          {searching
            ? "Searching server…"
            : usingServer
              ? `Server results (${rows.length}) — text terms + fielded operators ran in the backend.`
              : demo
                ? `Local demo results (${rows.length}) — fixtures only.`
                : `Local results (${rows.length}) — search IPC unavailable; grammar mirrored over already-loaded messages${parsed.hasToScope ? "; to: is server-only here" : ""}.`}
        </small>
      </p>
      {searchError && (
        <div className="kiwi-banner error" role="alert">
          <small>
            Server search failed ({searchError}) — showing local results.
          </small>
        </div>
      )}
      {query.trim() && rows.length === 0 && !searching && (
        <div className="kiwi-empty">
          <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true"><Icon name="search" size={28} /></span>
          <strong>No matches</strong>
          <br />
          <small>Try fewer terms, or clear the filter chips.</small>
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }} role="list" aria-label="Search results">
        {rows.map((r) => (
          <article
            key={r.key}
            role="listitem"
            className="kiwi-row"
            tabIndex={0}
            onClick={() => onOpenHit(r)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onOpenHit(r);
            }}
            aria-label={`From ${r.from}: ${r.subject}`}
          >
            <div style={{ display: "flex", justifyContent: "space-between", gap: "0.4rem" }}>
              <span>
                <Highlight text={r.from} terms={parsed.highlight} />
                {r.hasAttachments && <Icon name="paperclip" size={12} label="has attachments" />}
              </span>
              <span style={{ color: "var(--kiwi-text-secondary)", fontSize: "0.8rem" }}>
                {r.date ? new Date(r.date).toLocaleString() : "—"}
              </span>
            </div>
            <div>
              <Highlight text={r.subject} terms={parsed.highlight} />
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
              {r.accountEmail} · <Highlight text={r.snippet} terms={parsed.highlight} />
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
