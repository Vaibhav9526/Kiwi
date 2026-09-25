/**
 * Search view (T-160, T-176, live-wired T-231): results over the real
 * `kiwi_search_messages` IPC (lock-gated FTS over the local store,
 * `accountId` resolved server-side per hit). A labeled client-side
 * fallback over already-loaded real messages applies only when the IPC
 * is unreachable or errors — it never reads mock fixtures; demo mode
 * searches the fixtures directly.
 *
 * Query grammar mirrors `kiwi-mail/src/search.rs` exactly: plain tokens,
 * `subject:`/`from:`/`to:`/`body:` scopes, `"quoted phrases"`, `-negation`
 * (unknown `prefix:` stays literal). `has:attachment` and `folder:` are
 * UI-side post-filters — stripped before the server call, applied to both
 * sources. Syntax chips surface the grammar; matches highlight with `<mark>`.
 * Demo mode searches the fixtures.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { MessageEnvelope, SearchHit } from "../kiwi";
import { unixToIso } from "../kiwi";
import { api, BackendUnavailableError } from "../ipc";

export interface ParsedQuery {
  /** Verbatim backend string (real grammar; UI-only tokens removed). */
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
    if (low === "has:attachment") {
      hasAttachment = true;
      continue;
    }
    if (low.startsWith("folder:") && tok.length > 7) {
      folder = tok.slice(7);
      continue;
    }
    serverTokens.push(tok);
    // Highlight texts: drop negation, peel known scopes, trim quotes.
    let h = tok.startsWith("-") ? tok.slice(1) : tok;
    const colon = h.indexOf(":");
    if (colon > 0 && KNOWN_SCOPES.has(h.slice(0, colon).toLowerCase())) {
      const scope = h.slice(0, colon).toLowerCase();
      h = h.slice(colon + 1);
      if (scope === "from" && from === undefined) from = h.replace(/^"|"$/g, "");
      if (scope === "to") hasToScope = true;
    }
    h = h.replace(/^"|"$/g, "").trim();
    if (h) highlight.push(h);
  }
  return { serverQuery: serverTokens.join(" "), highlight, from, hasAttachment, folder, hasToScope };
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
    let scope = "";
    let text = t;
    const colon = t.indexOf(":");
    if (colon > 0 && KNOWN_SCOPES.has(t.slice(0, colon).toLowerCase()) && t.length > colon + 1) {
      scope = t.slice(0, colon).toLowerCase();
      text = t.slice(colon + 1);
    }
    if (scope === "to") continue; // server-only locally — noted in-view
    text = text.replace(/^"|"$/g, "").toLowerCase();
    if (!text) continue;
    const hit = fields(scope).includes(text);
    if (negated ? hit : !hit) return false;
  }
  return true;
}

const SYNTAX_CHIPS = ["from:", "to:", "subject:", "body:", "-", '"phrase"', "has:attachment", "folder:"];

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
    const folder = (parsed.folder ?? "").toLowerCase();
    return messages
      .filter((m) => {
        if (parsed.hasAttachment && !m.hasAttachments) return false;
        if (folder && !`${m.folder} ${m.accountEmail}`.toLowerCase().includes(folder)) return false;
        return localMatches(m, parsed.serverQuery);
      })
      .map(envelopeToRow);
  }, [messages, parsed]);

  // UI-side post-filters also apply to server rows (the backend never sees
  // has:/folder: tokens).
  const serverFiltered = useMemo(() => {
    if (serverRows === null) return null;
    const folder = (parsed.folder ?? "").toLowerCase();
    return serverRows.filter((r) => {
      if (parsed.hasAttachment && !r.hasAttachments) return false;
      if (folder && !r.accountEmail.toLowerCase().includes(folder)) return false;
      return true;
    });
  }, [serverRows, parsed]);

  const usingServer = serverFiltered !== null;
  const rows = usingServer ? serverFiltered : localRows;

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
            placeholder='terms, from:a, to:b, subject:report, body:wood, -spam, "exact phrase"'
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
                    ? "Post-filter: only messages with attachments"
                    : chip === "folder:"
                      ? "Post-filter: folder/account substring"
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
          title="UI-side filter (never sent to the server)"
        >
          {parsed.hasAttachment ? "✓ " : ""}has:attachment
        </button>
        <label>
          <small>folder: </small>
          <input
            type="text"
            value={folderDraft}
            onChange={(e) => {
              setFolderDraft(e.target.value);
              onQuery(setToken(query, "folder:", e.target.value.trim()));
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
              ? `Server results (${rows.length}) — FTS grammar ran in the backend.`
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
          <span className="kiwi-empty-icon" aria-hidden="true">🔍</span>
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
                {r.hasAttachments && <span aria-label="has attachments"> 📎</span>}
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
