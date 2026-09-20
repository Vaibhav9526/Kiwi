/**
 * Search view (T-160): results over `kiwi_search_messages` (Agent 8's pending
 * command) with a labeled client-side fallback over already-loaded messages.
 * Query language: plain terms plus `from:<addr>`, `has:attachment`, and
 * `folder:<text>` tokens — parsed once, shown as removable filter chips, and
 * honored by both the server call (opaque string) and the local fallback.
 * Matches highlight with `<mark>`. Demo mode searches the fixtures.
 */

import { useEffect, useMemo, useState } from "react";
import type { MessageEnvelope, SearchHit } from "../kiwi";
import { unixToIso } from "../kiwi";
import { api, BackendUnavailableError } from "../ipc";

export interface ParsedQuery {
  terms: string[];
  from?: string;
  hasAttachment: boolean;
  folder?: string;
}

/** Split `from:/has:/folder:` tokens from free-text terms. */
export function parseSearchQuery(q: string): ParsedQuery {
  const terms: string[] = [];
  let from: string | undefined;
  let hasAttachment = false;
  let folder: string | undefined;
  for (const tok of q.trim().split(/\s+/).filter(Boolean)) {
    const low = tok.toLowerCase();
    if (low.startsWith("from:") && tok.length > 5) from = tok.slice(5);
    else if (low === "has:attachment") hasAttachment = true;
    else if (low.startsWith("folder:") && tok.length > 7) folder = tok.slice(7);
    else terms.push(tok);
  }
  return { terms, from, hasAttachment, folder };
}

function setToken(q: string, prefix: string, value: string | null): string {
  const low = prefix.toLowerCase();
  const rest = q
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .filter((t) => !t.toLowerCase().startsWith(low));
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

  useEffect(() => {
    setFromDraft(parsed.from ?? "");
    setFolderDraft(parsed.folder ?? "");
  }, [parsed.from, parsed.folder]);

  // Live search (debounced); any failure → labeled local fallback.
  useEffect(() => {
    if (demo || !query.trim()) {
      setServerRows(null);
      setSearchError(null);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const t = window.setTimeout(() => {
      void (async () => {
        try {
          const hits = await api.searchMessages(query.trim(), 50);
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
  }, [demo, query, emailOf]);

  const localRows = useMemo(() => {
    const terms = [...parsed.terms.map((t) => t.toLowerCase())];
    const from = (parsed.from ?? "").toLowerCase();
    const folder = (parsed.folder ?? "").toLowerCase();
    return messages
      .filter((m) => {
        if (parsed.hasAttachment && !m.hasAttachments) return false;
        if (from && !m.from.toLowerCase().includes(from)) return false;
        if (folder && !`${m.folder} ${m.accountEmail}`.toLowerCase().includes(folder)) return false;
        const hay = `${m.from} ${m.subject} ${m.snippet}`.toLowerCase();
        return terms.every((t) => hay.includes(t));
      })
      .map(envelopeToRow);
  }, [messages, parsed]);

  const usingServer = serverRows !== null;
  const rows = usingServer ? serverRows : localRows;
  const highlightTerms = [...parsed.terms, ...(parsed.from ? [parsed.from] : [])];

  return (
    <section aria-label="Search results" style={{ maxWidth: "52rem" }}>
      <h1>Search {demo && <small style={{ color: "var(--kiwi-text-secondary)" }}>(demo)</small>}</h1>
      <p>
        <label>
          Query:{" "}
          <input
            type="search"
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder="terms, from:a@b, has:attachment, folder:inbox"
            style={{ width: "min(28rem, 100%)" }}
            aria-label="Search query"
          />
        </label>
      </p>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "0.6rem" }} aria-label="Filter chips">
        <label>
          <small>from: </small>
          <input
            type="text"
            value={fromDraft}
            onChange={(e) => {
              setFromDraft(e.target.value);
              onQuery(setToken(query, "from:", e.target.value.trim()));
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
              ? `Server results (${rows.length}) — query ran in the backend.`
              : demo
                ? `Local demo results (${rows.length}) — fixtures only.`
                : `Local results (${rows.length}) — search IPC not yet in the backend; filtering loaded messages only.`}
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
                <Highlight text={r.from} terms={highlightTerms} />
                {r.hasAttachments && <span aria-label="has attachments"> 📎</span>}
              </span>
              <span style={{ color: "var(--kiwi-text-secondary)", fontSize: "0.8rem" }}>
                {r.date ? new Date(r.date).toLocaleString() : "—"}
              </span>
            </div>
            <div>
              <Highlight text={r.subject} terms={highlightTerms} />
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
              {r.accountEmail} · <Highlight text={r.snippet} terms={highlightTerms} />
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
