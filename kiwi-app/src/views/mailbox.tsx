/**
 * Mailbox view (T-143): live folders/messages/body via kiwi.ipc/1, sync,
 * outbox with cancel/flush, per-account trust pills. Star/read toggles stay
 * local-only (the command surface has no flag-mutation command — documented
 * in the view). Demo mode renders the T-112 fixtures.
 */
import { useEffect } from "react";
import type { CSSProperties } from "react";
import type { FindingInfo, MessageBodyView, MessageEnvelope, OutboxItem } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "../ipc";
import { navigate } from "../router";
import { SecurityPill } from "../components/security";

const grid: CSSProperties = { display: "grid", gridTemplateColumns: "minmax(280px, 380px) 1fr", gap: "0.8rem", height: "100%" };
const listStyle: CSSProperties = { overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.3rem" };

function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export interface MailboxProps {
  folder: string;
  folderLabel: string;
  messages: MessageEnvelope[];
  messagesLoading: boolean;
  messagesError: string | null;
  selectedId?: string;
  body: MessageBodyView | null;
  bodyLoading: boolean;
  bodyError: string | null;
  findings: FindingInfo[];
  locked: boolean;
  syncing: boolean;
  syncNote: string | null;
  outbox: OutboxItem[];
  onOpenFinding: (index: number) => void;
  onToggleStar: (id: string) => void;
  onToggleRead: (id: string) => void;
  onSync: () => void;
  onFlushOutbox: () => void;
  onCancelSend: (queueId: string) => void;
  onOutboxRefresh: () => void;
}

export function MailboxView(props: MailboxProps) {
  const { folder, folderLabel, messages, selectedId, findings, locked } = props;
  const selected = messages.find((m) => m.id === selectedId) ?? messages[0];

  // Live outbox progress (kiwi://outbox status events) — refresh on arrival.
  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    listen("kiwi://outbox", () => props.onOutboxRefresh()).then((fn) => {
      unlisten = fn;
    }).catch(() => undefined);
    return () => unlisten?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [folder]);

  const stepSelection = (dir: 1 | -1) => {
    if (!selected || messages.length === 0) return;
    const i = messages.findIndex((m) => m.id === selected.id);
    const next = messages[(i + dir + messages.length) % messages.length];
    if (next) navigate({ name: "mail", folder, messageId: next.id });
  };

  return (
    <div style={grid}>
      <section aria-label={`${folderLabel} message list`}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
          <h1 style={{ fontSize: "1.1rem", margin: 0 }}>
            {folderLabel} <small style={{ color: "var(--kiwi-text-secondary)" }}>({folder === "outbox" ? props.outbox.length : messages.length})</small>
          </h1>
          {folder !== "outbox" ? (
            <button type="button" onClick={props.onSync} disabled={props.syncing} aria-label="Sync now">
              {props.syncing ? "Syncing…" : "⟳ Sync"}
            </button>
          ) : (
            <button type="button" onClick={props.onFlushOutbox} aria-label="Send all queued mail now">
              Send all now
            </button>
          )}
        </div>
        {props.syncNote && (
          <p role="status">
            <small>{props.syncNote}</small>
          </p>
        )}
        {folder === "outbox" ? (
          <OutboxList outbox={props.outbox} onCancelSend={props.onCancelSend} />
        ) : (
          <>
            {props.messagesLoading && (
              <div role="status" aria-label="Loading messages">
                <div className="kiwi-skeleton" />
                <div className="kiwi-skeleton" />
                <div className="kiwi-skeleton" />
              </div>
            )}
            {props.messagesError && (
              <div className="kiwi-banner error" role="alert">
                <small>{props.messagesError}</small>
              </div>
            )}
            {messages.length === 0 && !props.messagesLoading && (
              <div className="kiwi-empty">
                <span className="kiwi-empty-icon" aria-hidden="true">✉</span>
                <strong>Nothing here</strong>
                <br />
                <small>No messages in this folder yet.</small>
              </div>
            )}
            <div
              style={listStyle}
              role="listbox"
              aria-label="Messages. Press n or p to move between messages."
              aria-activedescendant={selected?.id}
              onKeyDown={(e) => {
                if (e.key === "n") stepSelection(1);
                else if (e.key === "p") stepSelection(-1);
                else if (e.key === "u" && selected) props.onToggleRead(selected.id);
              }}
            >
              {messages.map((m) => (
            <article
              key={m.id}
              id={m.id}
              role="option"
              className={`kiwi-row${m.unread ? " is-unread" : ""}`}
              aria-selected={m.id === selected?.id}
              aria-label={`${m.unread ? "Unread" : "Read"} from ${m.from}: ${m.subject}. Account trust ${severityLabel(m.trust)}.`}
              onClick={() => navigate({ name: "mail", folder, messageId: m.id })}
              onKeyDown={(e) => {
                if (e.key === "Enter") navigate({ name: "mail", folder, messageId: m.id });
              }}
              tabIndex={0}
            >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: "0.4rem" }}>
                    <span>
                      {m.unread && <span aria-hidden="true">● </span>}
                      {m.starred && <span aria-label="starred">★ </span>}
                      {m.from}
                    </span>
                    <span title={m.date} style={{ color: "var(--kiwi-text-secondary)", fontSize: "0.8rem" }}>
                      {formatDate(m.date)}
                    </span>
                  </div>
                  <div>{m.subject}</div>
                  <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
                    <span aria-hidden="true" title={`Account trust: ${severityLabel(m.trust)}`}>
                      [{severityGlyph(m.trust)}]
                    </span>{" "}
                    {m.snippet}
                  </div>
                </article>
              ))}
            </div>
          </>
        )}
      </section>
      <section className="kiwi-reader" aria-label="Message reader" tabIndex={0}>
        {!selected && folder !== "outbox" && <p>Select a message to read.</p>}
        {folder === "outbox" && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>Queued sends live here. Undo works while the grace window is open; “Send all now” skips remaining grace.</small>
          </p>
        )}
        {selected && folder !== "outbox" && (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
              <h2 style={{ margin: 0 }}>{selected.subject}</h2>
              <SecurityPill
                level={selected.trust}
                summary={`Account trust for ${selected.accountEmail}. Per-message session attribution is not yet exposed by the backend.`}
                onOpen={() => props.onOpenFinding(0)}
              />
            </div>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              From {selected.from} · To {selected.accountEmail} · {formatDate(selected.date)}
            </p>
            {locked ? (
              <p role="note">Message body unavailable — mailbox is locked.</p>
            ) : props.bodyLoading ? (
              <div role="status" aria-label="Loading message body">
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton text" />
                <div className="kiwi-skeleton" />
              </div>
            ) : props.bodyError ? (
              <div className="kiwi-banner error" role="alert">
                <small>{props.bodyError}</small>
              </div>
            ) : props.body ? (
              <>
                {props.body.attachments.length > 0 && (
                  <p>
                    <small>
                      Attachments: {props.body.attachments.map((a) => `${a.filename} (${a.size} B)`).join(", ")} (download
                      arrives with a file-save command — not yet in kiwi.ipc/1).
                    </small>
                  </p>
                )}
                <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "inherit" }}>{props.body.textBody}</pre>
                {props.body.htmlBody && (
                  <p style={{ color: "var(--kiwi-text-secondary)" }}>
                    <small>An HTML variant exists but is not rendered: remote content stays blocked by default.</small>
                  </p>
                )}
              </>
            ) : (
              <p>{selected.snippet}</p>
            )}
            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              <button type="button" onClick={() => navigate({ name: "compose" })}>
                Reply
              </button>
              <button type="button" onClick={() => props.onToggleStar(selected.id)} aria-pressed={selected.starred}>
                {selected.starred ? "Unstar" : "Star"}
              </button>
              <button type="button" onClick={() => props.onToggleRead(selected.id)}>
                Mark {selected.unread ? "read" : "unread"} (u)
              </button>
              <button type="button" disabled={findings.length === 0} onClick={() => props.onOpenFinding(0)}>
                Security details ({findings.length})
              </button>
            </div>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>Star/read flags are local-only: kiwi.ipc/1 exposes no flag-mutation command.</small>
            </p>
          </>
        )}
      </section>
    </div>
  );
}

function OutboxList({ outbox, onCancelSend }: { outbox: OutboxItem[]; onCancelSend: (queueId: string) => void }) {
  if (outbox.length === 0) {
    return (
      <div className="kiwi-empty">
        <span className="kiwi-empty-icon" aria-hidden="true">📤</span>
        <strong>Outbox is empty</strong>
        <br />
        <small>Queued and scheduled sends will appear here.</small>
      </div>
    );
  }
  return (
    <div style={listStyle} role="list" aria-label="Queued sends">
      {outbox.map((o) => (
        <article key={o.queueId} role="listitem" style={{ border: "1px solid var(--kiwi-border)", borderRadius: "8px", padding: "0.5rem 0.6rem" }}>
          <div>
            <strong>{o.subject || "(no subject)"}</strong>
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
            To {o.to.join(", ")} · attempts {o.attempts} · {o.cancelable ? "undo window open" : "dispatching"}
          </div>
          <div style={{ marginTop: "0.3rem" }}>
            <button type="button" onClick={() => onCancelSend(o.queueId)} disabled={!o.cancelable}>
              Undo send
            </button>
          </div>
        </article>
      ))}
    </div>
  );
}
