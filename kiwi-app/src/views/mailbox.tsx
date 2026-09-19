/**
 * Mailbox view (T-112): message list (016) + reader (017) + S-01 pill.
 * Surfaces KIWI-UI-015/016/017. Real sync/paging arrives with kiwi-mail
 * (Agent 2, T-105/T-106); this scaffold renders IPC-or-demo envelopes.
 */
import type { CSSProperties } from "react";
import type { FindingInfo, MessageEnvelope } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";
import { navigate } from "../router";
import { SecurityPill } from "../components/security";

const grid: CSSProperties = { display: "grid", gridTemplateColumns: "minmax(280px, 380px) 1fr", gap: "0.8rem", height: "100%" };
const listStyle: CSSProperties = { overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.3rem" };
const readerStyle: CSSProperties = {
  background: "var(--kiwi-surface)",
  border: "1px solid var(--kiwi-border)",
  borderRadius: "8px",
  padding: "0.9rem",
  overflowY: "auto",
};

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function MailboxView({
  folder,
  folderLabel,
  messages,
  selectedId,
  findings,
  locked,
  onOpenFinding,
}: {
  folder: string;
  folderLabel: string;
  messages: MessageEnvelope[];
  selectedId?: string;
  findings: FindingInfo[];
  locked: boolean;
  onOpenFinding: (index: number) => void;
}) {
  const selected = messages.find((m) => m.id === selectedId) ?? messages[0];
  return (
    <div style={grid}>
      <section aria-label={`${folderLabel} message list`}>
        <h1 style={{ fontSize: "1.1rem", margin: "0 0 0.5rem" }}>
          {folderLabel} <small style={{ color: "var(--kiwi-text-secondary)" }}>({messages.length})</small>
        </h1>
        {messages.length === 0 && <p>No messages in this folder.</p>}
        <div style={listStyle} role="listbox" aria-label="Messages" aria-activedescendant={selected?.id}>
          {messages.map((m) => (
            <article
              key={m.id}
              id={m.id}
              role="option"
              aria-selected={m.id === selected?.id}
              aria-label={`${m.unread ? "Unread" : "Read"} from ${m.from}: ${m.subject}. Security ${severityLabel(m.trust)}.`}
              onClick={() => navigate({ name: "mail", folder, messageId: m.id })}
              onKeyDown={(e) => {
                if (e.key === "Enter") navigate({ name: "mail", folder, messageId: m.id });
              }}
              tabIndex={0}
              style={{
                border: "1px solid var(--kiwi-border)",
                borderRadius: "8px",
                padding: "0.5rem 0.6rem",
                background: m.id === selected?.id ? "var(--kiwi-surface)" : "transparent",
                fontWeight: m.unread ? 700 : 400,
                cursor: "pointer",
              }}
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
                <span aria-hidden="true" title={`Security: ${severityLabel(m.trust)}`}>
                  [{severityGlyph(m.trust)}]
                </span>{" "}
                {m.snippet}
              </div>
            </article>
          ))}
        </div>
      </section>
      <section style={readerStyle} aria-label="Message reader" tabIndex={0}>
        {!selected && <p>Select a message to read.</p>}
        {selected && (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
              <h2 style={{ margin: 0 }}>{selected.subject}</h2>
              <SecurityPill
                level={selected.trust}
                summary={`Delivered via ${selected.accountEmail}.`}
                onOpen={() => onOpenFinding(0)}
              />
            </div>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              From {selected.from} · To {selected.accountEmail} · {formatDate(selected.date)}
            </p>
            {locked ? (
              <p role="note">Message body unavailable — mailbox is locked.</p>
            ) : (
              <>
                <p>{selected.snippet}</p>
                <p style={{ color: "var(--kiwi-text-secondary)" }}>
                  <small>Full body render arrives with kiwi-mail message fetch (T-105/T-106).</small>
                </p>
              </>
            )}
            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              <button type="button" onClick={() => navigate({ name: "compose" })}>
                Reply
              </button>
              <button type="button" disabled={findings.length === 0} onClick={() => onOpenFinding(0)}>
                Security details ({findings.length})
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
