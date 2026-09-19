/**
 * Composer (T-112): addressing, body, attachments stub, policy banner (007),
 * templates picker (022), send-later popover + undo-send grace toast (021).
 * Demo policy rule is LOCAL-ONLY scaffolding (addresses ending
 * @blocked.test / outside *.test warn) until kiwi-admin bridge (T-108).
 */
import { useEffect, useRef, useState } from "react";
import type { PolicyBannerVerdict } from "../kiwi";
import { PolicyBanner } from "../components/security";

const TEMPLATES = ["Status update", "Meeting request", "Out of office"];
const GRACE_SECONDS = 10;

function demoEvaluate(recipients: string[]): { verdict: PolicyBannerVerdict; offenders: string[] } {
  const blocked = recipients.filter((r) => r.trim().toLowerCase().endsWith("@blocked.test"));
  if (blocked.length > 0) return { verdict: "block", offenders: blocked };
  const warned = recipients.filter((r) => {
    const t = r.trim().toLowerCase();
    return t.includes("@") && !t.endsWith(".test");
  });
  if (warned.length > 0) return { verdict: "warn", offenders: warned };
  return { verdict: "none", offenders: [] };
}

export function ComposeView() {
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [scheduled, setScheduled] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [graceLeft, setGraceLeft] = useState<number | null>(null);
  const [sentNote, setSentNote] = useState<string | null>(null);
  const [showSchedule, setShowSchedule] = useState(false);
  const timer = useRef<number | null>(null);

  const evalResult = demoEvaluate(recipients);
  const blocked = evalResult.verdict === "block";

  useEffect(() => {
    if (graceLeft === null) return;
    if (graceLeft <= 0) {
      setGraceLeft(null);
      setSending(false);
      setSentNote(scheduled ? `Scheduled for ${scheduled}.` : "Message sent.");
      return;
    }
    timer.current = window.setTimeout(() => setGraceLeft((g) => (g === null ? null : g - 1)), 1000);
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [graceLeft, scheduled]);

  const addRecipient = () => {
    const v = to.trim();
    if (v && !recipients.includes(v)) setRecipients((r) => [...r, v]);
    setTo("");
  };

  const send = () => {
    if (blocked || sending) return;
    setSentNote(null);
    setSending(true);
    setGraceLeft(GRACE_SECONDS);
  };

  const undo = () => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    setGraceLeft(null);
    setSending(false);
    setSentNote("Send undone — back to draft.");
  };

  return (
    <section aria-label="Compose message" style={{ maxWidth: "46rem" }}>
      <h1>Compose</h1>
      <PolicyBanner verdict={evalResult.verdict} offenders={evalResult.offenders} onRemove={(a) => setRecipients((r) => r.filter((x) => x !== a))} />
      <p>
        <label>
          To:{" "}
          <input
            type="email"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addRecipient();
              }
            }}
            placeholder="name@example.test, Enter to add"
          />{" "}
          <button type="button" onClick={addRecipient}>
            Add
          </button>
        </label>
      </p>
      <p aria-label="Recipients">
        {recipients.map((r) => (
          <span key={r} className="kiwi-pill unknown" style={{ marginRight: "0.3rem" }}>
            {r}{" "}
            <button type="button" onClick={() => setRecipients((x) => x.filter((y) => y !== r))} aria-label={`Remove ${r}`}>
              ✕
            </button>
          </span>
        ))}
        {recipients.length === 0 && <small style={{ color: "var(--kiwi-text-secondary)" }}>No recipients yet.</small>}
      </p>
      <p>
        <label>
          Subject: <input type="text" value={subject} onChange={(e) => setSubject(e.target.value)} style={{ width: "70%" }} />
        </label>
      </p>
      <p>
        <label>
          Template:{" "}
          <select
            aria-label="Insert template"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) setBody((b) => `${b}\n[${e.target.value} template inserted]`);
              e.target.value = "";
            }}
          >
            <option value="">Insert template…</option>
            {TEMPLATES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
      </p>
      <p>
        <label htmlFor="compose-body">Body</label>
        <br />
        <textarea id="compose-body" rows={10} value={body} onChange={(e) => setBody(e.target.value)} style={{ width: "100%" }} />
      </p>
      <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
        <button type="button" onClick={send} disabled={blocked || sending} aria-disabled={blocked || sending}>
          {sending ? `Sending in ${graceLeft}s…` : scheduled ? "Schedule send" : "Send (Ctrl+Enter)"}
        </button>
        <button type="button" onClick={() => setShowSchedule((s) => !s)} aria-expanded={showSchedule}>
          Send later
        </button>
        <button type="button" disabled>
          Attach (soon)
        </button>
      </div>
      {showSchedule && (
        <p>
          <label>
            Schedule for:{" "}
            <input type="datetime-local" onChange={(e) => setScheduled(e.target.value || null)} />
          </label>{" "}
          <small>Timezone shown at send time. Offline at due time → sends on reconnect.</small>
        </p>
      )}
      {graceLeft !== null && (
        <div className="kiwi-banner warn" role="status" style={{ marginTop: "0.6rem" }}>
          Sending in {graceLeft}s —{" "}
          <button type="button" onClick={undo}>
            Undo send
          </button>
        </div>
      )}
      {sentNote && (
        <p role="status">
          <small>{sentNote}</small>
        </p>
      )}
      <p style={{ color: "var(--kiwi-text-secondary)" }}>
        <small>
          Demo policy: <code>@blocked.test</code> blocks, non-<code>.test</code> domains warn. Real evaluation via
          kiwi-admin bridge (T-108); send queue via kiwi-mail (T-102).
        </small>
      </p>
    </section>
  );
}
