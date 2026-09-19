/**
 * Composer (T-143): live send via kiwi_send_message with real undo-grace
 * receipts, send-later scheduling, attachment upload (≤25 MiB), and
 * server-side policy outcomes (policy-blocked / policy-unavailable) rendered
 * as the S-07 banner. No client-side policy invention in live mode — the
 * bridge runs in the backend (T-144); demo mode keeps the labeled local
 * simulation from T-112.
 */
import { useEffect, useRef, useState } from "react";
import type { PolicyBannerVerdict } from "../kiwi";
import { loadPref } from "../prefs";
import { api, IpcError } from "../ipc";
import { PolicyBanner } from "../components/security";

const TEMPLATES = ["Status update", "Meeting request", "Out of office"];
const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

interface Attachment {
  name: string;
  size: number;
  contentType: string;
  dataB64: string;
}

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

function fileToB64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const url = typeof reader.result === "string" ? reader.result : "";
      const comma = url.indexOf(",");
      resolve(comma >= 0 ? url.slice(comma + 1) : url);
    };
    reader.onerror = () => reject(new Error(`could not read ${file.name}`));
    reader.readAsDataURL(file);
  });
}

export function ComposeView({
  mode,
  accounts,
  onSent,
}: {
  mode: "live" | "demo";
  accounts: { id: string; email: string; displayName: string }[];
  onSent: () => void;
}) {
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? "");
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [scheduled, setScheduled] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [graceLeft, setGraceLeft] = useState<number | null>(null);
  const [queueId, setQueueId] = useState<string | null>(null);
  const [sentNote, setSentNote] = useState<string | null>(null);
  const [sendError, setSendError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ verdict: PolicyBannerVerdict; offenders: string[] } | null>(null);
  const [showSchedule, setShowSchedule] = useState(false);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [readingFiles, setReadingFiles] = useState(false);
  const [graceSeconds] = useState(() => {
    const v = Number(loadPref("kiwi.grace", "10"));
    return [5, 10, 20, 30].includes(v) ? v : 10;
  });
  const timer = useRef<number | null>(null);

  const demoResult = mode === "demo" ? demoEvaluate(recipients) : null;
  const blocked = mode === "demo" && demoResult?.verdict === "block";

  useEffect(() => {
    if (mode === "demo") {
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
    }
  }, [mode, graceLeft, scheduled]);

  useEffect(() => {
    if (mode !== "live") return;
    if (graceLeft === null) return;
    if (graceLeft <= 0) {
      setGraceLeft(null);
      setQueueId(null);
      setSending(false);
      setSentNote("Queued for dispatch.");
      onSent();
      return;
    }
    timer.current = window.setTimeout(() => setGraceLeft((g) => (g === null ? null : g - 1)), 1000);
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [mode, graceLeft, onSent]);

  // Ctrl+Enter sends.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        void send();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, accountId, recipients, subject, body, scheduled, attachments, sending]);

  const addRecipient = () => {
    const v = to.trim();
    if (v && !recipients.includes(v)) setRecipients((r) => [...r, v]);
    setTo("");
  };

  const send = async () => {
    if (sending || blocked) return;
    setSentNote(null);
    setSendError(null);
    setBanner(null);
    if (mode === "demo") {
      setSending(true);
      setGraceLeft(graceSeconds);
      return;
    }
    if (!accountId) {
      setSendError("Choose a sending account first.");
      return;
    }
    if (recipients.length === 0) {
      setSendError("Add at least one recipient.");
      return;
    }
    setSending(true);
    try {
      const sendAtUnix = scheduled ? Math.floor(new Date(scheduled).getTime() / 1000) : null;
      const receipt = await api.sendMessage(
        accountId,
        {
          to: recipients,
          cc: [],
          bcc: [],
          subject,
          text: body,
          html: null,
          inReplyTo: null,
          references: [],
          attachments: attachments.map((a) => ({ filename: a.name, contentType: a.contentType, dataB64: a.dataB64 })),
        },
        { sendAtUnix, undoGraceSecs: graceSeconds },
      );
      setQueueId(receipt.queueId);
      const left = Math.max(0, Math.ceil(receipt.undoWindowUntilUnix - Date.now() / 1000));
      setGraceLeft(left > 0 ? left : null);
      if (left <= 0) {
        setSending(false);
        setSentNote("Queued for dispatch.");
        onSent();
      }
    } catch (e) {
      setSending(false);
      if (e instanceof IpcError && e.code === "policy-blocked") {
        setBanner({ verdict: "block", offenders: recipients });
        setSendError(`Policy blocked this send: ${e.message}`);
      } else if (e instanceof IpcError && e.code === "policy-unavailable") {
        setBanner({ verdict: "warn", offenders: recipients });
        setSendError(`Policy service unreachable — the server held the send (fail-closed): ${e.message}`);
      } else {
        setSendError(e instanceof Error ? e.message : String(e));
      }
    }
  };

  const undo = async () => {
    if (mode === "demo") {
      if (timer.current !== null) window.clearTimeout(timer.current);
      setGraceLeft(null);
      setSending(false);
      setSentNote("Send undone — back to draft.");
      return;
    }
    if (!queueId) return;
    try {
      const r = await api.cancelSend(queueId);
      setGraceLeft(null);
      setQueueId(null);
      setSending(false);
      setSentNote(r.cancelled ? "Send undone — back to draft." : "Undo window already closed — message dispatching.");
      onSent();
    } catch (e) {
      setSendError(e instanceof Error ? e.message : String(e));
    }
  };

  const addFiles = async (files: FileList | null) => {
    if (!files) return;
    setAttachError(null);
    setReadingFiles(true);
    try {
      const current = attachments.reduce((n, a) => n + a.size, 0);
      const list = [...files];
      const total = current + list.reduce((n, f) => n + f.size, 0);
      if (total > MAX_ATTACHMENT_BYTES) {
        setAttachError(`Attachments exceed the 25 MB total cap (${(total / 1048576).toFixed(1)} MB).`);
        return;
      }
      const read = await Promise.all(
        list.map(async (f) => ({ name: f.name, size: f.size, contentType: f.type || "application/octet-stream", dataB64: await fileToB64(f) })),
      );
      setAttachments((a) => [...a, ...read]);
    } catch (e) {
      setAttachError(e instanceof Error ? e.message : String(e));
    } finally {
      setReadingFiles(false);
    }
  };

  return (
    <section aria-label="Compose message" style={{ maxWidth: "46rem" }}>
      <h1>Compose {mode === "demo" && <small style={{ color: "var(--kiwi-text-secondary)" }}>(demo)</small>}</h1>
      {mode === "demo" && demoResult && demoResult.verdict !== "none" && (
        <PolicyBanner verdict={demoResult.verdict} offenders={demoResult.offenders} onRemove={(a) => setRecipients((r) => r.filter((x) => x !== a))} />
      )}
      {banner && (
        <PolicyBanner verdict={banner.verdict} offenders={banner.offenders} onRemove={(a) => setRecipients((r) => r.filter((x) => x !== a))} />
      )}
      {mode === "live" && accounts.length > 0 && (
        <p>
          <label>
            From:{" "}
            <select value={accountId} onChange={(e) => setAccountId(e.target.value)} aria-label="Sending account">
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.displayName} &lt;{a.email}&gt;
                </option>
              ))}
            </select>
          </label>
        </p>
      )}
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
        <button type="button" className="kiwi-btn-primary" onClick={() => void send()} disabled={blocked || sending} aria-disabled={blocked || sending}>
          {sending ? `Sending in ${graceLeft ?? "…"}s…` : scheduled ? "Schedule send" : "Send (Ctrl+Enter)"}
        </button>
        <button type="button" onClick={() => setShowSchedule((s) => !s)} aria-expanded={showSchedule}>
          Send later
        </button>
      </div>
      <p>
        <label>
          Attachments (25 MB total cap): <input type="file" multiple onChange={(e) => void addFiles(e.target.files)} />
        </label>
        {readingFiles && (
          <span role="status">
            <br />
            <small>Reading files…</small>
          </span>
        )}
        {attachError && (
          <span role="alert">
            <br />
            <small>{attachError}</small>
          </span>
        )}
      </p>
      {attachments.length > 0 && (
        <ul aria-label="Attachments">
          {attachments.map((a) => (
            <li key={`${a.name}-${a.size}`}>
              {a.name} <small>({(a.size / 1024).toFixed(1)} KB)</small>{" "}
              <button
                type="button"
                onClick={() => setAttachments((x) => x.filter((y) => y !== a))}
                aria-label={`Remove attachment ${a.name}`}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
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
          <button type="button" onClick={() => void undo()}>
            Undo send
          </button>
        </div>
      )}
      {sendError && (
        <div className="kiwi-banner error" role="alert" style={{ marginTop: "0.6rem" }}>
          <small>{sendError}</small>
        </div>
      )}
      {sentNote && (
        <p role="status">
          <small>{sentNote}</small>
        </p>
      )}
      {mode === "demo" && (
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>
            Demo policy: <code>@blocked.test</code> blocks, non-<code>.test</code> domains warn. Live sends are
            evaluated by the server-side bridge (fail-closed).
          </small>
        </p>
      )}
    </section>
  );
}
