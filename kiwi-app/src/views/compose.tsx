/**
 * Composer (T-143, T-151, T-173): live send via kiwi_send_message with real
 * undo-grace receipts, send-later scheduling, attachment upload (≤25 MiB),
 * and server-side policy outcomes (policy-blocked / policy-unavailable)
 * rendered as the S-07 banner. To/Cc fields share a contact autocomplete
 * (server book, else the local book). Formatting toolbar inserts plaintext
 * markers (the send path is text-only; no HTML is generated). Drafts
 * autosave to this device's localStorage (no draft command in kiwi.ipc/1 —
 * attachments are never part of the autosave). Demo mode keeps the labeled
 * local simulation from T-112.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { PolicyBannerVerdict } from "../kiwi";
import type { ContactView } from "../kiwi";
import { contactLabel, contactPrimaryEmail } from "../kiwi";
import { accountPref, loadPref } from "../prefs";
import { api, IpcError } from "../ipc";
import { filterContacts, loadLocalBook } from "../contacts";
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

/**
 * Recipient field with contact autocomplete (T-173): filters the address
 * book (server list, else the local book) by substring; ↑↓/Enter/Esc,
 * mouse pick, Enter with no match adds the typed address. Book loads once —
 * server `search_contacts` semantics are substring too, so local filtering
 * matches on land.
 */
function RecipientInput({
  id,
  label,
  value,
  onChange,
  onPick,
  book,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  onPick: (email: string) => void;
  book: ContactView[];
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const sugg = useMemo(() => (value.trim() ? filterContacts(book, value).slice(0, 6) : []), [book, value]);
  useEffect(() => setActive(0), [value]);
  const shown = open && sugg.length > 0;
  return (
    <span style={{ position: "relative", display: "inline-block" }}>
      <label htmlFor={id}>{label}: </label>
      <input
        id={id}
        type="text"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 120)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && sugg.length > 0) {
            e.preventDefault();
            setOpen(true);
            setActive((a) => (a + 1) % sugg.length);
          } else if (e.key === "ArrowUp" && sugg.length > 0) {
            e.preventDefault();
            setActive((a) => (a - 1 + sugg.length) % sugg.length);
          } else if (e.key === "Enter") {
            e.preventDefault();
            if (shown && sugg[active]) {
              const hit = sugg[active];
              onPick(contactPrimaryEmail(hit) || contactLabel(hit));
            } else {
              onPick(value.trim());
            }
            onChange("");
            setOpen(false);
          } else if (e.key === "Escape") {
            setOpen(false);
          }
        }}
        placeholder="type a name or address"
        role="combobox"
        aria-expanded={shown}
        aria-controls={`${id}-sugg`}
        aria-activedescendant={shown ? `${id}-sugg-${active}` : undefined}
        autoComplete="off"
      />
      {shown && (
        <ul
          id={`${id}-sugg`}
          role="listbox"
          aria-label={`${label} suggestions`}
          style={{
            position: "absolute", zIndex: 20, left: 0, right: 0, margin: 0, padding: 0, listStyle: "none",
            background: "var(--kiwi-surface)", border: "1px solid var(--kiwi-border)", borderRadius: "8px",
            boxShadow: "var(--kiwi-shadow)", maxHeight: "12rem", overflowY: "auto",
          }}
        >
          {sugg.map((c, i) => (
            <li
              key={c.id || contactPrimaryEmail(c)}
              id={`${id}-sugg-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => {
                e.preventDefault();
                onPick(contactPrimaryEmail(c) || contactLabel(c));
                onChange("");
                setOpen(false);
              }}
              onMouseEnter={() => setActive(i)}
              style={{
                padding: "0.35rem 0.55rem", cursor: "pointer",
                background: i === active ? "var(--kiwi-hover-bg)" : "transparent",
                borderLeft: i === active ? "2px solid var(--kiwi-brand)" : "2px solid transparent",
              }}
            >
              <strong>{contactLabel(c)}</strong>{" "}
              <small style={{ color: "var(--kiwi-text-secondary)" }}>{contactPrimaryEmail(c)}</small>
            </li>
          ))}
        </ul>
      )}
    </span>
  );
}

export function ComposeView({
  mode,
  accounts,
  onSent,
  onNotify,
}: {
  mode: "live" | "demo";
  accounts: { id: string; email: string; displayName: string }[];
  onSent: () => void;
  onNotify: (
    kind: "info" | "ok" | "warn" | "error",
    text: string,
    opts?: { action?: { label: string; run: () => void }; ttlMs?: number },
  ) => void;
}) {
  const [accountId, setAccountId] = useState(() => {
    try {
      const preferred = window.localStorage.getItem("kiwi.defaultAccount");
      if (preferred) {
        const want = JSON.parse(preferred) as string;
        if (typeof want === "string" && accounts.some((a) => a.id === want)) return want;
      }
    } catch {
      // Fall through to the first account.
    }
    return accounts[0]?.id ?? "";
  });
  const [to, setTo] = useState("");
  const [cc, setCc] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [ccRecipients, setCcRecipients] = useState<string[]>([]);
  const [book, setBook] = useState<ContactView[]>([]);
  const [bookSource, setBookSource] = useState<"server" | "local">("local");
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
  const [draftNote, setDraftNote] = useState<string | null>(null);
  const [includeSig, setIncludeSig] = useState(true);
  const bodyRef = useRef<HTMLTextAreaElement | null>(null);
  const [graceSeconds] = useState(() => {
    const v = Number(loadPref("kiwi.grace", "10"));
    return [5, 10, 20, 30].includes(v) ? v : 10;
  });
  const timer = useRef<number | null>(null);

  // Address book for autocomplete (T-173, live-wired T-231): live mode is
  // IPC-only — a backend failure leaves autocomplete empty rather than
  // surfacing demo fixtures. Demo mode owns the seeded local book.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (mode === "demo") {
        if (!cancelled) {
          setBook(loadLocalBook());
          setBookSource("local");
        }
        return;
      }
      try {
        const list = await api.searchContacts("", 500);
        if (!cancelled) {
          setBook(list);
          setBookSource("server");
        }
      } catch {
        if (!cancelled) {
          setBook([]);
          setBookSource("server");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mode]);

  // Per-account signature (T-167): stored in prefs (Settings → Accounts),
  // appended at send time only — drafts and the outbox never gain it silently.
  const signature = accountId ? loadPref(accountPref("kiwi.signature", accountId), "") : "";
  const sendText = includeSig && signature ? `${body}\n\n-- \n${signature}` : body;

  // Draft autosave (T-151): no draft command exists in kiwi.ipc/1, so drafts
  // persist to this device's localStorage only — never credentials, never
  // attachments (b64 blobs would blow the quota). One draft per account.
  const draftKey = `kiwi.draft.${accountId || "default"}`;

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(draftKey);
      if (!raw) return;
      const d = JSON.parse(raw) as { recipients?: unknown; cc?: unknown; subject?: unknown; body?: unknown; scheduled?: unknown };
      if (Array.isArray(d.recipients)) setRecipients(d.recipients.filter((r): r is string => typeof r === "string"));
      if (Array.isArray(d.cc)) setCcRecipients(d.cc.filter((r): r is string => typeof r === "string"));
      if (typeof d.subject === "string") setSubject(d.subject);
      if (typeof d.body === "string") setBody(d.body);
      if (typeof d.scheduled === "string" || d.scheduled === null) setScheduled(d.scheduled as string | null);
      setDraftNote("Draft restored (this device only).");
    } catch {
      // Corrupt draft — autosave overwrites it on next keystroke.
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftKey]);

  useEffect(() => {
    const t = window.setTimeout(() => {
      if (recipients.length === 0 && ccRecipients.length === 0 && !subject && !body) return;
      try {
        window.localStorage.setItem(draftKey, JSON.stringify({ recipients, cc: ccRecipients, subject, body, scheduled, at: Date.now() }));
        setDraftNote(`Draft autosaved ${new Date().toLocaleTimeString()} (this device only, no attachments).`);
      } catch {
        setDraftNote("Draft autosave failed (storage full?) — copy your text before leaving.");
      }
    }, 1000);
    return () => window.clearTimeout(t);
  }, [draftKey, recipients, ccRecipients, subject, body, scheduled]);

  const clearDraft = () => {
    try {
      window.localStorage.removeItem(draftKey);
    } catch {
      // Already gone — nothing to do.
    }
    setRecipients([]);
    setCcRecipients([]);
    setSubject("");
    setBody("");
    setScheduled(null);
    setDraftNote("Draft discarded.");
  };

  const allRecipients = useMemo(() => [...recipients, ...ccRecipients], [recipients, ccRecipients]);
  const demoResult = mode === "demo" ? demoEvaluate(allRecipients) : null;
  const blocked = mode === "demo" && demoResult?.verdict === "block";

  useEffect(() => {
    if (mode === "demo") {
      if (graceLeft === null) return;
      if (graceLeft <= 0) {
        setGraceLeft(null);
        setSending(false);
        const note = scheduled ? `Scheduled for ${scheduled}.` : "Message sent.";
        setSentNote(note);
        onNotify("ok", `Demo: ${note}`);
        return;
      }
      timer.current = window.setTimeout(() => setGraceLeft((g) => (g === null ? null : g - 1)), 1000);
      return () => {
        if (timer.current !== null) window.clearTimeout(timer.current);
      };
    }
  }, [mode, graceLeft, scheduled, onNotify]);

  useEffect(() => {
    if (mode !== "live") return;
    if (graceLeft === null) return;
    if (graceLeft <= 0) {
      setGraceLeft(null);
      setQueueId(null);
      setSending(false);
      setSentNote("Queued for dispatch.");
      onNotify("ok", "Message queued for dispatch.");
      onSent();
      return;
    }
    timer.current = window.setTimeout(() => setGraceLeft((g) => (g === null ? null : g - 1)), 1000);
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [mode, graceLeft, onSent, onNotify]);

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
  }, [mode, accountId, recipients, ccRecipients, subject, body, scheduled, attachments, sending]);

  /** Add a picked/typed address to To (false) or Cc (true), de-duplicated. */
  const addAddress = (email: string, toCc: boolean) => {
    const v = email.trim();
    if (!v) return;
    if (toCc) {
      if (!ccRecipients.includes(v) && !recipients.includes(v)) setCcRecipients((r) => [...r, v]);
      setCc("");
    } else {
      if (!recipients.includes(v) && !ccRecipients.includes(v)) setRecipients((r) => [...r, v]);
      setTo("");
    }
  };

  const removeAddress = (email: string) => {
    setRecipients((x) => x.filter((y) => y !== email));
    setCcRecipients((x) => x.filter((y) => y !== email));
  };

  // Plaintext formatting toolbar: wraps the textarea selection with markers
  // (the send path is text-only — no HTML leaves this view).
  const wrapSelection = (before: string, after: string = before, linePrefix?: string) => {
    const el = bodyRef.current;
    if (!el) return;
    const { selectionStart: s, selectionEnd: e, value } = el;
    const sel = value.slice(s, e) || "text";
    const insert = linePrefix
      ? sel.split("\n").map((l) => `${linePrefix}${l}`).join("\n")
      : `${before}${sel}${after}`;
    setBody(value.slice(0, s) + insert + value.slice(e));
    const innerStart = linePrefix ? s : s + before.length;
    window.setTimeout(() => {
      el.focus();
      el.setSelectionRange(innerStart, innerStart + sel.length);
    }, 0);
  };

  const send = async () => {
    if (sending || blocked) return;
    setSentNote(null);
    setSendError(null);
    setBanner(null);
    // Sending consumes the autosaved draft (fields stay for undo).
    try {
      window.localStorage.removeItem(draftKey);
    } catch {
      // Non-fatal — the draft simply persists.
    }
    setDraftNote(null);
    if (mode === "demo") {
      setSending(true);
      setGraceLeft(graceSeconds);
      // Demo undo is local-only; the toast action reuses the same path.
      onNotify("info", `Demo: sending — undo open for ${graceSeconds}s.`, {
        action: { label: "Undo send", run: () => void undo() },
        ttlMs: graceSeconds * 1000,
      });
      return;
    }
    if (!accountId) {
      setSendError("Choose a sending account first.");
      return;
    }
    if (recipients.length === 0 && ccRecipients.length === 0) {
      setSendError("Add at least one recipient (To or Cc).");
      return;
    }
    // Send-later validation: the backend treats sendAtUnix as not-before.
    let sendAtUnix: number | null = null;
    if (scheduled) {
      const t = new Date(scheduled).getTime();
      if (Number.isNaN(t)) {
        setSendError("Scheduled time is not a valid date.");
        return;
      }
      sendAtUnix = Math.floor(t / 1000);
      if (sendAtUnix <= Date.now() / 1000) {
        setSendError("Scheduled time must be in the future.");
        return;
      }
    }
    setSending(true);
    try {
      const receipt = await api.sendMessage(
        accountId,
        {
          to: recipients,
          cc: ccRecipients,
          bcc: [],
          subject,
          text: sendText,
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
        onNotify("ok", "Message queued for dispatch.");
        onSent();
      } else {
        onNotify("info", `Message queued — undo open for ${left}s.`, {
          action: { label: "Undo send", run: () => void undo(receipt.queueId) },
          ttlMs: left * 1000,
        });
      }
    } catch (e) {
      setSending(false);
      if (e instanceof IpcError && e.code === "policy-blocked") {
        setBanner({ verdict: "block", offenders: recipients });
        setSendError(`Policy blocked this send: ${e.message}`);
        onNotify("error", `Policy blocked this send: ${e.message}`);
      } else if (e instanceof IpcError && e.code === "policy-unavailable") {
        setBanner({ verdict: "warn", offenders: recipients });
        setSendError(`Policy service unreachable — the server held the send (fail-closed): ${e.message}`);
        onNotify("warn", "Policy service unreachable — the server held the send (fail-closed).");
      } else {
        const msg = e instanceof Error ? e.message : String(e);
        setSendError(msg);
        onNotify("error", msg);
      }
    }
  };

  const undo = async (explicitQueueId?: string) => {
    if (mode === "demo") {
      if (timer.current !== null) window.clearTimeout(timer.current);
      setGraceLeft(null);
      setSending(false);
      setSentNote("Send undone — back to draft.");
      onNotify("info", "Demo: send undone — back to draft.");
      return;
    }
    // Toast actions fire after render, so the queued id is passed explicitly
    // (the `queueId` state in this closure would still be the pre-send null).
    const id = explicitQueueId ?? queueId;
    if (!id) return;
    try {
      const r = await api.cancelSend(id);
      setGraceLeft(null);
      setQueueId(null);
      setSending(false);
      const note = r.cancelled ? "Send undone — back to draft." : "Undo window already closed — message dispatching.";
      setSentNote(note);
      onNotify("info", note);
      onSent();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setSendError(msg);
      onNotify("error", msg);
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
        <PolicyBanner verdict={demoResult.verdict} offenders={demoResult.offenders} onRemove={removeAddress} />
      )}
      {banner && (
        <PolicyBanner verdict={banner.verdict} offenders={banner.offenders} onRemove={removeAddress} />
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
        <RecipientInput
          id="compose-to"
          label="To"
          value={to}
          onChange={setTo}
          onPick={(email) => addAddress(email, false)}
          book={book}
        />{" "}
        <button type="button" onClick={() => addAddress(to, false)}>
          Add
        </button>
      </p>
      <p>
        <RecipientInput
          id="compose-cc"
          label="Cc"
          value={cc}
          onChange={setCc}
          onPick={(email) => addAddress(email, true)}
          book={book}
        />{" "}
        <button type="button" onClick={() => addAddress(cc, true)}>
          Add
        </button>{" "}
        <small style={{ color: "var(--kiwi-text-secondary)" }}>
          Contacts: {bookSource === "server" ? "address book" : "demo book (localStorage fixture)"}.
        </small>
      </p>
      <p aria-label="Recipients">
        {recipients.map((r) => (
          <span key={`to-${r}`} className="kiwi-pill unknown" style={{ marginRight: "0.3rem" }}>
            To: {r}{" "}
            <button type="button" onClick={() => removeAddress(r)} aria-label={`Remove ${r}`}>
              ✕
            </button>
          </span>
        ))}
        {ccRecipients.map((r) => (
          <span key={`cc-${r}`} className="kiwi-pill unknown" style={{ marginRight: "0.3rem" }}>
            Cc: {r}{" "}
            <button type="button" onClick={() => removeAddress(r)} aria-label={`Remove ${r}`}>
              ✕
            </button>
          </span>
        ))}
        {recipients.length === 0 && ccRecipients.length === 0 && (
          <small style={{ color: "var(--kiwi-text-secondary)" }}>No recipients yet.</small>
        )}
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
        <label htmlFor="compose-body">Body</label>{" "}
        <small style={{ color: "var(--kiwi-text-secondary)" }}>
          (plaintext — toolbar inserts markers, no HTML is sent)
        </small>
        <br />
        <span role="toolbar" aria-label="Format body text" style={{ display: "inline-flex", gap: "0.25rem", marginBottom: "0.25rem" }}>
          <button type="button" title="Bold (**text**)" aria-label="Bold" onClick={() => wrapSelection("**")}>
            <strong>B</strong>
          </button>
          <button type="button" title="Italic (*text*)" aria-label="Italic" onClick={() => wrapSelection("*")}>
            <em>I</em>
          </button>
          <button type="button" title="Underline (__text__)" aria-label="Underline" onClick={() => wrapSelection("__")}>
            <u>U</u>
          </button>
          <button type="button" title="Code (`text`)" aria-label="Code" onClick={() => wrapSelection("`")}>
            {"</>"}
          </button>
          <button type="button" title="Quote selected lines" aria-label="Quote" onClick={() => wrapSelection("", "", "> ")}>
            “”
          </button>
          <button type="button" title="Bulleted list" aria-label="Bulleted list" onClick={() => wrapSelection("", "", "- ")}>
            ☰
          </button>
        </span>
        <textarea
          id="compose-body"
          ref={bodyRef}
          rows={10}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          style={{ width: "100%" }}
        />
      </p>
      {draftNote && (
        <p role="status">
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            {draftNote}{" "}
            <button type="button" onClick={clearDraft}>
              Discard draft
            </button>
          </small>
        </p>
      )}
      {signature && (
        <p>
          <label>
            <input type="checkbox" checked={includeSig} onChange={(e) => setIncludeSig(e.target.checked)} />{" "}
            Append signature
          </label>{" "}
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            <pre style={{ display: "inline", fontFamily: "inherit", whiteSpace: "pre-wrap" }}>{signature}</pre> (Settings →
            Accounts)
          </small>
        </p>
      )}
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
