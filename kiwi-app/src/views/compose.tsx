/**
 * Composer (T-143, T-151, T-173): live send via kiwi_send_message with real
 * undo-grace receipts, send-later scheduling, attachment upload (≤25 MiB),
 * and server-side policy outcomes (policy-blocked / policy-unavailable)
 * rendered as the S-07 banner. To/Cc fields share a contact autocomplete
 * (server book, else the local book). Formatting toolbar inserts plaintext
 * markers (the send path is text-only; no HTML is generated). Drafts
 * autosave to this device's localStorage (no draft command in kiwi.ipc/1 —
 * attachments are never part of the autosave). Demo mode keeps the labeled
 * local simulation from T-112. T-294: files attach via picker, drag-drop
 * (DOM drop — the Tauri window sets dragDropEnabled:false so OS drops reach
 * the DOM as File objects), or clipboard paste; chips show per-file read
 * progress and the 25 MiB cap is enforced before the send IPC runs.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { ClipboardEvent, DragEvent, ReactNode } from "react";
import type { PolicyBannerVerdict, TemplateView } from "../kiwi";
import type { ContactView } from "../kiwi";
import { contactLabel, contactPrimaryEmail } from "../kiwi";
import { accountPref, loadPref } from "../prefs";
import { api, IpcError } from "../ipc";
import { filterContacts, loadLocalBook } from "../contacts";
import { PolicyBanner } from "../components/security";
import { DropMenu, useDismissable } from "../components/chrome";
import type { MenuEntry } from "../components/chrome";
import { Icon, isIconName } from "../components/icons/index";
import { navigate } from "../router";
import { fireComposerAction, useComposerActions } from "../plugins";

const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

interface Attachment {
  name: string;
  size: number;
  contentType: string;
  dataB64: string;
  /** true while FileReader is streaming the dropped/pasted file into b64. */
  pending?: boolean;
  /** 0..1 read progress — only meaningful while pending. */
  progress?: number;
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

function fileToB64(file: File, onProgress?: (fraction: number) => void): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const url = typeof reader.result === "string" ? reader.result : "";
      const comma = url.indexOf(",");
      resolve(comma >= 0 ? url.slice(comma + 1) : url);
    };
    reader.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
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

/**
 * T-343: Gmail-style floating compose dock. The dock is pure chrome around
 * the real ComposeView — draft autosave, seed handoffs, send/undo/outbox all
 * stay identical. `#/compose` remains the full-page form (expand target +
 * deep links); `requestCompose()` opens a dock when the app registered one,
 * else falls back to the route (never loses the ability to compose).
 *
 * Minimized docks stay MOUNTED-but-hidden — the autosave is 1s-debounced so
 * an unmount could drop sub-second keystrokes; hiding keeps React state (and
 * Gmail's semantics) intact.
 */
export interface ComposeDockApi {
  /** Dock is collapsed — the composer ignores Ctrl+Enter and pointer focus. */
  hidden: boolean;
  /** This dock's isolated autosave slot (`kiwi.draft.dock.<id>`). Per-dock
   * keys are mandatory: the page slot is one-draft-per-account, so sharing
   * it would let concurrent drafts (or a dock + the page composer)
   * clobber each other's autosave. */
  draftKey: string;
  /** Live subject preview for the dock header/chip. */
  onSubject: (subject: string) => void;
  /** The draft finished (sent/queued/scheduled) or was discarded. */
  onDone: () => void;
  /** Escape / header chevron / header × — minimize, never destroy. */
  onMinimize: () => void;
  /** Open the same draft as the full-page composer (flushes autosave first). */
  onExpand: () => void;
  /** Assigned by the view: synchronous draft handoff (used by expand). */
  flushRef: { current: (() => void) | null };
  /** Assigned by the view: discard the draft + report done. */
  discardRef: { current: (() => void) | null };
}

let composeDockOpener: (() => void) | null = null;
/** App registers the real dock opener; unmount unregisters. */
export function registerComposeDock(fn: () => void): () => void {
  composeDockOpener = fn;
  return () => {
    if (composeDockOpener === fn) composeDockOpener = null;
  };
}
/** Every compose entry point (reply/forward/new) goes through here. */
export function requestCompose(): void {
  if (composeDockOpener) composeDockOpener();
  else navigate({ name: "compose" });
}

/** Dock card chrome — header with live subject + min/expand/close. */
export function ComposeDockCard({
  subject,
  focused,
  onMinimize,
  onExpand,
  children,
}: {
  subject: string;
  /** Visible + topmost — focus lands in the To field on open AND on
   *  chip-restore (the card stays mounted while minimized, so this must
   *  be prop-driven, not a mount effect). */
  focused: boolean;
  onMinimize: () => void;
  onExpand: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (focused) ref.current?.querySelector("input")?.focus();
  }, [focused]);
  return (
    <div
      ref={ref}
      className="em-dock"
      role="dialog"
      aria-modal="false"
      aria-label={subject ? `Compose message: ${subject}` : "Compose message"}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onMinimize(); // never destroys — the draft survives as a chip
        }
      }}
    >
      <header className="em-dock-head">
        <span className="em-dock-title" title={subject || "New message"}>
          {subject || "New message"}
        </span>
        <button
          type="button"
          className="em-iconbtn"
          aria-label="Minimize compose — draft stays as a chip"
          title="Minimize (draft kept)"
          onClick={onMinimize}
        >
          <Icon name="chevron-down" size={12} />
        </button>
        <button
          type="button"
          className="em-iconbtn"
          aria-label="Expand compose to full page"
          title="Open as full page"
          onClick={onExpand}
        >
          <Icon name="external" size={12} />
        </button>
        <button
          type="button"
          className="em-iconbtn"
          aria-label="Close compose — draft stays as a minimized chip"
          title="Close (draft kept)"
          onClick={onMinimize}
        >
          <Icon name="close" size={12} />
        </button>
      </header>
      {children}
    </div>
  );
}

export function ComposeView({
  mode,
  accounts,
  onSent,
  onNotify,
  dock,
}: {
  mode: "live" | "demo";
  accounts: { id: string; email: string; displayName: string }[];
  onSent: () => void;
  onNotify: (
    kind: "info" | "ok" | "warn" | "error",
    text: string,
    opts?: { action?: { label: string; run: () => void }; ttlMs?: number },
  ) => void;
  /** T-343: present when mounted inside the floating dock. */
  dock?: ComposeDockApi;
}) {
  const [accountId, setAccountId] = useState(() => {
    try {
      // T-343: a dock expand handoff carries its owning account — the page
      // composer must mount under it or the draft fields would render with
      // the wrong sender. The payload itself is consumed by the restore
      // effect below (it stays in sessionStorage until then).
      if (!dock) {
        const ex = window.sessionStorage.getItem("kiwi.expandDraft");
        if (ex) {
          const d = JSON.parse(ex) as { account?: unknown };
          if (typeof d.account === "string" && accounts.some((a) => a.id === d.account)) return d.account;
        }
      }
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
  // T-302: plugin-registered composer actions (composer-action capability).
  const pluginActions = useComposerActions();
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
  const [dragOver, setDragOver] = useState(false);
  const dragDepth = useRef(0);
  // T-301: real template store (kiwi_templates_*). Rows load lazily on first
  // picker open; render is server-side so {{var}} semantics stay tested once.
  const [tplRows, setTplRows] = useState<TemplateView[] | null>(null);
  const [tplBusy, setTplBusy] = useState(false);
  const [tplError, setTplError] = useState<string | null>(null);
  const [tplNote, setTplNote] = useState<string | null>(null);
  const [saveTplOpen, setSaveTplOpen] = useState(false);
  const [saveTplName, setSaveTplName] = useState("");
  const [draftNote, setDraftNote] = useState<string | null>(null);
  const [includeSig, setIncludeSig] = useState(true);
  const bodyRef = useRef<HTMLTextAreaElement | null>(null);
  // Gmail-style footer: split Send (chevron = send options), icon row
  // (formatting toggle, attach, link, image, overflow), trash at the far
  // right. The hidden inputs are the real pickers — footer icons drive them.
  const [sendMenuOpen, setSendMenuOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [fmtOpen, setFmtOpen] = useState(true);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const imageRef = useRef<HTMLInputElement | null>(null);
  const sendMenuRef = useDismissable(sendMenuOpen, () => setSendMenuOpen(false));
  const moreMenuRef = useDismissable(moreOpen, () => setMoreOpen(false));
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
  // attachments (b64 blobs would blow the quota). One draft per account on
  // the page composer; docked composers get an isolated per-dock slot so
  // concurrent drafts can never clobber each other (T-343).
  const draftKey = dock?.draftKey ?? `kiwi.draft.${accountId || "default"}`;

  useEffect(() => {
    try {
      // T-343 expand handoff: a dock's flush publishes the full draft as a
      // one-shot sessionStorage payload. It REPLACES page state (it is the
      // draft, not a merge) and suppresses the page-key read so a stale
      // autosave under this account can't resurrect over it. The account
      // was already adopted by the useState initializer above.
      if (!dock) {
        const ex = window.sessionStorage.getItem("kiwi.expandDraft");
        if (ex) {
          window.sessionStorage.removeItem("kiwi.expandDraft");
          const d = JSON.parse(ex) as {
            recipients?: unknown;
            cc?: unknown;
            subject?: unknown;
            body?: unknown;
            scheduled?: unknown;
          };
          setRecipients(Array.isArray(d.recipients) ? d.recipients.filter((r): r is string => typeof r === "string") : []);
          setCcRecipients(Array.isArray(d.cc) ? d.cc.filter((r): r is string => typeof r === "string") : []);
          setSubject(typeof d.subject === "string" ? d.subject : "");
          setBody(typeof d.body === "string" ? d.body : "");
          setScheduled(typeof d.scheduled === "string" ? d.scheduled : null);
          setDraftNote("Draft restored (this device only).");
          return;
        }
      }
      const raw = window.localStorage.getItem(draftKey);
      if (!raw) return;
      const d = JSON.parse(raw) as { account?: unknown; recipients?: unknown; cc?: unknown; subject?: unknown; body?: unknown; scheduled?: unknown };
      // Drafts written by dock autosaves carry their owning account — adopt
      // it when valid (the orphan sweep files them under that account's
      // slot, so this only fires for consistent payloads).
      if (!dock && typeof d.account === "string" && accounts.some((a) => a.id === d.account)) setAccountId(d.account);
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

  // T-312: one-shot "Write" handoff from the Contacts detail card. Runs
  // after draft restore (mount-effect order) so a restored draft's
  // recipients merge with, and are never clobbered by, the handoff.
  useEffect(() => {
    try {
      const addr = window.sessionStorage.getItem("kiwi.composeTo");
      if (addr) {
        window.sessionStorage.removeItem("kiwi.composeTo");
        setRecipients((r) => (r.includes(addr) ? r : [...r, addr]));
      }
      // T-314: reply/reply-all/forward seed — same one-shot handoff.
      // Merge recipients; subject only fills an empty field; the quote
      // appends below existing draft text (never clobbers).
      const raw = window.sessionStorage.getItem("kiwi.replySeed");
      if (raw) {
        window.sessionStorage.removeItem("kiwi.replySeed");
        const seed = JSON.parse(raw) as { to?: string[]; cc?: string[]; subject?: string; quote?: string | null };
        if (Array.isArray(seed.to)) setRecipients((r) => [...new Set([...r, ...seed.to!])]);
        if (Array.isArray(seed.cc)) setCcRecipients((c) => [...new Set([...c, ...seed.cc!])]);
        if (typeof seed.subject === "string" && seed.subject) setSubject((s) => (s.trim() ? s : seed.subject!));
        if (typeof seed.quote === "string" && seed.quote) setBody((b) => (b.trim() ? `${b.replace(/\s+$/, "")}\n\n${seed.quote}` : seed.quote!));
      }
    } catch {
      // storage denied / malformed — nothing to seed.
    }
  }, []);

  useEffect(() => {
    const t = window.setTimeout(() => {
      if (recipients.length === 0 && ccRecipients.length === 0 && !subject && !body) return;
      try {
        // `account` rides along so an orphaned dock draft (app exit while
        // minimized) can be swept back into the right account's slot.
        window.localStorage.setItem(draftKey, JSON.stringify({ account: accountId, recipients, cc: ccRecipients, subject, body, scheduled, at: Date.now() }));
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

  // T-343 dock integration. The dock header/chip mirrors the live subject —
  // reported through a ref-guard because the `dock` prop is a fresh object
  // every App render: without the guard each render would re-report and
  // setDocks would feed a render loop.
  const dockSubject = useRef<string | null>(null);
  useEffect(() => {
    if (!dock || dockSubject.current === subject) return;
    dockSubject.current = subject;
    dock.onSubject(subject);
  }, [dock, subject]);
  // flushRef/discardRef are down-calls from the dock chrome — assigned in an
  // effect (never mid-render) with no dep array so the closures always see
  // the latest draft fields.
  useEffect(() => {
    if (!dock) return;
    // Expand handoff: publish the WHOLE draft (incl. account — even an
    // empty one, so a stale page-slot draft can't resurrect over it) as a
    // one-shot sessionStorage payload, then release this dock's autosave
    // slot. The page composer consumes it on mount (initializer + restore
    // effect above) — byte-identical state, no shared-key write needed.
    dock.flushRef.current = () => {
      try {
        window.sessionStorage.setItem(
          "kiwi.expandDraft",
          JSON.stringify({ account: accountId, recipients, cc: ccRecipients, subject, body, scheduled }),
        );
        window.localStorage.removeItem(draftKey);
      } catch {
        // storage denied — the expand navigation still happens; the draft
        // simply doesn't follow, which the empty composer shows honestly.
      }
    };
    dock.discardRef.current = () => {
      clearDraft();
      dock.onDone();
    };
  });
  // Close the dock once the draft has actually finished its lifecycle —
  // sent/queued/scheduled (grace window over), not merely "sending" (undo
  // must stay reachable inside the dock while graceLeft counts down).
  useEffect(() => {
    if (!dock || graceLeft !== null) return;
    if (sentNote === "Queued for dispatch." || sentNote === "Message sent." || (sentNote !== null && /^Scheduled for /.test(sentNote))) dock.onDone();
  }, [dock, sentNote, graceLeft]);

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

  // Ctrl+Enter sends. A minimized (hidden) dock composer must not fire —
  // several docks share this window-level listener.
  useEffect(() => {
    if (dock?.hidden) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        void send();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, accountId, recipients, ccRecipients, subject, body, scheduled, attachments, sending, dock?.hidden]);

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
    if (attachments.some((a) => a.pending)) {
      setSendError("Attachments are still being read — wait a moment and retry.");
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

  // Attach via File objects (input picker, DOM drop, clipboard paste — Tauri
  // window has dragDropEnabled:false so OS drops reach the DOM). The send IPC
  // contract takes dataB64 payloads, so each file streams through FileReader;
  // chips render immediately as pending and flip when the read completes.
  const addFiles = (files: Iterable<File> | FileList | null) => {
    const list = files ? [...files] : [];
    if (list.length === 0) return;
    setAttachError(null);
    const current = attachments.reduce((n, a) => n + a.size, 0);
    const total = current + list.reduce((n, f) => n + f.size, 0);
    if (total > MAX_ATTACHMENT_BYTES) {
      const over = list.filter((f) => f.size > MAX_ATTACHMENT_BYTES);
      setAttachError(
        over.length > 0
          ? `${over.map((f) => f.name).join(", ")} exceed${over.length > 1 ? "" : "s"} the 25 MiB per-message attachment cap — not attached.`
          : `Attachments exceed the 25 MiB total cap (${(total / 1048576).toFixed(1)} MiB) — not attached.`,
      );
      return;
    }
    const entries: Attachment[] = list.map((f) => ({
      name: f.name,
      size: f.size,
      contentType: f.type || "application/octet-stream",
      dataB64: "",
      pending: true,
      progress: 0,
    }));
    setAttachments((a) => [...a, ...entries]);
    entries.forEach((entry, i) => {
      void fileToB64(list[i], (p) =>
        setAttachments((xs) => xs.map((x) => (x === entry ? { ...x, progress: p } : x))),
      )
        .then((dataB64) =>
          setAttachments((xs) => xs.map((x) => (x === entry ? { ...x, dataB64, pending: false, progress: 1 } : x))),
        )
        .catch(() => {
          setAttachments((xs) => xs.filter((x) => x !== entry));
          setAttachError(`Could not read ${entry.name} — attachment removed.`);
        });
    });
  };

  /* ---- T-301 templates (kiwi_templates_*). The picker loads lazily; render
   * is server-side — the composer supplies honest context vars (from_*,
   * to, date) and surfaces `missingVars` verbatim rather than guessing. ---- */
  const templateVars = (): Record<string, string> => {
    const acc = accounts.find((a) => a.id === accountId);
    const vars: Record<string, string> = { date: new Date().toISOString().slice(0, 10) };
    if (acc) {
      vars.from_name = acc.displayName;
      vars.from_email = acc.email;
    }
    if (recipients[0]) vars.to = recipients[0];
    return vars;
  };

  const loadTemplates = async () => {
    setTplBusy(true);
    setTplError(null);
    try {
      setTplRows(await api.templatesList());
    } catch (e) {
      setTplError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const applyTemplate = async (id: string) => {
    setTplBusy(true);
    setTplError(null);
    setTplNote(null);
    try {
      const r = await api.templatesRender(id, templateVars());
      if (r.subject) setSubject(r.subject);
      setBody((b) => (b ? `${b.replace(/\s+$/, "")}\n\n${r.bodyText}` : r.bodyText));
      setTplNote(
        r.missingVars.length > 0
          ? `Template inserted — fill these placeholders before sending: ${r.missingVars.map((v) => `{{${v}}}`).join(", ")}.`
          : "Template inserted.",
      );
    } catch (e) {
      setTplError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const saveAsTemplate = async () => {
    const name = saveTplName.trim();
    if (!name) return;
    setTplBusy(true);
    setTplError(null);
    try {
      const created = await api.templatesCreate({ name, subject: subject || undefined, bodyText: body || undefined });
      setTplNote(`Saved template “${created.name}”.`);
      setSaveTplOpen(false);
      setSaveTplName("");
      setTplRows(null); // lazily reload on next picker open
    } catch (e) {
      setTplError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  // DOM drop target (T-294): dragDepth tracks nested enter/leave so the veil
  // doesn't flicker over children. Paste attaches clipboard files too.
  const dragHandlers = {
    onDragEnter: (e: DragEvent) => {
      if (!e.dataTransfer.types.includes("Files")) return;
      e.preventDefault();
      dragDepth.current += 1;
      setDragOver(true);
    },
    onDragOver: (e: DragEvent) => {
      if (e.dataTransfer.types.includes("Files")) e.preventDefault();
    },
    onDragLeave: (e: DragEvent) => {
      if (!e.dataTransfer.types.includes("Files")) return;
      dragDepth.current = Math.max(0, dragDepth.current - 1);
      if (dragDepth.current === 0) setDragOver(false);
    },
    onDrop: (e: DragEvent) => {
      dragDepth.current = 0;
      setDragOver(false);
      if (e.dataTransfer.files.length === 0) return;
      e.preventDefault();
      addFiles(e.dataTransfer.files);
    },
    onPaste: (e: ClipboardEvent) => {
      if (e.clipboardData.files.length > 0) {
        e.preventDefault();
        addFiles(e.clipboardData.files);
      }
    },
  };

  return (
    <section aria-label="Compose message" style={{ maxWidth: "46rem", position: "relative" }} {...dragHandlers}>
      {dragOver && (
        <div className="em-drop-veil" role="status">
          <Icon name="file" size={28} />
          <p>Drop files to attach</p>
        </div>
      )}
      {!dock && (
        <h1>
          Compose {mode === "demo" && <small style={{ color: "var(--kiwi-text-secondary)" }}>(demo)</small>}
        </h1>
      )}
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
              <Icon name="close" size={10} />
            </button>
          </span>
        ))}
        {ccRecipients.map((r) => (
          <span key={`cc-${r}`} className="kiwi-pill unknown" style={{ marginRight: "0.3rem" }}>
            Cc: {r}{" "}
            <button type="button" onClick={() => removeAddress(r)} aria-label={`Remove ${r}`}>
              <Icon name="close" size={10} />
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
            disabled={mode !== "live" || tplBusy}
            title={mode !== "live" ? "Templates need the Tauri backend" : undefined}
            defaultValue=""
            onFocus={() => {
              if (tplRows === null && !tplBusy) void loadTemplates();
            }}
            onChange={(e) => {
              if (e.target.value) void applyTemplate(e.target.value);
              e.target.value = "";
            }}
          >
            <option value="">
              {tplBusy ? "Loading…" : tplRows === null ? "Insert template…" : tplRows.length === 0 ? "No saved templates" : "Insert template…"}
            </option>
            {(tplRows ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>{" "}
        <button
          type="button"
          disabled={mode !== "live"}
          title={mode !== "live" ? "Templates need the Tauri backend" : "Save the current subject + body as a template"}
          onClick={() => {
            setSaveTplOpen((o) => !o);
            setTplError(null);
          }}
          aria-expanded={saveTplOpen}
        >
          Save as template…
        </button>{" "}
        <button type="button" onClick={() => navigate({ name: "settings" })} title="Manage templates in Settings → Appearance">
          Manage…
        </button>
      </p>
      {saveTplOpen && (
        <p role="group" aria-label="Save as template">
          <label>
            Template name:{" "}
            <input
              type="text"
              value={saveTplName}
              maxLength={128}
              onChange={(e) => setSaveTplName(e.target.value)}
              placeholder="e.g. Status update"
              autoFocus
            />
          </label>{" "}
          <button type="button" className="kiwi-btn-primary" disabled={!saveTplName.trim() || tplBusy} onClick={() => void saveAsTemplate()}>
            Save
          </button>{" "}
          <button type="button" onClick={() => setSaveTplOpen(false)}>
            Cancel
          </button>{" "}
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            saves the current subject + body verbatim (placeholders like {"{{name}}"} included)
          </small>
        </p>
      )}
      {/* T-302: plugin composer actions (composer-action capability). Click
          posts `composer.action` to the owning plugin with bounded draft
          metadata (subject + recipient addresses — never body bytes). */}
      {pluginActions.length > 0 && (
        <p role="toolbar" aria-label="Plugin actions" style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap", alignItems: "center" }}>
          <small style={{ color: "var(--kiwi-text-secondary)" }}>Plugins:</small>
          {pluginActions.map((a) => (
            <button
              key={`${a.pluginId}/${a.actionId}`}
              type="button"
              title={a.title ?? `${a.label} — provided by ${a.pluginName}`}
              onClick={() => {
                const ok = fireComposerAction(a, { subject, to: recipients, cc: ccRecipients });
                if (!ok) onNotify("warn", `[${a.pluginId}] plugin is not running — action not delivered.`);
              }}
            >
              <Icon name={a.icon && isIconName(a.icon) ? a.icon : "puzzle"} size={11} /> {a.label}
            </button>
          ))}
        </p>
      )}
      {tplError && (
        <div className="kiwi-banner error" role="alert">
          <small>{tplError}</small>
        </div>
      )}
      {tplNote && (
        <p className="em-note" role="status">
          <small>{tplNote}</small>
        </p>
      )}
      <p>
        <label htmlFor="compose-body">Body</label>{" "}
        <small style={{ color: "var(--kiwi-text-secondary)" }}>
          (plaintext — toolbar inserts markers, no HTML is sent)
        </small>
        <br />
        {fmtOpen && (
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
            <Icon name="list" size={13} />
          </button>
        </span>
        )}
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
      <div className="em-compose-footer">
        <div className="em-menu-wrap em-send-wrap" ref={sendMenuRef}>
          <span className="em-send-split">
            <button
              type="button"
              className="em-send"
              title="Send (Ctrl+Enter)"
              onClick={() => void send()}
              disabled={blocked || sending}
              aria-disabled={blocked || sending}
            >
              {sending ? `Sending in ${graceLeft ?? "…"}s…` : scheduled ? "Schedule send" : "Send"}
            </button>
            <button
              type="button"
              className="em-send-chev"
              aria-label="Send options"
              title="Send options"
              aria-haspopup="menu"
              aria-expanded={sendMenuOpen}
              disabled={blocked || sending}
              onClick={() => setSendMenuOpen((o) => !o)}
            >
              <Icon name="chevron-down" size={12} />
            </button>
          </span>
          {sendMenuOpen && (
            <DropMenu
              label="Send options"
              onClose={() => setSendMenuOpen(false)}
              entries={[
                {
                  label: scheduled ? "Edit scheduled time…" : "Schedule send…",
                  run: () => setShowSchedule(true),
                },
              ]}
            />
          )}
        </div>
        <span className="em-compose-tools" role="toolbar" aria-label="Compose tools">
          <button
            type="button"
            className={`em-iconbtn em-fmt${fmtOpen ? " is-active" : ""}`}
            title="Formatting options"
            aria-label="Formatting options"
            aria-pressed={fmtOpen}
            onClick={() => setFmtOpen((o) => !o)}
          >
            Aa
          </button>
          <button
            type="button"
            className="em-iconbtn"
            title="Attach files"
            aria-label="Attach files"
            onClick={() => fileRef.current?.click()}
          >
            <Icon name="paperclip" size={15} />
          </button>
          <button
            type="button"
            className="em-iconbtn"
            title="Insert link"
            aria-label="Insert link"
            onClick={() => wrapSelection("[", "](https://)")}
          >
            <Icon name="link" size={15} />
          </button>
          <button
            type="button"
            className="em-iconbtn"
            title="Attach image"
            aria-label="Attach image"
            onClick={() => imageRef.current?.click()}
          >
            <Icon name="image" size={15} />
          </button>
          <div className="em-menu-wrap" ref={moreMenuRef}>
            <button
              type="button"
              className="em-iconbtn"
              title="More options"
              aria-label="More compose options"
              aria-haspopup="menu"
              aria-expanded={moreOpen}
              onClick={() => setMoreOpen((o) => !o)}
            >
              <Icon name="more" size={15} />
            </button>
            {moreOpen && (
              <DropMenu
                label="More compose options"
                onClose={() => setMoreOpen(false)}
                entries={
                  [
                    { label: "Save as template…", run: () => setSaveTplOpen(true) },
                    { label: "Manage templates…", run: () => navigate({ name: "settings" }) },
                    ...(signature
                      ? [{ label: includeSig ? "✓ Append signature" : "Append signature", run: () => setIncludeSig((s) => !s) }]
                      : []),
                  ] as MenuEntry[]
                }
              />
            )}
          </div>
        </span>
        <button
          type="button"
          className="em-iconbtn em-compose-trash"
          aria-label="Discard draft"
          title="Discard draft"
          onClick={() => {
            clearDraft();
            dock?.onDone();
          }}
        >
          <Icon name="trash" size={15} />
        </button>
      </div>
      <input
        ref={fileRef}
        type="file"
        multiple
        hidden
        aria-label="Choose files to attach"
        onChange={(e) => {
          addFiles(e.target.files);
          e.target.value = "";
        }}
      />
      <input
        ref={imageRef}
        type="file"
        accept="image/*"
        multiple
        hidden
        aria-label="Attach image"
        onChange={(e) => {
          addFiles(e.target.files);
          e.target.value = "";
        }}
      />
      <p>
        <small style={{ color: "var(--kiwi-text-secondary)" }}>
          Attachments (25 MiB total cap) — drop files anywhere in this window / paste an image
        </small>
        {attachError && (
          <span role="alert">
            <br />
            <small>{attachError}</small>
          </span>
        )}
      </p>
      {attachments.length > 0 && (
        <ul aria-label="Attachments">
          {attachments.map((a, i) => (
            <li key={`${a.name}-${a.size}-${i}`}>
              {a.name} <small>({a.size >= 1048576 ? `${(a.size / 1048576).toFixed(1)} MB` : `${(a.size / 1024).toFixed(1)} KB`})</small>{" "}
              {a.pending && (
                <small role="status" style={{ color: "var(--kiwi-text-secondary)" }}>
                  {a.progress ? `reading ${(a.progress * 100).toFixed(0)}%…` : "reading…"}
                </small>
              )}{" "}
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
