/**
 * Integrations (T-242, ipc.md §9e) — the two `kiwi-integrations` surfaces,
 * embedded as the Preferences ▸ Integrations tab.
 *
 * Temp mail: the mandated `PUBLIC_INBOX_NOTICE` renders verbatim BEFORE
 * the user can create an inbox, and again from every backend response
 * (`publicInboxNotice` is structural — never paraphrased). Fetch returns
 * pre-sanitized html (remote resources are always stripped backend-side);
 * the fragment mounts via dangerouslySetInnerHTML exactly like the
 * reading-pane render path. Nothing persists — sessions die with the app.
 *
 * Deliverability: begin mints testId + a single-use consentToken; the
 * token stays in component memory (never rendered); the send requires
 * the consent checkbox — `consentNotice` is shown verbatim beside it.
 * Status polls are single-shot IPC calls; one recursive timeout drives
 * the loop while a test is in flight, and the report loads once `ready`.
 *
 * CSP strict: no remote assets, no navigation — `reportUrl` and citation
 * URLs render as text with Copy, never anchors.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, BackendUnavailableError, IpcError } from "../ipc";
import type {
  AccountView,
  DeliverabilityBeginView,
  DeliverabilityCheckView,
  DeliverabilityReportView,
  DeliverabilitySendView,
  DeliverabilityStatusView,
  TempMailboxView,
  TempMessageSummaryView,
  TempMessageView,
} from "../kiwi";
import { PUBLIC_INBOX_NOTICE } from "../kiwi";
import { Icon } from "../components/icons/index";

function errText(e: unknown): string {
  return e instanceof IpcError
    ? `${e.code}: ${e.message}`
    : e instanceof BackendUnavailableError
      ? "Backend unavailable — integrations need the live KIWI backend."
      : e instanceof Error
        ? e.message
        : String(e);
}

function fmtUnix(u?: number): string {
  if (!u) return "—";
  const d = new Date(u * 1000);
  return Number.isNaN(d.getTime()) ? String(u) : d.toLocaleString();
}

/** Milli-units → one-decimal display ("87000" → "87.0"). */
function milli(m?: number): string {
  return m === undefined ? "—" : (m / 1000).toFixed(1);
}

/** Copy helper shared by both panels. */
function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="ms-btn"
      onClick={() => {
        if (!navigator.clipboard) return;
        void navigator.clipboard.writeText(text).then(
          () => {
            setDone(true);
            window.setTimeout(() => setDone(false), 1500);
          },
          () => {},
        );
      }}
    >
      {done ? "Copied" : `Copy ${label}`}
    </button>
  );
}

/* ================= Temp mail ================= */

export function TempMailPanel({ live }: { live: boolean }) {
  const [mailbox, setMailbox] = useState<TempMailboxView | null>(null);
  const [notice, setNotice] = useState(PUBLIC_INBOX_NOTICE);
  const [localPart, setLocalPart] = useState("");
  const [messages, setMessages] = useState<TempMessageSummaryView[]>([]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [openBody, setOpenBody] = useState<TempMessageView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Reconnect to a live session if the view remounts (sessions are
  // backend-held; a poll tells us whether one exists).
  useEffect(() => {
    if (!live || mailbox) return;
    api
      .integrationsTempmailPoll()
      .then((p) => {
        if (!mounted.current) return;
        if (p.address) setMailbox({ address: p.address, publicInboxNotice: p.publicInboxNotice });
        setNotice(p.publicInboxNotice);
        setMessages(p.messages);
      })
      .catch((e) => {
        if (mounted.current) setError(errText(e));
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setError(null);
    setFlash(null);
    try {
      await fn();
    } catch (e) {
      if (mounted.current) setError(errText(e));
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const create = () =>
    run("create", async () => {
      const v = await api.integrationsTempmailCreate(localPart.trim() || undefined);
      setMailbox(v);
      setNotice(v.publicInboxNotice);
      const p = await api.integrationsTempmailPoll();
      setMessages(p.messages);
    });

  const refresh = () =>
    run("poll", async () => {
      const p = await api.integrationsTempmailPoll();
      setNotice(p.publicInboxNotice);
      setMessages(p.messages);
      if (p.address && !mailbox) setMailbox({ address: p.address, publicInboxNotice: p.publicInboxNotice });
    });

  const fetchMsg = (mailId: string) =>
    run("fetch", async () => {
      if (openId === mailId) {
        setOpenId(null);
        setOpenBody(null);
        return;
      }
      const m = await api.integrationsTempmailFetch(mailId);
      setOpenId(mailId);
      setOpenBody(m);
      setNotice(m.publicInboxNotice);
    });

  const extend = () =>
    run("extend", async () => {
      const v = await api.integrationsTempmailExtend();
      setNotice(v.publicInboxNotice);
      setFlash(v.extended ? "Session extended." : v.expired ? "Session already expired server-side." : "Not extended.");
    });

  const discard = () =>
    run("discard", async () => {
      const v = await api.integrationsTempmailDiscard();
      setNotice(v.publicInboxNotice);
      setMailbox(null);
      setMessages([]);
      setOpenId(null);
      setOpenBody(null);
      setFlash(
        v.discarded
          ? v.remoteForgotten
            ? "Address discarded; the remote session was forgotten too."
            : "Address discarded locally; the remote inbox may still exist briefly."
          : "Nothing to discard.",
      );
    });

  return (
    <div className="kiwi-card" style={{ padding: "0.9rem", marginBottom: "1rem" }}>
      <h2 style={{ marginTop: 0 }}>Disposable inbox (temp mail)</h2>
      {/* The notice precedes every control — it must be seen before enable. */}
      <div className="kiwi-banner warn" role="note" aria-label="Public inbox notice">
        <small>{notice}</small>
      </div>
      {!live && (
        <p>
          <small>Demo mode — disposable inboxes require the live backend.</small>
        </p>
      )}
      {error && (
        <div className="kiwi-banner error" role="alert">
          <small>{error}</small>
        </div>
      )}
      {flash && (
        <p role="status">
          <small>{flash}</small>
        </p>
      )}

      {!mailbox && (
        <>
          <p>
            <small>
              Create a throwaway address on a public provider for sign-ups you don't trust. Optional local part:
            </small>{" "}
            <input
              type="text"
              value={localPart}
              onChange={(e) => setLocalPart(e.target.value)}
              placeholder="(random)"
              aria-label="Requested local part"
              style={{ width: "12rem" }}
              disabled={!live || busy !== null}
            />{" "}
            <button
              type="button"
              className="ms-btn ms-btn-primary"
              disabled={!live || busy !== null}
              onClick={() => void create()}
            >
              {busy === "create" ? "Creating…" : "Create disposable address"}
            </button>
          </p>
        </>
      )}

      {mailbox && (
        <>
          <p>
            <strong>Address:</strong> <code>{mailbox.address}</code>{" "}
            <CopyButton text={mailbox.address} label="address" />{" "}
            {mailbox.addressCreatedUnix && <small>created {fmtUnix(mailbox.addressCreatedUnix)}</small>}
          </p>
          <p>
            <button
              type="button"
              className="ms-btn"
              disabled={busy !== null}
              onClick={() => void refresh()}
            >
              {busy === "poll" ? "Checking…" : "Check for mail"}
            </button>{" "}
            <button type="button" className="ms-btn" disabled={busy !== null} onClick={() => void extend()}>
              {busy === "extend" ? "Extending…" : "Extend session"}
            </button>{" "}
            <button type="button" className="ms-btn" disabled={busy !== null} onClick={() => void discard()}>
              {busy === "discard" ? "Discarding…" : "Discard address"}
            </button>
          </p>

          {messages.length === 0 ? (
            <p>
              <small>No mail yet — the inbox is live; anything sent to the address lands here.</small>
            </p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {messages.map((m) => (
                <li key={m.mailId} style={{ borderTop: "1px solid var(--kiwi-border-soft)", padding: "0.4rem 0" }}>
                  <button
                    type="button"
                    className="ms-btn"
                    onClick={() => void fetchMsg(m.mailId)}
                    aria-expanded={openId === m.mailId}
                  >
                    <Icon name={openId === m.mailId ? "chevron-down" : "chevron-right"} size={12} />
                  </button>{" "}
                  <strong>
                    {m.from || "(unknown)"}
                  </strong>{" "}
                  — {m.subject || "(no subject)"}{" "}
                  <small>{m.date || fmtUnix(m.timestampUnix)}</small>
                  {openId === m.mailId && openBody && (
                    <div className="ms-unsub-panel" style={{ marginTop: "0.4rem" }}>
                      {openBody.html ? (
                        <div
                          /* Backend-sanitized fragment — remote resources
                             always stripped for a public inbox (T-227). */
                          style={{ pointerEvents: "none" }}
                          onClickCapture={(event) => event.preventDefault()}
                          onKeyDownCapture={(event) => {
                            if (event.key === "Enter" || event.key === " ") event.preventDefault();
                          }}
                          onSubmitCapture={(event) => event.preventDefault()}
                          dangerouslySetInnerHTML={{ __html: openBody.html }}
                        />
                      ) : (
                        <pre className="kiwi-evidence" style={{ whiteSpace: "pre-wrap" }}>
                          {openBody.text ?? "(empty body)"}
                        </pre>
                      )}
                      {openBody.remoteImagesStripped > 0 && (
                        <p>
                          <small>{openBody.remoteImagesStripped} remote resource(s) stripped.</small>
                        </p>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

/* ================= Deliverability ================= */

const CATEGORY_LABEL: Record<string, string> = {
  auth: "Authentication",
  infra_spam: "Infrastructure & spam",
  content: "Content",
  compliance: "Compliance",
};

function statusPill(s: string): string {
  if (s === "pass") return "secure";
  if (s === "warn") return "warning";
  if (s === "fail") return "danger";
  return "unknown";
}

function CheckRow({ c, flagged }: { c: DeliverabilityCheckView; flagged: boolean }) {
  return (
    <li style={{ borderTop: "1px solid var(--kiwi-border-soft)", padding: "0.45rem 0" }}>
      <span className={`kiwi-pill ${statusPill(c.status)}`}>{c.status}</span>{" "}
      <strong>{c.title}</strong>{" "}
      <small>
        {CATEGORY_LABEL[c.category] ?? c.categoryRaw}
        {flagged ? " · auth gate failure" : ""}
      </small>
      <p style={{ margin: "0.25rem 0 0" }}>
        <small>{c.summary}</small>
      </p>
      {c.citations.length > 0 && (
        <ul style={{ margin: "0.25rem 0 0", paddingLeft: "1rem" }}>
          {c.citations.map((ct, i) => (
            <li key={i}>
              <small>
                {ct.kind}: {ct.title} — <code>{ct.url}</code> <CopyButton text={ct.url} label="URL" />
              </small>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function ReportView({ r }: { r: DeliverabilityReportView }) {
  const flagSet = new Set(r.authFailureIds);
  const authBlocked = r.authGate !== "pass";
  return (
    <div>
      {authBlocked && (
        <div className="kiwi-banner error" role="alert">
          <small>Authentication gate is {r.authGate}; this report is blocked until it passes.</small>
        </div>
      )}
      {authBlocked ? (
        <p>
          <small>Deliverability score withheld because the authentication gate did not pass.</small>
        </p>
      ) : (
        <p style={{ fontSize: "1.4rem", margin: "0.4rem 0" }}>
          <strong>{milli(r.scoreOursMilli)}</strong>
          <small> /100 deliverability</small>{" "}
          {r.scoreCompatMilli !== undefined && (
            <>
              <span className="kiwi-pill unknown">compat {milli(r.scoreCompatMilli)}/10</span>{" "}
            </>
          )}
          {!r.complete && <span className="kiwi-pill warn">partial report</span>}
        </p>
      )}
      {r.authFailureIds.length > 0 && (
        <div className="kiwi-banner error" role="alert">
          <small>
            Authentication failures gate the score: {r.authFailureIds.join(", ")} — fix auth before content work.
          </small>
        </div>
      )}
      {Object.keys(r.subscores).length > 0 && (
        <p>
          {Object.entries(r.subscores).map(([k, v]) => (
            <span key={k} className="kiwi-pill unknown" style={{ marginRight: "0.4rem" }}>
              {CATEGORY_LABEL[k] ?? k}: {milli(v)}
            </span>
          ))}
        </p>
      )}
      {Object.keys(r.tallies).length > 0 && (
        <p>
          {Object.entries(r.tallies).map(([k, t]) => (
            <span key={k} className="kiwi-pill unknown" style={{ marginRight: "0.4rem" }}>
              {CATEGORY_LABEL[k] ?? k}: {t.pass}
              <Icon name="check" size={10} /> {t.warn}
              <Icon name="alert-triangle" size={10} /> {t.fail}
              <Icon name="x-circle" size={10} />
              {t.skip ? <> {t.skip}<Icon name="blocked" size={10} /></> : null}
              {t.other ? ` ${t.other}?` : ""}
            </span>
          ))}
        </p>
      )}
      <h3>Checks ({r.checks.length})</h3>
      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {r.checks.map((c) => (
          <CheckRow key={c.id} c={c} flagged={flagSet.has(c.id)} />
        ))}
      </ul>
      {r.reportUrl && (
        <p>
          <small>
            Full report: <code>{r.reportUrl}</code>
          </small>{" "}
          <CopyButton text={r.reportUrl} label="URL" />
        </p>
      )}
    </div>
  );
}

export const DELIVERABILITY_POLL_MS = 15_000;
const MAX_POLL_DELAY_MS = 60 * 60 * 1000;

function retryAfterMs(error: unknown): number | undefined {
  if (typeof error === "object" && error !== null) {
    const value = (error as Record<string, unknown>)["retryAfterMs"] ?? (error as Record<string, unknown>)["retry_after_ms"];
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
      return Math.min(value, MAX_POLL_DELAY_MS);
    }
  }
  return undefined;
}

function pollDelay(status: DeliverabilityStatusView | undefined, error?: unknown): number {
  const value = status?.retryAfterMs ?? retryAfterMs(error);
  if (value === undefined) return DELIVERABILITY_POLL_MS;
  return Math.max(1, Math.min(value, MAX_POLL_DELAY_MS));
}

function terminalStatus(status: DeliverabilityStatusView): boolean {
  return status.ready || ["failed", "expired", "cancelled", "canceled", "error"].includes(status.analysisStatus.toLowerCase());
}

function retryableError(error: unknown): boolean {
  return error instanceof BackendUnavailableError || (error instanceof IpcError && ["rate-limited", "connect-failed"].includes(error.code));
}

export function DeliverabilityPanel({ accounts, live }: { accounts: AccountView[]; live: boolean }) {
  const [begin, setBegin] = useState<DeliverabilityBeginView | null>(null);
  const [accountId, setAccountId] = useState("");
  const [consent, setConsent] = useState(false);
  const [sent, setSent] = useState<DeliverabilitySendView | null>(null);
  const [status, setStatus] = useState<DeliverabilityStatusView | null>(null);
  const [report, setReport] = useState<DeliverabilityReportView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const timer = useRef<number | null>(null);
  const inFlightGeneration = useRef<number | null>(null);
  const pollAgain = useRef(false);
  const pollTarget = useRef<{ generation: number; testId: string } | null>(null);
  const reportRef = useRef<DeliverabilityReportView | null>(null);
  const pollRef = useRef<(generation: number, testId: string) => Promise<void>>(async () => {});

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const clearTimer = useCallback(() => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  const stopPolling = useCallback(() => {
    generation.current += 1;
    pollAgain.current = false;
    pollTarget.current = null;
    clearTimer();
  }, [clearTimer]);

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setError(null);
    try {
      await fn();
    } catch (e) {
      if (mounted.current) setError(errText(e));
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const schedule = (currentGeneration: number, testId: string, delay: number) => {
    if (!mounted.current || currentGeneration !== generation.current) return;
    clearTimer();
    timer.current = window.setTimeout(() => {
      timer.current = null;
      void pollRef.current(currentGeneration, testId);
    }, delay);
  };

  const poll = async (currentGeneration: number, testId: string) => {
    if (!mounted.current || currentGeneration !== generation.current) return;
    if (inFlightGeneration.current !== null) {
      pollAgain.current = true;
      return;
    }
    inFlightGeneration.current = currentGeneration;
    setBusy("status");
    setError(null);
    try {
      const nextStatus = await api.integrationsDeliverabilityStatus(testId);
      if (!mounted.current || currentGeneration !== generation.current) return;
      setStatus(nextStatus);
      if (nextStatus.ready) {
        if (!reportRef.current) {
          const nextReport = await api.integrationsDeliverabilityReport(testId);
          if (!mounted.current || currentGeneration !== generation.current) return;
          reportRef.current = nextReport;
          setReport(nextReport);
        }
      } else if (!terminalStatus(nextStatus)) {
        schedule(currentGeneration, testId, pollDelay(nextStatus));
      }
    } catch (e) {
      if (!mounted.current || currentGeneration !== generation.current) return;
      setError(errText(e));
      if (retryableError(e)) schedule(currentGeneration, testId, pollDelay(undefined, e));
    } finally {
      if (inFlightGeneration.current === currentGeneration) {
        inFlightGeneration.current = null;
        if (mounted.current && currentGeneration !== generation.current && pollAgain.current) {
          const target = pollTarget.current;
          pollAgain.current = false;
          if (target?.generation === generation.current) void pollRef.current(target.generation, target.testId);
        }
      }
      if (mounted.current && currentGeneration === generation.current) setBusy(null);
    }
  };
  pollRef.current = poll;

  useEffect(() => {
    if (!sent || !begin) return;
    const currentGeneration = generation.current + 1;
    generation.current = currentGeneration;
    pollTarget.current = { generation: currentGeneration, testId: begin.testId };
    clearTimer();
    void pollRef.current(currentGeneration, begin.testId);
    return () => {
      if (generation.current === currentGeneration) {
        generation.current += 1;
        pollAgain.current = false;
        pollTarget.current = null;
      }
      clearTimer();
    };
  }, [begin?.testId, clearTimer, sent?.testId]);

  const doBegin = () =>
    run("begin", async () => {
      stopPolling();
      const currentGeneration = generation.current;
      const v = await api.integrationsDeliverabilityBegin();
      if (!mounted.current || currentGeneration !== generation.current) return;
      setBegin(v);
      setConsent(false);
      setSent(null);
      setStatus(null);
      reportRef.current = null;
      setReport(null);
    });

  const doSend = () =>
    run("send", async () => {
      if (!begin || !accountId) return;
      const currentGeneration = generation.current;
      const v = await api.integrationsDeliverabilitySend(begin.testId, begin.consentToken, accountId, {
        to: [],
        subject: "KIWI deliverability test",
        text: "This message exercises KIWI's outbound pipeline for deliverability analysis.",
      });
      if (!mounted.current || currentGeneration !== generation.current) return;
      setSent(v);
    });

  const checkStatus = () => {
    if (!begin || !sent) return;
    void pollRef.current(generation.current, begin.testId);
  };

  const reset = () => {
    stopPolling();
    setBegin(null);
    setSent(null);
    setStatus(null);
    reportRef.current = null;
    setReport(null);
    setConsent(false);
    setBusy(null);
    setError(null);
  };

  return (
    <div className="kiwi-card" style={{ padding: "0.9rem" }}>
      <h2 style={{ marginTop: 0 }}>Deliverability test</h2>
      <p>
        <small>
          Reserves a single-use address on a third-party spam checker, sends a test message through your own relay,
          and reports how authentication, infrastructure, content, and compliance land.
        </small>
      </p>
      {!live && (
        <p>
          <small>Demo mode — deliverability tests require the live backend.</small>
        </p>
      )}
      {error && (
        <div className="kiwi-banner error" role="alert">
          <small>{error}</small>
        </div>
      )}

      {!begin && (
        <button
          type="button"
          className="ms-btn ms-btn-primary"
          disabled={!live || busy !== null}
          onClick={() => void doBegin()}
        >
          {busy === "begin" ? "Reserving…" : "Begin test"}
        </button>
      )}

      {begin && !sent && (
        <>
          <p>
            <small>
              Test id: <code>{begin.testId}</code> — send exactly one message to{" "}
              <code>{begin.address}</code>
            </small>{" "}
            <CopyButton text={begin.address} label="address" />{" "}
            {begin.expiresAtUnix && <small>(expires {fmtUnix(begin.expiresAtUnix)})</small>}
          </p>
          <div className="kiwi-banner warn" role="note">
            <small>{begin.consentNotice}</small>
          </div>
          <p>
            <label>
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
                disabled={!live || busy !== null}
              />{" "}
              I consent — send the test message once (single-use; the backend will refuse a replay).
            </label>
          </p>
          <p>
            <label>
              Send from account:{" "}
              <select
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                disabled={!live || busy !== null}
              >
                <option value="">— choose —</option>
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.email}
                  </option>
                ))}
              </select>
            </label>{" "}
            <button
              type="button"
              className="ms-btn ms-btn-primary"
              disabled={!live || !consent || !accountId || busy !== null}
              onClick={() => void doSend()}
            >
              {busy === "send" ? "Queuing…" : "Send test"}
            </button>{" "}
            <button type="button" className="ms-btn" disabled={busy !== null} onClick={reset}>
              Abandon
            </button>
          </p>
        </>
      )}

      {sent && (
        <>
          <p>
            <span className="kiwi-pill secure">queued</span>{" "}
            <small>
              test message queued as <code>{sent.queueId}</code> — analysis runs server-side.
            </small>
          </p>
          <p>
            <button type="button" className="ms-btn" disabled={busy !== null} onClick={checkStatus}>
              {busy === "status" ? "Checking…" : "Check status"}
            </button>{" "}
            {status && (
              <small>
                {status.analysisStatus} — {status.checksDone}/{status.checksTotal} checks
                {status.ready ? " — report ready" : " (auto-refreshing every 15 s)"}
              </small>
            )}
          </p>
          {report && <ReportView r={report} />}
          <p>
            <button type="button" className="ms-btn" onClick={reset}>
              New test
            </button>
          </p>
        </>
      )}
    </div>
  );
}

/* ================= root ================= */

export function IntegrationsView({ accounts, mode }: { accounts: AccountView[]; mode: "live" | "demo" }) {
  const live = mode === "live";
  return (
    <div className="ms-view-enter">
      <TempMailPanel live={live} />
      <DeliverabilityPanel accounts={accounts} live={live} />
    </div>
  );
}
