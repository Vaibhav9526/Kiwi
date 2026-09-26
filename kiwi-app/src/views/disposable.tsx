/**
 * Disposable Inbox (T-342) — the temp-mail inbox promoted to a first-class
 * sidebar view (was a card inside Settings → Integrations). The mandated
 * `PUBLIC_INBOX_NOTICE` renders verbatim at the top, BEFORE any control, and
 * re-renders from every backend response via the shared `useTempMail` state.
 *
 * Layout mirrors the mail view's inbox idiom: list of summaries on the left,
 * reader on the right. Fetched html is backend-sanitized and remote resources
 * are always stripped (public inbox); the fragment mounts click-inert exactly
 * like the old panel — no navigation, no forms, no remote assets.
 *
 * The countdown is the provider's documented ~60-minute age-out (ipc.md
 * §9e.1), computed from `addressCreatedUnix` (+1h once if extended). It is an
 * ESTIMATE — labeled "≈" — because the backend contract carries no expiry
 * timestamp; it never claims precision the backend does not have.
 */
import { useEffect, useState } from "react";
import type { TempMail } from "../state/tempmail";
import type { TempMessageSummaryView, TempMessageView } from "../kiwi";
import { Icon } from "../components/icons/index";

function fmtWhen(m: TempMessageSummaryView): string {
  return m.date || (m.timestampUnix ? new Date(m.timestampUnix * 1000).toLocaleString() : "—");
}

/** Live countdown to the provider age-out estimate. */
function ExpiryCountdown({ expiresAtUnix }: { expiresAtUnix: number }) {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(t);
  }, []);
  const left = expiresAtUnix - now;
  if (left <= 0) {
    return (
      <span className="kiwi-pill warn" title="The provider expires idle disposable inboxes ~60 minutes after creation">
        provider may have expired this address
      </span>
    );
  }
  const mm = Math.floor(left / 60);
  const ss = left % 60;
  return (
    <span
      className={`kiwi-pill ${left < 600 ? "warn" : "unknown"}`}
      title="Provider age-out estimate — disposable inboxes expire ~60 minutes after creation (extend once for +1h). Not a backend-verified expiry."
    >
      <Icon name="clock" size={10} /> ≈{mm}:{String(ss).padStart(2, "0")} left
    </span>
  );
}

export function DisposableInboxView({ temp, live }: { temp: TempMail; live: boolean }) {
  const [localPart, setLocalPart] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [openBody, setOpenBody] = useState<TempMessageView | null>(null);
  const [openBusy, setOpenBusy] = useState(false);

  const open = async (mailId: string) => {
    if (openId === mailId) return;
    setOpenBusy(true);
    const m = await temp.fetchMessage(mailId);
    setOpenBusy(false);
    if (m) {
      setOpenId(mailId);
      setOpenBody(m);
    }
  };

  const discardAndClose = async () => {
    await temp.discard();
    setOpenId(null);
    setOpenBody(null);
  };

  return (
    <section className="ms-view-enter kiwi-dispo" aria-label="Disposable inbox" style={{ padding: "0.9rem 1rem" }}>
      <h1 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}>
        <Icon name="clock" size={18} /> Disposable Inbox
      </h1>
      {/* The notice precedes every control — it must be seen before use. */}
      <div className="kiwi-banner warn" role="note" aria-label="Public inbox notice">
        <small>{temp.notice}</small>
      </div>
      {!live && (
        <p>
          <small>Demo mode — disposable inboxes require the live backend. The notice above still applies.</small>
        </p>
      )}
      {temp.error && (
        <div className="kiwi-banner error" role="alert">
          <small>{temp.error}</small>
        </div>
      )}
      {temp.flash && (
        <p role="status">
          <small>{temp.flash}</small>
        </p>
      )}

      {!temp.mailbox && (
        <div className="kiwi-empty" style={{ paddingTop: "1.5rem" }}>
          <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
            <Icon name="clock" size={28} />
          </span>
          <strong>No disposable inbox</strong>
          <br />
          <small>
            Create a throwaway address on a public provider for sign-ups you don't trust. The provider expires
            idle inboxes ~60 minutes after creation.
          </small>
          <br />
          <span style={{ display: "inline-flex", gap: "0.4rem", marginTop: "0.5rem", alignItems: "center" }}>
            <input
              type="text"
              value={localPart}
              onChange={(e) => setLocalPart(e.target.value)}
              placeholder="local part (random)"
              aria-label="Requested local part"
              disabled={!live || temp.busy !== null}
            />
            <button
              type="button"
              className="ms-btn ms-btn-primary"
              disabled={!live || temp.busy !== null}
              onClick={() => void temp.create(localPart.trim() || undefined)}
            >
              {temp.busy === "create" ? "Creating…" : "Create disposable address"}
            </button>
          </span>
        </div>
      )}

      {temp.mailbox && (
        <>
          <div className="kiwi-card kiwi-dispo-head" style={{ padding: "0.6rem 0.8rem", marginBottom: "0.7rem" }}>
            <strong>Address:</strong> <code>{temp.mailbox.address}</code>{" "}
            {temp.expiresAtUnix != null && <ExpiryCountdown expiresAtUnix={temp.expiresAtUnix} />}{" "}
            <span className="kiwi-toolbar-gap" />
            <button type="button" className="ms-btn" disabled={temp.busy !== null} onClick={() => void temp.refresh()}>
              {temp.busy === "poll" ? "Checking…" : "Check for mail"}
            </button>{" "}
            <button type="button" className="ms-btn" disabled={temp.busy !== null} onClick={() => void temp.extend()}>
              {temp.busy === "extend" ? "Extending…" : "Extend session"}
            </button>{" "}
            <button type="button" className="ms-btn" disabled={temp.busy !== null} onClick={() => void discardAndClose()}>
              {temp.busy === "discard" ? "Discarding…" : "Discard address"}
            </button>
          </div>

          <div className="kiwi-dispo-split">
            <div className="em-rows kiwi-dispo-list" role="listbox" aria-label="Disposable inbox messages">
              {temp.messages.length === 0 && (
                <div className="kiwi-empty" style={{ padding: "1.5rem 1rem" }}>
                  <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                    <Icon name="inbox" size={26} />
                  </span>
                  <strong>Inbox is live</strong>
                  <br />
                  <small>Anything sent to the address lands here — it refreshes every 45 s.</small>
                </div>
              )}
              {temp.messages.map((m) => (
                <button
                  type="button"
                  key={m.mailId}
                  role="option"
                  aria-selected={openId === m.mailId}
                  className={`em-tree-item kiwi-dispo-row${openId === m.mailId ? " is-active" : ""}`}
                  onClick={() => void open(m.mailId)}
                >
                  <span className={`em-dot${m.read ? "" : " is-unread"}`} aria-hidden="true" />
                  <span className="em-row-text">
                    <span className="em-row-line em-row-top">
                      <span className="em-row-sender">{m.from || "(unknown)"}</span>
                      <time className="em-row-date">{fmtWhen(m)}</time>
                    </span>
                    <span className="em-row-line">
                      <span className="em-row-subject">{m.subject || "(no subject)"}</span>
                    </span>
                    {m.excerpt && (
                      <span className="em-row-line em-row-sub">
                        <span className="em-row-snippet">{m.excerpt}</span>
                      </span>
                    )}
                  </span>
                </button>
              ))}
            </div>

            <div className="kiwi-dispo-reader" aria-label="Message">
              {openBusy && (
                <p role="status">
                  <small>Fetching…</small>
                </p>
              )}
              {!openBusy && !openBody && (
                <div className="kiwi-empty" style={{ padding: "2rem 1rem" }}>
                  <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                    <Icon name="mail-open" size={26} />
                  </span>
                  <strong>Select a message to read</strong>
                  <br />
                  <small>Fetched bodies are sanitized — remote resources and links are stripped.</small>
                </div>
              )}
              {!openBusy && openBody && (
                <div className="ms-unsub-panel" style={{ margin: 0 }}>
                  <p style={{ marginTop: 0 }}>
                    <strong>{openBody.subject || "(no subject)"}</strong>
                    <br />
                    <small>
                      {openBody.from} — {openBody.date}
                    </small>
                  </p>
                  {openBody.html ? (
                    <div
                      /* Backend-sanitized fragment — remote resources always
                         stripped for a public inbox (T-227). */
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
            </div>
          </div>
        </>
      )}
    </section>
  );
}
