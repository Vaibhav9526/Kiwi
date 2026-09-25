/**
 * OAuth2 sign-in card (T-243, ipc.md §9f; kiwi.oauth2/1). Shared by the
 * setup wizard's Credentials step and the Settings → Accounts re-auth
 * badge — one guided flow for both grant shapes:
 *
 * - `device_code`: render `userCode` large + `verificationUri` link, then
 *   poll honoring `pollIntervalSecs` and each response's `retryAfterSecs`
 *   (RFC 8628 `slow_down` backoff arrives through the same field).
 * - `loopback_code`: "open sign-in page" opens `authorizeUrl` in the
 *   system browser via `kiwi_open_external` (provider sign-in never runs
 *   inside the webview); the loopback listener is already bound, we just
 *   poll until the redirect lands.
 *
 * Terminal failures surface as `status:"error"` + a §9f code — mapped to
 * human copy here, with a restart affordance (`oauth2-expired` in
 * particular must offer "Start over"). Transient IPC errors keep polling
 * (the grant survives them); `BackendUnavailableError` ends the flow.
 * `onDone` receives the ticket id — the caller binds it via
 * `kiwi_add_account` (`oauth2Ticket`) or, for re-auth, nothing at all:
 * completing the grant already re-wrote the stored token.
 */
import { useEffect, useRef, useState } from "react";
import { api, BackendUnavailableError, IpcError } from "../ipc";
import type { OAuth2BeginView } from "../kiwi";
import { Icon } from "./icons/index";

type Phase =
  | { stage: "idle" }
  | { stage: "starting" }
  | { stage: "waiting"; begin: OAuth2BeginView }
  | { stage: "done"; email?: string }
  | { stage: "failed"; code: string; message: string };

const PROVIDER_LABEL: Record<string, string> = {
  google: "Google",
  microsoft: "Microsoft",
};
export function oauth2ProviderLabel(provider: string): string {
  return PROVIDER_LABEL[provider] ?? provider;
}

/** §9f error codes → human copy. `detail` is the sanitized backend message. */
function oauth2ErrorCopy(code: string, detail: string, provider: string): string {
  switch (code) {
    case "oauth2-denied":
      return "You declined the sign-in — nothing was stored.";
    case "oauth2-expired":
      return "The sign-in session expired before it completed.";
    case "oauth2-not-configured":
      return `This KIWI deployment has no OAuth2 client id configured for ${oauth2ProviderLabel(provider)} — ask your administrator, or add the account with an app password instead.`;
    case "oauth2-reauth":
      return "The stored grant was revoked — sign in again to re-authorize.";
    case "oauth2-incomplete":
      return "The sign-in grant was not finished — start the sign-in again.";
    case "oauth2-endpoint":
      return detail ? `The provider rejected the request: ${detail}` : "The provider rejected the sign-in request.";
    case "backend-unavailable":
      return "The KIWI backend is not available — run inside the desktop app to sign in.";
    case "locked":
      return "KIWI is locked — unlock it, then try the sign-in again.";
    default:
      return detail || "The sign-in failed.";
  }
}

export function OAuth2SignIn(props: {
  /** Provider id — `"google"` | `"microsoft"` (ProviderConfig::by_id). */
  provider: string;
  /** Email the grant binds to (account address) — sent to begin. */
  email?: string;
  /** Overrides the default "Sign in with {Provider}" label. */
  buttonLabel?: string;
  /** Called with the completed ticket id — caller decides bind vs re-auth. */
  onDone: (ticketId: string, email?: string) => void;
  /** Called when the user cancels an in-progress grant. */
  onCancel?: () => void;
}) {
  const { provider, email, buttonLabel, onDone, onCancel } = props;
  const [phase, setPhase] = useState<Phase>({ stage: "idle" });
  // Generation counter — a bumped value invalidates a running poll loop.
  const genRef = useRef(0);
  const ticketRef = useRef<string | null>(null);
  // A completed ticket must NOT be cancelled on unmount — it is consumed
  // by kiwi_add_account (or already persisted for re-auth).
  const keepRef = useRef(false);
  const [copied, setCopied] = useState<string | null>(null);
  // Effective poll cadence — displayed honestly because retryAfterSecs
  // (RFC 8628 slow_down) changes it after begin.
  const [pollSecs, setPollSecs] = useState<number | null>(null);

  const label = oauth2ProviderLabel(provider);

  useEffect(
    () => () => {
      genRef.current += 1;
      const ticket = ticketRef.current;
      if (ticket && !keepRef.current) void api.oauth2Cancel(ticket).catch(() => {});
    },
    [],
  );

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  const start = async () => {
    if (phase.stage === "starting" || phase.stage === "waiting") return;
    const gen = ++genRef.current;
    ticketRef.current = null;
    keepRef.current = false;
    setCopied(null);
    setPhase({ stage: "starting" });
    let begin: OAuth2BeginView | null;
    try {
      begin = await api.oauth2Begin(provider, email);
    } catch (e) {
      const code = e instanceof IpcError ? e.code : e instanceof BackendUnavailableError ? "backend-unavailable" : "oauth2-error";
      const detail = e instanceof Error ? e.message : String(e);
      if (gen === genRef.current) setPhase({ stage: "failed", code, message: detail });
      return;
    }
    if (!begin) {
      setPhase({ stage: "failed", code: "oauth2-error", message: "malformed response from the backend" });
      return;
    }
    if (gen !== genRef.current) {
      void api.oauth2Cancel(begin.ticketId).catch(() => {});
      return;
    }
    ticketRef.current = begin.ticketId;
    setPhase({ stage: "waiting", begin });
    // Poll loop: `retryAfterSecs` on each response wins (slow_down), else
    // the provider's pollIntervalSecs, else a 2 s floor — clamped so a
    // hostile/buggy value can never busy-loop the IPC channel.
    let delaySecs = Math.min(60, Math.max(1, begin.pollIntervalSecs ?? 2));
    setPollSecs(delaySecs);
    for (;;) {
      await sleep(delaySecs * 1000);
      if (gen !== genRef.current) return;
      try {
        const p = await api.oauth2Poll(begin.ticketId);
        if (gen !== genRef.current) return;
        if (!p) {
          setPhase({ stage: "failed", code: "oauth2-error", message: "malformed poll response" });
          return;
        }
        if (p.status === "complete") {
          keepRef.current = true;
          setPhase({ stage: "done", email: p.email });
          onDone(begin.ticketId, p.email);
          return;
        }
        if (p.status === "error") {
          setPhase({
            stage: "failed",
            code: p.errorCode ?? "oauth2-error",
            message: p.errorMessage ?? "",
          });
          return;
        }
        delaySecs = Math.min(60, Math.max(1, p.retryAfterSecs ?? begin.pollIntervalSecs ?? 2));
        setPollSecs(delaySecs);
      } catch (e) {
        if (e instanceof BackendUnavailableError) {
          setPhase({ stage: "failed", code: "backend-unavailable", message: e.message });
          return;
        }
        if (e instanceof IpcError && (e.code === "locked" || e.code === "not-found")) {
          setPhase({ stage: "failed", code: e.code, message: e.message });
          return;
        }
        // Transient transport failure — the grant stays alive; keep polling.
      }
    }
  };

  const cancel = () => {
    genRef.current += 1;
    const ticket = ticketRef.current;
    ticketRef.current = null;
    if (ticket && !keepRef.current) void api.oauth2Cancel(ticket).catch(() => {});
    setPhase({ stage: "idle" });
    onCancel?.();
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(text);
    } catch {
      setCopied(null);
    }
  };

  const openLink = (url: string) => {
    void api.openExternal(url).catch(() => {
      // Best-effort — the URL is also rendered for manual copy/paste.
    });
  };

  if (phase.stage === "idle") {
    return (
      <p>
        <button type="button" onClick={() => void start()}>
          {buttonLabel ?? `Sign in with ${label}`}
        </button>
      </p>
    );
  }

  if (phase.stage === "starting") {
    return (
      <p role="status">
        <button type="button" disabled>
          Contacting {label}…
        </button>
      </p>
    );
  }

  if (phase.stage === "done") {
    return (
      <div className="kiwi-banner warn" role="status">
        <strong>
          <Icon name="check-circle" size={14} /> Signed in{phase.email ? ` as ${phase.email}` : ""}.
        </strong>{" "}
        <small>The {label} grant is stored in the OS credential store — continue to finish adding the account.</small>
      </div>
    );
  }

  if (phase.stage === "failed") {
    return (
      <div className="kiwi-banner block" role="alert">
        <strong>Sign-in could not complete.</strong>{" "}
        <small>{oauth2ErrorCopy(phase.code, phase.message, provider)}</small>{" "}
        <button type="button" onClick={() => void start()}>
          {phase.code === "oauth2-expired" ? "Start over" : "Try again"}
        </button>{" "}
        <button type="button" onClick={cancel}>
          Cancel
        </button>
      </div>
    );
  }

  // phase.stage === "waiting"
  const { begin } = phase;
  const device = begin.kind === "device_code";
  const link = device ? (begin.verificationUriComplete ?? begin.verificationUri) : begin.authorizeUrl;
  return (
    <div className="kiwi-banner warn" role="status" aria-live="polite">
      {device ? (
        <>
          {begin.userCode ? (
            <p style={{ margin: "0 0 0.4rem" }}>
              <small>Enter this code at {label}:</small>
              <br />
              <code style={{ fontSize: "1.5rem", letterSpacing: "0.12em", userSelect: "all" }}>{begin.userCode}</code>{" "}
              <button type="button" onClick={() => void copy(begin.userCode ?? "")}>
                {copied === begin.userCode ? "Copied" : "Copy code"}
              </button>
            </p>
          ) : (
            <p style={{ margin: "0 0 0.4rem" }}>
              <small>The provider did not return a user code — open the sign-in page below to continue.</small>
            </p>
          )}
        </>
      ) : (
        <p style={{ margin: "0 0 0.4rem" }}>
          <small>
            A browser sign-in is ready — approve it in your browser. The grant lands back here automatically.
          </small>
        </p>
      )}
      {link && (
        <p style={{ margin: "0 0 0.4rem" }}>
          <button type="button" onClick={() => openLink(link)}>
            Open sign-in page
          </button>{" "}
          <small>
            <code style={{ userSelect: "all", wordBreak: "break-all" }}>{begin.verificationUri ?? link}</code>{" "}
            <button type="button" onClick={() => void copy(begin.verificationUri ?? link)}>
              {copied === (begin.verificationUri ?? link) ? "Copied" : "Copy"}
            </button>
          </small>
        </p>
      )}
      <p style={{ margin: 0 }}>
        <small>
          <strong>Pending</strong> — waiting for {label} approval (checking every {pollSecs ?? begin.pollIntervalSecs ?? 2}s
          {begin.expiresAtUnix ? `, expires ${new Date(begin.expiresAtUnix * 1000).toLocaleTimeString()}` : ""})
        </small>{" "}
        <button type="button" onClick={cancel}>
          Cancel
        </button>
      </p>
    </div>
  );
}
