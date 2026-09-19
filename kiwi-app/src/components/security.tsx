/**
 * Security components (T-112): SecurityPill (001), PolicyBanner (007),
 * FindingDialog (004), LockOverlay (005), AuthenticatorDialog (006).
 * All severities render glyph + text (never color-only); dialogs trap focus
 * via Esc-to-close and return focus to the invoker (handled by callers).
 */
import { useEffect, useRef } from "react";
import type { FindingInfo, PolicyBannerVerdict, Severity } from "../kiwi";
import { severityGlyph, severityLabel } from "../kiwi";

export function SecurityPill({
  level,
  summary,
  onOpen,
}: {
  level: Severity;
  summary: string;
  onOpen: () => void;
}) {
  return (
    <button
      type="button"
      className={`kiwi-pill ${level}`}
      onClick={onOpen}
      aria-label={`Connection security: ${severityLabel(level)}. ${summary} Activate for details.`}
      title={summary}
    >
      {severityGlyph(level)} {severityLabel(level)}
    </button>
  );
}

export function PolicyBanner({
  verdict,
  offenders,
  onRemove,
}: {
  verdict: PolicyBannerVerdict;
  offenders: string[];
  onRemove: (addr: string) => void;
}) {
  if (verdict === "none") return null;
  const blocking = verdict === "block";
  return (
    <div className={`kiwi-banner ${blocking ? "block" : "warn"}`} role={blocking ? "alert" : "status"}>
      <strong>{blocking ? "Blocked" : "Warning"}:</strong>{" "}
      {blocking
        ? "sending is disabled until the flagged recipients are removed."
        : "review the flagged recipients before sending."}{" "}
      <span>
        Blocked in this client. Organization-wide enforcement happens at the mail gateway.
      </span>
      <ul>
        {offenders.map((o) => (
          <li key={o}>
            <code>{o}</code>{" "}
            <button type="button" onClick={() => onRemove(o)} aria-label={`Remove recipient ${o}`}>
              Remove
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function useEsc(onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
}

export function FindingDialog({
  finding,
  position,
  total,
  onClose,
  onPrev,
  onNext,
}: {
  finding: FindingInfo;
  position: number;
  total: number;
  onClose: () => void;
  onPrev: () => void;
  onNext: () => void;
}) {
  useEsc(onClose);
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => closeRef.current?.focus(), []);
  return (
    <div className="kiwi-dialog-backdrop" onClick={onClose}>
      <div
        className="kiwi-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
        onClick={(e) => e.stopPropagation()}
      >
        <p>
          <span className={`kiwi-pill ${finding.severity}` as string}>
            {severityGlyph(finding.severity)} {severityLabel(finding.severity)}
          </span>{" "}
          <small>
            {position} of {total} · {finding.id} · engine {finding.engineVersion}
          </small>
        </p>
        <h2 id="finding-title">{finding.title}</h2>
        <p>
          <strong>Session:</strong> <code>{finding.session}</code>
        </p>
        <h3>Evidence</h3>
        <pre className="kiwi-evidence" tabIndex={0} aria-label="Finding evidence">
          {finding.evidence}
        </pre>
        <h3>Impact</h3>
        <p>{finding.impact}</p>
        <h3>Remediation</h3>
        <ol>
          {finding.remediation.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.8rem" }}>
          <button type="button" onClick={onPrev} disabled={position <= 1}>
            ← Prev
          </button>
          <button type="button" onClick={onNext} disabled={position >= total}>
            Next →
          </button>
          <button type="button" onClick={onClose} ref={closeRef}>
            Close (Esc)
          </button>
        </div>
      </div>
    </div>
  );
}

export function LockOverlay({
  reason,
  busy,
  onVerify,
  onRetry,
}: {
  reason: string;
  busy: boolean;
  onVerify: () => void;
  onRetry: () => void;
}) {
  const verifyRef = useRef<HTMLButtonElement>(null);
  useEffect(() => verifyRef.current?.focus(), []);
  return (
    <div className="kiwi-lock-overlay" role="alertdialog" aria-modal="true" aria-labelledby="lock-title">
      <div>
        <div className="kiwi-lock-mark" aria-hidden="true">
          🔒
        </div>
        <h1 id="lock-title">Mailbox locked</h1>
        <p>{reason}</p>
        <p>
          <small>Message bodies, attachments, and sending are unavailable while locked.</small>
        </p>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center" }}>
          <button type="button" onClick={onVerify} disabled={busy} ref={verifyRef}>
            {busy ? "Working…" : "Verify with authenticator"}
          </button>
          <button type="button" onClick={onRetry} disabled={busy}>
            Retry trust check
          </button>
        </div>
      </div>
    </div>
  );
}

export type AuthStatus = "waiting" | "approved" | "denied" | "expired" | "error";

export function AuthenticatorDialog({
  eventLabel,
  deviceName,
  fpTail,
  secondsLeft,
  status,
  onCancel,
  detail,
}: {
  eventLabel: string;
  deviceName: string;
  fpTail: string;
  secondsLeft: number;
  status: AuthStatus;
  onCancel: () => void;
  /** Optional challenge identifier line (live mode: real challengeId). */
  detail?: string;
}) {
  useEsc(onCancel);
  return (
    <div className="kiwi-dialog-backdrop" onClick={onCancel}>
      <div
        className="kiwi-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="auth-title">{eventLabel}</h2>
        <p>
          Approve on your KIWI authenticator: <strong>{deviceName}</strong> · ends {fpTail}
        </p>
        {detail && (
          <p>
            <small>
              Challenge <code>{detail}</code> — the UI cannot approve on your behalf; use the paired device.
            </small>
          </p>
        )}
        <p role="status">
          {status === "waiting" && `Waiting for device… ${secondsLeft}s remaining.`}
          {status === "approved" && "Approved — continuing."}
          {status === "denied" && "Denied on the device — mailbox remains locked."}
          {status === "expired" && "Code expired — request a new one. Old codes no longer work."}
          {status === "error" && "Transport failure — retry."}
        </p>
        <button type="button" onClick={onCancel}>
          Cancel (Esc)
        </button>
      </div>
    </div>
  );
}
