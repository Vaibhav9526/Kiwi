/**
 * Device-pairing QR surface (T-303, ipc.md §9d). The backend owns the
 * ticket, endpoint, desktop key, and expiry — `pair_begin` returns the
 * ready-made `qrPayload` JSON (`{"type":"kiwi-pairing",…}`) and this
 * component only renders it. The encoder is the mobile app's segno-verified
 * implementation (mobile/src/qr/qrcode.ts, T-194) imported as the single
 * source of truth — no renderer-side reimplementation.
 *
 * Lock semantics (§9d.7): unlocked ⇒ `pair_begin` passes the ordinary gate;
 * locked ⇒ it succeeds only while a backend-owned pairing flow is live —
 * an `IpcError("locked")` is surfaced honestly rather than faking a code.
 *
 * Secrecy (§9d.2): ticket/qrPayload are bearer secrets — rendered, never
 * logged, persisted, or re-queried (`pair_status` never echoes them).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { encodeQrMatrix, QR_QUIET_ZONE } from "../../../mobile/src/qr/qrcode";
import { api, IpcError } from "../ipc";
import type { DeviceView, PairBeginView } from "../kiwi";

/** Draw a `QrMatrix` onto a canvas — dark modules only, recommended quiet
 *  zone, integer module scale so edges stay crisp. */
function QrCanvas({ payload, size = 176 }: { payload: string; size?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const [encodeError, setEncodeError] = useState<string | null>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    try {
      const m = encodeQrMatrix(payload);
      const total = m.size + QR_QUIET_ZONE * 2;
      const px = Math.max(2, Math.floor(size / total));
      canvas.width = canvas.height = total * px;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        setEncodeError("canvas 2d context unavailable");
        return;
      }
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#000000";
      for (let r = 0; r < m.size; r++) {
        for (let c = 0; c < m.size; c++) {
          if (m.modules[r]?.[c]) {
            ctx.fillRect((c + QR_QUIET_ZONE) * px, (r + QR_QUIET_ZONE) * px, px, px);
          }
        }
      }
      setEncodeError(null);
    } catch (e) {
      setEncodeError(e instanceof Error ? e.message : String(e));
    }
  }, [payload, size]);
  if (encodeError) {
    return (
      <p role="alert" style={{ color: "var(--kiwi-text-secondary)" }}>
        <small>QR could not be encoded: {encodeError}</small>
      </p>
    );
  }
  return (
    <canvas
      ref={ref}
      role="img"
      aria-label="Device-pairing QR code — scan with the KIWI authenticator"
      style={{
        display: "block",
        margin: "0.5rem auto 0",
        imageRendering: "pixelated",
        border: "1px solid var(--kiwi-border)",
        borderRadius: "8px",
        background: "#ffffff",
      }}
    />
  );
}

type PairPhase =
  | { kind: "beginning" }
  | { kind: "awaiting"; view: PairBeginView }
  | { kind: "claimed"; device: DeviceView | null }
  | { kind: "expired" }
  | { kind: "unavailable"; message: string };

/**
 * Self-contained pairing flow: begins a real ticket on mount, renders the
 * backend's `qrPayload` as a scannable QR, and polls `pair_status` until the
 * ticket is claimed or expires. Expiry offers a real re-begin ("New code").
 */
export function PairQrFlow({
  deviceLabel = "KIWI desktop",
  onClaimed,
}: {
  /** Label the authenticator records for this desktop — display hint only;
   *  identity material stays backend-owned. */
  deviceLabel?: string;
  onClaimed?: (device: DeviceView | null) => void;
}) {
  const [phase, setPhase] = useState<PairPhase>({ kind: "beginning" });
  const [nowTick, setNowTick] = useState(() => Math.floor(Date.now() / 1000));
  const alive = useRef(true);

  const begin = useCallback(async () => {
    setPhase({ kind: "beginning" });
    try {
      const view = await api.pairBegin(deviceLabel);
      if (alive.current) setPhase({ kind: "awaiting", view });
    } catch (e) {
      const message =
        e instanceof IpcError && e.code === "locked"
          ? "Device pairing can't start while the mailbox is locked — pair a device in Settings → Identity once unlocked."
          : e instanceof Error
            ? `${(e instanceof IpcError ? `${e.code}: ` : "")}${e.message}`
            : String(e);
      if (alive.current) setPhase({ kind: "unavailable", message });
    }
  }, [deviceLabel]);

  useEffect(() => {
    alive.current = true;
    void begin();
    return () => {
      alive.current = false;
    };
  }, [begin]);

  // Poll the bound ticket while awaiting; claimed/expired end the loop.
  // `pair_status` is read-only (§9d.3) — it never returns the payload.
  useEffect(() => {
    if (phase.kind !== "awaiting") return;
    const ticket = phase.view.ticket;
    const timer = window.setInterval(() => {
      setNowTick(Math.floor(Date.now() / 1000));
      void api
        .pairStatus(ticket)
        .then((s) => {
          if (!alive.current) return;
          if (s.state === "claimed") {
            setPhase({ kind: "claimed", device: s.device });
            onClaimed?.(s.device);
          } else if (s.state === "expired") {
            setPhase({ kind: "expired" });
          }
        })
        .catch((e) => {
          if (!alive.current) return;
          // A locked/unknown-ticket reply means the backend flow died —
          // treat the ticket as expired rather than looping forever.
          if (e instanceof IpcError && (e.code === "locked" || e.code === "invalid" || e.code === "not-found")) {
            setPhase({ kind: "expired" });
          }
        });
    }, 2500);
    return () => window.clearInterval(timer);
  }, [phase, onClaimed]);

  const expiresUnix = phase.kind === "awaiting" ? phase.view.expiresUnix : null;
  const secsLeft = expiresUnix === null ? null : Math.max(0, expiresUnix - nowTick);

  return (
    <div style={{ textAlign: "center" }}>
      {phase.kind === "beginning" && (
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>Requesting a pairing ticket…</small>
        </p>
      )}
      {phase.kind === "unavailable" && (
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>{phase.message}</small>
        </p>
      )}
      {phase.kind === "awaiting" && (
        <>
          <QrCanvas payload={phase.view.qrPayload} />
          <p style={{ margin: "0.4rem 0 0", color: "var(--kiwi-text-secondary)" }}>
            <small>
              Scan with the KIWI authenticator — the code carries the pairing endpoint and this
              desktop's public key; the ticket is not shown here.
            </small>
          </p>
          <p style={{ margin: "0.2rem 0 0", color: "var(--kiwi-text-secondary)" }}>
            <small aria-live="polite">
              Awaiting device — {secsLeft !== null && secsLeft > 0 ? `expires in ${secsLeft}s` : "expired"}
            </small>
          </p>
        </>
      )}
      {phase.kind === "expired" && (
        <p style={{ margin: 0 }}>
          <small style={{ color: "var(--kiwi-text-secondary)" }}>Pairing ticket expired.</small>{" "}
          <button type="button" className="ms-btn" onClick={() => void begin()}>
            New code
          </button>
        </p>
      )}
      {phase.kind === "claimed" && (
        <p role="status" style={{ margin: 0 }}>
          <small>
            Device paired{phase.device ? ` — ${phase.device.label}` : ""}. Approve the pending
            action on it.
          </small>
        </p>
      )}
    </div>
  );
}
