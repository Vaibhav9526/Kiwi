/**
 * Toast notifications (T-153): ephemeral status for send/sync/policy events.
 * Pure view layer — producers in App.tsx push `{ kind, text }`; dismissal is
 * local. `role="status"` announces politely; errors also get `role="alert"`.
 * Glyphs → `Icon` set (T-268).
 */
import { Icon } from "./icons/index";
import type { IconName } from "./icons/index";

export type ToastKind = "info" | "ok" | "warn" | "error";

export interface ToastAction {
  label: string;
  run: () => void;
}

export interface Toast {
  id: number;
  kind: ToastKind;
  text: string;
  action?: ToastAction;
}

const KIND_ICON: Record<ToastKind, IconName> = {
  info: "info",
  ok: "check-circle",
  warn: "alert-triangle",
  error: "x-circle",
};

const KIND_LABEL: Record<ToastKind, string> = {
  info: "Notice",
  ok: "Done",
  warn: "Warning",
  error: "Error",
};

export function ToastStack({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div className="kiwi-toasts" aria-live="polite" aria-label="Notifications">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`kiwi-toast ${t.kind}`}
          role={t.kind === "error" ? "alert" : "status"}
        >
          <span aria-hidden="true" className="kiwi-toast-glyph">
            <Icon name={KIND_ICON[t.kind]} size={14} />
          </span>
          <span>
            <strong className="kiwi-sr-only">{KIND_LABEL[t.kind]}: </strong>
            {t.text}
          </span>
          {t.action && (
            <button type="button" className="kiwi-btn-primary" onClick={() => { t.action?.run(); onDismiss(t.id); }}>
              {t.action.label}
            </button>
          )}
          <button type="button" onClick={() => onDismiss(t.id)} aria-label="Dismiss notification">
            <Icon name="close" size={12} />
          </button>
        </div>
      ))}
    </div>
  );
}
