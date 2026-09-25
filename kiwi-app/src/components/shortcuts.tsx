/**
 * Shortcuts help overlay (T-153): the full keyboard map. Opened with `?`
 * (Shift+/ outside text fields), closed with Esc or the button. Static
 * content — no backend, works identically in demo and live modes.
 */

export const SHORTCUT_ROWS: [string, string][] = [
  ["Ctrl+K", "Command palette (compose · search · go to · theme · sync · lock)"],
  ["Ctrl+N", "Compose new message"],
  ["F5", "Get new messages (sync now)"],
  ["/", "Focus message search"],
  ["Enter (in search)", "Open full search results"],
  ["j / ↓  ·  k / ↑", "Next / previous message"],
  ["n / p", "Next / previous message (alternate)"],
  ["Enter (in list)", "Open message — focus moves into the reader"],
  ["s", "Star / unstar selected message"],
  ["e", "Archive selected message"],
  ["Delete", "Delete selected message (Trash; permanent when already in Trash)"],
  ["u", "Mark selected message read / unread"],
  ["r / a / f", "Reply / reply-all / forward (composer)"],
  ["Esc (in reader)", "Back to the message list"],
  ["Ctrl+click · Shift+click", "Toggle select / range-select for bulk actions"],
  ["?", "This shortcuts overlay"],
  ["Esc", "Close dialog / overlay"],
  ["Ctrl+Enter", "Send (in composer)"],
];

export function ShortcutsHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="kiwi-dialog-backdrop" onClick={onClose} role="presentation">
      <div
        className="kiwi-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          }
        }}
      >
        <h1 style={{ marginTop: 0 }}>Keyboard shortcuts</h1>
        <table style={{ borderCollapse: "collapse", width: "100%" }}>
          <tbody>
            {SHORTCUT_ROWS.map(([keys, what]) => (
              <tr key={keys}>
                <td style={{ padding: "0.3rem 0.6rem 0.3rem 0", whiteSpace: "nowrap" }}>
                  <code>{keys}</code>
                </td>
                <td style={{ padding: "0.3rem 0" }}>{what}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>
            List and reader shortcuts are inactive while typing in a text
            field (Esc blurs the field first). Demo mode supports the same
            map; archive, delete, and flags stay local-only there.
          </small>
        </p>
        <button type="button" className="kiwi-btn-primary" onClick={onClose} autoFocus>
          Close (Esc)
        </button>
      </div>
    </div>
  );
}
