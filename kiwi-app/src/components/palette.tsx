/**
 * Command palette (T-153): Ctrl+K quick actions — compose, message search,
 * go-to-folder, toggle theme, Security Center, sync, lock. Typing filters the
 * action list; a non-empty query also offers "Search messages for …" which
 * drives the TopBar query. Demo mode keeps every action but backend ones
 * (sync/lock) are labeled demo-safe and no-op with a toast.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./icons/index";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

export function CommandPalette({
  open,
  query,
  onQuery,
  actions,
  onClose,
}: {
  open: boolean;
  query: string;
  onQuery: (q: string) => void;
  actions: PaletteAction[];
  onClose: () => void;
}) {
  const [input, setInput] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (open) {
      setInput("");
      setCursor(0);
      // Focus after paint so the dialog exists.
      const t = window.setTimeout(() => inputRef.current?.focus(), 0);
      return () => window.clearTimeout(t);
    }
  }, [open ]);

  const filtered = useMemo(() => {
    const q = input.trim().toLowerCase();
    if (!q) return actions;
    return actions.filter(
      (a) => a.label.toLowerCase().includes(q) || (a.hint ?? "").toLowerCase().includes(q),
    );
  }, [actions, input]);

  useEffect(() => {
    setCursor(0);
  }, [input]);

  // "Search messages for …" is always available while typing.
  const showSearchRow = input.trim().length > 0;

  if (!open) return null;

  const totalRows = filtered.length + (showSearchRow ? 1 : 0);

  const choose = (index: number) => {
    if (showSearchRow && index === filtered.length) {
      onQuery(input.trim());
      onClose();
      return;
    }
    const action = filtered[index];
    if (action) {
      onClose();
      action.run();
    }
  };

  return (
    <div
      className="kiwi-dialog-backdrop"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="kiwi-dialog kiwi-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          } else if (e.key === "ArrowDown") {
            e.preventDefault();
            setCursor((c) => (totalRows === 0 ? 0 : (c + 1) % totalRows));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setCursor((c) => (totalRows === 0 ? 0 : (c - 1 + totalRows) % totalRows));
          } else if (e.key === "Enter") {
            e.preventDefault();
            choose(cursor);
          }
        }}
      >
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Type a command or search… (Esc to close)"
          aria-label="Command palette input"
          aria-activedescendant={totalRows > 0 ? `kiwi-palette-row-${cursor}` : undefined}
          role="combobox"
          aria-expanded="true"
          aria-controls="kiwi-palette-list"
          style={{ width: "100%" }}
        />
        <div id="kiwi-palette-list" role="listbox" aria-label="Commands" style={{ marginTop: "0.5rem" }}>
          {filtered.length === 0 && !showSearchRow && (
            <div className="kiwi-palette-empty">
              <Icon name="command" size={15} />
              <span>No matching commands.</span>
            </div>
          )}
          {filtered.map((a, i) => (
            <button
              key={a.id}
              id={`kiwi-palette-row-${i}`}
              type="button"
              role="option"
              aria-selected={i === cursor}
              className={`kiwi-palette-row${i === cursor ? " is-active" : ""}`}
              onMouseEnter={() => setCursor(i)}
              onClick={() => choose(i)}
            >
              <span>{a.label}</span>
              {a.hint && (
                <small style={{ color: "var(--kiwi-text-secondary)", marginLeft: "auto" }}>{a.hint}</small>
              )}
            </button>
          ))}
          {showSearchRow && (
            <button
              key="__search"
              id={`kiwi-palette-row-${filtered.length}`}
              type="button"
              role="option"
              aria-selected={filtered.length === cursor}
              className={`kiwi-palette-row${filtered.length === cursor ? " is-active" : ""}`}
              onMouseEnter={() => setCursor(filtered.length)}
              onClick={() => choose(filtered.length)}
            >
              <span>Search messages for “{input.trim()}”</span>
              <small style={{ color: "var(--kiwi-text-secondary)", marginLeft: "auto" }}>
                current query: {query || "—"}
              </small>
            </button>
          )}
        </div>
        <p style={{ color: "var(--kiwi-text-secondary)", marginBottom: 0 }}>
          <small>↑↓ to move · Enter to run · Esc to close · ? for all shortcuts</small>
        </p>
      </div>
    </div>
  );
}
