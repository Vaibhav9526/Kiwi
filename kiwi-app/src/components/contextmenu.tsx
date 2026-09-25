/**
 * ContextMenu (T-299) — native-look right-click menu shared by the message
 * list and the folder tree. Fixed-position at the cursor, clamped to the
 * viewport; Esc / outside pointer dismiss; full keyboard nav (↑↓ move,
 * Enter select, → opens a submenu, ← closes it, Esc collapses then closes).
 * One submenu level — items render their own flyout anchored to the row.
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { Icon } from "./icons/index";
import type { IconName } from "./icons/index";

export interface CtxItem {
  label: string;
  icon?: IconName;
  disabled?: boolean;
  danger?: boolean;
  hint?: string;
  /** Tooltip — used to explain WHY an item is disabled. */
  title?: string;
  onSelect?: () => void;
  submenu?: CtxItem[];
}

export type CtxEntry = CtxItem | "divider";

function nextEnabled(entries: CtxEntry[], from: number, dir: 1 | -1): number {
  for (let i = 1; i <= entries.length; i++) {
    const idx = (from + dir * i + entries.length) % entries.length;
    const e = entries[idx];
    if (e !== "divider" && !e.disabled) return idx;
  }
  return from;
}

export function ContextMenu({
  x,
  y,
  entries,
  onClose,
}: {
  x: number;
  y: number;
  entries: CtxEntry[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState({ x, y });
  const [active, setActive] = useState(() => nextEnabled(entries, -1, 1));
  const [sub, setSub] = useState<number | null>(null);
  const [subActive, setSubActive] = useState(0);

  // Clamp to the viewport after first paint.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const nx = Math.min(x, Math.max(0, window.innerWidth - r.width - 6));
    const ny = Math.min(y, Math.max(0, window.innerHeight - r.height - 6));
    if (nx !== x || ny !== y) setPos({ x: nx, y: ny });
    el.focus();
  }, [x, y]);

  // Outside pointerdown / window blur dismiss. (A right-click elsewhere
  // also fires pointerdown — the row's own contextmenu handler replaces
  // this menu anyway.)
  useEffect(() => {
    const down = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    window.addEventListener("pointerdown", down, true);
    window.addEventListener("blur", onClose);
    return () => {
      window.removeEventListener("pointerdown", down, true);
      window.removeEventListener("blur", onClose);
    };
  }, [onClose]);

  const fire = (item: CtxItem) => {
    if (item.disabled) return;
    if (item.submenu) {
      setSubActive(0);
      return; // hover/arrows own submenu opening; Enter falls through below
    }
    item.onSelect?.();
    onClose();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    const subItems = sub !== null ? (entries[sub] as CtxItem).submenu ?? [] : [];
    switch (e.key) {
      case "Escape":
        e.preventDefault();
        if (sub !== null) setSub(null);
        else onClose();
        return;
      case "ArrowDown":
      case "ArrowUp": {
        e.preventDefault();
        const dir = e.key === "ArrowDown" ? 1 : -1;
        if (sub !== null) {
          setSubActive((i) => nextEnabled(subItems, i, dir));
        } else {
          setActive((i) => nextEnabled(entries, i, dir));
        }
        return;
      }
      case "ArrowRight": {
        e.preventDefault();
        const it = entries[active];
        if (it !== "divider" && it.submenu && !it.disabled) {
          setSub(active);
          setSubActive(nextEnabled(it.submenu, -1, 1));
        }
        return;
      }
      case "ArrowLeft":
        if (sub !== null) {
          e.preventDefault();
          setSub(null);
        }
        return;
      case "Enter": {
        e.preventDefault();
        if (sub !== null) {
          const child = subItems[subActive];
          if (child && !child.disabled) {
            child.onSelect?.();
            onClose();
          }
          return;
        }
        const it = entries[active];
        if (it !== "divider") {
          if (it.submenu && !it.disabled) {
            setSub(active);
            setSubActive(nextEnabled(it.submenu, -1, 1));
          } else fire(it);
        }
        return;
      }
      case "Home":
        e.preventDefault();
        if (sub !== null) setSubActive(nextEnabled(subItems, -1, 1));
        else setActive(nextEnabled(entries, -1, 1));
        return;
      case "End":
        e.preventDefault();
        if (sub !== null) setSubActive(nextEnabled(subItems, 0, -1));
        else setActive(nextEnabled(entries, 0, -1));
        return;
    }
  };

  return (
    <div ref={ref} className="em-ctx" role="menu" style={{ left: pos.x, top: pos.y }} tabIndex={-1} onKeyDown={onKeyDown}>
      {entries.map((e, i) => {
        if (e === "divider") return <div key={i} className="em-ctx-sep" role="separator" />;
        return (
          <div key={i} className="em-ctx-item-wrap">
            <button
              type="button"
              role="menuitem"
              className={`em-ctx-item${i === active ? " is-active" : ""}${e.danger ? " is-danger" : ""}`}
              disabled={e.disabled}
              title={e.title}
              aria-haspopup={e.submenu ? "menu" : undefined}
              aria-expanded={e.submenu ? sub === i : undefined}
              onMouseEnter={() => {
                setActive(i);
                if (e.submenu && !e.disabled) {
                  setSub(i);
                  setSubActive(nextEnabled(e.submenu, -1, 1));
                } else setSub(null);
              }}
              onClick={() => {
                if (e.submenu && !e.disabled) {
                  setSub(i);
                  setSubActive(nextEnabled(e.submenu, -1, 1));
                  return;
                }
                fire(e);
              }}
            >
              {e.icon && (
                <span className="em-ctx-icon" aria-hidden="true">
                  <Icon name={e.icon} size={13} />
                </span>
              )}
              <span className="em-ctx-label">{e.label}</span>
              {e.hint && <span className="em-ctx-hint">{e.hint}</span>}
              {e.submenu && (
                <span className="em-ctx-caret" aria-hidden="true">
                  <Icon name="chevron-right" size={11} />
                </span>
              )}
            </button>
            {sub === i && e.submenu && (
              <div className="em-ctx em-ctx-sub" role="menu">
                {e.submenu.map((s, j) => (
                  <button
                    key={j}
                    type="button"
                    role="menuitem"
                    className={`em-ctx-item${j === subActive ? " is-active" : ""}`}
                    disabled={s.disabled}
                    title={s.title}
                    onMouseEnter={() => setSubActive(j)}
                    onClick={() => {
                      if (s.disabled) return;
                      s.onSelect?.();
                      onClose();
                    }}
                  >
                    <span className="em-ctx-label">{s.label}</span>
                    {s.hint && <span className="em-ctx-hint">{s.hint}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
