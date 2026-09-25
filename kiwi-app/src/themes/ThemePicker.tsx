/**
 * `ThemePicker` (T-268) — Appearance picker for Preferences. A24 drops this
 * into the Settings → Appearance section (or rebuilds around `useTheme`).
 * Lists "System" + every registered theme package with swatches from the
 * manifest vars; selection applies instantly via `data-theme` on root.
 */
import { Icon } from "../components/icons/index";
import type { ThemeManifest } from "./types";
import { SYSTEM_THEME, useTheme } from "./useTheme";

function Swatches({ manifest }: { manifest: ThemeManifest }) {
  const v = manifest.vars;
  const colors = [
    v["--kiwi-ms-bg"] ?? v["--kiwi-bg"],
    v["--kiwi-ms-surface"] ?? v["--kiwi-surface"],
    v["--kiwi-ms-accent"] ?? v["--kiwi-brand"],
    v["--kiwi-ms-primary"],
  ].filter((c): c is string => typeof c === "string");
  return (
    <span aria-hidden="true" style={{ display: "inline-flex", gap: 3, marginRight: 8, verticalAlign: "-0.2em" }}>
      {colors.map((c, i) => (
        <span
          key={i}
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            background: c,
            border: "1px solid var(--kiwi-ms-border-strong, #888)",
            display: "inline-block",
          }}
        />
      ))}
    </span>
  );
}

export function ThemePicker() {
  const { theme, resolvedTheme, themes, setTheme } = useTheme();
  return (
    <fieldset className="kiwi-theme-picker" style={{ border: "none", margin: 0, padding: 0 }}>
      <legend className="kiwi-sr-only">Color theme</legend>
      <div role="radiogroup" aria-label="Color theme" style={{ display: "grid", gap: 6 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
          <input
            type="radio"
            name="kiwi-theme"
            checked={theme === SYSTEM_THEME}
            onChange={() => setTheme(SYSTEM_THEME)}
          />
          <Icon name="monitor" size={14} />
          <span>
            System <small style={{ color: "var(--kiwi-text-secondary)" }}>({resolvedTheme})</small>
          </span>
        </label>
        {themes.map((t) => (
          <label key={t.id} style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
            <input
              type="radio"
              name="kiwi-theme"
              checked={theme === t.id}
              onChange={() => setTheme(t.id)}
            />
            <Swatches manifest={t} />
            <span>
              {t.name}{" "}
              <small style={{ color: "var(--kiwi-text-secondary)" }}>
                v{t.version}
                {t.id === "light" ? " · default" : ""}
              </small>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
