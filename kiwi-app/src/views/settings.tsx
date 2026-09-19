/**
 * Settings (T-112): section nav + General, Accounts, KIWI Security,
 * Templates (local CRUD stub), Notifications, Privacy, Advanced.
 * Surface KIWI-UI-023 (+003 panel placeholder, 022 template store).
 */
import { useState } from "react";

const SECTIONS = ["General", "Accounts", "KIWI Security", "Templates", "Notifications", "Privacy", "Advanced"] as const;
type Section = (typeof SECTIONS)[number];

export function SettingsView() {
  const [section, setSection] = useState<Section>("General");
  const [themeDefault, setThemeDefault] = useState("system");
  const [grace, setGrace] = useState("10");
  const [minTls, setMinTls] = useState("tls1.2");
  const [templates, setTemplates] = useState<string[]>(["Status update", "Meeting request"]);
  const [newTemplate, setNewTemplate] = useState("");

  return (
    <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "0.8rem" }}>
      <nav aria-label="Settings sections">
        {SECTIONS.map((s) => (
          <button
            key={s}
            type="button"
            aria-current={s === section ? "page" : undefined}
            onClick={() => setSection(s)}
            style={{ display: "block", width: "100%", textAlign: "left", marginBottom: "0.25rem", fontWeight: s === section ? 700 : 400 }}
          >
            {s}
          </button>
        ))}
      </nav>
      <section aria-label={`${section} settings`}>
        <h1>{section}</h1>

        {section === "General" && (
          <>
            <p>
              <label>
                Theme:{" "}
                <select value={themeDefault} onChange={(e) => setThemeDefault(e.target.value)}>
                  <option value="system">System</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Undo-send grace window:{" "}
                <select value={grace} onChange={(e) => setGrace(e.target.value)}>
                  <option value="5">5 seconds</option>
                  <option value="10">10 seconds</option>
                  <option value="20">20 seconds</option>
                  <option value="30">30 seconds</option>
                </select>
              </label>
            </p>
          </>
        )}

        {section === "Accounts" && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>No accounts configured in this scaffold. Real account storage arrives with kiwi-mail (T-105).</small>
          </p>
        )}

        {section === "KIWI Security" && (
          <>
            <p>
              <label>
                Minimum TLS version:{" "}
                <select value={minTls} onChange={(e) => setMinTls(e.target.value)}>
                  <option value="tls1.0">TLS 1.0</option>
                  <option value="tls1.1">TLS 1.1</option>
                  <option value="tls1.2">TLS 1.2 (recommended)</option>
                  <option value="tls1.3">TLS 1.3</option>
                </select>
              </label>
            </p>
            <h2>Trusted devices</h2>
            <p style={{ color: "var(--kiwi-text-secondary)" }}>
              <small>No devices enrolled yet. Pairing dialog (S-12) arrives with the authenticator flow (Phase 4).</small>
            </p>
          </>
        )}

        {section === "Templates" && (
          <>
            <ul>
              {templates.map((t) => (
                <li key={t}>
                  {t}{" "}
                  <button type="button" onClick={() => setTemplates((x) => x.filter((y) => y !== t))} aria-label={`Delete template ${t}`}>
                    Delete
                  </button>
                </li>
              ))}
            </ul>
            <p>
              <label>
                New template: <input type="text" value={newTemplate} onChange={(e) => setNewTemplate(e.target.value)} />{" "}
                <button
                  type="button"
                  disabled={!newTemplate.trim()}
                  onClick={() => {
                    setTemplates((x) => [...x, newTemplate.trim()]);
                    setNewTemplate("");
                  }}
                >
                  Add
                </button>
              </label>
            </p>
          </>
        )}

        {section === "Privacy" && (
          <p>
            Remote content: blocked by default. Read receipts and link tracking are <strong>off</strong> and stay off
            pending owner sign-off (ARCHITECTURE.md §4).
          </p>
        )}

        {(section === "Notifications" || section === "Advanced") && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>
            <small>Scaffold placeholder — backend preferences arrive with the settings IPC (post-T-110 follow-up).</small>
          </p>
        )}
      </section>
    </div>
  );
}
