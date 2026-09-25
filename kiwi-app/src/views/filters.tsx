/**
 * Mail filters view (T-186): Thunderbird-style rules over the rule engine
 * in `src/filters.ts`. List with enable/disable + reorder, inline editor
 * (from/to/subject contains conditions; mark-read/star/archive/delete
 * actions), per-account scope, and Run-on-list applying enabled rules in
 * order to the currently loaded messages via the real bulk commands. Rules
 * persist in prefs (`kiwi.filterRules`, backend-pushed when the prefs IPC
 * lands). Demo runs the same path with the bulk layer's local fallbacks.
 */

import { useEffect, useMemo, useState } from "react";
import type { MessageEnvelope, MessagePatch } from "../kiwi";
import { loadPref, savePref } from "../prefs";
import { describeRule, matchRule, newRule, RULE_ACTIONS, RULE_FIELDS, validateRule } from "../filters";
import type { FilterRule, RuleAction, RuleField } from "../filters";
import { Icon } from "../components/icons/index";

function sanitizeRules(raw: unknown): FilterRule[] {
  if (!Array.isArray(raw)) return [];
  const out: FilterRule[] = [];
  for (const r of raw) {
    if (typeof r !== "object" || r === null) continue;
    const o = r as Record<string, unknown>;
    if (typeof o["id"] !== "string" || !o["id"]) continue;
    const conditions = Array.isArray(o["conditions"])
      ? (o["conditions"] as unknown[])
          .filter((c): c is { field: RuleField; value: string } => {
            if (typeof c !== "object" || c === null) return false;
            const co = c as Record<string, unknown>;
            return (
              (co["field"] === "from" || co["field"] === "to" || co["field"] === "subject") &&
              typeof co["value"] === "string"
            );
          })
          .map((c) => ({ field: c.field, value: c.value }))
      : [];
    const actions = Array.isArray(o["actions"])
      ? (o["actions"] as unknown[]).filter(
          (a): a is RuleAction =>
            a === "mark-read" || a === "star" || a === "archive" || a === "delete",
        )
      : [];
    out.push({
      id: o["id"],
      name: typeof o["name"] === "string" && o["name"] ? o["name"] : "Untitled rule",
      enabled: o["enabled"] !== false,
      accountId: typeof o["accountId"] === "string" && o["accountId"] ? o["accountId"] : null,
      conditions,
      actions,
    });
  }
  return out;
}

const inputStyle = { width: "100%" };

export function FiltersView({
  demo,
  accounts,
  messages,
  listLabel,
  onBulkPatch,
  onBulkDelete,
  onNotify,
}: {
  demo: boolean;
  accounts: { id: string; email: string; displayName: string }[];
  /** Currently loaded messages — the run scope (honestly labeled). */
  messages: MessageEnvelope[];
  listLabel: string;
  onBulkPatch: (ids: string[], patch: MessagePatch, actionLabel: string) => void;
  onBulkDelete: (ids: string[], permanent: boolean, actionLabel: string) => void;
  onNotify: (kind: "info" | "ok" | "warn" | "error", text: string) => void;
}) {
  const [rules, setRules] = useState<FilterRule[]>(() => sanitizeRules(loadPref("kiwi.filterRules", [])));
  const [openId, setOpenId] = useState<string | null>(null);
  const [draft, setDraft] = useState<FilterRule | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => savePref("kiwi.filterRules", rules), [rules]);

  const emailOf = (id: string | null) =>
    id ? (accounts.find((a) => a.id === id)?.email ?? id) : "all accounts";

  const matchCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rules) m.set(r.id, messages.filter((msg) => matchRule(r, msg)).length);
    return m;
  }, [rules, messages]);

  const move = (id: string, dir: -1 | 1) => {
    setRules((rs) => {
      const i = rs.findIndex((r) => r.id === id);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= rs.length) return rs;
      const next = rs.slice();
      const [rule] = next.splice(i, 1);
      next.splice(j, 0, rule);
      return next;
    });
  };

  const startEdit = (rule: FilterRule) => {
    setOpenId(rule.id);
    setDraft(JSON.parse(JSON.stringify(rule)) as FilterRule);
    setFormError(null);
  };

  const saveDraft = () => {
    if (!draft) return;
    const problem = validateRule(draft);
    if (problem) {
      setFormError(problem);
      return;
    }
    setRules((rs) => rs.map((r) => (r.id === draft.id ? draft : r)));
    setOpenId(null);
    setDraft(null);
  };

  const runAll = () => {
    const active = rules.filter((r) => r.enabled);
    if (active.length === 0 || messages.length === 0 || running) return;
    setRunning(true);
    try {
      let acted = 0;
      for (const rule of active) {
        const ids = messages.filter((m) => matchRule(rule, m)).map((m) => m.id);
        if (ids.length === 0) continue;
        const tag = `Filter "${rule.name}"`;
        // Reads/stars first (rows stay), then moves, then deletes.
        if (rule.actions.includes("mark-read")) {
          onBulkPatch(ids, { seen: true }, tag);
          acted += ids.length;
        }
        if (rule.actions.includes("star")) {
          onBulkPatch(ids, { starred: true }, tag);
          acted += ids.length;
        }
        if (rule.actions.includes("archive")) {
          onBulkPatch(ids, { archived: true }, tag);
          acted += ids.length;
        }
        if (rule.actions.includes("delete")) {
          onBulkDelete(ids, false, tag);
          acted += ids.length;
        }
      }
      onNotify("ok", `Ran ${active.length} rule(s) over ${messages.length} loaded message(s) — ${acted} action(s).`);
    } finally {
      setRunning(false);
    }
  };

  const setDraftCond = (i: number, patch: Partial<{ field: RuleField; value: string }>) =>
    setDraft((d) => (d ? { ...d, conditions: d.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c)) } : d));

  const toggleAction = (action: RuleAction) =>
    setDraft((d) =>
      d
        ? { ...d, actions: d.actions.includes(action) ? d.actions.filter((a) => a !== action) : [...d.actions, action] }
        : d,
    );

  return (
    <section aria-label="Mail filters" style={{ maxWidth: "52rem" }}>
      <h1>Filters {demo && <small style={{ color: "var(--kiwi-text-secondary)" }}>(demo)</small>}</h1>
      <p style={{ color: "var(--kiwi-text-secondary)" }}>
        <small>
          Rules run top-down; conditions AND. “To” matches your account address (per-message recipients
          aren’t on the wire). Run applies to the loaded list only — {messages.length} message(s)
          {listLabel ? ` (${listLabel})` : ""}.
        </small>
      </p>
      <div style={{ display: "flex", gap: "0.4rem", marginBottom: "0.7rem", flexWrap: "wrap" }}>
        <button
          type="button"
          className="kiwi-btn-primary"
          onClick={() => {
            const r = newRule();
            setRules((rs) => [...rs, r]);
            startEdit(r);
          }}
        >
          + New rule
        </button>
        <button
          type="button"
          onClick={runAll}
          disabled={running || rules.every((r) => !r.enabled) || messages.length === 0}
          title={
            messages.length === 0
              ? "Load a folder first"
              : `Apply enabled rules to ${messages.length} loaded message(s)`
          }
        >
          {running ? "Running…" : `Run on loaded list (${messages.length})`}
        </button>
      </div>
      {rules.length === 0 && (
        <div className="kiwi-empty">
          <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true"><Icon name="filters" size={28} /></span>
          <strong>No rules yet</strong>
          <br />
          <small>Create one — e.g. from contains “invoice” → mark read.</small>
        </div>
      )}
      <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: "0.4rem" }}>
        {rules.map((r, i) => {
          const open = openId === r.id;
          return (
            <li key={r.id} className="kiwi-card" style={{ marginBottom: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                <label style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={() => setRules((rs) => rs.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)))}
                    aria-label={`Enable rule ${r.name}`}
                  />
                </label>
                <strong>{r.name}</strong>
                <small style={{ color: "var(--kiwi-text-secondary)" }}>
                  {describeRule(r, emailOf)} · matches {matchCounts.get(r.id) ?? 0} loaded
                </small>
                <span style={{ marginLeft: "auto", display: "inline-flex", gap: "0.25rem" }}>
                  <button type="button" onClick={() => move(r.id, -1)} disabled={i === 0} aria-label={`Move ${r.name} up`}>
                    <Icon name="arrow-up" size={12} />
                  </button>
                  <button
                    type="button"
                    onClick={() => move(r.id, 1)}
                    disabled={i === rules.length - 1}
                    aria-label={`Move ${r.name} down`}
                  >
                    <Icon name="arrow-down" size={12} />
                  </button>
                  <button type="button" onClick={() => (open ? (setOpenId(null), setDraft(null)) : startEdit(r))}>
                    {open ? "Close" : "Edit"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRules((rs) => rs.filter((x) => x.id !== r.id));
                      if (openId === r.id) {
                        setOpenId(null);
                        setDraft(null);
                      }
                    }}
                    aria-label={`Delete rule ${r.name}`}
                  >
                    Delete
                  </button>
                </span>
              </div>
              {open && draft && draft.id === r.id && (
                <div style={{ marginTop: "0.6rem", borderTop: "1px solid var(--kiwi-border-soft)", paddingTop: "0.6rem" }}>
                  <p>
                    <label>
                      Name<br />
                      <input
                        type="text"
                        value={draft.name}
                        onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                        style={inputStyle}
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Account scope<br />
                      <select
                        value={draft.accountId ?? ""}
                        onChange={(e) => setDraft({ ...draft, accountId: e.target.value || null })}
                      >
                        <option value="">All accounts</option>
                        {accounts.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.displayName} &lt;{a.email}&gt;
                          </option>
                        ))}
                      </select>
                    </label>
                  </p>
                  <h3>Conditions (all must match)</h3>
                  {draft.conditions.map((c, j) => (
                    <p key={j} style={{ display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap" }}>
                      <select
                        value={c.field}
                        onChange={(e) => setDraftCond(j, { field: e.target.value as RuleField })}
                        aria-label={`Condition ${j + 1} field`}
                      >
                        {RULE_FIELDS.map((f) => (
                          <option key={f} value={f}>
                            {f} contains
                          </option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={c.value}
                        onChange={(e) => setDraftCond(j, { value: e.target.value })}
                        placeholder="text to match"
                        aria-label={`Condition ${j + 1} value`}
                        style={{ flex: 1, minWidth: "10rem" }}
                      />
                      <button
                        type="button"
                        onClick={() => setDraft((d) => (d ? { ...d, conditions: d.conditions.filter((_, k) => k !== j) } : d))}
                        aria-label={`Remove condition ${j + 1}`}
                      >
                        <Icon name="close" size={11} />
                      </button>
                    </p>
                  ))}
                  <p>
                    <button
                      type="button"
                      onClick={() => setDraft((d) => (d ? { ...d, conditions: [...d.conditions, { field: "from", value: "" }] } : d))}
                    >
                      + Add condition
                    </button>
                  </p>
                  <h3>Actions</h3>
                  <p style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap" }}>
                    {RULE_ACTIONS.map((a) => (
                      <label key={a} style={{ display: "inline-flex", gap: "0.25rem", alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={draft.actions.includes(a)}
                          onChange={() => toggleAction(a)}
                        />
                        {a === "mark-read" ? "Mark read" : a === "star" ? "Star" : a === "archive" ? "Archive" : "Delete (→ Trash)"}
                      </label>
                    ))}
                  </p>
                  {formError && (
                    <div className="kiwi-banner error" role="alert">
                      <small>{formError}</small>
                    </div>
                  )}
                  <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button type="button" className="kiwi-btn-primary" onClick={saveDraft}>
                      Save rule
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setOpenId(null);
                        setDraft(null);
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
