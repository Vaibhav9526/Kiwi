/**
 * Inbox rules editor (T-281): the authoring surface for the backend rules
 * engine (`kiwi_rules_*`, ipc.md §6d — T-228/T-233/T-244). Live mode is
 * IPC-only: list/create-or-replace via `kiwi_rules_upsert`, delete with
 * inline confirm, enable/disable + reorder are upserts of the stored row,
 * "Test rule" dry-runs `kiwi_rules_preview`, "Run now" calls
 * `kiwi_rules_apply_now`. Renderer input is bounded (maxLength mirrors
 * model.rs caps) but never trusted — `Rule::validate` runs server-side.
 * Demo mode never fabricates a ruleset — it shows a labeled empty state.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  FolderView,
  RuleAction,
  RuleMatchOp,
  RulePredicate,
  RulePreviewView,
  RuleView,
} from "../kiwi";
import { api } from "../ipc";
import { Icon } from "../components/icons/index";

/* Renderer-side bounds mirroring kiwi-mail/src/rules/model.rs — the
 * server re-validates; these only stop obviously-doomed submits. */
const MAX_NAME = 128;
const MAX_VALUE = 512;
const MAX_HEADER_NAME = 64;
const MAX_ACTIONS = 8;
const MAX_NODES = 32;
const MAX_DEPTH = 8;

const FIELD_KINDS = [
  ["sender", "Sender address"],
  ["recipient", "Recipient address"],
  ["subject", "Subject"],
  ["header", "Header"],
  ["body_contains", "Body contains"],
  ["attachment_name", "Attachment name"],
] as const;

const NODE_KINDS: { kind: RulePredicate["kind"]; label: string }[] = [
  ...FIELD_KINDS.map(([kind, label]) => ({ kind, label })),
  { kind: "all", label: "All of (AND)" },
  { kind: "any", label: "Any of (OR)" },
  { kind: "not", label: "Not (negate)" },
  { kind: "always", label: "Always (every message)" },
];

const OPS: { op: RuleMatchOp; label: string }[] = [
  { op: "contains", label: "contains" },
  { op: "is", label: "is exactly" },
  { op: "ends_with", label: "ends with" },
  { op: "domain", label: "domain is" },
];

const ACTION_KINDS: { do: RuleAction["do"]; label: string }[] = [
  { do: "move", label: "Move to folder" },
  { do: "archive", label: "Archive" },
  { do: "delete", label: "Delete (Trash)" },
  { do: "mark_read", label: "Mark read" },
  { do: "star", label: "Star" },
];

const DISPOSITIONS = new Set<RuleAction["do"]>(["move", "archive", "delete"]);

type LeafPredicate = Extract<RulePredicate, { kind: "sender" | "recipient" | "subject" | "attachment_name" | "header" | "body_contains" }>;
function isLeaf(p: RulePredicate): p is LeafPredicate {
  return p.kind !== "all" && p.kind !== "any" && p.kind !== "not" && p.kind !== "always";
}

function blankLeaf(kind: RulePredicate["kind"]): RulePredicate {
  switch (kind) {
    case "header":
      return { kind: "header", name: "", op: "contains", value: "" };
    case "body_contains":
      return { kind: "body_contains", value: "" };
    case "all":
      return { kind: "all", children: [{ kind: "sender", op: "contains", value: "" }] };
    case "any":
      return { kind: "any", children: [{ kind: "sender", op: "contains", value: "" }] };
    case "not":
      return { kind: "not", child: { kind: "sender", op: "contains", value: "" } };
    case "always":
      return { kind: "always" };
    default:
      return { kind, op: "contains", value: "" } as RulePredicate;
  }
}

function countNodes(p: RulePredicate): number {
  if (p.kind === "all" || p.kind === "any") return 1 + p.children.reduce((n, c) => n + countNodes(c), 0);
  if (p.kind === "not") return 1 + countNodes(p.child);
  return 1;
}

function describePredicate(p: RulePredicate): string {
  switch (p.kind) {
    case "always":
      return "always";
    case "body_contains":
      return `body contains "${p.value}"`;
    case "header":
      return `header ${p.name} ${p.op} "${p.value}"`;
    case "all":
      return `(${p.children.map(describePredicate).join(" AND ")})`;
    case "any":
      return `(${p.children.map(describePredicate).join(" OR ")})`;
    case "not":
      return `NOT ${describePredicate(p.child)}`;
    default:
      return `${p.kind} ${p.op} "${p.value}"`;
  }
}

function describeAction(a: RuleAction): string {
  if (a.do === "move") return `move → ${a.folder}`;
  return a.do.replace("_", " ");
}

function newRuleId(): string {
  return `r-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/** One predicate-tree node: kind select swaps shape, combinators nest. */
function PredicateEditor({
  value,
  onChange,
  onRemove,
  depth,
  nodes,
}: {
  value: RulePredicate;
  onChange: (p: RulePredicate) => void;
  onRemove?: () => void;
  depth: number;
  nodes: number;
}) {
  const leaf = isLeaf(value) ? value : null;
  return (
    <div className="rule-node" style={{ marginLeft: depth > 0 ? "0.9rem" : 0 }}>
      <div style={{ display: "flex", gap: "0.35rem", alignItems: "center", flexWrap: "wrap" }}>
        <select
          value={value.kind}
          aria-label="Condition type"
          onChange={(e) => onChange(blankLeaf(e.target.value as RulePredicate["kind"]))}
        >
          {NODE_KINDS.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.label}
            </option>
          ))}
        </select>
        {leaf && leaf.kind !== "body_contains" && (
          <select
            value={leaf.op}
            aria-label="Match operator"
            onChange={(e) => onChange({ ...leaf, op: e.target.value as RuleMatchOp } as RulePredicate)}
          >
            {OPS.map((o) => (
              <option key={o.op} value={o.op}>
                {o.label}
              </option>
            ))}
          </select>
        )}
        {leaf?.kind === "header" && (
          <input
            type="text"
            value={leaf.name}
            maxLength={MAX_HEADER_NAME}
            placeholder="Header name (e.g. List-Id)"
            aria-label="Header name"
            style={{ width: "9rem" }}
            onChange={(e) => onChange({ ...leaf, name: e.target.value })}
          />
        )}
        {leaf && (
          <input
            type="text"
            value={leaf.value}
            maxLength={MAX_VALUE}
            placeholder="value"
            aria-label="Match value"
            style={{ minWidth: "10rem", flex: 1 }}
            onChange={(e) => onChange({ ...leaf, value: e.target.value } as RulePredicate)}
          />
        )}
        {value.kind === "always" && <small style={{ color: "var(--kiwi-text-secondary)" }}>matches every message</small>}
        {onRemove && (
          <button type="button" className="em-iconbtn" onClick={onRemove} aria-label="Remove condition" title="Remove condition">
            <Icon name="close" size={11} />
          </button>
        )}
      </div>
      {(value.kind === "all" || value.kind === "any") && (
        <div style={{ marginTop: "0.3rem" }}>
          {value.children.map((c, i) => (
            <PredicateEditor
              key={i}
              value={c}
              depth={depth + 1}
              nodes={nodes}
              onChange={(next) =>
                onChange({ ...value, children: value.children.map((x, j) => (j === i ? next : x)) } as RulePredicate)
              }
              onRemove={() =>
                onChange({ ...value, children: value.children.filter((_, j) => j !== i) } as RulePredicate)
              }
            />
          ))}
          <button
            type="button"
            className="ms-btn"
            disabled={depth + 1 >= MAX_DEPTH || nodes >= MAX_NODES}
            onClick={() =>
              onChange({
                ...value,
                children: [...value.children, { kind: "sender", op: "contains", value: "" }],
              } as RulePredicate)
            }
          >
            + Add condition
          </button>
        </div>
      )}
      {value.kind === "not" && (
        <div style={{ marginTop: "0.3rem" }}>
          <PredicateEditor
            value={value.child}
            depth={depth + 1}
            nodes={nodes}
            onChange={(next) => onChange({ kind: "not", child: next })}
          />
        </div>
      )}
    </div>
  );
}

export function RulesView({
  demo,
  accounts,
  folderLists,
}: {
  demo: boolean;
  accounts: { id: string; email: string; displayName: string }[];
  folderLists: Record<string, FolderView[]>;
}) {
  const [rules, setRules] = useState<RuleView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [draft, setDraft] = useState<RuleView | null>(null);
  const [confirmDel, setConfirmDel] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<RulePreviewView | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);

  const load = useCallback(async () => {
    if (demo) {
      setRules([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // kiwi_rules_list scopes per account (global + that account's) —
      // a bare call returns globals only, so merge per-account results
      // deduped by id to show the full ruleset.
      const perAccount = await Promise.all(accounts.map((a) => api.rulesList(a.id)));
      const merged = new Map<string, RuleView>();
      for (const list of [await api.rulesList(), ...perAccount]) {
        for (const r of list) merged.set(r.id, r);
      }
      setRules([...merged.values()]);
    } catch (e) {
      setRules([]);
      setError(`Rules unavailable: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, [demo, accounts]);

  useEffect(() => {
    void load();
  }, [load]);

  const sorted = useMemo(
    () => [...rules].sort((a, b) => a.position - b.position || a.id.localeCompare(b.id)),
    [rules],
  );

  const scopeLabel = (id: string | null | undefined) =>
    id ? accounts.find((a) => a.id === id)?.email ?? id : "All accounts";

  const startCreate = () => {
    setDraft({
      id: newRuleId(),
      accountId: null,
      name: "",
      enabled: true,
      position: (sorted[sorted.length - 1]?.position ?? -1) + 1,
      isBlock: false,
      when: { kind: "sender", op: "contains", value: "" },
      then: [{ do: "mark_read" }],
      failureCount: 0,
      lastError: null,
      lastFailureUnix: null,
    });
    setPreview(null);
    setError(null);
    setNote(null);
  };

  const startEdit = (r: RuleView) => {
    setDraft({ ...r, when: r.when, then: [...r.then] });
    setPreview(null);
    setError(null);
    setNote(null);
  };

  const saveDraft = async () => {
    if (!draft) return;
    setBusy(true);
    setError(null);
    try {
      await api.rulesUpsert(draft);
      setDraft(null);
      setPreview(null);
      setNote(`Rule "${draft.name || draft.id}" saved.`);
      await load();
    } catch (e) {
      // Server-side validation rejected it — show the reason verbatim.
      setError(`Save failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const toggleEnabled = async (r: RuleView) => {
    try {
      await api.rulesUpsert({ ...r, enabled: !r.enabled });
      await load();
    } catch (e) {
      setError(`Update failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  /** Reorder = swap `position` with the neighbor, one upsert each. */
  const move = async (r: RuleView, dir: 1 | -1) => {
    const i = sorted.findIndex((x) => x.id === r.id);
    const neighbor = sorted[i + dir];
    if (!neighbor) return;
    try {
      await api.rulesUpsert({ ...r, position: neighbor.position });
      await api.rulesUpsert({ ...neighbor, position: r.position });
      await load();
    } catch (e) {
      setError(`Reorder failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const remove = async (r: RuleView) => {
    try {
      await api.rulesDelete(r.id);
      setConfirmDel(null);
      setNote(`Rule "${r.name}" deleted.`);
      await load();
    } catch (e) {
      setError(`Delete failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  /** `kiwi_rules_preview` dry-run: candidate alone vs stored mail, pure read. */
  const runPreview = async () => {
    if (!draft) return;
    const accountId = draft.accountId ?? accounts[0]?.id;
    if (!accountId) {
      setError("Preview needs an account — none configured.");
      return;
    }
    setPreviewBusy(true);
    setError(null);
    try {
      setPreview(await api.rulesPreview(accountId, draft, 25));
    } catch (e) {
      setPreview(null);
      setError(`Preview failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setPreviewBusy(false);
    }
  };

  /** Re-run the enabled ruleset over stored mail on every account —
    * `kiwi_rules_apply_now` is per-account, so totals aggregate. */
  const applyNow = async () => {
    setError(null);
    try {
      let scanned = 0;
      let matched = 0;
      let moved = 0;
      let blocked = 0;
      let flagsChanged = 0;
      let skippedNoBody = 0;
      for (const a of accounts) {
        const r = await api.rulesApplyNow(a.id);
        scanned += r.scanned;
        matched += r.matched;
        moved += r.moved;
        blocked += r.blocked;
        flagsChanged += r.flagsChanged;
        skippedNoBody += r.skippedNoBody;
      }
      setNote(
        `Re-ran rules on ${accounts.length} account(s): ${scanned} scanned, ${matched} matched, ${moved} moved, ${blocked} blocked, ${flagsChanged} flag change(s), ${skippedNoBody} skipped (no body).`,
      );
    } catch (e) {
      setError(`Apply failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  /** Folder picker source — the rule's scope account, else every account
    * grouped. Stored value is the folder NAME (backend resolves it). */
  const folderOptions = useMemo(() => {
    if (draft?.accountId) return [{ account: scopeLabel(draft.accountId), folders: folderLists[draft.accountId] ?? [] }];
    return accounts.map((a) => ({ account: a.email, folders: folderLists[a.id] ?? [] }));
  }, [draft?.accountId, accounts, folderLists]);

  const nodes = draft ? countNodes(draft.when) : 0;

  return (
    <>
      <h2 style={{ marginTop: 0 }}>
        Inbox rules{" "}
        <small style={{ color: "var(--kiwi-text-secondary)", fontWeight: "normal" }}>
          — server-side, evaluated on ingest (kiwi.rules/1)
        </small>
      </h2>
      {demo ? (
        <p>
          <small>Rules management needs the Tauri backend — demo mode shows no ruleset (nothing fabricated).</small>
        </p>
      ) : (
        <>
          {error && (
            <div className="kiwi-banner error" role="alert">
              <small>{error}</small>
            </div>
          )}
          {note && (
            <p role="status">
              <small>{note}</small>
            </p>
          )}
          {loading ? (
            <p role="status">
              <small>Loading rules…</small>
            </p>
          ) : (
            <>
              {sorted.length === 0 && !draft && (
                <div className="kiwi-empty">
                  <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true">
                    <Icon name="filters" size={28} />
                  </span>
                  <strong>No rules yet</strong>
                  <br />
                  <small>Create the first one below — it evaluates in order, top first.</small>
                </div>
              )}
              <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                {sorted.map((r, i) => (
                  <div key={r.id} className="kiwi-row" style={{ display: "block" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <input
                        type="checkbox"
                        checked={r.enabled}
                        onChange={() => void toggleEnabled(r)}
                        aria-label={`${r.enabled ? "Disable" : "Enable"} rule ${r.name}`}
                        title={r.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                      />
                      <strong>{r.name}</strong>
                      {r.isBlock && (
                        <span className="kiwi-pill danger" title="Evaluated before regular rules; a match is terminal (Trash)">
                          block-list
                        </span>
                      )}
                      {r.failureCount > 0 && (
                        <span
                          className="kiwi-pill warning"
                          title={`${r.failureCount} apply-time failure(s)${r.lastFailureUnix ? ` — last ${new Date(r.lastFailureUnix * 1000).toLocaleString()}` : ""}${r.lastError ? `: ${r.lastError}` : ""}`}
                        >
                          failing ×{r.failureCount}
                        </span>
                      )}
                      <span className="kiwi-pill unknown" title={`Rule id ${r.id}`}>
                        {scopeLabel(r.accountId)}
                      </span>
                      <span style={{ marginLeft: "auto", display: "flex", gap: "0.2rem" }}>
                        <button
                          type="button"
                          className="em-iconbtn"
                          disabled={i === 0}
                          onClick={() => void move(r, -1)}
                          aria-label={`Move ${r.name} earlier`}
                          title="Move earlier (evaluates sooner)"
                        >
                          <Icon name="arrow-up" size={12} />
                        </button>
                        <button
                          type="button"
                          className="em-iconbtn"
                          disabled={i === sorted.length - 1}
                          onClick={() => void move(r, 1)}
                          aria-label={`Move ${r.name} later`}
                          title="Move later"
                        >
                          <Icon name="arrow-down" size={12} />
                        </button>
                        <button type="button" className="ms-btn" onClick={() => startEdit(r)}>
                          Edit
                        </button>
                        {confirmDel === r.id ? (
                          <>
                            <button type="button" className="ms-btn" onClick={() => void remove(r)} title="Confirm delete">
                              Delete?
                            </button>
                            <button type="button" className="ms-btn" onClick={() => setConfirmDel(null)}>
                              Keep
                            </button>
                          </>
                        ) : (
                          <button type="button" className="ms-btn" onClick={() => setConfirmDel(r.id)} title="Delete rule">
                            Delete
                          </button>
                        )}
                      </span>
                    </div>
                    <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)", marginTop: "0.15rem" }}>
                      when {describePredicate(r.when)} → {r.then.map(describeAction).join(", ")}
                      <span title="Evaluation position"> · pos {r.position}</span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
          {!draft && (
            <p style={{ marginTop: "0.5rem" }}>
              <button type="button" className="kiwi-btn-primary" onClick={startCreate}>
                + New rule
              </button>{" "}
              <button type="button" className="ms-btn" onClick={() => void applyNow()} disabled={accounts.length === 0}
                title="Re-run enabled rules over stored messages on every account (kiwi_rules_apply_now)">
                Run rules now
              </button>
            </p>
          )}

          {draft && (
            <div className="kiwi-card" style={{ marginTop: "0.6rem" }} aria-label="Rule editor">
              <h3 style={{ marginTop: 0 }}>{rules.some((r) => r.id === draft.id) ? "Edit rule" : "New rule"}</h3>
              <p style={{ display: "flex", gap: "0.8rem", flexWrap: "wrap" }}>
                <label>
                  Name
                  <br />
                  <input
                    type="text"
                    value={draft.name}
                    maxLength={MAX_NAME}
                    style={{ width: "16rem" }}
                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  />
                </label>
                <label>
                  Applies to
                  <br />
                  <select
                    value={draft.accountId ?? ""}
                    onChange={(e) => setDraft({ ...draft, accountId: e.target.value || null })}
                    aria-label="Rule scope"
                  >
                    <option value="">All accounts</option>
                    {accounts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.displayName || a.email}
                      </option>
                    ))}
                  </select>
                </label>
                <label style={{ alignSelf: "end" }}>
                  <input
                    type="checkbox"
                    checked={draft.enabled}
                    onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                  />{" "}
                  Enabled
                </label>
                <label style={{ alignSelf: "end" }} title="Block-list rules run before regular rules and a match is terminal (Trash)">
                  <input
                    type="checkbox"
                    checked={draft.isBlock}
                    onChange={(e) => setDraft({ ...draft, isBlock: e.target.checked })}
                  />{" "}
                  Block-list (terminal Trash)
                </label>
              </p>

              <fieldset style={{ border: "1px solid var(--kiwi-border)", borderRadius: "6px", padding: "0.5rem" }}>
                <legend>
                  <small>When this predicate matches ({nodes}/{MAX_NODES} nodes)</small>
                </legend>
                <PredicateEditor value={draft.when} onChange={(when) => setDraft({ ...draft, when })} depth={0} nodes={nodes} />
              </fieldset>

              <fieldset style={{ border: "1px solid var(--kiwi-border)", borderRadius: "6px", padding: "0.5rem", marginTop: "0.5rem" }}>
                <legend>
                  <small>Then apply ({draft.then.length}/{MAX_ACTIONS} actions — first folder action wins)</small>
                </legend>
                {draft.then.map((a, i) => (
                  <div key={i} style={{ display: "flex", gap: "0.35rem", alignItems: "center", marginBottom: "0.25rem" }}>
                    <select
                      value={a.do}
                      aria-label="Action"
                      onChange={(e) => {
                        const kind = e.target.value as RuleAction["do"];
                        const next: RuleAction =
                          kind === "move" ? { do: "move", folder: folderOptions[0]?.folders[0]?.name ?? "" } : { do: kind };
                        setDraft({ ...draft, then: draft.then.map((x, j) => (j === i ? next : x)) });
                      }}
                    >
                      {ACTION_KINDS.map((k) => (
                        <option
                          key={k.do}
                          value={k.do}
                          disabled={DISPOSITIONS.has(k.do) && draft.then.some((x, j) => j !== i && DISPOSITIONS.has(x.do))}
                        >
                          {k.label}
                        </option>
                      ))}
                    </select>
                    {a.do === "move" && (
                      <select
                        value={a.folder}
                        aria-label="Destination folder"
                        onChange={(e) => setDraft({ ...draft, then: draft.then.map((x, j) => (j === i ? { do: "move", folder: e.target.value } : x)) })}
                      >
                        {a.folder === "" && <option value="">(choose folder)</option>}
                        {folderOptions.map((g) => (
                          <optgroup key={g.account} label={g.account}>
                            {g.folders.map((f) => (
                              <option key={f.id} value={f.name}>
                                {f.name}
                              </option>
                            ))}
                          </optgroup>
                        ))}
                      </select>
                    )}
                    <button
                      type="button"
                      className="em-iconbtn"
                      aria-label="Remove action"
                      disabled={draft.then.length <= 1}
                      onClick={() => setDraft({ ...draft, then: draft.then.filter((_, j) => j !== i) })}
                    >
                      <Icon name="close" size={11} />
                    </button>
                  </div>
                ))}
                <button
                  type="button"
                  className="ms-btn"
                  disabled={draft.then.length >= MAX_ACTIONS}
                  onClick={() => setDraft({ ...draft, then: [...draft.then, { do: "star" }] })}
                >
                  + Add action
                </button>
              </fieldset>

              {preview && (
                <div className="kiwi-banner warn" role="status" style={{ marginTop: "0.5rem" }}>
                  <small>
                    Dry-run: {preview.matched} of {preview.scanned} stored message(s) would match
                    {preview.skippedNoBody > 0 ? ` (${preview.skippedNoBody} skipped — no body stored)` : ""}.
                  </small>
                  {preview.hits.length > 0 && (
                    <ul style={{ margin: "0.3rem 0 0" }}>
                      {preview.hits.slice(0, 10).map((h, i) => (
                        <li key={i}>
                          <small>
                            {h.folder} — {h.subject ?? "(no subject)"}
                          </small>
                        </li>
                      ))}
                      {preview.hits.length > 10 && (
                        <li>
                          <small>…and {preview.hits.length - 10} more</small>
                        </li>
                      )}
                    </ul>
                  )}
                </div>
              )}

              <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.6rem" }}>
                <button type="button" className="kiwi-btn-primary" onClick={() => void saveDraft()} disabled={busy}>
                  {busy ? "Saving…" : "Save rule"}
                </button>
                <button
                  type="button"
                  className="ms-btn"
                  onClick={() => void runPreview()}
                  disabled={previewBusy || accounts.length === 0}
                  title="Dry-run this rule against stored mail — nothing is moved or flagged (kiwi_rules_preview)"
                >
                  {previewBusy ? "Testing…" : "Test rule"}
                </button>
                <button
                  type="button"
                  className="ms-btn"
                  onClick={() => {
                    setDraft(null);
                    setPreview(null);
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}
