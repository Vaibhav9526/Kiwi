/**
 * TemplatesManager (T-301, ipc.md §6i): real CRUD over kiwi_templates_* —
 * flat named list (content, not policy; no account scoping). Placeholder
 * UX mirrors the server grammar: detected `{{name}}` tokens are listed for
 * reference, and "Preview" renders server-side (`kiwi_templates_render`)
 * with caller-supplied test vars — `missingVars` is surfaced verbatim as
 * the names the composer will flag. Preview needs a saved row because the
 * contract renders by id only.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../ipc";
import type { RenderedTemplateView, TemplateView } from "../kiwi";
import { Icon } from "../components/icons/index";

/** Server grammar (§6i): `{{` + [A-Za-z0-9_.-]+ ≤64B + `}}`, inner ws trimmed. */
const VAR_RE = /\{\{\s*([A-Za-z0-9_.-]{1,64})\s*\}\}/g;

/** Placeholder names detected in template text — display-only; the server
 * remains the authority (it reports `missingVars` on render). */
export function templateVars(subject: string, bodyText: string, bodyHtml?: string): string[] {
  const found = new Set<string>();
  for (const src of [subject, bodyText, bodyHtml ?? ""]) {
    for (const m of src.matchAll(VAR_RE)) found.add(m[1]);
  }
  return [...found].sort();
}

export function TemplatesManager({ live }: { live: boolean }) {
  const [rows, setRows] = useState<TemplateView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<TemplateView | null>(null);
  const [draftNew, setDraftNew] = useState(false);
  const [confirmDel, setConfirmDel] = useState<string | null>(null);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [previewVars, setPreviewVars] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<RenderedTemplateView | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!live) {
      setRows([]);
      return;
    }
    setError(null);
    try {
      setRows(await api.templatesList());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRows([]);
    }
  }, [live]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (t: { id?: string; name: string; subject: string; bodyText: string; bodyHtml: string }) => {
    setBusy(true);
    setError(null);
    try {
      if (t.id) {
        const orig = rows?.find((r) => r.id === t.id);
        await api.templatesUpdate({
          id: t.id,
          name: t.name,
          subject: t.subject,
          bodyText: t.bodyText,
          ...(t.bodyHtml ? { bodyHtml: t.bodyHtml } : {}),
          createdUnix: orig?.createdUnix ?? 0,
          updatedUnix: orig?.updatedUnix ?? 0,
        });
        setNote(`Template “${t.name}” updated.`);
      } else {
        const created = await api.templatesCreate({
          name: t.name,
          subject: t.subject || undefined,
          bodyText: t.bodyText || undefined,
          ...(t.bodyHtml ? { bodyHtml: t.bodyHtml } : {}),
        });
        setNote(`Template “${created.name}” saved as ${created.id}.`);
      }
      setEditing(null);
      setDraftNew(false);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const del = async (id: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.templatesDelete(id);
      setConfirmDel(null);
      if (editing?.id === id) setEditing(null);
      setNote("Template deleted.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const runPreview = async (id: string) => {
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.templatesRender(id, previewVars));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!live) {
    return (
      <p className="em-note">
        <small>Message templates need the Tauri backend — demo mode shows no stored list.</small>
      </p>
    );
  }

  return (
    <div aria-label="Message templates">
      {error && (
        <div className="kiwi-banner error" role="alert">
          <small>{error}</small>{" "}
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {note && (
        <p className="em-note" role="status">
          <small>{note}</small>
        </p>
      )}
      {rows === null ? (
        <p role="status">
          <small>Loading templates…</small>
        </p>
      ) : rows.length === 0 ? (
        <p className="em-note">
          <small>No templates yet — create one below or save the composer body via “Save as template”.</small>
        </p>
      ) : (
        <ul aria-label="Stored templates" style={{ listStyle: "none", padding: 0, margin: "0 0 0.6rem" }}>
          {rows.map((t) => {
            const vars = templateVars(t.subject, t.bodyText, t.bodyHtml);
            return (
              <li key={t.id} className="em-card" style={{ padding: "0.5rem 0.75rem", marginBottom: "0.4rem" }}>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "baseline", flexWrap: "wrap" }}>
                  <strong>{t.name}</strong>
                  {t.subject && <small style={{ color: "var(--kiwi-text-secondary)" }}>Subject: {t.subject}</small>}
                  <small style={{ marginLeft: "auto", color: "var(--kiwi-text-secondary)" }}>
                    updated {new Date(t.updatedUnix * 1000).toLocaleDateString()}
                  </small>
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--kiwi-text-secondary)", margin: "0.2rem 0" }}>
                  {t.bodyText.slice(0, 120)}
                  {t.bodyText.length > 120 ? "…" : ""}
                  {vars.length > 0 && (
                    <>
                      {" "}
                      · placeholders:{" "}
                      {vars.map((v) => (
                        <code key={v}>{`{{${v}}}`}</code>
                      ))}
                    </>
                  )}
                </div>
                <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    onClick={() => {
                      setEditing({ ...t });
                      setDraftNew(false);
                      setPreviewId(null);
                    }}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setPreviewId(previewId === t.id ? null : t.id);
                      setPreview(null);
                      setPreviewVars({});
                    }}
                    aria-expanded={previewId === t.id}
                  >
                    Preview…
                  </button>
                  {confirmDel === t.id ? (
                    <>
                      <button type="button" className="ms-btn-primary" disabled={busy} onClick={() => void del(t.id)}>
                        Confirm delete
                      </button>
                      <button type="button" onClick={() => setConfirmDel(null)}>
                        Keep
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setConfirmDel(t.id)} aria-label={`Delete template ${t.name}`}>
                      Delete
                    </button>
                  )}
                </div>
                {previewId === t.id && (
                  <div className="em-note" style={{ marginTop: "0.5rem" }}>
                    {vars.length > 0 && (
                      <p style={{ margin: "0 0 0.35rem" }}>
                        <small>Fill test values (empty = left verbatim + flagged):</small>
                        {vars.map((v) => (
                          <label key={v} style={{ display: "inline-flex", gap: "0.25rem", alignItems: "center", margin: "0 0.5rem 0.25rem 0" }}>
                            <code>{`{{${v}}}`}</code>
                            <input
                              type="text"
                              value={previewVars[v] ?? ""}
                              onChange={(e) => setPreviewVars((m) => ({ ...m, [v]: e.target.value }))}
                              style={{ width: "8rem" }}
                              aria-label={`Test value for ${v}`}
                            />
                          </label>
                        ))}
                      </p>
                    )}
                    <button type="button" disabled={busy} onClick={() => void runPreview(t.id)}>
                      Render preview
                    </button>
                    {preview && (
                      <div style={{ marginTop: "0.4rem" }}>
                        {preview.missingVars.length > 0 && (
                          <div className="kiwi-banner warn" role="status">
                            <small>
                              Unfilled placeholders stay verbatim: {preview.missingVars.map((v) => `{{${v}}}`).join(", ")}
                            </small>
                          </div>
                        )}
                        {preview.subject && (
                          <p style={{ margin: "0.25rem 0" }}>
                            <small>Subject:</small> <strong>{preview.subject}</strong>
                          </p>
                        )}
                        <pre style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem", maxHeight: "12rem", overflow: "auto", margin: "0.25rem 0" }}>
                          {preview.bodyText}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {editing || draftNew ? (
        <TemplateEditor
          initial={editing}
          busy={busy}
          onCancel={() => {
            setEditing(null);
            setDraftNew(false);
          }}
          onSave={(t) => void save(t)}
        />
      ) : (
        <p>
          <button type="button" className="kiwi-btn-primary" onClick={() => setDraftNew(true)}>
            New template…
          </button>{" "}
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            Placeholders look like <code>{"{{name}}"}</code>. The composer fills <code>{"{{from_name}}"}</code>,{" "}
            <code>{"{{from_email}}"}</code>, <code>{"{{to}}"}</code> and <code>{"{{date}}"}</code> automatically; anything
            else is left verbatim and flagged on insert.
          </small>
        </p>
      )}
    </div>
  );
}

function TemplateEditor({
  initial,
  busy,
  onCancel,
  onSave,
}: {
  initial: TemplateView | null;
  busy: boolean;
  onCancel: () => void;
  onSave: (t: { id?: string; name: string; subject: string; bodyText: string; bodyHtml: string }) => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [subject, setSubject] = useState(initial?.subject ?? "");
  const [bodyText, setBodyText] = useState(initial?.bodyText ?? "");
  const [bodyHtml, setBodyHtml] = useState(initial?.bodyHtml ?? "");
  const vars = templateVars(subject, bodyText, bodyHtml);
  return (
    <fieldset className="em-card" style={{ padding: "0.6rem 0.75rem" }} disabled={busy}>
      <legend>{initial ? `Edit ${initial.name}` : "New template"}</legend>
      <p>
        <label>
          Name:{" "}
          <input type="text" required value={name} maxLength={128} onChange={(e) => setName(e.target.value)} style={{ width: "18rem" }} />
        </label>
      </p>
      <p>
        <label>
          Subject:{" "}
          <input type="text" value={subject} maxLength={998} onChange={(e) => setSubject(e.target.value)} style={{ width: "26rem" }} />
        </label>
      </p>
      <p>
        <label style={{ display: "block" }}>
          Body (plaintext):{" "}
          <textarea rows={8} value={bodyText} maxLength={65536} onChange={(e) => setBodyText(e.target.value)} style={{ width: "100%" }} />
        </label>
      </p>
      <details>
        <summary>HTML body (optional — the plaintext composer ignores it)</summary>
        <textarea rows={4} value={bodyHtml} maxLength={131072} onChange={(e) => setBodyHtml(e.target.value)} style={{ width: "100%" }} />
      </details>
      {vars.length > 0 && (
        <p className="em-note">
          <small>
            <Icon name="info" size={11} /> Placeholders detected:{" "}
            {vars.map((v) => (
              <code key={v}>{`{{${v}}}`}</code>
            ))}{" "}
            — saved verbatim; substituted only at render.
          </small>
        </p>
      )}
      <p>
        <button type="button" className="kiwi-btn-primary" disabled={busy || !name.trim()} onClick={() => onSave({ id: initial?.id, name: name.trim(), subject, bodyText, bodyHtml })}>
          {initial ? "Save changes" : "Create template"}
        </button>{" "}
        <button type="button" onClick={onCancel}>
          Cancel
        </button>{" "}
        {!initial && <small style={{ color: "var(--kiwi-text-secondary)" }}>Render preview is available after saving (the backend renders by id).</small>}
      </p>
    </fieldset>
  );
}
