/**
 * Contacts view (T-173): list/search/detail/edit panels over the address
 * book (`kiwi.contacts/1`, docs/contracts/contacts.md §3), live-wired to
 * the contacts IPC commands (T-231). Live mode is IPC-only — a backend
 * failure surfaces as an error banner, never as local/demo data. The
 * labeled localStorage book (`src/contacts.ts`, with seeded demo cards)
 * is reachable only when `demo` is set — a live account never sees it.
 * The search box filters the loaded list client-side (bounded at 500);
 * `kiwi_search_contacts` remains for larger books. Import keeps a
 * client-side parse only for the preview table — the write itself goes
 * through `kiwi_import_vcards` (server-side dedupe + issue report);
 * export uses `kiwi_export_vcards`.
 */

import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import type { ContactInput, ContactView } from "../kiwi";
import { contactLabel, contactPrimaryEmail, parseContact } from "../kiwi";
import { api } from "../ipc";
import { Icon } from "../components/icons/index";
import {
  deleteLocal,
  filterContacts,
  loadLocalBook,
  saveLocalBook,
  upsertLocal,
  validateContactInput,
} from "../contacts";
import { exportVCard, MAX_VCARD_BYTES, parseVCard } from "../vcard";
import type { VCardParse } from "../vcard";

const grid: CSSProperties = { display: "grid", gridTemplateColumns: "minmax(240px, 320px) 1fr", gap: "0.8rem", height: "100%" };

interface FormState {
  displayName: string;
  givenName: string;
  familyName: string;
  org: string;
  title: string;
  emails: string;
  phones: string;
  tags: string;
  notes: string;
}

const BLANK: FormState = {
  displayName: "", givenName: "", familyName: "", org: "", title: "",
  emails: "", phones: "", tags: "", notes: "",
};

function toForm(c: ContactView): FormState {
  return {
    displayName: c.displayName,
    givenName: c.givenName ?? "",
    familyName: c.familyName ?? "",
    org: c.org ?? "",
    title: c.title ?? "",
    emails: c.emails.map((e) => e.address).join("\n"),
    phones: c.phones.map((p) => p.number).join("\n"),
    tags: c.tags.join(", "),
    notes: c.notes ?? "",
  };
}

function toInput(f: FormState): ContactInput {
  return {
    displayName: f.displayName.trim(),
    givenName: f.givenName.trim() || null,
    familyName: f.familyName.trim() || null,
    org: f.org.trim() || null,
    title: f.title.trim() || null,
    notes: f.notes.trimEnd() || null,
    tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean),
    emails: f.emails.split("\n").map((a) => a.trim()).filter(Boolean).map((address) => ({ address })),
    phones: f.phones.split("\n").map((n) => n.trim()).filter(Boolean).map((number) => ({ number })),
  };
}

export function ContactsView({
  demo,
  onNotify,
}: {
  demo: boolean;
  onNotify: (kind: "info" | "ok" | "warn" | "error", text: string) => void;
}) {
  const [contacts, setContacts] = useState<ContactView[]>([]);
  const [source, setSource] = useState<"server" | "local">("local");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState<FormState>(BLANK);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showIO, setShowIO] = useState(false);
  const [preview, setPreview] = useState<VCardParse | null>(null);
  const [previewName, setPreviewName] = useState("");
  const [previewText, setPreviewText] = useState("");
  const [ioNote, setIoNote] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    void (async () => {
      if (demo) {
        // Demo mode owns the seeded localStorage book — no IPC at all.
        if (!cancelled) {
          setContacts(loadLocalBook());
          setSource("local");
          setLoading(false);
        }
        return;
      }
      try {
        const list = await api.listContacts(500);
        if (!cancelled) {
          setContacts(list);
          setSource("server");
        }
      } catch (e) {
        // Live mode never falls back to local/demo fixtures — surface
        // the failure and show an empty book.
        if (!cancelled) {
          setContacts([]);
          setSource("server");
          setError(`Address book unavailable: ${e instanceof Error ? e.message : String(e)}`);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [demo]);

  const filtered = useMemo(() => filterContacts(contacts, query), [contacts, query]);
  const selected = contacts.find((c) => c.id === selectedId) ?? null;

  const startEdit = () => {
    if (!selected) return;
    setForm(toForm(selected));
    setEditing(true);
    setCreating(false);
    setError(null);
    setNote(null);
    setConfirmDelete(false);
  };

  const startCreate = () => {
    setForm(BLANK);
    setCreating(true);
    setEditing(false);
    setSelectedId(null);
    setError(null);
    setNote(null);
    setConfirmDelete(false);
  };

  const persistLocal = (next: ContactView[], msg: string) => {
    setContacts(next);
    saveLocalBook(next);
    setNote(msg);
    onNotify("ok", msg);
  };

  const save = async () => {
    const input = toInput(form);
    const problem = validateContactInput(input);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (creating) {
        if (demo) {
          const next = upsertLocal(loadLocalBook(), input);
          persistLocal(next, "Saved to the demo book.");
          setCreating(false);
          const last = next[next.length - 1];
          if (last) setSelectedId(last.id);
        } else {
          try {
            const created = parseContact(await api.createContact(input));
            const list = await api.listContacts(500);
            setContacts(list);
            setSource("server");
            if (created) setSelectedId(created.id);
            setCreating(false);
            onNotify("ok", "Contact created.");
          } catch (e) {
            setError(`Create failed: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
      } else if (selected) {
        if (demo) {
          persistLocal(
            upsertLocal(loadLocalBook(), input, selected.id),
            "Updated in the demo book.",
          );
          setEditing(false);
        } else {
          try {
            await api.updateContact(selected.id, input);
            const list = await api.listContacts(500);
            setContacts(list);
            setSource("server");
            setEditing(false);
            onNotify("ok", "Contact updated.");
          } catch (e) {
            setError(`Update failed: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (demo) {
        persistLocal(deleteLocal(loadLocalBook(), selected.id), "Deleted from the demo book.");
      } else {
        try {
          await api.deleteContact(selected.id);
          setContacts(await api.listContacts(500));
          onNotify("ok", "Contact deleted.");
        } catch (e) {
          setError(`Delete failed: ${e instanceof Error ? e.message : String(e)}`);
          return;
        }
      }
      setSelectedId(null);
      setConfirmDelete(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const set = (k: keyof FormState) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  /** .vcf picker (T-176): platform file input, 1 MiB cap. Parsed
    * client-side into a preview table; the raw text is kept so live
    * import can hand the backend the original payload unchanged. */
  const pickFile = (files: FileList | null) => {
    setIoNote(null);
    setPreview(null);
    setPreviewText("");
    const file = files?.[0];
    if (!file) return;
    if (file.size > MAX_VCARD_BYTES) {
      setIoNote(`"${file.name}" exceeds the 1 MiB import cap — split the file and retry.`);
      return;
    }
    setPreviewName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = typeof reader.result === "string" ? reader.result : "";
        setPreview(parseVCard(text));
        setPreviewText(text);
      } catch {
        setIoNote(`Could not read "${file.name}" as text.`);
      }
    };
    reader.onerror = () => setIoNote(`Could not read "${file.name}".`);
    reader.readAsText(file);
  };

  /** Import previewed cards: live mode writes the server book only
    * (per-card failures are counted, not silently diverted); demo mode
    * upserts the local book, matching on primary email (case-insensitive)
    * so the same file twice does not duplicate. */
  const importPreview = async () => {
    if (!preview || preview.contacts.length === 0) return;
    setBusy(true);
    setIoNote(null);
    try {
      if (demo) {
        let next = loadLocalBook();
        let added = 0;
        let updated = 0;
        for (const input of preview.contacts) {
          const primary = (input.emails[0]?.address ?? "").toLowerCase();
          const match = next.find((c) => c.emails.some((e) => e.address.toLowerCase() === primary) && primary);
          if (match) {
            next = upsertLocal(next, input, match.id);
            updated++;
          } else {
            next = upsertLocal(next, input);
            added++;
          }
        }
        saveLocalBook(next);
        setContacts(next);
        const msg = `Demo import: ${added} added, ${updated} updated.`;
        setIoNote(msg);
        onNotify("ok", msg);
        setPreview(null);
        return;
      }
      // Live import — kiwi_import_vcards re-parses the original payload
      // server-side (dedupe + per-card issues come from the contract).
      const r = await api.importVcards(previewText);
      setContacts(await api.listContacts(500));
      const msg = r.issues.length
        ? `Import done: ${r.contacts.length} contact(s) imported, ${r.issues.length} issue(s) — ${r.issues
            .slice(0, 2)
            .map((i) => `card ${i.cardIndex >= 0 ? i.cardIndex + 1 : "—"}: ${i.detail}`)
            .join("; ")}.`
        : `Import done: ${r.contacts.length} contact(s) imported.`;
      setIoNote(msg);
      onNotify(r.issues.length ? "warn" : "ok", msg);
      setPreview(null);
      setPreviewText("");
    } catch (e) {
      setIoNote(`Import failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  /** Export: live mode pulls the canonical server serialization
    * (kiwi_export_vcards); demo serializes the local book client-side. */
  const exportAll = async () => {
    setIoNote(null);
    let text: string;
    if (demo) {
      text = exportVCard(contacts);
    } else {
      try {
        text = (await api.exportVcards()).vcard;
      } catch (e) {
        setIoNote(`Export failed: ${e instanceof Error ? e.message : String(e)}`);
        return;
      }
    }
    if (!text) {
      setIoNote("Nothing to export — the book is empty.");
      return;
    }
    const blob = new Blob([text], { type: "text/vcard;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "kiwi-contacts.vcf";
    a.click();
    URL.revokeObjectURL(url);
    setIoNote(`Exported ${contacts.length} contact(s) to kiwi-contacts.vcf (vCard 4.0).`);
  };

  return (
    <div style={grid}>
      <section aria-label="Contact list">
        <h1 style={{ fontSize: "1.1rem", margin: "0 0 0.5rem" }}>
          Contacts{" "}
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            ({filtered.length}
            {source === "server" ? "" : " · demo"})
          </small>
        </h1>
        <p>
          <label>
            <span className="kiwi-sr-only">Search contacts</span>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search name, org, email…"
              style={{ width: "100%" }}
              aria-label="Search contacts"
            />
          </label>
        </p>
        <p>
          <button type="button" className="kiwi-btn-primary" onClick={startCreate}>
            + New contact
          </button>
        </p>
        {loading && <p role="status"><small>Loading…</small></p>}
        {filtered.length === 0 && !loading && (
          <div className="kiwi-empty">
            <span className="kiwi-empty-icon em-empty-icon" aria-hidden="true"><Icon name="accounts" size={28} /></span>
            <strong>No contacts</strong>
            <br />
            <small>{query ? "No matches — clear the search." : "Create the first card."}</small>
          </div>
        )}
        <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.3rem" }} role="listbox" aria-label="Contacts">
          {filtered.map((c) => (
            <article
              key={c.id}
              role="option"
              aria-selected={c.id === selectedId}
              className="kiwi-row"
              tabIndex={0}
              onClick={() => {
                setSelectedId(c.id);
                setEditing(false);
                setCreating(false);
                setError(null);
                setNote(null);
                setConfirmDelete(false);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setSelectedId(c.id);
                  setEditing(false);
                  setCreating(false);
                }
              }}
              aria-label={`${contactLabel(c)}${contactPrimaryEmail(c) ? `, ${contactPrimaryEmail(c)}` : ""}`}
            >
              <div><strong>{contactLabel(c)}</strong></div>
              <div style={{ fontSize: "0.8rem", color: "var(--kiwi-text-secondary)" }}>
                {[contactPrimaryEmail(c), c.org].filter(Boolean).join(" · ")}
                {c.emails.length > 1 && ` +${c.emails.length - 1} more`}
              </div>
            </article>
          ))}
        </div>
        <p style={{ color: "var(--kiwi-text-secondary)" }}>
          <small>
            {source === "server"
              ? "Live address book (kiwi.contacts/1)."
              : "Demo address book — localStorage fixture, no IPC."}
          </small>
        </p>
        <p>
          <button type="button" onClick={() => setShowIO((s) => !s)} aria-expanded={showIO}>
            {showIO ? "Hide import / export" : "Import / export (.vcf)"}
          </button>
        </p>
        {showIO && (
          <div className="kiwi-card" aria-label="vCard import and export">
            <h2 style={{ marginTop: 0 }}>Import / export</h2>
            <p>
              <label>
                .vcf file (typed path, 1 MiB cap):{" "}
                <input
                  type="file"
                  accept=".vcf,.vcard,text/vcard,text/x-vcard"
                  onChange={(e) => pickFile(e.target.files)}
                  aria-label="Choose a vCard file to import"
                />
              </label>
            </p>
            {ioNote && (
              <p role="status"><small>{ioNote}</small></p>
            )}
            {preview && (
              <>
                <h3>
                  Preview: {previewName} ({preview.contacts.length} valid, {preview.issues.length} issue(s))
                </h3>
                {preview.contacts.length > 0 && (
                  <table style={{ borderCollapse: "collapse", width: "100%", marginBottom: "0.5rem" }}>
                    <caption className="kiwi-sr-only">Parsed contacts preview</caption>
                    <thead>
                      <tr>
                        {["Name", "Emails", "Org"].map((h) => (
                          <th key={h} scope="col" style={{ textAlign: "left", borderBottom: "1px solid var(--kiwi-border)", padding: "0.3rem" }}>
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {preview.contacts.map((c, i) => (
                        <tr key={i}>
                          <td style={{ padding: "0.3rem" }}>{c.displayName || "(unnamed)"}</td>
                          <td style={{ padding: "0.3rem" }}>{c.emails.map((e) => e.address).join(", ")}</td>
                          <td style={{ padding: "0.3rem" }}>{c.org ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {preview.issues.length > 0 && (
                  <ul>
                    {preview.issues.map((issue, i) => (
                      <li key={i}>
                        <small>
                          Card {issue.cardIndex >= 0 ? issue.cardIndex + 1 : "—"}: {issue.detail}
                        </small>
                      </li>
                    ))}
                  </ul>
                )}
                <div style={{ display: "flex", gap: "0.4rem" }}>
                  <button
                    type="button"
                    className="kiwi-btn-primary"
                    onClick={() => void importPreview()}
                    disabled={busy || preview.contacts.length === 0}
                  >
                    {busy ? "Importing…" : `Import ${preview.contacts.length} contact(s)`}
                  </button>
                  <button type="button" onClick={() => setPreview(null)}>
                    Discard preview
                  </button>
                </div>
              </>
            )}
            <p>
              <button type="button" onClick={() => void exportAll()} disabled={contacts.length === 0}>
                Export all ({contacts.length}) as .vcf
              </button>{" "}
              <small style={{ color: "var(--kiwi-text-secondary)" }}>
                vCard 4.0 download — photos never stored, per the contract.
              </small>
            </p>
          </div>
        )}
      </section>
      <section className="kiwi-reader" aria-label="Contact detail" tabIndex={0}>
        {note && (
          <p role="status"><small>{note}</small></p>
        )}
        {error && (
          <div className="kiwi-banner error" role="alert"><small>{error}</small></div>
        )}
        {(editing || creating) && (
          <>
            <h2 style={{ marginTop: 0 }}>{creating ? "New contact" : "Edit contact"}</h2>
            <p><label>Display name<br /><input type="text" value={form.displayName} onChange={set("displayName")} style={{ width: "100%" }} /></label></p>
            <p style={{ display: "flex", gap: "0.5rem" }}>
              <label>Given name<br /><input type="text" value={form.givenName} onChange={set("givenName")} style={{ width: "100%" }} /></label>
              <label>Family name<br /><input type="text" value={form.familyName} onChange={set("familyName")} style={{ width: "100%" }} /></label>
            </p>
            <p style={{ display: "flex", gap: "0.5rem" }}>
              <label>Organization<br /><input type="text" value={form.org} onChange={set("org")} style={{ width: "100%" }} /></label>
              <label>Title<br /><input type="text" value={form.title} onChange={set("title")} style={{ width: "100%" }} /></label>
            </p>
            <p><label>Emails (one per line)<br /><textarea rows={3} value={form.emails} onChange={set("emails")} style={{ width: "100%" }} /></label></p>
            <p><label>Phones (one per line)<br /><textarea rows={2} value={form.phones} onChange={set("phones")} style={{ width: "100%" }} /></label></p>
            <p><label>Tags (comma-separated)<br /><input type="text" value={form.tags} onChange={set("tags")} style={{ width: "100%" }} /></label></p>
            <p><label>Notes<br /><textarea rows={3} value={form.notes} onChange={set("notes")} style={{ width: "100%" }} /></label></p>
            <div style={{ display: "flex", gap: "0.4rem" }}>
              <button type="button" className="kiwi-btn-primary" onClick={() => void save()} disabled={busy}>
                {busy ? "Saving…" : creating ? "Create" : "Save"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setEditing(false);
                  setCreating(false);
                  setError(null);
                }}
              >
                Cancel
              </button>
            </div>
          </>
        )}
        {!editing && !creating && selected && (
          <>
            <h2 style={{ marginTop: 0 }}>{contactLabel(selected)}</h2>
            {(selected.org || selected.title) && (
              <p style={{ color: "var(--kiwi-text-secondary)" }}>
                {[selected.title, selected.org].filter(Boolean).join(", ")}
              </p>
            )}
            {selected.emails.length > 0 && (
              <>
                <h3>Emails</h3>
                <ul>
                  {selected.emails.map((e) => (
                    <li key={e.address}>
                      {e.address}{e.label && <small> ({e.label})</small>}
                    </li>
                  ))}
                </ul>
              </>
            )}
            {selected.phones.length > 0 && (
              <>
                <h3>Phones</h3>
                <ul>
                  {selected.phones.map((p) => (
                    <li key={p.number}>
                      {p.number}{p.label && <small> ({p.label})</small>}
                    </li>
                  ))}
                </ul>
              </>
            )}
            {selected.tags.length > 0 && (
              <p>
                {selected.tags.map((t) => (
                  <span key={t} className="kiwi-pill unknown" style={{ marginRight: "0.3rem" }}>{t}</span>
                ))}
              </p>
            )}
            {selected.notes && (
              <>
                <h3>Notes</h3>
                <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit" }}>{selected.notes}</pre>
              </>
            )}
            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              <button type="button" onClick={startEdit}>Edit</button>
              {confirmDelete ? (
                <>
                  <button type="button" onClick={() => void remove()} disabled={busy}>
                    Confirm delete {contactLabel(selected)}
                  </button>
                  <button type="button" onClick={() => setConfirmDelete(false)}>Keep</button>
                </>
              ) : (
                <button type="button" onClick={() => setConfirmDelete(true)}>Delete…</button>
              )}
            </div>
          </>
        )}
        {!editing && !creating && !selected && (
          <p style={{ color: "var(--kiwi-text-secondary)" }}>Select a contact — or create one.</p>
        )}
      </section>
    </div>
  );
}
