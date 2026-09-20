/**
 * Contacts view (T-173): list/search/detail/edit panels over the address
 * book (`kiwi.contacts/1`, docs/contracts/contacts.md §3). No backend
 * command exists yet (Agent 7) — the view tries `kiwi_list_contacts` first
 * and falls back to the labeled localStorage book (`src/contacts.ts`),
 * which also seeds two demo cards. Writes try the IPC then the local book
 * with an honest note. Same wrappers either way: zero view changes on land.
 */

import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import type { ContactInput, ContactView } from "../kiwi";
import { contactLabel, contactPrimaryEmail, parseContact } from "../kiwi";
import { api } from "../ipc";
import {
  deleteLocal,
  filterContacts,
  loadLocalBook,
  saveLocalBook,
  upsertLocal,
  validateContactInput,
} from "../contacts";

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

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    void (async () => {
      try {
        const list = await api.listContacts(500);
        if (!cancelled) {
          setContacts(list);
          setSource("server");
        }
      } catch {
        if (!cancelled) {
          setContacts(loadLocalBook());
          setSource("local");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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
        try {
          const created = parseContact(await api.createContact(input));
          const list = await api.listContacts(500);
          setContacts(list);
          setSource("server");
          if (created) setSelectedId(created.id);
          setCreating(false);
          onNotify("ok", "Contact created.");
        } catch {
          const next = upsertLocal(loadLocalBook(), input);
          persistLocal(next, "Saved locally — contacts IPC not in the backend yet.");
          setCreating(false);
          const last = next[next.length - 1];
          if (last) setSelectedId(last.id);
        }
      } else if (selected) {
        try {
          await api.updateContact(selected.id, input);
          const list = await api.listContacts(500);
          setContacts(list);
          setSource("server");
          setEditing(false);
          onNotify("ok", "Contact updated.");
        } catch {
          persistLocal(
            upsertLocal(loadLocalBook(), input, selected.id),
            "Updated locally — contacts IPC not in the backend yet.",
          );
          setEditing(false);
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
      try {
        await api.deleteContact(selected.id);
        setContacts(await api.listContacts(500));
        onNotify("ok", "Contact deleted.");
      } catch {
        persistLocal(deleteLocal(loadLocalBook(), selected.id), "Deleted locally — contacts IPC not in the backend yet.");
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

  return (
    <div style={grid}>
      <section aria-label="Contact list">
        <h1 style={{ fontSize: "1.1rem", margin: "0 0 0.5rem" }}>
          Contacts{" "}
          <small style={{ color: "var(--kiwi-text-secondary)" }}>
            ({filtered.length}
            {source === "server" ? "" : demo ? " · demo" : " · local"})
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
            <span className="kiwi-empty-icon" aria-hidden="true">👥</span>
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
              : "Local address book — contacts IPC not in the backend yet; cards sync when it lands."}
          </small>
        </p>
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
