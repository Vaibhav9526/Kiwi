/**
 * Local address-book fallback (T-173): user-authored contacts persisted in
 * localStorage until the contacts IPC lands (`kiwi_list_contacts` et al —
 * no backend command exists yet, verified in `src-tauri/`). Same shapes as
 * the wire views, so views switch source without changes. Seeded once with
 * two labeled demo cards; the seed flag keeps user edits from re-seeding.
 */

import type { ContactInput, ContactView } from "./kiwi";
import { parseContact } from "./kiwi";

export const LOCAL_BOOK_KEY = "kiwi.contacts.local";
const SEED_KEY = "kiwi.contacts.seeded";

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function seed(): ContactView[] {
  const t = nowSecs();
  return [
    {
      id: "demo-alice", displayName: "Alice Example", givenName: "Alice", familyName: "Example",
      org: "Example Co", title: "Engineer", notes: "Demo card — replaced by the real address book.",
      tags: ["demo"], emails: [{ address: "alice@example.test", label: "work" }], phones: [],
      createdUnix: t, updatedUnix: t,
    },
    {
      id: "demo-bob", displayName: "Bob Retro", givenName: "Bob", familyName: "Retro",
      org: null, title: null, notes: null, tags: ["demo"],
      emails: [{ address: "bob@retro.test", label: null }], phones: [{ number: "+1-555-0100", label: "mobile" }],
      createdUnix: t, updatedUnix: t,
    },
  ];
}

export function loadLocalBook(): ContactView[] {
  try {
    const raw = window.localStorage.getItem(LOCAL_BOOK_KEY);
    if (raw !== null) {
      const arr = JSON.parse(raw) as unknown;
      if (Array.isArray(arr)) {
        const out: ContactView[] = [];
        for (const item of arr) {
          const c = parseContact(item);
          if (c) out.push(c);
        }
        return out;
      }
    }
    if (window.localStorage.getItem(SEED_KEY) === null) {
      const s = seed();
      window.localStorage.setItem(LOCAL_BOOK_KEY, JSON.stringify(s));
      window.localStorage.setItem(SEED_KEY, "1");
      return s;
    }
    return [];
  } catch {
    return [];
  }
}

export function saveLocalBook(book: ContactView[]): void {
  try {
    window.localStorage.setItem(LOCAL_BOOK_KEY, JSON.stringify(book));
    window.localStorage.setItem(SEED_KEY, "1");
  } catch {
    // Quota/private mode — edits last for the session only.
  }
}

let localSeq = 0;

/** Insert or replace in the local book (empty id assigns `local-N`). */
export function upsertLocal(book: ContactView[], input: ContactInput, id?: string): ContactView[] {
  const t = nowSecs();
  const clean = (s: string) => s.trim();
  const emails = input.emails
    .map((e) => ({ address: e.address.trim(), label: e.label?.trim() || null }))
    .filter((e) => e.address);
  const phones = (input.phones ?? [])
    .map((p) => ({ number: p.number.trim(), label: p.label?.trim() || null }))
    .filter((p) => p.number);
  if (id) {
    return book.map((c) =>
      c.id === id
        ? {
            ...c,
            displayName: clean(input.displayName) || emails[0]?.address || c.displayName,
            givenName: input.givenName?.trim() || null,
            familyName: input.familyName?.trim() || null,
            org: input.org?.trim() || null,
            title: input.title?.trim() || null,
            notes: input.notes?.trimEnd() || null,
            tags: [...new Set(input.tags.map((x) => x.trim()).filter(Boolean))],
            emails,
            phones,
            updatedUnix: t,
          }
        : c,
    );
  }
  localSeq += 1;
  const created: ContactView = {
    id: `local-${Date.now().toString(36)}-${localSeq}`,
    displayName: clean(input.displayName) || emails[0]?.address || "(unnamed)",
    givenName: input.givenName?.trim() || null,
    familyName: input.familyName?.trim() || null,
    org: input.org?.trim() || null,
    title: input.title?.trim() || null,
    notes: input.notes?.trimEnd() || null,
    tags: [...new Set(input.tags.map((x) => x.trim()).filter(Boolean))],
    emails,
    phones,
    createdUnix: t,
    updatedUnix: t,
  };
  return [...book, created];
}

export function deleteLocal(book: ContactView[], id: string): ContactView[] {
  return book.filter((c) => c.id !== id);
}

/**
 * Substring match across name/org/notes/tags/emails (mirrors contacts.md
 * §3.2 at UI scale). Empty query returns the whole book.
 */
export function filterContacts(book: ContactView[], q: string): ContactView[] {
  const needle = q.trim().toLowerCase();
  if (!needle) return book;
  return book.filter((c) => {
    const hay = [c.displayName, c.org ?? "", c.notes ?? "", ...c.tags, ...c.emails.map((e) => e.address)]
      .join(" ")
      .toLowerCase();
    return hay.includes(needle);
  });
}

/** Client-side mirror of the crate bounds that matter for typing. */
export function validateContactInput(input: ContactInput): string | null {
  const addrs = input.emails.map((e) => e.address.trim()).filter(Boolean);
  if (!input.displayName.trim() && addrs.length === 0) {
    return "A contact needs a display name or at least one email address.";
  }
  if (input.displayName.length > 256) return "Display name exceeds 256 bytes.";
  for (const a of addrs) {
    if (a.length > 320) return `Email exceeds 320 bytes: ${a}`;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a)) return `Not a usable email address: ${a}`;
  }
  if (addrs.length > 16) return "More than 16 email addresses.";
  if ((input.notes ?? "").length > 4096) return "Notes exceed 4096 bytes.";
  if (input.tags.length > 32) return "More than 32 tags.";
  return null;
}
