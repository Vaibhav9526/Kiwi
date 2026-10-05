// Adapter for Mailspring `flux/models/contact.ts` + `flux/stores/contact-store.ts`
// — Contact is a thin {id, name, email} class (no Model/Attributes/AccountStore);
// ContactStore searches via api.searchContacts (KIWI IPC) instead of SQLite.
// parseContactsInString's regex loop is vendor-verbatim; name lookup resolves
// through the IPC search. ContactGroup is a minimal {id, name} stub —
// participants-text-field imports the type but KIWI has no groups.
import { api, BackendUnavailableError } from "../ipc";
import type { ContactView } from "../kiwi";
import { RegExpUtils } from "./ms-regexp-utils";
import { generateTempId } from "./ms-utils";

export class Contact {
  id: string;
  name: string;
  email: string;

  constructor({ id, name, email }: { id?: string; name?: string; email?: string } = {}) {
    this.id = id ?? generateTempId();
    this.name = name ?? "";
    this.email = typeof email === "string" ? email.trim() : "";
  }

  /** KIWI seam: ContactView → Contact (first emails[] entry + displayName). */
  static fromKiwi(view: ContactView): Contact {
    return new Contact({
      id: view.id,
      name: view.displayName,
      email: view.emails[0]?.address ?? "",
    });
  }

  // Vendor verbatim: `Full Name <email>` when named, bare email otherwise.
  toString() {
    return this.name && this.name !== this.email ? `${this.name} <${this.email}>` : this.email;
  }

  isValid() {
    if (!this.email) {
      return false;
    }
    const result = RegExpUtils.emailRegex().exec(this.email);
    return result instanceof Array ? result[0] === this.email : false;
  }

  // No AccountStore in KIWI — the vendor's "You"/compact options collapse
  // to the plain name-or-email fallback.
  displayName(_options: { includeAccountLabel?: boolean; forceAccountLabel?: boolean; compact?: boolean } = {}) {
    return this.name || this.email;
  }

  fullName() {
    return this.name || this.email;
  }

  initials() {
    const source = this.name && this.name !== this.email ? this.name : this.email;
    const readable = source.includes("@") ? source.split("@")[0] : source;
    const parts = readable.split(/[\s._\-+]+/).filter(Boolean);
    if (parts.length === 0) {
      return "";
    }
    const first = parts[0][0] ?? "";
    const last = parts.length > 1 ? parts[parts.length - 1][0] ?? "" : "";
    return (first + last).toUpperCase();
  }
}

export class ContactGroup {
  id?: string;
  name: string;

  constructor({ id, name }: { id?: string; name?: string } = {}) {
    this.id = id;
    this.name = name ?? "";
  }
}

// remove query results that are duplicates, preferring ones that have names
// (vendor `_distinctByEmail` verbatim)
function distinctByEmail(contacts: Contact[]): Contact[] {
  const uniq: { [email: string]: Contact } = {};
  for (const contact of contacts) {
    if (!contact.email) {
      continue;
    }
    const key = contact.email.toLowerCase();
    const existing = uniq[key];
    if (!existing || !existing.name || existing.name === existing.email) {
      uniq[key] = contact;
    }
  }
  return Object.values(uniq);
}

export const ContactStore = {
  // KIWI has no contact groups — empty result is honest, not fabricated.
  searchContactGroups(_search: string): Promise<ContactGroup[]> {
    return Promise.resolve([]);
  },

  async searchContacts(search: string, options: { limit?: number } = {}): Promise<Contact[]> {
    if (!search || search.trim().length === 0) {
      return [];
    }
    const limit = Math.max(options.limit ?? 12, 0);
    let views: ContactView[];
    try {
      views = await api.searchContacts(search, limit);
    } catch (err) {
      // Browser preview / offline: no address book, so no suggestions.
      if (err instanceof BackendUnavailableError) {
        return [];
      }
      throw err;
    }
    return distinctByEmail(views.map((v) => Contact.fromKiwi(v))).slice(0, limit);
  },

  async findContactWithEmail(email: string): Promise<Contact | null> {
    const results = await ContactStore.searchContacts(email, { limit: 10 });
    const needle = email.trim().toLowerCase();
    return results.find((c) => c.email.toLowerCase() === needle) ?? null;
  },

  isValidContact(contact: unknown): boolean {
    return contact instanceof Contact ? contact.isValid() : false;
  },

  parseContactsInString(
    contactString: string,
    { skipNameLookup }: { skipNameLookup?: boolean } = {},
  ): Promise<Contact[]> {
    const detected: Contact[] = [];
    const emailRegex = RegExpUtils.emailRegex();
    let lastMatchEnd = 0;
    let match: RegExpExecArray | null = null;

    while ((match = emailRegex.exec(contactString))) {
      let email = match[0];
      let name: string | null = null;

      const startsWithQuote = ["'", '"'].includes(email[0]);
      const hasTrailingQuote = ["'", '"'].includes(contactString[match.index + email.length]);
      if (startsWithQuote && hasTrailingQuote) {
        email = email.slice(1, email.length - 1);
      }

      const hasLeadingParen = ["(", "<"].includes(contactString[match.index - 1]);
      const hasTrailingParen = [")", ">"].includes(contactString[match.index + email.length]);

      if (hasLeadingParen && hasTrailingParen) {
        let nameStart = lastMatchEnd;
        for (const char of [",", ";", "\n", "\r"]) {
          const i = contactString.lastIndexOf(char, match.index);
          if (i + 1 > nameStart) {
            nameStart = i + 1;
          }
        }
        name = contactString.slice(nameStart, match.index - 1).trim();
      }

      // The "nameStart" for the next match must begin after lastMatchEnd
      lastMatchEnd = match.index + email.length;
      if (hasTrailingParen) {
        lastMatchEnd += 1;
      }

      if (!name || name.length === 0) {
        name = email;
      }

      // If the first and last character of the name are quotation marks, remove them
      if (['"', "'"].includes(name[0]) && ['"', "'"].includes(name[name.length - 1])) {
        name = name.slice(1, name.length - 1);
      }

      detected.push(new Contact({ email, name }));
    }

    // Tokens carrying no email at all still become contacts — pasting
    // "Alice, Bob <b@c>" must not silently drop "Alice".
    for (const token of contactString.split(/[,;\r\n]+/)) {
      const t = token.trim();
      if (t && !RegExpUtils.emailRegex().test(t)) {
        detected.push(new Contact({ email: t }));
      }
    }

    if (skipNameLookup) {
      return Promise.resolve(detected);
    }

    return Promise.all(
      detected.map((contact) => {
        if (contact.name !== contact.email) {
          return Promise.resolve(contact);
        }
        return ContactStore.searchContacts(contact.email, { limit: 1 }).then(([smatch]) =>
          smatch && smatch.email === contact.email ? smatch : contact,
        );
      }),
    );
  },
};
