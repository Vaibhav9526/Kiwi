/**
 * Minimal vCard interchange (T-176): import preview + export-all, mirroring
 * `docs/contracts/contacts.md` §5 at UI scale. Bounds: 1 MiB input, 1000
 * cards. Imported properties: FN/N/ORG/TITLE/NOTE/UID/EMAIL/TEL/CATEGORIES
 * (+PREF ordering); PHOTO, URL, ADR, BDAY, X-props and unknown props are
 * ignored, never errors. Per-card issues never discard the rest of the
 * file. Export writes vCard 4.0 with §3.4 escaping and 75-octet folding.
 */

import type { ContactInput, ContactView } from "./kiwi";
import { validateContactInput } from "./contacts";

export const MAX_VCARD_BYTES = 1024 * 1024;
const MAX_CARDS = 1000;

export interface VCardIssue {
  cardIndex: number;
  detail: string;
}

export interface VCardParse {
  contacts: ContactInput[];
  issues: VCardIssue[];
}

/** RFC 6350 §3.2 unfolding: continuation lines start with SP/HTAB. */
function unfold(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r\n|\r|\n/)) {
    if ((raw.startsWith(" ") || raw.startsWith("\t")) && out.length > 0) {
      out[out.length - 1] += raw.slice(1);
    } else {
      out.push(raw);
    }
  }
  return out;
}

/** Unescape §3.4 value escapes (\\, \,, \;, \n/\N). Raw CR is dropped. */
function unescapeValue(v: string): string {
  return v
    .replace(/\r/g, "")
    .replace(/\\N/gi, "\n")
    .replace(/\\,/g, ",")
    .replace(/\\;/g, ";")
    .replace(/\\\\/g, "\\");
}

interface Prop {
  name: string;
  params: string;
  value: string;
}

function parseLine(line: string): Prop | null {
  const colon = line.indexOf(":");
  if (colon <= 0) return null;
  const left = line.slice(0, colon);
  const semi = left.indexOf(";");
  return {
    name: (semi < 0 ? left : left.slice(0, semi)).trim().toUpperCase(),
    params: semi < 0 ? "" : left.slice(semi + 1),
    value: line.slice(colon + 1),
  };
}

/** TYPE label: lowercased, transport hints (`internet`, `pref`) dropped. */
function typeLabel(params: string): string | null {
  const m = params.match(/(?:^|;)TYPE=([^;:]+)/i);
  if (!m) return null;
  for (const part of m[1].split(",")) {
    const t = part.trim().toLowerCase();
    if (t && t !== "internet" && t !== "pref") return t;
  }
  return null;
}

function hasPref(params: string): boolean {
  return /(?:^|;)PREF(?:=|$|;)/i.test(params) || /(?:^|;)TYPE=[^;:]*\bpref\b/i.test(params);
}

export function parseVCard(text: string): VCardParse {
  const contacts: ContactInput[] = [];
  const issues: VCardIssue[] = [];
  if (text.length > MAX_VCARD_BYTES) {
    return { contacts, issues: [{ cardIndex: -1, detail: `File exceeds the 1 MiB import cap (${text.length} bytes).` }] };
  }
  const lines = unfold(text);
  let inCard = false;
  let props: Prop[] = [];
  let cardIndex = 0;
  const flush = () => {
    if (!inCard) return;
    inCard = false;
    const idx = cardIndex++;
    if (idx >= MAX_CARDS) {
      issues.push({ cardIndex: idx, detail: `Past the ${MAX_CARDS}-card cap — remaining cards skipped.` });
      props = [];
      return;
    }
    const get = (name: string) => props.filter((p) => p.name === name);
    const version = get("VERSION").map((p) => p.value.trim()).join("");
    if (!["4.0", "3.0", "2.1"].includes(version)) {
      issues.push({ cardIndex: idx, detail: `Unsupported or missing VERSION ("${version || "—"}") — card skipped.` });
      props = [];
      return;
    }
    const fn_ = get("FN").map((p) => unescapeValue(p.value).trim()).find(Boolean) ?? "";
    const n = get("N")[0] ? get("N")[0].value.split(";") : [];
    const emails = get("EMAIL").map((p) => ({
      address: unescapeValue(p.value).trim(),
      label: typeLabel(p.params),
      pref: hasPref(p.params),
    }));
    emails.sort((a, b) => Number(b.pref) - Number(a.pref));
    const input: ContactInput = {
      displayName:
        fn_ ||
        [n[1] ?? "", n[0] ?? ""].map((s) => unescapeValue(s).trim()).filter(Boolean).join(" ") ||
        emails[0]?.address ||
        "",
      givenName: n[1] ? unescapeValue(n[1]).trim() || null : null,
      familyName: n[0] ? unescapeValue(n[0]).trim() || null : null,
      org: get("ORG")[0] ? unescapeValue(get("ORG")[0].value.split(";")[0]).trim() || null : null,
      title: get("TITLE")[0] ? unescapeValue(get("TITLE")[0].value).trim() || null : null,
      notes: get("NOTE")[0] ? unescapeValue(get("NOTE")[0].value).trim() || null : null,
      tags: get("CATEGORIES").flatMap((p) => unescapeValue(p.value).split(",").map((t) => t.trim()).filter(Boolean)),
      emails: emails.map((e) => ({ address: e.address, label: e.label })),
      phones: get("TEL").map((p) => ({ number: unescapeValue(p.value).trim(), label: typeLabel(p.params) })),
    };
    const problem = validateContactInput(input);
    if (problem) {
      issues.push({ cardIndex: idx, detail: problem });
    } else {
      contacts.push(input);
    }
    props = [];
  };
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    const up = t.toUpperCase();
    if (up === "BEGIN:VCARD") {
      if (inCard) {
        issues.push({ cardIndex, detail: "Unterminated card — skipped." });
        cardIndex++;
      }
      inCard = true;
      props = [];
      continue;
    }
    if (up === "END:VCARD") {
      if (!inCard) {
        issues.push({ cardIndex, detail: "END:VCARD outside any card — ignored." });
        continue;
      }
      flush();
      continue;
    }
    if (!inCard) {
      // Hard error per contracts.md §5.2: past this point the stream bounds
      // can't be guaranteed, so parsing stops (parsed cards are kept).
      issues.push({ cardIndex, detail: "Content outside any card — import stopped here." });
      break;
    }
    const prop = parseLine(line);
    if (!prop) {
      issues.push({ cardIndex, detail: `Malformed content line — card skipped: "${line.slice(0, 60)}".` });
      inCard = false;
      props = [];
      cardIndex++;
      continue;
    }
    props.push(prop);
  }
  if (inCard) {
    issues.push({ cardIndex, detail: "Unterminated card at end of file — skipped." });
  }
  return { contacts, issues };
}

/** Escape a value per RFC 6350 §3.4. */
function escapeValue(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/,/g, "\\,").replace(/;/g, "\\;");
}

/** Fold at 75 chars on character boundaries (ASCII-safe approximation). */
function fold(line: string): string {
  if (line.length <= 75) return line;
  const parts: string[] = [];
  let rest = line;
  parts.push(rest.slice(0, 75));
  rest = rest.slice(75);
  while (rest.length > 0) {
    parts.push(` ${rest.slice(0, 74)}`);
    rest = rest.slice(74);
  }
  return parts.join("\r\n");
}

function labelParam(label: string | null): string {
  const clean = (label ?? "").toLowerCase().replace(/[^a-z0-9-]/g, "");
  return clean ? `;TYPE=${clean}` : "";
}

export function exportVCard(book: ContactView[]): string {
  const out: string[] = [];
  for (const c of book) {
    const lines = ["BEGIN:VCARD", "VERSION:4.0"];
    if (c.displayName) lines.push(`FN:${escapeValue(c.displayName)}`);
    if (c.givenName || c.familyName) {
      lines.push(`N:${escapeValue(c.familyName ?? "")};${escapeValue(c.givenName ?? "")};;;`);
    }
    if (c.org) lines.push(`ORG:${escapeValue(c.org)}`);
    if (c.title) lines.push(`TITLE:${escapeValue(c.title)}`);
    for (const e of c.emails) {
      if (e.address) lines.push(`EMAIL${labelParam(e.label)}:${escapeValue(e.address)}`);
    }
    for (const p of c.phones) {
      if (p.number) lines.push(`TEL${labelParam(p.label)}:${escapeValue(p.number)}`);
    }
    if (c.tags.length > 0) lines.push(`CATEGORIES:${c.tags.map(escapeValue).join(",")}`);
    if (c.notes) lines.push(`NOTE:${escapeValue(c.notes)}`);
    lines.push("END:VCARD");
    out.push(lines.map(fold).join("\r\n"));
  }
  return out.length > 0 ? out.join("\r\n") + "\r\n" : "";
}
