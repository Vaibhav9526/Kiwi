/** Shared frontend types (T-112). Backend-owned verdicts arrive via ipc.ts;
 * these shapes mirror docs/contracts/ui-surfaces.md §3 (all fields optional
 * at render time — missing data renders unknown/stale, never secure). */

export type Severity = "secure" | "warning" | "danger" | "unknown";

export interface TrustState {
  trust: Severity;
  locked: boolean;
}

export interface AccountInfo {
  id: string;
  email: string;
  displayName: string;
  trust: Severity;
  unread: number;
  /** Sidebar color-dot, hex. */
  color: string;
}

export interface MessageEnvelope {
  id: string;
  accountId: string;
  accountEmail: string;
  folder: string;
  from: string;
  subject: string;
  /** ISO timestamp. */
  date: string;
  unread: boolean;
  starred: boolean;
  hasAttachments: boolean;
  trust: Severity;
  snippet: string;
}

export interface FindingInfo {
  id: string;
  severity: "warning" | "danger";
  title: string;
  session: string;
  evidence: string;
  impact: string;
  remediation: string[];
  engineVersion: string;
}

export interface SecurityEventRow {
  id: string;
  ts: string;
  accountEmail: string;
  category: string;
  severity: Severity;
  summary: string;
}

export type PolicyBannerVerdict = "none" | "warn" | "block";

export function severityLabel(s: Severity): string {
  switch (s) {
    case "secure":
      return "Secure";
    case "warning":
      return "Warning";
    case "danger":
      return "Danger";
    case "unknown":
      return "Unknown";
  }
}

/** Glyph differs per severity so meaning is never color-only. */
export function severityGlyph(s: Severity): string {
  switch (s) {
    case "secure":
      return "✓";
    case "warning":
      return "!";
    case "danger":
      return "✕";
    case "unknown":
      return "?";
  }
}
