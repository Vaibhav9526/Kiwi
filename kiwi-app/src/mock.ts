/**
 * Demo fixtures (T-112). Used ONLY when the Tauri backend is unreachable
 * (plain browser dev) — every view badges this as demo data. Never ships as
 * real security state; real verdicts come from kiwi-core/kiwi-forensics.
 */
import type { AccountInfo, FindingInfo, MessageEnvelope, SecurityEventRow } from "./kiwi";

export const DEMO_ACCOUNTS: AccountInfo[] = [
  { id: "acc-demo-1", email: "ava@example.test", displayName: "Ava", trust: "secure", unread: 3, color: "#1f7a3d" },
  { id: "acc-demo-2", email: "ava.oldmail.test", displayName: "Ava (old)", trust: "warning", unread: 1, color: "#8a5f00" },
];

export const DEMO_MESSAGES: MessageEnvelope[] = [
  {
    id: "msg-1", accountId: "acc-demo-1", accountEmail: "ava@example.test", folder: "inbox",
    folderId: 1, uid: 101,
    from: "billing@provider.test", subject: "Your invoice is ready", date: "2026-09-19T08:12:00Z",
    unread: true, starred: false, hasAttachments: true, trust: "secure",
    snippet: "Invoice #1042 for September is attached…",
    category: "primary",
    unsub: { url: null, mailto: null, oneClick: false },
  },
  {
    id: "msg-2", accountId: "acc-demo-1", accountEmail: "ava@example.test", folder: "inbox",
    folderId: 1, uid: 102,
    from: "team@project.test", subject: "Re: launch checklist", date: "2026-09-18T17:40:00Z",
    unread: true, starred: true, hasAttachments: false, trust: "secure",
    snippet: "All blockers cleared except the installer signing…",
    category: "primary",
    unsub: { url: null, mailto: null, oneClick: false },
  },
  {
    id: "msg-3", accountId: "acc-demo-2", accountEmail: "ava.oldmail.test", folder: "inbox",
    folderId: 1, uid: 103,
    from: "newsletter@retro.test", subject: "Weekly digest", date: "2026-09-15T09:00:00Z",
    unread: true, starred: false, hasAttachments: false, trust: "warning",
    snippet: "This server negotiated TLS 1.0 — consider migrating…",
    category: "newsletters",
    unsub: { url: "https://retro.test/newsletter/unsubscribe", mailto: "leave@retro.test", oneClick: false },
  },
  {
    id: "msg-4", accountId: "acc-demo-1", accountEmail: "ava@example.test", folder: "sent",
    folderId: 2, uid: 104,
    from: "ava@example.test", toAddrs: "team@project.test", subject: "Re: launch checklist", date: "2026-09-18T18:02:00Z",
    unread: false, starred: false, hasAttachments: false, trust: "secure",
    snippet: "Sounds good — shipping Friday…",
    category: "primary",
    unsub: { url: null, mailto: null, oneClick: false },
  },
  {
    id: "msg-5", accountId: "acc-demo-1", accountEmail: "ava@example.test", folder: "inbox",
    folderId: 1, uid: 105,
    from: "ops@project.test", subject: "Fwd: launch checklist", date: "2026-09-19T07:55:00Z",
    unread: true, starred: false, hasAttachments: false, trust: "secure",
    snippet: "Forwarding the checklist for the on-call rotation…",
    category: "primary",
    unsub: { url: null, mailto: null, oneClick: false },
  },
];

export const DEMO_FINDINGS: FindingInfo[] = [
  {
    id: "find-demo-1",
    severity: "warning",
    title: "TLS 1.0 negotiated with retro.test",
    session: "imap/retro.test:993 · TLS 1.0 · 3DES · no forward secrecy",
    evidence: "SERVER HELLO: version=0x0301 (TLS 1.0)\nCIPHER: TLS_RSA_WITH_3DES_EDE_CBC_SHA\nCERT: CN=*.retro.test, valid, expires 2027-02-01",
    impact: "Traffic can be decrypted if session keys are later compromised; 3DES is legacy-strength.",
    remediation: ["Enable TLS 1.2+ on the server.", "Prefer ECDHE cipher suites.", "Re-scan after the change."],
    engineVersion: "kiwi-forensics demo/0.1",
  },
];

export const DEMO_EVENTS: SecurityEventRow[] = [
  { id: "ev-1", ts: "2026-09-19T08:12:00Z", accountEmail: "ava.oldmail.test", category: "tls", severity: "warning", summary: "TLS 1.0 negotiated with retro.test", detailRef: "" },
  { id: "ev-2", ts: "2026-09-19T07:58:00Z", accountEmail: "ava@example.test", category: "sync", severity: "secure", summary: "Inbox sync completed, 0 findings", detailRef: "" },
];

export const DEMO_FOLDERS = [
  { id: "all-inboxes", label: "All Inboxes" },
  { id: "inbox", label: "Inbox" },
  { id: "snoozed", label: "Snoozed" },
  { id: "scheduled", label: "Scheduled" },
  { id: "sent", label: "Sent" },
  { id: "drafts", label: "Drafts" },
  { id: "spam", label: "Spam" },
  { id: "trash", label: "Trash" },
];
